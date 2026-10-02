"""Deliver incident notifications to webhook, ntfy, Telegram, and e-mail."""

from __future__ import annotations

import json
import logging
import queue
import smtplib
import ssl
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from email.message import EmailMessage

from moniwifi.incidents import SEVERITY_WEIGHT

logger = logging.getLogger(__name__)

NTFY_PRIORITY = {"info": "2", "low": "2", "medium": "3", "high": "4", "critical": "5"}


def _post(url: str, body: bytes, headers: dict[str, str], timeout: float = 10.0) -> None:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-configured URL
        if response.status >= 300:
            raise RuntimeError(f"HTTP {response.status}")


class WebhookChannel:
    name = "webhook"

    def __init__(self, url: str) -> None:
        self.url = url

    def send(self, title: str, message: str, severity: str, payload: dict) -> None:
        body = json.dumps({"title": title, "message": message, "severity": severity, "incident": payload}).encode()
        _post(self.url, body, {"Content-Type": "application/json"})


class NtfyChannel:
    name = "ntfy"

    def __init__(self, url: str, token: str | None = None) -> None:
        self.url = url
        self.token = token

    def send(self, title: str, message: str, severity: str, payload: dict) -> None:
        headers = {
            # HTTP headers must be latin-1; ntfy accepts RFC 2047 but ASCII keeps it simple.
            "Title": title.encode("ascii", "replace").decode(),
            "Priority": NTFY_PRIORITY.get(severity, "3"),
            "Tags": f"shield,{severity}",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        _post(self.url, message.encode(), headers)


class TelegramChannel:
    name = "telegram"

    def __init__(self, token: str, chat_id: str, api_base: str = "https://api.telegram.org") -> None:
        self.url = f"{api_base}/bot{token}/sendMessage"
        self.chat_id = chat_id

    def send(self, title: str, message: str, severity: str, payload: dict) -> None:
        body = urllib.parse.urlencode({"chat_id": self.chat_id, "text": f"{title}\n\n{message}"}).encode()
        _post(self.url, body, {"Content-Type": "application/x-www-form-urlencoded"})


class EmailChannel:
    name = "email"

    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        recipients: list[str],
        username: str | None = None,
        password: str | None = None,
        starttls: bool = True,
        smtp_factory=smtplib.SMTP,
    ) -> None:
        self.host = host
        self.port = port
        self.sender = sender
        self.recipients = recipients
        self.username = username
        self.password = password
        self.starttls = starttls
        self.smtp_factory = smtp_factory

    def send(self, title: str, message: str, severity: str, payload: dict) -> None:
        email = EmailMessage()
        email["Subject"] = title
        email["From"] = self.sender
        email["To"] = ", ".join(self.recipients)
        email.set_content(message)
        with self.smtp_factory(self.host, self.port, timeout=15) as smtp:
            if self.starttls:
                smtp.starttls(context=ssl.create_default_context())
            if self.username:
                smtp.login(self.username, self.password or "")
            smtp.send_message(email)


def format_incident(incident: dict, event: str) -> tuple[str, str]:
    verb = {"created": "New", "escalated": "Escalated", "test": "Test"}.get(event, "Updated")
    subject = incident.get("hostname") or incident.get("ip") or incident.get("mac") or incident.get("entity")
    title = f"[WiFi Guardian] {verb} {incident['severity'].upper()} incident: {subject}"
    lines = [
        f"Score: {incident['score']} ({incident['severity']})",
        f"Device: {subject} (IP {incident.get('ip') or '-'}, MAC {incident.get('mac') or '-'})",
        "Alerts: " + ", ".join(f"{kind} x{count}" for kind, count in incident.get("alert_types", {}).items()),
    ]
    lines += [f"Why: {reason}" for reason in incident.get("reasons", [])]
    lines += ["", "Latest alerts:"]
    lines += [f"- [{alert['severity']}] {alert['detail']}" for alert in incident.get("alerts", [])[-5:]]
    return title, "\n".join(lines)


class Notifier:
    """Queue incident notifications and send them from a worker thread, with rate limiting."""

    def __init__(self, channels: list, min_severity: str = "high", max_per_hour: int = 20) -> None:
        self.channels = channels
        self.min_severity = min_severity
        self.max_per_hour = max_per_hour
        self._queue: queue.Queue = queue.Queue(maxsize=500)
        self._sent_times: deque[float] = deque()
        self._lock = threading.Lock()
        self.sent = 0
        self.dropped = 0
        self.last_error: str | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.channels)

    def should_notify(self, incident: dict, event: str) -> bool:
        return (
            self.enabled
            and event in ("created", "escalated")
            and incident["status"] != "closed"
            and SEVERITY_WEIGHT[incident["severity"]] >= SEVERITY_WEIGHT[self.min_severity]
        )

    def submit(self, incident: dict, event: str) -> bool:
        if not self.should_notify(incident, event):
            return False
        try:
            self._queue.put_nowait((incident, event))
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def send_now(self, incident: dict, event: str) -> dict[str, str | None]:
        """Send immediately to every channel; returns per-channel errors (None on success)."""
        title, message = format_incident(incident, event)
        results = {}
        for channel in self.channels:
            try:
                channel.send(title, message, incident["severity"], incident)
                results[channel.name] = None
            except Exception as exc:  # noqa: BLE001 - one channel failing must not block the others
                logger.error("Notification via %s failed: %s", channel.name, exc)
                results[channel.name] = str(exc)
        errors = [f"{name}: {error}" for name, error in results.items() if error]
        self.last_error = "; ".join(errors) or None
        return results

    def run(self, stop_event: threading.Event, heartbeat=lambda: None) -> None:
        while not stop_event.is_set():
            heartbeat()
            try:
                incident, event = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            if not self._allow():
                self.dropped += 1
                logger.warning("Notification rate limit reached; dropping %s", incident["id"])
                continue
            self.send_now(incident, event)
            self.sent += 1

    def _allow(self) -> bool:
        now = time.time()
        with self._lock:
            while self._sent_times and now - self._sent_times[0] > 3600:
                self._sent_times.popleft()
            if len(self._sent_times) >= self.max_per_hour:
                return False
            self._sent_times.append(now)
            return True

    def stats(self) -> dict:
        return {
            "channels": [channel.name for channel in self.channels],
            "min_severity": self.min_severity,
            "sent": self.sent,
            "dropped": self.dropped,
            "queued": self._queue.qsize(),
            "last_error": self.last_error,
        }


def channels_from_config(config) -> list:
    channels = []
    if config.NOTIFY_WEBHOOK_URL:
        channels.append(WebhookChannel(config.NOTIFY_WEBHOOK_URL))
    if config.NOTIFY_NTFY_URL:
        channels.append(NtfyChannel(config.NOTIFY_NTFY_URL, config.NOTIFY_NTFY_TOKEN))
    if config.NOTIFY_TELEGRAM_TOKEN and config.NOTIFY_TELEGRAM_CHAT_ID:
        channels.append(TelegramChannel(config.NOTIFY_TELEGRAM_TOKEN, config.NOTIFY_TELEGRAM_CHAT_ID))
    if config.SMTP_HOST and config.NOTIFY_EMAIL_TO:
        channels.append(
            EmailChannel(
                config.SMTP_HOST,
                config.SMTP_PORT,
                config.SMTP_FROM,
                config.NOTIFY_EMAIL_TO,
                username=config.SMTP_USER,
                password=config.SMTP_PASSWORD,
                starttls=config.SMTP_STARTTLS,
            )
        )
    return channels
