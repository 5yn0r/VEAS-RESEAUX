"""Forward alerts and incidents to a SIEM (Wazuh, Elastic, Splunk, Graylog...).

Two sinks, usable together:

* Syslog over UDP or TCP (RFC 5424 header), with a JSON body or ArcSight CEF.
* A JSON Lines file with size-based rotation, to be tailed by a Wazuh agent,
  Filebeat, or Fluent Bit.

JSON events use Elastic Common Schema (ECS) field names so they map onto
existing SIEM dashboards without custom parsing.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

PRODUCT = "VEAS RESEAUX"
VENDOR = "VEAS"
VERSION = "1.0"
# 0-100 for ECS event.severity, 0-10 for CEF, syslog severity codes (RFC 5424).
SEVERITY_SCORE = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 95}
CEF_SEVERITY = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}
SYSLOG_SEVERITY = {"info": 6, "low": 5, "medium": 4, "high": 3, "critical": 2}
SYSLOG_FACILITY_LOCAL0 = 16


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _threat(techniques: list[dict]) -> dict:
    if not techniques:
        return {}
    tactics = []
    for technique in techniques:
        tactics += [tactic for tactic in technique["tactics"] if tactic not in tactics]
    return {
        "framework": "MITRE ATT&CK",
        "technique": {
            "id": [technique["id"] for technique in techniques],
            "name": [technique["name"] for technique in techniques],
            "reference": [technique["url"] for technique in techniques],
        },
        "tactic": {"name": tactics},
    }


def alert_to_ecs(alert: dict, host: str) -> dict:
    evidence = alert.get("evidence") or {}
    event = {
        "@timestamp": _iso(alert["timestamp"]),
        "message": alert["message"],
        "event": {
            "kind": "alert",
            "category": ["network", "intrusion_detection"],
            "type": ["info"],
            "module": "veas",
            "dataset": "veas.alert",
            "action": alert["type"],
            "id": alert["id"],
            "severity": SEVERITY_SCORE.get(alert["severity"], 50),
        },
        "rule": {"name": alert["type"]},
        "log": {"level": alert["severity"]},
        "observer": {"vendor": VENDOR, "product": PRODUCT, "type": "ids", "hostname": host},
        "threat": _threat(alert.get("mitre") or []),
        "veas": {"severity": alert["severity"], "evidence": evidence},
    }
    if alert.get("source_ip"):
        event["source"] = {"ip": alert["source_ip"]}
        if evidence.get("mac"):
            event["source"]["mac"] = evidence["mac"].replace(":", "-").upper()
    if alert.get("destination_ip"):
        event["destination"] = {"ip": alert["destination_ip"]}
    return {key: value for key, value in event.items() if value}


def incident_to_ecs(incident: dict, event_name: str, host: str) -> dict:
    return {
        "@timestamp": _iso(incident["last_seen"]),
        "message": f"Incident {event_name}: {incident['summary']} (score {incident['score']})",
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection"],
            "type": ["info"],
            "module": "veas",
            "dataset": "veas.incident",
            "action": f"incident_{event_name}",
            "id": incident["id"],
            "severity": SEVERITY_SCORE.get(incident["severity"], 50),
            "risk_score": incident["score"],
        },
        "log": {"level": incident["severity"]},
        "observer": {"vendor": VENDOR, "product": PRODUCT, "type": "ids", "hostname": host},
        "host": {"ip": [incident["ip"]] if incident.get("ip") else [], "mac": [incident["mac"]] if incident.get("mac") else []},
        "threat": {"framework": "MITRE ATT&CK", "technique": {"id": incident.get("mitre_techniques", [])}, "tactic": {"name": incident.get("mitre_tactics", [])}},
        "veas": {
            "severity": incident["severity"],
            "status": incident["status"],
            "alert_types": incident.get("alert_types", {}),
            "reasons": incident.get("reasons", []),
            "entity": incident.get("entity"),
            "hostname": incident.get("hostname"),
        },
    }


def _cef_header(value) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _cef_extension(value) -> str:
    return str(value).replace("\\", "\\\\").replace("=", "\\=").replace("\r", " ").replace("\n", " ")


def alert_to_cef(alert: dict) -> str:
    """ArcSight Common Event Format, understood by most SIEMs."""
    evidence = alert.get("evidence") or {}
    techniques = alert.get("mitre") or []
    extensions = {
        "rt": int(alert["timestamp"] * 1000),
        "src": alert.get("source_ip"),
        "dst": alert.get("destination_ip"),
        "smac": evidence.get("mac"),
        "dpt": evidence.get("port"),
        "msg": alert["detail"],
        "externalId": alert["id"],
        "cs1Label": "mitreTechnique",
        "cs1": ",".join(technique["id"] for technique in techniques) or None,
        "cs2Label": "mitreTactic",
        "cs2": ",".join(sorted({tactic for technique in techniques for tactic in technique["tactics"]})) or None,
    }
    extension = " ".join(f"{key}={_cef_extension(value)}" for key, value in extensions.items() if value not in (None, ""))
    header = "|".join(
        _cef_header(part)
        for part in (VENDOR, PRODUCT, VERSION, alert["type"], alert["detail"][:128], CEF_SEVERITY.get(alert["severity"], 5))
    )
    return f"CEF:0|{header}|{extension}"


class SyslogSink:
    name = "syslog"

    def __init__(self, host: str, port: int = 514, protocol: str = "udp", message_format: str = "json") -> None:
        if protocol not in ("udp", "tcp"):
            raise ValueError("syslog protocol must be udp or tcp")
        if message_format not in ("json", "cef"):
            raise ValueError("syslog format must be json or cef")
        self.host = host
        self.port = port
        self.protocol = protocol
        self.message_format = message_format
        self.hostname = socket.gethostname()
        self._socket: socket.socket | None = None

    def frame(self, record: dict) -> bytes:
        severity = record["severity"]
        priority = SYSLOG_FACILITY_LOCAL0 * 8 + SYSLOG_SEVERITY.get(severity, 5)
        if self.message_format == "cef" and record["kind"] == "alert":
            body = alert_to_cef(record["source"])
        else:
            body = json.dumps(record["ecs"], separators=(",", ":"), default=str)
        timestamp = record["ecs"]["@timestamp"]
        message = f"<{priority}>1 {timestamp} {self.hostname} veas-reseaux - {record['kind']} - {body}"
        if self.protocol == "tcp":
            # RFC 6587 octet counting keeps multi-line-safe framing over TCP.
            encoded = message.encode()
            return f"{len(encoded)} ".encode() + encoded
        return message.encode()

    def send(self, record: dict) -> None:
        data = self.frame(record)
        if self.protocol == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(data, (self.host, self.port))
            return
        for attempt in range(2):
            try:
                if self._socket is None:
                    self._socket = socket.create_connection((self.host, self.port), timeout=5)
                self._socket.sendall(data)
                return
            except OSError:
                self.close()
                if attempt:
                    raise

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None


class JsonFileSink:
    name = "file"

    def __init__(self, path: str, max_bytes: int = 50 * 1024 * 1024, backups: int = 5) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, record: dict) -> None:
        line = json.dumps(record["ecs"], separators=(",", ":"), default=str) + "\n"
        if self.path.exists() and self.path.stat().st_size + len(line) > self.max_bytes:
            self._rotate()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)

    def _rotate(self) -> None:
        for index in range(self.backups - 1, 0, -1):
            older = self.path.with_name(f"{self.path.name}.{index}")
            if older.exists():
                os.replace(older, self.path.with_name(f"{self.path.name}.{index + 1}"))
        if self.backups:
            os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))
        else:
            self.path.unlink()

    def close(self) -> None:
        pass


class SiemExporter:
    """Queue events and write them to every sink from a worker thread."""

    def __init__(self, sinks: list, min_severity: str = "low", include_incidents: bool = True) -> None:
        self.sinks = sinks
        self.min_severity = min_severity
        self.include_incidents = include_incidents
        self.host = socket.gethostname()
        self._queue: queue.Queue = queue.Queue(maxsize=10000)
        self.sent = 0
        self.dropped = 0
        self.errors = 0
        self.last_error: str | None = None
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.sinks)

    def _passes(self, severity: str) -> bool:
        return SEVERITY_SCORE.get(severity, 0) >= SEVERITY_SCORE.get(self.min_severity, 0)

    def submit_alert(self, alert: dict) -> None:
        if self.enabled and self._passes(alert["severity"]):
            self._put({"kind": "alert", "severity": alert["severity"], "source": alert, "ecs": alert_to_ecs(alert, self.host)})

    def submit_incident(self, incident: dict, event_name: str) -> None:
        if self.enabled and self.include_incidents and event_name in ("created", "escalated", "status") and self._passes(incident["severity"]):
            self._put(
                {"kind": "incident", "severity": incident["severity"], "source": incident, "ecs": incident_to_ecs(incident, event_name, self.host)}
            )

    def _put(self, record: dict) -> None:
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            with self._lock:
                self.dropped += 1

    def drain(self) -> int:
        """Send everything queued now (used by the worker and by offline tools)."""
        count = 0
        while True:
            try:
                record = self._queue.get_nowait()
            except queue.Empty:
                return count
            self._deliver(record)
            count += 1

    def _deliver(self, record: dict) -> None:
        for sink in self.sinks:
            try:
                sink.send(record)
            except Exception as exc:  # noqa: BLE001 - a SIEM outage must not stop monitoring
                with self._lock:
                    self.errors += 1
                    self.last_error = f"{sink.name}: {exc}"
                logger.warning("SIEM sink %s failed: %s", sink.name, exc)
        with self._lock:
            self.sent += 1

    def run(self, stop_event: threading.Event, heartbeat=lambda: None) -> None:
        while not stop_event.is_set():
            heartbeat()
            try:
                record = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            self._deliver(record)
        for sink in self.sinks:
            sink.close()

    def stats(self) -> dict:
        with self._lock:
            return {
                "sinks": [sink.name for sink in self.sinks],
                "min_severity": self.min_severity,
                "sent": self.sent,
                "dropped": self.dropped,
                "errors": self.errors,
                "queued": self._queue.qsize(),
                "last_error": self.last_error,
            }


def sinks_from_config(config) -> list:
    sinks = []
    if config.SIEM_SYSLOG_HOST:
        sinks.append(SyslogSink(config.SIEM_SYSLOG_HOST, config.SIEM_SYSLOG_PORT, config.SIEM_SYSLOG_PROTOCOL, config.SIEM_SYSLOG_FORMAT))
    if config.SIEM_JSON_FILE:
        sinks.append(JsonFileSink(config.SIEM_JSON_FILE, config.SIEM_JSON_MAX_MB * 1024 * 1024, config.SIEM_JSON_BACKUPS))
    return sinks

