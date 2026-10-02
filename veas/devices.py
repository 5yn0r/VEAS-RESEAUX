"""Device identity: MAC-keyed registry fed by ARP scans and passive observation."""

from __future__ import annotations

import threading
import time

HOSTNAME_PRIORITY = {"dhcp": 3, "mdns": 2, "dns": 1, "scan": 1}
MAX_IP_HISTORY = 10


class DeviceRegistry:
    """Track every device seen, keyed by MAC.

    ``observe`` returns what changed so detection code can raise alerts (a
    never-seen MAC, a device moving to a new IP, an IP moving to another MAC)
    without the registry knowing about alerts itself.
    """

    def __init__(self, active_timeout: float = 300.0, learning_period: float = 0.0) -> None:
        self.active_timeout = active_timeout
        self.learning_period = learning_period
        self._lock = threading.Lock()
        self._devices: dict[str, dict] = {}
        self._ip_to_mac: dict[str, str] = {}
        self._dirty: set[str] = set()
        self._learning_until = 0.0

    # Loading and persistence ---------------------------------------------

    def load(self, devices: dict[str, dict], now: float | None = None) -> None:
        """Load persisted devices. On an empty history, start a learning period with no new-device alerts."""
        now = time.time() if now is None else now
        with self._lock:
            for mac, stored in devices.items():
                details = stored.get("details") or {}
                device = self._blank(mac, float(stored.get("first_seen") or now))
                device.update({key: value for key, value in stored.items() if key != "details" and value is not None})
                device.update(details)
                device["sources"] = set(details.get("sources") or [])
                device["ip_history"] = list(details.get("ip_history") or [])
                self._devices[mac] = device
                if device.get("ip"):
                    self._ip_to_mac[device["ip"]] = mac
            self._learning_until = now + self.learning_period if not devices else 0.0

    def start_learning_if_empty(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            if not self._devices:
                self._learning_until = now + self.learning_period

    def drain_dirty(self) -> dict[str, dict]:
        with self._lock:
            dirty = {mac: self._serialize(self._devices[mac]) for mac in self._dirty if mac in self._devices}
            self._dirty.clear()
            return dirty

    # Observation ---------------------------------------------------------

    def observe(
        self,
        mac: str,
        ip: str | None = None,
        source: str = "passive",
        hostname: str | None = None,
        vendor: str | None = None,
        details: dict | None = None,
        now: float | None = None,
    ) -> dict:
        now = time.time() if now is None else now
        mac = mac.lower()
        changes = {"new_device": False, "ip_changed": None, "ip_moved_from": None, "learning": now < self._learning_until}
        with self._lock:
            device = self._devices.get(mac)
            if device is None:
                device = self._blank(mac, now)
                self._devices[mac] = device
                changes["new_device"] = True
            device["last_seen"] = now
            device["sources"].add(source)

            if ip and ip != "0.0.0.0":
                previous_ip = device.get("ip")
                if previous_ip and previous_ip != ip:
                    # Keep the previous mapping until another MAC claims that IP: a spoofer answering
                    # for the gateway still owns its own address, and its alerts must stay attributed.
                    changes["ip_changed"] = previous_ip
                owner = self._ip_to_mac.get(ip)
                if owner and owner != mac:
                    changes["ip_moved_from"] = owner
                device["ip"] = ip
                self._ip_to_mac[ip] = mac
                if ip not in device["ip_history"]:
                    device["ip_history"] = (device["ip_history"] + [ip])[-MAX_IP_HISTORY:]

            if hostname and hostname != "Unknown":
                rank = HOSTNAME_PRIORITY.get(source, 0)
                if rank >= HOSTNAME_PRIORITY.get(device.get("hostname_source") or "", 0) or not device.get("hostname"):
                    device["hostname"] = hostname
                    device["hostname_source"] = source
            if vendor and (not device.get("vendor") or source == "scan"):
                device["vendor"] = vendor
            if details:
                device.update({key: value for key, value in details.items() if value})
            self._dirty.add(mac)
        return changes

    # Queries -------------------------------------------------------------

    def mac_for_ip(self, ip: str) -> str | None:
        with self._lock:
            return self._ip_to_mac.get(ip)

    def get(self, mac: str) -> dict | None:
        with self._lock:
            device = self._devices.get(mac.lower())
            return self._serialize(device) if device else None

    def active(self, now: float | None = None) -> dict[str, dict]:
        now = time.time() if now is None else now
        with self._lock:
            return {
                mac: self._serialize(device)
                for mac, device in self._devices.items()
                if now - device["last_seen"] <= self.active_timeout
            }

    def all(self) -> dict[str, dict]:
        with self._lock:
            return {mac: self._serialize(device) for mac, device in self._devices.items()}

    def count_active(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            return sum(1 for device in self._devices.values() if now - device["last_seen"] <= self.active_timeout)

    # Helpers -------------------------------------------------------------

    @staticmethod
    def _blank(mac: str, now: float) -> dict:
        return {
            "mac": mac,
            "ip": None,
            "vendor": None,
            "hostname": None,
            "hostname_source": None,
            "first_seen": now,
            "last_seen": now,
            "sources": set(),
            "ip_history": [],
        }

    @staticmethod
    def _serialize(device: dict) -> dict:
        data = dict(device)
        data["sources"] = sorted(device["sources"])
        data["ip_history"] = list(device["ip_history"])
        return data
