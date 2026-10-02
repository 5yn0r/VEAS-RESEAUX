from __future__ import annotations

import time
from collections import Counter, OrderedDict, defaultdict, deque
from threading import Lock

from moniwifi.devices import DeviceRegistry
from moniwifi.dnslog import DomainTracker
from moniwifi.flows import FlowTable


class MonitorState:
    def __init__(
        self,
        max_alerts: int,
        max_history: int = 5000,
        max_dns_cache: int = 1000,
        max_packet_history: int = 1000,
        device_active_timeout: float = 300.0,
        new_device_learning_period: float = 0.0,
        max_active_flows: int = 20000,
        max_dns_log: int = 2000,
    ) -> None:
        self.lock = Lock()
        self.traffic_data = defaultdict(
            lambda: {
                "upload": 0,
                "download": 0,
                "ips": set(),
                "last_update": time.time(),
            }
        )
        self.suspicious_events = deque(maxlen=max_alerts)
        self.traffic_buffer = {}
        self.dns_cache: OrderedDict[str, str] = OrderedDict()
        self.max_history = max_history
        self.max_dns_cache = max_dns_cache
        self.max_packet_history = max_packet_history
        self.packet_buffer: deque[dict] = deque(maxlen=max_packet_history)
        self.packet_history: deque[dict] = deque(maxlen=max_packet_history)
        self.pending_alerts: list[dict] = []
        self.current_rates = {"upload_bps": 0.0, "download_bps": 0.0, "updated_at": time.time()}
        # These components carry their own locks.
        self.devices = DeviceRegistry(
            active_timeout=device_active_timeout,
            learning_period=new_device_learning_period,
        )
        self.flows = FlowTable(max_active=max_active_flows)
        self.domains = DomainTracker(max_log=max_dns_log, max_ip_cache=max_dns_cache * 10)
        self.counters = {
            "packets_seen": 0,
            "packets_dropped": 0,
            "callback_errors": 0,
            "packets_per_second": 0.0,
        }
        self.last_scan = {
            "at": None,
            "last_success_at": None,
            "ok": None,
            "error": None,
            "devices": 0,
        }

    def get_cached_hostname(self, ip_addr: str) -> str | None:
        with self.lock:
            hostname = self.dns_cache.get(ip_addr)
            if hostname is not None:
                self.dns_cache.move_to_end(ip_addr)
            return hostname

    def cache_hostname(self, ip_addr: str, hostname: str) -> None:
        with self.lock:
            self.dns_cache[ip_addr] = hostname
            self.dns_cache.move_to_end(ip_addr)
            while len(self.dns_cache) > self.max_dns_cache:
                self.dns_cache.popitem(last=False)

    def load_known_devices(self, devices: dict[str, dict]) -> None:
        self.devices.load(devices)

    def upsert_devices(self, devices: dict[str, dict]) -> dict[str, dict]:
        """Record an ARP scan result; returns ``{mac: changes}`` from the registry."""
        return {
            mac: self.devices.observe(
                mac,
                ip=device.get("ip"),
                source="scan",
                hostname=device.get("hostname"),
                vendor=device.get("vendor"),
            )
            for mac, device in devices.items()
        }

    def buffer_traffic(
        self,
        *,
        local_ip: str,
        remote_ip: str,
        packet_length: int,
        direction: str,
    ) -> None:
        with self.lock:
            entry = self.traffic_buffer.setdefault(
                local_ip,
                {"upload": 0, "download": 0, "ips": set(), "alerts": []},
            )
            entry[direction] += packet_length
            entry["ips"].add(remote_ip)

    def buffer_alert(self, src_ip: str, alert: dict) -> None:
        with self.lock:
            entry = self.traffic_buffer.setdefault(
                src_ip,
                {"upload": 0, "download": 0, "ips": set(), "alerts": []},
            )
            entry["alerts"].append(alert)

    def buffer_packet(self, packet: dict) -> None:
        """Queue packet metadata only; payloads are intentionally never retained."""
        with self.lock:
            self.counters["packets_seen"] += 1
            if len(self.packet_buffer) == self.packet_buffer.maxlen:
                self.counters["packets_dropped"] += 1
            self.packet_buffer.append(packet)

    def record_callback_error(self) -> None:
        with self.lock:
            self.counters["callback_errors"] += 1

    def record_scan(self, ok: bool, error: str | None = None, devices: int = 0) -> None:
        with self.lock:
            now = time.time()
            self.last_scan["at"] = now
            self.last_scan["ok"] = ok
            self.last_scan["error"] = error
            if ok:
                self.last_scan["last_success_at"] = now
                self.last_scan["devices"] = devices

    def load_alerts(self, alerts: list[dict]) -> None:
        with self.lock:
            self.suspicious_events.clear()
            self.suspicious_events.extend(alerts)

    def add_alert(self, alert: dict) -> None:
        """Queue an alert that is not tied to one traffic source (e.g. from the scanner)."""
        with self.lock:
            self.pending_alerts.append(alert)

    def health_snapshot(self) -> dict:
        with self.lock:
            capture = dict(self.counters)
            scanner = dict(self.last_scan)
        capture.update(self.flows.stats())
        return {"capture": capture, "scanner": scanner}

    def flush_packets(self) -> list[dict]:
        with self.lock:
            if not self.packet_buffer:
                return []
            packets = list(self.packet_buffer)
            self.packet_buffer.clear()
            self.packet_history.extend(packets)
            return packets

    def update_packet_rate(self, packets_per_second: float) -> None:
        with self.lock:
            self.counters["packets_per_second"] = packets_per_second

    def flush_traffic(self) -> tuple[list[dict], list[dict]]:
        traffic_events = []
        alert_events = []

        with self.lock:
            for alert in self.pending_alerts:
                self.suspicious_events.append(alert)
                alert_events.append(alert)
            self.pending_alerts.clear()

            if not self.traffic_buffer:
                return traffic_events, alert_events

            current_time = time.time()
            for ip, data in list(self.traffic_buffer.items()):
                traffic_events.append(
                    {
                        "ip": ip,
                        "upload": data["upload"],
                        "download": data["download"],
                        "unique_connections": len(data["ips"]),
                        "timestamp": current_time,
                    }
                )

                self.traffic_data[ip]["upload"] += data["upload"]
                self.traffic_data[ip]["download"] += data["download"]
                self.traffic_data[ip]["ips"].update(data["ips"])
                self.traffic_data[ip]["last_update"] = current_time

                for alert in data["alerts"]:
                    self.suspicious_events.append(alert)
                    alert_events.append(alert)

            self.traffic_buffer.clear()

            for ip in list(self.traffic_data.keys()):
                if current_time - self.traffic_data[ip].get("last_update", 0) > 3600:
                    del self.traffic_data[ip]

            if len(self.traffic_data) > self.max_history:
                oldest_ips = sorted(
                    self.traffic_data,
                    key=lambda ip: self.traffic_data[ip]["last_update"],
                )[: len(self.traffic_data) - self.max_history]
                for ip in oldest_ips:
                    del self.traffic_data[ip]

        return traffic_events, alert_events

    def stats(self) -> dict:
        with self.lock:
            return {
                "devices_count": self.devices.count_active(),
                "total_traffic_bytes": sum(
                    device["upload"] + device["download"] for device in self.traffic_data.values()
                ),
                "alerts_count": len(self.suspicious_events),
                "current_upload_bps": self.current_rates["upload_bps"],
                "current_download_bps": self.current_rates["download_bps"],
                "current_total_bps": self.current_rates["upload_bps"] + self.current_rates["download_bps"],
                "timestamp": time.time(),
            }

    def update_current_rates(self, upload_bps: float, download_bps: float) -> None:
        with self.lock:
            self.current_rates = {
                "upload_bps": upload_bps,
                "download_bps": download_bps,
                "updated_at": time.time(),
            }

    def devices_snapshot(self) -> dict:
        return self.devices.active()

    def alerts_snapshot(
        self,
        limit: int = 10,
        severity: str | None = None,
        alert_type: str | None = None,
    ) -> list[dict]:
        with self.lock:
            alerts = [
                dict(alert)
                for alert in self.suspicious_events
                if (not severity or alert["severity"] == severity)
                and (not alert_type or alert["type"] == alert_type)
            ]
            return alerts[-limit:]

    def traffic_snapshot(self, limit: int = 10) -> list[dict]:
        with self.lock:
            ranked = sorted(
                self.traffic_data.items(),
                key=lambda item: item[1].get("last_update", 0),
                reverse=True,
            )
            snapshots = []
            for ip, data in ranked[:limit]:
                snapshots.append(
                    {
                        "ip": ip,
                        "upload": data.get("upload", 0),
                        "download": data.get("download", 0),
                        "unique_connections": len(data.get("ips", set())),
                        "timestamp": data.get("last_update", time.time()),
                    }
                )
            return snapshots

    def packets_snapshot(
        self,
        limit: int = 100,
        ip_addr: str | None = None,
        protocol: str | None = None,
        port: int | None = None,
        direction: str | None = None,
    ) -> list[dict]:
        with self.lock:
            packets = reversed(self.packet_history)
            result = []
            for packet in packets:
                if ip_addr and ip_addr not in (packet["source_ip"], packet["destination_ip"]):
                    continue
                if protocol and packet["protocol"] != protocol:
                    continue
                if port and port not in (packet.get("source_port"), packet.get("destination_port")):
                    continue
                if direction and packet["direction"] != direction:
                    continue
                result.append(dict(packet))
                if len(result) >= limit:
                    break
            return result

    def packets_summary(self) -> dict:
        with self.lock:
            protocols = Counter(packet["protocol"] for packet in self.packet_history)
            directions = Counter(packet["direction"] for packet in self.packet_history)
            return {
                "captured_packets": len(self.packet_history),
                "protocols": dict(protocols),
                "directions": dict(directions),
                "latest_timestamp": self.packet_history[-1]["timestamp"] if self.packet_history else None,
            }
