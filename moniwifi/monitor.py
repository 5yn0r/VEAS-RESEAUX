from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
import threading
import time

from scapy.all import ARP, ICMP, IP, TCP, UDP, AsyncSniffer, Ether
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS

import config
from moniwifi.allowlist import Allowlist
from moniwifi.baseline import BaselineTracker
from moniwifi.detectors import DetectionEngine, DetectionSettings
from moniwifi.incidents import IncidentManager
from moniwifi.netinfo import NetworkContext
from moniwifi.notify import Notifier, channels_from_config
from moniwifi.siem import SiemExporter, sinks_from_config
from moniwifi.oui import OuiDatabase
from moniwifi import protocols
from moniwifi.state import MonitorState
from moniwifi.supervisor import ThreadSupervisor
from moniwifi.threatintel import ThreatIntel

logger = logging.getLogger(__name__)

ARP_LINE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+(.+)", re.IGNORECASE)
IGNORED_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}
# Passive sightings of the same (mac, ip) are recorded at most this often.
PASSIVE_OBSERVATION_INTERVAL = 30.0


class NetworkMonitor:
    def __init__(
        self,
        socketio,
        state: MonitorState,
        storage=None,
        network: NetworkContext | None = None,
        sniffer_factory=AsyncSniffer,
        oui: OuiDatabase | None = None,
        intel: ThreatIntel | None = None,
        detection_settings: DetectionSettings | None = None,
        notifier: Notifier | None = None,
        baselines: BaselineTracker | None = None,
        siem: SiemExporter | None = None,
    ) -> None:
        self.socketio = socketio
        self.state = state
        self.storage = storage
        self.network = network or NetworkContext(
            interface_override=config.NETWORK_INTERFACE,
            refresh_interval=config.INTERFACE_REFRESH_INTERVAL,
        )
        self.sniffer_factory = sniffer_factory
        self.oui = oui or OuiDatabase(([config.OUI_FILE] if config.OUI_FILE else []) + list(OuiDatabase().paths))
        self._recent_observations: dict[tuple[str, str | None], float] = {}
        self.dhcp_servers: dict[str, dict] = {}
        self.intel = intel or ThreatIntel(config.THREAT_INTEL_DIR, config.THREAT_INTEL_FEEDS)
        self.allowlist = Allowlist()
        self.baselines = baselines or baselines_from_config()
        self.incidents = IncidentManager(window=config.INCIDENT_WINDOW)
        self.notifier = notifier or Notifier(
            channels_from_config(config),
            min_severity=config.NOTIFY_MIN_SEVERITY,
            max_per_hour=config.NOTIFY_MAX_PER_HOUR,
        )
        self.siem = siem or siem_from_config()
        self.detector = DetectionEngine(
            state,
            settings=detection_settings or settings_from_config(),
            intel=self.intel,
            gateway_ip=self.network.gateway_ip,
            is_local=self.network.is_local,
            allowlist=self.allowlist,
            baselines=self.baselines,
        )
        self._last_maintenance = 0.0
        self.stop_event = threading.Event()
        self.supervisor = ThreadSupervisor(stop_event=self.stop_event)
        self.started_at: float | None = None
        self._last_purge = 0.0

    # Compatibility helpers -------------------------------------------------

    def get_default_interface(self) -> str | None:
        return self.network.interface()

    def get_local_network(self):
        return self.network.local_network()

    # Persistence -----------------------------------------------------------

    def load_persisted_state(self) -> None:
        if not self.storage:
            self.state.devices.start_learning_if_empty()
            return
        try:
            self.state.load_known_devices(self.storage.known_devices())
            self.state.load_alerts(self.storage.recent_alerts(limit=config.MAX_ALERTS))
            self.allowlist.load(self.storage.load_allowlist())
            self.baselines.load(self.storage.load_baselines())
            self.incidents.load(self.storage.load_incidents(since=time.time() - 7 * 86400))
        except Exception as exc:  # noqa: BLE001 - storage problems must not stop monitoring
            logger.error("Unable to load persisted state: %s", exc)
            self.state.devices.start_learning_if_empty()

    def _persist(self, method: str, *args) -> None:
        if not self.storage:
            return
        try:
            getattr(self.storage, method)(*args)
        except Exception as exc:  # noqa: BLE001
            logger.error("Storage %s failed: %s", method, exc)

    # Discovery -------------------------------------------------------------

    def observe_device(
        self,
        mac: str | None,
        ip: str | None,
        source: str,
        hostname: str | None = None,
        vendor: str | None = None,
        details: dict | None = None,
        now: float | None = None,
    ) -> dict | None:
        """Record a device sighting and raise identity alerts. ``now`` is the capture time when known."""
        if not mac:
            return None
        mac = mac.lower()
        if mac in IGNORED_MACS or int(mac.split(":")[0], 16) & 0x01:  # broadcast / multicast
            return None
        if source == "passive":
            key, seen = (mac, ip), time.time() if now is None else now
            if abs(seen - self._recent_observations.get(key, -PASSIVE_OBSERVATION_INTERVAL)) < PASSIVE_OBSERVATION_INTERVAL:
                return None
            if len(self._recent_observations) > 10000:
                self._recent_observations.clear()
            self._recent_observations[key] = seen

        vendor = vendor or self.oui.lookup(mac)
        changes = self.state.devices.observe(
            mac, ip=ip, source=source, hostname=hostname, vendor=vendor, details=details, now=now
        )
        self.detector.on_device(mac, ip, source, changes, hostname=hostname, vendor=vendor, now=now)
        return changes

    def resolve_hostname(self, ip_addr: str) -> str:
        cached = self.state.get_cached_hostname(ip_addr)
        if cached is not None:
            return cached

        try:
            hostname = socket.gethostbyaddr(ip_addr)[0]
        except (socket.herror, socket.timeout, OSError):
            hostname = "Unknown"

        self.state.cache_hostname(ip_addr, hostname)
        return hostname

    def parse_arp_scan(self, output: str) -> dict[str, dict]:
        devices = {}
        now = time.time()
        for line in output.splitlines():
            match = ARP_LINE.search(line)
            if not match:
                continue
            ip_addr, mac, vendor = match.groups()
            devices[mac.lower()] = {
                "ip": ip_addr,
                "vendor": vendor.strip()[:30],
                "hostname": self.resolve_hostname(ip_addr),
                "first_seen": now,
            }
        return devices

    def scan_once(self) -> dict[str, dict]:
        command = [config.ARP_SCAN_COMMAND, "--retry=2"]
        iface = self.network.interface()
        if iface:
            command.append(f"--interface={iface}")
        command.append("--localnet")
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
        if result.returncode not in (0, 1):
            raise RuntimeError(result.stderr.strip() or "arp-scan failed")

        devices = self.parse_arp_scan(result.stdout)
        for mac, device in devices.items():
            self.observe_device(mac, device["ip"], "scan", hostname=device["hostname"], vendor=device["vendor"])
        self.state.record_scan(ok=True, devices=len(devices))
        return devices

    def scan_network(self) -> None:
        logger.info("Network scanner started")
        failure_count = 0

        while not self.stop_event.is_set():
            try:
                devices = self.scan_once()
                failure_count = 0
                logger.info("Network scan: %s devices", len(devices))
            except subprocess.TimeoutExpired:
                logger.warning("arp-scan timed out")
                self.state.record_scan(ok=False, error="arp-scan timed out")
                failure_count += 1
            except Exception as exc:  # noqa: BLE001 - keep scanning after transient failures
                logger.error("Scan error: %s", exc)
                self.state.record_scan(ok=False, error=str(exc))
                failure_count += 1

            self.supervisor.heartbeat("Scanner")
            self.stop_event.wait(config.SCAN_INTERVAL * (2 ** min(failure_count, 3)))

    # Capture ---------------------------------------------------------------

    def handle_arp(self, packet, now: float | None = None) -> None:
        info = protocols.parse_arp(packet)
        if info and info["sender_ip"] != "0.0.0.0":
            self.observe_device(info["sender_mac"], info["sender_ip"], "passive", now=now)

    def handle_dhcp(self, packet, now: float | None = None) -> None:
        info = protocols.parse_dhcp(packet)
        if not info:
            return
        if info["message_type"] in ("discover", "request", "inform", "release"):
            ip = info["client_ip"] or info["requested_ip"]
            self.observe_device(
                info["client_mac"],
                ip if info["message_type"] != "release" else None,
                "dhcp",
                hostname=info["hostname"],
                details={"dhcp_vendor_class": info["vendor_class"]},
                now=now,
            )
        elif info["message_type"] in ("offer", "ack"):
            server = info["server_id"] or info["server_ip"]
            if server:
                entry = self.dhcp_servers.setdefault(server, {"first_seen": time.time(), "mac": info["server_mac"]})
                entry["last_seen"] = time.time()
                entry["router"] = info["router"]
                self.detector.on_dhcp_server(server, info["server_mac"], info["router"])
            if info["message_type"] == "ack" and info["offered_ip"]:
                self.observe_device(info["client_mac"], info["offered_ip"], "dhcp", now=now)

    def handle_dns(
        self, packet, src_ip: str, dst_ip: str, src_is_local: bool, dst_is_local: bool, now: float | None = None
    ) -> None:
        info = protocols.parse_dns(packet)
        if not info:
            return
        if info["multicast"]:
            ether_src = packet[Ether].src if Ether in packet else None
            for answer in info["answers"]:
                if answer["type"] == "A" and answer["name"].endswith(".local"):
                    mac = self.state.devices.mac_for_ip(answer["data"]) or (ether_src if answer["data"] == src_ip else None)
                    self.observe_device(mac, answer["data"], "mdns", hostname=answer["name"][: -len(".local")], now=now)
            return
        if not info["is_response"] and src_is_local:
            for query in info["queries"]:
                self.state.domains.record_query(src_ip, query["name"], query["type"], now=now)
                self.detector.on_dns_query(src_ip, query["name"], dst_ip, now=now)
        elif info["is_response"] and dst_is_local:
            self.state.domains.record_response(dst_ip, info["queries"], info["answers"], info["rcode"])

    def packet_callback(self, packet) -> None:
        try:
            # Capture time, not processing time: exact live, and required when replaying a pcap.
            now = float(getattr(packet, "time", 0) or time.time())
            if ARP in packet:
                self.handle_arp(packet, now)
                return
            if IP not in packet:
                return
            if DHCP in packet:
                self.handle_dhcp(packet, now)

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            local_network = self.network.local_network()
            if not local_network:
                return

            src_is_local = ipaddress.ip_address(src_ip) in local_network
            dst_is_local = ipaddress.ip_address(dst_ip) in local_network
            if not src_is_local and not dst_is_local:
                return

            packet_length = len(packet)
            if TCP in packet:
                protocol = "TCP"
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport
                flags = str(packet[TCP].flags)
            elif UDP in packet:
                protocol = "UDP"
                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport
                flags = None
            elif ICMP in packet:
                protocol = "ICMP"
                source_port = None
                destination_port = None
                flags = None
                if packet[ICMP].type == 8:
                    self.detector.on_icmp_echo(src_ip, dst_ip, now=now)
            else:
                protocol = "IP"
                source_port = None
                destination_port = None
                flags = None

            direction = "local" if src_is_local and dst_is_local else "outbound" if src_is_local else "inbound"
            if src_is_local and Ether in packet:
                self.observe_device(packet[Ether].src, src_ip, "passive", now=now)
            if UDP in packet and (packet[UDP].sport in (137, 5355) or packet[UDP].dport in (137, 5355)):
                resolution = protocols.parse_name_resolution(packet)
                if resolution:
                    self.detector.on_name_resolution(src_ip, dst_ip, resolution, now=now)
            if DNS in packet and UDP in packet:
                self.handle_dns(packet, src_ip, dst_ip, src_is_local, dst_is_local, now=now)

            server_name, name_source = None, "dns"
            if protocol == "TCP" and src_is_local:
                named = protocols.extract_server_name(packet)
                if named:
                    server_name, name_source = named
                    self.state.domains.observe_name(src_ip, server_name, name_source)
                    self.state.domains.remember_ip(dst_ip, server_name)
                    self.detector.on_server_name(src_ip, server_name, name_source)
            if server_name is None:
                server_name = self.state.domains.domain_for_ip(src_ip if dst_is_local and not src_is_local else dst_ip)
            flow = self.state.flows.update(
                protocol=protocol,
                src_ip=src_ip,
                src_port=source_port,
                dst_ip=dst_ip,
                dst_port=destination_port,
                size=packet_length,
                direction=direction,
                tcp_flags=flags,
                server_name=server_name,
                name_source=name_source,
                now=now,
            )
            if flow["packets_out"] + flow["packets_in"] == 1:
                self.detector.on_new_flow(flow, now=now)
            if protocol == "TCP" and src_ip == flow["server_ip"] and flow["packets_in"] == 1:
                self.detector.on_inbound_accepted(flow)
            if flags == "S":
                self.detector.on_tcp_syn(src_ip, dst_ip, destination_port, now=now)

            self.state.buffer_packet(
                {
                    "timestamp": now,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "protocol": protocol,
                    "source_port": source_port,
                    "destination_port": destination_port,
                    "size": packet_length,
                    "direction": direction,
                    "tcp_flags": flags,
                }
            )
            if src_is_local:
                self.state.buffer_traffic(
                    local_ip=src_ip,
                    remote_ip=dst_ip,
                    packet_length=packet_length,
                    direction="upload",
                )
            if dst_is_local:
                self.state.buffer_traffic(
                    local_ip=dst_ip,
                    remote_ip=src_ip,
                    packet_length=packet_length,
                    direction="download",
                )
        except Exception as exc:  # noqa: BLE001 - one malformed packet must not stop capture
            self.state.record_callback_error()
            logger.debug("packet_callback error: %s", exc)

    def run_sniffer(self) -> None:
        """Capture on the current interface and restart capture when it changes."""
        logger.info("Packet sniffer started")
        while not self.stop_event.is_set():
            iface = self.network.interface()
            if not iface or not self.network.local_network():
                logger.warning("No capture interface available; retrying")
                self.supervisor.heartbeat("Sniffer")
                self.stop_event.wait(config.SNIFFER_CHECK_INTERVAL)
                continue

            sniffer = self.sniffer_factory(iface=iface, prn=self.packet_callback, store=False, filter="ip or arp")
            sniffer.start()
            logger.info("Sniffing on interface %s", iface)
            try:
                while not self.stop_event.wait(config.SNIFFER_CHECK_INTERVAL):
                    self.supervisor.heartbeat("Sniffer")
                    thread = getattr(sniffer, "thread", None)
                    if thread is not None and not thread.is_alive():
                        raise RuntimeError(f"capture on {iface} stopped unexpectedly")
                    if self.network.interface() != iface:
                        logger.info("Capture interface changed from %s; restarting capture", iface)
                        break
            finally:
                self._stop_sniffer(sniffer)

    @staticmethod
    def _stop_sniffer(sniffer) -> None:
        try:
            if getattr(sniffer, "running", False):
                sniffer.stop()
        except Exception as exc:  # noqa: BLE001 - scapy raises when the capture thread already died
            logger.debug("Sniffer stop failed: %s", exc)

    # Flush -----------------------------------------------------------------

    def entity_for(self, alert: dict) -> dict:
        """Pick the local device an alert is about, for incident grouping."""
        evidence = alert.get("evidence") or {}
        if alert["type"] in ("arp_spoofing", "ip_conflict"):
            ip, mac = evidence.get("ip"), evidence.get("mac")
        else:
            candidates = [alert.get("source_ip"), alert.get("destination_ip")]
            ip = next((c for c in candidates if c and self.network.is_local(c)), alert.get("source_ip"))
            mac = evidence.get("mac") or (self.state.devices.mac_for_ip(ip) if ip else None)
        device = self.state.devices.get(mac) if mac else None
        return {
            "key": mac or ip or "network",
            "ip": ip,
            "mac": mac,
            "hostname": device.get("hostname") if device else None,
        }

    def correlate(self, alerts: list[dict]) -> None:
        for alert in alerts:
            self.siem.submit_alert(alert)
            incident, event = self.incidents.ingest(alert, self.entity_for(alert))
            self.siem.submit_incident(incident, event)
            self.socketio.emit("incident_update", {"event": event, "incident": incident})
            self.notifier.submit(incident, event)

    def flush_once(self) -> None:
        traffic_events, alert_events = self.state.flush_traffic()
        self.detector.on_traffic(traffic_events)
        self.correlate(alert_events)
        packets = self.state.flush_packets()
        total_upload = sum(event.get("upload", 0) for event in traffic_events)
        total_download = sum(event.get("download", 0) for event in traffic_events)
        self.state.update_current_rates(
            upload_bps=total_upload / config.UPDATE_INTERVAL,
            download_bps=total_download / config.UPDATE_INTERVAL,
        )
        self.state.update_packet_rate(len(packets) / config.UPDATE_INTERVAL)

        expired_flows = self.state.flows.expire()
        domain_observations = self.state.domains.drain_observations()
        changed_devices = self.state.devices.drain_dirty()

        self._persist("add_traffic", traffic_events)
        self._persist("add_alerts", alert_events)
        self._persist("add_flows", expired_flows)
        self._persist("add_domain_observations", domain_observations)
        self._persist("upsert_devices", changed_devices)
        self._persist("upsert_incidents", self.incidents.drain_dirty())

        if changed_devices:
            self.socketio.emit("device_update", self.state.devices_snapshot())

        for event in traffic_events:
            self.socketio.emit("traffic_update", event)
        for alert in alert_events:
            self.socketio.emit("alert", alert)

        now = time.time()
        if now - self._last_maintenance >= 60:
            self._last_maintenance = now
            self.detector.maintenance(now)
            self._persist("upsert_baselines", self.baselines.drain_dirty())
        if self.storage and now - self._last_purge >= 3600:
            self._last_purge = now
            self._persist("purge", config.RETENTION_DAYS)

    def flush_traffic_buffer(self) -> None:
        logger.info("Traffic flush started")
        while not self.stop_event.wait(config.UPDATE_INTERVAL):
            try:
                self.flush_once()
            except Exception as exc:  # noqa: BLE001
                logger.error("flush_traffic_buffer error: %s", exc)
            self.supervisor.heartbeat("Flush")

    def run_threat_intel(self) -> None:
        """Reload local indicator files hourly and download configured feeds when due."""
        last_download = 0.0
        while not self.stop_event.is_set():
            if self.intel.feeds and time.time() - last_download >= config.THREAT_INTEL_REFRESH_HOURS * 3600:
                self.intel.download_feeds()
                last_download = time.time()
            self.intel.reload()
            self.supervisor.heartbeat("ThreatIntel")
            self.stop_event.wait(3600)

    # Lifecycle and health --------------------------------------------------

    def start_background_threads(self) -> None:
        self.started_at = time.time()
        self.supervisor.add("Scanner", self.scan_network)
        self.supervisor.add("Sniffer", self.run_sniffer)
        self.supervisor.add("Flush", self.flush_traffic_buffer)
        self.supervisor.add("ThreatIntel", self.run_threat_intel)
        self.supervisor.add("SIEM", lambda: self.siem.run(self.stop_event, lambda: self.supervisor.heartbeat("SIEM")))
        self.supervisor.add("Notifier", lambda: self.notifier.run(self.stop_event, lambda: self.supervisor.heartbeat("Notifier")))
        self.supervisor.start()

    def stop(self, timeout: float | None = 5.0) -> None:
        self.supervisor.stop(timeout)

    def health(self) -> dict:
        now = time.time()
        threads = self.supervisor.status()
        network = self.network.snapshot()
        counters = self.state.health_snapshot()
        storage = self.storage.health() if self.storage else {"enabled": False, "ok": True}

        problems = []
        if self.started_at is None:
            problems.append("monitor not started")
        for name, status in threads.items():
            if not status["alive"]:
                problems.append(f"{name} thread is not running")
        if self.started_at is not None and not network["local_network"]:
            problems.append("no capture network available")
        if counters["scanner"]["ok"] is False:
            problems.append(f"last scan failed: {counters['scanner']['error']}")
        if not storage["ok"]:
            problems.append(f"storage error: {storage.get('last_error')}")

        return {
            "status": "ok" if not problems else "degraded",
            "problems": problems,
            "uptime_seconds": now - self.started_at if self.started_at else 0,
            "threads": threads,
            "capture": {**network, **counters["capture"]},
            "scanner": counters["scanner"],
            "storage": storage,
            "detection": {**self.detector.stats(), "threat_intel": self.intel.stats(), "allowlist_rules": len(self.allowlist.rules())},
            "incidents": {"open": self.incidents.open_count()},
            "notifications": self.notifier.stats(),
            "siem": self.siem.stats(),
            "timestamp": now,
        }


def _csv(value: str) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def settings_from_config() -> DetectionSettings:
    risky = {}
    for item in _csv(config.RISKY_PORTS):
        port, _, name = item.partition(":")
        risky[int(port)] = name or f"port {port}"
    return DetectionSettings(
        scan_window=config.PORT_SCAN_WINDOW,
        port_scan_threshold=config.PORT_SCAN_THRESHOLD,
        host_sweep_threshold=config.HOST_SWEEP_THRESHOLD,
        alert_cooldown=config.ALERT_COOLDOWN,
        beacon_min_events=config.BEACON_MIN_EVENTS,
        beacon_max_jitter=config.BEACON_MAX_JITTER,
        trusted_dhcp_servers=frozenset(_csv(config.TRUSTED_DHCP_SERVERS)),
        allowed_dns_servers=frozenset(_csv(config.ALLOWED_DNS_SERVERS)),
        risky_ports=risky,
        brute_force_threshold=config.BRUTE_FORCE_THRESHOLD,
        brute_force_window=config.BRUTE_FORCE_WINDOW,
        name_poisoning_threshold=config.NAME_POISONING_THRESHOLD,
    )


def baselines_from_config() -> BaselineTracker:
    return BaselineTracker(
        bucket_seconds=config.BASELINE_BUCKET_SECONDS,
        min_samples=config.BASELINE_MIN_SAMPLES,
        sigma=config.BASELINE_SIGMA,
        min_anomaly_bytes=config.BASELINE_MIN_ANOMALY_MB * 1024 * 1024,
        learning_seconds=config.BASELINE_LEARNING_HOURS * 3600,
        quiet_destination_limit=config.BASELINE_QUIET_DESTINATIONS,
    )


def siem_from_config() -> SiemExporter:
    return SiemExporter(
        sinks_from_config(config),
        min_severity=config.SIEM_MIN_SEVERITY,
        include_incidents=config.SIEM_INCLUDE_INCIDENTS,
    )
