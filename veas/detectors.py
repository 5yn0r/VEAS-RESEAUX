"""Detection rules fed by the packet callback, the device registry, and the flow table."""

from __future__ import annotations

import math
import statistics
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field

from veas.alerts import make_alert

DEFAULT_RISKY_PORTS = {21: "FTP", 23: "Telnet", 139: "NetBIOS", 445: "SMB", 3389: "RDP", 5900: "VNC"}
BEACON_IGNORED_PORTS = {53, 123, 5353, 67, 68}
# Services where many new connections from one source usually mean password guessing.
DEFAULT_AUTH_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 110: "POP3", 143: "IMAP", 389: "LDAP", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
}
# Names Windows clients resolve automatically; an answer for them is a classic attack.
SENSITIVE_NAMES = {"wpad", "isatap"}


@dataclass
class DetectionSettings:
    scan_window: float = 60.0
    port_scan_threshold: int = 20
    host_sweep_threshold: int = 20
    alert_cooldown: float = 3600.0
    beacon_min_events: int = 8
    beacon_max_jitter: float = 0.1
    beacon_min_interval: float = 10.0
    beacon_max_interval: float = 3600.0
    dns_tunnel_label_length: int = 50
    dns_tunnel_name_length: int = 120
    dns_tunnel_unique_names: int = 150
    trusted_dhcp_servers: frozenset = frozenset()
    allowed_dns_servers: frozenset = frozenset()
    risky_ports: dict = field(default_factory=lambda: dict(DEFAULT_RISKY_PORTS))
    brute_force_threshold: int = 20
    brute_force_window: float = 60.0
    auth_ports: dict = field(default_factory=lambda: dict(DEFAULT_AUTH_PORTS))
    name_poisoning_threshold: int = 3


class SlidingDistinct:
    """Count distinct values per key over a sliding time window."""

    def __init__(self, window: float) -> None:
        self.window = window
        self._data: dict[tuple, dict] = {}

    def add(self, key: tuple, value, now: float) -> int:
        values = self._data.setdefault(key, {})
        values.pop(value, None)
        values[value] = now  # dicts keep insertion order: oldest sighting first
        cutoff = now - self.window
        while values:
            oldest = next(iter(values))
            if values[oldest] >= cutoff:
                break
            del values[oldest]
        return len(values)

    def values(self, key: tuple) -> list:
        return list(self._data.get(key, {}))

    def purge(self, now: float) -> None:
        cutoff = now - self.window
        for key in [key for key, values in self._data.items() if not values or max(values.values()) < cutoff]:
            del self._data[key]


class SlidingCounter:
    """Count events per key over a sliding time window."""

    def __init__(self, window: float) -> None:
        self.window = window
        self._data: dict[tuple, deque] = {}

    def add(self, key: tuple, now: float) -> int:
        events = self._data.setdefault(key, deque())
        events.append(now)
        while events and events[0] < now - self.window:
            events.popleft()
        return len(events)

    def purge(self, now: float) -> None:
        for key in [key for key, events in self._data.items() if not events or events[-1] < now - self.window]:
            del self._data[key]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(count / len(text) * math.log2(count / len(text)) for count in counts.values())


def base_domain(name: str) -> str:
    labels = name.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


class DetectionEngine:
    def __init__(
        self,
        state,
        settings: DetectionSettings | None = None,
        intel=None,
        gateway_ip=lambda: None,
        is_local=lambda ip: False,
        allowlist=None,
        baselines=None,
    ) -> None:
        self.state = state
        self.allowlist = allowlist
        self.baselines = baselines
        self.settings = settings or DetectionSettings()
        self.intel = intel
        self.gateway_ip = gateway_ip
        self.is_local = is_local
        self._lock = threading.Lock()
        window = self.settings.scan_window
        self._ports = SlidingDistinct(window)
        self._hosts = SlidingDistinct(window)
        self._dns_names = SlidingDistinct(window)
        self._auth_attempts = SlidingCounter(self.settings.brute_force_window)
        self._poisoned_names = SlidingDistinct(window * 10)
        self._beacons: dict[tuple, deque] = {}
        self._last_alert: dict[tuple, float] = {}
        self._auto_trusted_dhcp: set[str] = set()
        self.counts: Counter = Counter()
        self.suppressed = 0
        self.allowlisted = 0

    # Alert emission ------------------------------------------------------

    def emit(
        self,
        alert_type: str,
        detail: str,
        *,
        severity: str,
        key: tuple,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        evidence: dict | None = None,
        now: float | None = None,
    ) -> dict | None:
        """Raise an alert unless it is allowlisted or the same (type, key) fired within ``alert_cooldown``."""
        now = time.time() if now is None else now
        evidence = dict(evidence or {})
        # Tie the alert to the local device so correlation and allowlist rules can use its MAC.
        for ip in (source_ip, destination_ip):
            if "mac" in evidence:
                break
            if ip and self.is_local(ip):
                mac = self.state.devices.mac_for_ip(ip)
                if mac:
                    evidence["mac"] = mac
        alert = make_alert(
            alert_type,
            detail,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            evidence=evidence,
            timestamp=now,
        )
        throttle_key = (alert_type, *key)
        with self._lock:
            last = self._last_alert.get(throttle_key)
            if last is not None and now - last < self.settings.alert_cooldown:
                self.suppressed += 1
                return None
            # Also set for allowlisted alerts, so a long scan is not re-evaluated on every packet.
            self._last_alert[throttle_key] = now
        if self.allowlist is not None and self.allowlist.match(alert):
            with self._lock:
                self.allowlisted += 1
            return None
        with self._lock:
            self.counts[alert_type] += 1
        self.state.add_alert(alert)
        return alert

    def maintenance(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            self._ports.purge(now)
            self._hosts.purge(now)
            self._dns_names.purge(now)
            self._auth_attempts.purge(now)
            self._poisoned_names.purge(now)
            cutoff = now - self.settings.alert_cooldown
            for key in [key for key, last in self._last_alert.items() if last < cutoff]:
                del self._last_alert[key]
            stale = now - 2 * self.settings.beacon_max_interval
            for key in [key for key, times in self._beacons.items() if not times or times[-1] < stale]:
                del self._beacons[key]

    def stats(self) -> dict:
        with self._lock:
            return {
                "alerts_by_type": dict(self.counts),
                "suppressed": self.suppressed,
                "allowlisted": self.allowlisted,
            }

    # Identity ------------------------------------------------------------

    def on_device(
        self, mac: str, ip: str | None, source: str, changes: dict, hostname=None, vendor=None, now: float | None = None
    ) -> None:
        now = time.time() if now is None else now
        if changes.get("new_device") and not changes.get("learning"):
            label = hostname or vendor or "unknown vendor"
            self.emit(
                "new_device",
                f"New device {mac} ({label}) seen at {ip or 'unknown IP'} via {source}",
                severity="low",
                key=(mac,),
                source_ip=ip,
                evidence={"mac": mac, "vendor": vendor, "hostname": hostname, "source": source},
                now=now,
            )

        previous_mac = changes.get("ip_moved_from")
        if not ip or not previous_mac:
            return
        evidence = {"ip": ip, "mac": mac, "previous_mac": previous_mac, "source": source}
        if ip == self.gateway_ip():
            self.emit(
                "arp_spoofing",
                f"Gateway {ip} is now answered by {mac} instead of {previous_mac}: possible man-in-the-middle",
                severity="critical",
                key=(ip, mac),
                source_ip=ip,
                evidence=evidence,
                now=now,
            )
            return
        previous = self.state.devices.get(previous_mac)
        # A DHCP lease handed to a new device is normal once the old owner has gone away.
        if previous and now - previous["last_seen"] <= self.state.devices.active_timeout:
            self.emit(
                "ip_conflict",
                f"{ip} is claimed by {mac} while {previous_mac} is still active",
                severity="medium",
                key=(ip, mac),
                source_ip=ip,
                evidence=evidence,
                now=now,
            )

    def on_dhcp_server(self, server_ip: str, server_mac: str | None, router: str | None) -> None:
        trusted = self.settings.trusted_dhcp_servers
        if not trusted:
            gateway = self.gateway_ip()
            with self._lock:
                if not self._auto_trusted_dhcp:
                    self._auto_trusted_dhcp.add(gateway or server_ip)
                trusted = frozenset(self._auto_trusted_dhcp)
        if server_ip in trusted:
            return
        self.emit(
            "rogue_dhcp",
            f"Unexpected DHCP server {server_ip} ({server_mac or 'unknown MAC'}) offering router {router or 'n/a'}",
            severity="high",
            key=(server_ip,),
            source_ip=server_ip,
            evidence={"server_ip": server_ip, "server_mac": server_mac, "router": router, "trusted": sorted(trusted)},
        )

    # Scans ---------------------------------------------------------------

    def on_tcp_syn(self, src_ip: str, dst_ip: str, dst_port: int, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            ports = self._ports.add((src_ip, dst_ip), dst_port, now)
            hosts = self._hosts.add((src_ip, dst_port), dst_ip, now)
            attempts = (
                self._auth_attempts.add((src_ip, dst_ip, dst_port), now)
                if dst_port in self.settings.auth_ports
                else 0
            )
            sample_ports = sorted(self._ports.values((src_ip, dst_ip)))[:20] if ports >= self.settings.port_scan_threshold else None
            sample_hosts = sorted(self._hosts.values((src_ip, dst_port)))[:20] if hosts >= self.settings.host_sweep_threshold else None
        inbound = not self.is_local(src_ip)
        if sample_ports is not None:
            self.emit(
                "port_scan",
                f"{src_ip} contacted {ports} TCP ports on {dst_ip} in {int(self.settings.scan_window)}s",
                severity="high" if inbound else "medium",
                key=(src_ip, dst_ip),
                source_ip=src_ip,
                destination_ip=dst_ip,
                evidence={"distinct_ports": ports, "window_seconds": self.settings.scan_window, "sample_ports": sample_ports, "inbound": inbound},
                now=now,
            )
        if sample_hosts is not None:
            self.emit(
                "host_sweep",
                f"{src_ip} contacted TCP port {dst_port} on {hosts} hosts in {int(self.settings.scan_window)}s",
                severity="high" if inbound else "medium",
                key=(src_ip, dst_port),
                source_ip=src_ip,
                evidence={"port": dst_port, "distinct_hosts": hosts, "sample_hosts": sample_hosts, "inbound": inbound},
                now=now,
            )

        if attempts >= self.settings.brute_force_threshold:
            service = self.settings.auth_ports[dst_port]
            self.emit(
                "brute_force",
                f"{src_ip} opened {attempts} {service} connections to {dst_ip} in {int(self.settings.brute_force_window)}s",
                severity="high" if inbound else "medium",
                key=(src_ip, dst_ip, dst_port),
                source_ip=src_ip,
                destination_ip=dst_ip,
                evidence={"service": service, "port": dst_port, "attempts": attempts, "window_seconds": self.settings.brute_force_window, "inbound": inbound},
                now=now,
            )

    def on_name_resolution(self, responder_ip: str, target_ip: str, info: dict, now: float | None = None) -> None:
        """Watch LLMNR/NBT-NS answers: Responder-style tools answer every name, including WPAD."""
        if not info.get("is_response"):
            return
        now = time.time() if now is None else now
        name = info["name"]
        with self._lock:
            names = self._poisoned_names.add((responder_ip,), name, now)
            sample = sorted(self._poisoned_names.values((responder_ip,)))[:10]
        sensitive = name.split(".")[0] in SENSITIVE_NAMES
        if not sensitive and names < self.settings.name_poisoning_threshold:
            return
        reason = f"answered the {name.upper()} lookup" if sensitive else f"answered {names} different names"
        self.emit(
            "llmnr_poisoning",
            f"{responder_ip} {reason} over {info['protocol'].upper()}: possible Responder-style credential capture",
            severity="high",
            key=(responder_ip,),
            source_ip=responder_ip,
            destination_ip=target_ip,
            evidence={"protocol": info["protocol"], "names": sample, "answers": info.get("answers", []), "wpad": sensitive},
            now=now,
        )

    def on_icmp_echo(self, src_ip: str, dst_ip: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            hosts = self._hosts.add((src_ip, "icmp"), dst_ip, now)
            sample = sorted(self._hosts.values((src_ip, "icmp")))[:20] if hosts >= self.settings.host_sweep_threshold else None
        if sample is not None:
            self.emit(
                "ping_sweep",
                f"{src_ip} pinged {hosts} hosts in {int(self.settings.scan_window)}s",
                severity="medium",
                key=(src_ip,),
                source_ip=src_ip,
                evidence={"distinct_hosts": hosts, "sample_hosts": sample},
                now=now,
            )

    # Flows ---------------------------------------------------------------

    def on_new_flow(self, flow: dict, now: float | None = None) -> None:
        now = time.time() if now is None else now
        client, server, port = flow["client_ip"], flow["server_ip"], flow.get("server_port")
        client_local, server_local = self.is_local(client), self.is_local(server)

        if self.intel is not None:
            remote = server if client_local else client
            if not self.is_local(remote):
                source = self.intel.match_ip(remote)
                if source:
                    local = client if client_local else server
                    self.emit(
                        "threat_intel_ip",
                        f"{local} exchanged traffic with {remote} listed in {source}",
                        severity="high",
                        key=(local, remote),
                        source_ip=local,
                        destination_ip=remote,
                        evidence={"indicator": remote, "list": source, "server_name": flow.get("server_name"), "port": port},
                        now=now,
                    )

        if client_local and not server_local and port in self.settings.risky_ports:
            service = self.settings.risky_ports[port]
            self.emit(
                "risky_protocol",
                f"{client} opened {service} (port {port}) to Internet host {server}",
                severity="medium",
                key=(client, server, port),
                source_ip=client,
                destination_ip=server,
                evidence={"service": service, "port": port, "protocol": flow["protocol"]},
                now=now,
            )

        if client_local and not server_local and port not in BEACON_IGNORED_PORTS:
            self._track_beacon(client, flow.get("server_name") or server, server, port, now)

        if client_local and not server_local and self.baselines is not None:
            name = flow.get("server_name")
            destination = base_domain(name) if name else server
            finding = self.baselines.add_destination(self.device_key(client), destination, now)
            if finding:
                self.emit(
                    "new_destination",
                    f"{client} contacted {destination}, outside its usual {finding['known_destinations']} destinations",
                    severity="low",
                    key=(client, destination),
                    source_ip=client,
                    destination_ip=server,
                    evidence={**finding, "port": port},
                    now=now,
                )

    # Baselines -----------------------------------------------------------

    def device_key(self, ip: str) -> str:
        return self.state.devices.mac_for_ip(ip) or ip

    def on_traffic(self, events: list[dict], now: float | None = None) -> None:
        """Feed flushed per-IP traffic into volume baselines."""
        if self.baselines is None:
            return
        now = time.time() if now is None else now
        for event in events:
            ip = event["ip"]
            for finding in self.baselines.add_traffic(self.device_key(ip), event["upload"], event["download"], now):
                megabytes = finding["upload_bytes"] / 1024 / 1024
                self.emit(
                    "traffic_anomaly",
                    f"{ip} uploaded {megabytes:.1f} MB in {int(finding['bucket_seconds'] // 60)} min, far above its usual volume",
                    severity="medium",
                    key=(ip,),
                    source_ip=ip,
                    evidence=finding,
                    now=now,
                )

    def on_inbound_accepted(self, flow: dict) -> None:
        """A remote client got an answer from a local server: the service is reachable from outside."""
        client, server, port = flow["client_ip"], flow["server_ip"], flow.get("server_port")
        if self.is_local(client) or not self.is_local(server):
            return
        service = self.settings.risky_ports.get(port)
        self.emit(
            "exposed_service",
            f"{server} answered {flow['protocol']} port {port}{f' ({service})' if service else ''} to Internet host {client}",
            severity="high" if service else "medium",
            key=(server, port),
            source_ip=client,
            destination_ip=server,
            evidence={"port": port, "service": service, "protocol": flow["protocol"]},
        )

    def _track_beacon(self, client: str, target: str, server: str, port, now: float) -> None:
        key = (client, target, port)
        minimum = self.settings.beacon_min_events
        with self._lock:
            times = self._beacons.setdefault(key, deque(maxlen=max(minimum * 2, 16)))
            times.append(now)
            if len(times) < minimum:
                return
            recent = list(times)[-minimum:]
        intervals = [later - earlier for earlier, later in zip(recent, recent[1:])]
        mean = statistics.fmean(intervals)
        if not self.settings.beacon_min_interval <= mean <= self.settings.beacon_max_interval:
            return
        jitter = statistics.pstdev(intervals) / mean
        if jitter > self.settings.beacon_max_jitter:
            return
        self.emit(
            "beaconing",
            f"{client} connects to {target}:{port} every {mean:.0f}s (jitter {jitter:.0%})",
            severity="low",
            key=(client, target, port),
            source_ip=client,
            destination_ip=server,
            evidence={"interval_seconds": round(mean, 1), "jitter": round(jitter, 3), "connections": len(recent), "target": target},
            now=now,
        )

    # Names ---------------------------------------------------------------

    def on_dns_query(self, client_ip: str, name: str, resolver_ip: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        name = name.lower().rstrip(".")
        self._check_domain(client_ip, name, "dns", now)

        allowed = self.settings.allowed_dns_servers
        if allowed and resolver_ip not in allowed:
            self.emit(
                "dns_bypass",
                f"{client_ip} queries unapproved resolver {resolver_ip}",
                severity="low",
                key=(client_ip, resolver_ip),
                source_ip=client_ip,
                destination_ip=resolver_ip,
                evidence={"resolver": resolver_ip, "allowed": sorted(allowed), "query": name},
                now=now,
            )

        labels = name.split(".")
        longest = max((len(label) for label in labels), default=0)
        subdomain = ".".join(labels[:-2])
        with self._lock:
            unique = self._dns_names.add((client_ip, base_domain(name)), name, now)
        suspicious_shape = (
            longest >= self.settings.dns_tunnel_label_length
            or len(name) >= self.settings.dns_tunnel_name_length
        ) and shannon_entropy(subdomain) >= 3.5
        if suspicious_shape or unique >= self.settings.dns_tunnel_unique_names:
            self.emit(
                "dns_tunnel",
                f"{client_ip} sends unusual DNS queries under {base_domain(name)}",
                severity="medium",
                key=(client_ip, base_domain(name)),
                source_ip=client_ip,
                evidence={
                    "example": name[:200],
                    "longest_label": longest,
                    "entropy": round(shannon_entropy(subdomain), 2),
                    "unique_names_in_window": unique,
                },
                now=now,
            )

    def on_server_name(self, client_ip: str, name: str, source: str) -> None:
        self._check_domain(client_ip, name, source, time.time())

    def _check_domain(self, client_ip: str, name: str, source: str, now: float) -> None:
        if self.intel is None:
            return
        match = self.intel.match_domain(name)
        if not match:
            return
        listed, list_name = match
        self.emit(
            "threat_intel_domain",
            f"{client_ip} looked up or contacted {name} (listed as {listed} in {list_name})",
            severity="high",
            key=(client_ip, listed),
            source_ip=client_ip,
            evidence={"domain": name, "indicator": listed, "list": list_name, "seen_via": source},
            now=now,
        )
