"""Capture-wide statistics: volume, protocol hierarchy, endpoints, conversations, histogram."""

from __future__ import annotations

from array import array
from collections import Counter

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, IPv6
from scapy.layers.dns import DNS

from veas.forensics.model import is_private

SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5355: "LLMNR", 5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis",
    8000: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch", 27017: "MongoDB",
}
LINK_TYPES = {1: "Ethernet", 101: "IP brut", 105: "802.11", 113: "Linux cooked (SLL)", 127: "802.11 radiotap", 228: "IPv4 brut", 276: "Linux cooked v2 (SLL2)"}
HISTOGRAM_BUCKETS = 60
TOP = 25


def service_name(port: int | None) -> str | None:
    return SERVICES.get(port) if port is not None else None


def guess_os(ttl: int | None, window: int | None = None) -> str | None:
    """Initial TTL (and SYN window) of common stacks; a hint, not proof."""
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux / Android / macOS" if window not in (8192, 65535) else "macOS / BSD"
    if ttl <= 128:
        return "Windows"
    return "Équipement réseau / Solaris"


def _ip_layer(packet):
    if IP in packet:
        return packet[IP], packet[IP].ttl
    if IPv6 in packet:
        return packet[IPv6], packet[IPv6].hlim
    return None, None


class Overview:
    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.timestamps = array("d")
        self.protocols: Counter = Counter()
        self.endpoints: dict[str, dict] = {}
        self.conversations: dict[tuple, dict] = {}
        self.ports: Counter = Counter()

    def process(self, packet, frame: int, ts: float) -> None:
        size = len(packet)
        self.packets += 1
        self.bytes += size
        self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
        self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        self.timestamps.append(ts)

        if Ether in packet:
            self.protocols["Ethernet"] += 1
        if ARP in packet:
            self.protocols["ARP"] += 1
            return
        layer, ttl = _ip_layer(packet)
        if layer is None:
            self.protocols["Autre"] += 1
            return
        self.protocols["IPv4" if IP in packet else "IPv6"] += 1
        protocol, sport, dport = "IP", None, None
        if TCP in packet:
            protocol, sport, dport = "TCP", packet[TCP].sport, packet[TCP].dport
            self.protocols["TCP"] += 1
            payload = bytes(packet[TCP].payload)
            if payload[:4] in (b"GET ", b"POST", b"HTTP", b"PUT ", b"HEAD") or payload[:7] in (b"DELETE ", b"OPTIONS"):
                self.protocols["HTTP"] += 1
            elif payload[:1] == b"\x16" and payload[1:2] == b"\x03":
                self.protocols["TLS"] += 1
        elif UDP in packet:
            protocol, sport, dport = "UDP", packet[UDP].sport, packet[UDP].dport
            self.protocols["UDP"] += 1
            if DNS in packet:
                self.protocols["DNS"] += 1
        elif ICMP in packet or getattr(layer, "nh", None) == 58:
            protocol = "ICMP"
            self.protocols["ICMP"] += 1
        else:
            self.protocols["Autre IP"] += 1

        src, dst = layer.src, layer.dst
        syn = TCP in packet and packet[TCP].flags & 0x12 == 0x02
        for address, sent in ((src, True), (dst, False)):
            endpoint = self.endpoints.setdefault(
                address, {"ip": address, "packets_sent": 0, "packets_received": 0, "bytes_sent": 0, "bytes_received": 0, "ttl": None, "syn_window": None}
            )
            endpoint["packets_sent" if sent else "packets_received"] += 1
            endpoint["bytes_sent" if sent else "bytes_received"] += size
        sender = self.endpoints[src]
        if syn:
            sender["ttl"], sender["syn_window"] = ttl, packet[TCP].window
        elif sender["ttl"] is None or (sender["syn_window"] is None and ttl > sender["ttl"]):
            sender["ttl"] = ttl

        key = (protocol, *sorted((src, dst)))
        conversation = self.conversations.setdefault(
            key, {"protocol": protocol, "a": key[1], "b": key[2], "packets": 0, "bytes": 0, "first_seen": ts, "last_seen": ts, "first_frame": frame}
        )
        conversation["packets"] += 1
        conversation["bytes"] += size
        conversation["last_seen"] = max(conversation["last_seen"], ts)
        # Server ports: TCP ports that received a SYN, UDP ports that look like a service.
        if syn:
            self.ports[("TCP", dport)] += 1
        elif protocol == "UDP" and (dport in SERVICES or dport < sport):
            self.ports[("UDP", dport)] += 1

    def report(self) -> dict:
        duration = (self.last_ts - self.first_ts) if self.packets else 0.0
        endpoints = sorted(self.endpoints.values(), key=lambda item: item["packets_sent"] + item["packets_received"], reverse=True)
        for endpoint in endpoints:
            endpoint["private"] = is_private(endpoint["ip"])
            endpoint["os_guess"] = guess_os(endpoint["ttl"], endpoint["syn_window"])
        conversations = sorted(self.conversations.values(), key=lambda item: item["bytes"], reverse=True)[:TOP]
        for conversation in conversations:
            conversation["duration"] = conversation["last_seen"] - conversation["first_seen"]
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "start": self.first_ts,
            "end": self.last_ts,
            "duration": duration,
            "packets_per_second": self.packets / duration if duration else None,
            "bits_per_second": self.bytes * 8 / duration if duration else None,
            "protocols": dict(self.protocols.most_common()),
            "endpoints_total": len(endpoints),
            "endpoints": endpoints[:TOP],
            "conversations": conversations,
            "top_ports": [
                {"protocol": protocol, "port": port, "service": service_name(port), "count": count}
                for (protocol, port), count in self.ports.most_common(TOP)
            ],
            "histogram": self._histogram(duration),
        }

    def endpoint(self, address: str) -> dict | None:
        return self.endpoints.get(address)

    def _histogram(self, duration: float) -> dict:
        if not self.timestamps:
            return {"bucket_seconds": 0, "counts": []}
        buckets = HISTOGRAM_BUCKETS if duration > 0 else 1
        width = duration / buckets if duration > 0 else 1.0
        counts = [0] * buckets
        for ts in self.timestamps:
            counts[min(int((ts - self.first_ts) / width), buckets - 1)] += 1
        return {"bucket_seconds": width, "counts": counts}
