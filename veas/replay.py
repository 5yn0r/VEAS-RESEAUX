"""Analyse a pcap file offline with the same pipeline as live capture.

Usage: python -m veas.replay capture.pcap [--network 192.168.1.0/24] [--gateway 192.168.1.1]
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from collections import Counter

from scapy.all import IP, PcapReader

from veas.detectors import DetectionSettings
from veas.monitor import NetworkMonitor, settings_from_config
from veas.netinfo import StaticNetworkContext
from veas.siem import JsonFileSink, SiemExporter
from veas.state import MonitorState
from veas.threatintel import ThreatIntel


class NullSocketIO:
    def emit(self, event, payload):
        pass


def infer_network(path: str, sample: int = 5000) -> str:
    """Guess the LAN as the most common private /24 among packet sources."""
    counts: Counter = Counter()
    with PcapReader(path) as reader:
        for index, packet in enumerate(reader):
            if index >= sample:
                break
            if IP in packet:
                address = ipaddress.ip_address(packet[IP].src)
                if address.is_private and not address.is_multicast and str(address) != "0.0.0.0":
                    counts[str(ipaddress.ip_network(f"{address}/24", strict=False))] += 1
    if not counts:
        raise ValueError("cannot infer the local network; pass --network")
    return counts.most_common(1)[0][0]


def analyse(
    path: str,
    network: str | None = None,
    gateway: str | None = None,
    intel_dir: str | None = None,
    settings: DetectionSettings | None = None,
    siem_json: str | None = None,
) -> dict:
    network = network or infer_network(path)
    state = MonitorState(max_alerts=100000, max_packet_history=1, new_device_learning_period=0)
    monitor = NetworkMonitor(
        socketio=NullSocketIO(),
        state=state,
        network=StaticNetworkContext(network, gateway),
        intel=ThreatIntel(intel_dir),
        detection_settings=settings or settings_from_config(),
        siem=SiemExporter([JsonFileSink(siem_json)] if siem_json else []),
    )
    monitor.intel.reload()

    packets = 0
    first = last = None
    with PcapReader(path) as reader:
        for packet in reader:
            packets += 1
            first = first if first is not None else float(packet.time)
            last = float(packet.time)
            monitor.packet_callback(packet)
            if packets % 5000 == 0:
                monitor.correlate(state.flush_traffic()[1])
    monitor.correlate(state.flush_traffic()[1])
    monitor.siem.drain()
    flows = state.flows.snapshot(limit=100000)
    domains = Counter(entry["query"] for entry in state.domains.recent(limit=100000))

    return {
        "file": path,
        "network": network,
        "gateway": gateway,
        "packets": packets,
        "start": first,
        "end": last,
        "devices": state.devices.all(),
        "flows": len(flows),
        "top_domains": domains.most_common(20),
        "alerts": state.alerts_snapshot(limit=100000),
        "incidents": monitor.incidents.list(limit=1000),
    }


def format_report(report: dict) -> str:
    lines = [
        f"File:      {report['file']}",
        f"Network:   {report['network']} (gateway {report['gateway'] or 'unknown'})",
        f"Packets:   {report['packets']}   Flows: {report['flows']}   Devices: {len(report['devices'])}",
        "",
        f"Incidents ({len(report['incidents'])}):",
    ]
    for incident in report["incidents"]:
        lines.append(f"  [{incident['severity'].upper():8}] score {incident['score']:3}  {incident['summary']}")
        lines += [f"             why: {reason}" for reason in incident["reasons"]]
    lines += ["", f"Alerts ({len(report['alerts'])}):"]
    lines += [f"  [{alert['severity']:8}] {alert['message']}" for alert in report["alerts"]]
    if report["top_domains"]:
        lines += ["", "Top DNS queries:"]
        lines += [f"  {count:5}  {name}" for name, count in report["top_domains"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyse a pcap with VEAS RÉSEAUX detections.")
    parser.add_argument("pcap")
    parser.add_argument("--network", help="local network CIDR (inferred when omitted)")
    parser.add_argument("--gateway", help="gateway IP, enables ARP-spoofing detection")
    parser.add_argument("--intel-dir", help="directory of threat-intel *.txt files")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    parser.add_argument("--siem-json", help="also write alerts and incidents as ECS JSON Lines for a SIEM")
    args = parser.parse_args(argv)

    try:
        report = analyse(args.pcap, args.network, args.gateway, args.intel_dir, siem_json=args.siem_json)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, default=str) if args.json else format_report(report))
    return 1 if any(incident["severity"] in ("high", "critical") for incident in report["incidents"]) else 0


if __name__ == "__main__":
    sys.exit(main())
