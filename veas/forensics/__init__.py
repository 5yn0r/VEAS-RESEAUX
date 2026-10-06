"""Forensic analysis of packet captures (Wireshark / tcpdump .pcap and .pcapng)."""

from veas.forensics.engine import analyse_pcap, detect_format

__all__ = ["analyse_pcap", "detect_format"]
