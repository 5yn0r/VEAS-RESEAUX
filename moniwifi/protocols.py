"""Metadata extractors for ARP, DHCP, DNS/mDNS, TLS SNI, and HTTP Host.

Payload bytes are inspected transiently to read a name and are never stored.
"""

from __future__ import annotations

from scapy.all import ARP, IP, TCP, UDP, Ether
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNSHeader, NBNSQueryRequest, NBNSQueryResponse

DHCP_MESSAGE_TYPES = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


def _text(value) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value).rstrip(".")


def parse_arp(packet) -> dict | None:
    if ARP not in packet:
        return None
    arp = packet[ARP]
    return {
        "op": "request" if arp.op == 1 else "reply" if arp.op == 2 else str(arp.op),
        "sender_mac": str(arp.hwsrc).lower(),
        "sender_ip": arp.psrc,
        "target_ip": arp.pdst,
        "ether_src": str(packet[Ether].src).lower() if Ether in packet else None,
    }


def parse_dhcp(packet) -> dict | None:
    if DHCP not in packet or BOOTP not in packet:
        return None
    options = {}
    for option in packet[DHCP].options:
        if isinstance(option, tuple) and len(option) >= 2:
            options[option[0]] = option[1] if len(option) == 2 else option[1:]
    message_type = options.get("message-type")
    bootp = packet[BOOTP]
    result = {
        "message_type": DHCP_MESSAGE_TYPES.get(message_type, str(message_type)),
        "client_mac": bytes(bootp.chaddr[:6]).hex(":"),
        "client_ip": bootp.ciaddr if bootp.ciaddr != "0.0.0.0" else None,
        "offered_ip": bootp.yiaddr if bootp.yiaddr != "0.0.0.0" else None,
        "hostname": _text(options["hostname"]) if "hostname" in options else None,
        "vendor_class": _text(options["vendor_class_id"]) if "vendor_class_id" in options else None,
        "requested_ip": options.get("requested_addr"),
        "server_id": options.get("server_id"),
        "router": options.get("router"),
        "server_ip": packet[IP].src if IP in packet and bootp.op == 2 else None,
        "server_mac": str(packet[Ether].src).lower() if Ether in packet and bootp.op == 2 else None,
    }
    if isinstance(result["router"], (list, tuple)):
        result["router"] = result["router"][0]
    return result


MDNS_GROUPS = {"224.0.0.251", "ff02::fb"}


def _is_mdns(packet) -> bool:
    udp = packet[UDP]
    if udp.sport == 5353 and udp.dport == 5353:
        return True
    return IP in packet and packet[IP].dst in MDNS_GROUPS


def parse_dns(packet) -> dict | None:
    if DNS not in packet or UDP not in packet:
        return None
    dns = packet[DNS]
    if not dns.qdcount and not dns.ancount:
        return None
    queries = []
    for index in range(dns.qdcount or 0):
        try:
            question = dns.qd[index]
        except IndexError:
            break
        queries.append({"name": _text(question.qname), "type": DNS_TYPES.get(question.qtype, str(question.qtype))})
    answers = []
    for index in range(dns.ancount or 0):
        try:
            record = dns.an[index]
        except IndexError:
            break
        record_type = DNS_TYPES.get(record.type, str(record.type))
        data = record.rdata
        if isinstance(data, (list, tuple)):
            data = data[0] if data else ""
        answers.append({"name": _text(record.rrname), "type": record_type, "data": _text(data)})
    return {
        "is_response": bool(dns.qr),
        "multicast": _is_mdns(packet),
        "rcode": dns.rcode,
        "queries": queries,
        "answers": answers,
    }


def parse_name_resolution(packet) -> dict | None:
    """Decode LLMNR (UDP 5355) and NBT-NS (UDP 137) queries and responses.

    These Windows fallback protocols are what tools such as Responder answer
    to capture credentials.
    """
    if UDP not in packet:
        return None
    udp = packet[UDP]
    if LLMNRQuery in packet or LLMNRResponse in packet:
        layer = packet[LLMNRResponse] if LLMNRResponse in packet else packet[LLMNRQuery]
        if not layer.qdcount:
            return None
        answers = []
        for index in range(layer.ancount or 0):
            try:
                answers.append(_text(layer.an[index].rdata))
            except (IndexError, AttributeError):
                break
        return {
            "protocol": "llmnr",
            "is_response": bool(layer.qr),
            "name": _text(layer.qd.qname).lower(),
            "answers": answers,
        }
    if (udp.sport == 137 or udp.dport == 137) and NBNSHeader in packet:
        header = packet[NBNSHeader]
        if header.RESPONSE and NBNSQueryResponse in packet:
            response = packet[NBNSQueryResponse]
            return {
                "protocol": "nbns",
                "is_response": True,
                "name": _text(response.RR_NAME).strip().lower(),
                "answers": [entry.NB_ADDRESS for entry in (response.ADDR_ENTRY or [])],
            }
        if not header.RESPONSE and NBNSQueryRequest in packet:
            return {
                "protocol": "nbns",
                "is_response": False,
                "name": _text(packet[NBNSQueryRequest].QUESTION_NAME).strip().lower(),
                "answers": [],
            }
    return None


def extract_sni(payload: bytes) -> str | None:
    """Return the server name from a TLS ClientHello, or None."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        position = 9 + 2 + 32  # record header, handshake header, version, random
        session_length = payload[position]
        position += 1 + session_length
        cipher_length = int.from_bytes(payload[position : position + 2], "big")
        position += 2 + cipher_length
        compression_length = payload[position]
        position += 1 + compression_length
        extensions_end = position + 2 + int.from_bytes(payload[position : position + 2], "big")
        position += 2
        while position + 4 <= min(extensions_end, len(payload)):
            ext_type = int.from_bytes(payload[position : position + 2], "big")
            ext_length = int.from_bytes(payload[position + 2 : position + 4], "big")
            position += 4
            if ext_type == 0:
                # server_name_list length (2), name type (1), name length (2), name
                name_length = int.from_bytes(payload[position + 3 : position + 5], "big")
                name = payload[position + 5 : position + 5 + name_length]
                return name.decode("ascii", errors="replace").lower() or None
            position += ext_length
    except (IndexError, ValueError):
        return None
    return None


def extract_http_host(payload: bytes) -> str | None:
    if not payload.startswith(HTTP_METHODS):
        return None
    header_end = payload.find(b"\r\n\r\n")
    headers = payload[: header_end if header_end != -1 else 4096]
    for line in headers.split(b"\r\n")[1:]:
        if line[:5].lower() == b"host:":
            host = line[5:].strip().decode("ascii", errors="replace").lower()
            return host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return None


def extract_server_name(packet) -> tuple[str, str] | None:
    """Return (name, source) for a TLS ClientHello or HTTP request, else None."""
    if TCP not in packet:
        return None
    # Scapy may dissect port 443/80 payloads into TLS/HTTP layers, so read the raw TCP payload.
    payload = bytes(packet[TCP].payload)
    if not payload:
        return None
    name = extract_sni(payload)
    if name:
        return name, "tls"
    name = extract_http_host(payload)
    if name:
        return name, "http"
    return None
