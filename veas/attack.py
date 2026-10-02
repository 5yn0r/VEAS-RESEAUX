"""MITRE ATT&CK (Enterprise) techniques associated with each alert type.

Reference: https://attack.mitre.org/ . A mapping states which adversary
technique the detected behaviour is evidence of; it is not proof that the
technique was used (a port scan can come from an administrator).
"""

from __future__ import annotations

TECHNIQUES = {
    "T1018": ("Remote System Discovery", ["discovery"]),
    "T1021": ("Remote Services", ["lateral-movement"]),
    "T1046": ("Network Service Discovery", ["discovery"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["exfiltration"]),
    "T1071": ("Application Layer Protocol", ["command-and-control"]),
    "T1071.004": ("Application Layer Protocol: DNS", ["command-and-control"]),
    "T1110": ("Brute Force", ["credential-access"]),
    "T1133": ("External Remote Services", ["initial-access", "persistence"]),
    "T1200": ("Hardware Additions", ["initial-access"]),
    "T1557": ("Adversary-in-the-Middle", ["credential-access", "collection"]),
    "T1557.001": ("LLMNR/NBT-NS Poisoning and SMB Relay", ["credential-access", "collection"]),
    "T1557.002": ("ARP Cache Poisoning", ["credential-access", "collection"]),
    "T1557.003": ("DHCP Spoofing", ["credential-access", "collection"]),
    "T1568": ("Dynamic Resolution", ["command-and-control"]),
    "T1572": ("Protocol Tunneling", ["command-and-control"]),
}

ALERT_TECHNIQUES = {
    "new_device": ["T1200"],
    "arp_spoofing": ["T1557.002"],
    "ip_conflict": ["T1557"],
    "rogue_dhcp": ["T1557.003"],
    "llmnr_poisoning": ["T1557.001"],
    "port_scan": ["T1046"],
    "host_sweep": ["T1046"],
    "ping_sweep": ["T1018"],
    "brute_force": ["T1110"],
    "threat_intel_ip": ["T1071"],
    "threat_intel_domain": ["T1071", "T1568"],
    "risky_protocol": ["T1021"],
    "exposed_service": ["T1133"],
    "beaconing": ["T1071"],
    "dns_tunnel": ["T1071.004", "T1572"],
    "dns_bypass": ["T1071.004"],
    "traffic_anomaly": ["T1048"],
    "new_destination": ["T1071"],
}


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def techniques_for(alert_type: str) -> list[dict]:
    return [
        {
            "id": technique_id,
            "name": TECHNIQUES[technique_id][0],
            "tactics": list(TECHNIQUES[technique_id][1]),
            "url": technique_url(technique_id),
        }
        for technique_id in ALERT_TECHNIQUES.get(alert_type, [])
    ]


def tactics_for(alert_types) -> list[str]:
    tactics: list[str] = []
    for alert_type in alert_types:
        for technique in techniques_for(alert_type):
            tactics += [tactic for tactic in technique["tactics"] if tactic not in tactics]
    return tactics
