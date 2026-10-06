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
    "T1059": ("Command and Scripting Interpreter", ["execution"]),
    "T1083": ("File and Directory Discovery", ["discovery"]),
    "T1095": ("Non-Application Layer Protocol", ["command-and-control"]),
    "T1105": ("Ingress Tool Transfer", ["command-and-control"]),
    "T1190": ("Exploit Public-Facing Application", ["initial-access"]),
    "T1498": ("Network Denial of Service", ["impact"]),
    "T1499": ("Endpoint Denial of Service", ["impact"]),
    "T1505.003": ("Server Software Component: Web Shell", ["persistence"]),
    "T1552": ("Unsecured Credentials", ["credential-access"]),
    "T1568.002": ("Dynamic Resolution: Domain Generation Algorithms", ["command-and-control"]),
    "T1595": ("Active Scanning", ["reconnaissance"]),
    "T1595.003": ("Active Scanning: Wordlist Scanning", ["reconnaissance"]),
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


def technique(technique_id: str) -> dict:
    name, tactics = TECHNIQUES[technique_id]
    return {"id": technique_id, "name": name, "tactics": list(tactics), "url": technique_url(technique_id)}


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
