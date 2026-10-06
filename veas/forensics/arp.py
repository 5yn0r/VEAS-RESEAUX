"""ARP analysis: poisoning (one IP announced by several MACs) and ARP scans."""

from __future__ import annotations

from collections import Counter, defaultdict

from scapy.all import ARP

from veas.forensics.model import Frames, finding
from veas.protocols import parse_arp

SCAN_THRESHOLD = 20


class ArpAnalyzer:
    category = "arp"

    def __init__(self) -> None:
        self.ops: Counter = Counter()
        self.gratuitous = 0
        self.claims: dict[str, dict[str, Frames]] = defaultdict(lambda: defaultdict(Frames))
        self.requests: dict[str, dict] = defaultdict(lambda: {"targets": set(), "frames": Frames()})
        self.mac_ips: dict[str, set] = defaultdict(set)

    def process(self, packet, frame: int, ts: float) -> None:
        if ARP not in packet:
            return
        info = parse_arp(packet)
        if not info:
            return
        self.ops[info["op"]] += 1
        sender_ip, sender_mac = info["sender_ip"], info["sender_mac"]
        if sender_ip == info["target_ip"]:
            self.gratuitous += 1
        if sender_ip and sender_ip != "0.0.0.0":
            self.claims[sender_ip][sender_mac].add(frame, ts)
            self.mac_ips[sender_mac].add(sender_ip)
        if info["op"] == "request" and info["target_ip"] != sender_ip:
            entry = self.requests[sender_mac]
            entry["targets"].add(info["target_ip"])
            entry["frames"].add(frame, ts)

    def report(self) -> dict:
        return {
            "stats": {"packets": sum(self.ops.values()), "requests": self.ops["request"], "replies": self.ops["reply"], "gratuitous": self.gratuitous},
            "tables": {
                "ip_mac": sorted(
                    (
                        {"ip": ip, "macs": [{"mac": mac, "packets": frames.count, "first_frame": frames.numbers[0]} for mac, frames in macs.items()]}
                        for ip, macs in self.claims.items()
                    ),
                    key=lambda row: (-len(row["macs"]), row["ip"]),
                )[:200],
            },
            "findings": self._findings(),
        }

    def _findings(self) -> list[dict]:
        findings = []
        for ip, macs in self.claims.items():
            if len(macs) < 2:
                continue
            ordered = sorted(macs.items(), key=lambda item: item[1].first_ts or 0)
            legitimate, (attacker, attacker_frames) = ordered[0][0], ordered[-1]
            frames = Frames()
            for _, mac_frames in ordered:
                frames.merge(mac_frames)
            other_ips = sorted(self.mac_ips[attacker] - {ip})
            # If the first owner stopped before the newcomer appeared, it is likely a DHCP re-assignment.
            overlap = any((frames_.last_ts or 0) >= (attacker_frames.first_ts or 0) for _, frames_ in ordered[:-1])
            severity = "critical" if overlap and (other_ips or attacker_frames.count >= 5) else "high" if overlap else "low"
            findings.append(
                finding(
                    "arp", "arp_spoofing", severity,
                    "Usurpation ARP (empoisonnement de cache)",
                    (
                        f"L'adresse {ip} est annoncée par {len(macs)} cartes réseau : {legitimate} d'abord, puis {attacker} "
                        f"(trame {attacker_frames.numbers[0]}, {attacker_frames.count} annonces)."
                        + (f" {attacker} annonce aussi {', '.join(other_ips[:5])}." if other_ips else "")
                        + ("" if overlap else " Les deux cartes ne sont jamais actives en même temps : il peut s'agir d'une réattribution d'adresse.")
                    ),
                    explanation=(
                        "Avec ARP, une machine dit « l'adresse IP X, c'est moi ». Rien ne vérifie cette affirmation : un attaquant "
                        "qui annonce l'IP de la passerelle ou d'un serveur reçoit le trafic des victimes et peut le lire ou le modifier "
                        "(homme du milieu, outils arpspoof, Ettercap, Bettercap)."
                    ),
                    recommendation=(
                        f"Localiser la carte {attacker} (table MAC du commutateur), la déconnecter, purger les caches ARP des victimes "
                        "et activer la Dynamic ARP Inspection sur les commutateurs."
                    ),
                    mitre=["T1557.002"], source=other_ips[0] if other_ips else attacker, target=ip, frames=frames,
                    wireshark_filter=f"arp.src.proto_ipv4=={ip}",
                    evidence={"ip": ip, "macs": [{"mac": mac, "announcements": data.count, "first_frame": data.numbers[0]} for mac, data in ordered], "attacker_mac": attacker, "attacker_other_ips": other_ips[:20]},
                )
            )
        for mac, data in self.requests.items():
            if len(data["targets"]) < SCAN_THRESHOLD:
                continue
            own = sorted(self.mac_ips[mac])
            findings.append(
                finding(
                    "arp", "arp_scan", "medium",
                    "Balayage ARP du réseau local",
                    f"La carte {mac}{f' ({own[0]})' if own else ''} a demandé l'adresse de {len(data['targets'])} IP différentes.",
                    explanation="Sur un réseau local, demander en ARP « qui a l'IP X ? » pour toute la plage est la façon la plus rapide et la plus fiable de trouver les machines présentes (arp-scan, netdiscover, nmap -sn en local).",
                    recommendation="Vérifier si cette carte appartient à un poste d'administration ; sinon l'isoler.",
                    mitre=["T1018"], source=own[0] if own else mac, frames=data["frames"],
                    wireshark_filter=f"arp.opcode==1 && eth.src=={mac}",
                    evidence={"targets": len(data["targets"]), "targets_sample": sorted(data["targets"])[:30]},
                )
            )
        return findings
