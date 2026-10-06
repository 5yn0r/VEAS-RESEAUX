"""DNS analysis: queries, failures, generated domains, tunnelling."""

from __future__ import annotations

from collections import Counter, defaultdict

from scapy.all import IP, UDP, IPv6
from scapy.layers.dns import DNS

from veas.detectors import base_domain, shannon_entropy
from veas.forensics.model import Frames, finding, ip_filter, top
from veas.protocols import parse_dns

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
NXDOMAIN_MIN = 20
TUNNEL_UNIQUE_NAMES = 50
TUNNEL_LABEL_LENGTH = 40
TUNNEL_ENTROPY = 3.5
TXT_MIN = 30


class DnsAnalyzer:
    category = "dns"

    def __init__(self) -> None:
        self.queries = 0
        self.responses = 0
        self.types: Counter = Counter()
        self.rcodes: Counter = Counter()
        self.names: Counter = Counter()
        self.clients: Counter = Counter()
        self.resolvers: Counter = Counter()
        self.nxdomain: dict[str, dict] = defaultdict(lambda: {"names": Counter(), "frames": Frames()})
        self.subdomains: dict[tuple, dict] = defaultdict(lambda: {"names": set(), "longest": 0, "frames": Frames(), "txt": 0, "sample": ""})

    def process(self, packet, frame: int, ts: float) -> None:
        if DNS not in packet or UDP not in packet:
            return
        info = parse_dns(packet)
        if not info or info["multicast"]:
            return
        layer = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
        if layer is None:
            return
        if not info["is_response"]:
            self.queries += 1
            self.clients[layer.src] += 1
            self.resolvers[layer.dst] += 1
            for query in info["queries"]:
                name = query["name"].lower()
                self.types[query["type"]] += 1
                self.names[name] += 1
                domain = base_domain(name)
                entry = self.subdomains[(layer.src, domain)]
                entry["names"].add(name)
                entry["frames"].add(frame, ts)
                longest = max((len(label) for label in name.split(".")), default=0)
                if longest > entry["longest"]:
                    entry["longest"], entry["sample"] = longest, name
                if query["type"] == "TXT":
                    entry["txt"] += 1
        else:
            self.responses += 1
            self.rcodes[RCODES.get(info["rcode"], str(info["rcode"]))] += 1
            if info["rcode"] == 3:
                entry = self.nxdomain[layer.dst]
                for query in info["queries"]:
                    entry["names"][query["name"].lower()] += 1
                entry["frames"].add(frame, ts)

    def report(self) -> dict:
        return {
            "stats": {
                "queries": self.queries,
                "responses": self.responses,
                "types": dict(self.types.most_common()),
                "response_codes": dict(self.rcodes.most_common()),
            },
            "tables": {
                "top_names": top(self.names, 30, "name"),
                "clients": top(self.clients, 20, "ip"),
                "resolvers": top(self.resolvers, 10, "ip"),
                "nxdomain_by_client": sorted(
                    ({"client": client, "count": data["frames"].count, "distinct_names": len(data["names"])} for client, data in self.nxdomain.items()),
                    key=lambda row: row["count"], reverse=True,
                )[:20],
            },
            "findings": self._findings(),
        }

    def _findings(self) -> list[dict]:
        findings = []
        for client, data in self.nxdomain.items():
            if data["frames"].count < NXDOMAIN_MIN:
                continue
            names = list(data["names"])
            entropy = sum(shannon_entropy(name.split(".")[0]) for name in names) / len(names)
            generated = entropy >= 3.0
            findings.append(
                finding(
                    "dns", "nxdomain_burst", "high" if generated else "medium",
                    "Nombreuses résolutions DNS en échec (NXDOMAIN)" + (" : domaines générés par algorithme probables" if generated else ""),
                    f"{client} a reçu {data['frames'].count} réponses « domaine inexistant » pour {len(names)} noms différents.",
                    explanation=(
                        "Certains logiciels malveillants calculent chaque jour des centaines de noms de domaine aléatoires (DGA) et essaient "
                        "de les joindre jusqu'à trouver celui que l'attaquant a réellement enregistré. Le résultat : une rafale d'échecs DNS "
                        "pour des noms qui ressemblent à du bruit."
                    ),
                    recommendation="Examiner la machine cliente (processus à l'origine des requêtes) et bloquer les domaines qui finissent par répondre.",
                    mitre=["T1568.002"], source=client, frames=data["frames"],
                    wireshark_filter=f"dns.flags.rcode==3 && {ip_filter('ip.dst', client)}",
                    evidence={"sample_names": [name for name, _ in data["names"].most_common(20)], "average_label_entropy": round(entropy, 2)},
                )
            )
        for (client, domain), data in self.subdomains.items():
            unique = len(data["names"])
            entropy = shannon_entropy(data["sample"].split(".")[0]) if data["sample"] else 0
            long_labels = data["longest"] >= TUNNEL_LABEL_LENGTH and entropy >= TUNNEL_ENTROPY
            if not (unique >= TUNNEL_UNIQUE_NAMES or long_labels or data["txt"] >= TXT_MIN):
                continue
            description = f"{client} a interrogé {unique} sous-domaines différents de {domain}"
            if long_labels:
                description += f", avec des étiquettes de {data['longest']} caractères"
            if data["txt"]:
                description += f", et a fait {data['txt']} requêtes TXT"
            description += "."
            findings.append(
                finding(
                    "dns", "dns_tunnel", "high",
                    "Tunnel DNS probable (exfiltration ou canal de commande)",
                    description,
                    explanation=(
                        "Des outils comme iodine, dnscat2 ou DNSExfiltrator encodent des données dans les sous-domaines "
                        "(« ZXhmaWx0cmF0aW9u.attaquant.com ») et récupèrent les réponses dans des enregistrements TXT. Le DNS passe "
                        "presque toujours le pare-feu, d'où son intérêt pour un attaquant."
                    ),
                    recommendation=f"Bloquer {domain} sur le résolveur, isoler {client} et décoder les sous-domaines pour savoir ce qui a été transmis.",
                    mitre=["T1071.004", "T1048"], source=client, target=domain, frames=data["frames"],
                    wireshark_filter=f"dns.qry.name contains \"{domain}\" && {ip_filter('ip.src', client)}",
                    evidence={"domain": domain, "unique_names": unique, "longest_label": data["longest"], "label_entropy": round(entropy, 2), "txt_queries": data["txt"], "example": data["sample"][:200]},
                )
            )
        return findings
