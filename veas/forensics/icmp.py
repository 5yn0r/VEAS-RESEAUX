"""ICMP analysis: message types, echo pairing and RTT, sweeps, scans, tunnels, redirects, floods."""

from __future__ import annotations

from collections import Counter, defaultdict

from scapy.all import ICMP, IP, IPv6, Ether
from scapy.layers.inet import IPerror, UDPerror

from veas.forensics.model import Frames, finding, ip_filter, top

ICMP_TYPES = {
    0: "Echo reply (réponse ping)", 3: "Destination injoignable", 4: "Source quench", 5: "Redirection",
    8: "Echo request (ping)", 9: "Annonce de routeur", 10: "Sollicitation de routeur", 11: "Temps dépassé",
    12: "Problème de paramètre", 13: "Timestamp request", 14: "Timestamp reply", 15: "Information request",
    16: "Information reply", 17: "Address mask request", 18: "Address mask reply",
}
UNREACHABLE_CODES = {
    0: "réseau injoignable", 1: "hôte injoignable", 2: "protocole injoignable", 3: "port injoignable",
    4: "fragmentation nécessaire (DF)", 5: "routage source impossible", 6: "réseau inconnu", 7: "hôte inconnu",
    9: "réseau interdit par l'administrateur", 10: "hôte interdit par l'administrateur",
    13: "communication interdite (filtrage)",
}
TIME_EXCEEDED_CODES = {0: "TTL expiré en transit", 1: "délai de réassemblage dépassé"}
REDIRECT_CODES = {0: "pour le réseau", 1: "pour l'hôte", 2: "pour le TOS et le réseau", 3: "pour le TOS et l'hôte"}
ICMPV6_TYPES = {
    1: "Destination injoignable", 2: "Paquet trop grand", 3: "Temps dépassé", 4: "Problème de paramètre",
    128: "Echo request (ping)", 129: "Echo reply (réponse ping)", 133: "Sollicitation de routeur",
    134: "Annonce de routeur", 135: "Sollicitation de voisin", 136: "Annonce de voisin", 137: "Redirection",
}
RECON_TYPES = {13: "Timestamp", 15: "Information", 17: "Address mask"}

SWEEP_THRESHOLD = 10
UDP_SCAN_THRESHOLD = 10
TUNNEL_MIN_PACKETS = 5
TUNNEL_MIN_PAYLOAD = 64
FLOOD_MIN_PACKETS = 100
FLOOD_MIN_RATE = 50.0
SMURF_THRESHOLD = 3
TRACEROUTE_MIN_HOPS = 3


def type_label(version: int, icmp_type: int, code: int) -> str:
    if version == 6:
        return ICMPV6_TYPES.get(icmp_type, f"ICMPv6 type {icmp_type}")
    label = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
    detail = {3: UNREACHABLE_CODES, 11: TIME_EXCEEDED_CODES, 5: REDIRECT_CODES}.get(icmp_type, {}).get(code)
    return f"{label} - {detail}" if detail else label


class IcmpAnalyzer:
    category = "icmp"

    def __init__(self) -> None:
        self.messages: Counter = Counter()
        self.message_frames: dict[str, Frames] = defaultdict(Frames)
        self.requests: dict[tuple, tuple[int, float]] = {}
        self.replied: set[tuple] = set()
        self.rtts: list[float] = []
        self.orphan_replies = 0
        self.sweeps: dict[str, dict] = defaultdict(lambda: {"targets": set(), "frames": Frames()})
        self.recon: dict[tuple, Frames] = defaultdict(Frames)
        self.port_unreachable: dict[tuple, dict] = defaultdict(lambda: {"ports": set(), "frames": Frames()})
        self.payloads: dict[tuple, dict] = defaultdict(lambda: {"sizes": [], "suffixes": set(), "bytes": 0, "frames": Frames()})
        self.redirects: dict[tuple, dict] = defaultdict(lambda: {"gateways": set(), "frames": Frames()})
        self.echo_to_target: dict[str, dict] = defaultdict(lambda: {"sources": Counter(), "frames": Frames()})
        self.broadcast_echo: dict[str, dict] = defaultdict(lambda: {"targets": set(), "frames": Frames()})
        self.traceroutes: dict[tuple, dict] = defaultdict(lambda: {"routers": [], "frames": Frames()})
        self.fragments: dict[tuple, dict] = defaultdict(lambda: {"max_end": 0, "frames": Frames()})
        self.filtered = Frames()
        self.total = 0

    # Processing ----------------------------------------------------------

    def process(self, packet, frame: int, ts: float) -> None:
        if IP in packet and packet[IP].proto == 1 and (packet[IP].frag or packet[IP].flags.MF):
            self._fragment(packet, frame, ts)
        if ICMP in packet and IP in packet:
            self._icmpv4(packet, frame, ts)
        elif IPv6 in packet and packet[IPv6].nh == 58:
            self._icmpv6(packet, frame, ts)

    def _fragment(self, packet, frame: int, ts: float) -> None:
        ip = packet[IP]
        entry = self.fragments[(ip.src, ip.dst, ip.id)]
        entry["max_end"] = max(entry["max_end"], ip.frag * 8 + len(ip.payload))
        entry["frames"].add(frame, ts)

    def _count(self, label: str, frame: int, ts: float) -> None:
        self.total += 1
        self.messages[label] += 1
        self.message_frames[label].add(frame, ts)

    def _icmpv4(self, packet, frame: int, ts: float) -> None:
        ip, icmp = packet[IP], packet[ICMP]
        src, dst = ip.src, ip.dst
        self._count(type_label(4, icmp.type, icmp.code), frame, ts)

        if icmp.type in (8, 0):
            payload = bytes(icmp.payload)
            self._echo(4, icmp.type == 8, src, dst, icmp.id, icmp.seq, payload, frame, ts)
            if icmp.type == 8 and (dst.endswith(".255") or (Ether in packet and packet[Ether].dst == "ff:ff:ff:ff:ff:ff")):
                entry = self.broadcast_echo[src]
                entry["targets"].add(dst)
                entry["frames"].add(frame, ts)
        elif icmp.type in RECON_TYPES:
            self.recon[(src, dst, RECON_TYPES[icmp.type])].add(frame, ts)
        elif icmp.type == 3:
            if icmp.code in (9, 10, 13):
                self.filtered.add(frame, ts)
            if icmp.code == 3 and IPerror in packet and UDPerror in packet:
                # The quoted header is the probe: its source is the scanner, its destination the target.
                quoted = packet[IPerror]
                entry = self.port_unreachable[(quoted.src, quoted.dst)]
                entry["ports"].add(packet[UDPerror].dport)
                entry["frames"].add(frame, ts)
        elif icmp.type == 5:
            entry = self.redirects[(src, dst)]
            entry["gateways"].add(icmp.gw)
            entry["frames"].add(frame, ts)
        elif icmp.type == 11 and icmp.code == 0:
            final = packet[IPerror].dst if IPerror in packet else None
            entry = self.traceroutes[(dst, final)]
            if src not in entry["routers"]:
                entry["routers"].append(src)
            entry["frames"].add(frame, ts)

    def _icmpv6(self, packet, frame: int, ts: float) -> None:
        ip = packet[IPv6]
        layer = ip.payload
        icmp_type, code = getattr(layer, "type", None), getattr(layer, "code", 0)
        if icmp_type is None:
            return
        self._count(type_label(6, icmp_type, code), frame, ts)
        if icmp_type in (128, 129):
            payload = bytes(getattr(layer, "data", b"") or b"")
            self._echo(6, icmp_type == 128, ip.src, ip.dst, getattr(layer, "id", 0), getattr(layer, "seq", 0), payload, frame, ts)

    def _echo(self, version, request, src, dst, ident, seq, payload, frame, ts) -> None:
        if request:
            self.requests.setdefault((src, dst, ident, seq), (frame, ts))
            sweep = self.sweeps[src]
            sweep["targets"].add(dst)
            sweep["frames"].add(frame, ts)
            flood = self.echo_to_target[dst]
            flood["sources"][src] += 1
            flood["frames"].add(frame, ts)
        else:
            key = (dst, src, ident, seq)
            if key in self.requests and key not in self.replied:
                self.replied.add(key)
                self.rtts.append(ts - self.requests[key][1])
            elif key not in self.requests:
                self.orphan_replies += 1
        # Ping payloads repeat the same pattern after the first 16 bytes (timestamp); tunnels do not.
        entry = self.payloads[(src, dst) if request else (dst, src)]
        entry["sizes"].append(len(payload))
        entry["bytes"] += len(payload)
        if len(payload) >= TUNNEL_MIN_PAYLOAD:
            entry["suffixes"].add(payload[16:])
        entry["frames"].add(frame, ts)

    # Report --------------------------------------------------------------

    def report(self) -> dict:
        unanswered = len(self.requests) - len(self.replied)
        rtt = None
        if self.rtts:
            rtt = {"min_ms": min(self.rtts) * 1000, "avg_ms": sum(self.rtts) / len(self.rtts) * 1000, "max_ms": max(self.rtts) * 1000}
        return {
            "stats": {
                "messages": self.total,
                "echo_requests": len(self.requests),
                "echo_answered": len(self.replied),
                "echo_unanswered": unanswered,
                "orphan_replies": self.orphan_replies,
                "rtt": rtt,
                "filtered_by_admin": self.filtered.count,
            },
            "tables": {
                "types": [
                    {"type": label, "count": count, "first_frame": self.message_frames[label].numbers[0] if self.message_frames[label].numbers else None}
                    for label, count in self.messages.most_common()
                ],
                "ping_sources": sorted(
                    ({"source": src, "targets": len(data["targets"]), "requests": data["frames"].count} for src, data in self.sweeps.items()),
                    key=lambda row: row["targets"],
                    reverse=True,
                )[:50],
            },
            "findings": self._findings(),
        }

    def _findings(self) -> list[dict]:
        findings = []
        for src, data in self.sweeps.items():
            if len(data["targets"]) >= SWEEP_THRESHOLD:
                answered = sorted({key[1] for key in self.replied if key[0] == src})
                findings.append(
                    finding(
                        "icmp", "ping_sweep", "medium",
                        "Balayage ping (découverte d'hôtes)",
                        f"{src} a envoyé des pings à {len(data['targets'])} hôtes ; {len(answered)} ont répondu.",
                        explanation=(
                            "Un attaquant envoie des Echo request à toute une plage d'adresses pour savoir quelles machines "
                            "sont allumées. C'est souvent la première étape d'une intrusion (nmap -sn, fping)."
                        ),
                        recommendation="Identifier la machine source, vérifier si ce balayage est autorisé et filtrer l'ICMP entrant depuis l'extérieur.",
                        mitre=["T1018"], source=src, frames=data["frames"],
                        wireshark_filter=f"{ip_filter('ip.src', src)} && icmp.type==8",
                        evidence={"targets_sample": sorted(data["targets"])[:30], "alive_hosts": answered[:50]},
                    )
                )
        for (src, dst, kind), frames in self.recon.items():
            findings.append(
                finding(
                    "icmp", "icmp_recon", "low",
                    f"Requête ICMP {kind} (empreinte du système)",
                    f"{src} a envoyé {frames.count} requête(s) ICMP {kind} a {dst}.",
                    explanation=(
                        "Les requêtes Timestamp, Information et Address mask ne servent presque plus à rien en usage normal. "
                        "Les scanners (nmap -PP, -PM) les utilisent pour détecter des hôtes et deviner leur système."
                    ),
                    recommendation="Bloquer ces types ICMP sur le pare-feu ; vérifier les autres activités de la source.",
                    mitre=["T1595"], source=src, target=dst, frames=frames,
                    wireshark_filter=f"{ip_filter('ip.src', src)} && icmp.type in {{13 15 17}}",
                )
            )
        for (scanner, target), data in self.port_unreachable.items():
            if len(data["ports"]) >= UDP_SCAN_THRESHOLD:
                findings.append(
                    finding(
                        "icmp", "udp_scan", "medium",
                        "Scan de ports UDP",
                        f"{target} a répondu 'port injoignable' à {scanner} pour {len(data['ports'])} ports UDP différents.",
                        explanation=(
                            "Quand on sonde un port UDP fermé, la cible répond par un ICMP 'port injoignable'. Une rafale de ces "
                            "réponses vers la même source révèle un scan UDP (nmap -sU) : les ports sans réponse sont ouverts ou filtrés."
                        ),
                        recommendation="Limiter le débit des messages ICMP sortants de la cible et analyser les services UDP exposés.",
                        mitre=["T1046"], source=scanner, target=target, frames=data["frames"],
                        wireshark_filter=f"icmp.type==3 && icmp.code==3 && {ip_filter('ip.dst', scanner)}",
                        evidence={"closed_udp_ports": sorted(data["ports"])[:100]},
                    )
                )
        for (src, dst), data in self.payloads.items():
            large = [size for size in data["sizes"] if size >= TUNNEL_MIN_PAYLOAD]
            if len(large) >= TUNNEL_MIN_PACKETS and len(data["suffixes"]) >= max(3, len(large) // 2):
                findings.append(
                    finding(
                        "icmp", "icmp_tunnel", "high",
                        "Tunnel ICMP probable (données cachées dans les pings)",
                        f"{len(large)} pings entre {src} et {dst} transportent des données différentes à chaque fois ({data['bytes']} octets au total).",
                        explanation=(
                            "Un ping normal répète toujours le même motif. Ici le contenu change d'un paquet à l'autre : c'est la "
                            "signature d'outils comme ptunnel, icmpsh ou icmptunnel, qui font passer un canal de commande ou des "
                            "données volées dans l'ICMP pour contourner le pare-feu."
                        ),
                        recommendation="Isoler les deux machines, extraire les charges utiles (Wireshark : data.data) et limiter la taille des pings autorisés.",
                        mitre=["T1095"], source=src, target=dst, frames=data["frames"],
                        wireshark_filter=f"icmp && {ip_filter('ip.addr', src)} && {ip_filter('ip.addr', dst)} && data.len>={TUNNEL_MIN_PAYLOAD}",
                        evidence={"packets": len(large), "distinct_payloads": len(data["suffixes"]), "sizes_sample": sorted(set(large))[:20], "total_bytes": data["bytes"]},
                    )
                )
        for (router, victim), data in self.redirects.items():
            findings.append(
                finding(
                    "icmp", "icmp_redirect", "high",
                    "Redirection ICMP (détournement de trafic possible)",
                    f"{router} a demandé à {victim} de router son trafic via {', '.join(sorted(data['gateways']))}.",
                    explanation=(
                        "Un message ICMP Redirect modifie la table de routage de la victime. Un attaquant l'utilise pour faire passer "
                        "le trafic par sa machine (homme du milieu), sans toucher au cache ARP."
                    ),
                    recommendation="Désactiver l'acceptation des redirections ICMP (net.ipv4.conf.all.accept_redirects=0) et vérifier la passerelle indiquée.",
                    mitre=["T1557"], source=router, target=victim, frames=data["frames"],
                    wireshark_filter=f"icmp.type==5 && {ip_filter('ip.dst', victim)}",
                    evidence={"gateways": sorted(data["gateways"])},
                )
            )
        for src, data in self.broadcast_echo.items():
            if data["frames"].count >= SMURF_THRESHOLD:
                findings.append(
                    finding(
                        "icmp", "smurf", "high",
                        "Attaque Smurf (ping vers une adresse de diffusion)",
                        f"{data['frames'].count} pings envoyés au nom de {src} vers {', '.join(sorted(data['targets']))}.",
                        explanation=(
                            "Un ping vers l'adresse de diffusion fait répondre toutes les machines du réseau. Avec une source "
                            "usurpée, toutes ces réponses inondent la victime : c'est l'attaque Smurf, un déni de service par amplification."
                        ),
                        recommendation="Interdire les pings vers la diffusion (net.ipv4.icmp_echo_ignore_broadcasts=1) et les paquets dirigés vers la diffusion sur les routeurs.",
                        mitre=["T1498"], source=src, frames=data["frames"],
                        wireshark_filter=f"icmp.type==8 && {ip_filter('ip.src', src)} && (eth.dst==ff:ff:ff:ff:ff:ff || ip.dst==255.255.255.255)",
                    )
                )
        for target, data in self.echo_to_target.items():
            frames = data["frames"]
            duration = max((frames.last_ts or 0) - (frames.first_ts or 0), 1.0)
            if frames.count >= FLOOD_MIN_PACKETS and frames.count / duration >= FLOOD_MIN_RATE:
                findings.append(
                    finding(
                        "icmp", "icmp_flood", "high",
                        "Inondation ICMP (ping flood)",
                        f"{target} a reçu {frames.count} pings en {duration:.1f} s ({frames.count / duration:.0f}/s) depuis {len(data['sources'])} source(s).",
                        explanation="Un très grand nombre de pings en peu de temps sature le lien ou la machine cible : c'est un déni de service.",
                        recommendation="Limiter le débit ICMP (rate limiting) en entrée et identifier les sources ; plusieurs sources indiquent une attaque distribuée.",
                        mitre=["T1498"], target=target, source=data["sources"].most_common(1)[0][0], frames=frames,
                        wireshark_filter=f"icmp.type==8 && {ip_filter('ip.dst', target)}",
                        evidence={"rate_per_second": round(frames.count / duration, 1), "top_sources": top(data["sources"], 10, "ip")},
                    )
                )
        for (src, dst, _), data in self.fragments.items():
            if data["max_end"] > 65535:
                findings.append(
                    finding(
                        "icmp", "ping_of_death", "critical",
                        "Ping of death (paquet ICMP de plus de 65 535 octets)",
                        f"{src} a envoyé à {dst} des fragments ICMP qui reconstituent un paquet de {data['max_end']} octets.",
                        explanation="Un paquet IP ne peut pas dépasser 65 535 octets. Les fragments qui dépassent cette limite visent à faire planter la pile réseau de la cible.",
                        recommendation="Vérifier l'état de la cible, mettre à jour son système et filtrer les fragments ICMP anormaux.",
                        mitre=["T1499"], source=src, target=dst, frames=data["frames"],
                        wireshark_filter=f"ip.proto==1 && (ip.flags.mf==1 || ip.frag_offset>0) && {ip_filter('ip.src', src)}",
                    )
                )
        for (tracer, final), data in self.traceroutes.items():
            if len(data["routers"]) >= TRACEROUTE_MIN_HOPS:
                findings.append(
                    finding(
                        "icmp", "traceroute", "info",
                        "Traceroute (cartographie du chemin réseau)",
                        f"{tracer} a tracé la route vers {final or 'une destination'} : {len(data['routers'])} routeurs ont répondu.",
                        explanation="Des messages 'TTL expiré' venant de routeurs successifs montrent qu'un hôte a cartographié le chemin vers une cible.",
                        recommendation="Activité souvent légitime ; à corréler avec les autres constats de la même source.",
                        mitre=["T1018"], source=tracer, target=final, frames=data["frames"],
                        wireshark_filter=f"icmp.type==11 && {ip_filter('ip.dst', tracer)}",
                        evidence={"hops": data["routers"][:30]},
                    )
                )
        return findings
