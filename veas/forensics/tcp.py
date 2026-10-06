"""TCP analysis: connection states, scans (with discovered ports), SYN floods, brute force, invalid flags."""

from __future__ import annotations

from collections import Counter, defaultdict

from scapy.all import IP, TCP, IPv6

from veas.detectors import DEFAULT_AUTH_PORTS
from veas.forensics.model import Frames, finding, ip_filter
from veas.forensics.overview import service_name

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
SCAN_THRESHOLD = 10
SWEEP_THRESHOLD = 10
SYN_FLOOD_MIN = 100
SYN_FLOOD_RATE = 50.0
SYN_FLOOD_SOURCES = 20
BRUTE_FORCE_MIN = 10
MAX_RETRANSMISSION_KEYS = 5000
MAX_CONNECTIONS_TABLE = 1000

# Probe kind -> (scan name, nmap option).
PROBES = {
    "syn": ("SYN", "-sS / -sT"),
    "null": ("NULL", "-sN"),
    "fin": ("FIN", "-sF"),
    "xmas": ("XMAS", "-sX"),
    "ack": ("ACK", "-sA"),
    "maimon": ("Maimon", "-sM"),
}
STATE_LABELS = {
    "established_data": "Établie avec données",
    "established": "Établie sans données",
    "half_open": "Semi-ouverte (RST du client après SYN/ACK)",
    "refused": "Refusée (RST du serveur)",
    "unanswered": "SYN sans réponse (filtré)",
    "probe": "Sonde sans connexion",
    "partial": "Prise en cours de capture",
}


def flag_text(flags: int) -> str:
    names = [(URG, "U"), (ACK, "A"), (PSH, "P"), (RST, "R"), (SYN, "S"), (FIN, "F")]
    return "".join(letter for bit, letter in names if flags & bit) or "aucun"


def probe_kind(flags: int, payload: int) -> str | None:
    """Classify the first packet of a connection seen from its initiator."""
    if flags & (SYN | ACK) == SYN and not flags & RST:
        return "syn"
    if payload:
        return None
    if flags == 0:
        return "null"
    if flags == FIN:
        return "fin"
    if flags & (FIN | PSH | URG) == FIN | PSH | URG and not flags & (SYN | ACK | RST):
        return "xmas"
    if flags == ACK:
        return "ack"
    if flags == FIN | ACK:
        return "maimon"
    return None


class Connection:
    __slots__ = (
        "client", "cport", "server", "sport", "first_ts", "last_ts", "first_frame", "probe", "syn", "synack",
        "handshake", "client_rst", "server_rst", "fin", "packets", "bytes_c2s", "bytes_s2c", "server_replied",
    )

    def __init__(self, client, cport, server, sport, ts, frame, probe) -> None:
        self.client, self.cport, self.server, self.sport = client, cport, server, sport
        self.first_ts = self.last_ts = ts
        self.first_frame = frame
        self.probe = probe
        self.syn = self.synack = self.handshake = self.client_rst = self.server_rst = self.fin = self.server_replied = False
        self.packets = 0
        self.bytes_c2s = self.bytes_s2c = 0

    def state(self) -> str:
        if self.probe in ("null", "fin", "xmas", "ack", "maimon"):
            return "probe"
        if self.handshake:
            return "established_data" if self.bytes_c2s or self.bytes_s2c else "established"
        if self.synack and self.client_rst:
            return "half_open"
        if self.syn and self.server_rst:
            return "refused"
        if self.syn and not self.server_replied:
            return "unanswered"
        return "partial"


class TcpAnalyzer:
    category = "tcp"

    def __init__(self) -> None:
        self.connections: dict[tuple, Connection] = {}
        self.flags: Counter = Counter()
        self.segments = 0
        self.retransmissions = 0
        self._seen_segments: dict[tuple, set] = defaultdict(set)
        self.invalid: dict[tuple, dict] = defaultdict(lambda: {"flags": Counter(), "frames": Frames()})
        self.syn_frames: dict[tuple, Frames] = defaultdict(Frames)

    def process(self, packet, frame: int, ts: float) -> None:
        if TCP not in packet:
            return
        layer = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
        if layer is None:
            return
        tcp = packet[TCP]
        src, dst, sport, dport = layer.src, layer.dst, tcp.sport, tcp.dport
        flags = int(tcp.flags)
        payload = len(tcp.payload)
        self.segments += 1
        self.flags[flag_text(flags)] += 1

        if flags & SYN and flags & FIN or flags & SYN and flags & RST:
            entry = self.invalid[(src, dst)]
            entry["flags"][flag_text(flags)] += 1
            entry["frames"].add(frame, ts)

        forward, reverse = (src, sport, dst, dport), (dst, dport, src, sport)
        if forward in self.connections:
            conn, from_client = self.connections[forward], True
        elif reverse in self.connections:
            conn, from_client = self.connections[reverse], False
        elif flags & (SYN | ACK) == SYN | ACK:
            # Capture started after the SYN: the SYN/ACK sender is the server.
            conn = self.connections[reverse] = Connection(dst, dport, src, sport, ts, frame, None)
            from_client = False
        else:
            kind = probe_kind(flags, payload)
            conn = self.connections[forward] = Connection(src, sport, dst, dport, ts, frame, kind)
            from_client = True

        conn.packets += 1
        conn.last_ts = ts
        if from_client:
            conn.bytes_c2s += payload
            if flags & (SYN | ACK) == SYN:
                conn.syn = True
                self.syn_frames[(conn.server, conn.sport)].add(frame, ts)
            if flags & RST:
                conn.client_rst = True
            if conn.synack and flags & ACK and not flags & (SYN | RST):
                conn.handshake = True
        else:
            conn.server_replied = True
            conn.bytes_s2c += payload
            if flags & (SYN | ACK) == SYN | ACK:
                conn.synack = True
            if flags & RST:
                conn.server_rst = True
            if conn.probe is None and conn.synack and not conn.syn and flags & ACK and not flags & SYN:
                conn.handshake = True
        if flags & FIN:
            conn.fin = True

        if payload:
            key = (src, sport, dst, dport)
            seen = self._seen_segments[key]
            marker = (tcp.seq, payload)
            if marker in seen:
                self.retransmissions += 1
            elif len(seen) < MAX_RETRANSMISSION_KEYS:
                seen.add(marker)

    # Report --------------------------------------------------------------

    def report(self) -> dict:
        connections = list(self.connections.values())
        states = Counter(conn.state() for conn in connections)
        servers = Counter((conn.sport) for conn in connections if conn.syn)
        table = sorted(connections, key=lambda conn: conn.bytes_c2s + conn.bytes_s2c, reverse=True)[:MAX_CONNECTIONS_TABLE]
        return {
            "stats": {
                "segments": self.segments,
                "connections": len(connections),
                "retransmissions": self.retransmissions,
                "states": {STATE_LABELS[state]: count for state, count in states.most_common()},
            },
            "tables": {
                "flags": [{"flags": name, "count": count} for name, count in self.flags.most_common()],
                "server_ports": [{"port": port, "service": service_name(port), "connections": count} for port, count in servers.most_common(30)],
                "connections": [
                    {
                        "client": conn.client, "client_port": conn.cport, "server": conn.server, "server_port": conn.sport,
                        "service": service_name(conn.sport), "state": STATE_LABELS[conn.state()], "packets": conn.packets,
                        "bytes_sent": conn.bytes_c2s, "bytes_received": conn.bytes_s2c, "start": conn.first_ts,
                        "duration": conn.last_ts - conn.first_ts, "first_frame": conn.first_frame,
                    }
                    for conn in table
                ],
            },
            "findings": self._scans(connections) + self._sweeps(connections) + self._syn_floods(connections)
            + self._brute_force(connections) + self._invalid_flags(),
        }

    def _scans(self, connections) -> list[dict]:
        groups: dict[tuple, list[Connection]] = defaultdict(list)
        for conn in connections:
            if conn.probe:
                groups[(conn.client, conn.server, conn.probe)].append(conn)
        findings = []
        for (scanner, target, kind), conns in groups.items():
            ports = {conn.sport for conn in conns}
            if len(ports) < SCAN_THRESHOLD:
                continue
            name, option = PROBES[kind]
            frames = Frames()
            for conn in sorted(conns, key=lambda item: item.first_ts):
                frames.add(conn.first_frame, conn.first_ts)
            if kind == "syn":
                open_ports = sorted({conn.sport for conn in conns if conn.synack})
                closed = sorted({conn.sport for conn in conns if conn.server_rst and not conn.synack})
                filtered = sorted(ports - set(open_ports) - set(closed))
                full = sum(1 for conn in conns if conn.handshake and not conn.bytes_c2s)
                half = sum(1 for conn in conns if conn.synack and conn.client_rst and not conn.handshake)
                name = "TCP connect (poignée de main complète)" if full > half else "SYN (semi-ouvert)"
                option = "-sT" if full > half else "-sS"
                result = (
                    f"Ports ouverts découverts : {', '.join(map(str, open_ports[:30])) or 'aucun'}"
                    f"{' ...' if len(open_ports) > 30 else ''}. {len(closed)} fermés, {len(filtered)} sans réponse (filtrés)."
                )
                wireshark = f"{ip_filter('ip.src', scanner)} && {ip_filter('ip.dst', target)} && tcp.flags.syn==1 && tcp.flags.ack==0"
            else:
                open_ports = []
                closed = sorted({conn.sport for conn in conns if conn.server_rst})
                filtered = sorted(ports - set(closed))
                verdict = "non filtrés" if kind == "ack" else "ouverts ou filtrés"
                result = f"{len(closed)} ports ont répondu RST ; {len(filtered)} sont {verdict}."
                wireshark = {
                    "null": "tcp.flags==0x000",
                    "fin": "tcp.flags==0x001",
                    "xmas": "tcp.flags.fin==1 && tcp.flags.push==1 && tcp.flags.urg==1",
                    "ack": "tcp.flags==0x010 && tcp.len==0",
                    "maimon": "tcp.flags==0x011",
                }[kind] + f" && {ip_filter('ip.src', scanner)}"
            severity = "high" if open_ports else "medium"
            explanation = {
                "syn": (
                    "L'attaquant envoie un SYN sur de nombreux ports. Un SYN/ACK signifie que le port est ouvert, un RST qu'il est "
                    "fermé, l'absence de réponse qu'il est filtré par un pare-feu. En scan SYN, il coupe aussitôt (RST) sans terminer "
                    "la connexion ; en scan Connect, il l'établit puis la ferme."
                ),
                "null": "Paquets TCP sans aucun drapeau : une pile conforme répond RST si le port est fermé et se tait s'il est ouvert. Technique furtive pour contourner certains filtres.",
                "fin": "Paquets avec le seul drapeau FIN, hors de toute connexion : un port fermé répond RST, un port ouvert ignore le paquet.",
                "xmas": "Paquets avec FIN, PSH et URG allumés « comme un sapin de Noël » : même logique que le scan FIN, pour passer sous certains filtres.",
                "ack": "Paquets ACK isolés : ils ne disent pas si un port est ouvert, mais révèlent quels ports sont filtrés par le pare-feu (cartographie des règles).",
                "maimon": "Paquets FIN/ACK hors connexion (technique de Uriel Maimon) : certains systèmes BSD ne répondent pas quand le port est ouvert.",
            }[kind]
            findings.append(
                finding(
                    "tcp", f"{kind}_scan", severity,
                    f"Scan de ports TCP {name}",
                    f"{scanner} a sondé {len(ports)} ports TCP de {target} (équivalent nmap {option}). {result}",
                    explanation=explanation,
                    recommendation=(
                        "Bloquer ou surveiller la source, fermer les services inutiles et vérifier que les ports ouverts découverts "
                        "sont à jour et protégés : ce sont les prochaines cibles de l'attaquant."
                    ),
                    mitre=["T1046"], source=scanner, target=target, frames=frames, wireshark_filter=wireshark,
                    evidence={"scan_type": name, "probed_ports": len(ports), "open_ports": open_ports, "closed_ports": closed[:100], "filtered_ports": filtered[:100]},
                )
            )
        return findings

    def _sweeps(self, connections) -> list[dict]:
        groups: dict[tuple, list[Connection]] = defaultdict(list)
        for conn in connections:
            if conn.probe == "syn":
                groups[(conn.client, conn.sport)].append(conn)
        findings = []
        for (scanner, port), conns in groups.items():
            targets = {conn.server for conn in conns}
            if len(targets) < SWEEP_THRESHOLD:
                continue
            frames = Frames()
            for conn in sorted(conns, key=lambda item: item.first_ts):
                frames.add(conn.first_frame, conn.first_ts)
            answering = sorted({conn.server for conn in conns if conn.synack})
            service = service_name(port)
            findings.append(
                finding(
                    "tcp", "host_sweep", "medium",
                    f"Balayage du port {port}{f' ({service})' if service else ''} sur le réseau",
                    f"{scanner} a contacté le port {port} de {len(targets)} machines ; {len(answering)} l'ont ouvert.",
                    explanation=(
                        "Au lieu de scanner tous les ports d'une machine, l'attaquant cherche un service précis sur tout le réseau, "
                        "souvent pour une vulnérabilité connue ou pour se propager (ver, rançongiciel)."
                    ),
                    recommendation="Vérifier les machines qui exposent ce service et appliquer les correctifs ; isoler la source si l'activité n'est pas prévue.",
                    mitre=["T1046"], source=scanner, frames=frames,
                    wireshark_filter=f"{ip_filter('ip.src', scanner)} && tcp.dstport=={port} && tcp.flags.syn==1 && tcp.flags.ack==0",
                    evidence={"port": port, "service": service, "targets": len(targets), "hosts_with_port_open": answering[:100]},
                )
            )
        return findings

    def _syn_floods(self, connections) -> list[dict]:
        groups: dict[tuple, list[Connection]] = defaultdict(list)
        for conn in connections:
            if conn.syn and not conn.handshake:
                groups[(conn.server, conn.sport)].append(conn)
        findings = []
        for (server, port), conns in groups.items():
            if len(conns) < SYN_FLOOD_MIN:
                continue
            sources = Counter(conn.client for conn in conns)
            frames = self.syn_frames[(server, port)]
            duration = max((frames.last_ts or 0) - (frames.first_ts or 0), 1.0)
            rate = len(conns) / duration
            if len(sources) < SYN_FLOOD_SOURCES and rate < SYN_FLOOD_RATE:
                continue
            spoofed = len(sources) >= SYN_FLOOD_SOURCES
            findings.append(
                finding(
                    "tcp", "syn_flood", "high",
                    "Inondation SYN (déni de service)",
                    (
                        f"{server}:{port} a reçu {len(conns)} demandes de connexion jamais terminées ({rate:.0f}/s) "
                        f"depuis {len(sources)} adresse(s){' probablement usurpées' if spoofed else ''}."
                    ),
                    explanation=(
                        "Chaque SYN réserve de la mémoire sur le serveur en attendant la fin de la poignée de main. En envoyant des milliers "
                        "de SYN sans jamais répondre, l'attaquant remplit cette file et le service ne peut plus accepter de vrais clients."
                    ),
                    recommendation="Activer les SYN cookies (net.ipv4.tcp_syncookies=1), limiter le débit des SYN et filtrer en amont (fournisseur, anti-DDoS).",
                    mitre=["T1498", "T1499"], source=sources.most_common(1)[0][0], target=server, frames=frames,
                    wireshark_filter=f"{ip_filter('ip.dst', server)} && tcp.dstport=={port} && tcp.flags.syn==1 && tcp.flags.ack==0",
                    evidence={"half_open_connections": len(conns), "rate_per_second": round(rate, 1), "distinct_sources": len(sources), "top_sources": [{"ip": ip, "count": n} for ip, n in sources.most_common(10)]},
                )
            )
        return findings

    def _brute_force(self, connections) -> list[dict]:
        groups: dict[tuple, list[Connection]] = defaultdict(list)
        for conn in connections:
            if conn.sport in DEFAULT_AUTH_PORTS and conn.sport not in (80, 443) and (conn.handshake or conn.syn):
                groups[(conn.client, conn.server, conn.sport)].append(conn)
        findings = []
        for (client, server, port), conns in groups.items():
            established = [conn for conn in conns if conn.handshake]
            if len(established) < BRUTE_FORCE_MIN:
                continue
            frames = Frames()
            for conn in sorted(established, key=lambda item: item.first_ts):
                frames.add(conn.first_frame, conn.first_ts)
            service = DEFAULT_AUTH_PORTS[port]
            duration = max((frames.last_ts or 0) - (frames.first_ts or 0), 1.0)
            longest = max(established, key=lambda conn: conn.bytes_c2s + conn.bytes_s2c)
            findings.append(
                finding(
                    "tcp", "brute_force", "high",
                    f"Force brute probable sur {service}",
                    f"{client} a ouvert {len(established)} connexions {service} vers {server} en {duration:.0f} s.",
                    explanation=(
                        "Un outil comme Hydra ou Medusa ouvre une connexion par essai de mot de passe. Une rafale de connexions courtes "
                        f"vers {service} depuis la même source est la signature d'une attaque par dictionnaire. Une connexion nettement "
                        "plus longue ou plus volumineuse que les autres peut indiquer un essai réussi."
                    ),
                    recommendation=f"Vérifier les journaux d'authentification de {server}, bloquer la source, imposer des mots de passe forts et une limitation des tentatives (fail2ban).",
                    mitre=["T1110"], source=client, target=server, frames=frames,
                    wireshark_filter=f"{ip_filter('ip.src', client)} && {ip_filter('ip.dst', server)} && tcp.dstport=={port} && tcp.flags.syn==1",
                    evidence={
                        "service": service, "port": port, "connections": len(established),
                        "largest_session": {"first_frame": longest.first_frame, "bytes": longest.bytes_c2s + longest.bytes_s2c, "duration": longest.last_ts - longest.first_ts},
                    },
                )
            )
        return findings

    def _invalid_flags(self) -> list[dict]:
        return [
            finding(
                "tcp", "invalid_flags", "medium",
                "Combinaisons de drapeaux TCP impossibles",
                f"{src} a envoyé {data['frames'].count} paquet(s) à {dst} avec des drapeaux incohérents ({', '.join(data['flags'])}).",
                explanation=(
                    "SYN+FIN ou SYN+RST n'existent pas dans une communication normale. Ces paquets servent à identifier le système "
                    "de la cible (empreinte) ou à tromper un pare-feu ou une sonde de détection."
                ),
                recommendation="Faire rejeter ces paquets par le pare-feu et examiner les autres actions de la source.",
                mitre=["T1595"], source=src, target=dst, frames=data["frames"],
                wireshark_filter=f"{ip_filter('ip.src', src)} && ((tcp.flags.syn==1 && tcp.flags.fin==1) || (tcp.flags.syn==1 && tcp.flags.reset==1))",
                evidence={"flags": dict(data["flags"])},
            )
            for (src, dst), data in self.invalid.items()
        ]
