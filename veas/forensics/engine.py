"""Read a capture once, feed every protocol analyser, and build the forensic report."""

from __future__ import annotations

import hashlib
import logging
import os
import time
from collections import Counter, defaultdict
from typing import Callable

from scapy.all import PcapReader
from scapy.error import Scapy_Exception

from veas.forensics.arp import ArpAnalyzer
from veas.forensics.dns import DnsAnalyzer
from veas.forensics.http import HttpAnalyzer
from veas.forensics.icmp import IcmpAnalyzer
from veas.forensics.model import SEVERITY_LABEL, is_private, severity_rank
from veas.forensics.overview import LINK_TYPES, Overview
from veas.forensics.tcp import TcpAnalyzer

logger = logging.getLogger(__name__)

REPORT_VERSION = 1
PROGRESS_EVERY = 5000
TACTIC_ORDER = (
    "reconnaissance", "discovery", "initial-access", "credential-access", "execution", "persistence",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
)
TACTIC_LABEL = {
    "reconnaissance": "Reconnaissance", "discovery": "Découverte", "initial-access": "Accès initial",
    "credential-access": "Accès aux identifiants", "execution": "Exécution", "persistence": "Persistance",
    "lateral-movement": "Mouvement latéral", "collection": "Collecte", "command-and-control": "Commande et contrôle",
    "exfiltration": "Exfiltration", "impact": "Impact",
}
MAGIC = {
    b"\xd4\xc3\xb2\xa1": "pcap", b"\xa1\xb2\xc3\xd4": "pcap",
    b"\x4d\x3c\xb2\xa1": "pcap (nanosecondes)", b"\xa1\xb2\x3c\x4d": "pcap (nanosecondes)",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}


def detect_format(header: bytes) -> str | None:
    return MAGIC.get(header[:4])


def file_digest(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def primary_tactic(item: dict) -> str | None:
    if item.get("phase"):
        return item["phase"]
    tactics = [tactic for technique in item["mitre"] for tactic in technique["tactics"]]
    return min(tactics, key=TACTIC_ORDER.index) if tactics else None


def analyse_pcap(
    path: str,
    progress: Callable[[int, float], None] | None = None,
    max_packets: int | None = None,
    filename: str | None = None,
) -> dict:
    with open(path, "rb") as handle:
        file_format = detect_format(handle.read(4))
    if file_format is None:
        raise ValueError("ce fichier n'est pas une capture pcap ou pcapng")

    started = time.monotonic()
    size = os.path.getsize(path)
    overview = Overview()
    analyzers = [IcmpAnalyzer(), TcpAnalyzer(), HttpAnalyzer(), DnsAnalyzer(), ArpAnalyzer()]
    warnings: list[str] = []
    errors: Counter = Counter()
    frame = 0
    link_type = None

    try:
        reader = PcapReader(path)
    except (Scapy_Exception, OSError, ValueError) as exc:
        raise ValueError(f"capture illisible : {exc}") from exc
    with reader:
        link_type = getattr(reader, "linktype", None)
        iterator = iter(reader)
        while True:
            try:
                packet = next(iterator)
            except StopIteration:
                break
            except Exception as exc:  # noqa: BLE001 - a truncated capture still yields a useful report
                warnings.append(f"Lecture interrompue après la trame {frame} : {exc}")
                break
            frame += 1
            ts = float(packet.time)
            overview.process(packet, frame, ts)
            for analyzer in analyzers:
                try:
                    analyzer.process(packet, frame, ts)
                except Exception as exc:  # noqa: BLE001 - one malformed packet must not stop the analysis
                    errors[analyzer.category] += 1
                    logger.debug("%s failed on frame %s: %s", analyzer.category, frame, exc)
            if progress and frame % PROGRESS_EVERY == 0:
                position = reader.f.tell() if hasattr(reader, "f") else 0
                progress(frame, min(position / size * 100, 99.0) if size else 0.0)
            if max_packets and frame >= max_packets:
                warnings.append(f"Analyse limitée aux {max_packets} premières trames.")
                break

    for category, count in errors.items():
        warnings.append(f"{count} trame(s) n'ont pas pu être analysées par le module {category.upper()}.")

    protocols = {}
    findings = []
    for analyzer in analyzers:
        result = analyzer.report()
        findings += result.pop("findings")
        protocols[analyzer.category] = result
    findings.sort(key=lambda item: (-severity_rank(item["severity"]), item["first_seen"] or 0))
    overview_report = overview.report()

    report = {
        "version": REPORT_VERSION,
        "file": {
            "name": filename or os.path.basename(path),
            "size": size,
            "format": file_format,
            "link_type": LINK_TYPES.get(link_type, str(link_type) if link_type is not None else None),
            "sha256": file_digest(path),
        },
        "analysed_at": time.time(),
        "analysis_seconds": round(time.monotonic() - started, 2),
        "warnings": warnings,
        "overview": overview_report,
        "findings": findings,
        "protocols": protocols,
    }
    report["summary"] = summarize(findings)
    report["actors"] = actors(findings, overview)
    report["timeline"] = timeline(findings, overview_report)
    report["narrative"] = narrative(findings, report["actors"])
    return report


def summarize(findings: list[dict]) -> dict:
    by_severity = Counter(item["severity"] for item in findings)
    techniques: dict[str, dict] = {}
    tactics: list[str] = []
    for item in findings:
        for technique in item["mitre"]:
            entry = techniques.setdefault(technique["id"], {**technique, "findings": 0})
            entry["findings"] += 1
        # Automated probes only count as reconnaissance, not as the tactic they imitate.
        observed = [item["phase"]] if item.get("phase") else [tactic for technique in item["mitre"] for tactic in technique["tactics"]]
        tactics += [tactic for tactic in observed if tactic not in tactics]
    worst = max((item["severity"] for item in findings), key=severity_rank, default=None)
    return {
        "threat_level": worst or "none",
        "threat_label": SEVERITY_LABEL.get(worst, "Aucune menace détectée"),
        "findings_total": len(findings),
        "findings_by_severity": {level: by_severity.get(level, 0) for level in ("critical", "high", "medium", "low", "info")},
        "mitre_techniques": sorted(techniques.values(), key=lambda entry: entry["id"]),
        "mitre_tactics": [{"id": tactic, "label": TACTIC_LABEL[tactic]} for tactic in sorted(tactics, key=TACTIC_ORDER.index)],
    }


def actors(findings: list[dict], overview: Overview) -> list[dict]:
    table: dict[str, dict] = {}
    for item in findings:
        for role in ("source", "target"):
            address = item[role]
            if not address:
                continue
            actor = table.setdefault(address, {"address": address, "as_source": 0, "as_target": 0, "max_severity": "info", "categories": set()})
            actor["as_source" if role == "source" else "as_target"] += 1
            actor["categories"].add(item["category"])
            if severity_rank(item["severity"]) > severity_rank(actor["max_severity"]):
                actor["max_severity"] = item["severity"]
    result = []
    for address, actor in table.items():
        endpoint = overview.endpoint(address) or {}
        if actor["as_source"] and actor["as_target"]:
            role = "Attaquant et cible"
        elif actor["as_source"]:
            role = "Attaquant probable"
        else:
            role = "Cible"
        result.append({
            **actor,
            "categories": sorted(actor["categories"]),
            "role": role,
            "private": is_private(address),
            "os_guess": endpoint.get("os_guess"),
            "packets": endpoint.get("packets_sent", 0) + endpoint.get("packets_received", 0),
            "bytes": endpoint.get("bytes_sent", 0) + endpoint.get("bytes_received", 0),
        })
    result.sort(key=lambda actor: (-severity_rank(actor["max_severity"]), -actor["as_source"], actor["address"]))
    return result


def timeline(findings: list[dict], overview: dict) -> list[dict]:
    events = []
    if overview["start"] is not None:
        events.append({"time": overview["start"], "kind": "capture", "severity": "info", "title": "Début de la capture", "frame": 1})
    for item in findings:
        if item["first_seen"] is None:
            continue
        events.append({
            "time": item["first_seen"], "kind": "finding", "severity": item["severity"], "title": item["title"],
            "description": item["description"], "source": item["source"], "target": item["target"],
            "frame": item["frames"][0] if item["frames"] else None, "finding_id": item["id"],
            "phase": TACTIC_LABEL.get(primary_tactic(item)),
        })
    if overview["end"] is not None:
        events.append({"time": overview["end"], "kind": "capture", "severity": "info", "title": "Fin de la capture", "frame": overview["packets"]})
    events.sort(key=lambda event: (event["time"], event["kind"] != "capture"))
    return events


def narrative(findings: list[dict], actor_list: list[dict]) -> list[dict]:
    """One story per probable attacker: its findings in time order, labelled with ATT&CK phases."""
    per_source: dict[str, list[dict]] = defaultdict(list)
    for item in findings:
        if item["source"] and item["severity"] != "info":
            per_source[item["source"]].append(item)
    by_address = {actor["address"]: actor for actor in actor_list}
    stories = []
    for source, items in per_source.items():
        items.sort(key=lambda item: item["first_seen"] or 0)
        phases: list[str] = []
        steps = []
        for item in items:
            tactic = primary_tactic(item)
            label = TACTIC_LABEL.get(tactic, "Activité suspecte")
            if label not in phases:
                phases.append(label)
            steps.append({
                "time": item["first_seen"], "phase": label, "severity": item["severity"], "title": item["title"],
                "description": item["description"], "frame": item["frames"][0] if item["frames"] else None, "finding_id": item["id"],
            })
        actor = by_address.get(source, {})
        targets = sorted({item["target"] for item in items if item["target"]})
        worst = max((item["severity"] for item in items), key=severity_rank)
        who = source + (f" ({actor['os_guess']})" if actor.get("os_guess") else "")
        summary = (
            f"{who} est à l'origine de {len(items)} constat(s)"
            + (f" visant {', '.join(targets[:5])}{' ...' if len(targets) > 5 else ''}" if targets else "")
            + f". Déroulé : {' → '.join(phases)}."
        )
        stories.append({"attacker": source, "severity": worst, "summary": summary, "phases": phases, "targets": targets, "steps": steps})
    stories.sort(key=lambda story: (-severity_rank(story["severity"]), story["steps"][0]["time"] or 0))
    return stories
