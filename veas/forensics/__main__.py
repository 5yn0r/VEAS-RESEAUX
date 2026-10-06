"""Forensic report for a capture: python -m veas.forensics capture.pcap [--json report.json]."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

from veas.forensics.engine import analyse_pcap
from veas.forensics.model import SEVERITY_LABEL


def _time(ts: float | None) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "-"


def format_report(report: dict, limit: int = 30) -> str:
    overview, summary = report["overview"], report["summary"]
    lines = [
        f"Fichier     : {report['file']['name']} ({report['file']['format']}, {report['file']['size']} octets)",
        f"SHA-256     : {report['file']['sha256']}",
        f"Période     : {_time(overview['start'])} -> {_time(overview['end'])} ({overview['duration']:.1f} s)",
        f"Paquets     : {overview['packets']}   Protocoles : {', '.join(f'{name} {count}' for name, count in overview['protocols'].items())}",
        f"Menace      : {summary['threat_label'].upper()}   Constats : "
        + ", ".join(f"{SEVERITY_LABEL[level]} {count}" for level, count in summary["findings_by_severity"].items() if count),
    ]
    if summary["mitre_tactics"]:
        lines.append("Tactiques   : " + " -> ".join(tactic["label"] for tactic in summary["mitre_tactics"]))
    lines += [f"Attention   : {warning}" for warning in report["warnings"]]

    if report["narrative"]:
        lines += ["", "RÉCIT DE L'ATTAQUE"]
        for story in report["narrative"]:
            lines.append(f"  {story['summary']}")
            for step in story["steps"]:
                lines.append(f"    {_time(step['time'])}  [{step['phase']}] {step['title']} (trame {step['frame']})")

    lines += ["", f"CONSTATS ({len(report['findings'])})"]
    for item in report["findings"][:limit]:
        lines.append(f"  [{SEVERITY_LABEL[item['severity']].upper():8}] {item['title']}")
        lines.append(f"      {item['description']}")
        if item["mitre"]:
            lines.append("      MITRE : " + ", ".join(f"{technique['id']} {technique['name']}" for technique in item["mitre"]))
        if item["frames"]:
            lines.append(f"      Trames : {', '.join(map(str, item['frames'][:10]))}{' ...' if item['count'] > 10 else ''}")
        if item["wireshark_filter"]:
            lines.append(f"      Filtre Wireshark : {item['wireshark_filter']}")
    if len(report["findings"]) > limit:
        lines.append(f"  ... {len(report['findings']) - limit} autres constats dans le rapport JSON.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m veas.forensics", description="Analyse forensique d'une capture Wireshark (.pcap / .pcapng).")
    parser.add_argument("capture")
    parser.add_argument("--json", metavar="FICHIER", help="écrire le rapport complet en JSON")
    parser.add_argument("--max-packets", type=int, help="n'analyser que les N premières trames")
    parser.add_argument("--limit", type=int, default=30, help="nombre de constats affichés (défaut 30)")
    args = parser.parse_args(argv)

    try:
        report = analyse_pcap(args.capture, max_packets=args.max_packets)
    except (OSError, ValueError) as exc:
        print(f"erreur : {exc}", file=sys.stderr)
        return 2
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2, default=str)
    print(format_report(report, args.limit))
    return 1 if report["summary"]["threat_level"] in ("high", "critical") else 0


if __name__ == "__main__":
    sys.exit(main())
