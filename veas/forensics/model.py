"""Finding model shared by the protocol analysers of a forensic report."""

from __future__ import annotations

import hashlib
import ipaddress

from veas.attack import technique

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
SEVERITY_LABEL = {"info": "Info", "low": "Faible", "medium": "Moyenne", "high": "Elevee", "critical": "Critique"}
MAX_FRAMES = 25


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0


class Frames:
    """First frame numbers of an observation, plus the total count."""

    def __init__(self) -> None:
        self.numbers: list[int] = []
        self.count = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None

    def add(self, frame: int, ts: float) -> None:
        self.count += 1
        if len(self.numbers) < MAX_FRAMES:
            self.numbers.append(frame)
        self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
        self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)

    def merge(self, other: "Frames") -> None:
        for frame in other.numbers:
            if len(self.numbers) < MAX_FRAMES and frame not in self.numbers:
                self.numbers.append(frame)
        self.numbers.sort()
        self.count += other.count
        for ts in (other.first_ts, other.last_ts):
            if ts is not None:
                self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
                self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)


def finding(
    category: str,
    kind: str,
    severity: str,
    title: str,
    description: str,
    *,
    explanation: str,
    recommendation: str,
    mitre: list[str] | tuple[str, ...] = (),
    source: str | None = None,
    target: str | None = None,
    frames: Frames | None = None,
    wireshark_filter: str | None = None,
    evidence: dict | None = None,
) -> dict:
    """Build one forensic finding (texts are in French, for the supervisor)."""
    if severity not in SEVERITY_ORDER:
        raise ValueError(f"unknown severity: {severity}")
    frames = frames or Frames()
    key = f"{category}|{kind}|{source}|{target}|{description}"
    return {
        "id": hashlib.sha1(key.encode()).hexdigest()[:12],
        "category": category,
        "type": kind,
        "severity": severity,
        "title": title,
        "description": description,
        "explanation": explanation,
        "recommendation": recommendation,
        "mitre": [technique(technique_id) for technique_id in mitre],
        "source": source,
        "target": target,
        "first_seen": frames.first_ts,
        "last_seen": frames.last_ts,
        "count": frames.count,
        "frames": sorted(frames.numbers),
        "wireshark_filter": wireshark_filter,
        "evidence": evidence or {},
    }


def ip_filter(field: str, address: str | None) -> str:
    """Wireshark field for an address: ``ip.src`` becomes ``ipv6.src`` for IPv6."""
    if address and ":" in address:
        field = field.replace("ip.", "ipv6.", 1)
    return f"{field}=={address}"


def is_private(address: str | None) -> bool:
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def mask_secret(secret: str) -> str:
    return f"{'*' * min(len(secret), 8)} ({len(secret)} car.)" if secret else "(vide)"


def top(counter, limit: int = 20, key: str = "name") -> list[dict]:
    return [{key: name, "count": count} for name, count in counter.most_common(limit)]
