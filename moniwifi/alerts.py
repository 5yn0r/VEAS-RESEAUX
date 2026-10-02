"""Structured alert model shared by detection, storage, API, and Socket.IO."""

from __future__ import annotations

import time
import uuid

from moniwifi.attack import techniques_for

SEVERITIES = ("info", "low", "medium", "high", "critical")


def make_alert(
    alert_type: str,
    detail: str,
    *,
    severity: str = "medium",
    source_ip: str | None = None,
    destination_ip: str | None = None,
    evidence: dict | None = None,
    timestamp: float | None = None,
) -> dict:
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity: {severity}")
    return {
        "id": uuid.uuid4().hex,
        "type": alert_type,
        "severity": severity,
        "timestamp": time.time() if timestamp is None else timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "detail": detail,
        "evidence": evidence or {},
        "message": format_message(alert_type, detail),
        "mitre": techniques_for(alert_type),
    }


def format_message(alert_type: str, detail: str) -> str:
    return f"[{alert_type.upper()}] {detail}"


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else 0
