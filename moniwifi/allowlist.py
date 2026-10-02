"""Operator-defined exceptions that silence expected alerts."""

from __future__ import annotations

import threading
import time
import uuid

RULE_FIELDS = ("type", "ip", "mac", "domain")


def normalize_rule(data: dict) -> dict:
    rule = {field: str(data[field]).strip().lower() for field in RULE_FIELDS if data.get(field)}
    if not rule:
        raise ValueError("a rule needs at least one of: " + ", ".join(RULE_FIELDS))
    rule["id"] = data.get("id") or uuid.uuid4().hex
    rule["comment"] = str(data.get("comment") or "")[:200]
    rule["created_at"] = data.get("created_at") or time.time()
    return rule


def _alert_ips(alert: dict) -> set[str]:
    evidence = alert.get("evidence") or {}
    return {value for value in (alert.get("source_ip"), alert.get("destination_ip"), evidence.get("ip")) if value}


def _alert_domains(alert: dict) -> set[str]:
    evidence = alert.get("evidence") or {}
    keys = ("domain", "indicator", "server_name", "target")
    return {str(evidence[key]).lower() for key in keys if evidence.get(key)}


class Allowlist:
    """Every field set on a rule must match; ``domain`` also matches subdomains."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rules: dict[str, dict] = {}
        self.hits = 0

    def load(self, rules: list[dict]) -> None:
        with self._lock:
            self._rules = {rule["id"]: rule for rule in rules}

    def add(self, data: dict) -> dict:
        rule = normalize_rule(data)
        with self._lock:
            self._rules[rule["id"]] = rule
        return dict(rule)

    def remove(self, rule_id: str) -> bool:
        with self._lock:
            return self._rules.pop(rule_id, None) is not None

    def rules(self) -> list[dict]:
        with self._lock:
            return sorted((dict(rule) for rule in self._rules.values()), key=lambda rule: rule["created_at"])

    def match(self, alert: dict) -> dict | None:
        with self._lock:
            rules = list(self._rules.values())
        if not rules:
            return None
        evidence = alert.get("evidence") or {}
        macs = {str(value).lower() for value in (evidence.get("mac"), evidence.get("previous_mac")) if value}
        ips = _alert_ips(alert)
        domains = _alert_domains(alert)
        for rule in rules:
            if "type" in rule and rule["type"] != alert["type"]:
                continue
            if "ip" in rule and rule["ip"] not in ips:
                continue
            if "mac" in rule and rule["mac"] not in macs:
                continue
            if "domain" in rule and not any(
                domain == rule["domain"] or domain.endswith("." + rule["domain"]) for domain in domains
            ):
                continue
            self.hits += 1
            return rule
        return None
