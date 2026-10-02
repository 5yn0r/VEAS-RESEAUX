"""Group related alerts per device into scored incidents."""

from __future__ import annotations

import threading
import time
import uuid
from collections import Counter

from moniwifi.attack import tactics_for, techniques_for

SEVERITY_WEIGHT = {"info": 1, "low": 2, "medium": 5, "high": 10, "critical": 25}
STATUSES = ("open", "acknowledged", "closed")
# Repeats of one alert type add less and less to the score.
MAX_COUNTED_PER_TYPE = 3
DIVERSITY_BONUS = 5
MAX_ALERTS_PER_INCIDENT = 200

# (first set, second set, bonus, explanation): both sets present in one incident.
CHAINS = (
    (
        {"new_device"},
        {"port_scan", "host_sweep", "ping_sweep", "arp_spoofing", "rogue_dhcp", "llmnr_poisoning", "brute_force"},
        15,
        "a newly connected device started reconnaissance or impersonation",
    ),
    (
        {"threat_intel_ip", "threat_intel_domain"},
        {"beaconing", "dns_tunnel", "traffic_anomaly"},
        20,
        "contact with a listed indicator plus command-and-control or exfiltration behaviour",
    ),
    ({"arp_spoofing", "ip_conflict"}, {"rogue_dhcp"}, 15, "address spoofing combined with a rogue DHCP server"),
    ({"exposed_service"}, {"port_scan", "host_sweep", "threat_intel_ip", "brute_force"}, 10, "an Internet-exposed service under active probing"),
    ({"llmnr_poisoning"}, {"brute_force", "arp_spoofing"}, 15, "credential capture combined with password guessing or interception"),
    ({"beaconing"}, {"traffic_anomaly", "dns_tunnel"}, 10, "regular callbacks together with unusual outbound data"),
)


def severity_for_score(score: int) -> str:
    if score >= 50:
        return "critical"
    if score >= 25:
        return "high"
    if score >= 10:
        return "medium"
    return "low"


class IncidentManager:
    def __init__(self, window: float = 3600.0, max_incidents: int = 1000) -> None:
        self.window = window
        self.max_incidents = max_incidents
        self._lock = threading.Lock()
        self._incidents: dict[str, dict] = {}
        self._open_by_entity: dict[str, str] = {}
        self._dirty: set[str] = set()

    def load(self, incidents: list[dict]) -> None:
        with self._lock:
            for incident in sorted(incidents, key=lambda item: item["last_seen"]):
                self._incidents[incident["id"]] = incident
                if incident["status"] != "closed":
                    self._open_by_entity[incident["entity"]] = incident["id"]

    def ingest(self, alert: dict, entity: dict) -> tuple[dict, str]:
        """Attach an alert to the entity's current incident or open a new one.

        Returns (incident copy, event) where event is ``created``, ``escalated`` or ``updated``.
        """
        now = alert.get("timestamp") or time.time()
        with self._lock:
            incident = self._incidents.get(self._open_by_entity.get(entity["key"], ""))
            if incident is None or incident["status"] == "closed" or now - incident["last_seen"] > self.window:
                incident = self._create(entity, now)
                event = "created"
            else:
                event = "updated"
            previous_severity = incident["severity"]
            incident["alerts"].append(
                {"id": alert["id"], "type": alert["type"], "severity": alert["severity"], "timestamp": now, "detail": alert["detail"]}
            )
            del incident["alerts"][:-MAX_ALERTS_PER_INCIDENT]
            incident["last_seen"] = max(incident["last_seen"], now)
            for field in ("ip", "mac", "hostname"):
                if entity.get(field):
                    incident[field] = entity[field]
            self._score(incident)
            if event == "updated" and SEVERITY_WEIGHT[incident["severity"]] > SEVERITY_WEIGHT[previous_severity]:
                event = "escalated"
                if incident["status"] == "acknowledged":
                    incident["status"] = "open"  # an escalation needs a fresh look
            self._dirty.add(incident["id"])
            return self._copy(incident), event

    def set_status(self, incident_id: str, status: str) -> dict | None:
        if status not in STATUSES:
            raise ValueError(f"unknown status: {status}")
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident is None:
                return None
            incident["status"] = status
            incident["updated_at"] = time.time()
            if status == "closed" and self._open_by_entity.get(incident["entity"]) == incident_id:
                del self._open_by_entity[incident["entity"]]
            elif status != "closed":
                self._open_by_entity[incident["entity"]] = incident_id
            self._dirty.add(incident_id)
            return self._copy(incident)

    def get(self, incident_id: str) -> dict | None:
        with self._lock:
            incident = self._incidents.get(incident_id)
            return self._copy(incident) if incident else None

    def list(self, status: str | None = None, limit: int = 100, min_severity: str | None = None) -> list[dict]:
        with self._lock:
            incidents = [
                self._copy(incident)
                for incident in self._incidents.values()
                if (not status or incident["status"] == status)
                and (not min_severity or SEVERITY_WEIGHT[incident["severity"]] >= SEVERITY_WEIGHT[min_severity])
            ]
        incidents.sort(key=lambda item: (item["status"] == "closed", -item["last_seen"]))
        return incidents[:limit]

    def drain_dirty(self) -> list[dict]:
        with self._lock:
            dirty = [self._copy(self._incidents[key]) for key in self._dirty if key in self._incidents]
            self._dirty.clear()
            return dirty

    def open_count(self) -> int:
        with self._lock:
            return sum(1 for incident in self._incidents.values() if incident["status"] != "closed")

    # Helpers -------------------------------------------------------------

    def _create(self, entity: dict, now: float) -> dict:
        incident = {
            "id": uuid.uuid4().hex,
            "entity": entity["key"],
            "ip": entity.get("ip"),
            "mac": entity.get("mac"),
            "hostname": entity.get("hostname"),
            "status": "open",
            "severity": "low",
            "score": 0,
            "first_seen": now,
            "last_seen": now,
            "updated_at": now,
            "alerts": [],
            "alert_types": {},
            "reasons": [],
            "summary": "",
        }
        self._incidents[incident["id"]] = incident
        self._open_by_entity[entity["key"]] = incident["id"]
        if len(self._incidents) > self.max_incidents:
            closed = sorted(
                (item for item in self._incidents.values() if item["status"] == "closed"),
                key=lambda item: item["last_seen"],
            )
            for old in closed[: len(self._incidents) - self.max_incidents]:
                del self._incidents[old["id"]]
        return incident

    @staticmethod
    def _score(incident: dict) -> None:
        types = Counter(alert["type"] for alert in incident["alerts"])
        worst: dict[str, int] = {}
        for alert in incident["alerts"]:
            worst[alert["type"]] = max(worst.get(alert["type"], 0), SEVERITY_WEIGHT.get(alert["severity"], 1))
        score = sum(weight * min(types[kind], MAX_COUNTED_PER_TYPE) for kind, weight in worst.items())
        score += DIVERSITY_BONUS * (len(types) - 1)
        reasons = []
        present = set(types)
        for first, second, bonus, explanation in CHAINS:
            if present & first and present & second:
                score += bonus
                reasons.append(explanation)
        incident["score"] = score
        # An incident is never less severe than its worst alert.
        worst_alert = max(incident["alerts"], key=lambda alert: SEVERITY_WEIGHT.get(alert["severity"], 1))["severity"]
        incident["severity"] = max(severity_for_score(score), worst_alert, key=lambda level: SEVERITY_WEIGHT.get(level, 1))
        incident["alert_types"] = dict(types)
        incident["reasons"] = reasons
        incident["mitre_tactics"] = tactics_for(types)
        incident["mitre_techniques"] = sorted({t["id"] for kind in types for t in techniques_for(kind)})
        subject = incident.get("hostname") or incident.get("ip") or incident.get("mac") or incident["entity"]
        kinds = ", ".join(kind.replace("_", " ") for kind, _ in types.most_common(3))
        incident["summary"] = f"{subject}: {kinds}" + (f" ({len(types) - 3} more)" if len(types) > 3 else "")

    @staticmethod
    def _copy(incident: dict) -> dict:
        data = dict(incident)
        data["alerts"] = [dict(alert) for alert in incident["alerts"]]
        data["alert_types"] = dict(incident["alert_types"])
        data["reasons"] = list(incident["reasons"])
        data["mitre_tactics"] = list(incident.get("mitre_tactics", []))
        data["mitre_techniques"] = list(incident.get("mitre_techniques", []))
        return data
