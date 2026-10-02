"""SQLite persistence for devices, alerts, and hourly traffic totals."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path

from veas.attack import techniques_for

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    vendor TEXT,
    hostname TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    timestamp REAL NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    detail TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS alerts_timestamp ON alerts (timestamp);
CREATE TABLE IF NOT EXISTS traffic_hourly (
    ip TEXT NOT NULL,
    hour INTEGER NOT NULL,
    upload INTEGER NOT NULL DEFAULT 0,
    download INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, hour)
);
CREATE INDEX IF NOT EXISTS traffic_hourly_hour ON traffic_hourly (hour);
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    client_port INTEGER,
    server_ip TEXT NOT NULL,
    server_port INTEGER,
    direction TEXT,
    server_name TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    packets_out INTEGER NOT NULL,
    bytes_out INTEGER NOT NULL,
    packets_in INTEGER NOT NULL,
    bytes_in INTEGER NOT NULL,
    tcp_flags TEXT
);
CREATE INDEX IF NOT EXISTS flows_last_seen ON flows (last_seen);
CREATE INDEX IF NOT EXISTS flows_client ON flows (client_ip, last_seen);
CREATE TABLE IF NOT EXISTS domains (
    client_ip TEXT NOT NULL,
    domain TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (client_ip, domain, source)
);
CREATE INDEX IF NOT EXISTS domains_last_seen ON domains (last_seen);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    last_seen REAL NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_last_seen ON incidents (last_seen);
CREATE TABLE IF NOT EXISTS baselines (
    key TEXT PRIMARY KEY,
    updated_at REAL NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS allowlist (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    data TEXT NOT NULL
);
"""

DEVICE_COLUMNS = ("ip", "vendor", "hostname", "first_seen", "last_seen")


class Storage:
    """Thread-safe wrapper around one SQLite connection.

    The monitor writes from its worker threads and Flask reads from request
    threads; a single connection behind a lock keeps SQLite's writer rules
    simple for this low-volume, single-process workload.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()
        self.last_error: str | None = None
        self.last_write_at: float | None = None

    def _migrate(self) -> None:
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(devices)")}
        if "details" not in columns:
            self._conn.execute("ALTER TABLE devices ADD COLUMN details TEXT NOT NULL DEFAULT '{}'")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _write(self, sql: str, rows) -> None:
        rows = list(rows)
        if not rows:
            return
        with self._lock:
            try:
                with self._conn:
                    self._conn.executemany(sql, rows)
            except sqlite3.Error as exc:
                self.last_error = str(exc)
                raise
            self.last_error = None
            self.last_write_at = time.time()

    def _query(self, sql: str, params=()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    # Devices ---------------------------------------------------------------

    def upsert_devices(self, devices: dict[str, dict], seen_at: float | None = None) -> None:
        """Upsert devices; keys outside the base columns are kept in the ``details`` JSON."""
        seen_at = time.time() if seen_at is None else seen_at
        self._write(
            """
            INSERT INTO devices (mac, ip, vendor, hostname, first_seen, last_seen, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ip = COALESCE(excluded.ip, devices.ip),
                vendor = COALESCE(excluded.vendor, devices.vendor),
                hostname = COALESCE(excluded.hostname, devices.hostname),
                first_seen = MIN(devices.first_seen, excluded.first_seen),
                last_seen = MAX(devices.last_seen, excluded.last_seen),
                details = excluded.details
            """,
            (
                (
                    mac,
                    device.get("ip"),
                    device.get("vendor"),
                    device.get("hostname"),
                    float(device.get("first_seen", seen_at)),
                    float(device.get("last_seen", seen_at)),
                    json.dumps(
                        {key: value for key, value in device.items() if key not in DEVICE_COLUMNS and key != "mac"},
                        default=list,
                    ),
                )
                for mac, device in devices.items()
            ),
        )

    def known_devices(self) -> dict[str, dict]:
        rows = self._query("SELECT * FROM devices ORDER BY last_seen DESC")
        devices = {}
        for row in rows:
            device = {key: row[key] for key in DEVICE_COLUMNS}
            device["details"] = json.loads(row["details"] or "{}")
            devices[row["mac"]] = device
        return devices

    # Alerts ----------------------------------------------------------------

    def add_alerts(self, alerts: list[dict]) -> None:
        self._write(
            """
            INSERT OR IGNORE INTO alerts
                (id, type, severity, timestamp, source_ip, destination_ip, detail, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    alert["id"],
                    alert["type"],
                    alert["severity"],
                    alert["timestamp"],
                    alert.get("source_ip"),
                    alert.get("destination_ip"),
                    alert["detail"],
                    json.dumps(alert.get("evidence") or {}),
                )
                for alert in alerts
            ),
        )

    def recent_alerts(
        self,
        limit: int = 100,
        severity: str | None = None,
        alert_type: str | None = None,
        since: float | None = None,
    ) -> list[dict]:
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if alert_type:
            clauses.append("type = ?")
            params.append(alert_type)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._query(
            f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?",
            (*params, limit),
        )
        alerts = []
        for row in reversed(rows):
            alert = {key: row[key] for key in row.keys()}
            alert["evidence"] = json.loads(alert["evidence"] or "{}")
            alert["message"] = f"[{alert['type'].upper()}] {alert['detail']}"
            alert["mitre"] = techniques_for(alert["type"])
            alerts.append(alert)
        return alerts

    # Traffic ---------------------------------------------------------------

    def add_traffic(self, events: list[dict]) -> None:
        self._write(
            """
            INSERT INTO traffic_hourly (ip, hour, upload, download)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip, hour) DO UPDATE SET
                upload = upload + excluded.upload,
                download = download + excluded.download
            """,
            (
                (event["ip"], int(event["timestamp"] // 3600) * 3600, event["upload"], event["download"])
                for event in events
            ),
        )

    def traffic_history(self, ip_addr: str | None = None, since: float | None = None) -> list[dict]:
        clauses, params = [], []
        if ip_addr:
            clauses.append("ip = ?")
            params.append(ip_addr)
        if since is not None:
            clauses.append("hour >= ?")
            params.append(int(since // 3600) * 3600)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._query(
            f"""
            SELECT hour, SUM(upload) AS upload, SUM(download) AS download
            FROM traffic_hourly {where}
            GROUP BY hour ORDER BY hour
            """,
            params,
        )
        return [{"hour": row["hour"], "upload": row["upload"], "download": row["download"]} for row in rows]

    # Flows and domains -----------------------------------------------------

    FLOW_COLUMNS = (
        "protocol", "client_ip", "client_port", "server_ip", "server_port", "direction", "server_name",
        "first_seen", "last_seen", "packets_out", "bytes_out", "packets_in", "bytes_in", "tcp_flags",
    )

    def add_flows(self, flows: list[dict]) -> None:
        columns = ", ".join(self.FLOW_COLUMNS)
        placeholders = ", ".join("?" for _ in self.FLOW_COLUMNS)
        self._write(
            f"INSERT INTO flows ({columns}) VALUES ({placeholders})",
            (tuple(flow.get(column) for column in self.FLOW_COLUMNS) for flow in flows),
        )

    def recent_flows(
        self,
        limit: int = 100,
        ip_addr: str | None = None,
        since: float | None = None,
        server_name: str | None = None,
    ) -> list[dict]:
        clauses, params = [], []
        if ip_addr:
            clauses.append("(client_ip = ? OR server_ip = ?)")
            params += [ip_addr, ip_addr]
        if since is not None:
            clauses.append("last_seen >= ?")
            params.append(since)
        if server_name:
            clauses.append("server_name LIKE ?")
            params.append(f"%{server_name}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._query(f"SELECT * FROM flows {where} ORDER BY last_seen DESC LIMIT ?", (*params, limit))
        return [{key: row[key] for key in row.keys()} for row in rows]

    def add_domain_observations(self, observations: list[dict]) -> None:
        self._write(
            """
            INSERT INTO domains (client_ip, domain, source, first_seen, last_seen, count)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(client_ip, domain, source) DO UPDATE SET
                first_seen = MIN(domains.first_seen, excluded.first_seen),
                last_seen = MAX(domains.last_seen, excluded.last_seen),
                count = domains.count + excluded.count
            """,
            (
                (item["client_ip"], item["domain"], item["source"], item["first_seen"], item["last_seen"], item["count"])
                for item in observations
            ),
        )

    def domains(self, client_ip: str | None = None, since: float | None = None, limit: int = 200) -> list[dict]:
        clauses, params = [], []
        if client_ip:
            clauses.append("client_ip = ?")
            params.append(client_ip)
        if since is not None:
            clauses.append("last_seen >= ?")
            params.append(since)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._query(
            f"""
            SELECT domain, GROUP_CONCAT(DISTINCT client_ip) AS clients, GROUP_CONCAT(DISTINCT source) AS sources,
                   SUM(count) AS count, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen
            FROM domains {where}
            GROUP BY domain ORDER BY count DESC LIMIT ?
            """,
            (*params, limit),
        )
        return [
            {
                "domain": row["domain"],
                "clients": sorted(row["clients"].split(",")),
                "sources": sorted(row["sources"].split(",")),
                "count": row["count"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
            }
            for row in rows
        ]

    # Incidents, baselines, allowlist --------------------------------------

    def upsert_incidents(self, incidents: list[dict]) -> None:
        self._write(
            """
            INSERT INTO incidents (id, status, severity, score, last_seen, data) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status, severity = excluded.severity, score = excluded.score,
                last_seen = excluded.last_seen, data = excluded.data
            """,
            (
                (item["id"], item["status"], item["severity"], item["score"], item["last_seen"], json.dumps(item))
                for item in incidents
            ),
        )

    def load_incidents(self, since: float | None = None) -> list[dict]:
        since = 0 if since is None else since
        rows = self._query("SELECT data FROM incidents WHERE last_seen >= ? ORDER BY last_seen", (since,))
        return [json.loads(row["data"]) for row in rows]

    def upsert_baselines(self, baselines: dict[str, dict]) -> None:
        now = time.time()
        self._write(
            """
            INSERT INTO baselines (key, updated_at, data) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET updated_at = excluded.updated_at, data = excluded.data
            """,
            ((key, now, json.dumps(data)) for key, data in baselines.items()),
        )

    def load_baselines(self) -> dict[str, dict]:
        return {row["key"]: json.loads(row["data"]) for row in self._query("SELECT key, data FROM baselines")}

    def save_allowlist_rule(self, rule: dict) -> None:
        self._write(
            "INSERT OR REPLACE INTO allowlist (id, created_at, data) VALUES (?, ?, ?)",
            [(rule["id"], rule["created_at"], json.dumps(rule))],
        )

    def delete_allowlist_rule(self, rule_id: str) -> None:
        self._write("DELETE FROM allowlist WHERE id = ?", [(rule_id,)])

    def load_allowlist(self) -> list[dict]:
        return [json.loads(row["data"]) for row in self._query("SELECT data FROM allowlist ORDER BY created_at")]

    # Maintenance -----------------------------------------------------------

    def purge(self, retention_days: int, now: float | None = None) -> None:
        cutoff = (time.time() if now is None else now) - retention_days * 86400
        with self._lock:
            try:
                with self._conn:
                    self._conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
                    self._conn.execute("DELETE FROM traffic_hourly WHERE hour < ?", (cutoff,))
                    self._conn.execute("DELETE FROM devices WHERE last_seen < ?", (cutoff,))
                    self._conn.execute("DELETE FROM flows WHERE last_seen < ?", (cutoff,))
                    self._conn.execute("DELETE FROM domains WHERE last_seen < ?", (cutoff,))
                    self._conn.execute("DELETE FROM incidents WHERE last_seen < ?", (cutoff,))
                    self._conn.execute("DELETE FROM baselines WHERE updated_at < ?", (cutoff,))
            except sqlite3.Error as exc:
                self.last_error = str(exc)
                raise

    def health(self) -> dict:
        return {
            "enabled": True,
            "path": self.path,
            "ok": self.last_error is None,
            "last_error": self.last_error,
            "last_write_at": self.last_write_at,
        }
