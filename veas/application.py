from __future__ import annotations

import csv
import io
import json
import logging
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, abort, g, jsonify, render_template, request
from flask_socketio import SocketIO

import config
from veas.alerts import SEVERITIES
from veas.auth import AuthSettings, init_auth
from veas.incidents import STATUSES
from veas.linkinfo import NetworkInfo
from veas.monitor import NetworkMonitor
from veas.state import MonitorState
from veas.storage import Storage

logger = logging.getLogger(__name__)


def _bounded_int(name: str, default: int, maximum: int) -> int:
    try:
        return max(1, min(int(request.args.get(name, default)), maximum))
    except ValueError:
        abort(400, description=f"{name} must be an integer")


EXPORT_KINDS = ("alerts", "incidents", "devices", "flows", "dns", "domains")


def _to_csv(rows: list[dict]) -> str:
    columns: list[str] = []
    for row in rows:
        columns += [key for key in row if key not in columns]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {key: json.dumps(value, default=list) if isinstance(value, (dict, list, set, tuple)) else value for key, value in row.items()}
        )
    return buffer.getvalue()


def _open_storage(db_path: str | None):
    if not db_path:
        return None
    try:
        return Storage(db_path)
    except Exception as exc:  # noqa: BLE001 - monitoring still works without history
        logger.error("Persistence disabled, cannot open %s: %s", db_path, exc)
        return None


def create_app(db_path: str | None = None, network=None):
    """Build the Flask app. ``db_path=None`` uses ``config.DB_PATH``; ``""`` disables storage."""
    logging.basicConfig(level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))
    project_root = Path(__file__).resolve().parent.parent
    template_dir = project_root / "templates"

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(project_root / "static"),
        static_url_path="/static",
    )
    app.config["SECRET_KEY"] = config.SECRET_KEY
    socketio = SocketIO(app, cors_allowed_origins=config.CORS_ALLOWED_ORIGINS)
    init_auth(
        app,
        socketio,
        AuthSettings(config.AUTH_USERNAME, config.AUTH_PASSWORD_HASH, config.AUTH_PASSWORD, config.API_TOKEN),
        host=config.HOST,
        allow_unauthenticated=config.ALLOW_UNAUTHENTICATED,
    )
    state = MonitorState(
        max_alerts=config.MAX_ALERTS,
        max_history=config.MAX_HISTORY,
        max_dns_cache=config.MAX_DNS_CACHE,
        max_packet_history=config.MAX_PACKET_HISTORY,
        device_active_timeout=config.DEVICE_ACTIVE_TIMEOUT,
        new_device_learning_period=config.NEW_DEVICE_LEARNING_PERIOD,
        max_active_flows=config.MAX_ACTIVE_FLOWS,
        max_dns_log=config.MAX_DNS_LOG,
    )
    storage = _open_storage(config.DB_PATH if db_path is None else db_path)
    monitor = NetworkMonitor(socketio=socketio, state=state, storage=storage, network=network)
    monitor.load_persisted_state()

    def json_body() -> dict:
        # Requiring a JSON body blocks cross-site form posts (they cannot set this content type).
        if not request.is_json:
            abort(415, description="expected application/json")
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            abort(400, description="expected a JSON object")
        return body

    def require_storage():
        if not storage:
            abort(404, description="persistence is disabled")
        return storage

    @app.route("/")
    def index():
        return render_template("dashboard.html", auth_enabled=app.config["AUTH_ENABLED"])

    @app.route("/api/stats")
    def api_stats():
        return {**state.stats(), "open_incidents": monitor.incidents.open_count()}

    link_info = NetworkInfo(oui=monitor.oui)

    @app.route("/api/network")
    def api_network():
        return link_info.collect(monitor.network.interface(), monitor.network.gateway_ip())

    @app.route("/api/devices")
    def api_devices():
        return state.devices_snapshot()

    @app.route("/api/health")
    def api_health():
        health = monitor.health()
        code = 200 if health["status"] == "ok" else 503
        if app.config["AUTH_ENABLED"] and not g.get("authenticated"):
            # Unauthenticated callers (container healthchecks) only learn the status.
            return jsonify({"status": health["status"]}), code
        return jsonify(health), code

    @app.route("/api/devices/known")
    def api_known_devices():
        return state.devices.all()

    @app.route("/api/devices/<mac>")
    def api_device(mac):
        device = state.devices.get(mac)
        if not device:
            abort(404, description="unknown device")
        ip_addr = device.get("ip")
        detail = {"device": device, "flows": [], "dns": [], "domains": [], "alerts": []}
        if ip_addr:
            detail["flows"] = state.flows.snapshot(limit=50, ip_addr=ip_addr)
            detail["dns"] = state.domains.recent(limit=50, client_ip=ip_addr)
            detail["alerts"] = [
                alert
                for alert in state.alerts_snapshot(limit=config.MAX_ALERTS)
                if ip_addr in (alert.get("source_ip"), alert.get("destination_ip"))
                or alert.get("evidence", {}).get("mac") == device["mac"]
            ]
            if storage:
                try:
                    detail["domains"] = storage.domains(client_ip=ip_addr, limit=50)
                except Exception as exc:  # noqa: BLE001
                    logger.error("Domain query failed: %s", exc)
        detail["baseline"] = monitor.baselines.snapshot(device["mac"])
        detail["incidents"] = [
            incident for incident in monitor.incidents.list(limit=1000) if incident["entity"] == device["mac"]
        ][:20]
        return detail

    @app.route("/api/incidents")
    def api_incidents():
        status = request.args.get("status") or None
        if status and status not in STATUSES:
            abort(400, description="unsupported status")
        severity = request.args.get("severity") or None
        if severity and severity not in SEVERITIES:
            abort(400, description="unsupported severity")
        return jsonify(
            monitor.incidents.list(status=status, min_severity=severity, limit=_bounded_int("limit", 100, 1000))
        )

    @app.route("/api/incidents/<incident_id>", methods=["GET", "POST"])
    def api_incident(incident_id):
        if request.method == "POST":
            status = json_body().get("status")
            if status not in STATUSES:
                abort(400, description="status must be one of " + ", ".join(STATUSES))
            incident = monitor.incidents.set_status(incident_id, status)
            if incident:
                monitor._persist("upsert_incidents", [incident])
                monitor.siem.submit_incident(incident, "status")
                socketio.emit("incident_update", {"event": "status", "incident": incident})
        else:
            incident = monitor.incidents.get(incident_id)
        if not incident:
            abort(404, description="unknown incident")
        return incident

    @app.route("/api/allowlist", methods=["GET", "POST"])
    def api_allowlist():
        if request.method == "GET":
            return jsonify(monitor.allowlist.rules())
        try:
            rule = monitor.allowlist.add(json_body())
        except ValueError as exc:
            abort(400, description=str(exc))
        monitor._persist("save_allowlist_rule", rule)
        return rule, 201

    @app.route("/api/allowlist/<rule_id>", methods=["DELETE"])
    def api_allowlist_delete(rule_id):
        if not monitor.allowlist.remove(rule_id):
            abort(404, description="unknown rule")
        monitor._persist("delete_allowlist_rule", rule_id)
        return "", 204

    @app.route("/api/export/<kind>")
    def api_export(kind):
        if kind not in EXPORT_KINDS:
            abort(404, description="export kinds: " + ", ".join(EXPORT_KINDS))
        export_format = request.args.get("format", "csv")
        if export_format not in ("csv", "json"):
            abort(400, description="format must be csv or json")
        since = time.time() - _bounded_int("hours", 24, config.RETENTION_DAYS * 24) * 3600
        if kind == "alerts":
            rows = storage.recent_alerts(limit=100000, since=since) if storage else state.alerts_snapshot(limit=100000)
        elif kind == "incidents":
            rows = [dict(item, alerts=len(item["alerts"])) for item in monitor.incidents.list(limit=100000) if item["last_seen"] >= since]
        elif kind == "devices":
            rows = [dict(device, mac=mac) for mac, device in state.devices.all().items()]
        elif kind == "flows":
            rows = require_storage().recent_flows(limit=100000, since=since)
        elif kind == "dns":
            rows = [entry for entry in state.domains.recent(limit=config.MAX_DNS_LOG) if entry["timestamp"] >= since]
        else:
            rows = require_storage().domains(since=since, limit=100000)

        filename = f"veas-reseaux-{kind}-{datetime.now():%Y%m%d-%H%M}.{export_format}"
        body = json.dumps(rows, default=list, indent=2) if export_format == "json" else _to_csv(rows)
        return Response(
            body,
            mimetype="application/json" if export_format == "json" else "text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.route("/api/notifications/test", methods=["POST"])
    def api_notifications_test():
        json_body()
        if not monitor.notifier.enabled:
            abort(409, description="no notification channel is configured")
        sample = {
            "id": "test",
            "entity": "test",
            "ip": None,
            "mac": None,
            "hostname": "VEAS RÉSEAUX",
            "status": "open",
            "severity": "high",
            "score": 0,
            "alert_types": {"test": 1},
            "reasons": ["this is a test notification"],
            "alerts": [],
        }
        results = monitor.notifier.send_now(sample, "test")
        return {"results": results}, 200 if all(error is None for error in results.values()) else 502

    @app.route("/api/flows")
    def api_flows():
        limit = _bounded_int("limit", 100, 1000)
        ip_addr = request.args.get("ip") or None
        if request.args.get("history") in ("1", "true"):
            hours = _bounded_int("hours", 24, config.RETENTION_DAYS * 24)
            return jsonify(
                require_storage().recent_flows(
                    limit=limit,
                    ip_addr=ip_addr,
                    since=time.time() - hours * 3600,
                    server_name=request.args.get("name") or None,
                )
            )
        return jsonify(state.flows.snapshot(limit=limit, ip_addr=ip_addr))

    @app.route("/api/dns")
    def api_dns():
        return jsonify(
            state.domains.recent(
                limit=_bounded_int("limit", 100, config.MAX_DNS_LOG),
                client_ip=request.args.get("ip") or None,
                query=request.args.get("q") or None,
            )
        )

    @app.route("/api/domains")
    def api_domains():
        hours = _bounded_int("hours", 24, config.RETENTION_DAYS * 24)
        return jsonify(
            require_storage().domains(
                client_ip=request.args.get("ip") or None,
                since=time.time() - hours * 3600,
                limit=_bounded_int("limit", 200, 5000),
            )
        )

    @app.route("/api/alerts")
    def api_alerts():
        limit = _bounded_int("limit", 50, max(config.MAX_ALERTS, 1000))
        severity = request.args.get("severity") or None
        if severity and severity not in SEVERITIES:
            abort(400, description="unsupported severity")
        alert_type = request.args.get("type") or None
        if storage:
            try:
                return storage.recent_alerts(limit=limit, severity=severity, alert_type=alert_type)
            except Exception as exc:  # noqa: BLE001 - fall back to in-memory alerts
                logger.error("Alert history query failed: %s", exc)
        return state.alerts_snapshot(limit=limit, severity=severity, alert_type=alert_type)

    @app.route("/api/traffic")
    def api_traffic():
        return state.traffic_snapshot(limit=_bounded_int("limit", 10, config.MAX_HISTORY))

    @app.route("/api/traffic/history")
    def api_traffic_history():
        hours = _bounded_int("hours", 24, config.RETENTION_DAYS * 24)
        return jsonify(
            require_storage().traffic_history(
                ip_addr=request.args.get("ip") or None,
                since=time.time() - hours * 3600,
            )
        )

    @app.route("/api/packets")
    def api_packets():
        port_value = request.args.get("port")
        try:
            port = int(port_value) if port_value else None
        except ValueError:
            abort(400, description="port must be an integer")
        if port is not None and not 1 <= port <= 65535:
            abort(400, description="port must be between 1 and 65535")

        protocol = request.args.get("protocol", "").upper() or None
        if protocol and protocol not in {"TCP", "UDP", "ICMP", "IP"}:
            abort(400, description="unsupported protocol")
        direction = request.args.get("direction") or None
        if direction and direction not in {"inbound", "outbound", "local"}:
            abort(400, description="unsupported direction")

        return state.packets_snapshot(
            limit=_bounded_int("limit", 100, config.MAX_PACKET_HISTORY),
            ip_addr=request.args.get("ip") or None,
            protocol=protocol,
            port=port,
            direction=direction,
        )

    @app.route("/api/packets/summary")
    def api_packets_summary():
        return state.packets_summary()

    return app, socketio, monitor
