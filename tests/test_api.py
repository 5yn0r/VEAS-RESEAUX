import os
import tempfile
import unittest
from unittest import mock

import config
from moniwifi.alerts import make_alert
from moniwifi.application import create_app
from tests.helpers import FakeNetwork


class ApiTests(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(config, "NEW_DEVICE_LEARNING_PERIOD", 0):
            self.app, _, self.monitor = create_app(db_path=":memory:", network=FakeNetwork())
        self.client = self.app.test_client()
        self.storage = self.monitor.storage

    def test_health_reports_degraded_before_start(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["status"], "degraded")

    def test_alerts_come_from_history_with_filters(self):
        self.storage.add_alerts(
            [
                make_alert("port_scan", "a", severity="medium", timestamp=1.0),
                make_alert("arp_spoof", "b", severity="high", timestamp=2.0),
            ]
        )
        self.assertEqual([a["detail"] for a in self.client.get("/api/alerts").get_json()], ["a", "b"])
        self.assertEqual(
            [a["detail"] for a in self.client.get("/api/alerts?severity=high").get_json()],
            ["b"],
        )
        self.assertEqual(self.client.get("/api/alerts?severity=bogus").status_code, 400)
        self.assertEqual(self.client.get("/api/alerts?limit=x").status_code, 400)

    def test_traffic_history_and_known_devices(self):
        self.storage.add_traffic([{"ip": "192.168.1.5", "timestamp": 1e12, "upload": 3, "download": 4}])
        self.monitor.observe_device("aa:bb:cc:00:00:01", "192.168.1.5", "scan")
        history = self.client.get("/api/traffic/history?hours=1").get_json()
        self.assertEqual(history[-1]["upload"], 3)
        self.assertIn("aa:bb:cc:00:00:01", self.client.get("/api/devices/known").get_json())

    def test_network_endpoint(self):
        with mock.patch("moniwifi.linkinfo.NetworkInfo.collect", return_value={"connected": True, "interface": {"name": "eth0"}}) as collect:
            response = self.client.get("/api/network")
        self.assertEqual(response.get_json()["interface"]["name"], "eth0")
        collect.assert_called_once_with("eth0", "192.168.1.1")

    def test_existing_endpoints_still_respond(self):
        for path in ("/api/stats", "/api/devices", "/api/traffic", "/api/packets", "/api/packets/summary", "/"):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        self.assertEqual(self.client.get("/api/packets?port=70000").status_code, 400)

    def test_device_detail_flows_and_dns_endpoints(self):
        self.monitor.observe_device("aa:bb:cc:00:00:01", "192.168.1.5", "scan")
        self.monitor.state.flows.update(
            protocol="TCP", src_ip="192.168.1.5", src_port=40000, dst_ip="1.1.1.1", dst_port=443,
            size=10, direction="outbound", tcp_flags="S",
        )
        self.monitor.state.domains.record_query("192.168.1.5", "example.com", "A")
        self.monitor.flush_once()

        detail = self.client.get("/api/devices/AA:BB:CC:00:00:01").get_json()
        self.assertEqual(detail["device"]["ip"], "192.168.1.5")
        self.assertEqual(detail["flows"][0]["server_ip"], "1.1.1.1")
        self.assertEqual(detail["dns"][0]["query"], "example.com")
        self.assertEqual(detail["domains"][0]["domain"], "example.com")
        self.assertEqual(detail["alerts"][0]["type"], "new_device")
        self.assertEqual(self.client.get("/api/devices/00:00:00:00:00:99").status_code, 404)

        self.assertEqual(self.client.get("/api/flows?ip=1.1.1.1").get_json()[0]["client_ip"], "192.168.1.5")
        self.assertEqual(self.client.get("/api/dns?q=example").get_json()[0]["client_ip"], "192.168.1.5")
        self.assertEqual(self.client.get("/api/domains").get_json()[0]["count"], 1)
        self.assertEqual(self.client.get("/api/flows?history=1").get_json(), [])

    def scan_alert(self):
        for port in range(1, 25):
            self.monitor.detector.on_tcp_syn("192.168.1.10", "192.168.1.1", port)
        self.monitor.flush_once()

    def test_alerts_become_incidents_with_status_workflow(self):
        self.monitor.observe_device("aa:bb:cc:00:00:10", "192.168.1.10", "scan")
        self.monitor.detector.on_traffic([{"ip": "192.168.1.10", "upload": 100, "download": 100}])
        self.monitor.flush_once()
        self.scan_alert()

        incidents = self.client.get("/api/incidents").get_json()
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(incident["entity"], "aa:bb:cc:00:00:10")
        self.assertEqual(set(incident["alert_types"]), {"new_device", "port_scan"})
        self.assertEqual(self.client.get("/api/stats").get_json()["open_incidents"], 1)

        url = f"/api/incidents/{incident['id']}"
        self.assertEqual(self.client.post(url, data="status=closed").status_code, 415)
        self.assertEqual(self.client.post(url, json={"status": "bogus"}).status_code, 400)
        closed = self.client.post(url, json={"status": "closed"}).get_json()
        self.assertEqual(closed["status"], "closed")
        self.assertEqual(self.client.get("/api/incidents?status=open").get_json(), [])
        self.assertEqual(self.client.get("/api/incidents/missing").status_code, 404)
        self.assertEqual(self.client.get("/api/incidents?severity=bogus").status_code, 400)

        detail = self.client.get("/api/devices/aa:bb:cc:00:00:10").get_json()
        self.assertEqual(detail["incidents"][0]["id"], incident["id"])
        self.assertIsNotNone(detail["baseline"])

    def test_allowlist_crud_suppresses_alerts(self):
        response = self.client.post("/api/allowlist", json={"type": "port_scan", "ip": "192.168.1.10", "comment": "nmap box"})
        self.assertEqual(response.status_code, 201)
        rule = response.get_json()
        self.assertEqual(self.client.post("/api/allowlist", json={"comment": "empty"}).status_code, 400)
        self.scan_alert()
        self.assertNotIn("port_scan", [a["type"] for a in self.client.get("/api/alerts").get_json()])
        self.assertEqual(self.monitor.detector.stats()["allowlisted"], 1)
        self.assertEqual(self.storage.load_allowlist()[0]["id"], rule["id"])

        self.assertEqual(self.client.delete(f"/api/allowlist/{rule['id']}").status_code, 204)
        self.assertEqual(self.client.delete(f"/api/allowlist/{rule['id']}").status_code, 404)
        self.assertEqual(self.client.get("/api/allowlist").get_json(), [])

    def test_notification_test_endpoint(self):
        self.assertEqual(self.client.post("/api/notifications/test", json={}).status_code, 409)
        channel = mock.Mock()
        channel.name = "mock"
        self.monitor.notifier.channels = [channel]
        response = self.client.post("/api/notifications/test", json={})
        self.assertEqual(response.get_json(), {"results": {"mock": None}})
        channel.send.side_effect = RuntimeError("down")
        self.assertEqual(self.client.post("/api/notifications/test", json={}).status_code, 502)

    def test_high_incident_is_queued_for_notification(self):
        channel = mock.Mock()
        channel.name = "mock"
        self.monitor.notifier.channels = [channel]
        self.monitor.detector.emit("arp_spoofing", "spoof", severity="critical", key=("x",), evidence={"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:66"})
        self.monitor.flush_once()
        self.assertEqual(self.monitor.notifier.stats()["queued"], 1)

    def test_exports(self):
        self.storage.add_alerts([make_alert("port_scan", "exported, with comma", evidence={"ports": [1, 2]})])
        self.monitor.observe_device("aa:bb:cc:00:00:01", "192.168.1.5", "scan")
        response = self.client.get("/api/export/alerts")
        self.assertEqual(response.mimetype, "text/csv")
        self.assertIn("attachment; filename=\"wifi-guardian-alerts-", response.headers["Content-Disposition"])
        text = response.get_data(as_text=True)
        self.assertIn('"exported, with comma"', text)
        self.assertIn('"{""ports"": [1, 2]}"', text)

        devices = self.client.get("/api/export/devices?format=json").get_json()
        self.assertEqual(devices[0]["mac"], "aa:bb:cc:00:00:01")
        for kind in ("incidents", "flows", "dns", "domains"):
            self.assertEqual(self.client.get(f"/api/export/{kind}").status_code, 200, kind)
        self.assertEqual(self.client.get("/api/export/secrets").status_code, 404)
        self.assertEqual(self.client.get("/api/export/alerts?format=xml").status_code, 400)


class PersistenceReloadTests(unittest.TestCase):
    def test_incidents_allowlist_and_baselines_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(config, "NEW_DEVICE_LEARNING_PERIOD", 0):
            path = os.path.join(directory, "guardian.db")
            app, _, monitor = create_app(db_path=path, network=FakeNetwork())
            client = app.test_client()
            client.post("/api/allowlist", json={"domain": "vendor.example"})
            monitor.observe_device("aa:bb:cc:00:00:10", "192.168.1.10", "scan")
            monitor.detector.on_traffic([{"ip": "192.168.1.10", "upload": 10, "download": 5}])
            monitor.flush_once()
            monitor._last_maintenance = 0
            monitor.flush_once()
            monitor.storage.close()

            app2, _, monitor2 = create_app(db_path=path, network=FakeNetwork())
            client2 = app2.test_client()
            self.assertEqual(client2.get("/api/allowlist").get_json()[0]["domain"], "vendor.example")
            self.assertEqual(client2.get("/api/incidents").get_json()[0]["alert_types"], {"new_device": 1})
            self.assertIsNotNone(monitor2.baselines.snapshot("aa:bb:cc:00:00:10"))
            monitor2.storage.close()


class ApiWithoutStorageTests(unittest.TestCase):
    def test_memory_mode_serves_alerts_and_hides_history(self):
        app, _, monitor = create_app(db_path="", network=FakeNetwork())
        client = app.test_client()
        monitor.state.load_alerts([make_alert("port_scan", "mem")])
        self.assertEqual(client.get("/api/alerts").get_json()[0]["detail"], "mem")
        self.assertEqual(client.get("/api/traffic/history").status_code, 404)


if __name__ == "__main__":
    unittest.main()
