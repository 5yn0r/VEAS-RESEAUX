import os
import tempfile
import unittest

from moniwifi.alerts import make_alert
from moniwifi.storage import Storage


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.storage = Storage(":memory:")

    def tearDown(self):
        self.storage.close()

    def test_devices_keep_earliest_first_seen_and_latest_details(self):
        self.storage.upsert_devices({"aa:bb": {"ip": "192.168.1.5", "first_seen": 100.0}}, seen_at=100.0)
        self.storage.upsert_devices(
            {"aa:bb": {"ip": "192.168.1.6", "hostname": "nas", "first_seen": 300.0}}, seen_at=300.0
        )
        device = self.storage.known_devices()["aa:bb"]
        self.assertEqual(device["first_seen"], 100.0)
        self.assertEqual(device["last_seen"], 300.0)
        self.assertEqual(device["ip"], "192.168.1.6")
        self.assertEqual(device["hostname"], "nas")

    def test_alerts_round_trip_with_filters_in_chronological_order(self):
        first = make_alert("port_scan", "one", severity="medium", evidence={"ports": [1, 2]}, timestamp=10.0)
        second = make_alert("arp_spoof", "two", severity="high", timestamp=20.0)
        self.storage.add_alerts([first, second])
        self.storage.add_alerts([first])  # duplicates are ignored

        alerts = self.storage.recent_alerts()
        self.assertEqual([alert["detail"] for alert in alerts], ["one", "two"])
        self.assertEqual(alerts[0]["evidence"], {"ports": [1, 2]})
        self.assertEqual(alerts[0]["message"], "[PORT_SCAN] one")
        self.assertEqual([a["detail"] for a in self.storage.recent_alerts(severity="high")], ["two"])
        self.assertEqual([a["detail"] for a in self.storage.recent_alerts(alert_type="port_scan")], ["one"])
        self.assertEqual([a["detail"] for a in self.storage.recent_alerts(limit=1)], ["two"])

    def test_traffic_is_aggregated_per_hour(self):
        self.storage.add_traffic(
            [
                {"ip": "192.168.1.5", "timestamp": 3600.0, "upload": 10, "download": 1},
                {"ip": "192.168.1.5", "timestamp": 3700.0, "upload": 5, "download": 2},
                {"ip": "192.168.1.6", "timestamp": 3800.0, "upload": 1, "download": 1},
                {"ip": "192.168.1.5", "timestamp": 7300.0, "upload": 7, "download": 0},
            ]
        )
        self.assertEqual(
            self.storage.traffic_history(),
            [{"hour": 3600, "upload": 16, "download": 4}, {"hour": 7200, "upload": 7, "download": 0}],
        )
        self.assertEqual(
            self.storage.traffic_history(ip_addr="192.168.1.5", since=7200),
            [{"hour": 7200, "upload": 7, "download": 0}],
        )

    def test_purge_removes_data_older_than_retention(self):
        now = 10 * 86400.0
        self.storage.add_alerts([make_alert("old", "x", timestamp=now - 3 * 86400), make_alert("new", "y", timestamp=now)])
        self.storage.add_traffic([{"ip": "a", "timestamp": now - 3 * 86400, "upload": 1, "download": 1}])
        self.storage.upsert_devices({"aa": {"first_seen": 0.0}}, seen_at=now - 3 * 86400)

        self.storage.purge(retention_days=2, now=now)
        self.assertEqual([a["type"] for a in self.storage.recent_alerts()], ["new"])
        self.assertEqual(self.storage.traffic_history(), [])
        self.assertEqual(self.storage.known_devices(), {})

    def test_file_database_persists_between_connections(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "nested", "guardian.db")
            storage = Storage(path)
            storage.add_alerts([make_alert("port_scan", "kept")])
            storage.close()

            reopened = Storage(path)
            self.assertEqual(reopened.recent_alerts()[0]["detail"], "kept")
            self.assertTrue(reopened.health()["ok"])
            reopened.close()


if __name__ == "__main__":
    unittest.main()
