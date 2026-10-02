import unittest

from moniwifi.alerts import make_alert
from moniwifi.state import MonitorState


class MonitorStateTests(unittest.TestCase):
    def test_devices_are_active_until_timeout_and_keep_first_seen(self):
        state = MonitorState(max_alerts=10, device_active_timeout=100)
        device = {"ip": "192.168.1.10", "vendor": "Example", "hostname": "laptop"}
        state.devices.observe("aa:bb:cc:dd:ee:ff", ip="192.168.1.10", source="scan", now=100.0)
        state.devices.observe("aa:bb:cc:dd:ee:ff", ip="192.168.1.10", source="scan", now=200.0)
        state.upsert_devices({"11:22:33:44:55:66": device})

        snapshot = state.devices.active(now=250.0)
        self.assertEqual(snapshot["aa:bb:cc:dd:ee:ff"]["first_seen"], 100.0)
        self.assertEqual(snapshot["aa:bb:cc:dd:ee:ff"]["last_seen"], 200.0)
        self.assertNotIn("aa:bb:cc:dd:ee:ff", state.devices.active(now=301.0))
        self.assertEqual(state.stats()["devices_count"], 1)

    def test_dns_cache_is_bounded_and_keeps_recent_entry(self):
        state = MonitorState(max_alerts=10, max_dns_cache=2)
        state.cache_hostname("192.168.1.1", "one")
        state.cache_hostname("192.168.1.2", "two")
        self.assertEqual(state.get_cached_hostname("192.168.1.1"), "one")
        state.cache_hostname("192.168.1.3", "three")

        self.assertIsNone(state.get_cached_hostname("192.168.1.2"))
        self.assertEqual(state.get_cached_hostname("192.168.1.1"), "one")
        self.assertEqual(state.get_cached_hostname("192.168.1.3"), "three")

    def test_flush_updates_totals_and_alerts(self):
        state = MonitorState(max_alerts=10)
        state.buffer_traffic(
            local_ip="192.168.1.10",
            remote_ip="1.1.1.1",
            packet_length=120,
            direction="upload",
        )
        alert = make_alert("port_scan", "example", source_ip="192.168.1.10")
        state.buffer_alert("192.168.1.10", alert)

        traffic, alerts = state.flush_traffic()
        self.assertEqual(traffic[0]["upload"], 120)
        self.assertEqual(alerts, [alert])
        self.assertEqual(alerts[0]["message"], "[PORT_SCAN] example")
        self.assertEqual(state.stats()["total_traffic_bytes"], 120)
        self.assertEqual(state.alerts_snapshot()[0]["id"], alert["id"])

    def test_packet_history_is_bounded_and_filterable(self):
        state = MonitorState(max_alerts=10, max_packet_history=2)
        state.buffer_packet(
            {
                "timestamp": 1.0,
                "source_ip": "192.168.1.10",
                "destination_ip": "1.1.1.1",
                "protocol": "TCP",
                "source_port": 50000,
                "destination_port": 443,
                "size": 120,
                "direction": "outbound",
                "tcp_flags": "S",
            }
        )
        state.buffer_packet(
            {
                "timestamp": 2.0,
                "source_ip": "8.8.8.8",
                "destination_ip": "192.168.1.10",
                "protocol": "UDP",
                "source_port": 53,
                "destination_port": 53000,
                "size": 80,
                "direction": "inbound",
                "tcp_flags": None,
            }
        )
        state.buffer_packet(
            {
                "timestamp": 3.0,
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.1",
                "protocol": "ICMP",
                "source_port": None,
                "destination_port": None,
                "size": 60,
                "direction": "outbound",
                "tcp_flags": None,
            }
        )
        state.flush_packets()

        packets = state.packets_snapshot(protocol="UDP")
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]["source_ip"], "8.8.8.8")
        self.assertEqual(state.packets_summary()["captured_packets"], 2)

    def test_known_devices_keep_first_seen_across_restart(self):
        state = MonitorState(max_alerts=10)
        state.load_known_devices(
            {"aa:bb:cc:dd:ee:ff": {"ip": "192.168.1.10", "first_seen": 50.0, "last_seen": 60.0, "details": {}}}
        )
        changes = state.upsert_devices(
            {"aa:bb:cc:dd:ee:ff": {"ip": "192.168.1.11", "vendor": "X", "hostname": "h"}}
        )
        self.assertFalse(changes["aa:bb:cc:dd:ee:ff"]["new_device"])
        self.assertEqual(changes["aa:bb:cc:dd:ee:ff"]["ip_changed"], "192.168.1.10")
        device = state.devices.get("aa:bb:cc:dd:ee:ff")
        self.assertEqual(device["first_seen"], 50.0)
        self.assertEqual(device["ip"], "192.168.1.11")

    def test_pending_alerts_are_flushed_without_traffic(self):
        state = MonitorState(max_alerts=10)
        alert = make_alert("new_device", "hello", severity="low")
        state.add_alert(alert)
        traffic, alerts = state.flush_traffic()
        self.assertEqual(traffic, [])
        self.assertEqual(alerts, [alert])
        self.assertEqual(state.flush_traffic(), ([], []))

    def test_alert_snapshot_filters_by_severity_and_type(self):
        state = MonitorState(max_alerts=10)
        state.load_alerts(
            [
                make_alert("port_scan", "a", severity="medium"),
                make_alert("arp_spoof", "b", severity="high"),
            ]
        )
        self.assertEqual([a["detail"] for a in state.alerts_snapshot(severity="high")], ["b"])
        self.assertEqual([a["detail"] for a in state.alerts_snapshot(alert_type="port_scan")], ["a"])

    def test_packet_counters_track_seen_and_dropped(self):
        state = MonitorState(max_alerts=10, max_packet_history=1)
        state.buffer_packet({"protocol": "TCP", "direction": "outbound"})
        state.buffer_packet({"protocol": "TCP", "direction": "outbound"})
        state.record_callback_error()
        state.record_scan(ok=False, error="boom")
        health = state.health_snapshot()
        self.assertEqual(health["capture"]["packets_seen"], 2)
        self.assertEqual(health["capture"]["packets_dropped"], 1)
        self.assertEqual(health["capture"]["callback_errors"], 1)
        self.assertEqual(health["scanner"]["error"], "boom")
        self.assertIsNone(health["scanner"]["last_success_at"])


if __name__ == "__main__":
    unittest.main()
