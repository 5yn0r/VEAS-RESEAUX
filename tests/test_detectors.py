import os
import tempfile
import unittest
from pathlib import Path

from moniwifi.detectors import DetectionEngine, DetectionSettings, SlidingDistinct, shannon_entropy
from moniwifi.state import MonitorState
from moniwifi.threatintel import ThreatIntel, parse_indicators
from tests.helpers import FakeNetwork


def engine(**settings):
    network = FakeNetwork()
    state = MonitorState(max_alerts=100)
    detector = DetectionEngine(
        state,
        DetectionSettings(**settings),
        intel=ThreatIntel(),
        gateway_ip=network.gateway_ip,
        is_local=network.is_local,
    )
    return detector, state


def alert_types(state):
    return [alert["type"] for alert in state.flush_traffic()[1]]


def flow(client, server, port, name=None, protocol="TCP"):
    return {"client_ip": client, "server_ip": server, "server_port": port, "server_name": name, "protocol": protocol}


class SlidingDistinctTests(unittest.TestCase):
    def test_counts_only_values_inside_window(self):
        window = SlidingDistinct(10)
        self.assertEqual(window.add(("k",), 1, now=0), 1)
        self.assertEqual(window.add(("k",), 2, now=5), 2)
        self.assertEqual(window.add(("k",), 1, now=9), 2)  # refreshed, not duplicated
        self.assertEqual(window.add(("k",), 3, now=16), 2)  # value 2 (t=5) expired
        self.assertEqual(sorted(window.values(("k",))), [1, 3])
        window.purge(now=100)
        self.assertEqual(window.values(("k",)), [])


class ScanDetectionTests(unittest.TestCase):
    def test_port_scan_uses_sliding_window(self):
        detector, state = engine(scan_window=10, port_scan_threshold=3)
        detector.on_tcp_syn("192.168.1.10", "192.168.1.1", 22, now=0)
        detector.on_tcp_syn("192.168.1.10", "192.168.1.1", 80, now=8)
        detector.on_tcp_syn("192.168.1.10", "192.168.1.1", 443, now=15)  # port 22 left the window
        self.assertEqual(alert_types(state), [])
        detector.on_tcp_syn("192.168.1.10", "192.168.1.1", 8080, now=16)
        alerts = state.flush_traffic()[1]
        self.assertEqual(alerts[0]["type"], "port_scan")
        self.assertEqual(alerts[0]["severity"], "medium")
        self.assertEqual(alerts[0]["evidence"]["sample_ports"], [80, 443, 8080])

    def test_ping_sweep(self):
        detector, state = engine(host_sweep_threshold=3)
        for host in range(3):
            detector.on_icmp_echo("192.168.1.66", f"192.168.1.{100 + host}")
        self.assertEqual(alert_types(state), ["ping_sweep"])

    def test_cooldown_suppresses_repeats_until_expiry(self):
        detector, state = engine(alert_cooldown=100)
        self.assertIsNotNone(detector.emit("x", "a", severity="low", key=("k",), now=0))
        self.assertIsNone(detector.emit("x", "a", severity="low", key=("k",), now=50))
        self.assertIsNotNone(detector.emit("x", "a", severity="low", key=("other",), now=50))
        self.assertIsNotNone(detector.emit("x", "a", severity="low", key=("k",), now=101))
        self.assertEqual(detector.stats(), {"alerts_by_type": {"x": 3}, "suppressed": 1, "allowlisted": 0})


class IdentityDetectionTests(unittest.TestCase):
    def test_ip_conflict_only_while_previous_owner_is_active(self):
        detector, state = engine()
        state.devices.observe("aa:00:00:00:00:01", ip="192.168.1.50")
        changes = state.devices.observe("aa:00:00:00:00:02", ip="192.168.1.50")
        detector.on_device("aa:00:00:00:00:02", "192.168.1.50", "passive", changes)
        self.assertEqual(alert_types(state), ["new_device", "ip_conflict"])

        state.devices.observe("aa:00:00:00:00:03", ip="192.168.1.60", now=0)  # long gone
        changes = state.devices.observe("aa:00:00:00:00:04", ip="192.168.1.60")
        detector.on_device("aa:00:00:00:00:04", "192.168.1.60", "dhcp", changes)
        self.assertNotIn("ip_conflict", alert_types(state))

    def test_configured_trusted_dhcp_servers(self):
        detector, state = engine(trusted_dhcp_servers=frozenset({"192.168.1.2"}))
        detector.on_dhcp_server("192.168.1.2", None, None)
        detector.on_dhcp_server("192.168.1.1", None, None)  # the gateway is not trusted when a list is set
        self.assertEqual(alert_types(state), ["rogue_dhcp"])


class FlowDetectionTests(unittest.TestCase):
    def test_beaconing_regular_interval(self):
        detector, state = engine(beacon_min_events=5, beacon_max_jitter=0.1)
        for index in range(5):
            detector.on_new_flow(flow("192.168.1.10", "203.0.113.5", 443, "c2.example"), now=index * 60 + (index % 2))
        alerts = state.flush_traffic()[1]
        self.assertEqual(alerts[0]["type"], "beaconing")
        self.assertEqual(alerts[0]["evidence"]["target"], "c2.example")

    def test_irregular_or_dns_traffic_is_not_beaconing(self):
        detector, state = engine(beacon_min_events=5)
        for now in (0, 5, 70, 80, 300, 310):
            detector.on_new_flow(flow("192.168.1.10", "203.0.113.5", 443), now=now)
        for index in range(10):
            detector.on_new_flow(flow("192.168.1.10", "8.8.8.8", 53, protocol="UDP"), now=index * 60)
        self.assertEqual(alert_types(state), [])

    def test_exposed_service_requires_remote_client_and_local_server(self):
        detector, state = engine()
        detector.on_inbound_accepted(flow("192.168.1.5", "192.168.1.6", 22))
        detector.on_inbound_accepted(flow("203.0.113.7", "192.168.1.6", 8443))
        alerts = state.flush_traffic()[1]
        self.assertEqual([(a["type"], a["severity"]) for a in alerts], [("exposed_service", "medium")])


class DnsDetectionTests(unittest.TestCase):
    def test_long_random_labels_look_like_tunnel(self):
        detector, state = engine()
        detector.on_dns_query("192.168.1.10", "www.example.com", "192.168.1.1")
        self.assertEqual(alert_types(state), [])
        encoded = "mzxw6ytboi4dqnrsgezdgnbvgy3tqojqgeztimjrgi2dmnzygfqwe3dt"
        detector.on_dns_query("192.168.1.10", f"{encoded}.t.exfil.example", "192.168.1.1")
        self.assertEqual(alert_types(state), ["dns_tunnel"])
        self.assertGreater(shannon_entropy(encoded), 3.5)

    def test_many_unique_subdomains_look_like_tunnel(self):
        detector, state = engine(dns_tunnel_unique_names=20)
        for index in range(20):
            detector.on_dns_query("192.168.1.10", f"q{index}.exfil.example", "192.168.1.1")
        self.assertEqual(alert_types(state), ["dns_tunnel"])

    def test_unapproved_resolver(self):
        detector, state = engine(allowed_dns_servers=frozenset({"192.168.1.1"}))
        detector.on_dns_query("192.168.1.10", "example.com", "192.168.1.1")
        detector.on_dns_query("192.168.1.10", "example.com", "1.1.1.1")
        self.assertEqual(alert_types(state), ["dns_bypass"])


class ThreatIntelTests(unittest.TestCase):
    def test_parse_plain_cidr_and_hosts_formats(self):
        ips, networks, domains = parse_indicators(
            "# Feodo\n203.0.113.5\n198.51.100.0/24 ; SBL123\n10.0.0.1/32\n"
            "127.0.0.1 localhost\n0.0.0.0 malware.example\nphish.example.org\n"
        )
        self.assertEqual(ips, {"203.0.113.5", "10.0.0.1"})
        self.assertEqual([str(n) for n in networks], ["198.51.100.0/24"])
        self.assertEqual(domains, {"malware.example", "phish.example.org"})

    def test_matching_ip_network_and_parent_domain(self):
        intel = ThreatIntel()
        intel.load_text("203.0.113.5\n198.51.100.0/24\nmalware.example\n", "list")
        self.assertEqual(intel.match_ip("203.0.113.5"), "list")
        self.assertEqual(intel.match_ip("198.51.100.77"), "list")
        self.assertIsNone(intel.match_ip("8.8.8.8"))
        self.assertEqual(intel.match_domain("a.b.malware.example"), ("malware.example", "list"))
        self.assertIsNone(intel.match_domain("example"))
        self.assertIsNone(intel.match_domain("notmalware.example"))

    def test_reload_directory_and_download_feed(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "source.txt")
            source.write_text("203.0.113.9\n")
            intel_dir = Path(directory, "intel")
            intel = ThreatIntel(str(intel_dir), feeds=[source.as_uri(), "file:///does/not/exist"])
            intel.download_feeds()
            intel.reload()
            self.assertTrue(intel.match_ip("203.0.113.9").startswith("feed-"))
            self.assertIn("does/not/exist", intel.stats()["last_error"])
            self.assertEqual(len(os.listdir(intel_dir)), 1)


if __name__ == "__main__":
    unittest.main()
