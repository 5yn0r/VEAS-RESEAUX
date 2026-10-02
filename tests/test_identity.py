import unittest

from veas.devices import DeviceRegistry
from veas.dnslog import DomainTracker
from veas.flows import FlowTable


class DeviceRegistryTests(unittest.TestCase):
    def test_new_device_ip_change_and_ip_takeover(self):
        registry = DeviceRegistry()
        self.assertTrue(registry.observe("aa:00:00:00:00:01", ip="192.168.1.5", now=1)["new_device"])
        changes = registry.observe("aa:00:00:00:00:01", ip="192.168.1.6", now=2)
        self.assertFalse(changes["new_device"])
        self.assertEqual(changes["ip_changed"], "192.168.1.5")

        changes = registry.observe("aa:00:00:00:00:02", ip="192.168.1.6", now=3)
        self.assertEqual(changes["ip_moved_from"], "aa:00:00:00:00:01")
        self.assertEqual(registry.mac_for_ip("192.168.1.6"), "aa:00:00:00:00:02")
        self.assertEqual(registry.get("aa:00:00:00:00:01")["ip_history"], ["192.168.1.5", "192.168.1.6"])

    def test_hostname_priority_prefers_dhcp_over_reverse_dns(self):
        registry = DeviceRegistry()
        registry.observe("aa:00:00:00:00:01", source="dhcp", hostname="Pixel-7")
        registry.observe("aa:00:00:00:00:01", source="scan", hostname="192-168-1-5.isp.example")
        registry.observe("aa:00:00:00:00:01", source="mdns", hostname="pixel")
        self.assertEqual(registry.get("aa:00:00:00:00:01")["hostname"], "Pixel-7")
        self.assertEqual(registry.get("aa:00:00:00:00:01")["sources"], ["dhcp", "mdns", "scan"])

    def test_learning_period_only_on_empty_history(self):
        fresh = DeviceRegistry(learning_period=100)
        fresh.load({}, now=0)
        self.assertTrue(fresh.observe("aa:00:00:00:00:01", now=50)["learning"])
        self.assertFalse(fresh.observe("aa:00:00:00:00:02", now=150)["learning"])

        known = DeviceRegistry(learning_period=100)
        known.load({"aa:00:00:00:00:09": {"ip": "192.168.1.9", "first_seen": 1.0, "last_seen": 1.0, "details": {"sources": ["scan"]}}}, now=0)
        self.assertFalse(known.observe("aa:00:00:00:00:01", now=50)["learning"])
        self.assertEqual(known.mac_for_ip("192.168.1.9"), "aa:00:00:00:00:09")

    def test_drain_dirty_returns_serializable_changes_once(self):
        registry = DeviceRegistry()
        registry.observe("aa:00:00:00:00:01", ip="192.168.1.5", details={"dhcp_vendor_class": "MSFT 5.0"})
        dirty = registry.drain_dirty()
        self.assertEqual(dirty["aa:00:00:00:00:01"]["dhcp_vendor_class"], "MSFT 5.0")
        self.assertIsInstance(dirty["aa:00:00:00:00:01"]["sources"], list)
        self.assertEqual(registry.drain_dirty(), {})


class FlowTableTests(unittest.TestCase):
    def test_bidirectional_counters_and_client_detection(self):
        flows = FlowTable()
        flows.update(protocol="TCP", src_ip="192.168.1.5", src_port=40000, dst_ip="1.1.1.1", dst_port=443, size=60, direction="outbound", tcp_flags="S", now=1)
        flows.update(protocol="TCP", src_ip="1.1.1.1", src_port=443, dst_ip="192.168.1.5", dst_port=40000, size=1500, direction="inbound", tcp_flags="SA", now=2)
        flow = flows.snapshot()[0]
        self.assertEqual((flow["client_ip"], flow["server_port"], flow["direction"]), ("192.168.1.5", 443, "outbound"))
        self.assertEqual((flow["packets_out"], flow["bytes_out"], flow["packets_in"], flow["bytes_in"]), (1, 60, 1, 1500))
        self.assertEqual(flow["tcp_flags"], "AS")

    def test_mid_stream_packet_uses_well_known_port_as_server(self):
        flows = FlowTable()
        flows.update(protocol="TCP", src_ip="1.1.1.1", src_port=443, dst_ip="192.168.1.5", dst_port=40000, size=100, direction="inbound", tcp_flags="A")
        flow = flows.snapshot()[0]
        self.assertEqual((flow["client_ip"], flow["direction"], flow["bytes_in"]), ("192.168.1.5", "outbound", 100))

    def test_expiry_closed_idle_and_eviction(self):
        flows = FlowTable(max_active=2, udp_idle_timeout=60, closed_timeout=5)
        flows.update(protocol="TCP", src_ip="a", src_port=1, dst_ip="b", dst_port=80, size=1, direction="local", tcp_flags="R", now=0)
        flows.update(protocol="UDP", src_ip="a", src_port=2, dst_ip="c", dst_port=53, size=1, direction="local", now=0)
        self.assertEqual(len(flows.expire(now=10)), 1)
        self.assertEqual(len(flows.expire(now=61)), 1)

        flows.update(protocol="UDP", src_ip="a", src_port=3, dst_ip="d", dst_port=53, size=1, direction="local", now=100)
        flows.update(protocol="UDP", src_ip="a", src_port=4, dst_ip="d", dst_port=53, size=1, direction="local", now=101)
        flows.update(protocol="UDP", src_ip="a", src_port=5, dst_ip="d", dst_port=53, size=1, direction="local", now=102)
        self.assertEqual(flows.stats(), {"active_flows": 2, "evicted_flows": 1})
        self.assertEqual([flow["client_port"] for flow in flows.expire(now=102)], [3])

    def test_tls_name_overrides_dns_name(self):
        flows = FlowTable()
        common = dict(protocol="TCP", src_ip="a", src_port=1, dst_ip="b", dst_port=443, size=1, direction="outbound")
        flows.update(**common, server_name="cdn.example", name_source="dns")
        flows.update(**common, server_name="real.example", name_source="tls")
        flows.update(**common, server_name="other.example", name_source="dns")
        self.assertEqual(flows.snapshot()[0]["server_name"], "real.example")


class DomainTrackerTests(unittest.TestCase):
    def test_query_response_and_ip_mapping(self):
        tracker = DomainTracker()
        tracker.record_query("192.168.1.5", "Example.COM", "A", now=1)
        tracker.record_response("192.168.1.5", [{"name": "example.com"}], [{"type": "CNAME", "data": "edge.cdn"}, {"type": "A", "data": "93.184.216.34"}])
        entry = tracker.recent()[0]
        self.assertEqual((entry["query"], entry["answers"]), ("example.com", ["93.184.216.34"]))
        self.assertEqual(tracker.domain_for_ip("93.184.216.34"), "example.com")
        self.assertEqual(tracker.recent(query="EXAMPLE")[0]["client_ip"], "192.168.1.5")
        self.assertEqual(tracker.recent(client_ip="10.0.0.1"), [])

    def test_observations_are_aggregated_and_reverse_lookups_ignored(self):
        tracker = DomainTracker()
        tracker.observe_name("192.168.1.5", "example.com", "dns", now=1)
        tracker.observe_name("192.168.1.5", "example.com.", "dns", now=5)
        tracker.observe_name("192.168.1.5", "4.3.2.1.in-addr.arpa", "dns")
        observations = tracker.drain_observations()
        self.assertEqual(len(observations), 1)
        self.assertEqual((observations[0]["count"], observations[0]["first_seen"], observations[0]["last_seen"]), (2, 1, 5))
        self.assertEqual(tracker.drain_observations(), [])


if __name__ == "__main__":
    unittest.main()
