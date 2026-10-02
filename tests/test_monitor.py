import threading
import unittest
from unittest import mock

from scapy.all import ARP, IP, TCP, UDP, Ether, Raw
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR

import config
from moniwifi.detectors import DetectionSettings
from moniwifi.monitor import NetworkMonitor, settings_from_config
from moniwifi.state import MonitorState
from moniwifi.storage import Storage
from tests.helpers import FakeNetwork, FakeSocketIO
from tests.test_protocols import client_hello


class FakeSniffer:
    instances = []

    def __init__(self, iface, prn, store, filter):
        self.iface = iface
        self.prn = prn
        self.running = False
        self.stopped = False
        self.thread = threading.Thread(target=lambda: None)
        FakeSniffer.instances.append(self)

    def start(self):
        self.running = True
        self.thread = mock.Mock(is_alive=mock.Mock(return_value=True))

    def stop(self):
        self.running = False
        self.stopped = True


def make_monitor(storage=None, network=None, **kwargs):
    state = MonitorState(max_alerts=10)
    kwargs.setdefault("detection_settings", DetectionSettings(port_scan_threshold=3, host_sweep_threshold=3))
    return NetworkMonitor(
        socketio=FakeSocketIO(),
        state=state,
        storage=storage,
        network=network or FakeNetwork(),
        **kwargs,
    )


class PacketCallbackTests(unittest.TestCase):
    def test_outbound_packet_is_recorded_as_metadata_and_traffic(self):
        monitor = make_monitor()
        monitor.packet_callback(Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=5000, dport=53))
        monitor.state.flush_packets()

        packet = monitor.state.packets_snapshot()[0]
        self.assertEqual(packet["direction"], "outbound")
        self.assertEqual(packet["protocol"], "UDP")
        self.assertEqual(packet["destination_port"], 53)
        traffic, _ = monitor.state.flush_traffic()
        self.assertGreater(traffic[0]["upload"], 0)

    def test_foreign_packets_and_missing_network_are_ignored(self):
        monitor = make_monitor()
        monitor.packet_callback(IP(src="10.0.0.1", dst="10.0.0.2") / TCP())
        self.assertEqual(monitor.state.health_snapshot()["capture"]["packets_seen"], 0)

        offline = make_monitor(network=FakeNetwork(network=None))
        offline.packet_callback(IP(src="192.168.1.10", dst="8.8.8.8") / TCP())
        self.assertEqual(offline.state.health_snapshot()["capture"]["packets_seen"], 0)

    def test_port_scan_alert_is_emitted_and_persisted_on_flush(self):
        storage = Storage(":memory:")
        monitor = make_monitor(storage=storage)
        for port in (22, 80, 443):
            monitor.packet_callback(IP(src="192.168.1.10", dst="192.168.1.1") / TCP(dport=port, flags="S"))

        monitor.flush_once()

        emitted = monitor.socketio.of("alert")
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["type"], "port_scan")
        self.assertEqual(storage.recent_alerts()[0]["id"], emitted[0]["id"])
        self.assertTrue(storage.traffic_history())
        self.assertGreater(monitor.state.health_snapshot()["capture"]["packets_per_second"], 0)

    def test_callback_errors_are_counted(self):
        monitor = make_monitor()
        monitor.network = mock.Mock(local_network=mock.Mock(side_effect=RuntimeError("x")))
        monitor.packet_callback(IP(src="192.168.1.10", dst="8.8.8.8") / TCP())
        self.assertEqual(monitor.state.health_snapshot()["capture"]["callback_errors"], 1)


class ScannerTests(unittest.TestCase):
    ARP_OUTPUT = (
        "Interface: eth0, type: EN10MB\n"
        "192.168.1.1\taa:bb:cc:dd:ee:01\tRouterCorp\n"
        "192.168.1.20\tAA:BB:CC:DD:EE:02\tPhone Maker Inc.\n"
        "2 packets received\n"
    )

    def test_scan_once_parses_persists_and_emits_devices(self):
        storage = Storage(":memory:")
        monitor = make_monitor(storage=storage)
        result = mock.Mock(returncode=0, stdout=self.ARP_OUTPUT, stderr="")
        with mock.patch("moniwifi.monitor.subprocess.run", return_value=result) as run, mock.patch.object(
            monitor, "resolve_hostname", return_value="host"
        ):
            devices = monitor.scan_once()
        monitor.flush_once()

        self.assertIn("--interface=eth0", run.call_args.args[0])
        self.assertEqual(set(devices), {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})
        self.assertEqual(set(storage.known_devices()), set(devices))
        self.assertEqual(set(monitor.socketio.of("device_update")[-1]), set(devices))
        self.assertEqual(storage.known_devices()["aa:bb:cc:dd:ee:01"]["vendor"], "RouterCorp")
        self.assertTrue(monitor.state.health_snapshot()["scanner"]["ok"])

    def test_failed_scan_is_reported(self):
        monitor = make_monitor()
        result = mock.Mock(returncode=2, stdout="", stderr="permission denied")
        with mock.patch("moniwifi.monitor.subprocess.run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "permission denied"):
                monitor.scan_once()


class SnifferLoopTests(unittest.TestCase):
    def setUp(self):
        FakeSniffer.instances = []
        patcher = mock.patch.object(config, "SNIFFER_CHECK_INTERVAL", 0.01)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_until(self, monitor, predicate):
        errors = []

        def target():
            try:
                monitor.run_sniffer()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        for _ in range(200):
            if predicate() or errors:
                break
            threading.Event().wait(0.01)
        monitor.stop_event.set()
        thread.join(1)
        return errors

    def test_capture_restarts_when_interface_changes(self):
        network = FakeNetwork()
        monitor = make_monitor(network=network, sniffer_factory=FakeSniffer)

        def switch_interface():
            if FakeSniffer.instances and network.iface == "eth0":
                network.iface = "wlan0"
            return len(FakeSniffer.instances) >= 2

        errors = self.run_until(monitor, switch_interface)
        self.assertEqual(errors, [])
        self.assertEqual([s.iface for s in FakeSniffer.instances[:2]], ["eth0", "wlan0"])
        self.assertTrue(FakeSniffer.instances[0].stopped)

    def test_dead_capture_thread_raises_for_supervisor(self):
        monitor = make_monitor(sniffer_factory=FakeSniffer)

        def kill_capture():
            if FakeSniffer.instances:
                FakeSniffer.instances[0].thread.is_alive.return_value = False
            return False

        errors = self.run_until(monitor, kill_capture)
        self.assertEqual(len(errors), 1)
        self.assertIn("stopped unexpectedly", str(errors[0]))


class HealthTests(unittest.TestCase):
    def test_health_is_degraded_until_started(self):
        monitor = make_monitor()
        health = monitor.health()
        self.assertEqual(health["status"], "degraded")
        self.assertIn("monitor not started", health["problems"])
        self.assertEqual(health["capture"]["interface"], "eth0")
        self.assertFalse(health["storage"]["enabled"])

    def test_health_reports_failed_scan_and_storage(self):
        storage = Storage(":memory:")
        storage.last_error = "disk full"
        monitor = make_monitor(storage=storage)
        monitor.started_at = 1.0
        monitor.state.record_scan(ok=False, error="timeout")
        problems = monitor.health()["problems"]
        self.assertIn("last scan failed: timeout", problems)
        self.assertIn("storage error: disk full", problems)

    def test_persisted_state_is_loaded_on_start(self):
        storage = Storage(":memory:")
        storage.upsert_devices({"aa:bb": {"ip": "192.168.1.5", "first_seen": 1.0}}, seen_at=1.0)
        monitor = make_monitor(storage=storage)
        monitor.load_persisted_state()
        self.assertIsNotNone(monitor.state.devices.get("aa:bb"))


class PassiveDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.storage = Storage(":memory:")
        self.monitor = make_monitor(storage=self.storage)
        self.monitor.oui = mock.Mock(lookup=mock.Mock(return_value="Vendor"))

    def test_arp_and_traffic_register_devices_once_per_interval(self):
        self.monitor.packet_callback(
            Ether(src="aa:00:00:00:00:01") / ARP(op=2, hwsrc="aa:00:00:00:00:01", psrc="192.168.1.9", pdst="192.168.1.2")
        )
        self.monitor.packet_callback(Ether(src="aa:00:00:00:00:02") / IP(src="192.168.1.10", dst="8.8.8.8") / UDP())
        self.monitor.packet_callback(Ether(src="aa:00:00:00:00:02") / IP(src="192.168.1.10", dst="8.8.4.4") / UDP())

        devices = self.monitor.state.devices_snapshot()
        self.assertEqual(devices["aa:00:00:00:00:01"]["ip"], "192.168.1.9")
        self.assertEqual(devices["aa:00:00:00:00:02"]["vendor"], "Vendor")
        self.monitor.flush_once()
        self.assertEqual(set(self.storage.known_devices()), {"aa:00:00:00:00:01", "aa:00:00:00:00:02"})
        self.assertEqual(len(self.monitor.socketio.of("device_update")), 1)

    def test_new_device_alert_after_learning_period(self):
        self.monitor.observe_device("aa:00:00:00:00:01", "192.168.1.9", "scan")
        self.monitor.flush_once()
        alerts = self.monitor.socketio.of("alert")
        self.assertEqual([alert["type"] for alert in alerts], ["new_device"])
        self.assertEqual(alerts[0]["evidence"]["mac"], "aa:00:00:00:00:01")

        self.monitor.observe_device("aa:00:00:00:00:01", "192.168.1.9", "scan")
        self.monitor.observe_device("ff:ff:ff:ff:ff:ff", "192.168.1.255", "scan")
        self.monitor.flush_once()
        self.assertEqual(len(self.monitor.socketio.of("alert")), 1)

    def test_no_new_device_alert_while_learning(self):
        self.monitor.state.devices.learning_period = 600
        self.monitor.load_persisted_state()
        self.monitor.observe_device("aa:00:00:00:00:01", "192.168.1.9", "scan")
        self.monitor.flush_once()
        self.assertEqual(self.monitor.socketio.of("alert"), [])

    def test_dhcp_request_names_device_and_ack_records_server(self):
        self.monitor.packet_callback(
            Ether(src="aa:bb:cc:dd:ee:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=bytes.fromhex("aabbccddeeff"))
            / DHCP(options=[("message-type", "request"), ("hostname", b"Pixel-7"), ("vendor_class_id", b"android-dhcp-13"), ("requested_addr", "192.168.1.50"), "end"])
        )
        self.monitor.packet_callback(
            Ether(src="00:11:22:33:44:55")
            / IP(src="192.168.1.1", dst="192.168.1.50")
            / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr="192.168.1.50", chaddr=bytes.fromhex("aabbccddeeff"))
            / DHCP(options=[("message-type", "ack"), ("server_id", "192.168.1.1"), "end"])
        )
        device = self.monitor.state.devices.get("aa:bb:cc:dd:ee:ff")
        self.assertEqual((device["hostname"], device["ip"]), ("Pixel-7", "192.168.1.50"))
        self.assertEqual(device["dhcp_vendor_class"], "android-dhcp-13")
        self.assertIn("192.168.1.1", self.monitor.dhcp_servers)

    def test_mdns_announcement_names_device(self):
        self.monitor.packet_callback(
            Ether(src="aa:00:00:00:00:07")
            / IP(src="192.168.1.7", dst="224.0.0.251")
            / UDP(sport=5353, dport=5353)
            / DNS(qr=1, an=DNSRR(rrname="living-room-tv.local", type="A", rdata="192.168.1.7"))
        )
        device = self.monitor.state.devices.get("aa:00:00:00:00:07")
        self.assertEqual((device["hostname"], device["hostname_source"]), ("living-room-tv", "mdns"))

    def test_dns_answer_labels_later_flow_and_is_persisted(self):
        self.monitor.packet_callback(
            IP(src="192.168.1.5", dst="8.8.8.8") / UDP(sport=5555, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        )
        self.monitor.packet_callback(
            IP(src="8.8.8.8", dst="192.168.1.5")
            / UDP(sport=53, dport=5555)
            / DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34"))
        )
        self.monitor.packet_callback(IP(src="192.168.1.5", dst="93.184.216.34") / TCP(sport=40000, dport=443, flags="S"))

        flows = self.monitor.state.flows.snapshot(ip_addr="93.184.216.34")
        self.assertEqual(flows[0]["server_name"], "example.com")
        self.assertEqual(self.monitor.state.domains.recent()[0]["answers"], ["93.184.216.34"])

        self.monitor.flush_once()
        domains = self.storage.domains()
        self.assertEqual(domains[0]["domain"], "example.com")
        self.assertEqual(domains[0]["clients"], ["192.168.1.5"])

    def test_tls_sni_names_flow_and_expired_flows_are_stored(self):
        self.monitor.packet_callback(
            IP(src="192.168.1.5", dst="1.1.1.1") / TCP(sport=40001, dport=443, flags="PA") / Raw(client_hello(b"one.one.one.one"))
        )
        self.monitor.packet_callback(IP(src="192.168.1.5", dst="1.1.1.1") / TCP(sport=40001, dport=443, flags="R"))
        self.assertEqual(self.monitor.state.flows.snapshot()[0]["server_name"], "one.one.one.one")

        self.monitor.state.flows.closed_timeout = 0
        self.monitor.flush_once()
        stored = self.storage.recent_flows()
        self.assertEqual((stored[0]["server_name"], stored[0]["server_port"]), ("one.one.one.one", 443))
        self.assertEqual(self.storage.domains()[0]["sources"], ["tls"])


class DetectionIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.monitor = make_monitor()

    def alerts(self):
        self.monitor.flush_once()
        return [alert["type"] for alert in self.monitor.socketio.of("alert")]

    def test_inbound_port_scan_and_host_sweep(self):
        for port in (22, 80, 443):
            self.monitor.packet_callback(IP(src="203.0.113.9", dst="192.168.1.10") / TCP(dport=port, flags="S"))
        for host in (20, 21, 22):
            self.monitor.packet_callback(IP(src="192.168.1.66", dst=f"192.168.1.{host}") / TCP(dport=445, flags="S"))
        alerts = self.monitor.socketio.of("alert")
        self.monitor.flush_once()
        alerts = self.monitor.socketio.of("alert")
        scan = next(alert for alert in alerts if alert["type"] == "port_scan")
        self.assertEqual((scan["severity"], scan["evidence"]["inbound"]), ("high", True))
        self.assertIn("host_sweep", [alert["type"] for alert in alerts])

    def test_gateway_arp_spoofing(self):
        arp = lambda mac: Ether(src=mac) / ARP(op=2, hwsrc=mac, psrc="192.168.1.1", pdst="192.168.1.10")
        self.monitor.packet_callback(arp("00:11:22:33:44:55"))
        self.monitor.packet_callback(arp("66:77:88:99:aa:bb"))
        types = self.alerts()
        self.assertIn("arp_spoofing", types)
        spoof = next(a for a in self.monitor.socketio.of("alert") if a["type"] == "arp_spoofing")
        self.assertEqual(spoof["severity"], "critical")
        self.assertEqual(spoof["evidence"]["previous_mac"], "00:11:22:33:44:55")

    def test_rogue_dhcp_server(self):
        def ack(server, mac):
            return (
                Ether(src=mac)
                / IP(src=server, dst="192.168.1.50")
                / UDP(sport=67, dport=68)
                / BOOTP(op=2, yiaddr="192.168.1.50", chaddr=bytes.fromhex("aabbccddeeff"))
                / DHCP(options=[("message-type", "offer"), ("server_id", server), ("router", server), "end"])
            )

        self.monitor.packet_callback(ack("192.168.1.1", "00:11:22:33:44:55"))
        self.assertNotIn("rogue_dhcp", self.alerts())
        self.monitor.packet_callback(ack("192.168.1.66", "66:77:88:99:aa:bb"))
        self.assertIn("rogue_dhcp", self.alerts())

    def test_threat_intel_ip_and_domain(self):
        self.monitor.intel.load_text("198.51.100.0/24\n0.0.0.0 evil.example\n", "testlist")
        self.monitor.packet_callback(IP(src="192.168.1.10", dst="198.51.100.7") / TCP(sport=40000, dport=443, flags="S"))
        self.monitor.packet_callback(
            IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=5000, dport=53) / DNS(rd=1, qd=DNSQR(qname="cdn.evil.example"))
        )
        types = self.alerts()
        self.assertIn("threat_intel_ip", types)
        self.assertIn("threat_intel_domain", types)

    def test_risky_protocol_and_exposed_service(self):
        self.monitor.packet_callback(IP(src="192.168.1.10", dst="203.0.113.5") / TCP(sport=40000, dport=23, flags="S"))
        self.monitor.packet_callback(IP(src="203.0.113.7", dst="192.168.1.20") / TCP(sport=50000, dport=3389, flags="S"))
        self.monitor.packet_callback(IP(src="192.168.1.20", dst="203.0.113.7") / TCP(sport=3389, dport=50000, flags="SA"))
        alerts = {alert["type"]: alert for alert in (self.alerts() and self.monitor.socketio.of("alert"))}
        self.assertIn("risky_protocol", alerts)
        self.assertEqual(alerts["exposed_service"]["evidence"]["service"], "RDP")

    def test_duplicate_alerts_are_suppressed(self):
        for _ in range(2):
            for port in (22, 80, 443, 8080):
                self.monitor.packet_callback(IP(src="192.168.1.10", dst="192.168.1.1") / TCP(dport=port, flags="S"))
        self.assertEqual(self.alerts().count("port_scan"), 1)
        self.assertGreater(self.monitor.detector.stats()["suppressed"], 0)

    def test_settings_from_config_parses_lists(self):
        with mock.patch.object(config, "RISKY_PORTS", "23:Telnet, 2323"), mock.patch.object(
            config, "TRUSTED_DHCP_SERVERS", "192.168.1.1, 192.168.1.2"
        ):
            settings = settings_from_config()
        self.assertEqual(settings.risky_ports, {23: "Telnet", 2323: "port 2323"})
        self.assertEqual(settings.trusted_dhcp_servers, frozenset({"192.168.1.1", "192.168.1.2"}))


if __name__ == "__main__":
    unittest.main()
