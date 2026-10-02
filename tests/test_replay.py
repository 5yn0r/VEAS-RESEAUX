"""End-to-end detection tests: build a pcap scenario, replay it offline, check the report."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from scapy.all import ARP, IP, TCP, UDP, Ether, Raw, wrpcap
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse

from moniwifi.detectors import DetectionSettings
from moniwifi.replay import analyse, infer_network, main
from tests.test_protocols import client_hello

GATEWAY_MAC = "00:11:22:33:44:55"
LAPTOP_MAC = "3c:22:fb:00:00:10"
ATTACKER_MAC = "3c:22:fb:00:00:66"
START = 1_700_000_000.0


def at(packet, offset):
    packet.time = START + offset
    return packet


def scenario() -> list:
    packets = []
    # Normal life: the gateway and a laptop resolve a name and browse over TLS.
    packets.append(at(Ether(src=GATEWAY_MAC) / ARP(op=2, hwsrc=GATEWAY_MAC, psrc="192.168.1.1", pdst="192.168.1.10"), 0))
    packets.append(at(Ether(src=LAPTOP_MAC) / IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname="docs.example.com")), 1))
    packets.append(
        at(
            Ether(src=GATEWAY_MAC)
            / IP(src="192.168.1.1", dst="192.168.1.10")
            / UDP(sport=53, dport=5353)
            / DNS(qr=1, qd=DNSQR(qname="docs.example.com"), an=DNSRR(rrname="docs.example.com", type="A", rdata="93.184.216.34")),
            1.1,
        )
    )
    packets.append(at(Ether(src=LAPTOP_MAC) / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=40000, dport=443, flags="PA") / Raw(client_hello(b"docs.example.com")), 2))

    # An attacker joins through DHCP...
    packets.append(
        at(
            Ether(src=ATTACKER_MAC)
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=bytes.fromhex(ATTACKER_MAC.replace(":", "")))
            / DHCP(options=[("message-type", "request"), ("hostname", b"kali"), ("requested_addr", "192.168.1.66"), "end"]),
            10,
        )
    )
    # ...scans the laptop...
    for index, port in enumerate(range(1, 30)):
        packets.append(at(Ether(src=ATTACKER_MAC) / IP(src="192.168.1.66", dst="192.168.1.10") / TCP(sport=50000, dport=port, flags="S"), 20 + index * 0.01))
    # ...and poisons the gateway ARP entry.
    packets.append(at(Ether(src=ATTACKER_MAC) / ARP(op=2, hwsrc=ATTACKER_MAC, psrc="192.168.1.1", pdst="192.168.1.10"), 30))

    # Responder: the attacker answers the laptop's LLMNR lookups, including WPAD...
    for offset, name in ((32, "fileserv"), (33, "wpad")):
        packets.append(at(Ether(src=LAPTOP_MAC) / IP(src="192.168.1.10", dst="224.0.0.252") / UDP(sport=51000, dport=5355) / LLMNRQuery(qd=DNSQR(qname=name)), offset))
        packets.append(
            at(
                Ether(src=ATTACKER_MAC)
                / IP(src="192.168.1.66", dst="192.168.1.10")
                / UDP(sport=5355, dport=51000)
                / LLMNRResponse(qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata="192.168.1.66")),
                offset + 0.01,
            )
        )
    # ...and guesses SSH passwords.
    for attempt in range(25):
        packets.append(at(Ether(src=ATTACKER_MAC) / IP(src="192.168.1.66", dst="192.168.1.10") / TCP(sport=52000 + attempt, dport=22, flags="S"), 35 + attempt))

    # The laptop looks up a listed domain and then beacons to a C2 every 60 seconds.
    packets.append(at(Ether(src=LAPTOP_MAC) / IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=5354, dport=53) / DNS(rd=1, qd=DNSQR(qname="update.evil-c2.example")), 40))
    for beat in range(8):
        packets.append(at(Ether(src=LAPTOP_MAC) / IP(src="192.168.1.10", dst="203.0.113.50") / TCP(sport=41000 + beat, dport=8443, flags="S"), 100 + beat * 60 + (beat % 2) * 0.5))
    return packets


class ReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.pcap = os.path.join(cls.directory.name, "scenario.pcap")
        wrpcap(cls.pcap, scenario())
        cls.intel = os.path.join(cls.directory.name, "intel")
        os.mkdir(cls.intel)
        with open(os.path.join(cls.intel, "c2.txt"), "w") as handle:
            handle.write("evil-c2.example\n203.0.113.50\n")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def report(self):
        settings = DetectionSettings(port_scan_threshold=20, beacon_min_events=8)
        return analyse(self.pcap, gateway="192.168.1.1", intel_dir=self.intel, settings=settings)

    def test_infers_local_network(self):
        self.assertEqual(infer_network(self.pcap), "192.168.1.0/24")

    def test_scenario_raises_expected_alerts(self):
        report = self.report()
        types = {alert["type"] for alert in report["alerts"]}
        self.assertTrue(
            {"new_device", "port_scan", "arp_spoofing", "llmnr_poisoning", "brute_force", "threat_intel_domain", "threat_intel_ip", "beaconing"} <= types,
            types,
        )
        self.assertEqual(report["packets"], len(scenario()))
        self.assertEqual(report["devices"][ATTACKER_MAC]["hostname"], "kali")
        beacon = next(alert for alert in report["alerts"] if alert["type"] == "beaconing")
        self.assertAlmostEqual(beacon["evidence"]["interval_seconds"], 60, delta=1)
        self.assertIn(("docs.example.com", 1), report["top_domains"])

    def test_scenario_is_correlated_into_incidents(self):
        incidents = {incident["entity"]: incident for incident in self.report()["incidents"]}
        attacker = incidents[ATTACKER_MAC]
        self.assertEqual(attacker["severity"], "critical")
        self.assertIn("arp_spoofing", attacker["alert_types"])
        self.assertIn("llmnr_poisoning", attacker["alert_types"])
        self.assertIn("T1557.001", attacker["mitre_techniques"])
        self.assertTrue(any("credential capture" in reason for reason in attacker["reasons"]))
        self.assertTrue(any("newly connected device" in reason for reason in attacker["reasons"]))
        laptop = incidents[LAPTOP_MAC]
        self.assertIn("beaconing", laptop["alert_types"])
        self.assertTrue(any("command-and-control" in reason for reason in laptop["reasons"]))

    def test_siem_json_export(self):
        path = os.path.join(self.directory.name, "siem.jsonl")
        analyse(self.pcap, gateway="192.168.1.1", intel_dir=self.intel, siem_json=path)
        with open(path) as handle:
            events = [json.loads(line) for line in handle]
        datasets = {event["event"]["dataset"] for event in events}
        self.assertEqual(datasets, {"wifi_guardian.alert", "wifi_guardian.incident"})
        spoof = next(event for event in events if event["event"]["action"] == "arp_spoofing")
        self.assertEqual(spoof["threat"]["technique"]["id"], ["T1557.002"])

    def test_cli_report_and_exit_code(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main([self.pcap, "--gateway", "192.168.1.1", "--intel-dir", self.intel])
        self.assertEqual(code, 1)  # high/critical incidents found
        self.assertIn("ARP_SPOOFING", output.getvalue())
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([os.path.join(self.directory.name, "missing.pcap")]), 2)


if __name__ == "__main__":
    unittest.main()
