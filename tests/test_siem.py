import json
import os
import socket
import socketserver
import tempfile
import threading
import unittest

from scapy.all import IP, UDP, Ether
from scapy.layers.dns import DNSQR, DNSRR
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNSHeader, NBNSQueryResponse

from veas import protocols
from veas.alerts import make_alert
from veas.attack import ALERT_TECHNIQUES, TECHNIQUES, tactics_for, technique_url, techniques_for
from veas.incidents import IncidentManager
from veas.siem import JsonFileSink, SiemExporter, SyslogSink, alert_to_cef, alert_to_ecs, incident_to_ecs
from tests.test_detectors import alert_types, engine


def sample_alert(**kwargs):
    options = dict(
        severity="high",
        source_ip="192.168.1.66",
        destination_ip="192.168.1.10",
        evidence={"mac": "aa:bb:cc:dd:ee:ff", "port": 22},
        timestamp=1_700_000_000.5,
    )
    options.update(kwargs)
    return make_alert("brute_force", "192.168.1.66 opened 25 SSH connections | test=1", **options)


class AttackMappingTests(unittest.TestCase):
    def test_every_mapping_points_to_a_known_technique(self):
        for alert_type, technique_ids in ALERT_TECHNIQUES.items():
            for technique_id in technique_ids:
                self.assertIn(technique_id, TECHNIQUES, alert_type)

    def test_alerts_carry_techniques(self):
        alert = make_alert("arp_spoofing", "x")
        self.assertEqual(alert["mitre"][0]["id"], "T1557.002")
        self.assertEqual(alert["mitre"][0]["url"], "https://attack.mitre.org/techniques/T1557/002/")
        self.assertEqual(make_alert("unknown_type", "x")["mitre"], [])
        self.assertEqual(technique_url("T1046"), "https://attack.mitre.org/techniques/T1046/")
        self.assertEqual(tactics_for(["port_scan", "beaconing"]), ["discovery", "command-and-control"])

    def test_incidents_aggregate_tactics(self):
        manager = IncidentManager()
        entity = {"key": "aa"}
        manager.ingest(make_alert("port_scan", "a", timestamp=1.0), entity)
        incident, _ = manager.ingest(make_alert("llmnr_poisoning", "b", timestamp=2.0), entity)
        self.assertEqual(incident["mitre_techniques"], ["T1046", "T1557.001"])
        self.assertEqual(incident["mitre_tactics"], ["discovery", "credential-access", "collection"])


class FormatTests(unittest.TestCase):
    def test_ecs_alert(self):
        event = alert_to_ecs(sample_alert(), "sensor-1")
        self.assertEqual(event["@timestamp"], "2023-11-14T22:13:20.500Z")
        self.assertEqual(event["event"]["kind"], "alert")
        self.assertEqual(event["event"]["severity"], 75)
        self.assertEqual(event["source"], {"ip": "192.168.1.66", "mac": "AA-BB-CC-DD-EE-FF"})
        self.assertEqual(event["threat"]["technique"]["id"], ["T1110"])
        self.assertEqual(event["threat"]["tactic"]["name"], ["credential-access"])
        self.assertEqual(event["observer"]["hostname"], "sensor-1")

    def test_ecs_incident(self):
        manager = IncidentManager()
        incident, _ = manager.ingest(sample_alert(), {"key": "aa", "ip": "192.168.1.66"})
        event = incident_to_ecs(incident, "created", "sensor-1")
        self.assertEqual(event["event"]["dataset"], "veas.incident")
        self.assertEqual(event["event"]["risk_score"], incident["score"])
        self.assertEqual(event["host"]["ip"], ["192.168.1.66"])

    def test_cef_escaping(self):
        cef = alert_to_cef(sample_alert())
        self.assertTrue(cef.startswith("CEF:0|VEAS|VEAS RESEAUX|1.0|brute_force|"))
        # Pipes are escaped in the header, equals signs in the extension.
        self.assertIn("|brute_force|192.168.1.66 opened 25 SSH connections \\| test=1|8|", cef)
        extension = cef.split("|8|", 1)[1]
        self.assertIn("msg=192.168.1.66 opened 25 SSH connections | test\\=1 ", extension)
        self.assertIn("src=192.168.1.66", extension)
        self.assertIn("cs1=T1110", extension)


class Receiver:
    """Collect syslog datagrams or a TCP stream on an ephemeral port."""

    def __init__(self, protocol):
        self.data = []
        received = self.data

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                if protocol == "udp":
                    received.append(self.request[0])
                else:
                    while True:
                        chunk = self.request.recv(65536)
                        if not chunk:
                            break
                        received.append(chunk)

        server_class = socketserver.UDPServer if protocol == "udp" else socketserver.ThreadingTCPServer
        self.server = server_class(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def wait(self, predicate):
        for _ in range(200):
            if predicate(b"".join(self.data)):
                return b"".join(self.data)
            threading.Event().wait(0.01)
        return b"".join(self.data)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class SinkTests(unittest.TestCase):
    def record(self):
        alert = sample_alert()
        return {"kind": "alert", "severity": "high", "source": alert, "ecs": alert_to_ecs(alert, "h")}

    def test_syslog_udp_json(self):
        receiver = Receiver("udp")
        self.addCleanup(receiver.close)
        SyslogSink("127.0.0.1", receiver.port, "udp", "json").send(self.record())
        data = receiver.wait(bool).decode()
        self.assertTrue(data.startswith("<131>1 2023-11-14T22:13:20.500Z "))  # local0 (16*8) + error (3)
        body = json.loads(data.split(" - alert - ", 1)[1])
        self.assertEqual(body["rule"]["name"], "brute_force")

    def test_syslog_tcp_cef_with_octet_counting(self):
        receiver = Receiver("tcp")
        self.addCleanup(receiver.close)
        sink = SyslogSink("127.0.0.1", receiver.port, "tcp", "cef")
        sink.send(self.record())
        sink.send(self.record())
        sink.close()
        data = receiver.wait(lambda raw: raw.count(b"CEF:0") == 2)
        length, rest = data.split(b" ", 1)
        self.assertEqual(len(rest[: int(length)]), int(length))
        self.assertIn(b"CEF:0|VEAS|VEAS RESEAUX", rest)

    def test_invalid_syslog_settings(self):
        with self.assertRaises(ValueError):
            SyslogSink("h", protocol="http")
        with self.assertRaises(ValueError):
            SyslogSink("h", message_format="xml")

    def test_json_file_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "siem", "alerts.jsonl")
            sink = JsonFileSink(path, max_bytes=1500, backups=2)
            for _ in range(8):
                sink.send(self.record())
            files = sorted(os.listdir(os.path.dirname(path)))
            self.assertEqual(files, ["alerts.jsonl", "alerts.jsonl.1", "alerts.jsonl.2"])
            with open(path) as handle:
                self.assertEqual(json.loads(handle.readline())["event"]["action"], "brute_force")


class ExporterTests(unittest.TestCase):
    def test_filters_and_counts_failures(self):
        good, bad = [], []

        class Good:
            name = "good"

            def send(self, record):
                good.append(record)

            def close(self):
                pass

        class Bad(Good):
            name = "bad"

            def send(self, record):
                raise OSError("unreachable")

        exporter = SiemExporter([Good(), Bad()], min_severity="medium")
        exporter.submit_alert(sample_alert(severity="low"))
        exporter.submit_alert(sample_alert())
        incident, _ = IncidentManager().ingest(sample_alert(), {"key": "aa"})
        exporter.submit_incident(incident, "updated")  # not exported
        exporter.submit_incident(incident, "created")
        self.assertEqual(exporter.drain(), 2)
        self.assertEqual([record["kind"] for record in good], ["alert", "incident"])
        stats = exporter.stats()
        self.assertEqual((stats["sent"], stats["errors"]), (2, 2))
        self.assertIn("bad: unreachable", stats["last_error"])

    def test_disabled_exporter_queues_nothing(self):
        exporter = SiemExporter([])
        exporter.submit_alert(sample_alert())
        self.assertEqual(exporter.drain(), 0)


class NewDetectionTests(unittest.TestCase):
    def test_brute_force_on_auth_port_only(self):
        detector, state = engine(brute_force_threshold=5, port_scan_threshold=100)
        for second in range(5):
            detector.on_tcp_syn("203.0.113.9", "192.168.1.20", 22, now=second)
            detector.on_tcp_syn("192.168.1.10", "192.168.1.20", 8080, now=second)
        alerts = state.flush_traffic()[1]
        self.assertEqual([alert["type"] for alert in alerts], ["brute_force"])
        self.assertEqual((alerts[0]["severity"], alerts[0]["evidence"]["service"]), ("high", "SSH"))

    def test_brute_force_window_slides(self):
        detector, state = engine(brute_force_threshold=3, brute_force_window=10)
        for now in (0, 5, 11, 22):
            detector.on_tcp_syn("192.168.1.10", "192.168.1.20", 3389, now=now)
        self.assertEqual(alert_types(state), [])

    def test_wpad_answer_alerts_immediately(self):
        detector, state = engine()
        detector.on_name_resolution("192.168.1.66", "192.168.1.10", {"protocol": "llmnr", "is_response": True, "name": "wpad", "answers": ["192.168.1.66"]})
        alerts = state.flush_traffic()[1]
        self.assertEqual(alerts[0]["type"], "llmnr_poisoning")
        self.assertTrue(alerts[0]["evidence"]["wpad"])
        self.assertEqual(alerts[0]["mitre"][0]["id"], "T1557.001")

    def test_many_answered_names_alert_but_one_does_not(self):
        detector, state = engine(name_poisoning_threshold=3)
        info = lambda name: {"protocol": "nbns", "is_response": True, "name": name, "answers": []}
        detector.on_name_resolution("192.168.1.30", "192.168.1.10", info("printer"))
        detector.on_name_resolution("192.168.1.30", "192.168.1.10", info("printer"))
        detector.on_name_resolution("192.168.1.30", "192.168.1.10", {"protocol": "llmnr", "is_response": False, "name": "x"})
        self.assertEqual(alert_types(state), [])
        for name in ("fileserv", "intranet", "sharepoint"):
            detector.on_name_resolution("192.168.1.66", "192.168.1.10", info(name))
        self.assertEqual(alert_types(state), ["llmnr_poisoning"])

    def test_llmnr_and_nbns_parsing(self):
        query = IP(bytes(IP(src="192.168.1.10", dst="224.0.0.252") / UDP(sport=50000, dport=5355) / LLMNRQuery(qd=DNSQR(qname="FileServ"))))
        self.assertEqual(protocols.parse_name_resolution(query), {"protocol": "llmnr", "is_response": False, "name": "fileserv", "answers": []})
        response = IP(
            bytes(
                IP(src="192.168.1.66", dst="192.168.1.10")
                / UDP(sport=5355, dport=50000)
                / LLMNRResponse(qd=DNSQR(qname="fileserv"), an=DNSRR(rrname="fileserv", rdata="192.168.1.66"))
            )
        )
        self.assertEqual(protocols.parse_name_resolution(response)["answers"], ["192.168.1.66"])
        nbns = IP(
            bytes(
                IP(src="192.168.1.66", dst="192.168.1.10")
                / UDP(sport=137, dport=137)
                / NBNSHeader(RESPONSE=1, ANCOUNT=1, QDCOUNT=0)
                / NBNSQueryResponse(RR_NAME="WPAD")
            )
        )
        info = protocols.parse_name_resolution(nbns)
        self.assertEqual((info["protocol"], info["name"], info["is_response"]), ("nbns", "wpad", True))
        self.assertIsNone(protocols.parse_name_resolution(IP() / UDP(sport=1, dport=2)))


if __name__ == "__main__":
    unittest.main()
