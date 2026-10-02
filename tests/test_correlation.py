import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from moniwifi.alerts import make_alert
from moniwifi.allowlist import Allowlist
from moniwifi.baseline import BaselineTracker
from moniwifi.incidents import IncidentManager, severity_for_score
from moniwifi.notify import EmailChannel, NtfyChannel, Notifier, TelegramChannel, WebhookChannel, format_incident

MB = 1024 * 1024


class BaselineTests(unittest.TestCase):
    def tracker(self, **kwargs):
        options = dict(bucket_seconds=60, min_samples=10, sigma=4, min_anomaly_bytes=10 * MB, learning_seconds=1000)
        options.update(kwargs)
        return BaselineTracker(**options)

    def test_upload_spike_after_learning_samples(self):
        tracker = self.tracker()
        now = 0
        for minute in range(12):
            now = minute * 60
            self.assertEqual(tracker.add_traffic("dev", 1 * MB + minute * 1000, 0, now=now), [])
        tracker.add_traffic("dev", 200 * MB, 0, now=now + 1)  # lands in the current bucket
        findings = tracker.add_traffic("dev", 0, 0, now=now + 61)  # closes it
        self.assertEqual(findings[0]["kind"], "upload_spike")
        self.assertGreater(findings[0]["upload_bytes"], 200 * MB)

    def test_no_spike_before_min_samples_or_below_floor(self):
        tracker = self.tracker(min_samples=100)
        for minute in range(5):
            tracker.add_traffic("dev", 1000, 0, now=minute * 60)
        tracker.add_traffic("dev", 500 * MB, 0, now=301)
        self.assertEqual(tracker.add_traffic("dev", 0, 0, now=400), [])

        small = self.tracker()
        for minute in range(12):
            small.add_traffic("dev", 1000, 0, now=minute * 60)
        small.add_traffic("dev", 5 * MB, 0, now=721)  # huge relative jump but under the 10 MB floor
        self.assertEqual(small.add_traffic("dev", 0, 0, now=800), [])

    def test_idle_gap_counts_as_zero_buckets(self):
        tracker = self.tracker()
        tracker.add_traffic("dev", 1000, 0, now=0)
        tracker.add_traffic("dev", 1000, 0, now=60 * 5)
        self.assertEqual(tracker.snapshot("dev")["samples"], 5)
        tracker.add_traffic("dev", 1000, 0, now=60 * 1000)
        self.assertEqual(tracker.snapshot("dev")["samples"], 5 + 1 + 12)

    def test_new_destination_only_for_quiet_learned_devices(self):
        tracker = self.tracker(quiet_destination_limit=2)
        tracker.add_destination("cam", "vendor-cloud.example", now=0)
        self.assertIsNone(tracker.add_destination("cam", "ntp.example", now=10))  # still learning
        finding = tracker.add_destination("cam", "unknown.example", now=2000)
        self.assertEqual(finding["destination"], "unknown.example")
        self.assertIsNone(tracker.add_destination("cam", "vendor-cloud.example", now=2001))
        self.assertIsNone(tracker.add_destination("cam", "fourth.example", now=2002))  # no longer quiet

    def test_export_and_load_round_trip(self):
        tracker = self.tracker()
        tracker.add_traffic("dev", 1000, 0, now=0)
        tracker.add_destination("dev", "a.example", now=0)
        dirty = json.loads(json.dumps(tracker.drain_dirty()))
        restored = self.tracker()
        restored.load(dirty)
        self.assertEqual(restored.snapshot("dev")["destinations"], ["a.example"])
        self.assertEqual(tracker.drain_dirty(), {})


def alert(alert_type, severity="medium", timestamp=1000.0, **kwargs):
    return make_alert(alert_type, f"{alert_type} detail", severity=severity, timestamp=timestamp, **kwargs)


ENTITY = {"key": "aa:00:00:00:00:01", "ip": "192.168.1.10", "mac": "aa:00:00:00:00:01", "hostname": "laptop"}


class IncidentTests(unittest.TestCase):
    def test_grouping_scoring_and_chain_bonus(self):
        manager = IncidentManager(window=600)
        incident, event = manager.ingest(alert("new_device", "low"), ENTITY)
        self.assertEqual((event, incident["score"], incident["severity"]), ("created", 2, "low"))

        incident, event = manager.ingest(alert("port_scan", "medium", timestamp=1100), ENTITY)
        # 2 (low) + 5 (medium) + 5 diversity + 15 chain = 27
        self.assertEqual((event, incident["score"], incident["severity"]), ("escalated", 27, "high"))
        self.assertEqual(len(incident["reasons"]), 1)
        self.assertEqual(incident["summary"], "laptop: new device, port scan")

        incident, event = manager.ingest(alert("port_scan", "medium", timestamp=1200), ENTITY)
        self.assertEqual((event, incident["score"]), ("updated", 32))

    def test_repeats_are_capped_and_window_splits_incidents(self):
        manager = IncidentManager(window=600)
        for index in range(10):
            incident, _ = manager.ingest(alert("beaconing", "low", timestamp=1000 + index), ENTITY)
        self.assertEqual(incident["score"], 6)
        later, event = manager.ingest(alert("beaconing", "low", timestamp=5000), ENTITY)
        self.assertEqual(event, "created")
        self.assertNotEqual(later["id"], incident["id"])

    def test_status_changes_and_reopen_on_escalation(self):
        manager = IncidentManager()
        incident, _ = manager.ingest(alert("port_scan", "medium"), ENTITY)
        manager.set_status(incident["id"], "acknowledged")
        updated, event = manager.ingest(alert("threat_intel_ip", "high", timestamp=1001), ENTITY)
        self.assertEqual((event, updated["status"]), ("escalated", "open"))

        manager.set_status(incident["id"], "closed")
        fresh, event = manager.ingest(alert("port_scan", timestamp=1002), ENTITY)
        self.assertEqual(event, "created")
        self.assertEqual(manager.open_count(), 1)
        with self.assertRaises(ValueError):
            manager.set_status(fresh["id"], "bogus")
        self.assertIsNone(manager.set_status("missing", "closed"))

    def test_list_filters_and_load(self):
        manager = IncidentManager()
        low, _ = manager.ingest(alert("new_device", "low"), ENTITY)
        high, _ = manager.ingest(alert("arp_spoofing", "critical"), {"key": "other"})
        self.assertEqual([i["id"] for i in manager.list(min_severity="high")], [high["id"]])
        restored = IncidentManager()
        restored.load(manager.drain_dirty())
        self.assertEqual(restored.open_count(), 2)
        self.assertEqual(restored.ingest(alert("new_device", "low", timestamp=1001), ENTITY)[1], "updated")

    def test_single_critical_alert_makes_critical_incident(self):
        incident, _ = IncidentManager().ingest(alert("arp_spoofing", "critical"), ENTITY)
        self.assertEqual((incident["score"], incident["severity"]), (25, "critical"))

    def test_severity_thresholds(self):
        self.assertEqual([severity_for_score(v) for v in (0, 10, 25, 50)], ["low", "medium", "high", "critical"])


class AllowlistTests(unittest.TestCase):
    def test_rules_require_every_field_to_match(self):
        allowlist = Allowlist()
        allowlist.add({"type": "beaconing", "domain": "vendor.example", "comment": "camera cloud"})
        allowlist.add({"type": "port_scan", "ip": "192.168.1.5"})
        allowlist.add({"mac": "AA:00:00:00:00:09"})

        beacon = alert("beaconing", evidence={"target": "api.vendor.example"})
        self.assertEqual(allowlist.match(beacon)["comment"], "camera cloud")
        self.assertIsNone(allowlist.match(alert("beaconing", evidence={"target": "notvendor.example"})))
        self.assertIsNotNone(allowlist.match(alert("port_scan", source_ip="192.168.1.5")))
        self.assertIsNone(allowlist.match(alert("host_sweep", source_ip="192.168.1.5")))
        self.assertIsNotNone(allowlist.match(alert("anything", evidence={"mac": "aa:00:00:00:00:09"})))
        self.assertEqual(allowlist.hits, 3)

    def test_empty_rule_rejected_and_remove(self):
        allowlist = Allowlist()
        with self.assertRaises(ValueError):
            allowlist.add({"comment": "no fields"})
        rule = allowlist.add({"ip": "192.168.1.5"})
        self.assertTrue(allowlist.remove(rule["id"]))
        self.assertFalse(allowlist.remove(rule["id"]))


class Recorder(BaseHTTPRequestHandler):
    requests = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Recorder.requests.append((self.path, dict(self.headers), body))
        self.send_response(200 if "fail" not in self.path else 500)
        self.end_headers()

    def log_message(self, *args):
        pass


class NotifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Recorder)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Recorder.requests = []
        manager = IncidentManager()
        manager.ingest(alert("new_device", "low"), ENTITY)
        self.incident, _ = manager.ingest(alert("arp_spoofing", "critical", timestamp=1001), ENTITY)

    def test_http_channels_deliver_and_report_errors(self):
        channels = [
            WebhookChannel(f"{self.base}/hook"),
            NtfyChannel(f"{self.base}/topic", token="secret"),
            TelegramChannel("TOKEN", "42", api_base=self.base),
            WebhookChannel(f"{self.base}/fail"),
        ]
        with mock.patch.dict("os.environ", {"NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}):
            results = Notifier(channels).send_now(self.incident, "created")
        self.assertEqual([results[name] for name in ("ntfy", "telegram")], [None, None])
        self.assertIn("500", results["webhook"])  # the last webhook failed and overwrote the name
        paths = [path for path, _, _ in Recorder.requests]
        self.assertEqual(paths, ["/hook", "/topic", "/botTOKEN/sendMessage", "/fail"])
        hook = json.loads(Recorder.requests[0][2])
        self.assertEqual(hook["incident"]["id"], self.incident["id"])
        ntfy_headers = Recorder.requests[1][1]
        self.assertEqual((ntfy_headers["Priority"], ntfy_headers["Authorization"]), ("5", "Bearer secret"))
        self.assertIn(b"chat_id=42", Recorder.requests[2][2])

    def test_email_channel(self):
        smtp = mock.MagicMock()
        channel = EmailChannel("smtp.test", 587, "from@test", ["to@test"], username="u", password="p", smtp_factory=smtp)
        channel.send("Title", "Body", "high", {})
        session = smtp.return_value.__enter__.return_value
        session.starttls.assert_called_once()
        session.login.assert_called_once_with("u", "p")
        self.assertEqual(session.send_message.call_args.args[0]["To"], "to@test")

    def test_filtering_rate_limit_and_worker(self):
        channel = mock.Mock()
        channel.name = "mock"
        notifier = Notifier([channel], min_severity="high", max_per_hour=1)
        low = dict(self.incident, severity="medium")
        self.assertFalse(notifier.submit(low, "created"))
        self.assertFalse(notifier.submit(self.incident, "updated"))
        self.assertTrue(notifier.submit(self.incident, "created"))
        self.assertTrue(notifier.submit(self.incident, "escalated"))

        stop = threading.Event()
        worker = threading.Thread(target=notifier.run, args=(stop,))
        worker.start()
        for _ in range(200):
            if notifier.sent + notifier.dropped >= 2:
                break
            threading.Event().wait(0.01)
        stop.set()
        worker.join(2)
        self.assertEqual((notifier.sent, notifier.dropped), (1, 1))
        title = channel.send.call_args.args[0]
        self.assertIn("CRITICAL", title)

    def test_format_incident(self):
        title, message = format_incident(self.incident, "escalated")
        self.assertTrue(title.startswith("[WiFi Guardian] Escalated CRITICAL incident: laptop"))
        self.assertIn("arp_spoofing x1", message)
        self.assertIn("Why:", message)


if __name__ == "__main__":
    unittest.main()
