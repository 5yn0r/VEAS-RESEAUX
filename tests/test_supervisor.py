import threading
import time
import unittest

from moniwifi.supervisor import ThreadSupervisor


def wait_until(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


class ThreadSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.supervisor = ThreadSupervisor(restart_delay=0.01, max_restart_delay=0.02)

    def tearDown(self):
        self.supervisor.stop(timeout=1)

    def test_crashing_worker_is_restarted_and_error_recorded(self):
        runs = []

        def worker():
            runs.append(1)
            if len(runs) < 3:
                raise RuntimeError("boom")
            self.supervisor.stop_event.wait()

        self.supervisor.add("Worker", worker)
        self.supervisor.start()

        self.assertTrue(wait_until(lambda: len(runs) >= 3))
        status = self.supervisor.status()["Worker"]
        self.assertTrue(status["alive"])
        self.assertEqual(status["restarts"], 2)
        self.assertIn("RuntimeError: boom", status["last_error"])

    def test_worker_that_returns_is_restarted(self):
        runs = []
        self.supervisor.add("Worker", lambda: runs.append(1))
        self.supervisor.start()
        self.assertTrue(wait_until(lambda: len(runs) >= 2))
        self.assertEqual(self.supervisor.status()["Worker"]["last_error"], "worker exited unexpectedly")

    def test_stop_ends_workers_and_heartbeat_is_reported(self):
        started = threading.Event()

        def worker():
            started.set()
            self.supervisor.heartbeat("Worker")
            self.supervisor.stop_event.wait()

        self.supervisor.add("Worker", worker)
        self.supervisor.start()
        self.assertTrue(started.wait(1))
        self.assertTrue(wait_until(lambda: self.supervisor.status()["Worker"]["last_heartbeat"]))

        self.supervisor.stop(timeout=1)
        status = self.supervisor.status()["Worker"]
        self.assertFalse(status["alive"])
        self.assertEqual(status["restarts"], 0)


if __name__ == "__main__":
    unittest.main()
