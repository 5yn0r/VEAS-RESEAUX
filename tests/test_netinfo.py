import unittest

from moniwifi.netinfo import NetworkContext
from tests.helpers import FakeClock, FakeNetifaces


class NetworkContextTests(unittest.TestCase):
    def test_resolves_default_interface_and_network(self):
        context = NetworkContext(backend=FakeNetifaces(), clock=FakeClock())
        self.assertEqual(context.interface(), "eth0")
        self.assertEqual(str(context.local_network()), "192.168.1.0/24")
        self.assertEqual(context.local_ip(), "192.168.1.2")

    def test_caches_until_refresh_interval_then_picks_up_changes(self):
        backend, clock = FakeNetifaces(), FakeClock()
        context = NetworkContext(refresh_interval=60, backend=backend, clock=clock)
        context.local_network()
        context.local_network()
        self.assertEqual(backend.calls, 1)

        backend.iface, backend.addr = "wlan0", "10.0.0.5"
        clock.now += 61
        self.assertEqual(context.interface(), "wlan0")
        self.assertEqual(str(context.local_network()), "10.0.0.0/24")

    def test_missing_network_is_retried_instead_of_cached_forever(self):
        backend, clock = FakeNetifaces(iface=None), FakeClock()
        context = NetworkContext(refresh_interval=60, retry_interval=5, backend=backend, clock=clock)
        self.assertIsNone(context.local_network())

        backend.iface = "eth0"
        clock.now += 6
        self.assertEqual(str(context.local_network()), "192.168.1.0/24")

    def test_backend_errors_are_reported_not_raised(self):
        backend = FakeNetifaces()
        backend.fail = True
        context = NetworkContext(backend=backend, clock=FakeClock())
        self.assertIsNone(context.local_network())
        self.assertIn("netlink", context.snapshot()["last_error"])

    def test_interface_override_skips_default_route(self):
        backend = FakeNetifaces(iface=None)
        context = NetworkContext(interface_override="br0", backend=backend, clock=FakeClock())
        self.assertEqual(context.interface(), "br0")
        self.assertEqual(str(context.local_network()), "192.168.1.0/24")
        self.assertIsNone(context.gateway_ip())

    def test_gateway_and_locality(self):
        context = NetworkContext(backend=FakeNetifaces(), clock=FakeClock())
        self.assertEqual(context.gateway_ip(), "192.168.1.1")
        self.assertTrue(context.is_local("192.168.1.77"))
        self.assertFalse(context.is_local("8.8.8.8"))
        self.assertFalse(context.is_local("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
