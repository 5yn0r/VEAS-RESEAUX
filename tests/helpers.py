"""Shared fakes for tests that must not touch the real network."""

import ipaddress


class FakeSocketIO:
    def __init__(self):
        self.events = []

    def emit(self, event, payload):
        self.events.append((event, payload))

    def of(self, name):
        return [payload for event, payload in self.events if event == name]


class FakeNetwork:
    def __init__(self, interface="eth0", network="192.168.1.0/24", local_ip="192.168.1.2", gateway="192.168.1.1"):
        self.gateway = gateway
        self.iface = interface
        self.network = ipaddress.ip_network(network) if network else None
        self.ip = local_ip

    def interface(self):
        return self.iface

    def local_network(self):
        return self.network

    def local_ip(self):
        return self.ip

    def gateway_ip(self):
        return self.gateway

    def is_local(self, address):
        try:
            return self.network is not None and ipaddress.ip_address(address) in self.network
        except ValueError:
            return False

    def snapshot(self):
        return {
            "interface": self.iface,
            "local_network": str(self.network) if self.network else None,
            "local_ip": self.ip,
            "gateway_ip": self.gateway,
            "last_error": None,
        }


class FakeNetifaces:
    AF_INET = 2

    def __init__(self, iface="eth0", addr="192.168.1.2", netmask="255.255.255.0"):
        self.iface = iface
        self.addr = addr
        self.netmask = netmask
        self.calls = 0
        self.fail = False

    def gateways(self):
        self.calls += 1
        if self.fail:
            raise OSError("netlink unavailable")
        if not self.iface:
            return {}
        return {"default": {self.AF_INET: ("192.168.1.1", self.iface)}}

    def ifaddresses(self, iface):
        if not self.addr:
            return {}
        return {self.AF_INET: [{"addr": self.addr, "netmask": self.netmask}]}


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now
