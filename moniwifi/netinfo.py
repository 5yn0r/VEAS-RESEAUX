"""Periodically refreshed view of the capture interface and local network."""

from __future__ import annotations

import ipaddress
import logging
import threading
import time

import netifaces

logger = logging.getLogger(__name__)


class NetworkContext:
    """Resolve the capture interface and LAN, re-checking on a timer.

    Lookups are cheap enough for the packet callback: they only hit netifaces
    when the cached value is older than ``refresh_interval`` (or
    ``retry_interval`` after a failure), so a late DHCP lease or a network
    change is picked up without restarting the process.
    """

    def __init__(
        self,
        interface_override: str | None = None,
        refresh_interval: float = 60.0,
        retry_interval: float = 5.0,
        backend=netifaces,
        clock=time.monotonic,
    ) -> None:
        self.interface_override = interface_override or None
        self.refresh_interval = refresh_interval
        self.retry_interval = retry_interval
        self.backend = backend
        self.clock = clock
        self._lock = threading.Lock()
        self._value: tuple[str | None, ipaddress.IPv4Network | None, str | None] = (None, None, None)
        self._checked_at: float | None = None
        self._last_error: str | None = None
        self._gateway: str | None = None

    def interface(self) -> str | None:
        return self._current()[0]

    def local_network(self) -> ipaddress.IPv4Network | None:
        return self._current()[1]

    def local_ip(self) -> str | None:
        return self._current()[2]

    def gateway_ip(self) -> str | None:
        self._current()
        return self._gateway

    def is_local(self, address: str) -> bool:
        network = self.local_network()
        if network is None:
            return False
        try:
            return ipaddress.ip_address(address) in network
        except ValueError:
            return False

    def refresh(self) -> tuple[str | None, ipaddress.IPv4Network | None, str | None]:
        with self._lock:
            return self._refresh_locked()

    def snapshot(self) -> dict:
        iface, network, local_ip = self._current()
        return {
            "interface": iface,
            "local_network": str(network) if network else None,
            "local_ip": local_ip,
            "gateway_ip": self._gateway,
            "last_error": self._last_error,
        }

    def _current(self):
        value, checked_at = self._value, self._checked_at
        interval = self.refresh_interval if value[1] else self.retry_interval
        if checked_at is not None and self.clock() - checked_at < interval:
            return value
        with self._lock:
            if self._checked_at is not None and self.clock() - self._checked_at < interval:
                return self._value
            return self._refresh_locked()

    def _refresh_locked(self):
        previous = self._value
        try:
            default_gateway, default_iface = self._default_route()
            iface = self.interface_override or default_iface
            self._gateway = default_gateway if default_iface == iface else None
            network, local_ip = self._network_for(iface) if iface else (None, None)
            self._last_error = None if network else "no IPv4 network on capture interface"
        except Exception as exc:  # noqa: BLE001 - netifaces raises assorted errors
            logger.error("Network detection failed: %s", exc)
            iface, network, local_ip = previous[0], None, None
            self._last_error = str(exc)

        self._value = (iface, network, local_ip)
        self._checked_at = self.clock()
        if self._value != previous:
            logger.info("Capture context: interface=%s network=%s ip=%s", iface, network, local_ip)
        return self._value

    def _default_route(self) -> tuple[str | None, str | None]:
        default = self.backend.gateways().get("default", {}).get(self.backend.AF_INET)
        return (default[0], default[1]) if default else (None, None)

    def _network_for(self, iface: str):
        addrs = self.backend.ifaddresses(iface).get(self.backend.AF_INET) or []
        if not addrs:
            return None, None
        info = addrs[0]
        network = ipaddress.ip_network(f"{info['addr']}/{info['netmask']}", strict=False)
        return network, info["addr"]


class StaticNetworkContext:
    """Fixed capture context, used to analyse a pcap recorded elsewhere."""

    def __init__(self, network: str, gateway: str | None = None, interface: str = "offline") -> None:
        self._network = ipaddress.ip_network(network, strict=False)
        self._gateway = gateway
        self._interface = interface

    def interface(self) -> str:
        return self._interface

    def local_network(self):
        return self._network

    def local_ip(self) -> str | None:
        return None

    def gateway_ip(self) -> str | None:
        return self._gateway

    def is_local(self, address: str) -> bool:
        try:
            return ipaddress.ip_address(address) in self._network
        except ValueError:
            return False

    def snapshot(self) -> dict:
        return {
            "interface": self._interface,
            "local_network": str(self._network),
            "local_ip": None,
            "gateway_ip": self._gateway,
            "last_error": None,
        }
