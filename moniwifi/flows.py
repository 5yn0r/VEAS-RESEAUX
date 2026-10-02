"""Bidirectional flow aggregation (client/server 5-tuples) with idle expiry."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque

WELL_KNOWN_PORT_LIMIT = 1024


class FlowTable:
    def __init__(
        self,
        max_active: int = 20000,
        max_completed: int = 2000,
        tcp_idle_timeout: float = 300.0,
        udp_idle_timeout: float = 60.0,
        closed_timeout: float = 5.0,
    ) -> None:
        self.max_active = max_active
        self.tcp_idle_timeout = tcp_idle_timeout
        self.udp_idle_timeout = udp_idle_timeout
        self.closed_timeout = closed_timeout
        self._lock = threading.Lock()
        self._active: OrderedDict[tuple, dict] = OrderedDict()
        self._completed: deque[dict] = deque(maxlen=max_completed)
        self.evicted = 0
        self._evicted_pending: list[dict] = []

    def update(
        self,
        *,
        protocol: str,
        src_ip: str,
        src_port: int | None,
        dst_ip: str,
        dst_port: int | None,
        size: int,
        direction: str,
        tcp_flags: str | None = None,
        server_name: str | None = None,
        name_source: str = "dns",
        now: float | None = None,
    ) -> dict:
        now = time.time() if now is None else now
        src_port = src_port or 0
        dst_port = dst_port or 0
        forward = (protocol, src_ip, src_port, dst_ip, dst_port)
        reverse = (protocol, dst_ip, dst_port, src_ip, src_port)
        with self._lock:
            if forward in self._active:
                key, from_client = forward, True
            elif reverse in self._active:
                key, from_client = reverse, False
            else:
                key, from_client = self._new_key(forward, reverse, src_port, dst_port, tcp_flags)
                client_is_src = key == forward
                self._active[key] = {
                    "protocol": protocol,
                    "client_ip": key[1],
                    "client_port": key[2] or None,
                    "server_ip": key[3],
                    "server_port": key[4] or None,
                    "direction": direction if client_is_src else _flip(direction),
                    "first_seen": now,
                    "last_seen": now,
                    "packets_out": 0,
                    "bytes_out": 0,
                    "packets_in": 0,
                    "bytes_in": 0,
                    "tcp_flags": "",
                    "server_name": None,
                    "server_name_source": None,
                    "closed": False,
                }
                self._evict_if_full()
            flow = self._active[key]
            self._active.move_to_end(key)
            flow["last_seen"] = now
            if from_client:
                flow["packets_out"] += 1
                flow["bytes_out"] += size
            else:
                flow["packets_in"] += 1
                flow["bytes_in"] += size
            if tcp_flags:
                flow["tcp_flags"] = "".join(sorted(set(flow["tcp_flags"]) | set(tcp_flags)))
                if "R" in tcp_flags or "F" in tcp_flags:
                    flow["closed"] = True
            # A name read from the flow itself (TLS SNI, HTTP Host) beats one inferred from DNS.
            if server_name and (not flow["server_name"] or (name_source != "dns" and flow["server_name_source"] == "dns")):
                flow["server_name"] = server_name
                flow["server_name_source"] = name_source
            return dict(flow)

    def expire(self, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        with self._lock:
            expired, self._evicted_pending = self._evicted_pending, []
            for key, flow in list(self._active.items()):
                idle = now - flow["last_seen"]
                timeout = (
                    self.closed_timeout
                    if flow["closed"]
                    else self.tcp_idle_timeout
                    if flow["protocol"] == "TCP"
                    else self.udp_idle_timeout
                )
                if idle >= timeout:
                    del self._active[key]
                    finished = self._finish(flow)
                    self._completed.append(finished)
                    expired.append(finished)
        return expired

    def snapshot(
        self,
        limit: int = 100,
        ip_addr: str | None = None,
        include_completed: bool = True,
    ) -> list[dict]:
        with self._lock:
            flows = [dict(flow, active=True) for flow in reversed(self._active.values())]
            if include_completed:
                flows += [dict(flow, active=False) for flow in reversed(self._completed)]
        if ip_addr:
            flows = [flow for flow in flows if ip_addr in (flow["client_ip"], flow["server_ip"])]
        return flows[:limit]

    def stats(self) -> dict:
        with self._lock:
            return {"active_flows": len(self._active), "evicted_flows": self.evicted}

    # Helpers -------------------------------------------------------------

    @staticmethod
    def _new_key(forward, reverse, src_port, dst_port, tcp_flags) -> tuple[tuple, bool]:
        """Pick the client side of a new flow.

        A bare SYN identifies the client. Otherwise, the side on a well-known
        port is taken as the server, and failing that the sender is the client.
        """
        if tcp_flags == "S":
            return forward, True
        if tcp_flags == "SA":
            return reverse, False
        if src_port and src_port < WELL_KNOWN_PORT_LIMIT <= dst_port:
            return reverse, False
        return forward, True

    def _evict_if_full(self) -> None:
        while len(self._active) > self.max_active:
            _, flow = self._active.popitem(last=False)
            finished = self._finish(flow)
            self._completed.append(finished)
            self._evicted_pending.append(finished)
            self.evicted += 1

    @staticmethod
    def _finish(flow: dict) -> dict:
        finished = dict(flow)
        finished["duration"] = flow["last_seen"] - flow["first_seen"]
        return finished


def _flip(direction: str) -> str:
    return {"outbound": "inbound", "inbound": "outbound"}.get(direction, direction)
