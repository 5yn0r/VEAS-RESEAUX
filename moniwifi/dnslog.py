"""DNS query log, IP-to-domain cache, and per-client domain aggregation."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque

IGNORED_SUFFIXES = (".in-addr.arpa", ".ip6.arpa", ".local")


class DomainTracker:
    def __init__(self, max_log: int = 2000, max_ip_cache: int = 10000) -> None:
        self._lock = threading.Lock()
        self._log: deque[dict] = deque(maxlen=max_log)
        self._ip_domains: OrderedDict[str, str] = OrderedDict()
        self._max_ip_cache = max_ip_cache
        self._pending: dict[tuple[str, str, str], dict] = {}

    def record_query(self, client_ip: str, name: str, qtype: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        name = name.lower()
        with self._lock:
            self._log.append({"timestamp": now, "client_ip": client_ip, "query": name, "type": qtype, "answers": []})
        self.observe_name(client_ip, name, "dns", now)

    def record_response(self, client_ip: str, queries: list[dict], answers: list[dict], rcode: int = 0) -> None:
        """Attach answers to the matching logged query and learn IP-to-name mappings."""
        names = {query["name"].lower() for query in queries}
        addresses = [answer["data"] for answer in answers if answer["type"] in ("A", "AAAA")]
        with self._lock:
            for entry in reversed(self._log):
                if entry["client_ip"] == client_ip and entry["query"] in names and not entry["answers"]:
                    entry["answers"] = addresses
                    entry["rcode"] = rcode
                    break
            # Map every returned address to the name the client asked for (not the CNAME target).
            asked = next(iter(names), None)
            for address in addresses:
                if asked:
                    self._ip_domains[address] = asked
                    self._ip_domains.move_to_end(address)
            while len(self._ip_domains) > self._max_ip_cache:
                self._ip_domains.popitem(last=False)

    def observe_name(self, client_ip: str, name: str, source: str, now: float | None = None) -> None:
        name = name.lower().rstrip(".")
        if not name or name.endswith(IGNORED_SUFFIXES):
            return
        now = time.time() if now is None else now
        with self._lock:
            entry = self._pending.setdefault(
                (client_ip, name, source), {"count": 0, "first_seen": now, "last_seen": now}
            )
            entry["count"] += 1
            entry["last_seen"] = now

    def remember_ip(self, address: str, name: str) -> None:
        with self._lock:
            self._ip_domains[address] = name.lower()
            self._ip_domains.move_to_end(address)
            while len(self._ip_domains) > self._max_ip_cache:
                self._ip_domains.popitem(last=False)

    def domain_for_ip(self, address: str) -> str | None:
        with self._lock:
            return self._ip_domains.get(address)

    def drain_observations(self) -> list[dict]:
        with self._lock:
            pending, self._pending = self._pending, {}
        return [
            {"client_ip": client_ip, "domain": domain, "source": source, **data}
            for (client_ip, domain, source), data in pending.items()
        ]

    def recent(self, limit: int = 100, client_ip: str | None = None, query: str | None = None) -> list[dict]:
        query = query.lower() if query else None
        with self._lock:
            entries = list(reversed(self._log))
        result = []
        for entry in entries:
            if client_ip and entry["client_ip"] != client_ip:
                continue
            if query and query not in entry["query"]:
                continue
            result.append(dict(entry, answers=list(entry["answers"])))
            if len(result) >= limit:
                break
        return result
