"""Offline IP/CIDR and domain indicators loaded from local files and optional feeds."""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import threading
import time
import urllib.request
from collections import OrderedDict
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_FEED_BYTES = 20 * 1024 * 1024
SINKHOLE_ADDRESSES = {"0.0.0.0", "127.0.0.1", "::", "::1"}


def parse_indicators(text: str) -> tuple[set[str], list, set[str]]:
    """Parse plain lists, CIDR lists (Spamhaus DROP), and hosts files (URLhaus).

    Returns (ips, networks, domains).
    """
    ips: set[str] = set()
    networks = []
    domains: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        tokens = line.split()
        token = tokens[0]
        if token in SINKHOLE_ADDRESSES and len(tokens) > 1:
            token = tokens[1]  # hosts-file format: "0.0.0.0 bad.example"
        token = token.strip().lower().rstrip(".")
        try:
            if "/" in token:
                network = ipaddress.ip_network(token, strict=False)
                if network.num_addresses == 1:
                    ips.add(str(network.network_address))
                else:
                    networks.append(network)
            else:
                ips.add(str(ipaddress.ip_address(token)))
            continue
        except ValueError:
            pass
        if "." in token and "/" not in token and ":" not in token and token not in ("localhost",):
            domains.add(token)
    return ips, networks, domains


class ThreatIntel:
    def __init__(self, directory: str | None = None, feeds: list[str] | None = None, cache_size: int = 50000) -> None:
        self.directory = Path(directory) if directory else None
        self.feeds = [feed for feed in (feeds or []) if feed]
        self._lock = threading.Lock()
        self._ips: dict[str, str] = {}
        self._networks: list[tuple] = []
        self._domains: dict[str, str] = {}
        self._cache: OrderedDict[str, str | None] = OrderedDict()
        self._cache_size = cache_size
        self.last_loaded_at: float | None = None
        self.last_error: str | None = None

    # Loading -------------------------------------------------------------

    def load_text(self, text: str, source: str) -> None:
        ips, networks, domains = parse_indicators(text)
        with self._lock:
            for ip in ips:
                self._ips[ip] = source
            self._networks.extend((network, source) for network in networks)
            for domain in domains:
                self._domains[domain] = source
            self._cache.clear()

    def reload(self) -> None:
        """Replace indicators with the content of every *.txt file in the directory."""
        fresh = ThreatIntel()
        if self.directory and self.directory.is_dir():
            for path in sorted(self.directory.glob("*.txt")):
                try:
                    fresh.load_text(path.read_text(encoding="utf-8", errors="replace"), path.stem)
                except OSError as exc:
                    logger.error("Cannot read indicator file %s: %s", path, exc)
        with self._lock:
            self._ips, self._networks, self._domains = fresh._ips, fresh._networks, fresh._domains
            self._cache.clear()
            self.last_loaded_at = time.time()
        logger.info("Threat intel loaded: %s", self.stats())

    def download_feeds(self) -> None:
        if not self.directory or not self.feeds:
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        errors = []
        for url in self.feeds:
            target = self.directory / f"feed-{hashlib.sha1(url.encode()).hexdigest()[:10]}.txt"
            try:
                with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - operator-configured URL
                    data = response.read(MAX_FEED_BYTES + 1)
                if len(data) > MAX_FEED_BYTES:
                    raise ValueError("feed larger than 20 MB")
                temporary = target.with_suffix(".tmp")
                temporary.write_bytes(data)
                temporary.replace(target)
                logger.info("Downloaded threat feed %s", url)
            except Exception as exc:  # noqa: BLE001 - one broken feed must not block the others
                logger.error("Threat feed %s failed: %s", url, exc)
                errors.append(f"{url}: {exc}")
        self.last_error = "; ".join(errors) or None

    # Matching ------------------------------------------------------------

    def match_ip(self, address: str) -> str | None:
        with self._lock:
            if address in self._cache:
                self._cache.move_to_end(address)
                return self._cache[address]
            source = self._ips.get(address)
            if source is None and self._networks:
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    parsed = None
                if parsed is not None:
                    for network, network_source in self._networks:
                        if parsed.version == network.version and parsed in network:
                            source = network_source
                            break
            self._cache[address] = source
            if len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
            return source

    def match_domain(self, name: str) -> tuple[str, str] | None:
        """Return (listed_domain, source) when ``name`` or one of its parents is listed."""
        labels = name.lower().rstrip(".").split(".")
        with self._lock:
            if not self._domains:
                return None
            for index in range(len(labels) - 1):
                candidate = ".".join(labels[index:])
                if candidate in self._domains:
                    return candidate, self._domains[candidate]
        return None

    def stats(self) -> dict:
        with self._lock:
            return {
                "ips": len(self._ips),
                "networks": len(self._networks),
                "domains": len(self._domains),
                "last_loaded_at": self.last_loaded_at,
                "last_error": self.last_error,
            }
