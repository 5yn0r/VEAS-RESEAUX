"""Offline MAC vendor lookup from the OUI files shipped by arp-scan or Wireshark."""

from __future__ import annotations

import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_PATHS = (
    "/usr/share/arp-scan/ieee-oui.txt",
    "/usr/share/wireshark/manuf",
    "/usr/local/share/arp-scan/ieee-oui.txt",
)


def is_randomized(mac: str) -> bool:
    """Locally administered addresses are used by phones and laptops for MAC randomization."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


class OuiDatabase:
    def __init__(self, paths: tuple[str, ...] | list[str] = DEFAULT_PATHS) -> None:
        self.paths = [path for path in paths if path]
        self._vendors: dict[str, str] | None = None
        self._lock = threading.Lock()

    def lookup(self, mac: str) -> str | None:
        if not mac:
            return None
        if is_randomized(mac):
            return "Randomized MAC"
        vendors = self._load()
        return vendors.get(mac.replace(":", "").replace("-", "").upper()[:6])

    def _load(self) -> dict[str, str]:
        if self._vendors is not None:
            return self._vendors
        with self._lock:
            if self._vendors is None:
                self._vendors = {}
                for path in self.paths:
                    if Path(path).is_file():
                        self._vendors = self._parse(Path(path))
                        logger.info("Loaded %s OUI vendors from %s", len(self._vendors), path)
                        break
        return self._vendors

    @staticmethod
    def _parse(path: Path) -> dict[str, str]:
        vendors = {}
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2:
                    continue
                prefix = parts[0].replace(":", "").replace("-", "").upper()
                # Wireshark lines carry longer masks (e.g. 00:1B:C5:00:00/36); keep 24-bit OUIs only.
                if len(prefix) != 6 or "/" in parts[0]:
                    continue
                vendor = (parts[2] if len(parts) > 2 and parts[2] else parts[1]).strip()
                vendors[prefix] = vendor[:40]
        return vendors
