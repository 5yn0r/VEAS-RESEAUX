"""Details of the network the host is connected to: addressing, gateway, DNS, Wi-Fi link, throughput.

Data comes from netifaces, /sys/class/net, /proc/net/arp, and the standard
Linux tools ``iw``, ``nmcli`` and ``resolvectl`` when they are installed.
Every source is optional: a missing tool leaves its fields empty.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

import netifaces

TOOL_DIRS = ("/usr/sbin", "/sbin", "/usr/bin", "/bin")
# A rate needs two samples; on the first request take a second one after this delay.
INITIAL_SAMPLE_DELAY = 0.5


def run_command(args: list[str], timeout: float = 3.0) -> str | None:
    executable = shutil.which(args[0]) or next(
        (f"{directory}/{args[0]}" for directory in TOOL_DIRS if Path(directory, args[0]).is_file()), None
    )
    if executable is None:
        return None
    try:
        result = subprocess.run([executable, *args[1:]], capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


# Parsers (pure functions, tested with captured output) ---------------------


def channel_from_frequency(mhz: float) -> tuple[int | None, str | None]:
    mhz = int(mhz)
    if mhz == 2484:
        return 14, "2.4 GHz"
    if 2412 <= mhz <= 2472:
        return (mhz - 2407) // 5, "2.4 GHz"
    if 5150 <= mhz <= 5895:
        return (mhz - 5000) // 5, "5 GHz"
    if 5955 <= mhz <= 7115:
        return (mhz - 5950) // 5, "6 GHz"
    return None, None


def signal_quality(dbm: float | None) -> tuple[int | None, str | None]:
    """Map dBm to a 0-100 % quality and a French label."""
    if dbm is None:
        return None, None
    quality = max(0, min(100, round((dbm + 90) * 100 / 60)))
    if dbm >= -50:
        label = "Excellent"
    elif dbm >= -60:
        label = "Bon"
    elif dbm >= -70:
        label = "Moyen"
    else:
        label = "Faible"
    return quality, label


def _float(pattern: str, text: str) -> float | None:
    match = re.search(pattern, text, re.MULTILINE)
    return float(match.group(1)) if match else None


def parse_iw_link(text: str) -> dict:
    """Parse ``iw dev <if> link``."""
    if not text or text.strip().startswith("Not connected"):
        return {"connected": False}
    bssid = re.search(r"Connected to ([0-9a-f:]{17})", text, re.I)
    ssid = re.search(r"^\s*SSID: (.*)$", text, re.MULTILINE)
    info = {
        "connected": True,
        "bssid": bssid.group(1).lower() if bssid else None,
        "ssid": ssid.group(1).strip() if ssid else None,
        "frequency_mhz": _float(r"freq: ([\d.]+)", text),
        "signal_dbm": _float(r"signal: (-?\d+) dBm", text),
        "rx_bitrate_mbps": _float(r"rx bitrate: ([\d.]+) MBit/s", text),
        "tx_bitrate_mbps": _float(r"tx bitrate: ([\d.]+) MBit/s", text),
    }
    standard = re.search(r"rx bitrate: .*?\b(EHT|HE|VHT|MCS)", text)
    info["standard"] = {"EHT": "Wi-Fi 7 (802.11be)", "HE": "Wi-Fi 6 (802.11ax)", "VHT": "Wi-Fi 5 (802.11ac)", "MCS": "Wi-Fi 4 (802.11n)"}.get(
        standard.group(1) if standard else "", None
    )
    return info


def parse_iw_info(text: str) -> dict:
    """Parse ``iw dev <if> info`` for channel width and transmit power."""
    if not text:
        return {}
    return {
        "channel_width_mhz": _float(r"width: (\d+) MHz", text),
        "tx_power_dbm": _float(r"txpower ([\d.]+) dBm", text),
        "mode": (re.search(r"^\s*type (\w+)", text, re.MULTILINE) or [None, None])[1],
    }


def parse_nmcli_wifi(text: str) -> dict:
    """Parse ``nmcli -t -f IN-USE,BSSID,SSID,SECURITY dev wifi list`` and keep the line in use."""
    for line in (text or "").splitlines():
        fields = re.split(r"(?<!\\):", line)
        if len(fields) >= 4 and fields[0] == "*":
            return {
                "bssid": fields[1].replace("\\:", ":").lower(),
                "ssid": fields[2].replace("\\:", ":"),
                "security": fields[3] or "Ouvert",
            }
    return {}


def parse_resolvectl(text: str) -> list[str]:
    """Parse ``resolvectl dns <if>``: ``Link 3 (wlp2s0): 192.168.1.254 fe80::1``."""
    if not text or ":" not in text:
        return []
    return text.split("):", 1)[-1].split()


def parse_resolv_conf(text: str) -> list[str]:
    return [line.split()[1] for line in text.splitlines() if line.startswith("nameserver") and len(line.split()) > 1]


def arp_lookup(ip: str, table: str) -> str | None:
    """Find the MAC of ``ip`` in /proc/net/arp."""
    for line in table.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 4 and fields[0] == ip and fields[3] != "00:00:00:00:00:00":
            return fields[3].lower()
    return None


def ipv4_details(address: str, netmask: str) -> dict:
    interface = ipaddress.ip_interface(f"{address}/{netmask}")
    network = interface.network
    hosts = max(network.num_addresses - 2, 0) if network.prefixlen < 31 else network.num_addresses
    first = network.network_address + 1 if network.prefixlen < 31 else network.network_address
    last = network.broadcast_address - 1 if network.prefixlen < 31 else network.broadcast_address
    return {
        "address": address,
        "netmask": netmask,
        "prefix": network.prefixlen,
        "network": str(network),
        "broadcast": str(network.broadcast_address),
        "usable_hosts": hosts,
        "host_range": f"{first} - {last}",
        "private": interface.ip.is_private,
    }


def ipv6_details(entries: list[dict]) -> list[dict]:
    addresses = []
    for entry in entries:
        address = entry["addr"].split("%", 1)[0]
        prefix = entry.get("netmask", "").rsplit("/", 1)[-1]
        ip = ipaddress.ip_address(address)
        scope = "lien local" if ip.is_link_local else "unique locale" if ip.is_private else "globale"
        addresses.append({"address": address, "prefix": int(prefix) if prefix.isdigit() else None, "scope": scope})
    return addresses


# Collector -------------------------------------------------------------------


class NetworkInfo:
    def __init__(self, oui=None, runner=run_command, sys_root: str = "/sys/class/net", proc_arp: str = "/proc/net/arp") -> None:
        self.oui = oui
        self.runner = runner
        self.sys_root = Path(sys_root)
        self.proc_arp = Path(proc_arp)
        self._lock = threading.Lock()
        self._previous: dict[str, tuple[float, dict]] = {}

    def collect(self, iface: str | None, gateway_ip: str | None = None) -> dict:
        if not iface:
            return {"connected": False, "error": "aucune interface réseau active", "timestamp": time.time()}
        sysdir = self.sys_root / iface
        wireless = (sysdir / "wireless").exists() or (sysdir / "phy80211").exists()
        result = {
            "connected": True,
            "timestamp": time.time(),
            "interface": {
                "name": iface,
                "type": "wifi" if wireless else "ethernet",
                "mac": self._mac(iface),
                "mtu": self._read_int(sysdir / "mtu"),
                "state": self._read(sysdir / "operstate"),
            },
            "ipv4": self._ipv4(iface),
            "ipv6": ipv6_details(netifaces.ifaddresses(iface).get(netifaces.AF_INET6, [])) if iface in netifaces.interfaces() else [],
            "gateway": self._gateway(iface, gateway_ip),
            "dns": self._dns(iface),
            "wifi": self._wifi(iface) if wireless else None,
            "ethernet": None if wireless else self._ethernet(sysdir),
        }
        result["interface"]["vendor"] = self._vendor(result["interface"]["mac"])
        result["traffic"] = self._traffic(iface, sysdir, self._capacity(result))
        return result

    # Sections ------------------------------------------------------------

    def _ipv4(self, iface: str) -> dict | None:
        try:
            entries = netifaces.ifaddresses(iface).get(netifaces.AF_INET) or []
        except ValueError:
            return None
        return ipv4_details(entries[0]["addr"], entries[0]["netmask"]) if entries else None

    def _gateway(self, iface: str, gateway_ip: str | None) -> dict | None:
        if not gateway_ip:
            default = netifaces.gateways().get("default", {}).get(netifaces.AF_INET)
            gateway_ip = default[0] if default and default[1] == iface else None
        if not gateway_ip:
            return None
        mac = arp_lookup(gateway_ip, self._read(self.proc_arp) or "")
        return {"ip": gateway_ip, "mac": mac, "vendor": self._vendor(mac)}

    def _dns(self, iface: str) -> list[str]:
        servers = parse_resolvectl(self.runner(["resolvectl", "dns", iface]) or "")
        return servers or parse_resolv_conf(self._read(Path("/etc/resolv.conf")) or "")

    def _wifi(self, iface: str) -> dict:
        info = parse_iw_link(self.runner(["iw", "dev", iface, "link"]) or "")
        if not info.get("connected"):
            return info
        info.update({key: value for key, value in parse_iw_info(self.runner(["iw", "dev", iface, "info"]) or "").items() if value is not None})
        nmcli = parse_nmcli_wifi(self.runner(["nmcli", "-t", "-f", "IN-USE,BSSID,SSID,SECURITY", "dev", "wifi", "list", "ifname", iface, "--rescan", "no"]) or "")
        info["security"] = nmcli.get("security")
        info["ssid"] = info.get("ssid") or nmcli.get("ssid")
        if info.get("frequency_mhz"):
            info["channel"], info["band"] = channel_from_frequency(info["frequency_mhz"])
        info["signal_quality"], info["signal_label"] = signal_quality(info.get("signal_dbm"))
        info["access_point_vendor"] = self._vendor(info.get("bssid"))
        return info

    def _ethernet(self, sysdir: Path) -> dict:
        speed = self._read_int(sysdir / "speed")
        return {"speed_mbps": speed if speed and speed > 0 else None, "duplex": self._read(sysdir / "duplex")}

    @staticmethod
    def _capacity(result: dict) -> float | None:
        """Negotiated link speed in Mbit/s: the bandwidth the link can carry."""
        if result["wifi"]:
            rates = [result["wifi"].get("rx_bitrate_mbps"), result["wifi"].get("tx_bitrate_mbps")]
            rates = [rate for rate in rates if rate]
            return max(rates) if rates else None
        return (result["ethernet"] or {}).get("speed_mbps")

    def _traffic(self, iface: str, sysdir: Path, capacity: float | None) -> dict:
        counters = self._counters(sysdir)
        now = time.monotonic()
        with self._lock:
            previous = self._previous.get(iface)
        if counters and (previous is None or now - previous[0] > 120):
            # First request: a second sample gives a rate immediately.
            time.sleep(INITIAL_SAMPLE_DELAY)
            previous, counters, now = (now, counters), self._counters(sysdir), time.monotonic()
        with self._lock:
            self._previous[iface] = (now, counters)

        rates = {"download_bps": None, "upload_bps": None, "utilization_percent": None}
        if counters and previous and now > previous[0]:
            elapsed = now - previous[0]
            rates["download_bps"] = max(counters["rx_bytes"] - previous[1]["rx_bytes"], 0) / elapsed
            rates["upload_bps"] = max(counters["tx_bytes"] - previous[1]["tx_bytes"], 0) / elapsed
            if capacity:
                used_bits = (rates["download_bps"] + rates["upload_bps"]) * 8
                rates["utilization_percent"] = round(min(used_bits / (capacity * 1_000_000) * 100, 100), 2)
        return {"link_capacity_mbps": capacity, **rates, "counters": counters}

    # Helpers -------------------------------------------------------------

    def _counters(self, sysdir: Path) -> dict | None:
        names = ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped")
        values = {name: self._read_int(sysdir / "statistics" / name) for name in names}
        return values if values["rx_bytes"] is not None else None

    def _mac(self, iface: str) -> str | None:
        mac = self._read(self.sys_root / iface / "address")
        return mac.lower() if mac else None

    def _vendor(self, mac: str | None) -> str | None:
        return self.oui.lookup(mac) if self.oui and mac else None

    @staticmethod
    def _read(path: Path) -> str | None:
        try:
            return path.read_text().strip()
        except OSError:
            return None

    def _read_int(self, path: Path) -> int | None:
        value = self._read(path)
        try:
            return int(value) if value is not None else None
        except ValueError:
            return None
