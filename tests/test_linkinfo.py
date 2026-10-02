import tempfile
import unittest
from pathlib import Path
from unittest import mock

from veas import linkinfo
from veas.linkinfo import (
    NetworkInfo,
    arp_lookup,
    channel_from_frequency,
    ipv4_details,
    ipv6_details,
    parse_iw_info,
    parse_iw_link,
    parse_nmcli_wifi,
    parse_resolv_conf,
    parse_resolvectl,
    signal_quality,
)

IW_LINK = """Connected to 78:4f:24:95:bf:d9 (on wlp2s0)
\tSSID: CANALBOX-A737-2G
\tfreq: 2452.0
\tRX: 1656548649 bytes (1224945 packets)
\tTX: 76355700 bytes (301198 packets)
\tsignal: -34 dBm
\trx bitrate: 144.4 MBit/s MCS 15 short GI
\ttx bitrate: 11.0 MBit/s
"""
IW_INFO = """Interface wlp2s0
\ttype managed
\tchannel 9 (2452 MHz), width: 20 MHz, center1: 2452 MHz
\ttxpower 20.00 dBm
"""
NMCLI = (
    " :78\\:4F\\:24\\:95\\:BF\\:DD:CANALBOX-A737:WPA2\n"
    "*:78\\:4F\\:24\\:95\\:BF\\:D9:CANALBOX-A737-2G:WPA2\n"
)
ARP = (
    "IP address       HW type     Flags       HW address            Mask     Device\n"
    "192.168.1.254    0x1         0x2         78:4f:24:95:bf:d0     *        wlp2s0\n"
    "192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        wlp2s0\n"
)


class ParserTests(unittest.TestCase):
    def test_iw_link(self):
        info = parse_iw_link(IW_LINK)
        self.assertEqual(info["ssid"], "CANALBOX-A737-2G")
        self.assertEqual(info["bssid"], "78:4f:24:95:bf:d9")
        self.assertEqual((info["frequency_mhz"], info["signal_dbm"]), (2452.0, -34.0))
        self.assertEqual((info["rx_bitrate_mbps"], info["tx_bitrate_mbps"]), (144.4, 11.0))
        self.assertEqual(info["standard"], "Wi-Fi 4 (802.11n)")
        self.assertEqual(parse_iw_link("Not connected."), {"connected": False})
        self.assertEqual(parse_iw_link("rx bitrate: 1200.9 MBit/s 80MHz HE-MCS 11")["standard"], "Wi-Fi 6 (802.11ax)")

    def test_iw_info_nmcli_and_dns(self):
        self.assertEqual(parse_iw_info(IW_INFO), {"channel_width_mhz": 20.0, "tx_power_dbm": 20.0, "mode": "managed"})
        self.assertEqual(parse_nmcli_wifi(NMCLI), {"bssid": "78:4f:24:95:bf:d9", "ssid": "CANALBOX-A737-2G", "security": "WPA2"})
        self.assertEqual(parse_nmcli_wifi("*:AA\\:BB\\:CC\\:DD\\:EE\\:FF:Cafe:\n")["security"], "Ouvert")
        self.assertEqual(parse_resolvectl("Link 3 (wlp2s0): 192.168.1.254 fe80::1\n"), ["192.168.1.254", "fe80::1"])
        self.assertEqual(parse_resolv_conf("# x\nnameserver 1.1.1.1\nnameserver 9.9.9.9\n"), ["1.1.1.1", "9.9.9.9"])

    def test_arp_lookup_skips_incomplete_entries(self):
        self.assertEqual(arp_lookup("192.168.1.254", ARP), "78:4f:24:95:bf:d0")
        self.assertIsNone(arp_lookup("192.168.1.50", ARP))
        self.assertIsNone(arp_lookup("10.0.0.1", ARP))

    def test_channels_and_signal(self):
        self.assertEqual(channel_from_frequency(2452), (9, "2.4 GHz"))
        self.assertEqual(channel_from_frequency(2484), (14, "2.4 GHz"))
        self.assertEqual(channel_from_frequency(5180), (36, "5 GHz"))
        self.assertEqual(channel_from_frequency(5975), (5, "6 GHz"))
        self.assertEqual(signal_quality(-34), (93, "Excellent"))
        self.assertEqual(signal_quality(-30), (100, "Excellent"))
        self.assertEqual(signal_quality(-65), (42, "Moyen"))
        self.assertEqual(signal_quality(-95), (0, "Faible"))

    def test_ipv4_and_ipv6_details(self):
        info = ipv4_details("192.168.1.99", "255.255.255.0")
        self.assertEqual((info["network"], info["broadcast"], info["usable_hosts"]), ("192.168.1.0/24", "192.168.1.255", 254))
        self.assertEqual(info["host_range"], "192.168.1.1 - 192.168.1.254")
        self.assertTrue(info["private"])
        self.assertEqual(ipv4_details("10.0.0.1", "255.255.255.255")["usable_hosts"], 1)
        scopes = ipv6_details(
            [
                {"addr": "fe80::1%wlp2s0", "netmask": "ffff:ffff:ffff:ffff::/64"},
                {"addr": "2c0f:ecf0:817:2b00::9", "netmask": "ffff:ffff:ffff:ffff::/64"},
                {"addr": "fd00::5", "netmask": "ffff:ffff:ffff:ffff::/64"},
            ]
        )
        self.assertEqual([entry["scope"] for entry in scopes], ["lien local", "globale", "unique locale"])
        self.assertEqual(scopes[0], {"address": "fe80::1", "prefix": 64, "scope": "lien local"})


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.sysdir = root / "net" / "wlp2s0"
        (self.sysdir / "statistics").mkdir(parents=True)
        (self.sysdir / "wireless").mkdir()
        (self.sysdir / "address").write_text("58:A0:23:A0:8A:57\n")
        (self.sysdir / "mtu").write_text("1500\n")
        (self.sysdir / "operstate").write_text("up\n")
        self.set_counters(1000, 500)
        for name in ("rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"):
            (self.sysdir / "statistics" / name).write_text("0\n")
        (root / "arp").write_text(ARP)
        outputs = {"link": IW_LINK, "info": IW_INFO, "nmcli": NMCLI, "resolvectl": "Link 3 (wlp2s0): 192.168.1.254\n"}

        def runner(args):
            if args[0] == "iw":
                return outputs[args[3]]
            return outputs.get(args[0])

        oui = mock.Mock(lookup=lambda mac: "Vendor" if mac else None)
        self.collector = NetworkInfo(oui=oui, runner=runner, sys_root=str(root / "net"), proc_arp=str(root / "arp"))
        patcher = mock.patch.object(linkinfo, "INITIAL_SAMPLE_DELAY", 0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def set_counters(self, rx, tx):
        (self.sysdir / "statistics" / "rx_bytes").write_text(f"{rx}\n")
        (self.sysdir / "statistics" / "tx_bytes").write_text(f"{tx}\n")

    def collect(self):
        with mock.patch.object(linkinfo.netifaces, "ifaddresses", return_value={2: [{"addr": "192.168.1.99", "netmask": "255.255.255.0"}]}), mock.patch.object(
            linkinfo.netifaces, "interfaces", return_value=["wlp2s0"]
        ):
            return self.collector.collect("wlp2s0", "192.168.1.254")

    def test_full_wifi_report(self):
        info = self.collect()
        self.assertEqual(info["interface"], {"name": "wlp2s0", "type": "wifi", "mac": "58:a0:23:a0:8a:57", "mtu": 1500, "state": "up", "vendor": "Vendor"})
        self.assertEqual(info["ipv4"]["network"], "192.168.1.0/24")
        self.assertEqual(info["gateway"], {"ip": "192.168.1.254", "mac": "78:4f:24:95:bf:d0", "vendor": "Vendor"})
        self.assertEqual(info["dns"], ["192.168.1.254"])
        wifi = info["wifi"]
        self.assertEqual((wifi["ssid"], wifi["channel"], wifi["band"], wifi["security"]), ("CANALBOX-A737-2G", 9, "2.4 GHz", "WPA2"))
        self.assertEqual(wifi["channel_width_mhz"], 20.0)
        self.assertEqual(info["traffic"]["link_capacity_mbps"], 144.4)
        self.assertIsNone(info["ethernet"])

    def test_throughput_from_counter_deltas(self):
        self.collect()
        self.set_counters(1000 + 1_000_000, 500 + 250_000)
        with mock.patch.object(linkinfo.time, "monotonic", side_effect=[1e9, 1e9]):
            self.collector._previous["wlp2s0"] = (1e9 - 2.0, self.collector._previous["wlp2s0"][1])
            traffic = self.collect()["traffic"]
        self.assertAlmostEqual(traffic["download_bps"], 500_000)
        self.assertAlmostEqual(traffic["upload_bps"], 125_000)
        self.assertAlmostEqual(traffic["utilization_percent"], round(625_000 * 8 / 144.4e6 * 100, 2))

    def test_ethernet_and_missing_interface(self):
        (self.sysdir / "wireless").rmdir()
        (self.sysdir / "speed").write_text("1000\n")
        (self.sysdir / "duplex").write_text("full\n")
        info = self.collect()
        self.assertEqual(info["interface"]["type"], "ethernet")
        self.assertEqual(info["ethernet"], {"speed_mbps": 1000, "duplex": "full"})
        self.assertEqual(info["traffic"]["link_capacity_mbps"], 1000)
        self.assertFalse(self.collector.collect(None)["connected"])


if __name__ == "__main__":
    unittest.main()
