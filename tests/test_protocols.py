import unittest

from scapy.all import ARP, IP, TCP, UDP, Ether, Raw
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.tls.extensions import ServerName, TLS_Ext_ServerName, TLS_Ext_SupportedGroups
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS

from moniwifi import protocols
from moniwifi.oui import OuiDatabase, is_randomized


def client_hello(name: bytes) -> bytes:
    extensions = [TLS_Ext_SupportedGroups(groups=[29]), TLS_Ext_ServerName(servernames=[ServerName(servername=name)])]
    return bytes(TLS(msg=[TLSClientHello(ciphers=[0x1301], ext=extensions)]))


def rebuild(packet):
    return packet.__class__(bytes(packet))


class ProtocolParserTests(unittest.TestCase):
    def test_arp_reply(self):
        packet = rebuild(Ether(src="aa:bb:cc:dd:ee:01") / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.9", pdst="192.168.1.2"))
        info = protocols.parse_arp(packet)
        self.assertEqual((info["op"], info["sender_mac"], info["sender_ip"]), ("reply", "aa:bb:cc:dd:ee:01", "192.168.1.9"))

    def test_dhcp_request_and_ack(self):
        request = rebuild(
            Ether(src="aa:bb:cc:dd:ee:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=bytes.fromhex("aabbccddeeff"))
            / DHCP(options=[("message-type", "request"), ("hostname", b"Pixel-7"), ("vendor_class_id", b"android-dhcp-13"), ("requested_addr", "192.168.1.50"), "end"])
        )
        info = protocols.parse_dhcp(request)
        self.assertEqual(info["message_type"], "request")
        self.assertEqual(info["client_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(info["hostname"], "Pixel-7")
        self.assertEqual(info["vendor_class"], "android-dhcp-13")
        self.assertEqual(info["requested_ip"], "192.168.1.50")

        ack = rebuild(
            Ether(src="00:11:22:33:44:55")
            / IP(src="192.168.1.1", dst="192.168.1.50")
            / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr="192.168.1.50", chaddr=bytes.fromhex("aabbccddeeff"))
            / DHCP(options=[("message-type", "ack"), ("server_id", "192.168.1.1"), ("router", "192.168.1.1"), "end"])
        )
        info = protocols.parse_dhcp(ack)
        self.assertEqual((info["message_type"], info["offered_ip"], info["server_id"]), ("ack", "192.168.1.50", "192.168.1.1"))
        self.assertEqual(info["server_mac"], "00:11:22:33:44:55")

    def test_dns_query_and_response(self):
        response = rebuild(
            IP(src="8.8.8.8", dst="192.168.1.5")
            / UDP(sport=53, dport=5555)
            / DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34"))
        )
        info = protocols.parse_dns(response)
        self.assertTrue(info["is_response"])
        self.assertFalse(info["multicast"])
        unicast_from_5353 = rebuild(IP(src="192.168.1.5", dst="192.168.1.1") / UDP(sport=5353, dport=53) / DNS(qd=DNSQR(qname="a.example")))
        self.assertFalse(protocols.parse_dns(unicast_from_5353)["multicast"])
        mdns = rebuild(IP(src="192.168.1.5", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="_ipp._tcp.local")))
        self.assertTrue(protocols.parse_dns(mdns)["multicast"])
        self.assertEqual(info["queries"], [{"name": "example.com", "type": "A"}])
        self.assertEqual(info["answers"][0]["data"], "93.184.216.34")

    def test_tls_sni_and_http_host(self):
        self.assertEqual(protocols.extract_sni(client_hello(b"WWW.Example.org")), "www.example.org")
        self.assertIsNone(protocols.extract_sni(b"\x16\x03\x01garbage"))
        self.assertIsNone(protocols.extract_sni(b""))
        self.assertEqual(protocols.extract_http_host(b"GET / HTTP/1.1\r\nHost: Site.test:8080\r\n\r\n"), "site.test")
        self.assertIsNone(protocols.extract_http_host(b"HTTP/1.1 200 OK\r\n"))

        packet = rebuild(IP(src="192.168.1.5", dst="1.1.1.1") / TCP(sport=40000, dport=443, flags="PA") / Raw(client_hello(b"one.one.one.one")))
        self.assertEqual(protocols.extract_server_name(packet), ("one.one.one.one", "tls"))


class OuiTests(unittest.TestCase):
    def test_lookup_from_arp_scan_and_wireshark_files(self):
        import tempfile, os

        with tempfile.TemporaryDirectory() as directory:
            arp_scan = os.path.join(directory, "ieee-oui.txt")
            with open(arp_scan, "w") as handle:
                handle.write("# comment\n001B63\tApple, Inc.\n")
            self.assertEqual(OuiDatabase([arp_scan]).lookup("00:1b:63:aa:bb:cc"), "Apple, Inc.")

            manuf = os.path.join(directory, "manuf")
            with open(manuf, "w") as handle:
                handle.write("00:1B:63\tApple\tApple, Inc.\n00:1B:C5:00:00/36\tX\tLong mask\n")
            database = OuiDatabase([os.path.join(directory, "missing"), manuf])
            self.assertEqual(database.lookup("00:1B:63:00:00:01"), "Apple, Inc.")
            self.assertIsNone(database.lookup("00:1b:c5:00:00:01"))

    def test_randomized_mac(self):
        self.assertTrue(is_randomized("da:a1:19:00:00:01"))
        self.assertFalse(is_randomized("00:1b:63:00:00:01"))
        self.assertEqual(OuiDatabase([]).lookup("da:a1:19:00:00:01"), "Randomized MAC")


if __name__ == "__main__":
    unittest.main()
