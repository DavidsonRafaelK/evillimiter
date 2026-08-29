import unittest
from unittest import mock

import evillimiter.console.shell  # noqa: F401 - resolve circular import first
from scapy.all import Ether, IP, UDP, BOOTP, DHCP # pylint: disable=no-name-in-module

from evillimiter.networking.dhcp_listener import DHCPHostnameListener


def _dhcp_packet(mac, hostname):
    return (
        Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') /
        IP(src='0.0.0.0', dst='255.255.255.255') /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(mac.replace(':', '')) + b'\x00' * 10) /
        DHCP(options=[('message-type', 'request'), ('hostname', hostname), 'end'])
    )


class DHCPHostnameListenerTest(unittest.TestCase):
    @mock.patch('evillimiter.networking.dhcp_listener.sniff')
    def test_records_hostname_by_mac(self, sniff):
        listener = DHCPHostnameListener('eth0')
        pkt = _dhcp_packet('aa:bb:cc:dd:ee:ff', b'MyPhone')

        def fake_sniff(**kwargs):
            kwargs['prn'](pkt)

        sniff.side_effect = fake_sniff
        listener._running = True
        listener._sniff()

        self.assertEqual(listener.get('aa:bb:cc:dd:ee:ff'), 'MyPhone')

    @mock.patch('evillimiter.networking.dhcp_listener.sniff')
    def test_lookup_is_case_insensitive(self, sniff):
        listener = DHCPHostnameListener('eth0')
        pkt = _dhcp_packet('aa:bb:cc:dd:ee:ff', b'MyPhone')

        def fake_sniff(**kwargs):
            kwargs['prn'](pkt)

        sniff.side_effect = fake_sniff
        listener._running = True
        listener._sniff()

        self.assertEqual(listener.get('AA:BB:CC:DD:EE:FF'), 'MyPhone')

    @mock.patch('evillimiter.networking.dhcp_listener.sniff')
    def test_ignores_non_dhcp_packets(self, sniff):
        listener = DHCPHostnameListener('eth0')
        pkt = Ether(src='aa:bb:cc:dd:ee:ff') / IP() / UDP()

        def fake_sniff(**kwargs):
            kwargs['prn'](pkt)

        sniff.side_effect = fake_sniff
        listener._running = True
        listener._sniff()

        self.assertIsNone(listener.get('aa:bb:cc:dd:ee:ff'))

    def test_get_returns_none_for_unknown_mac(self):
        listener = DHCPHostnameListener('eth0')
        self.assertIsNone(listener.get('aa:bb:cc:dd:ee:ff'))


if __name__ == '__main__':
    unittest.main()
