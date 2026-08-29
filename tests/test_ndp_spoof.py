import unittest
from unittest import mock

import evillimiter.console.shell  # noqa: F401 - resolve circular import first
from scapy.all import Ether, IPv6, ICMPv6ND_NS # pylint: disable=no-name-in-module

from evillimiter.networking.host import Host
from evillimiter.networking.ndp_spoof import NDPSpoofer


class NDPSpooferTest(unittest.TestCase):
    @mock.patch('evillimiter.networking.ndp_spoof.utils.get_interface_mac')
    def test_noop_when_no_ipv6_gateway(self, get_mac):
        get_mac.return_value = 'aa:aa:aa:aa:aa:aa'
        spoofer = NDPSpoofer('eth0', None)
        spoofer.start()
        self.assertFalse(spoofer._running)

    @mock.patch('evillimiter.networking.ndp_spoof.sendp')
    @mock.patch('evillimiter.networking.ndp_spoof.utils.get_interface_mac')
    def test_periodic_blast_claims_gateway_to_each_host(self, get_mac, sendp):
        get_mac.return_value = 'aa:aa:aa:aa:aa:aa'
        spoofer = NDPSpoofer('eth0', 'fe80::1')

        spoofer._send_unsolicited_na('bb:bb:bb:bb:bb:bb')

        sendp.assert_called_once()
        packet = sendp.call_args[0][0]
        self.assertEqual(packet.dst, 'bb:bb:bb:bb:bb:bb')             # Ether dst = victim
        self.assertEqual(packet['IPv6'].dst, 'ff02::1')
        self.assertEqual(packet['ICMPv6ND_NA'].tgt, 'fe80::1')        # claims to be the gateway
        self.assertEqual(packet['ICMPv6ND_NA'].S, 0)                  # unsolicited
        self.assertEqual(packet['ICMPv6NDOptDstLLAddr'].lladdr, 'aa:aa:aa:aa:aa:aa')  # ...at our mac
        self.assertEqual(sendp.call_args[1]['iface'], 'eth0')

    @mock.patch('evillimiter.networking.ndp_spoof.sendp')
    @mock.patch('evillimiter.networking.ndp_spoof.utils.get_interface_mac')
    def test_solicited_reply_answers_host_ns_directly(self, get_mac, sendp):
        get_mac.return_value = 'aa:aa:aa:aa:aa:aa'
        spoofer = NDPSpoofer('eth0', 'fe80::1')

        spoofer._send_solicited_na('bb:bb:bb:bb:bb:bb', 'fe80::5')

        sendp.assert_called_once()
        packet = sendp.call_args[0][0]
        self.assertEqual(packet.dst, 'bb:bb:bb:bb:bb:bb')
        self.assertEqual(packet['IPv6'].dst, 'fe80::5')                # unicast straight back
        self.assertEqual(packet['ICMPv6ND_NA'].tgt, 'fe80::1')
        self.assertEqual(packet['ICMPv6ND_NA'].S, 1)                   # solicited - answers a probe

    @mock.patch('evillimiter.networking.ndp_spoof.utils.get_interface_mac')
    def test_add_remove_tracks_hosts(self, get_mac):
        get_mac.return_value = 'aa:aa:aa:aa:aa:aa'
        spoofer = NDPSpoofer('eth0', 'fe80::1')
        host = Host('192.168.1.5', 'bb:bb:bb:bb:bb:bb', '')

        spoofer.add(host)
        self.assertIn(host, spoofer._hosts)

        spoofer.remove(host)
        self.assertNotIn(host, spoofer._hosts)


class NDPSpooferListenTest(unittest.TestCase):
    def _ns_packet(self, src_mac, src_ip6, tgt):
        return Ether(src=src_mac) / IPv6(src=src_ip6, dst='ff02::1') / ICMPv6ND_NS(tgt=tgt)

    @mock.patch('evillimiter.networking.ndp_spoof.sniff')
    @mock.patch('evillimiter.networking.ndp_spoof.utils.get_interface_mac')
    def test_answers_tracked_host_probing_for_gateway(self, get_mac, sniff):
        get_mac.return_value = 'aa:aa:aa:aa:aa:aa'
        spoofer = NDPSpoofer('eth0', 'fe80::1')
        spoofer.add(Host('192.168.1.5', 'bb:bb:bb:bb:bb:bb', ''))

        pkt = self._ns_packet('bb:bb:bb:bb:bb:bb', 'fe80::5', 'fe80::1')

        def fake_sniff(**kwargs):
            kwargs['prn'](pkt)

        sniff.side_effect = fake_sniff

        with mock.patch.object(spoofer, '_send_solicited_na') as reply:
            spoofer._running = True
            spoofer._listen()

        reply.assert_called_once_with('bb:bb:bb:bb:bb:bb', 'fe80::5')

    @mock.patch('evillimiter.networking.ndp_spoof.sniff')
    @mock.patch('evillimiter.networking.ndp_spoof.utils.get_interface_mac')
    def test_ignores_untracked_host(self, get_mac, sniff):
        get_mac.return_value = 'aa:aa:aa:aa:aa:aa'
        spoofer = NDPSpoofer('eth0', 'fe80::1')
        # no hosts added

        pkt = self._ns_packet('bb:bb:bb:bb:bb:bb', 'fe80::5', 'fe80::1')

        def fake_sniff(**kwargs):
            kwargs['prn'](pkt)

        sniff.side_effect = fake_sniff

        with mock.patch.object(spoofer, '_send_solicited_na') as reply:
            spoofer._running = True
            spoofer._listen()

        reply.assert_not_called()

    @mock.patch('evillimiter.networking.ndp_spoof.sniff')
    @mock.patch('evillimiter.networking.ndp_spoof.utils.get_interface_mac')
    def test_ignores_solicitation_for_other_targets(self, get_mac, sniff):
        get_mac.return_value = 'aa:aa:aa:aa:aa:aa'
        spoofer = NDPSpoofer('eth0', 'fe80::1')
        spoofer.add(Host('192.168.1.5', 'bb:bb:bb:bb:bb:bb', ''))

        # host is resolving some other node, not the gateway
        pkt = self._ns_packet('bb:bb:bb:bb:bb:bb', 'fe80::5', 'fe80::99')

        def fake_sniff(**kwargs):
            kwargs['prn'](pkt)

        sniff.side_effect = fake_sniff

        with mock.patch.object(spoofer, '_send_solicited_na') as reply:
            spoofer._running = True
            spoofer._listen()

        reply.assert_not_called()


if __name__ == '__main__':
    unittest.main()
