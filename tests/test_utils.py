import socket
import struct
import unittest
from unittest import mock

from evillimiter.networking.utils import (
    validate_ip_address,
    validate_mac_address,
    get_hostname,
    get_mdns_name,
    get_default_gateway_ipv6,
    get_interface_mac,
    _read_dns_name,
    ValueConverter,
    BitRate,
    ByteValue,
)


class ValidateIpAddressTest(unittest.TestCase):
    def test_accepts_dotted_quad(self):
        self.assertTrue(validate_ip_address('192.168.1.1'))
        self.assertTrue(validate_ip_address('0.0.0.0'))

    def test_rejects_incomplete_address(self):
        self.assertFalse(validate_ip_address('192.168.1'))

    def test_rejects_non_numeric(self):
        self.assertFalse(validate_ip_address('192.168.1.x'))

    def test_rejects_too_many_octets(self):
        self.assertFalse(validate_ip_address('1.2.3.4.5'))


class ValidateMacAddressTest(unittest.TestCase):
    def test_accepts_lower_and_upper_hex(self):
        self.assertTrue(validate_mac_address('1c:fc:bc:2d:a6:37'))
        self.assertTrue(validate_mac_address('AA:BB:CC:DD:EE:FF'))

    def test_rejects_short_address(self):
        self.assertFalse(validate_mac_address('1c:fc:bc:2d:a6'))

    def test_rejects_bad_separator(self):
        self.assertFalse(validate_mac_address('1c-fc-bc-2d-a6-37'))

    def test_rejects_non_hex(self):
        self.assertFalse(validate_mac_address('gg:fc:bc:2d:a6:37'))


class ValueConverterTest(unittest.TestCase):
    def test_byte_to_bit(self):
        self.assertEqual(ValueConverter.byte_to_bit(10), 80)
        self.assertEqual(ValueConverter.byte_to_bit(0), 0)


class BitRateStrTest(unittest.TestCase):
    def test_units_scale_by_1000(self):
        self.assertEqual(str(BitRate(500)), '500bit')
        self.assertEqual(str(BitRate(1000)), '1kbit')
        self.assertEqual(str(BitRate(1000 ** 2)), '1mbit')
        self.assertEqual(str(BitRate(1000 ** 3)), '1gbit')

    def test_repr_matches_str(self):
        r = BitRate(2000)
        self.assertEqual(repr(r), str(r))

    def test_exceeding_gbit_raises(self):
        with self.assertRaises(Exception):
            str(BitRate(1000 ** 4))


class BitRateMulTest(unittest.TestCase):
    def test_mul_scalar(self):
        self.assertEqual((BitRate(1000) * 3).rate, 3000)

    def test_mul_bitrate(self):
        self.assertEqual((BitRate(1000) * BitRate(2)).rate, 2000)

    def test_mul_truncates_to_int(self):
        self.assertEqual((BitRate(1000) * 1.5).rate, 1500)


class BitRateFmtTest(unittest.TestCase):
    def test_fmt_applies_to_number_only(self):
        self.assertEqual(BitRate(1000).fmt('%03d'), '001kbit')


class BitRateFromStringTest(unittest.TestCase):
    def test_parses_each_unit(self):
        self.assertEqual(BitRate.from_rate_string('500bit').rate, 500)
        self.assertEqual(BitRate.from_rate_string('2kbit').rate, 2000)
        self.assertEqual(BitRate.from_rate_string('3mbit').rate, 3 * 1000 ** 2)
        self.assertEqual(BitRate.from_rate_string('4gbit').rate, 4 * 1000 ** 3)

    def test_case_insensitive_unit(self):
        self.assertEqual(BitRate.from_rate_string('2KBIT').rate, 2000)

    def test_invalid_unit_raises(self):
        with self.assertRaises(Exception):
            BitRate.from_rate_string('5tbit')


class ByteValueStrTest(unittest.TestCase):
    def test_units_scale_by_1024(self):
        self.assertEqual(str(ByteValue(512)), '512b')
        self.assertEqual(str(ByteValue(1024)), '1kb')
        self.assertEqual(str(ByteValue(1024 ** 2)), '1mb')
        self.assertEqual(str(ByteValue(1024 ** 3)), '1gb')

    def test_terabyte_total(self):
        self.assertEqual(str(ByteValue(1024 ** 4)), '1tb')

    def test_exceeding_tb_raises(self):
        with self.assertRaises(Exception):
            str(ByteValue(1024 ** 5))


class ByteValueArithmeticTest(unittest.TestCase):
    def test_add_bytevalue(self):
        self.assertEqual(int(ByteValue(100) + ByteValue(50)), 150)

    def test_add_scalar(self):
        self.assertEqual(int(ByteValue(100) + 50), 150)

    def test_sub_bytevalue(self):
        self.assertEqual(int(ByteValue(100) - ByteValue(40)), 60)

    def test_mul_scalar(self):
        self.assertEqual(int(ByteValue(100) * 2), 200)

    def test_ge_bytevalue_and_scalar(self):
        self.assertTrue(ByteValue(100) >= ByteValue(100))
        self.assertTrue(ByteValue(100) >= 99)
        self.assertFalse(ByteValue(100) >= 101)


class ByteValueFromStringTest(unittest.TestCase):
    def test_parses_each_unit(self):
        self.assertEqual(ByteValue.from_byte_string('512b').value, 512)
        self.assertEqual(ByteValue.from_byte_string('2kb').value, 2 * 1024)
        self.assertEqual(ByteValue.from_byte_string('3mb').value, 3 * 1024 ** 2)
        self.assertEqual(ByteValue.from_byte_string('4gb').value, 4 * 1024 ** 3)
        self.assertEqual(ByteValue.from_byte_string('5tb').value, 5 * 1024 ** 4)

    def test_invalid_unit_raises(self):
        with self.assertRaises(Exception):
            ByteValue.from_byte_string('6pb')


class GetHostnameTest(unittest.TestCase):
    @mock.patch('evillimiter.networking.utils.socket.gethostbyaddr')
    def test_returns_reverse_dns_name(self, gethostbyaddr):
        gethostbyaddr.return_value = ('my-device.local', [], ['192.168.1.5'])
        self.assertEqual(get_hostname('192.168.1.5'), 'my-device.local')

    @mock.patch('evillimiter.networking.utils.get_netbios_name')
    @mock.patch('evillimiter.networking.utils.socket.gethostbyaddr')
    def test_falls_back_to_netbios_on_reverse_dns_failure(self, gethostbyaddr, netbios):
        gethostbyaddr.side_effect = socket.herror
        netbios.return_value = 'WINPC'
        self.assertEqual(get_hostname('192.168.1.5'), 'WINPC')

    @mock.patch('evillimiter.networking.utils.get_netbios_name')
    @mock.patch('evillimiter.networking.utils.socket.gethostbyaddr')
    def test_ignores_reverse_dns_result_equal_to_ip(self, gethostbyaddr, netbios):
        # some resolvers echo the queried ip back as the "hostname"
        gethostbyaddr.return_value = ('192.168.1.5', [], ['192.168.1.5'])
        netbios.return_value = 'WINPC'
        self.assertEqual(get_hostname('192.168.1.5'), 'WINPC')

    @mock.patch('evillimiter.networking.utils.get_mdns_name')
    @mock.patch('evillimiter.networking.utils.get_netbios_name')
    @mock.patch('evillimiter.networking.utils.socket.gethostbyaddr')
    def test_falls_back_to_mdns_when_netbios_fails(self, gethostbyaddr, netbios, mdns):
        gethostbyaddr.side_effect = socket.herror
        netbios.return_value = None
        mdns.return_value = 'Android.local'
        self.assertEqual(get_hostname('192.168.1.5'), 'Android.local')

    @mock.patch('evillimiter.networking.utils.get_mdns_name')
    @mock.patch('evillimiter.networking.utils.get_netbios_name')
    @mock.patch('evillimiter.networking.utils.socket.gethostbyaddr')
    def test_returns_none_when_all_fail(self, gethostbyaddr, netbios, mdns):
        gethostbyaddr.side_effect = socket.herror
        netbios.return_value = None
        mdns.return_value = None
        self.assertIsNone(get_hostname('192.168.1.5'))


class GetDefaultGatewayIpv6Test(unittest.TestCase):
    @mock.patch('evillimiter.networking.utils.netifaces.gateways')
    def test_returns_ipv6_gateway_when_present(self, gateways):
        gateways.return_value = {'default': {2: ('192.168.1.1', 'eth0'), 10: ('fe80::1', 'eth0')}}
        with mock.patch('evillimiter.networking.utils.netifaces.AF_INET6', 10):
            self.assertEqual(get_default_gateway_ipv6(), 'fe80::1')

    @mock.patch('evillimiter.networking.utils.netifaces.gateways')
    def test_returns_none_without_ipv6_route(self, gateways):
        gateways.return_value = {'default': {2: ('192.168.1.1', 'eth0')}}
        with mock.patch('evillimiter.networking.utils.netifaces.AF_INET6', 10):
            self.assertIsNone(get_default_gateway_ipv6())


class GetInterfaceMacTest(unittest.TestCase):
    @mock.patch('evillimiter.networking.utils.netifaces.ifaddresses')
    def test_returns_mac_address(self, ifaddresses):
        with mock.patch('evillimiter.networking.utils.netifaces.AF_LINK', 17):
            ifaddresses.return_value = {17: [{'addr': 'aa:bb:cc:dd:ee:ff'}]}
            self.assertEqual(get_interface_mac('eth0'), 'aa:bb:cc:dd:ee:ff')


class ReadDnsNameTest(unittest.TestCase):
    def test_parses_uncompressed_name(self):
        labels = [b'myphone', b'local']
        data = b''.join(bytes([len(l)]) + l for l in labels) + b'\x00' + b'TRAILER'
        name, offset = _read_dns_name(data, 0)
        self.assertEqual(name, 'myphone.local')
        self.assertEqual(offset, len(data) - len(b'TRAILER'))

    def test_follows_compression_pointer(self):
        # target name lives at offset 0, a pointer to it sits at offset 20
        target = b'\x07myphone\x05local\x00'
        pointer = b'\xc0\x00'
        data = target + b'\x00\x00\x00\x00\x00' + pointer + b'REST'
        pointer_offset = len(target) + 5
        name, offset = _read_dns_name(data, pointer_offset)
        self.assertEqual(name, 'myphone.local')
        # offset advances past the 2-byte pointer at the call site, not into the jump target
        self.assertEqual(offset, pointer_offset + 2)


class GetMdnsNameTest(unittest.TestCase):
    def _build_ptr_response(self, qname, hostname):
        header = struct.pack('>HHHHHH', 0, 0x8400, 1, 1, 0, 0)
        question = qname + struct.pack('>HH', 12, 1)
        ans_name = b'\xc0\x0c'  # pointer back to the question name
        rdata = b'\x07' + hostname.encode() + b'\x05local\x00'
        answer = ans_name + struct.pack('>HHIH', 12, 1, 120, len(rdata)) + rdata
        return header + question + answer

    @mock.patch('evillimiter.networking.utils.socket.socket')
    def test_parses_ptr_answer(self, socket_cls):
        qlabels = ['5', '1', '168', '192', 'in-addr', 'arpa']
        qname = b''.join(struct.pack('B', len(l)) + l.encode() for l in qlabels) + b'\x00'
        response = self._build_ptr_response(qname, 'myphone')

        sock = mock.Mock()
        sock.recvfrom.return_value = (response, ('192.168.1.5', 5353))
        socket_cls.return_value = sock

        self.assertEqual(get_mdns_name('192.168.1.5'), 'myphone.local')
        sock.sendto.assert_called_once()
        self.assertEqual(sock.sendto.call_args[0][1], ('192.168.1.5', 5353))

    @mock.patch('evillimiter.networking.utils.socket.socket')
    def test_returns_none_on_timeout(self, socket_cls):
        sock = mock.Mock()
        sock.recvfrom.side_effect = socket.timeout
        socket_cls.return_value = sock

        self.assertIsNone(get_mdns_name('192.168.1.5'))


if __name__ == '__main__':
    unittest.main()
