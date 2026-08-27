import unittest

from evillimiter.networking.utils import (
    validate_ip_address,
    validate_mac_address,
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


if __name__ == '__main__':
    unittest.main()
