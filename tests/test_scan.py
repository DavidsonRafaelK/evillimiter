import unittest
from unittest import mock

import evillimiter.console.shell  # noqa: F401 - resolve circular import first
from evillimiter.networking.scan import HostScanner
from evillimiter.networking.host import Host


class ScanHostnameResolutionTest(unittest.TestCase):
    @mock.patch('evillimiter.networking.scan.utils.get_hostname')
    def test_prefers_dhcp_listener_name_over_resolution(self, get_hostname):
        get_hostname.return_value = 'fallback-name'

        dhcp_listener = mock.Mock()
        dhcp_listener.get.return_value = 'DHCP-Name'

        scanner = HostScanner('eth0', [], dhcp_listener)
        with mock.patch.object(scanner, '_sweep', return_value=Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', '')):
            hosts = scanner.scan(iprange=['192.168.1.5'])

        self.assertEqual(hosts[0].name, 'DHCP-Name')
        get_hostname.assert_not_called()

    @mock.patch('evillimiter.networking.scan.utils.get_hostname')
    def test_falls_back_to_resolution_when_dhcp_listener_has_no_match(self, get_hostname):
        get_hostname.return_value = 'fallback-name'

        dhcp_listener = mock.Mock()
        dhcp_listener.get.return_value = None

        scanner = HostScanner('eth0', [], dhcp_listener)
        with mock.patch.object(scanner, '_sweep', return_value=Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', '')):
            hosts = scanner.scan(iprange=['192.168.1.5'])

        self.assertEqual(hosts[0].name, 'fallback-name')

    @mock.patch('evillimiter.networking.scan.utils.get_hostname')
    def test_works_without_dhcp_listener(self, get_hostname):
        get_hostname.return_value = 'fallback-name'

        scanner = HostScanner('eth0', [])
        with mock.patch.object(scanner, '_sweep', return_value=Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', '')):
            hosts = scanner.scan(iprange=['192.168.1.5'])

        self.assertEqual(hosts[0].name, 'fallback-name')


if __name__ == '__main__':
    unittest.main()
