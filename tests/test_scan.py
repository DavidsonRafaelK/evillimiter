import unittest
from unittest import mock

import evillimiter.console.shell  # noqa: F401 - resolve circular import first
from evillimiter.networking.scan import HostScanner, ScanIntensity
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


class ScanForReconnectsTest(unittest.TestCase):
    def _scanner_returning(self, scanned_hosts):
        scanner = HostScanner('eth0', [])
        scanner._sweep = mock.Mock(side_effect=scanned_hosts + [None] * 1000)
        return scanner

    def test_same_mac_new_ip_is_a_reconnect(self):
        tracked = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        rescanned = Host('192.168.1.9', 'aa:bb:cc:dd:ee:ff', '')

        scanner = self._scanner_returning([rescanned])
        reconnected = scanner.scan_for_reconnects([tracked], iprange=['192.168.1.9'])

        self.assertEqual(reconnected, {tracked: rescanned})
        self.assertEqual(rescanned.name, 'phone')  # name carried over

    def test_same_mac_same_ip_is_not_reconnect(self):
        tracked = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        rescanned = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', '')

        scanner = self._scanner_returning([rescanned])
        reconnected = scanner.scan_for_reconnects([tracked], iprange=['192.168.1.5'])

        self.assertEqual(reconnected, {})

    def test_different_mac_same_ip_is_not_reconnect(self):
        # a MAC-randomizing device landing on the old IP must not be
        # mistaken for the tracked host reconnecting
        tracked = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        unrelated = Host('192.168.1.5', '11:22:33:44:55:66', '')

        scanner = self._scanner_returning([unrelated])
        reconnected = scanner.scan_for_reconnects([tracked], iprange=['192.168.1.5'])

        self.assertEqual(reconnected, {})

    def test_host_temporarily_offline_does_not_crash_or_report_reconnect(self):
        tracked = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')

        scanner = self._scanner_returning([])  # nothing answers this pass
        reconnected = scanner.scan_for_reconnects([tracked], iprange=['192.168.1.5'])

        self.assertEqual(reconnected, {})

    def test_absent_param_unset_by_default_and_ignored_when_omitted(self):
        # existing callers that don't pass `absent` see no change at all
        tracked = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        rescanned = Host('192.168.1.9', 'aa:bb:cc:dd:ee:ff', '')

        scanner = self._scanner_returning([rescanned])
        reconnected = scanner.scan_for_reconnects([tracked], iprange=['192.168.1.9'])

        self.assertEqual(reconnected, {tracked: rescanned})

    def test_absent_collects_hosts_whose_mac_was_not_seen(self):
        online = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        offline = Host('192.168.1.6', '11:22:33:44:55:66', 'laptop')
        seen = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', '')  # same mac+ip as `online`

        scanner = self._scanner_returning([seen])
        absent = set()
        reconnected = scanner.scan_for_reconnects([online, offline], iprange=['192.168.1.5', '192.168.1.6'], absent=absent)

        self.assertEqual(reconnected, {})
        self.assertEqual(absent, {offline})

    def test_absent_excludes_a_host_found_via_reconnect(self):
        # a host that moved ip is present, not absent, even though it
        # isn't at its originally-tracked ip anymore
        tracked = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        rescanned = Host('192.168.1.9', 'aa:bb:cc:dd:ee:ff', '')

        scanner = self._scanner_returning([rescanned])
        absent = set()
        scanner.scan_for_reconnects([tracked], iprange=['192.168.1.9'], absent=absent)

        self.assertEqual(absent, set())


class ScanIntensityTest(unittest.TestCase):
    """
    bitbrute/evillimiter#63 wishlist: custom scan speed/intensity for
    quick or intensive scans. Requested but never shipped upstream.
    """
    def setUp(self):
        self.scanner = HostScanner('eth0', [])

    def test_defaults_to_normal_settings(self):
        self.assertEqual(self.scanner.settings, self.scanner._normal_settings)

    def test_set_intensity_quick(self):
        self.scanner.set_intensity(ScanIntensity.QUICK)
        self.assertEqual(self.scanner.settings, self.scanner._quick_settings)

    def test_set_intensity_intense(self):
        self.scanner.set_intensity(ScanIntensity.INTENSE)
        self.assertEqual(self.scanner.settings, self.scanner._intense_settings)

    def test_unknown_intensity_leaves_settings_unchanged(self):
        self.scanner.set_intensity(999)
        self.assertEqual(self.scanner.settings, self.scanner._normal_settings)

    def test_normal_settings_match_pre_intensity_defaults(self):
        # an untouched scanner must behave exactly as it did before
        # intensity existed - no default behavior change
        self.assertEqual(self.scanner.settings, HostScanner.Settings(max_workers=150, retries=1, timeout=1))

    def test_sweep_uses_current_settings_for_retry_and_timeout(self):
        self.scanner.set_intensity(ScanIntensity.INTENSE)

        with mock.patch('evillimiter.networking.scan.sr1', return_value=None) as sr1_mock:
            self.scanner._sweep('192.168.1.5')

        self.assertEqual(sr1_mock.call_args.kwargs['retry'], self.scanner._intense_settings.retries)
        self.assertEqual(sr1_mock.call_args.kwargs['timeout'], self.scanner._intense_settings.timeout)


if __name__ == '__main__':
    unittest.main()
