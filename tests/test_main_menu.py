import threading
import unittest
from unittest import mock

import evillimiter.console.shell  # noqa: F401 - resolve circular import first
from evillimiter.menus.main_menu import MainMenu
from evillimiter.networking.host import Host
from evillimiter.networking.limit import Direction, LimitApplyError, NetemRequiresLimitError
from evillimiter.networking.utils import BitRate


def _mock_menu(hosts):
    """
    Builds a Mock standing in for `self` with just what
    _limit_handler/_block_handler touch, so the handler can be
    called unbound without spinning up the full curses menu.
    """
    menu = mock.Mock()
    menu._get_hosts_by_ids.return_value = hosts
    menu._parse_direction_args.return_value = Direction.BOTH
    # pure (ignore menu state) - delegate to the real implementation so
    # limit-handler tests still exercise real rate parsing/formatting
    menu._parse_rate_args.side_effect = lambda rate_string, direction: MainMenu._parse_rate_args(menu, rate_string, direction)
    menu._pretty_rate.side_effect = lambda rate: MainMenu._pretty_rate(menu, rate)
    return menu


class BlockHandlerWatchesHostTest(unittest.TestCase):
    def test_block_auto_watches_host_so_reconnects_stay_blocked(self):
        host = Host('192.168.1.3', 'aa:bb:cc:dd:ee:ff', '')
        host.spoofed = False
        menu = _mock_menu([host])
        args = mock.Mock(id='0')

        MainMenu._block_handler(menu, args)

        menu.host_watcher.add.assert_called_once_with(host)
        menu.arp_spoofer.add.assert_called_once_with(host)
        menu.ndp_spoofer.add.assert_called_once_with(host)
        menu.limiter.block.assert_called_once_with(host, Direction.BOTH)

    def test_block_skips_redundant_arp_spoof_add_when_already_spoofed(self):
        host = Host('192.168.1.3', 'aa:bb:cc:dd:ee:ff', '')
        host.spoofed = True
        menu = _mock_menu([host])
        args = mock.Mock(id='0')

        MainMenu._block_handler(menu, args)

        menu.arp_spoofer.add.assert_not_called()
        # ndp spoof / watch are unconditional (idempotent set-add), so still applied
        menu.ndp_spoofer.add.assert_called_once_with(host)
        menu.host_watcher.add.assert_called_once_with(host)


class LimitHandlerWatchesHostTest(unittest.TestCase):
    def test_limit_auto_watches_host_so_reconnects_stay_limited(self):
        host = Host('192.168.1.3', 'aa:bb:cc:dd:ee:ff', '')
        menu = _mock_menu([host])
        args = mock.Mock(id='0', rate='1mbit')

        MainMenu._limit_handler(menu, args)

        menu.host_watcher.add.assert_called_once_with(host)
        menu.arp_spoofer.add.assert_called_once_with(host)
        menu.ndp_spoofer.add.assert_called_once_with(host)


class LimitHandlerDiagnosticsTest(unittest.TestCase):
    """
    limit()/block() now raise LimitApplyError when a tc/iptables step
    fails - the handler must report that specifically instead of
    claiming success, but must still track the host exactly as before
    (bandwidth_monitor.add() is unconditional either way).
    """
    def test_reports_error_instead_of_ok_on_partial_failure(self):
        host = Host('192.168.1.3', 'aa:bb:cc:dd:ee:ff', '')
        menu = _mock_menu([host])
        menu.limiter.limit.side_effect = LimitApplyError(['tc class (upload)'], Direction.BOTH)
        args = mock.Mock(id='0', rate='1mbit')

        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            MainMenu._limit_handler(menu, args)

        io.error.assert_called_once()
        io.ok.assert_not_called()
        self.assertIn('tc class (upload)', io.error.call_args.args[0])
        menu.bandwidth_monitor.add.assert_called_once_with(host)

    def test_reports_ok_when_limit_succeeds(self):
        host = Host('192.168.1.3', 'aa:bb:cc:dd:ee:ff', '')
        menu = _mock_menu([host])
        args = mock.Mock(id='0', rate='1mbit')

        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            MainMenu._limit_handler(menu, args)

        io.ok.assert_called_once()
        io.error.assert_not_called()


class BlockHandlerDiagnosticsTest(unittest.TestCase):
    def test_reports_error_instead_of_ok_on_partial_failure(self):
        host = Host('192.168.1.3', 'aa:bb:cc:dd:ee:ff', '')
        host.spoofed = False
        menu = _mock_menu([host])
        menu.limiter.block.side_effect = LimitApplyError(['iptables forward drop (upload)'], Direction.BOTH)
        args = mock.Mock(id='0')

        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            MainMenu._block_handler(menu, args)

        io.error.assert_called_once()
        io.ok.assert_not_called()
        self.assertIn('iptables forward drop (upload)', io.error.call_args.args[0])
        menu.bandwidth_monitor.add.assert_called_once_with(host)


class ReconnectCallbackDiagnosticsTest(unittest.TestCase):
    """
    _reconnect_callback previously printed nothing at all - a reconnect
    was only visible after the fact via `watch`'s history table.
    """
    def _mock_menu_for_reconnect(self, old_host):
        menu = mock.Mock()
        menu.hosts = [old_host]
        menu.hosts_lock = threading.Lock()
        return menu

    def test_prints_ok_on_successful_reapply(self):
        old_host = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        new_host = Host('192.168.1.9', 'aa:bb:cc:dd:ee:ff', 'phone')
        menu = self._mock_menu_for_reconnect(old_host)

        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            MainMenu._reconnect_callback(menu, old_host, new_host)

        io.ok.assert_called_once()
        io.error.assert_not_called()
        menu.limiter.replace.assert_called_once_with(old_host, new_host)

    def test_prints_error_when_reapply_partially_fails(self):
        old_host = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        new_host = Host('192.168.1.9', 'aa:bb:cc:dd:ee:ff', 'phone')
        menu = self._mock_menu_for_reconnect(old_host)
        menu.limiter.replace.side_effect = LimitApplyError(['tc class (upload)'], Direction.BOTH)

        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            MainMenu._reconnect_callback(menu, old_host, new_host)

        io.error.assert_called_once()
        io.ok.assert_not_called()
        self.assertIn('tc class (upload)', io.error.call_args.args[0])
        # unrelated bookkeeping still runs despite the reported failure
        menu.bandwidth_monitor.replace.assert_called_once_with(old_host, new_host)


class FreeHostDiagnosticsTest(unittest.TestCase):
    """
    _free_host is shared by the explicit `free` command AND automatic
    cleanup (rescan, shutdown) - it must never let a teardown failure
    propagate and skip cleanup of the other subsystems (spoofer,
    monitor, watcher) for this host or any other host in the caller's
    loop.
    """
    def test_reports_error_but_still_completes_other_cleanup(self):
        host = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        host.spoofed = True
        menu = mock.Mock()
        menu.limiter.unlimit.side_effect = LimitApplyError(['tc filter delete'], Direction.BOTH)

        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            MainMenu._free_host(menu, host)

        io.error.assert_called_once()
        self.assertIn('tc filter delete', io.error.call_args.args[0])
        menu.bandwidth_monitor.remove.assert_called_once_with(host)
        menu.host_watcher.remove.assert_called_once_with(host)


class PrettyHostStatusTest(unittest.TestCase):
    """
    bitbrute/evillimiter#63 wishlist: show details on the assigned
    bandwidth limit in the hosts table, instead of just 'Limited'.
    """
    def setUp(self):
        self.host = Host('192.168.1.3', 'aa:bb:cc:dd:ee:ff', '')
        self.menu = mock.Mock()
        # _pretty_rate is pure (ignores menu state) - use the real
        # implementation instead of stubbing a return value, so these
        # tests still catch a broken formatter
        self.menu._pretty_rate.side_effect = lambda rate: MainMenu._pretty_rate(self.menu, rate)

    def test_free_host_shows_bare_status(self):
        self.menu.limiter.info.return_value = None

        self.assertEqual(MainMenu._pretty_host_status(self.menu, self.host), self.host.pretty_status())

    def test_limited_both_directions_shows_rate_without_direction(self):
        self.host.limited = True
        self.menu.limiter.info.return_value = (BitRate(1000), Direction.BOTH, None)

        result = MainMenu._pretty_host_status(self.menu, self.host)

        self.assertIn('1kbit', result)
        self.assertNotIn('upload', result)
        self.assertNotIn('download', result)

    def test_limited_single_direction_shows_rate_and_direction(self):
        self.host.limited = True
        self.menu.limiter.info.return_value = (BitRate(1000), Direction.OUTGOING, None)

        result = MainMenu._pretty_host_status(self.menu, self.host)

        self.assertIn('1kbit upload', result)

    def test_blocked_both_directions_shows_bare_status(self):
        self.host.blocked = True
        self.menu.limiter.info.return_value = (None, Direction.BOTH, None)

        self.assertEqual(MainMenu._pretty_host_status(self.menu, self.host), self.host.pretty_status())

    def test_blocked_single_direction_shows_direction(self):
        self.host.blocked = True
        self.menu.limiter.info.return_value = (None, Direction.INCOMING, None)

        result = MainMenu._pretty_host_status(self.menu, self.host)

        self.assertIn('download', result)

    def test_limited_with_netem_appends_bracketed_detail(self):
        self.host.limited = True
        self.menu.limiter.info.return_value = (BitRate(1000), Direction.BOTH, {'delay': 100, 'loss': 5})
        self.menu._pretty_netem.side_effect = lambda netem: MainMenu._pretty_netem(self.menu, netem)

        result = MainMenu._pretty_host_status(self.menu, self.host)

        self.assertIn('1kbit', result)
        self.assertIn('[delay 100ms, loss 5%]', result)


class ScanHandlerIntensityTest(unittest.TestCase):
    """
    bitbrute/evillimiter#63 wishlist: custom scan speed/intensity for
    quick or intensive scans. Requested but never shipped upstream.
    """
    def setUp(self):
        self.menu = mock.Mock()
        self.menu.hosts_lock = threading.Lock()
        self.menu.hosts = []
        self.menu.host_scanner.scan.return_value = []

    def test_valid_intensity_sets_scanner_intensity(self):
        self.menu._parse_scan_intensity.return_value = 3
        args = mock.Mock(iprange=None, intensity='3')

        MainMenu._scan_handler(self.menu, args)

        self.menu.host_scanner.set_intensity.assert_called_once_with(3)

    def test_invalid_intensity_aborts_before_scanning(self):
        self.menu._parse_scan_intensity.return_value = None
        args = mock.Mock(iprange=None, intensity='9')

        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            MainMenu._scan_handler(self.menu, args)

        io.error.assert_called_once()
        self.menu.host_scanner.set_intensity.assert_not_called()
        self.menu.host_scanner.scan.assert_not_called()

    def test_omitted_intensity_leaves_scanner_setting_untouched(self):
        # sticky by design: also drives watch's background reconnect
        # sweeps, which share this same scanner instance
        args = mock.Mock(iprange=None, intensity=None)

        MainMenu._scan_handler(self.menu, args)

        self.menu.host_scanner.set_intensity.assert_not_called()


class ParseScanIntensityTest(unittest.TestCase):
    def test_accepts_1_2_3(self):
        for value in ('1', '2', '3'):
            self.assertEqual(MainMenu._parse_scan_intensity(mock.Mock(), value), int(value))

    def test_rejects_out_of_range_or_non_numeric(self):
        for value in ('0', '4', 'quick', ''):
            self.assertIsNone(MainMenu._parse_scan_intensity(mock.Mock(), value))


class ParseRateArgsTest(unittest.TestCase):
    """
    bitbrute/evillimiter#63 wishlist comment (andrewprivate): set
    different upload/download rates on the same device in one call.
    """
    def test_single_rate_returns_bitrate(self):
        rate = MainMenu._parse_rate_args(mock.Mock(), '200kbit', Direction.BOTH)
        self.assertIsInstance(rate, BitRate)
        self.assertEqual(rate.rate, 200000)

    def test_single_rate_valid_for_a_single_direction_too(self):
        rate = MainMenu._parse_rate_args(mock.Mock(), '200kbit', Direction.OUTGOING)
        self.assertIsInstance(rate, BitRate)
        self.assertEqual(rate.rate, 200000)

    def test_invalid_single_rate_reports_error_and_returns_none(self):
        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            rate = MainMenu._parse_rate_args(mock.Mock(), 'notarate', Direction.BOTH)

        self.assertIsNone(rate)
        io.error.assert_called_once()

    def test_compound_rate_with_both_directions_returns_tuple(self):
        rate = MainMenu._parse_rate_args(mock.Mock(), '200kbit/1mbit', Direction.BOTH)
        self.assertEqual((rate[0].rate, rate[1].rate), (200000, 1000000))

    def test_compound_rate_with_single_direction_is_rejected(self):
        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            rate = MainMenu._parse_rate_args(mock.Mock(), '200kbit/1mbit', Direction.OUTGOING)

        self.assertIsNone(rate)
        io.error.assert_called_once()

    def test_compound_rate_with_wrong_part_count_is_rejected(self):
        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            rate = MainMenu._parse_rate_args(mock.Mock(), '200kbit/1mbit/1gbit', Direction.BOTH)

        self.assertIsNone(rate)
        io.error.assert_called_once()

    def test_compound_rate_with_invalid_segment_is_rejected(self):
        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            rate = MainMenu._parse_rate_args(mock.Mock(), '200kbit/notarate', Direction.BOTH)

        self.assertIsNone(rate)
        io.error.assert_called_once()


class PrettyRateTest(unittest.TestCase):
    def test_single_rate_formats_plainly(self):
        self.assertEqual(MainMenu._pretty_rate(mock.Mock(), BitRate.from_rate_string('200kbit')), '200kbit')

    def test_tuple_rate_formats_with_arrows(self):
        rate = (BitRate.from_rate_string('200kbit'), BitRate.from_rate_string('1mbit'))
        self.assertEqual(MainMenu._pretty_rate(mock.Mock(), rate), '200kbit↑ 1mbit↓')


class LimitHandlerIndependentRateTest(unittest.TestCase):
    def test_compound_rate_applies_tuple_to_limiter(self):
        host = Host('192.168.1.3', 'aa:bb:cc:dd:ee:ff', '')
        menu = _mock_menu([host])
        args = mock.Mock(id='0', rate='200kbit/1mbit')

        MainMenu._limit_handler(menu, args)

        called_host, called_direction, called_rate = menu.limiter.limit.call_args.args
        self.assertEqual(called_host, host)
        self.assertEqual(called_direction, Direction.BOTH)
        self.assertEqual((called_rate[0].rate, called_rate[1].rate), (200000, 1000000))

    def test_invalid_compound_rate_aborts_before_touching_any_host(self):
        host = Host('192.168.1.3', 'aa:bb:cc:dd:ee:ff', '')
        menu = _mock_menu([host])
        args = mock.Mock(id='0', rate='200kbit/notarate')

        with mock.patch('evillimiter.menus.main_menu.IO'):
            MainMenu._limit_handler(menu, args)

        menu.limiter.limit.assert_not_called()
        menu.arp_spoofer.add.assert_not_called()


class ParseNetemArgsTest(unittest.TestCase):
    def test_neither_flag_given_returns_none_pair(self):
        args = mock.Mock(delay=None, loss=None)
        self.assertEqual(MainMenu._parse_netem_args(mock.Mock(), args), (None, None))

    def test_valid_delay_and_loss(self):
        args = mock.Mock(delay='100', loss='5')
        self.assertEqual(MainMenu._parse_netem_args(mock.Mock(), args), (100, 5))

    def test_delay_only(self):
        args = mock.Mock(delay='250', loss=None)
        self.assertEqual(MainMenu._parse_netem_args(mock.Mock(), args), (250, None))

    def test_invalid_delay_reports_error_and_returns_none(self):
        args = mock.Mock(delay='fast', loss=None)
        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            result = MainMenu._parse_netem_args(mock.Mock(), args)

        self.assertIsNone(result)
        io.error.assert_called_once()

    def test_loss_out_of_range_reports_error_and_returns_none(self):
        args = mock.Mock(delay=None, loss='150')
        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            result = MainMenu._parse_netem_args(mock.Mock(), args)

        self.assertIsNone(result)
        io.error.assert_called_once()

    def test_loss_non_numeric_reports_error_and_returns_none(self):
        args = mock.Mock(delay=None, loss='a-lot')
        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            result = MainMenu._parse_netem_args(mock.Mock(), args)

        self.assertIsNone(result)
        io.error.assert_called_once()


class NetemHandlerTest(unittest.TestCase):
    """
    bitbrute/evillimiter#63 wishlist: emulate packet loss/delay
    (tc-netem), only on an already-limited host.
    """
    def setUp(self):
        self.host = Host('192.168.1.3', 'aa:bb:cc:dd:ee:ff', '')
        self.menu = mock.Mock()
        self.menu._get_hosts_by_ids.return_value = [self.host]
        # pure (ignores menu state) - delegate to the real implementation
        # so these tests still exercise real --delay/--loss validation
        self.menu._parse_netem_args.side_effect = lambda args: MainMenu._parse_netem_args(self.menu, args)
        self.menu._pretty_netem.side_effect = lambda netem: MainMenu._pretty_netem(self.menu, netem)

    def test_applies_parsed_delay_and_loss(self):
        args = mock.Mock(id='0', clear=False, delay='100', loss='5')

        MainMenu._netem_handler(self.menu, args)

        self.menu.limiter.set_netem.assert_called_once_with(self.host, 100, 5)

    def test_neither_delay_nor_loss_given_is_an_error_and_skips_limiter(self):
        args = mock.Mock(id='0', clear=False, delay=None, loss=None)

        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            MainMenu._netem_handler(self.menu, args)

        io.error.assert_called_once()
        self.menu.limiter.set_netem.assert_not_called()

    def test_invalid_args_aborts_before_touching_limiter(self):
        args = mock.Mock(id='0', clear=False, delay='not-a-number', loss=None)

        with mock.patch('evillimiter.menus.main_menu.IO'):
            MainMenu._netem_handler(self.menu, args)

        self.menu.limiter.set_netem.assert_not_called()

    def test_requires_limit_error_reports_error_and_continues(self):
        self.menu.limiter.set_netem.side_effect = NetemRequiresLimitError()
        args = mock.Mock(id='0', clear=False, delay='100', loss=None)

        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            MainMenu._netem_handler(self.menu, args)

        io.error.assert_called_once()

    def test_partial_apply_reports_failed_steps(self):
        self.menu.limiter.set_netem.side_effect = LimitApplyError(['tc netem (upload)'], Direction.BOTH)
        args = mock.Mock(id='0', clear=False, delay='100', loss=None)

        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            MainMenu._netem_handler(self.menu, args)

        io.error.assert_called_once()
        self.assertIn('tc netem (upload)', io.error.call_args.args[0])

    def test_clear_flag_calls_clear_netem_instead_of_set_netem(self):
        args = mock.Mock(id='0', clear=True)

        MainMenu._netem_handler(self.menu, args)

        self.menu.limiter.clear_netem.assert_called_once_with(self.host)
        self.menu.limiter.set_netem.assert_not_called()

    def test_clear_flag_partial_apply_reports_failed_steps(self):
        self.menu.limiter.clear_netem.side_effect = LimitApplyError(['tc netem delete (upload)'], Direction.BOTH)
        args = mock.Mock(id='0', clear=True)

        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            MainMenu._netem_handler(self.menu, args)

        io.error.assert_called_once()
        self.assertIn('tc netem delete (upload)', io.error.call_args.args[0])

    def test_no_hosts_resolved_is_a_noop(self):
        self.menu._get_hosts_by_ids.return_value = None
        args = mock.Mock(id='99', clear=False, delay='100', loss=None)

        MainMenu._netem_handler(self.menu, args)

        self.menu.limiter.set_netem.assert_not_called()


class MonitorHandlerTest(unittest.TestCase):
    """
    bitbrute/evillimiter#63 wishlist: monitor every host in real-time,
    instead of just the hosts that are already limited.
    """
    def setUp(self):
        self.menu = mock.Mock()
        self.host1 = Host('192.168.1.3', 'aa:bb:cc:dd:ee:ff', 'phone')
        self.host2 = Host('192.168.1.4', '11:22:33:44:55:66', 'laptop')
        self.menu.hosts = [self.host1, self.host2]
        self.menu.hosts_lock = threading.Lock()

    def test_adds_every_discovered_host_not_just_limited(self):
        self.menu.bandwidth_monitor.get.return_value = None  # nothing tracked yet -> error path, no curses
        args = mock.Mock(interval=None)

        with mock.patch('evillimiter.menus.main_menu.IO') as io:
            MainMenu._monitor_handler(self.menu, args)

        self.menu.bandwidth_monitor.add.assert_has_calls([mock.call(self.host1), mock.call(self.host2)], any_order=True)
        io.error.assert_called_once()

    def test_invalid_interval_errors_before_opening_curses(self):
        args = mock.Mock(interval='not-a-number')

        with mock.patch('evillimiter.menus.main_menu.IO') as io, \
             mock.patch('evillimiter.menus.main_menu.curses') as curses_mock:
            MainMenu._monitor_handler(self.menu, args)

        io.error.assert_called_once()
        curses_mock.wrapper.assert_not_called()


class AutoScanTest(unittest.TestCase):
    """
    Upstream wishlist (bitbrute/evillimiter#63, comment by MR-Diamond):
    auto-run `scan` then `hosts` at startup, opt-in via config.
    """
    def test_runs_scan_then_hosts_through_the_parser(self):
        # goes through self.parser (not the handlers directly) so it
        # behaves exactly like a typed command, defaults included
        menu = mock.Mock()

        MainMenu._auto_scan(menu)

        menu.parser.parse.assert_has_calls([mock.call(['scan']), mock.call(['hosts'])])


if __name__ == '__main__':
    unittest.main()
