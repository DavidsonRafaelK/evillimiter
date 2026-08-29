import threading
import unittest
from unittest import mock

import evillimiter.console.shell  # noqa: F401 - resolve circular import first
from evillimiter.menus.main_menu import MainMenu
from evillimiter.networking.host import Host
from evillimiter.networking.limit import Direction, LimitApplyError


def _mock_menu(hosts):
    """
    Builds a Mock standing in for `self` with just what
    _limit_handler/_block_handler touch, so the handler can be
    called unbound without spinning up the full curses menu.
    """
    menu = mock.Mock()
    menu._get_hosts_by_ids.return_value = hosts
    menu._parse_direction_args.return_value = Direction.BOTH
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


if __name__ == '__main__':
    unittest.main()
