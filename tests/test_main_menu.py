import unittest
from unittest import mock

import evillimiter.console.shell  # noqa: F401 - resolve circular import first
from evillimiter.menus.main_menu import MainMenu
from evillimiter.networking.host import Host
from evillimiter.networking.limit import Direction


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


if __name__ == '__main__':
    unittest.main()
