import time
import unittest
from unittest import mock

from evillimiter.networking.host import Host
from evillimiter.networking.watch import HostWatcher


class AbsentHostsTest(unittest.TestCase):
    """
    HostWatcher surfaces which watched hosts went unanswered in the
    most recent scan sweep, using the `absent` set scan_for_reconnects
    already populates for free - no second sweep, no new subsystem.
    """
    def _watcher_with_scan_result(self, reconnected, absent_to_populate):
        scanner = mock.Mock()

        def fake_scan_for_reconnects(hosts, iprange, absent=None):
            if absent is not None:
                absent.update(absent_to_populate)
            return reconnected

        scanner.scan_for_reconnects.side_effect = fake_scan_for_reconnects
        return HostWatcher(scanner, reconnection_callback=mock.Mock())

    def _run_one_cycle(self, watcher):
        # _watch() loops on self._running and sleeps between cycles;
        # run its body directly rather than racing a background thread
        watcher._running = True

        def stop_after_one_sleep(_):
            watcher._running = False

        with mock.patch('evillimiter.networking.watch.time.sleep', side_effect=stop_after_one_sleep):
            watcher._watch()

    def test_absent_hosts_reflects_latest_sweep(self):
        online = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        offline = Host('192.168.1.6', '11:22:33:44:55:66', 'laptop')

        watcher = self._watcher_with_scan_result(reconnected={}, absent_to_populate={offline})
        watcher.add(online)
        watcher.add(offline)

        self._run_one_cycle(watcher)

        self.assertEqual(watcher.absent_hosts, {offline})

    def test_removing_a_host_clears_its_absent_flag(self):
        offline = Host('192.168.1.6', '11:22:33:44:55:66', 'laptop')

        watcher = self._watcher_with_scan_result(reconnected={}, absent_to_populate={offline})
        watcher.add(offline)
        self._run_one_cycle(watcher)
        self.assertEqual(watcher.absent_hosts, {offline})

        watcher.remove(offline)

        self.assertEqual(watcher.absent_hosts, set())

    def test_no_watched_hosts_never_calls_scanner(self):
        watcher = self._watcher_with_scan_result(reconnected={}, absent_to_populate=set())
        self._run_one_cycle(watcher)

        watcher._scanner.scan_for_reconnects.assert_not_called()
        self.assertEqual(watcher.absent_hosts, set())


if __name__ == '__main__':
    unittest.main()
