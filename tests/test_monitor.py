import unittest

import evillimiter.console.shell  # noqa: F401 - resolve circular import first
from evillimiter.networking.host import Host
from evillimiter.networking.monitor import BandwidthMonitor


class BandwidthMonitorReplaceTest(unittest.TestCase):
    """
    old_host and new_host share a MAC (that's what a reconnect is) and
    are therefore == under Host's MAC-based identity. replace() must
    still carry the tracked result over to new_host, not lose it - a
    naive `dict[new] = dict[old]; del dict[old]` silently deletes the
    entry it just wrote, since both keys refer to the same slot.
    """
    def test_replace_carries_result_to_new_host(self):
        monitor = BandwidthMonitor('eth0', 1)
        old_host = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        new_host = Host('192.168.1.9', 'aa:bb:cc:dd:ee:ff', 'phone')

        monitor.add(old_host)
        result_before = monitor._host_result_dict[old_host]

        monitor.replace(old_host, new_host)

        self.assertEqual(len(monitor._host_result_dict), 1)
        self.assertIs(monitor._host_result_dict[new_host], result_before)

    def test_replace_is_noop_when_old_host_untracked(self):
        monitor = BandwidthMonitor('eth0', 1)
        old_host = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        new_host = Host('192.168.1.9', 'aa:bb:cc:dd:ee:ff', 'phone')

        monitor.replace(old_host, new_host)

        self.assertEqual(monitor._host_result_dict, {})



class BandwidthMonitorGetTest(unittest.TestCase):
    def test_get_survives_zero_elapsed_time(self):
        import time
        monitor = BandwidthMonitor('eth0', 1)
        host = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        monitor.add(host)
        # force non-positive elapsed time (last_now in the future),
        # exercising the <= 0 guard
        monitor._host_result_dict[host]['last_now'] = time.time() + 1
        # must not raise ZeroDivisionError
        self.assertIsNotNone(monitor.get(host))


if __name__ == '__main__':
    unittest.main()
