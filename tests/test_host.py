import unittest

# console.shell and console.io have a circular import that only resolves when
# shell is loaded first (as the app's globals module does at startup). Import it
# up front so importing host below does not hit the partially-initialised module.
import evillimiter.console.shell  # noqa: F401
from evillimiter.networking.host import Host
from evillimiter.networking.limit import Direction


class HostEqualityTest(unittest.TestCase):
    """
    Identity is MAC-only: a device is the "same host" regardless of
    which IP it currently holds, and two different devices are never
    the same host even if one briefly reuses the other's old IP.
    __eq__ and __hash__ must agree on this (Python's data model
    requires equal objects to hash equally), so both key off mac.
    """
    def test_equal_when_same_mac_different_ip(self):
        a = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        b = Host('192.168.1.9', 'aa:bb:cc:dd:ee:ff', 'b')
        self.assertEqual(a, b)

    def test_not_equal_when_different_mac(self):
        a = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        b = Host('192.168.1.2', '11:22:33:44:55:66', 'a')
        self.assertNotEqual(a, b)

    def test_hash_matches_eq_same_mac_different_ip(self):
        a = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        b = Host('192.168.1.9', 'aa:bb:cc:dd:ee:ff', 'other')
        self.assertEqual(hash(a), hash(b))

    def test_hash_differs_for_different_mac(self):
        a = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        b = Host('192.168.1.2', '11:22:33:44:55:66', 'a')
        self.assertNotEqual(hash(a), hash(b))

    def test_safe_as_set_member_across_reconnect(self):
        # same physical device (mac unchanged) reconnecting with a new ip
        # must be recognized as the same set member, not a duplicate
        original = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        reconnected = Host('192.168.1.9', 'aa:bb:cc:dd:ee:ff', 'a')

        hosts = {original}
        hosts.discard(original)
        hosts.add(reconnected)

        self.assertEqual(len(hosts), 1)
        self.assertIn(reconnected, hosts)


class HostReconnectedAsTest(unittest.TestCase):
    def test_true_for_same_mac_different_ip(self):
        original = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        rescanned = Host('192.168.1.9', 'aa:bb:cc:dd:ee:ff', '')
        self.assertTrue(original.reconnected_as(rescanned))

    def test_false_for_same_mac_same_ip(self):
        # host is just still there, unchanged - not a reconnect
        original = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        rescanned = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', '')
        self.assertFalse(original.reconnected_as(rescanned))

    def test_false_for_different_mac_even_with_same_old_ip(self):
        # a MAC-randomizing device (or a different device entirely) that
        # happens to land on the old IP is not recognized as a reconnect
        original = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        different_device = Host('192.168.1.2', '11:22:33:44:55:66', '')
        self.assertFalse(original.reconnected_as(different_device))


class HostStatusTest(unittest.TestCase):
    def test_default_status_free(self):
        h = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        self.assertEqual(h.pretty_status(), 'Free')

    def test_limited_status(self):
        h = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        h.limited = True
        self.assertIn('Limited', h.pretty_status())

    def test_blocked_status(self):
        h = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        h.blocked = True
        self.assertIn('Blocked', h.pretty_status())

    def test_limited_takes_precedence_over_blocked(self):
        h = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        h.limited = True
        h.blocked = True
        self.assertIn('Limited', h.pretty_status())

    def test_default_flags_false(self):
        h = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        self.assertFalse(h.spoofed)
        self.assertFalse(h.limited)
        self.assertFalse(h.blocked)
        self.assertFalse(h.watched)


class DirectionTest(unittest.TestCase):
    def test_flag_values(self):
        self.assertEqual(Direction.OUTGOING | Direction.INCOMING, Direction.BOTH)

    def test_pretty_direction(self):
        self.assertEqual(Direction.pretty_direction(Direction.OUTGOING), 'upload')
        self.assertEqual(Direction.pretty_direction(Direction.INCOMING), 'download')
        self.assertEqual(Direction.pretty_direction(Direction.BOTH), 'upload / download')
        self.assertEqual(Direction.pretty_direction(Direction.NONE), '-')


class MacRandomizedTest(unittest.TestCase):
    def test_locally_administered_mac_flagged(self):
        self.assertTrue(Host('192.168.1.5', '02:11:22:33:44:55', '').mac_is_randomized)

    def test_oui_mac_not_flagged(self):
        self.assertFalse(Host('192.168.1.5', '1c:fc:bc:2d:a6:37', '').mac_is_randomized)


if __name__ == '__main__':
    unittest.main()
