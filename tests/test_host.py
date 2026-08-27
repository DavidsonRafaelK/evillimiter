import unittest

# console.shell and console.io have a circular import that only resolves when
# shell is loaded first (as the app's globals module does at startup). Import it
# up front so importing host below does not hit the partially-initialised module.
import evillimiter.console.shell  # noqa: F401
from evillimiter.networking.host import Host
from evillimiter.networking.limit import Direction


class HostEqualityTest(unittest.TestCase):
    def test_equal_when_same_ip(self):
        a = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        b = Host('192.168.1.2', '11:22:33:44:55:66', 'b')
        self.assertEqual(a, b)

    def test_not_equal_when_different_ip(self):
        a = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        b = Host('192.168.1.3', 'aa:bb:cc:dd:ee:ff', 'a')
        self.assertNotEqual(a, b)

    def test_hash_uses_mac_and_ip(self):
        a = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'a')
        b = Host('192.168.1.2', 'aa:bb:cc:dd:ee:ff', 'other')
        self.assertEqual(hash(a), hash(b))


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


if __name__ == '__main__':
    unittest.main()
