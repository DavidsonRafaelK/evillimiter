import unittest
from unittest import mock

# console.shell and console.io have a circular import that only resolves when
# shell is loaded first (as the app's globals module does at startup).
import evillimiter.console.shell  # noqa: F401
from evillimiter.networking.host import Host
from evillimiter.networking.limit import Limiter, Direction


def _capture_commands(limiter_call):
    """Runs limiter_call while recording every shell command issued."""
    with mock.patch(
        'evillimiter.networking.limit.shell.execute_suppressed',
        return_value=0,
    ) as exec_mock:
        limiter_call()
    return [call.args[0] for call in exec_mock.call_args_list]


class BlockAllChainsTest(unittest.TestCase):
    def setUp(self):
        self.limiter = Limiter('eth0')
        self.host = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'victim')

    def test_block_both_covers_forward_input_output(self):
        cmds = _capture_commands(
            lambda: self.limiter.block(self.host, Direction.BOTH)
        )
        joined = '\n'.join(cmds)
        # routed traffic in both directions
        self.assertIn('-A FORWARD -s 192.168.1.5 -j DROP', joined)
        self.assertIn('-A FORWARD -d 192.168.1.5 -j DROP', joined)
        # traffic to/from this machine itself
        self.assertIn('-A INPUT -s 192.168.1.5 -j DROP', joined)
        self.assertIn('-A OUTPUT -d 192.168.1.5 -j DROP', joined)
        self.assertTrue(self.host.blocked)

    def test_block_outgoing_only_adds_input_not_output(self):
        cmds = '\n'.join(_capture_commands(
            lambda: self.limiter.block(self.host, Direction.OUTGOING)
        ))
        self.assertIn('-A INPUT -s 192.168.1.5 -j DROP', cmds)
        self.assertNotIn('-A OUTPUT', cmds)

    def test_block_incoming_only_adds_output_not_input(self):
        cmds = '\n'.join(_capture_commands(
            lambda: self.limiter.block(self.host, Direction.INCOMING)
        ))
        self.assertIn('-A OUTPUT -d 192.168.1.5 -j DROP', cmds)
        self.assertNotIn('-A INPUT', cmds)

    def test_unlimit_removes_all_block_chains(self):
        # populate internal state without issuing real commands
        with mock.patch(
            'evillimiter.networking.limit.shell.execute_suppressed',
            return_value=0,
        ):
            self.limiter.block(self.host, Direction.BOTH)

        cmds = '\n'.join(_capture_commands(
            lambda: self.limiter.unlimit(self.host, Direction.BOTH)
        ))
        self.assertIn('-D FORWARD -s 192.168.1.5 -j DROP', cmds)
        self.assertIn('-D FORWARD -d 192.168.1.5 -j DROP', cmds)
        self.assertIn('-D INPUT -s 192.168.1.5 -j DROP', cmds)
        self.assertIn('-D OUTPUT -d 192.168.1.5 -j DROP', cmds)
        self.assertFalse(self.host.blocked)


if __name__ == '__main__':
    unittest.main()
