import unittest
from unittest import mock

# console.shell and console.io have a circular import that only resolves when
# shell is loaded first (as the app's globals module does at startup).
import evillimiter.console.shell  # noqa: F401
from evillimiter.networking.host import Host
from evillimiter.networking.limit import Limiter, Direction, LimitApplyError, NetemRequiresLimitError
from evillimiter.networking.utils import BitRate


def _capture_commands(limiter_call):
    """Runs limiter_call while recording every shell command issued."""
    with mock.patch(
        'evillimiter.networking.limit.shell.execute_suppressed',
        return_value=0,
    ) as exec_mock:
        limiter_call()
    return [call.args[0] for call in exec_mock.call_args_list]


def _run_with_failing(limiter_call, should_fail):
    """
    Runs limiter_call with shell.execute_suppressed mocked to return a
    failing exit code (1) for any command matching should_fail(cmd),
    and succeed (0) otherwise. Returns (commands_issued, raised_error) -
    raised_error is None if limiter_call didn't raise LimitApplyError.
    """
    commands = []

    def fake_execute(cmd, root=True):
        commands.append(cmd)
        return 1 if should_fail(cmd) else 0

    error = None
    with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', side_effect=fake_execute):
        try:
            limiter_call()
        except LimitApplyError as e:
            error = e

    return commands, error


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


class ReplaceAcrossReconnectTest(unittest.TestCase):
    """
    old_host and new_host share a MAC (that's what a reconnect is) and
    are therefore == under Host's MAC-based identity - a host that's
    mid-block/limit when it reconnects must stay tracked under its new
    IP, with the old IP's rules torn down.
    """
    def setUp(self):
        self.limiter = Limiter('eth0')
        self.old_host = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')
        self.new_host = Host('192.168.1.9', 'aa:bb:cc:dd:ee:ff', 'phone')

    def test_blocked_host_stays_blocked_under_new_ip(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.block(self.old_host, Direction.BOTH)

        cmds = '\n'.join(_capture_commands(
            lambda: self.limiter.replace(self.old_host, self.new_host)
        ))

        self.assertIn('-D FORWARD -s 192.168.1.5 -j DROP', cmds)   # old ip torn down
        self.assertIn('-A FORWARD -s 192.168.1.9 -j DROP', cmds)   # new ip blocked
        self.assertEqual(len(self.limiter._host_dict), 1)
        self.assertIn(self.new_host, self.limiter._host_dict)      # old_host equally matches
                                                                    # (same mac), one entry either way

    def test_untracked_host_replace_is_noop(self):
        cmds = _capture_commands(
            lambda: self.limiter.replace(self.old_host, self.new_host)
        )
        self.assertEqual(cmds, [])

    def test_replace_still_applies_new_host_when_old_teardown_fails(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.block(self.old_host, Direction.BOTH)

        commands, error = _run_with_failing(
            lambda: self.limiter.replace(self.old_host, self.new_host),
            should_fail=lambda cmd: '-D FORWARD -s 192.168.1.5' in cmd,
        )

        self.assertIsNotNone(error)
        self.assertTrue(any('forward drop delete' in step for step in error.failed_steps))
        # new host still gets blocked despite the old host's teardown failure
        self.assertIn('-A FORWARD -s 192.168.1.9 -j DROP', '\n'.join(commands))
        self.assertTrue(self.new_host.blocked)
        self.assertIn(self.new_host, self.limiter._host_dict)


class LimitApplyErrorPropagationTest(unittest.TestCase):
    """
    limit()/block() now surface tc/iptables failures instead of
    silently discarding the exit code - but bookkeeping (host flags,
    _host_dict registration) must complete exactly as it did before
    this existed, so free()/watch/monitor keep working on a
    partially-applied host.
    """
    def setUp(self):
        self.limiter = Limiter('eth0')
        self.host = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'phone')

    def test_limit_raises_but_still_tracks_host(self):
        commands, error = _run_with_failing(
            lambda: self.limiter.limit(self.host, Direction.OUTGOING, 1000),
            should_fail=lambda cmd: 'class add' in cmd,
        )

        self.assertIsNotNone(error)
        self.assertIn('tc class (upload)', error.failed_steps)
        self.assertTrue(self.host.limited)
        self.assertIn(self.host, self.limiter._host_dict)

    def test_block_raises_but_still_tracks_host(self):
        commands, error = _run_with_failing(
            lambda: self.limiter.block(self.host, Direction.OUTGOING),
            should_fail=lambda cmd: 'FORWARD' in cmd,
        )

        self.assertIsNotNone(error)
        self.assertIn('iptables forward drop (upload)', error.failed_steps)
        self.assertTrue(self.host.blocked)
        self.assertIn(self.host, self.limiter._host_dict)

    def test_fully_successful_limit_does_not_raise(self):
        _, error = _run_with_failing(
            lambda: self.limiter.limit(self.host, Direction.BOTH, 1000),
            should_fail=lambda cmd: False,
        )
        self.assertIsNone(error)


class UnlimitTeardownAccuracyTest(unittest.TestCase):
    """
    unlimit() must not report - or even attempt - steps that were never
    applicable in the first place: a blocked host never got a tc class
    (limit() didn't run), a limited host never got a DROP rule (block()
    didn't run). Attempting the wrong set unconditionally is exactly
    what would make every BOTH-direction free() falsely report a
    failure once failures are surfaced at all.
    """
    def setUp(self):
        self.limiter = Limiter('eth0')
        self.host = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'victim')

    def test_unlimit_blocked_host_never_touches_tc_or_mark(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.block(self.host, Direction.BOTH)

        commands, error = _run_with_failing(
            lambda: self.limiter.unlimit(self.host, Direction.BOTH),
            should_fail=lambda cmd: False,
        )

        self.assertIsNone(error)
        joined = '\n'.join(commands)
        self.assertNotIn('MARK', joined)
        self.assertFalse(any('class del' in c or 'filter del' in c for c in commands))
        # each real DROP rule deleted exactly once, not duplicated
        self.assertEqual(sum(1 for c in commands if 'FORWARD -s 192.168.1.5 -j DROP' in c), 1)
        self.assertEqual(sum(1 for c in commands if 'INPUT -s 192.168.1.5 -j DROP' in c), 1)
        self.assertEqual(sum(1 for c in commands if 'FORWARD -d 192.168.1.5 -j DROP' in c), 1)
        self.assertEqual(sum(1 for c in commands if 'OUTPUT -d 192.168.1.5 -j DROP' in c), 1)
        self.assertEqual(len(commands), 4)

    def test_unlimit_limited_host_never_touches_drop_rules(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.limit(self.host, Direction.BOTH, 1000)

        ids = self.limiter._host_dict[self.host]['ids']

        commands, error = _run_with_failing(
            lambda: self.limiter.unlimit(self.host, Direction.BOTH),
            should_fail=lambda cmd: False,
        )

        self.assertIsNone(error)
        joined = '\n'.join(commands)
        self.assertNotIn('DROP', joined)
        # mark-delete uses the correct id for each direction, exactly once each -
        # the old implementation re-checked the combined direction on every call
        # and for BOTH ran every branch twice, half the time with the wrong id
        self.assertEqual(
            sum(1 for c in commands if 'POSTROUTING -s 192.168.1.5 -j MARK --set-mark {}'.format(ids.upload_id) in c),
            1,
        )
        self.assertEqual(
            sum(1 for c in commands if 'PREROUTING -d 192.168.1.5 -j MARK --set-mark {}'.format(ids.download_id) in c),
            1,
        )
        self.assertEqual(len(commands), 6)  # 2 tc + 2 tc + 2 mark, no duplicates


class IndependentRateTest(unittest.TestCase):
    """
    bitbrute/evillimiter#63 wishlist comment (andrewprivate): set
    different upload/download rates on the same device in one call,
    instead of one rate applying to both directions.
    """
    def setUp(self):
        self.limiter = Limiter('eth0')
        self.host = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'victim')

    def test_tuple_rate_uses_distinct_upload_and_download_rates(self):
        cmds = '\n'.join(_capture_commands(
            lambda: self.limiter.limit(self.host, Direction.BOTH, (BitRate(1000), BitRate(500000)))
        ))
        self.assertIn('htb rate 1kbit', cmds)
        self.assertIn('htb rate 500kbit', cmds)

    def test_info_returns_the_rate_tuple_unchanged(self):
        rate = (BitRate(1000), BitRate(500000))
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.limit(self.host, Direction.BOTH, rate)

        self.assertEqual(self.limiter.info(self.host), (rate, Direction.BOTH, None))

    def test_unlimit_tears_down_both_directions(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.limit(self.host, Direction.BOTH, (BitRate(1000), BitRate(500000)))

        ids = self.limiter._host_dict[self.host]['ids']
        cmds = '\n'.join(_capture_commands(
            lambda: self.limiter.unlimit(self.host, Direction.BOTH)
        ))
        self.assertIn('classid 1:{}'.format(ids.upload_id), cmds)
        self.assertIn('classid 1:{}'.format(ids.download_id), cmds)
        self.assertFalse(self.host.limited)

    def test_replace_carries_the_rate_tuple_through_reconnect(self):
        old_host = self.host
        new_host = Host('192.168.1.9', 'aa:bb:cc:dd:ee:ff', 'victim')
        rate = (BitRate(1000), BitRate(500000))

        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.limit(old_host, Direction.BOTH, rate)

        cmds = '\n'.join(_capture_commands(
            lambda: self.limiter.replace(old_host, new_host)
        ))
        self.assertIn('htb rate 1kbit', cmds)
        self.assertIn('htb rate 500kbit', cmds)
        self.assertEqual(self.limiter.info(new_host), (rate, Direction.BOTH, None))


class LimiterInfoTest(unittest.TestCase):
    def setUp(self):
        self.limiter = Limiter('eth0')
        self.host = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'victim')

    def test_untracked_host_returns_none(self):
        self.assertIsNone(self.limiter.info(self.host))

    def test_limited_host_returns_rate_and_direction(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.limit(self.host, Direction.OUTGOING, 1000)

        self.assertEqual(self.limiter.info(self.host), (1000, Direction.OUTGOING, None))

    def test_blocked_host_returns_no_rate(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.block(self.host, Direction.BOTH)

        self.assertEqual(self.limiter.info(self.host), (None, Direction.BOTH, None))


class NetemTest(unittest.TestCase):
    """
    bitbrute/evillimiter#63 wishlist: emulate packet loss/delay
    (tc-netem). Attaches to an already-limited host's existing tc
    class - never ships as a standalone state, and never for a
    blocked host (block() has no tc class to attach to).
    """
    def setUp(self):
        self.limiter = Limiter('eth0')
        self.host = Host('192.168.1.5', 'aa:bb:cc:dd:ee:ff', 'victim')

    def test_requires_limit_on_untracked_host(self):
        with self.assertRaises(NetemRequiresLimitError):
            self.limiter.set_netem(self.host, delay=100, loss=5)

    def test_requires_limit_on_blocked_host(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.block(self.host, Direction.BOTH)

        with self.assertRaises(NetemRequiresLimitError):
            self.limiter.set_netem(self.host, delay=100, loss=5)

    def test_set_netem_on_both_directions(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.limit(self.host, Direction.BOTH, BitRate(1000))

        ids = self.limiter._host_dict[self.host]['ids']
        cmds = '\n'.join(_capture_commands(
            lambda: self.limiter.set_netem(self.host, delay=100, loss=5)
        ))

        self.assertIn('qdisc replace dev eth0 parent 1:{} handle {}: netem delay 100ms loss 5%'.format(ids.upload_id, ids.upload_id + 10000), cmds)
        self.assertIn('qdisc replace dev eth0 parent 1:{} handle {}: netem delay 100ms loss 5%'.format(ids.download_id, ids.download_id + 10000), cmds)

    def test_set_netem_on_single_direction_only_touches_that_class(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.limit(self.host, Direction.OUTGOING, BitRate(1000))

        ids = self.limiter._host_dict[self.host]['ids']
        cmds = '\n'.join(_capture_commands(
            lambda: self.limiter.set_netem(self.host, delay=100)
        ))

        self.assertIn('parent 1:{}'.format(ids.upload_id), cmds)
        self.assertNotIn('parent 1:{}'.format(ids.download_id), cmds)
        self.assertIn('netem delay 100ms', cmds)
        self.assertNotIn('loss', cmds)

    def test_set_netem_updates_info(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.limit(self.host, Direction.BOTH, BitRate(1000))
            self.limiter.set_netem(self.host, delay=100, loss=5)

        self.assertEqual(self.limiter.info(self.host)[2], {'delay': 100, 'loss': 5})

    def test_clear_netem_removes_qdisc_and_resets_info(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.limit(self.host, Direction.BOTH, BitRate(1000))
            self.limiter.set_netem(self.host, delay=100, loss=5)

        ids = self.limiter._host_dict[self.host]['ids']
        cmds = '\n'.join(_capture_commands(
            lambda: self.limiter.clear_netem(self.host)
        ))

        self.assertIn('qdisc del dev eth0 parent 1:{} handle {}:'.format(ids.upload_id, ids.upload_id + 10000), cmds)
        self.assertIn('qdisc del dev eth0 parent 1:{} handle {}:'.format(ids.download_id, ids.download_id + 10000), cmds)
        self.assertIsNone(self.limiter.info(self.host)[2])

    def test_clear_netem_is_a_noop_when_never_set(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.limit(self.host, Direction.BOTH, BitRate(1000))

        cmds = _capture_commands(lambda: self.limiter.clear_netem(self.host))
        self.assertEqual(cmds, [])

    def test_clear_netem_is_a_noop_on_untracked_host(self):
        cmds = _capture_commands(lambda: self.limiter.clear_netem(self.host))
        self.assertEqual(cmds, [])

    def test_relimiting_drops_stale_netem_state(self):
        with mock.patch('evillimiter.networking.limit.shell.execute_suppressed', return_value=0):
            self.limiter.limit(self.host, Direction.BOTH, BitRate(1000))
            self.limiter.set_netem(self.host, delay=100, loss=5)
            self.limiter.limit(self.host, Direction.BOTH, BitRate(2000))

        self.assertIsNone(self.limiter.info(self.host)[2])


if __name__ == '__main__':
    unittest.main()
