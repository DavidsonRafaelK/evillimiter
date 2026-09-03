import threading

import evillimiter.console.shell as shell
from .host import Host
from evillimiter.common.globals import BIN_TC, BIN_IPTABLES
from evillimiter.networking.utils import format_netem


# Offset applied to a host's tc class id to derive its netem qdisc's own
# handle major number. Class ids start at 1 and the root qdisc is
# `handle 1:0` (netutils.create_qdisc_root) - a plain reuse of the id
# would collide with the root the moment id==1. Adding a large constant
# keeps every netem handle unique (ids are already globally unique) and
# guarantees it's never 1.
NETEM_HANDLE_OFFSET = 10000


class LimitApplyError(Exception):
    """
    Raised by limit()/block()/unlimit()/replace() after they've finished
    applying whatever they could - carries the tc/iptables steps that
    returned a non-zero exit code, so a caller can report specifically
    what failed instead of a generic message.

    State bookkeeping (host.limited/.blocked, _host_dict) still
    completes exactly as before this existed; raising is purely an
    added signal, not a behavior change to what gets tracked.
    """
    def __init__(self, failed_steps, direction):
        self.failed_steps = failed_steps
        self.direction = direction
        super().__init__('failed: {}'.format(', '.join(failed_steps)))


class NetemRequiresLimitError(Exception):
    """
    Raised by set_netem()/clear_netem() when the host isn't currently
    limited (untracked, or blocked - block() never creates a tc class
    for netem to attach to).
    """
    pass


class Limiter(object):
    class HostLimitIDs(object):
        def __init__(self, upload_id, download_id):
            self.upload_id = upload_id
            self.download_id = download_id

    def __init__(self, interface):
        self.interface = interface
        self._host_dict = {}
        self._host_dict_lock = threading.Lock()

    def info(self, host):
        """
        Returns (rate, direction, netem) for a currently limited/blocked
        host, or None if the host isn't tracked. rate is None for a
        blocked host (block() has no associated rate), a single BitRate
        for a uniformly-limited host, or an (upload_rate, download_rate)
        tuple for independent rates. netem is None, or a
        {'delay':.., 'loss':..} dict if set_netem() has been applied.
        """
        with self._host_dict_lock:
            entry = self._host_dict.get(host)
        return None if entry is None else (entry['rate'], entry['direction'], entry.get('netem'))

    def _iter_directions(self, direction):
        """
        Yields (single_direction, label, flag, mangle_chain, local_chain)
        for each direction present in `direction`, replacing the repeated
        `(direction & X) == X` guards. `flag` is the iptables source/dest
        selector, `mangle_chain` the MARK chain, `local_chain` the
        host<->this-machine DROP chain.
        """
        meta = (
            (Direction.OUTGOING, 'upload', '-s', 'POSTROUTING', 'INPUT'),
            (Direction.INCOMING, 'download', '-d', 'PREROUTING', 'OUTPUT'),
        )
        for single, label, flag, mangle_chain, local_chain in meta:
            if (direction & single) == single:
                yield single, label, flag, mangle_chain, local_chain

    def _id_for_direction(self, host_ids, single_direction):
        return host_ids.upload_id if single_direction == Direction.OUTGOING else host_ids.download_id

    def limit(self, host, direction, rate):
        """
        Limits the uload/dload traffic of a host to a specified rate.

        `rate` is either a single BitRate applied to every direction in
        `direction`, or an (upload_rate, download_rate) tuple for
        independent rates - only meaningful (and only used) when
        `direction` is BOTH. Stored as-is in _host_dict, so info() and
        replace() hand the same shape straight back without needing to
        know which case they're in.
        """
        upload_rate, download_rate = rate if isinstance(rate, tuple) else (rate, rate)

        host_ids, failed_steps = self._new_host_limit_ids(host, direction)

        rates = {Direction.OUTGOING: upload_rate, Direction.INCOMING: download_rate}
        for single, label, flag, mangle_chain, _ in self._iter_directions(direction):
            id_ = self._id_for_direction(host_ids, single)
            r = rates[single]
            # add a class to the root qdisc with specified rate
            if not self._run('{} class add dev {} parent 1:0 classid 1:{} htb rate {r} burst {b}'.format(BIN_TC, self.interface, id_, r=r, b=r * 1.1)):
                failed_steps.append('tc class ({})'.format(label))
            # add a fw filter that filters packets marked with the corresponding ID
            if not self._run('{} filter add dev {} parent 1:0 protocol ip prio {id} handle {id} fw flowid 1:{id}'.format(BIN_TC, self.interface, id=id_)):
                failed_steps.append('tc filter ({})'.format(label))
            # marks packets in this direction
            if not self._run('{} -t mangle -A {chain} {flag} {ip} -j MARK --set-mark {id}'.format(BIN_IPTABLES, chain=mangle_chain, flag=flag, ip=host.ip, id=id_)):
                failed_steps.append('iptables mark ({})'.format(label))

        host.limited = True

        with self._host_dict_lock:
            self._host_dict[host] = { 'ids': host_ids, 'rate': rate, 'direction': direction }

        if failed_steps:
            raise LimitApplyError(failed_steps, direction)

    def block(self, host, direction):
        host_ids, failed_steps = self._new_host_limit_ids(host, direction)

        for single, label, flag, _, local_chain in self._iter_directions(direction):
            # drops forwarded packets matching this direction (routed
            # traffic, e.g. towards the internet)
            if not self._run('{} -t filter -A FORWARD {flag} {ip} -j DROP'.format(BIN_IPTABLES, flag=flag, ip=host.ip)):
                failed_steps.append('iptables forward drop ({})'.format(label))
            # drops packets directly between the host and this machine
            if not self._run('{} -t filter -A {chain} {flag} {ip} -j DROP'.format(BIN_IPTABLES, chain=local_chain, flag=flag, ip=host.ip)):
                failed_steps.append('iptables {} drop ({})'.format(local_chain.lower(), label))

        host.blocked = True

        with self._host_dict_lock:
            self._host_dict[host] = { 'ids': host_ids, 'rate': None, 'direction': direction }

        if failed_steps:
            raise LimitApplyError(failed_steps, direction)

    def set_netem(self, host, delay=None, loss=None):
        """
        Attaches (or updates) tc-netem packet delay/loss on an
        already-limited host's existing tc class(es) - applies to
        whichever direction(s) the host is currently limited in, no
        separate direction of its own. Raises NetemRequiresLimitError
        if the host isn't currently limited (untracked, or blocked -
        block() has no tc class to attach to).
        """
        with self._host_dict_lock:
            entry = self._host_dict.get(host)
            if entry is None or entry['rate'] is None:
                raise NetemRequiresLimitError()
            host_ids = entry['ids']
            direction = entry['direction']

        failed_steps = []
        netem_args = self._netem_qdisc_args(delay, loss)

        for single, label, _, _, _ in self._iter_directions(direction):
            id_ = self._id_for_direction(host_ids, single)
            if not self._run('{} qdisc replace dev {} parent 1:{id} handle {h}: netem {a}'.format(BIN_TC, self.interface, id=id_, h=id_ + NETEM_HANDLE_OFFSET, a=netem_args)):
                failed_steps.append('tc netem ({})'.format(label))

        with self._host_dict_lock:
            if host in self._host_dict:
                self._host_dict[host]['netem'] = {'delay': delay, 'loss': loss}

        if failed_steps:
            raise LimitApplyError(failed_steps, direction)

    def clear_netem(self, host):
        """
        Removes tc-netem impairment from an already-limited host,
        leaving its rate limit untouched. No-op if the host has no
        netem applied (including an untracked host - clearing
        something that was never set isn't an error).
        """
        with self._host_dict_lock:
            entry = self._host_dict.get(host)
            if entry is None or entry.get('netem') is None:
                return
            host_ids = entry['ids']
            direction = entry['direction']

        failed_steps = []

        for single, label, _, _, _ in self._iter_directions(direction):
            id_ = self._id_for_direction(host_ids, single)
            if not self._run('{} qdisc del dev {} parent 1:{id} handle {h}:'.format(BIN_TC, self.interface, id=id_, h=id_ + NETEM_HANDLE_OFFSET)):
                failed_steps.append('tc netem delete ({})'.format(label))

        with self._host_dict_lock:
            if host in self._host_dict:
                self._host_dict[host]['netem'] = None

        if failed_steps:
            raise LimitApplyError(failed_steps, direction)

    def _netem_qdisc_args(self, delay, loss):
        return format_netem(delay, loss)

    def unlimit(self, host, direction):
        if not host.limited and not host.blocked:
            return

        failed_steps = []

        with self._host_dict_lock:
            info = self._host_dict[host]
            host_ids = info['ids']
            was_limited = info['rate'] is not None

            for single, _, _, _, _ in self._iter_directions(direction):
                id_ = self._id_for_direction(host_ids, single)
                failed_steps += self._teardown_direction(host, id_, single, was_limited)

            del self._host_dict[host]

        host.limited = False
        host.blocked = False

        if failed_steps:
            raise LimitApplyError(failed_steps, direction)

    def replace(self, old_host, new_host):
        self._host_dict_lock.acquire()
        info = self._host_dict[old_host] if old_host in self._host_dict else None
        self._host_dict_lock.release()

        if info is None:
            return

        # old_host's teardown and new_host's re-application are independent -
        # a failure tearing down the old rules must not skip applying the
        # restriction to the new host, and vice versa
        failed_steps = []

        try:
            self.unlimit(old_host, Direction.BOTH)
        except LimitApplyError as e:
            failed_steps += e.failed_steps

        try:
            if info['rate'] is None:
                self.block(new_host, info['direction'])
            else:
                self.limit(new_host, info['direction'], info['rate'])
        except LimitApplyError as e:
            failed_steps += e.failed_steps

        if failed_steps:
            raise LimitApplyError(failed_steps, info['direction'])

    def _new_host_limit_ids(self, host, direction):
        """
        Get limit information for corresponding host
        If not present, create new

        Returns (host_ids, failed_steps) - failed_steps carries forward
        any failure tearing down the host's previous rules (re-limiting
        an already-tracked host), so the caller's own LimitApplyError
        reports the full picture instead of the teardown failure being
        lost.
        """
        host_ids = None
        failed_steps = []

        self._host_dict_lock.acquire()
        present = host in self._host_dict
        self._host_dict_lock.release()

        if present:
            host_ids = self._host_dict[host]['ids']
            try:
                self.unlimit(host, direction)
            except LimitApplyError as e:
                failed_steps = e.failed_steps

        return (Limiter.HostLimitIDs(*self._create_ids()) if host_ids is None else host_ids, failed_steps)

    def _create_ids(self):
        """
        Returns unique IDs that are
        currently not in use
        """
        def generate_id(*exc):
            """
            Generates a unique, unused ID
            exc: IDs that will not be used (exceptions)
            """
            id_ = 1
            with self._host_dict_lock:
                while True:
                    if id_ not in exc:
                        v = (x for x in self._host_dict.values())
                        ids = (x['ids'] for x in v)
                        if id_ not in (x for y in ids for x in [y.upload_id, y.download_id]):
                            return id_
                    id_ += 1

        id1 = generate_id()
        return (id1, generate_id(id1))

    def _run(self, command):
        """
        Runs a shell command, returns whether it succeeded (exit 0)
        """
        return shell.execute_suppressed(command) == 0

    def _teardown_direction(self, host, id_, single_direction, was_limited):
        """
        Removes every rule limit()/block() may have added for exactly
        one direction. was_limited picks which rules actually exist to
        remove: a limited host only ever got tc class/filter + an
        iptables mark for this direction, a blocked host only ever got
        an iptables DROP rule - never both, so only the relevant set is
        attempted (attempting the other set always "fails", since
        there's nothing there to delete, which would otherwise show up
        as a false positive once failures are surfaced).

        single_direction must be exactly one of Direction.OUTGOING /
        Direction.INCOMING, never BOTH - the caller narrows it before
        calling, so each rule is targeted with its own id and torn down
        exactly once (the previous implementation re-checked the full,
        still-combined direction on every call, which for Direction.BOTH
        ran every branch twice, half of the time with the wrong id).
        """
        if was_limited:
            return self._delete_tc_class(id_) + self._delete_iptables_mark_entry(host, single_direction, id_)
        else:
            return self._delete_iptables_drop_entries(host, single_direction)

    def _delete_tc_class(self, id_):
        """
        Deletes the tc class and applied filters
        for a given ID (host)
        """
        failed = []
        if not self._run('{} filter del dev {} parent 1:0 prio {}'.format(BIN_TC, self.interface, id_)):
            failed.append('tc filter delete')
        if not self._run('{} class del dev {} parent 1:0 classid 1:{}'.format(BIN_TC, self.interface, id_)):
            failed.append('tc class delete')
        return failed

    def _delete_iptables_mark_entry(self, host, single_direction, id_):
        """
        Deletes the mangle MARK rule limit() adds for one direction
        """
        failed = []
        if single_direction == Direction.OUTGOING:
            if not self._run('{} -t mangle -D POSTROUTING -s {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, id_)):
                failed.append('iptables mark delete (upload)')
        else:
            if not self._run('{} -t mangle -D PREROUTING -d {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, id_)):
                failed.append('iptables mark delete (download)')
        return failed

    def _delete_iptables_drop_entries(self, host, single_direction):
        """
        Deletes the FORWARD/INPUT/OUTPUT DROP rules block() adds for
        one direction
        """
        failed = []
        if single_direction == Direction.OUTGOING:
            if not self._run('{} -t filter -D FORWARD -s {} -j DROP'.format(BIN_IPTABLES, host.ip)):
                failed.append('iptables forward drop delete (upload)')
            if not self._run('{} -t filter -D INPUT -s {} -j DROP'.format(BIN_IPTABLES, host.ip)):
                failed.append('iptables input drop delete (upload)')
        else:
            if not self._run('{} -t filter -D FORWARD -d {} -j DROP'.format(BIN_IPTABLES, host.ip)):
                failed.append('iptables forward drop delete (download)')
            if not self._run('{} -t filter -D OUTPUT -d {} -j DROP'.format(BIN_IPTABLES, host.ip)):
                failed.append('iptables output drop delete (download)')
        return failed


class Direction:
    NONE = 0
    OUTGOING = 1
    INCOMING = 2
    BOTH = 3

    def pretty_direction(direction):
        if direction == Direction.OUTGOING:
            return 'upload'
        elif direction == Direction.INCOMING:
            return 'download'
        elif direction == Direction.BOTH:
            return 'upload / download'
        else:
            return '-'
