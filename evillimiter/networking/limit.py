import threading

import evillimiter.console.shell as shell
from .host import Host
from evillimiter.common.globals import BIN_TC, BIN_IPTABLES


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
        Returns (rate, direction) for a currently limited/blocked host,
        or None if the host isn't tracked. rate is None for a blocked
        host, since block() has no associated rate.
        """
        with self._host_dict_lock:
            entry = self._host_dict.get(host)
        return None if entry is None else (entry['rate'], entry['direction'])

    def limit(self, host, direction, rate):
        """
        Limits the uload/dload traffic of a host
        to a specified rate
        """
        host_ids, failed_steps = self._new_host_limit_ids(host, direction)

        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            # add a class to the root qdisc with specified rate
            if not self._run('{} class add dev {} parent 1:0 classid 1:{} htb rate {r} burst {b}'.format(BIN_TC, self.interface, host_ids.upload_id, r=rate, b=rate * 1.1)):
                failed_steps.append('tc class (upload)')
            # add a fw filter that filters packets marked with the corresponding ID
            if not self._run('{} filter add dev {} parent 1:0 protocol ip prio {id} handle {id} fw flowid 1:{id}'.format(BIN_TC, self.interface, id=host_ids.upload_id)):
                failed_steps.append('tc filter (upload)')
            # marks outgoing packets
            if not self._run('{} -t mangle -A POSTROUTING -s {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, host_ids.upload_id)):
                failed_steps.append('iptables mark (upload)')
        if (direction & Direction.INCOMING) == Direction.INCOMING:
            # add a class to the root qdisc with specified rate
            if not self._run('{} class add dev {} parent 1:0 classid 1:{} htb rate {r} burst {b}'.format(BIN_TC, self.interface, host_ids.download_id, r=rate, b=rate * 1.1)):
                failed_steps.append('tc class (download)')
            # add a fw filter that filters packets marked with the corresponding ID
            if not self._run('{} filter add dev {} parent 1:0 protocol ip prio {id} handle {id} fw flowid 1:{id}'.format(BIN_TC, self.interface, id=host_ids.download_id)):
                failed_steps.append('tc filter (download)')
            # marks incoming packets
            if not self._run('{} -t mangle -A PREROUTING -d {} -j MARK --set-mark {}'.format(BIN_IPTABLES, host.ip, host_ids.download_id)):
                failed_steps.append('iptables mark (download)')

        host.limited = True

        with self._host_dict_lock:
            self._host_dict[host] = { 'ids': host_ids, 'rate': rate, 'direction': direction }

        if failed_steps:
            raise LimitApplyError(failed_steps, direction)

    def block(self, host, direction):
        host_ids, failed_steps = self._new_host_limit_ids(host, direction)

        if (direction & Direction.OUTGOING) == Direction.OUTGOING:
            # drops forwarded packets with matching source (traffic routed
            # through this machine, e.g. towards the internet)
            if not self._run('{} -t filter -A FORWARD -s {} -j DROP'.format(BIN_IPTABLES, host.ip)):
                failed_steps.append('iptables forward drop (upload)')
            # drops packets the host sends directly to this machine
            if not self._run('{} -t filter -A INPUT -s {} -j DROP'.format(BIN_IPTABLES, host.ip)):
                failed_steps.append('iptables input drop (upload)')
        if (direction & Direction.INCOMING) == Direction.INCOMING:
            # drops forwarded packets with matching destination
            if not self._run('{} -t filter -A FORWARD -d {} -j DROP'.format(BIN_IPTABLES, host.ip)):
                failed_steps.append('iptables forward drop (download)')
            # drops packets this machine sends directly to the host
            if not self._run('{} -t filter -A OUTPUT -d {} -j DROP'.format(BIN_IPTABLES, host.ip)):
                failed_steps.append('iptables output drop (download)')

        host.blocked = True

        with self._host_dict_lock:
            self._host_dict[host] = { 'ids': host_ids, 'rate': None, 'direction': direction }

        if failed_steps:
            raise LimitApplyError(failed_steps, direction)

    def unlimit(self, host, direction):
        if not host.limited and not host.blocked:
            return

        failed_steps = []

        with self._host_dict_lock:
            info = self._host_dict[host]
            host_ids = info['ids']
            was_limited = info['rate'] is not None

            if (direction & Direction.OUTGOING) == Direction.OUTGOING:
                failed_steps += self._teardown_direction(host, host_ids.upload_id, Direction.OUTGOING, was_limited)
            if (direction & Direction.INCOMING) == Direction.INCOMING:
                failed_steps += self._teardown_direction(host, host_ids.download_id, Direction.INCOMING, was_limited)

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
