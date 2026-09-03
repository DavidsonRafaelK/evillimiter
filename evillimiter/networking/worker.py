import threading


class BackgroundWorker(object):
    """
    Base for the daemon-thread subsystems (ARP/NDP spoofers, the DHCP
    sniffer, the bandwidth monitor). Owns the `_running` flag and a
    start()/stop() pair that spawns the worker callables returned by
    `_worker_targets()` exactly once, each on its own daemon thread.
    """
    def __init__(self):
        self._running = False

    def _worker_targets(self):
        """Callables to run, each on its own daemon thread."""
        raise NotImplementedError

    def _can_start(self):
        """Optional precondition; start() is a no-op when this is False."""
        return True

    def start(self):
        if self._running or not self._can_start():
            return

        self._running = True
        for target in self._worker_targets():
            threading.Thread(target=target, args=[], daemon=True).start()

    def stop(self):
        self._running = False


class HostTracker(object):
    """
    A thread-safe set of tracked hosts, shared by the spoofers.
    Subclasses keep their own add()/remove() (which do extra work), but
    reuse the set, its lock, and a locked snapshot for the send loop.
    """
    def __init__(self):
        self._hosts = set()
        self._hosts_lock = threading.Lock()

    def _snapshot_hosts(self):
        with self._hosts_lock:
            return self._hosts.copy()
