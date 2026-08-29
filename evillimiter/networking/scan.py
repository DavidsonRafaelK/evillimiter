import threading
import collections
from tqdm import tqdm
from netaddr import IPAddress
from scapy.all import sr1, ARP # pylint: disable=no-name-in-module
from concurrent.futures import ThreadPoolExecutor

from .host import Host
from . import utils
from evillimiter.console.io import IO


class HostScanner(object):
    Settings = collections.namedtuple('Settings', 'max_workers retries timeout')

    def __init__(self, interface, iprange, dhcp_listener=None):
        self.interface = interface
        self.iprange = iprange
        self.dhcp_listener = dhcp_listener

        # max. amount of threads stays constant across intensities - only
        # per-host retry/timeout trade off scan speed against thoroughness.
        # NORMAL matches this scanner's pre-intensity defaults, so an
        # untouched `scan` behaves exactly as before this existed.
        self._quick_settings = HostScanner.Settings(max_workers=150, retries=0, timeout=1)
        self._normal_settings = HostScanner.Settings(max_workers=150, retries=1, timeout=1)
        self._intense_settings = HostScanner.Settings(max_workers=150, retries=3, timeout=3)

        self._settings = self._normal_settings
        self._settings_lock = threading.Lock()

    @property
    def settings(self):
        with self._settings_lock:
            return self._settings

    @settings.setter
    def settings(self, value):
        with self._settings_lock:
            self._settings = value

    def set_intensity(self, intensity):
        """
        Switches scan speed/thoroughness. Sticky across calls to scan()/
        scan_for_reconnects() - including watch's background reconnect
        sweeps, which share this same scanner instance - until changed
        again.
        """
        if intensity == ScanIntensity.QUICK:
            self.settings = self._quick_settings
        elif intensity == ScanIntensity.NORMAL:
            self.settings = self._normal_settings
        elif intensity == ScanIntensity.INTENSE:
            self.settings = self._intense_settings

    def scan(self, iprange=None):
        self._resolve_names = True

        with ThreadPoolExecutor(max_workers=self.settings.max_workers) as executor:
            hosts = []
            iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]
            iterator = tqdm(
                iterable=executor.map(self._sweep, iprange),
                total=len(iprange),
                ncols=45,
                bar_format='{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}'
            )

            try:
                for host in iterator:
                    if host is not None:
                        name = self.dhcp_listener.get(host.mac) if self.dhcp_listener else None
                        if not name:
                            name = utils.get_hostname(host.ip)

                        host.name = '' if name is None else name
                        hosts.append(host)
            except KeyboardInterrupt:
                iterator.close()
                IO.ok('aborted. waiting for shutdown...')

            return hosts

    def scan_for_reconnects(self, hosts, iprange=None, absent=None):
        """
        absent: optional set - if given, populated with every host from
        `hosts` whose MAC address wasn't seen anywhere in this sweep
        (offline this cycle). Reuses the sweep this method already does
        instead of scanning twice; existing callers that don't pass it
        see no change in behavior or return value.
        """
        with ThreadPoolExecutor(max_workers=self.settings.max_workers) as executor:
            scanned_hosts = []
            iprange = [str(x) for x in (self.iprange if iprange is None else iprange)]
            for host in executor.map(self._sweep, iprange):
                if host is not None:
                    scanned_hosts.append(host)

            reconnected_hosts = {}
            for host in hosts:
                seen = False
                for s_host in scanned_hosts:
                    if host.mac == s_host.mac:
                        seen = True
                    if host.reconnected_as(s_host):
                        s_host.name = host.name
                        reconnected_hosts[host] = s_host

                if absent is not None and not seen:
                    absent.add(host)

            return reconnected_hosts

    def _sweep(self, ip):
        """
        Sends ARP packet and listens for answer,
        if present the host is online
        """
        settings = self.settings

        packet = ARP(op=1, pdst=ip)
        answer = sr1(packet, retry=settings.retries, timeout=settings.timeout, verbose=0, iface=self.interface)

        if answer is not None:
            return Host(ip, answer.hwsrc, '')


class ScanIntensity:
    QUICK = 1
    NORMAL = 2
    INTENSE = 3