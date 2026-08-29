from tqdm import tqdm
from netaddr import IPAddress
from scapy.all import sr1, ARP # pylint: disable=no-name-in-module
from concurrent.futures import ThreadPoolExecutor

from .host import Host
from . import utils
from evillimiter.console.io import IO
        

class HostScanner(object):
    def __init__(self, interface, iprange, dhcp_listener=None):
        self.interface = interface
        self.iprange = iprange
        self.dhcp_listener = dhcp_listener

        self.max_workers = 150  # max. amount of threads
        self.retries = 1        # ARP retry
        self.timeout = 1        # time in s to wait for an answer

    def scan(self, iprange=None):
        self._resolve_names = True

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
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
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
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
        packet = ARP(op=1, pdst=ip)
        answer = sr1(packet, retry=self.retries, timeout=self.timeout, verbose=0, iface=self.interface)
        
        if answer is not None:
            return Host(ip, answer.hwsrc, '')