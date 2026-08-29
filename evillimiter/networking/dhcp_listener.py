import threading
from scapy.all import sniff, DHCP, Ether # pylint: disable=no-name-in-module


class DHCPHostnameListener(object):
    """
    Passively listens for DHCP traffic on the interface and records
    the hostname a device announces via option 12 ('host-name') when
    it requests/renews a lease. This is the same mechanism a Wi-Fi
    hotspot uses to show a friendly name ("David's iPhone") for a
    connected client, instead of relying on reverse DNS/NetBIOS/mDNS.

    Only devices whose DHCP negotiation is observed while the
    listener is running are resolved this way - a device that
    already held a lease before the listener started won't appear
    until its next renewal.
    """
    def __init__(self, interface):
        self.interface = interface

        self._hostnames = {}  # mac (lowercase) -> hostname
        self._hostnames_lock = threading.Lock()
        self._running = False

    def get(self, mac):
        with self._hostnames_lock:
            return self._hostnames.get(mac.lower())

    def start(self):
        if self._running:
            return

        self._running = True
        thread = threading.Thread(target=self._sniff, args=[], daemon=True)
        thread.start()

    def stop(self):
        self._running = False

    def _sniff(self):
        def pkt_handler(pkt):
            if not pkt.haslayer(DHCP) or not pkt.haslayer(Ether):
                return

            hostname = None
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == 'hostname':
                    hostname = opt[1]
                    break

            if isinstance(hostname, bytes):
                hostname = hostname.decode('ascii', 'ignore')

            if not hostname:
                return

            mac = pkt[Ether].src.lower()
            with self._hostnames_lock:
                self._hostnames[mac] = hostname

        def stop_filter(pkt):
            return not self._running

        sniff(
            iface=self.interface,
            filter='udp and (port 67 or port 68)',
            prn=pkt_handler,
            stop_filter=stop_filter,
            store=0
        )
