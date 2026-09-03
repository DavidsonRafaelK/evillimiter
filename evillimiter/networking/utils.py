import re
import socket
import struct
import netifaces
from scapy.all import ARP, sr1 # pylint: disable=no-name-in-module

import evillimiter.console.shell as shell
from evillimiter.common.globals import BIN_TC, BIN_IPTABLES, BIN_SYSCTL, IP_FORWARD_LOC


def get_default_interface():
    """
    Returns the default IPv4 interface
    """
    gateways = netifaces.gateways()
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        return gateways['default'][netifaces.AF_INET][1]


def get_default_gateway():
    """
    Returns the default IPv4 gateway address
    """
    gateways = netifaces.gateways()
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        return gateways['default'][netifaces.AF_INET][0]


def get_default_gateway_ipv6():
    """
    Returns the default IPv6 gateway address (usually link-local),
    or None if the network has no IPv6 default route.
    """
    gateways = netifaces.gateways()
    if 'default' in gateways and netifaces.AF_INET6 in gateways['default']:
        return gateways['default'][netifaces.AF_INET6][0]


def get_default_netmask(interface):
    """
    Returns the default IPv4 netmask associated to an interface 
    """
    ifaddrs = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in ifaddrs:
        return ifaddrs[netifaces.AF_INET][0].get('netmask')


def get_interface_mac(interface):
    """
    Returns the hardware (MAC) address of a local interface
    """
    ifaddrs = netifaces.ifaddresses(interface)
    if netifaces.AF_LINK in ifaddrs:
        return ifaddrs[netifaces.AF_LINK][0].get('addr')


def get_mac_by_ip(interface, address):
    """
    Resolves hardware address from IP by sending ARP request
    and receiving ARP response
    """
    # ARP packet with operation 1 (who-is)
    packet = ARP(op=1, pdst=address)
    response = sr1(packet, timeout=3, verbose=0, iface=interface)

    if response is not None:
        return response.hwsrc


def get_hostname(ip):
    """
    Resolves the hostname of a device by its IP address.
    Tries reverse DNS first, then falls back to a NetBIOS
    node status query (works for most Windows/SMB devices),
    then to an mDNS PTR query (works for most Apple/Linux/IoT
    devices advertising a '.local' name via Bonjour/Avahi).
    """
    try:
        host_info = socket.gethostbyaddr(ip)
        if host_info is not None and host_info[0] and host_info[0] != ip:
            return host_info[0]
    except (socket.herror, socket.gaierror, OSError):
        pass

    name = get_netbios_name(ip)
    if name:
        return name

    return get_mdns_name(ip)


def get_netbios_name(ip, timeout=1):
    """
    Sends a NetBIOS node status request (NBSTAT) to UDP port 137
    and parses the first non-group name from the response.
    Returns the hostname or None on failure.
    """
    # NBSTAT query for the wildcard name '*'
    query = struct.pack('>H', 0x0000)               # transaction id
    query += struct.pack('>H', 0x0010)              # flags (broadcast)
    query += struct.pack('>HHHH', 1, 0, 0, 0)       # qd, an, ns, ar counts
    # encoded wildcard name '*' padded to 16 bytes
    encoded = b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    query += struct.pack('B', len(encoded)) + encoded + b'\x00'
    query += struct.pack('>HH', 0x0021, 0x0001)     # type NBSTAT, class IN

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()

    try:
        # skip header (12) + question echo; number of names at fixed offset
        names_offset = 56
        num_names = data[names_offset]
        offset = names_offset + 1
        for _ in range(num_names):
            name = data[offset:offset + 15].decode('ascii', 'ignore').strip()
            flags = struct.unpack('>H', data[offset + 15:offset + 17])[0]
            offset += 18
            # bit 15 set => group name; skip groups, return first unique name
            if not (flags & 0x8000) and name:
                return name
    except (IndexError, struct.error):
        pass

    return None


def get_mdns_name(ip, timeout=1):
    """
    Sends a unicast mDNS PTR query for the reverse-IP name directly
    to the host's port 5353 and parses the first PTR answer.
    Resolves devices (Apple, Linux/Avahi, many IoT gadgets) that
    advertise a '.local' name via mDNS but have no reverse DNS or
    NetBIOS entry.
    """
    labels = list(reversed(ip.split('.'))) + ['in-addr', 'arpa']
    qname = b''.join(struct.pack('B', len(l)) + l.encode('ascii') for l in labels) + b'\x00'

    query = struct.pack('>HHHHHH', 0x0000, 0x0000, 1, 0, 0, 0)  # id, flags, qd/an/ns/ar counts
    query += qname
    query += struct.pack('>HH', 12, 1)  # QTYPE=PTR, QCLASS=IN

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (ip, 5353))
        data, _ = sock.recvfrom(1024)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()

    try:
        ancount = struct.unpack('>H', data[6:8])[0]
        if ancount == 0:
            return None

        offset = 12 + len(qname) + 4  # skip header + echoed question

        for _ in range(ancount):
            _, offset = _read_dns_name(data, offset)
            rtype, _, _, rdlength = struct.unpack('>HHIH', data[offset:offset + 10])
            offset += 10

            if rtype == 12:  # PTR
                name, _ = _read_dns_name(data, offset)
                return name.rstrip('.') if name else None

            offset += rdlength
    except (IndexError, struct.error):
        pass

    return None


def _read_dns_name(data, offset):
    """
    Reads a (possibly compressed, per RFC 1035 4.1.4) DNS name
    starting at offset. Returns (name, offset_after_field), where
    offset_after_field is the offset immediately following the
    name/pointer as it appeared at the call site (i.e. not inside
    a followed pointer's target).
    """
    labels = []
    jumped = False
    return_offset = offset

    while True:
        length = data[offset]

        if length == 0:
            offset += 1
            if not jumped:
                return_offset = offset
            break

        if (length & 0xC0) == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                return_offset = offset + 2
            offset = pointer
            jumped = True
            continue

        offset += 1
        labels.append(data[offset:offset + length].decode('ascii', 'ignore'))
        offset += length

    return '.'.join(labels), return_offset


def exists_interface(interface):
    """
    Determines whether or not a given interface exists
    """
    return interface in netifaces.interfaces()


def flush_network_settings(interface):
    """
    Flushes all iptable rules and traffic control entries
    related to the given interface
    """
    # reset default policy
    shell.execute_suppressed('{} -P INPUT ACCEPT'.format(BIN_IPTABLES))
    shell.execute_suppressed('{} -P OUTPUT ACCEPT'.format(BIN_IPTABLES))
    shell.execute_suppressed('{} -P FORWARD ACCEPT'.format(BIN_IPTABLES))

    # flush all chains in all tables (including user-defined)
    shell.execute_suppressed('{} -t mangle -F'.format(BIN_IPTABLES))
    shell.execute_suppressed('{} -t nat -F'.format(BIN_IPTABLES))
    shell.execute_suppressed('{} -F'.format(BIN_IPTABLES))
    shell.execute_suppressed('{} -X'.format(BIN_IPTABLES))

    # delete root qdisc for given interface
    shell.execute_suppressed('{} qdisc del dev {} root'.format(BIN_TC, interface))


def validate_ip_address(ip):
    return re.match(r'^(\d{1,3}\.){3}(\d{1,3})$', ip) is not None


def validate_mac_address(mac):
    return re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac) is not None


def create_qdisc_root(interface):
    """
    Creates a root htb qdisc in traffic control for a given interface
    """
    return shell.execute_suppressed('{} qdisc add dev {} root handle 1:0 htb'.format(BIN_TC, interface)) == 0


def delete_qdisc_root(interface):
    return shell.execute_suppressed('{} qdisc del dev {} root handle 1:0 htb'.format(BIN_TC, interface))


def enable_ip_forwarding():
    return shell.execute_suppressed('{} -w {}=1'.format(BIN_SYSCTL, IP_FORWARD_LOC)) == 0


def disable_ip_forwarding():
    return shell.execute_suppressed('{} -w {}=0'.format(BIN_SYSCTL, IP_FORWARD_LOC)) == 0


class InvalidBitRate(ValueError):
    """Raised when a bitrate string can't be parsed (bad/missing unit)."""


class InvalidByteValue(ValueError):
    """Raised when a byte-size string can't be parsed (bad/missing unit)."""


def format_netem(delay=None, loss=None, sep=' '):
    """
    Formats tc-netem delay/loss into a string, omitting whichever is
    None. sep is ' ' for tc qdisc args ('delay 100ms loss 5%') or
    ', ' for display ('delay 100ms, loss 5%').
    """
    parts = []
    if delay is not None:
        parts.append('delay {}ms'.format(delay))
    if loss is not None:
        parts.append('loss {}%'.format(loss))
    return sep.join(parts)


class ValueConverter:
    @staticmethod
    def byte_to_bit(v):
        return v * 8


class _ScaledValue(object):
    """
    Shared base for BitRate/ByteValue: a magnitude formatted with
    unit-scaling and parsed from a "<number><unit>" string. Subclasses
    only declare the base, the ordered unit list (low->high), the parse
    factor map, and the exception raised on a bad unit.
    """
    _base = None
    _units = ()
    _unit_factors = {}
    _invalid_exc = ValueError

    def __init__(self, amount=0):
        self._amount = amount

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        v = self._amount
        for unit in self._units:
            if v < self._base:
                return '{}{}'.format(int(v), unit)
            v /= self._base
        raise Exception('{} limit exceeded'.format(type(self).__name__))

    def fmt(self, fmt):
        string = self.__str__()
        end = len([c for c in string if c.isdigit()])
        num = int(string[:end])
        return '{}{}'.format(fmt % num, string[end:])

    @classmethod
    def _parse(cls, string):
        number = 0  # magnitude
        offset = 0  # index where the unit starts
        for c in string:
            if c.isdigit():
                number = number * 10 + int(c)
                offset += 1
            else:
                break

        unit = string[offset:].lower()
        if unit in cls._unit_factors:
            return number * cls._unit_factors[unit]
        raise cls._invalid_exc(string)


class BitRate(_ScaledValue):
    _base = 1000
    _units = ('bit', 'kbit', 'mbit', 'gbit')
    _unit_factors = {'bit': 1, 'kbit': 1000, 'mbit': 1000 ** 2, 'gbit': 1000 ** 3}
    _invalid_exc = InvalidBitRate

    def __init__(self, rate=0):
        super().__init__(rate)

    @property
    def rate(self):
        return self._amount

    def __mul__(self, other):
        if isinstance(other, BitRate):
            return BitRate(int(self._amount * other._amount))
        return BitRate(int(self._amount * other))

    @classmethod
    def from_rate_string(cls, rate_string):
        return cls(cls._parse(rate_string))


class ByteValue(_ScaledValue):
    _base = 1024
    _units = ('b', 'kb', 'mb', 'gb', 'tb')
    _unit_factors = {'b': 1, 'kb': 1024, 'mb': 1024 ** 2, 'gb': 1024 ** 3, 'tb': 1024 ** 4}
    _invalid_exc = InvalidByteValue

    def __init__(self, value=0):
        super().__init__(value)

    @property
    def value(self):
        return self._amount

    def __int__(self):
        return self._amount

    def __add__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self._amount + other._amount))
        return ByteValue(int(self._amount + other))

    def __sub__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self._amount - other._amount))
        return ByteValue(int(self._amount - other))

    def __mul__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self._amount * other._amount))
        return ByteValue(int(self._amount * other))

    def __ge__(self, other):
        if isinstance(other, ByteValue):
            return self._amount >= other._amount
        return self._amount >= other

    @classmethod
    def from_byte_string(cls, byte_string):
        return cls(cls._parse(byte_string))
