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


def get_default_netmask(interface):
    """
    Returns the default IPv4 netmask associated to an interface 
    """
    ifaddrs = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in ifaddrs:
        return ifaddrs[netifaces.AF_INET][0].get('netmask')


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
    node status query (works for most Windows/SMB devices on
    a LAN where reverse DNS is unavailable).
    """
    try:
        host_info = socket.gethostbyaddr(ip)
        if host_info is not None and host_info[0]:
            return host_info[0]
    except (socket.herror, socket.gaierror, OSError):
        pass

    return get_netbios_name(ip)


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


class ValueConverter:
    @staticmethod
    def byte_to_bit(v):
        return v * 8


class BitRate(object):
    def __init__(self, rate=0):
        self.rate = rate

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        counter = 0
        r = self.rate

        while True:
            if r >= 1000:
                r /= 1000
                counter += 1
            else:
                unit = ''
                if counter == 0:
                    unit = 'bit'
                elif counter == 1:
                    unit = 'kbit'
                elif counter == 2:
                    unit = 'mbit'
                elif counter == 3:
                    unit = 'gbit'
                
                return '{}{}'.format(int(r), unit)
            
            if counter > 3:
                raise Exception('Bitrate limit exceeded')

    def __mul__(self, other):
        if isinstance(other, BitRate):
            return BitRate(int(self.rate * other.rate))
        return BitRate(int(self.rate * other))

    def fmt(self, fmt):
        string = self.__str__()
        end = len([_ for _ in string if _.isdigit()])
        num = int(string[:end])
    
        return '{}{}'.format(fmt % num, string[end:])

    @classmethod
    def from_rate_string(cls, rate_string):
        return cls(BitRate._bit_value(rate_string))

    @staticmethod
    def _bit_value(rate_string):
        number = 0  # rate number
        offset = 0  # string offset

        for c in rate_string:
            if c.isdigit():
                number = number * 10 + int(c)
                offset += 1
            else:
                break

        unit = rate_string[offset:].lower()

        if unit == 'bit':
            return number
        elif unit == 'kbit':
            return number * 1000
        elif unit == 'mbit':
            return number * 1000 ** 2
        elif unit == 'gbit':
            return number * 1000 ** 3
        else:
            raise Exception('Invalid bitrate')


class ByteValue(object):
    def __init__(self, value=0):
        self.value = value

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        counter = 0
        v = self.value

        while True:
            if v >= 1024:
                v /= 1024
                counter += 1
            else:
                unit = ''
                if counter == 0:
                    unit = 'b'
                elif counter == 1:
                    unit = 'kb'
                elif counter == 2:
                    unit = 'mb'
                elif counter == 3:
                    unit = 'gb'
                elif counter == 4:
                    unit = 'tb'
                
                return '{}{}'.format(int(v), unit)

            if counter > 4:
                raise Exception('Byte value limit exceeded')

    def __int__(self):
        return self.value

    def __add__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self.value + other.value))
        return ByteValue(int(self.value + other))

    def __sub__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self.value - other.value))
        return ByteValue(int(self.value - other))

    def __mul__(self, other):
        if isinstance(other, ByteValue):
            return ByteValue(int(self.value * other.value))
        return ByteValue(int(self.value * other))

    def __ge__(self, other):
        if isinstance(other, ByteValue):
            return self.value >= other.value
        return self.value >= other

    def fmt(self, fmt):
        string = self.__str__()
        end = len([_ for _ in string if _.isdigit()])
        num = int(string[:end])

        return '{}{}'.format(fmt % num, string[end:])

    @classmethod
    def from_byte_string(cls, byte_string):
        return cls(ByteValue._byte_value(byte_string))

    @staticmethod
    def _byte_value(byte_string):
        number = 0  # rate number
        offset = 0  # string offset

        for c in byte_string:
            if c.isdigit():
                number = number * 10 + int(c)
                offset += 1
            else:
                break

        unit = byte_string[offset:].lower()

        if unit == 'b':
            return number
        elif unit == 'kb':
            return number * 1024
        elif unit == 'mb':
            return number * 1024 ** 2
        elif unit == 'gb':
            return number * 1024 ** 3
        elif unit == 'tb':
            return number * 1024 ** 4
        else:
            raise Exception('Invalid byte string')