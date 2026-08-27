import logging

# Silence scapy's runtime warning emitted on every spoofed is-at ARP reply
# (op=2 sent at layer 3 without an explicit Ethernet destination MAC).
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

__version__ = '1.5.0'
__description__ = 'Monitors, analyzes and limits the bandwidth of devices on the local network'