import logging
import warnings

# scapy imports Blowfish and CAST5, which the cryptography package now
# deprecates; drop those warnings before scapy is imported downstream.
warnings.filterwarnings('ignore', message=r'.*(Blowfish|CAST5).*')

# Silence scapy's runtime warning emitted on every spoofed is-at ARP reply
# (op=2 sent at layer 3 without an explicit Ethernet destination MAC).
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

# scapy warns that 'iface' has no effect on layer-3 send()/sr1() calls; the
# routing table already selects the correct interface, so drop the noise.
warnings.filterwarnings('ignore', message=r".*'iface' has no effect on L3 I/O.*")

__version__ = '1.6.0'
__description__ = 'Monitors, analyzes and limits the bandwidth of devices on the local network'