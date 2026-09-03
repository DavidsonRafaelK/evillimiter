<p align="center"><img src="https://raw.githubusercontent.com/DavidsonRafaelK/evillimiter/master/docs/images/logo.png" alt="Evil Limiter" width="500" /></p>

# Evil Limiter

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.7+-brightgreen.svg)](pyproject.toml)
[![CI](https://github.com/DavidsonRafaelK/evillimiter/actions/workflows/tests.yml/badge.svg)](https://github.com/DavidsonRafaelK/evillimiter/actions/workflows/tests.yml)
[![Latest release](https://img.shields.io/github/v/release/DavidsonRafaelK/evillimiter)](https://github.com/DavidsonRafaelK/evillimiter/releases)
[![Last commit](https://img.shields.io/github/last-commit/DavidsonRafaelK/evillimiter)](https://github.com/DavidsonRafaelK/evillimiter/commits/master)
[![GitHub stars](https://img.shields.io/github/stars/DavidsonRafaelK/evillimiter)](https://github.com/DavidsonRafaelK/evillimiter/stargazers)

> This project is a maintained fork of [bitbrute/evillimiter](https://github.com/bitbrute/evillimiter). The upstream repository is no longer maintained, so this fork continues development - bug fixes, new features, and compatibility updates. See [Fork-specific changes](#fork-specific-changes) below.

A tool to monitor, analyze and limit the bandwidth (upload/download) of devices on your local network without physical or administrative access.<br>
```evillimiter``` employs [ARP spoofing](https://en.wikipedia.org/wiki/ARP_spoofing) and [traffic shaping](https://en.wikipedia.org/wiki/Traffic_shaping) to throttle the bandwidth of hosts on the network. On IPv6-enabled networks, [NDP spoofing](https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Vulnerabilities) is used alongside ARP spoofing to also cut off a host's IPv6 traffic, which would otherwise bypass the IPv4-only limit/block.

**Searching for a Windows-compatible version?**<br>
Check out the open-source alternative [EvilLimiter for Windows](https://github.com/bitbrute/evillimiter-windows).

> Only run this against a network you own or have written permission to test. ARP and NDP spoofing disrupts other people's traffic by design, and doing it to a network you don't control is illegal in most places.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Restrictions](#restrictions)
- [Fork-specific changes](#fork-specific-changes)
- [Contributing](#contributing)

## Requirements
- Linux distribution
- Python 3.7 or newer

Possibly missing python packages will be installed during the installation process.

#### Compatibility notes

```evillimiter``` locates ```tc```, ```iptables``` and ```sysctl``` via ```PATH``` at startup and errors clearly if one is missing. It shells out to the ```iptables``` binary specifically - on distros where ```iptables``` is an ```iptables-nft``` compatibility shim this generally works, but a firewall managed purely through native ```nft``` rules with no ```iptables``` shim installed is not something this tool talks to.

## Installation

```bash
git clone https://github.com/DavidsonRafaelK/evillimiter.git
cd evillimiter
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

Run it with ```sudo``` (raw sockets, ```iptables```/```tc``` need root) - it's the run that needs root, not the install:

```bash
sudo .venv/bin/evillimiter
```

Note: ```sudo python3 setup.py install``` (the old instructions) is deprecated in modern setuptools and often fails outright with ```ModuleNotFoundError: No module named 'setuptools'``` - ```sudo``` runs the system Python, which usually doesn't have setuptools installed, unlike the venv's own Python that ```pip``` manages for you. On distros that enforce [PEP 668](https://peps.python.org/pep-0668/) (Arch, Debian 12+, ...), installing outside a venv is blocked entirely for this reason.

Alternatively, you can download a desired version from the [Release page](https://github.com/DavidsonRafaelK/evillimiter/releases).<br>

## Usage

Type ```evillimiter``` or ```python3 bin/evillimiter``` to run the tool.

```evillimiter``` will try to resolve required information (network interface, netmask, gateway address, ...) on its own, automatically.

<p align="center"><img src="https://raw.githubusercontent.com/DavidsonRafaelK/evillimiter/master/docs/images/screenshot.png" alt="evillimiter running in a terminal" width="800" /></p>

#### Command-Line Arguments

| Argument | Explanation |
| -------- | ----------- |
| ```-h``` | Displays help message listing all command-line arguments |
| ```-i [Interface Name]``` | Specifies network interface (resolved if not specified)|
| ```-g [Gateway IP Address]``` | Specifies gateway IP address (resolved if not specified)|
| ```-m [Gateway MAC Address]``` | Specifies gateway MAC address (resolved if not specified)|
| ```-n [Netmask Address]``` | Specifies netmask (resolved if not specified)|
| ```-f``` | Flushes current iptables and tc configuration. Ensures that packets are dealt with correctly.|
| ```--colorless``` | Disables colored output |
| ```-l [File Path]```, ```--log-file [File Path]``` | Also appends every ok/error message to this file (plain text, no color codes). |
| ```--version``` | Prints the installed version and exits. |

#### Config file

Any of the flags above (except ```-f```/```--flush```, which is a one-shot action, not a persisted preference) can be given a default in an optional ini file at ```~/.config/evillimiter/config.ini``` (or ```$XDG_CONFIG_HOME/evillimiter/config.ini```). A command-line flag always overrides the config file.

```ini
[general]
interface = wlan0
colorless = true
auto_scan = true
log_file = /var/log/evillimiter.log

[watch]
interval = 30
range = 192.168.1.1-192.168.1.50
```

```[watch]``` sets the initial values normally set at runtime via ```watch set interval```/```watch set range``` (see below), so they don't need to be re-entered every session.

```auto_scan``` (opt-in, off by default) runs ```scan``` then ```hosts``` automatically right after startup, so you don't have to type them every session.

#### ```evillimiter``` Commands

| Command | Explanation |
| ------- | ----------- |
| ```scan (--range [IP Range]) (--intensity [1,2,3])``` | Scans your network for online hosts. One of the first things to do after start.<br>```--range``` lets you specify a custom IP range.<br>```--intensity``` trades speed for thoroughness: ```1``` quick, ```2``` normal (default), ```3``` intense (more retries/longer timeout, useful on lossy networks). Sticky until changed again - also applies to `watch`'s background reconnect scans.<br>For example: ```scan --range 192.168.178.1-192.168.178.40``` or just ```scan``` to scan the entire subnet.
| ```hosts (--force)``` | Displays all the hosts/devices previously scanned and basic information. Shows ID for each host that is required for interaction.<br>```--force``` forces the table to be shown, even when it doesn't fit the terminal.
| ```limit [ID1,ID2,...] [Rate] (--upload) (--download)``` | Limits bandwidth of host(s) associated to specified ID. Rate determines the internet speed. Host(s) are automatically added to the watchlist.<br>```--upload``` limits outgoing traffic only.<br>```--download``` limits incoming traffic only.<br>Valid rates: ```bit```, ```kbit```, ```mbit```, ```gbit```<br>Rate can also be ```up/down``` (e.g. ```200kbit/1mbit```) for independent upload/download rates - only valid with both directions (no ```--upload```/```--download```).<br>For example: ```limit 4,5,6 200kbit``` or ```limit all 1gbit``` or ```limit 4 200kbit/1mbit```
| ```block [ID1,ID2,...] (--upload) (--download)``` | Blocks internet connection of host(s) associated to specified ID. Host(s) are automatically added to the watchlist.<br>```--upload``` limits outgoing traffic only <br>```--download``` limits incoming traffic only.
| ```netem [ID1,ID2,...] (--delay [ms]) (--loss [%]) (--clear)``` | Emulates packet delay/loss on host(s) - **requires the host to already be `limit`ed**, since it attaches to the existing rate-limit tc class. Attaches to whichever direction(s) the host is limited in; no separate direction flag.<br>```--clear``` removes netem while leaving the rate limit in place.<br>For example: ```netem 4 --delay 200ms --loss 10%``` or ```netem 4 --clear```
| ```free [ID1,ID2,...]``` | Unlimits/Unblocks host(s) associated to specified ID. Removes all further restrictions.
| ```add [IP] (--mac [MAC])``` | Adds custom host to host list. MAC-Address will be resolved automatically or can be specified manually.<br>For example: ```add 192.168.178.24``` or ```add 192.168.1.50 --mac 1c:fc:bc:2d:a6:37```
| ```monitor (--interval [time in ms])``` | Monitors bandwidth usage of every discovered host, not just limited/blocked ones (current usage, total bandwidth used, ...).<br>```--interval``` sets the interval after bandwidth information get refreshed in milliseconds (default 500ms).<br>For example: ```monitor --interval 1000```
| ```analyze [ID1,ID2,...] (--duration [time in s])``` | Analyzes traffic of host(s) without limiting to determine who uses how much bandwidth.<br>```--duration``` specifies the duration of the analysis in seconds (default 30s).<br>For example: ```analyze 2,3 --duration 120```
| ```watch``` | Shows current watch status, including each watched host's Online/Offline state as of the last scan sweep. The watch feature detects when a host reconnects with a different IP address.<br>Hosts are added to the watchlist automatically upon ```limit``` or ```block```.
| ```watch add [ID1,ID2,...]``` | Adds specified host(s) to the watchlist.<br>For example: ```watch add 6,7,8```
| ```watch remove [ID1,ID2,...]``` | Removes specified host(s) from the watchlist.<br>For example: ```watch remove all```
| ```watch set [Attribute] [Value]``` | Changes current watch settings. The following attributes can be changed:<br>```range``` is the IP range to scan for reconnects.<br>```interval``` is the time to wait between each network scan (in seconds).<br>For example: ```watch set interval 120```
| ```clear``` | Clears the terminal window.
| ```quit``` | Quits the application.
| ```?```, ```help``` | Displays command information similar to this one.

## Restrictions

- **Rate-limits IPv4 traffic only**, since [ARP spoofing](https://en.wikipedia.org/wiki/ARP_spoofing) requires the ARP packet that is only present on IPv4 networks. On networks with an IPv6 default route, a host's IPv6 traffic is instead fully blocked via NDP spoofing rather than rate-limited, since the ```tc```/```iptables``` rules that shape traffic are IPv4-only.
- **Cellular fallback defeats it.** A blocked/limited phone can just switch to LTE/5G once WiFi degrades (Android "avoid poor connections", iOS equivalents) - that traffic never touches your network at all.
- **MAC-randomizing devices reappear as a new host on reconnect.** Many phones present a different MAC per network join by default, so ```watch``` (matches by MAC) can't follow them; the old restriction is left bound to a MAC/IP nobody uses anymore. Such addresses are flagged as ```(random)``` in the ```hosts``` table (their locally-administered bit is set) so you can spot a device likely to reappear under a new identity.
- **Already-open connections can straggle.** A stream/download in progress doesn't always re-resolve the gateway's address mid-flight, so it can keep flowing on a stale ARP/NDP cache entry until it naturally resets - new connections are caught immediately.
- **Devices on a different subnet/VLAN are invisible.** Band-steering mesh systems that split 2.4GHz/5GHz onto separate subnets can let a host roam outside the scanned IP range entirely.
- **A second network path bypasses it.** A device that also has Ethernet (mainly laptops, not phones) can switch to it and land on an untouched segment.
- **Managed switches with Dynamic ARP Inspection can block the spoofing outright.** Irrelevant on typical home routers, matters on corporate/enterprise networks.

## Fork-specific changes

Everything below was added in this fork, on top of upstream's last release (v1.5.0):

- IPv6 (NDP) spoofing, so `limit`/`block` also cover a host's IPv6 traffic instead of only IPv4
- Optional config file (`~/.config/evillimiter/config.ini`) for default flags and watch settings
- `-l`/`--log-file` to persist ok/error messages to a file
- `--version` flag
- mDNS/NetBIOS/DHCP hostname fallback when reverse DNS fails
- `block` now also blocks the `INPUT`/`OUTPUT` chains (traffic to/from this machine itself), not just `FORWARD`
- `watch` now shows each watched host's Online/Offline status and auto-watches hosts on `limit`/`block`
- Host tracking keyed off MAC address instead of IP (fixes reconnect detection and a hash/equality bug)
- `limit`/`block` report `tc`/`iptables` failures instead of silently claiming success
- Fixed a false-positive/duplicate-command bug in restriction teardown for combined upload+download limits/blocks
- Fixed `ByteValue` formatting for totals in the terabyte range
- CI running the test suite on every push/PR
- Shell command history persisted across sessions (`~/.config/evillimiter/history`), navigable with ↑/↓
- `hosts` table shows the assigned rate/direction for limited/blocked hosts, instead of just "Limited"/"Blocked"
- `scan --intensity [1,2,3]` to trade scan speed for thoroughness (quick/normal/intense)
- `auto_scan` config option to run `scan` then `hosts` automatically at startup
- `monitor` tracks every discovered host, not just limited/blocked ones
- `limit` accepts `up/down` rates (e.g. `200kbit/1mbit`) for independent upload/download limits in one call
- `netem [ID] --delay [ms] --loss [%]` to emulate packet delay/loss on an already-limited host (`--clear` to remove it)

See [CHANGELOG](CHANGELOG) for the full version history, including upstream's.

## Contributing

Want to report a bug, request a feature, or submit a pull request? See [CONTRIBUTING.md](CONTRIBUTING.md) for the rules on filing issues and opening PRs. Please also read the [Code of Conduct](CODE_OF_CONDUCT.md).

## Disclaimer
[Evil Limiter](https://github.com/DavidsonRafaelK/evillimiter) - originally created by [bitbrute](https://github.com/bitbrute), now maintained by [DavidsonRafaelK](https://github.com/DavidsonRafaelK) - is provided "as is" and "with all faults". Neither the original author nor the current maintainer makes any representations or warranties of any kind concerning the safety, suitability, lack of viruses, inaccuracies, typographical errors, or other harmful components of this software. There are inherent dangers in the use of any software, and you are solely responsible for determining whether Evil Limiter is compatible with your equipment and other software installed on your equipment. You are also solely responsible for the protection of your equipment and backup of your data, and neither party will be liable for any damages you may suffer in connection with using, modifying, or distributing this software.

## License

Copyright (c) 2019-2026 by [bitbrute](https://github.com/bitbrute), copyright (c) 2026 by [DavidsonRafaelK](https://github.com/DavidsonRafaelK) for fork-specific changes. Some rights reserved.<br>
[Evil Limiter](https://github.com/DavidsonRafaelK/evillimiter) is licensed under the MIT License as stated in the [LICENSE file](LICENSE).