# Security Policy

## Supported versions

Only the latest release on [PyPI](https://pypi.org/project/evillimiter-dk/) and the latest tag on `master` get fixes. This is a small fork maintained by one person, there's no backport branch for older versions.

## What counts as a security issue here

evillimiter needs root and does ARP/NDP spoofing plus `tc`/`iptables` manipulation on purpose. That's the tool, not a bug. Don't report "it requires root" or "it can take over other people's traffic" as a vulnerability, that's the entire point of the software and it's already covered in the README's Disclaimer and Restrictions sections.

What I do want to hear about:

- Command injection through data that ends up in a `shell.execute*()` call (interface names, hostnames resolved via DNS/mDNS/NetBIOS/DHCP, MAC addresses, IP ranges) instead of being safely parameterized.
- Anything that lets a scanned/limited host on the network escalate back into the machine running evillimiter, beyond the traffic shaping it already applies.
- Arbitrary file write/read outside the intended config/log/history paths (`~/.config/evillimiter/`), for example via a crafted `-l`/`--log-file` value or config file.
- Dependency vulnerabilities in scapy, netifaces, or netaddr that are actually reachable through how evillimiter calls them.

## Reporting

Email **davidsonrafael20@gmail.com** directly. Don't open a public GitHub issue for this, per [CONTRIBUTING.md](CONTRIBUTING.md).

Include:
- The version (`evillimiter --version`) or commit you tested against.
- Exact steps or a PoC. If it's a shell injection, show the actual payload and what ran.
- What you'd expect to happen instead.

I'll get back to you when I can. No dedicated security team, no SLA, this is maintained in spare time. If you don't hear anything after a couple weeks, a follow-up email is fine.

## Disclosure

I'd rather you hold off on public disclosure until there's a fix released, but I'm not going to chase you legally over timing. Just don't drop a 0-day on an active network monitoring/limiting tool without giving people a chance to update first.
