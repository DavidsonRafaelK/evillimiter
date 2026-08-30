---
name: Bug report
about: Something in evillimiter doesn't work right
title: ''
labels: bug
assignees: ''
---

**evillimiter version and OS**
Output of `evillimiter --version`, or the commit hash if you're on a checkout. Distro and kernel version too, this stuff is very Linux-network-stack-specific.

**Command(s) you ran**
Paste the exact command(s), including flags. Not a paraphrase.

**What happened vs. what you expected**


**Full error output / traceback**
Wrap it in a code block. Don't trim it "because it looked repetitive", the repeated part is often the useful part.

```
paste here
```

**Anything unusual about your network**
VPN active, double NAT, IPv6-only network, unusual gateway config, mesh router with band-steered subnets, MAC-randomizing devices involved, managed switch with DAI, etc. Half the reports here turn out to be network topology, not code.

**Did you already check the README's Restrictions section?**
It lists known limitations (IPv6 fallback behavior, MAC randomization, cellular fallback, VLAN visibility, DAI). If your issue matches one of those, it's expected behavior, not a bug.
