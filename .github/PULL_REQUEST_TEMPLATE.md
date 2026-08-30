**What changed and why**
Not just what the diff does, why it needs to exist. Link the issue if there is one (`Fixes #123`).

**How you tested it**
Commands you ran, network conditions, manual verification. If this touches spoofing, traffic shaping, or anything running as root and you can't fully unit-test it, say what you checked by hand instead of just "ran the test suite".

**Checklist**
- [ ] `python3 -m unittest discover tests` passes locally
- [ ] Added/updated tests for the behavior this changes (not required for pure docs/typo fixes)
- [ ] Updated README.md if this adds/changes a command, flag, or user-visible behavior
- [ ] Updated CHANGELOG if the project is tracking one for the next release
- [ ] One topic per PR, no drive-by unrelated changes mixed in

**Heads up if this touches**
`spoof.py`, `ndp_spoof.py`, `limit.py`, or anything else that runs with root privileges: expect questions about cleanup on exit/failure and blast radius. That's not a knock on the PR, those files get read more carefully because a bug there means a stuck iptables rule or a spoofed host that never gets freed.
