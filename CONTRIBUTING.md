# Contributing to Evil Limiter

Thanks for your interest in improving Evil Limiter. This document covers the ground rules for contributing, how to file a good issue, and how to submit a pull request.

By participating in this project you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ground rules

- **Scope**: Evil Limiter is a defensive/educational network administration tool. Only propose changes that help someone monitor, analyze, or limit bandwidth on a network they own or are authorized to manage. Features aimed at evading detection, attacking third-party networks, or otherwise abusing the tool will not be merged.
- **Platform**: the project targets Linux with Python 3.7+. Don't add hard dependencies on other operating systems.
- **No secrets**: never commit credentials, API keys, real IP/MAC addresses beyond documentation examples, or other sensitive data.
- **Licensing**: contributions are accepted under the project's [MIT License](LICENSE). By opening a pull request you agree your contribution is licensed under the same terms.
- **One topic per change**: keep issues and pull requests focused on a single bug, feature, or question. Unrelated changes make review slower and history harder to follow.

## Filing an issue

Before opening a new issue, search existing [issues](https://github.com/bitbrute/evillimiter/issues) (open and closed) to avoid duplicates.

### Bug reports

Include:

- Evil Limiter version (`evillimiter --version` or the release/commit you're on) and OS/distribution.
- Exact command(s) you ran.
- Expected behavior vs. what actually happened.
- Full error output/traceback, if any (wrap it in a ``` code block).
- Anything unusual about your network setup that might be relevant (VPN, unusual gateway config, IPv6-only network, etc.).

### Feature requests

Include:

- The problem you're trying to solve, not just the solution you have in mind.
- Why existing commands/flags don't already cover it.
- Whether you're able to help implement it.

### Security issues

Do not open a public issue for a security vulnerability. Follow the reporting process in the [Code of Conduct](CODE_OF_CONDUCT.md) instead and contact the maintainers privately.

## Submitting a pull request

1. **Discuss first for anything non-trivial.** For bug fixes and small improvements, feel free to open a PR directly. For new features or behavioral changes, open an issue first so the approach can be agreed on before you invest time.
2. **Fork and branch.** Branch off `master` with a descriptive name (e.g. `fix/ipv6-gateway-detection`, `feat/ndp-spoofing`).
3. **Set up a dev environment:**
   ```bash
   git clone https://github.com/<your-fork>/evillimiter.git
   cd evillimiter
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e .
   ```
4. **Match the existing code style.** No enforced linter/formatter currently runs in CI — follow the conventions already present in the file you're editing (naming, docstrings, import grouping).
5. **Add or update tests.** Tests live in `tests/` and use the standard library `unittest`. Add a test for new behavior and update existing tests your change affects.
6. **Run the test suite before submitting:**
   ```bash
   python3 -m unittest discover tests
   ```
7. **Update documentation.** If your change adds/modifies a command, flag, or user-visible behavior, update `README.md` (and `CHANGELOG.md` if the project is tracking one for the next release).
8. **Write a clear commit history.** Commit messages should explain *why*, not just *what*. Squash trivial fixup commits before opening the PR.
9. **Open the PR against `master`** with:
   - A summary of what changed and why.
   - How you tested it (commands run, network conditions, manual verification if the change touches spoofing/traffic shaping and can't be fully unit-tested).
   - Any related issue number (`Fixes #123`).

### Review process

- A maintainer will review your PR and may request changes. Please respond to feedback rather than opening a new PR for the same change.
- PRs touching spoofing (`spoof.py`, `ndp_spoof.py`), traffic shaping (`limit.py`), or anything that runs with root privileges receive extra scrutiny — expect questions about safety, cleanup on exit/failure, and blast radius.
- Once approved, a maintainer will merge the PR. Contributors do not merge their own PRs.

## Questions

If anything here is unclear, open an issue with the `question` label (or start a discussion, if enabled on the repository) rather than guessing.
