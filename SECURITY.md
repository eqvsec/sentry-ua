# Security Policy

Sentry UA is a solo, community-maintained project. There's no bug bounty and no SLA, but vulnerability reports are taken seriously and will get a response.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.** Report it privately instead, whichever you prefer:

- **GitHub private vulnerability reporting** (preferred): the repository's **Security** tab → **Report a vulnerability**. The report stays private between you and the maintainer, and a fix can be coordinated in a private advisory.
- DM [@eqv_sec on X](https://x.com/eqv_sec)

Please include:
- A description of the issue and its potential impact.
- Steps to reproduce, or a proof of concept if you have one.
- The version (see `APP_VERSION` in `sentry_ua/__init__.py`, or the version shown in the app's Settings dialog / page footer) and, if relevant, whether it's the dashboard (`dashboard.py`) or the syslog collector (`palo_ua_tracker.py`).

You should get an initial response within a few days. Once a fix is available, credit will be given in the release notes unless you'd prefer to stay anonymous — just say so in your report.

## Scope and known-by-design tradeoffs

A few things are architectural tradeoffs rather than bugs, worth knowing before reporting them:

- **The UDP syslog listener has no built-in authentication.** PAN-OS syslog itself has no authentication mechanism, so this is inherent to the protocol, not something this app can add on the wire. Mitigate with `config.yaml`'s `network.allowed_sources` (an IP/CIDR allow-list) and a host firewall/ACL restricting the listener to your actual firewalls.
- **The dashboard has no built-in login.** It's intended for a trusted internal network. `config.yaml`'s `dashboard.allowed_sources` adds a best-effort source-IP allow-list, but it's built on `st.context.ip_address`, which Streamlit's own docs say "should not be used for security measures because it can easily be spoofed" - and it stops working correctly if a reverse proxy ever sits in front of the dashboard (every connection then appears to come from the proxy's IP). Put it behind a reverse proxy with real authentication if it needs to be reachable more broadly; a host firewall/ACL is the unspoofable version of the source-IP restriction.
- **Under Docker, both allow-lists depend on how the container's ports are published.** Docker Desktop (Windows/macOS) and rootless Docker rewrite client source IPs to a Docker-internal gateway address, so neither allow-list can tell real clients apart there; and on Linux, published ports bypass host-firewall INPUT rules (e.g. `ufw`). See the README's [Docker](README.md#docker) section for what to do instead (host networking on Linux, or the `DOCKER-USER` chain).

Reports about any of the above design tradeoffs are still welcome if you see a way to meaningfully improve on them within the app itself — just not as a "no auth at all" finding on its own, since that's documented behavior.

## Supported versions

Only the latest released version is supported. Please upgrade before reporting an issue that may already be fixed.
