import csv
import io
import ipaddress
import logging
import os
import re
import socket
import sqlite3
from datetime import datetime, timezone

import requests
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


def load_config(config_path="config.yaml"):
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_acl(allowed_sources):
    """Parses config.yaml's network.allowed_sources list (individual IPs or
    CIDR ranges, e.g. "10.0.0.5" or "10.0.0.0/24") into ip_network objects
    for fast membership checks in is_source_allowed(). A bare IP is treated
    as a /32 (or /128) via strict=False, the same as any CIDR tool would.

    An entry that doesn't parse is logged and skipped, rather than crashing
    startup over a typo in an otherwise-working config. If every entry
    turns out invalid (or the list is empty), that would silently drop all
    real firewall traffic with no obvious cause - worse than the permissive
    default it replaced - so this falls back to 0.0.0.0/0 (trust everyone)
    in that case and logs loudly about it, rather than failing closed and
    silent."""
    allowed_sources = allowed_sources or []
    networks = []
    for entry in allowed_sources:
        try:
            networks.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError:
            logging.error(f"Ignoring invalid network.allowed_sources entry: {entry!r}")
    if not networks:
        logging.error(
            "network.allowed_sources has no valid entries - falling back to "
            "0.0.0.0/0 (trust every source IP) rather than silently dropping "
            "all syslog traffic. Fix config.yaml to restrict this."
        )
        networks = [ipaddress.ip_network("0.0.0.0/0")]
    return networks


def is_source_allowed(src_ip, acl):
    """True if src_ip (a dotted-quad string, as given by socket.recvfrom's
    address tuple) falls inside any network in acl. Any parse failure of
    src_ip itself (shouldn't happen - it comes from the OS socket layer,
    not attacker-controlled) is treated as not allowed, failing closed."""
    try:
        ip_obj = ipaddress.ip_address(src_ip)
    except ValueError:
        return False
    return any(ip_obj in network for network in acl)


def init_db(db_path):
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")

    # One aggregate row per User-Agent + traffic direction + reporting
    # firewall (device_serial). Multiple firewalls can each report the same
    # UA/direction pair independently - that's what makes the dashboard's
    # per-device view and fleet-wide "All" aggregation both possible.
    # The latest matching syslog event is retained for investigation.
    conn.execute('''
        CREATE TABLE IF NOT EXISTS user_agents (
            user_agent TEXT NOT NULL,
            direction TEXT NOT NULL CHECK(direction IN ('ingress', 'egress')),
            device_serial TEXT NOT NULL DEFAULT 'unknown',
            device_name TEXT,
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            last_src_ip TEXT,
            last_dst_ip TEXT,
            last_action TEXT,
            last_url TEXT,
            url_category TEXT,
            last_raw_payload TEXT,
            hit_count INTEGER DEFAULT 1,
            PRIMARY KEY (user_agent, direction, device_serial)
        );
    ''')

    # Schema migration for databases created by earlier versions. NOTE: this
    # only adds new COLUMNS - it can't change an existing table's PRIMARY KEY
    # from (user_agent, direction) to (user_agent, direction, device_serial).
    # A database created before this multi-firewall version needs to be
    # deleted (or moved aside) once, so CREATE TABLE above can build it fresh
    # with the new key; after that, this migration list is what carries
    # forward any columns added in later versions without another rebuild.
    for column, col_type in [
        ("device_serial", "TEXT NOT NULL DEFAULT 'unknown'"),
        ("device_name", "TEXT"),
        ("last_src_ip", "TEXT"),
        ("last_dst_ip", "TEXT"),
        ("last_action", "TEXT"),
        ("last_url", "TEXT"),
        ("url_category", "TEXT"),
        ("last_raw_payload", "TEXT"),
        ("hit_count", "INTEGER DEFAULT 1"),
    ]:
        try:
            conn.execute(f"ALTER TABLE user_agents ADD COLUMN {column} {col_type};")
        except sqlite3.OperationalError:
            pass

    return conn


def sanitize_for_chat(text):
    """Google Chat interprets a small markup syntax in message text -
    *bold*, _italic_, ~strike~, `code`, and <url|label> links. Every value
    this function is applied to (user_agent, device_name, action, the IPs)
    comes straight from an unauthenticated UDP syslog packet - nothing
    validates that a PAN-OS firewall actually sent it - so a crafted packet
    could otherwise alter an alert's formatting or embed a misleading
    clickable link inside what looks like this app's own notification.
    Swaps the characters that trigger that markup for visually similar but
    inert lookalikes, rather than stripping them outright, so the alert
    stays readable and still shows what was actually received."""
    if not text:
        return text
    for bad, safe in (
        ("*", "∗"), ("_", "‗"), ("~", "∼"), ("`", "'"),
        ("<", "‹"), (">", "›"), ("|", "¦"),
    ):
        text = text.replace(bad, safe)
    return text


def send_gchat_alert(webhook_url, ua, direction, src_ip, dst_ip, action, timestamp, device_name=None):
    if not webhook_url:
        return

    ua = sanitize_for_chat(ua)
    action = sanitize_for_chat(action)
    src_ip = sanitize_for_chat(src_ip)
    dst_ip = sanitize_for_chat(dst_ip)
    device_name = sanitize_for_chat(device_name)

    device_line = f"• *Firewall:* `{device_name}`\n" if device_name else ""
    payload = {
        "text": (
            f"🚨 *New {direction.capitalize()} User-Agent Detected* 🚨\n"
            f"{device_line}"
            f"• *Time (UTC):* {timestamp}\n"
            f"• *Action:* `{action}`\n"
            f"• *Src IP:* `{src_ip}`\n"
            f"• *Dst IP:* `{dst_ip}`\n"
            f"• *User-Agent:* `{ua}`"
        )
    }

    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception as e:
        logging.error(f"Failed to send GChat webhook alert: {e}")


def determine_direction(src_zone, dst_zone, config):
    """internal_zones is NOT a config list - a zone counts as internal
    simply by NOT appearing in external_zones. That's deliberate: internal
    zone naming is the part that tends to vary per site across a fleet
    (LAN, Users, Servers, VLAN10, ...), while external_zones is a small,
    stable set worth maintaining by hand - so it's the only list a config
    author has to keep in sync as new firewalls come online, rather than
    an internal list that would need a new entry every time a site's
    internal segment naming differs even slightly.

    This also handles DMZ/partner/semi-trusted zones correctly with zero
    extra config, as a natural consequence of the binary "external vs.
    everything else" split rather than anything DMZ-specific: a DMZ zone
    is simply never in external_zones, so DMZ->external_zones traffic
    counts as egress (an outbound-from-DMZ signal, worth catching) and
    external_zones->DMZ counts as ingress (inbound to a DMZ-hosted
    service - typically the most security-relevant ingress traffic there
    is), while DMZ<->internal traffic lands in neither rule (both sides
    are "not external") and stays unclassified - same as it's always
    been, not a regression, and without inventing a third direction value
    that would ripple into the database schema, the dashboard's tiles,
    and its charts."""
    external = {z.lower() for z in config["zones"].get("external_zones", [])}
    src, dst = src_zone.lower(), dst_zone.lower()

    src_is_external = src in external
    dst_is_external = dst in external

    if not src_is_external and dst_is_external:
        return "egress"
    if src_is_external and not dst_is_external:
        return "ingress"
    return None


def extract_csv_payload(data):
    # PAN-OS syslog messages commonly contain a prefix before the CSV payload.
    match = re.search(r"(?:^|\s|:)(\d{1,5},\d{4}/\d{2}/\d{2}.*)", data)
    if match:
        return match.group(1)

    first_comma = data.find(",")
    if first_comma != -1:
        start_idx = max(
            data.rfind(" ", 0, first_comma),
            data.rfind(":", 0, first_comma),
        )
        return data[start_idx + 1:] if start_idx != -1 else data

    return data


def safe_field(fields, index, default=""):
    try:
        return fields[index].strip('"\' ')
    except IndexError:
        return default


def process_syslog(raw_data_bytes, conn, config):
    raw_str = raw_data_bytes.decode("utf-8", errors="ignore")
    csv_string = extract_csv_payload(raw_str)

    try:
        reader = csv.reader(io.StringIO(csv_string))
        fields = next(reader)
    except Exception as e:
        logging.error(f"Dropped [Parse Error]: {e}")
        return

    log_fmt = config["log_format"]

    try:
        log_type = safe_field(fields, log_fmt["type_index"]).lower()
        log_subtype = safe_field(fields, log_fmt["subtype_index"]).lower()

        # URL filtering logs are represented as THREAT/url in the documented CSV format.
        if log_type not in ["threat", "url"]:
            return

        src_ip = safe_field(fields, log_fmt["src_ip_index"])
        dst_ip = safe_field(fields, log_fmt["dst_ip_index"])
        src_zone = safe_field(fields, log_fmt["src_zone_index"])
        dst_zone = safe_field(fields, log_fmt["dst_zone_index"])
        user_agent = safe_field(fields, log_fmt["user_agent_index"])
        action = safe_field(fields, log_fmt["action_index"], "unknown")
        last_url = safe_field(fields, 31)
        url_category = safe_field(fields, 33)
        # Every PAN-OS syslog self-identifies its sending firewall by Serial
        # Number and Device Name - no manual per-firewall config needed.
        # device_serial is the DB's stable key (a hostname can be renamed;
        # the serial can't); device_name is what the dashboard displays.
        # Falls back to "unknown" only for logs missing the field entirely
        # (e.g. a non-standard forwarder), which buckets them together
        # rather than dropping them.
        device_serial = safe_field(fields, log_fmt.get("device_serial_index", 2)) or "unknown"
        device_name = safe_field(fields, log_fmt.get("device_name_index", 59)) or device_serial

        if not user_agent or user_agent.lower() == "unknown":
            return

    except Exception as e:
        logging.error(f"Dropped [Field Parse Error]: {e}")
        return

    direction = determine_direction(src_zone, dst_zone, config)
    if not direction:
        return

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    try:
        cursor = conn.cursor()

        cursor.execute(
            '''
            INSERT INTO user_agents (
                user_agent,
                direction,
                device_serial,
                device_name,
                first_seen,
                last_seen,
                last_src_ip,
                last_dst_ip,
                last_action,
                last_url,
                url_category,
                last_raw_payload,
                hit_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(user_agent, direction, device_serial) DO UPDATE SET
                device_name = excluded.device_name,
                last_seen = excluded.last_seen,
                last_src_ip = excluded.last_src_ip,
                last_dst_ip = excluded.last_dst_ip,
                last_action = excluded.last_action,
                last_url = excluded.last_url,
                url_category = excluded.url_category,
                last_raw_payload = excluded.last_raw_payload,
                hit_count = user_agents.hit_count + 1
            RETURNING hit_count
            ''',
            (
                user_agent,
                direction,
                device_serial,
                device_name,
                now,
                now,
                src_ip,
                dst_ip,
                action,
                last_url,
                url_category,
                raw_str,
            ),
        )

        result = cursor.fetchone()

        # hit_count == 1 means this INSERT created the row (the ON CONFLICT
        # branch always increments it past 1). An earlier version compared
        # first_seen == last_seen instead - but those only have one-second
        # resolution, so a brand-new UA sending two requests within its
        # first second (a browser loading one page, typically) looked
        # "new" twice and fired a duplicate alert.
        if result and result[0] == 1:
            # "New" is now scoped per firewall: the same UA/direction
            # showing up for the first time on a DIFFERENT device fires
            # again, deliberately - "first time this UA hit THIS firewall"
            # is meaningful fleet-visibility information on its own.
            logging.info(
                f"SUCCESS: New {direction.upper()} UA recorded: "
                f"{user_agent} | device={device_name} ({device_serial}) | "
                f"action={action} | subtype={log_subtype}"
            )
            send_gchat_alert(
                config["alerts"]["gchat_webhook_url"],
                user_agent,
                direction,
                src_ip,
                dst_ip,
                action,
                now,
                device_name=device_name,
            )

    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")


def main():
    config = load_config()
    # SENTRY_UA_DB_PATH (if set) overrides config.yaml - mainly for
    # containers, where the database lives on a mounted volume. The
    # dashboard honors the same variable, so both always agree.
    db_path = os.environ.get("SENTRY_UA_DB_PATH", "").strip() or config["database"]["db_path"]
    ip = config["network"]["listen_ip"]
    port = config["network"]["listen_port"]
    acl = build_acl(config["network"].get("allowed_sources", ["0.0.0.0/0"]))
    logging.info(f"Syslog source ACL: {[str(n) for n in acl]}")

    conn = init_db(db_path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    logging.info(f"Listening for Palo Alto UDP syslog on {ip}:{port}...")

    while True:
        data, addr = sock.recvfrom(8192)
        src_ip = addr[0]
        if not is_source_allowed(src_ip, acl):
            # Dropped before any parsing - the whole point of the ACL is to
            # keep an unauthenticated/untrusted source from reaching the
            # CSV/regex work at all, not just from having its data used.
            logging.warning(f"Dropped [ACL]: syslog packet from {src_ip} not in allowed_sources")
            continue
        if data:
            process_syslog(data, conn, config)


if __name__ == "__main__":
    main()
