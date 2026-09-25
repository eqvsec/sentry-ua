"""Data-loading layer: read-only SQLite access to the collector's
user_agents table, shaped into the DataFrames the dashboard renders,
plus best-effort field extraction from a stored raw syslog payload.

No Streamlit here - dashboard.py wraps load_devices()/load_data() in
st.cache_data itself, so this layer stays importable and testable
against a plain temporary database."""
import csv
import io
import pathlib
import sqlite3

import pandas as pd


def get_db_connection(db_path):
    """Read-only connection (mode=ro) - the dashboard never writes; the
    collector is the database's only writer. The path is resolved to an
    absolute file: URI so it behaves the same whether db_path came from
    config.yaml as a relative or an absolute path."""
    uri = pathlib.Path(db_path).resolve().as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def load_devices(db_path):
    """Every firewall that has reported telemetry, one row per device_serial
    (the DB's stable key), paired with the most recently reported
    device_name for that serial - so a hostname rename shows up here as soon
    as new traffic arrives, with no separate device-registry table needed.
    Powers the Panorama-style firewall selector. Returns an empty frame
    (not an error) against a pre-multi-firewall database that doesn't have
    these columns yet."""
    conn = get_db_connection(db_path)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(user_agents)").fetchall()}
        if "device_serial" not in columns:
            return pd.DataFrame(columns=["Device Serial", "Device Name", "Last Seen"])
        query = """
            SELECT
                device_serial AS "Device Serial",
                device_name AS "Device Name",
                MAX(last_seen) AS "Last Seen"
            FROM user_agents
            GROUP BY device_serial
        """
        devices = pd.read_sql_query(query, conn)
    finally:
        conn.close()
    devices["Device Name"] = devices["Device Name"].fillna("").astype(str).str.strip()
    blank_name = devices["Device Name"].eq("")
    devices.loc[blank_name, "Device Name"] = devices.loc[blank_name, "Device Serial"]
    return devices.sort_values("Device Name", key=lambda s: s.str.casefold()).reset_index(drop=True)


def load_data(db_path, device_serial=None):
    conn = get_db_connection(db_path)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(user_agents)").fetchall()}
        last_url_expr = 'last_url AS "Last URL"' if "last_url" in columns else "'' AS \"Last URL\""
        url_category_expr = 'url_category AS "URL Category"' if "url_category" in columns else "'' AS \"URL Category\""
        has_device_cols = "device_serial" in columns
        device_serial_expr = 'device_serial AS "Device Serial"' if has_device_cols else "'' AS \"Device Serial\""
        device_name_expr = 'device_name AS "Device Name"' if has_device_cols else "'' AS \"Device Name\""

        if has_device_cols and device_serial:
            # Scoped to one firewall - every row is already unique per
            # (User-Agent, Direction) within that device, so this is a
            # plain select, the same shape the query had before multi-
            # firewall support existed.
            query = f"""
                SELECT
                    user_agent AS "User-Agent",
                    hit_count AS "Hit Count",
                    direction AS "Direction",
                    last_action AS "Last Action",
                    {last_url_expr},
                    {url_category_expr},
                    last_src_ip AS "Last Src IP",
                    last_dst_ip AS "Last Dst IP",
                    first_seen AS "First Seen (UTC)",
                    last_seen AS "Last Seen (UTC)",
                    last_raw_payload AS "Raw Payload",
                    {device_serial_expr},
                    {device_name_expr}
                FROM user_agents
                WHERE device_serial = ?
                ORDER BY last_seen DESC
            """
            df = pd.read_sql_query(query, conn, params=(device_serial,))
        elif has_device_cols:
            # "All Firewalls" - Panorama-style fleet-wide aggregation, one
            # row per (User-Agent, Direction) across every device: Hit Count
            # is the SUM across all firewalls that have seen it, First/Last
            # Seen span the earliest and latest any firewall saw it, and
            # every other detail field (action, URL, IPs, device identity,
            # raw payload) is taken from whichever single firewall most
            # recently reported that exact UA+direction pair - the agreed
            # design: fleet-wide totals, single-device-worth of investigation
            # detail, rather than trying to merge details from many devices.
            query = """
                WITH ranked AS (
                    SELECT *,
                        ROW_NUMBER() OVER (
                            PARTITION BY user_agent, direction
                            ORDER BY last_seen DESC
                        ) AS rn
                    FROM user_agents
                ),
                totals AS (
                    SELECT
                        user_agent,
                        direction,
                        SUM(hit_count) AS hit_count,
                        MIN(first_seen) AS first_seen,
                        MAX(last_seen) AS last_seen
                    FROM user_agents
                    GROUP BY user_agent, direction
                )
                SELECT
                    totals.user_agent AS "User-Agent",
                    totals.hit_count AS "Hit Count",
                    totals.direction AS "Direction",
                    ranked.last_action AS "Last Action",
                    ranked.last_url AS "Last URL",
                    ranked.url_category AS "URL Category",
                    ranked.last_src_ip AS "Last Src IP",
                    ranked.last_dst_ip AS "Last Dst IP",
                    totals.first_seen AS "First Seen (UTC)",
                    totals.last_seen AS "Last Seen (UTC)",
                    ranked.last_raw_payload AS "Raw Payload",
                    ranked.device_serial AS "Device Serial",
                    ranked.device_name AS "Device Name"
                FROM totals
                JOIN ranked
                    ON ranked.user_agent = totals.user_agent
                    AND ranked.direction = totals.direction
                    AND ranked.rn = 1
                ORDER BY totals.last_seen DESC
            """
            df = pd.read_sql_query(query, conn)
        else:
            # Pre-multi-firewall database (device columns don't exist yet) -
            # identical to the query this app used before this feature.
            query = f"""
                SELECT
                    user_agent AS "User-Agent",
                    hit_count AS "Hit Count",
                    direction AS "Direction",
                    last_action AS "Last Action",
                    {last_url_expr},
                    {url_category_expr},
                    last_src_ip AS "Last Src IP",
                    last_dst_ip AS "Last Dst IP",
                    first_seen AS "First Seen (UTC)",
                    last_seen AS "Last Seen (UTC)",
                    last_raw_payload AS "Raw Payload",
                    {device_serial_expr},
                    {device_name_expr}
                FROM user_agents
                ORDER BY last_seen DESC
            """
            df = pd.read_sql_query(query, conn)
    finally:
        conn.close()
    for col in ("Last URL", "URL Category", "Device Serial", "Device Name"):
        if col not in df.columns:
            df[col] = ""
    missing_url = df["Last URL"].fillna("").astype(str).str.strip().eq("")
    missing_cat = df["URL Category"].fillna("").astype(str).str.strip().eq("")
    if "Raw Payload" in df.columns:
        if missing_url.any():
            df.loc[missing_url, "Last URL"] = df.loc[missing_url, "Raw Payload"].map(extract_url_from_raw)
        if missing_cat.any():
            df.loc[missing_cat, "URL Category"] = df.loc[missing_cat, "Raw Payload"].map(extract_url_category_from_raw)
    return df


def extract_url_from_raw(raw_payload):
    if not raw_payload:
        return ""
    try:
        fields = next(csv.reader(io.StringIO(str(raw_payload))))
        return fields[31].strip("\"' ") if len(fields) > 31 else ""
    except Exception:
        return ""


def extract_url_category_from_raw(raw_payload):
    if not raw_payload:
        return ""
    try:
        fields = next(csv.reader(io.StringIO(str(raw_payload))))
        return fields[33].strip("\"' ") if len(fields) > 33 else ""
    except Exception:
        return ""


# PAN-OS URL Filtering log field indexes (0-based), verified against:
# https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/url-filtering-log-fields
# These line up with the ones already in config.yaml (src_ip=7, dst_ip=8,
# src_zone=16, dst_zone=17, action=30, user_agent=46) and with the URL (31)
# and Category (33) indexes already used above.
PANOS_RULE_NAME_INDEX = 11
PANOS_SOURCE_USER_INDEX = 12
PANOS_APPLICATION_INDEX = 14


def extract_raw_field(raw_payload, index):
    """Best-effort extraction of a single field from the raw syslog CSV
    payload, by position. Used for the inspector-dialog-only fields (Rule
    Name, Source User, Application) that aren't worth precomputing as DB
    columns for every row up front."""
    if not raw_payload:
        return ""
    try:
        fields = next(csv.reader(io.StringIO(str(raw_payload))))
        return fields[index].strip("\"' ") if len(fields) > index else ""
    except Exception:
        return ""
