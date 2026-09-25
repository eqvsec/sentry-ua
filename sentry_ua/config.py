"""config.yaml loading, dashboard defaults, and the source-IP allow-list
helpers the dashboard's access gate is built on.

No Streamlit here. dashboard.py still owns the gate itself
(_check_dashboard_acl(), which reads st.context.ip_address and renders the
"Access Denied" page) - this module only holds the parsing/membership
logic, moved out unchanged so it can be tested on its own.
"""
import ipaddress
import os

import yaml

CONFIG_PATH = "config.yaml"

# Environment override for the SQLite path, honored by both the collector
# (palo_ua_tracker.py) and the dashboard. Mainly for containers, where the
# database lives on a mounted volume rather than next to the code; when
# unset, config.yaml's database.db_path is used as always.
DB_PATH_ENV_VAR = "SENTRY_UA_DB_PATH"
DEFAULT_DB_PATH = "user_agents.db"

REFRESH_OPTIONS = {
    5: "5s",
    10: "10s",
    15: "15s",
    30: "30s",
    60: "60s",
    120: "120s",
}
DEFAULT_REFRESH_SECONDS = 120


def load_config(config_path=CONFIG_PATH):
    """Parsed config.yaml as a dict ({} for an empty file). Raises OSError
    or yaml.YAMLError - callers decide whether a missing/broken config is
    fatal (the collector) or something to tolerate (the dashboard)."""
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def resolve_db_path(config):
    """SENTRY_UA_DB_PATH if set, else config.yaml's database.db_path, else
    user_agents.db. Relative paths resolve against the working directory,
    the same way the collector has always opened it."""
    env_value = (os.environ.get(DB_PATH_ENV_VAR) or "").strip()
    if env_value:
        return env_value
    database = (config or {}).get("database", {}) or {}
    return str(database.get("db_path") or DEFAULT_DB_PATH)


def load_dashboard_defaults(config_path=CONFIG_PATH):
    """Server-wide default refresh interval from config.yaml. This is a
    single fallback value the same for every visitor - not a per-user
    preference - so it's fine for it to live in a file on the server."""
    try:
        config = load_config(config_path)
        dashboard = config.get("dashboard", {}) or {}
        value = int(dashboard.get("refresh_seconds", DEFAULT_REFRESH_SECONDS))
        return value if value in REFRESH_OPTIONS else DEFAULT_REFRESH_SECONDS
    except (OSError, TypeError, ValueError, AttributeError, yaml.YAMLError):
        return DEFAULT_REFRESH_SECONDS


def build_ip_acl(allowed_sources):
    """Mirrors palo_ua_tracker.py's build_acl() - parses config.yaml's
    individual-IP/CIDR entries into ip_network objects, skipping anything
    that fails to parse, and falling back to 0.0.0.0/0 if nothing valid is
    left - a config typo should not be able to silently lock everyone out
    of the dashboard with no obvious cause.

    Returns (networks, invalid_entries). Reporting the invalid entries is
    left to the caller (dashboard.py shows them via st.warning, since it
    runs inside the Streamlit app rather than a script with its own log
    stream)."""
    networks = []
    invalid = []
    for entry in (allowed_sources or []):
        try:
            networks.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError:
            invalid.append(entry)
    if not networks:
        networks = [ipaddress.ip_network("0.0.0.0/0")]
    return networks, invalid


def is_ip_allowed(client_ip, acl):
    """True if client_ip falls inside any network in acl. A value that
    doesn't parse as an IP address is treated as not allowed (fails
    closed). Callers handle the "no IP reported at all" case (None, which
    Streamlit reports for localhost) before calling this."""
    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(ip_obj in network for network in acl)
