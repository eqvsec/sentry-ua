"""sentry_ua.config: config loading, DB path resolution, refresh default,
and the dashboard allow-list helpers."""
import ipaddress

import pytest
import yaml

from conftest import REPO_ROOT
from sentry_ua import config as c


def write(tmp_path, text):
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_shipped_config_yaml_is_valid_and_defaults_are_permissive():
    cfg = c.load_config(str(REPO_ROOT / "config.yaml"))
    # These defaults are documented (README/SECURITY.md/config comments) -
    # changing them is a security-posture change, not a refactor.
    assert cfg["network"]["allowed_sources"] == ["0.0.0.0/0"]
    assert cfg["dashboard"]["allowed_sources"] == ["0.0.0.0/0"]
    assert cfg["https"]["enabled"] is False
    assert cfg["alerts"]["gchat_webhook_url"] == ""
    assert cfg["dashboard"]["refresh_seconds"] in c.REFRESH_OPTIONS


def test_load_config_empty_file_is_empty_dict(tmp_path):
    assert c.load_config(write(tmp_path, "")) == {}


def test_load_config_errors_propagate(tmp_path):
    with pytest.raises(OSError):
        c.load_config(str(tmp_path / "missing.yaml"))
    with pytest.raises(yaml.YAMLError):
        c.load_config(write(tmp_path, "a: [unclosed"))


# --- db path --------------------------------------------------------------------

def test_resolve_db_path_precedence(monkeypatch):
    monkeypatch.delenv(c.DB_PATH_ENV_VAR, raising=False)
    assert c.resolve_db_path({}) == "user_agents.db"
    assert c.resolve_db_path(None) == "user_agents.db"
    assert c.resolve_db_path({"database": None}) == "user_agents.db"
    assert c.resolve_db_path({"database": {"db_path": "custom.db"}}) == "custom.db"
    monkeypatch.setenv(c.DB_PATH_ENV_VAR, "/data/from-env.db")
    assert c.resolve_db_path({"database": {"db_path": "custom.db"}}) == "/data/from-env.db"
    monkeypatch.setenv(c.DB_PATH_ENV_VAR, "   ")
    assert c.resolve_db_path({"database": {"db_path": "custom.db"}}) == "custom.db"


# --- refresh default ------------------------------------------------------------

@pytest.mark.parametrize(
    "text, expected",
    [
        ("dashboard:\n  refresh_seconds: 30\n", 30),
        ("dashboard:\n  refresh_seconds: '15'\n", 15),
        ("dashboard:\n  refresh_seconds: 7\n", c.DEFAULT_REFRESH_SECONDS),   # not an offered option
        ("dashboard:\n  refresh_seconds: fast\n", c.DEFAULT_REFRESH_SECONDS),
        ("dashboard:\n  refresh_seconds: [1]\n", c.DEFAULT_REFRESH_SECONDS),
        ("dashboard:\n", c.DEFAULT_REFRESH_SECONDS),
        ("", c.DEFAULT_REFRESH_SECONDS),
        ("- just\n- a list\n", c.DEFAULT_REFRESH_SECONDS),
        ("a: [unclosed", c.DEFAULT_REFRESH_SECONDS),
    ],
)
def test_load_dashboard_defaults(tmp_path, text, expected):
    assert c.load_dashboard_defaults(write(tmp_path, text)) == expected


def test_load_dashboard_defaults_missing_file(tmp_path):
    assert c.load_dashboard_defaults(str(tmp_path / "nope.yaml")) == c.DEFAULT_REFRESH_SECONDS


# --- dashboard.allowed_sources --------------------------------------------------

def test_build_ip_acl_reports_invalid_entries_and_keeps_valid_ones():
    acl, invalid = c.build_ip_acl(["10.0.0.5", "bogus", "192.168.0.0/16", 12])
    assert acl == [ipaddress.ip_network("10.0.0.5/32"), ipaddress.ip_network("192.168.0.0/16")]
    assert invalid == ["bogus", 12]


@pytest.mark.parametrize("entries", [None, [], ["bogus"]])
def test_build_ip_acl_never_locks_everyone_out(entries):
    acl, _ = c.build_ip_acl(entries)
    assert acl == [ipaddress.ip_network("0.0.0.0/0")]


@pytest.mark.parametrize(
    "client_ip, expected",
    [
        ("10.0.0.5", True),
        ("192.168.44.1", True),
        ("10.0.0.6", False),
        ("::1", False),              # IPv6 client vs IPv4-only list
        ("garbage", False),          # fails closed
        ("", False),
    ],
)
def test_is_ip_allowed(client_ip, expected):
    acl, _ = c.build_ip_acl(["10.0.0.5", "192.168.0.0/16"])
    assert c.is_ip_allowed(client_ip, acl) is expected


def test_is_ip_allowed_rejects_non_string_objects():
    # What Streamlit's AppTest hands back for st.context.ip_address - any
    # non-IP value must be denied, never treated as allowed.
    acl, _ = c.build_ip_acl(["0.0.0.0/0"])
    assert c.is_ip_allowed(object(), acl) is False


def test_dashboard_acl_matches_collector_acl_semantics():
    """The two allow-lists are documented as the same format/behavior."""
    import palo_ua_tracker

    entries = ["10.0.0.5", "not-valid", "172.16.0.0/12", "203.0.113.7/24"]
    dash_acl, _ = c.build_ip_acl(entries)
    assert dash_acl == palo_ua_tracker.build_acl(entries)
    for ip in ["10.0.0.5", "10.0.0.6", "172.20.1.1", "203.0.113.200", "8.8.8.8", "x"]:
        assert c.is_ip_allowed(ip, dash_acl) == palo_ua_tracker.is_source_allowed(ip, dash_acl)
