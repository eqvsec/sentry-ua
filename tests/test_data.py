"""sentry_ua.data: the dashboard's read-only data layer, run against real
databases written by the collector's own process_syslog()."""
import sqlite3

import pytest

import palo_ua_tracker as t
from sentry_ua import data
from sentry_ua.demo import build_url_log


def ingest(conn, config, **kwargs):
    t.process_syslog(build_url_log(**kwargs), conn, config)


def set_times(conn, ua, serial, first, last, hits=None):
    conn.execute(
        "UPDATE user_agents SET first_seen = ?, last_seen = ?, hit_count = COALESCE(?, hit_count) "
        "WHERE user_agent = ? AND device_serial = ?",
        (first, last, hits, ua, serial),
    )


@pytest.fixture
def fleet(conn, config, no_alerts):
    """UA seen on two firewalls with different details, plus a second UA
    on one firewall only."""
    ingest(conn, config, user_agent="UA-1", device_serial="S1", device_name="fw-one",
           dst_ip="203.0.113.1", action="alert", url="one.example.com/")
    ingest(conn, config, user_agent="UA-1", device_serial="S2", device_name="fw-two",
           dst_ip="203.0.113.2", action="block-url", url="two.example.com/")
    ingest(conn, config, user_agent="UA-2", device_serial="S1", device_name="fw-one")
    set_times(conn, "UA-1", "S1", "2026-01-01 00:00:00", "2026-03-01 00:00:00", hits=10)
    set_times(conn, "UA-1", "S2", "2026-02-01 00:00:00", "2026-04-01 00:00:00", hits=5)
    set_times(conn, "UA-2", "S1", "2026-01-15 00:00:00", "2026-01-20 00:00:00", hits=1)
    return conn


EXPECTED_COLUMNS = [
    "User-Agent", "Hit Count", "Direction", "Last Action", "Last URL", "URL Category",
    "Last Src IP", "Last Dst IP", "First Seen (UTC)", "Last Seen (UTC)", "Raw Payload",
    "Device Serial", "Device Name",
]


def test_all_firewalls_aggregates_totals_and_takes_latest_details(fleet, db_path):
    df = data.load_data(db_path)
    assert list(df.columns) == EXPECTED_COLUMNS
    assert list(df["User-Agent"]) == ["UA-1", "UA-2"]  # newest last_seen first
    row = df.iloc[0]
    assert row["Hit Count"] == 15                                  # summed
    assert row["First Seen (UTC)"] == "2026-01-01 00:00:00"        # earliest anywhere
    assert row["Last Seen (UTC)"] == "2026-04-01 00:00:00"         # latest anywhere
    # Every detail field comes from the most recent reporter (S2).
    assert row["Device Serial"] == "S2"
    assert row["Device Name"] == "fw-two"
    assert row["Last Action"] == "block-url"
    assert row["Last Dst IP"] == "203.0.113.2"
    assert row["Last URL"] == "two.example.com/"


def test_single_firewall_scope(fleet, db_path):
    df = data.load_data(db_path, "S1")
    assert sorted(df["User-Agent"]) == ["UA-1", "UA-2"]
    ua1 = df[df["User-Agent"] == "UA-1"].iloc[0]
    assert ua1["Hit Count"] == 10
    assert ua1["Last Action"] == "alert"
    assert list(data.load_data(db_path, "S2")["User-Agent"]) == ["UA-1"]
    assert data.load_data(db_path, "NOPE").empty


def test_device_serial_is_a_bound_parameter(fleet, db_path):
    # A crafted value in the ?device= query param must be data, not SQL.
    assert data.load_data(db_path, "S1' OR '1'='1").empty


def test_load_devices_uses_latest_name_and_sorts(conn, config, no_alerts, db_path):
    ingest(conn, config, user_agent="UA", device_serial="S1", device_name="zeta")
    ingest(conn, config, user_agent="UA", device_serial="S2", device_name="Alpha")
    devices = data.load_devices(db_path)
    assert list(devices["Device Name"]) == ["Alpha", "zeta"]  # case-insensitive sort
    # A rename shows up as soon as new traffic arrives.
    ingest(conn, config, user_agent="UA", device_serial="S1", device_name="renamed")
    devices = data.load_devices(db_path)
    assert dict(zip(devices["Device Serial"], devices["Device Name"]))["S1"] == "renamed"


def test_load_devices_falls_back_to_serial_for_blank_name(conn, db_path):
    conn.execute(
        "INSERT INTO user_agents (user_agent, direction, device_serial, device_name, first_seen, last_seen) "
        "VALUES ('UA', 'egress', 'S9', '  ', 'x', 'x')"
    )
    assert list(data.load_devices(db_path)["Device Name"]) == ["S9"]


def test_empty_database(conn, db_path):
    assert data.load_data(db_path).empty
    assert data.load_devices(db_path).empty


def test_legacy_database_without_device_or_url_columns(tmp_path):
    """A pre-multi-firewall DB: the dashboard should still load it, and
    recover Last URL / URL Category from the stored raw payload."""
    path = str(tmp_path / "legacy.db")
    raw = build_url_log(user_agent="UA", url="legacy.example.com/p", category="news").decode()
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE user_agents (user_agent TEXT, direction TEXT, first_seen TEXT, last_seen TEXT, "
        "last_src_ip TEXT, last_dst_ip TEXT, last_action TEXT, last_raw_payload TEXT, hit_count INTEGER)"
    )
    conn.execute(
        "INSERT INTO user_agents VALUES ('UA', 'egress', 'a', 'b', '10.0.0.1', '203.0.113.1', 'alert', ?, 3)",
        (raw,),
    )
    conn.commit()
    conn.close()

    df = data.load_data(path)
    assert list(df.columns) == EXPECTED_COLUMNS
    row = df.iloc[0]
    assert row["Last URL"] == "legacy.example.com/p"
    assert row["URL Category"] == "news"
    assert row["Device Serial"] == "" and row["Device Name"] == ""
    assert data.load_devices(path).empty


def test_connection_is_read_only(conn, db_path):
    ro = data.get_db_connection(db_path)
    try:
        with pytest.raises(sqlite3.OperationalError):
            ro.execute("DELETE FROM user_agents")
    finally:
        ro.close()


def test_missing_database_raises_instead_of_creating_one(tmp_path):
    path = tmp_path / "does-not-exist.db"
    with pytest.raises(sqlite3.OperationalError):
        data.load_data(str(path))
    assert not path.exists()


def test_relative_db_path_resolves_against_cwd(fleet, db_path, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert len(data.load_data("user_agents.db")) == 2


def test_path_with_uri_special_characters(tmp_path, config, no_alerts):
    # (No "?" - Windows forbids it in file names.)
    odd_dir = tmp_path / "dir with spaces #hash %25pct"
    odd_dir.mkdir()
    path = str(odd_dir / "ua.db")
    conn = t.init_db(path)
    ingest(conn, config, user_agent="UA")
    conn.close()
    assert list(data.load_data(path)["User-Agent"]) == ["UA"]


# --- raw payload field extraction ---------------------------------------------

def test_extract_fields_from_raw_payload():
    raw = build_url_log(
        user_agent="UA", url="x.example.com/a,b", category="news",
        rule_name="rule-1", source_user="corp\\jdoe", application="web-browsing",
    ).decode()
    # The prefix stays in the stored payload; field positions are what the
    # dashboard has always relied on for these, so check them as-is.
    assert data.extract_raw_field(raw, data.PANOS_RULE_NAME_INDEX) == "rule-1"
    assert data.extract_raw_field(raw, data.PANOS_SOURCE_USER_INDEX) == "corp\\jdoe"
    assert data.extract_raw_field(raw, data.PANOS_APPLICATION_INDEX) == "web-browsing"
    assert data.extract_url_from_raw(raw) == "x.example.com/a,b"
    assert data.extract_url_category_from_raw(raw) == "news"


@pytest.mark.parametrize("raw", [None, "", "a,b,c", "\x00"])
def test_extract_from_short_or_empty_payload(raw):
    assert data.extract_url_from_raw(raw) == ""
    assert data.extract_url_category_from_raw(raw) == ""
    assert data.extract_raw_field(raw, 14) == ""


def test_demo_database_shape(demo_db):
    df = data.load_data(demo_db)
    devices = data.load_devices(demo_db)
    assert len(devices) == 3
    assert set(df["Direction"]) == {"egress", "ingress"}
    assert (df["Hit Count"] > 0).all()
    # Demo data must stay in reserved/documentation space.
    for url in df["Last URL"]:
        host = url.split("/", 1)[0]
        assert host.endswith((".example.com", ".example.org", ".example.net", "example.com")) or host.startswith("198.51.100.")
