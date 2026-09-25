"""palo_ua_tracker.py: ACL, direction classification, CSV extraction,
ingestion/upsert, schema migration, and Google Chat alert sanitization."""
import ipaddress
import sqlite3

import pytest

import palo_ua_tracker as t
from sentry_ua.demo import build_url_log
from conftest import rows


# --- network.allowed_sources ACL -----------------------------------------------

def test_build_acl_parses_ips_and_cidrs():
    acl = t.build_acl(["10.0.0.5", "192.168.1.0/24", " 172.16.0.0/12 "])
    assert acl == [
        ipaddress.ip_network("10.0.0.5/32"),
        ipaddress.ip_network("192.168.1.0/24"),
        ipaddress.ip_network("172.16.0.0/12"),
    ]


def test_build_acl_host_bits_are_tolerated():
    # strict=False: "10.0.0.5/24" means the /24 it sits in, not an error.
    assert t.build_acl(["10.0.0.5/24"]) == [ipaddress.ip_network("10.0.0.0/24")]


def test_build_acl_skips_invalid_entries(caplog):
    acl = t.build_acl(["not-an-ip", "10.0.0.0/8", "300.1.1.1"])
    assert acl == [ipaddress.ip_network("10.0.0.0/8")]
    assert "not-an-ip" in caplog.text and "300.1.1.1" in caplog.text


@pytest.mark.parametrize("entries", [[], None, ["garbage"], ["", "nope/33"]])
def test_build_acl_falls_back_open_and_loud_when_nothing_valid(entries, caplog):
    # Documented behavior: fail open *and loud* rather than silently
    # dropping all syslog traffic because of a config typo.
    assert t.build_acl(entries) == [ipaddress.ip_network("0.0.0.0/0")]
    assert "falling back to 0.0.0.0/0" in caplog.text


@pytest.mark.parametrize(
    "src_ip, expected",
    [
        ("10.0.0.5", True),
        ("192.168.1.200", True),
        ("192.168.2.1", False),
        ("8.8.8.8", False),
        ("not-an-ip", False),  # fails closed
        ("", False),
    ],
)
def test_is_source_allowed(src_ip, expected):
    acl = t.build_acl(["10.0.0.5", "192.168.1.0/24"])
    assert t.is_source_allowed(src_ip, acl) is expected


def test_default_acl_allows_everything_ipv4():
    acl = t.build_acl(["0.0.0.0/0"])
    assert t.is_source_allowed("203.0.113.9", acl)


# --- zone -> direction ----------------------------------------------------------

# The same src/dst zone table the README says was checked by hand before
# the external-only zone model shipped.
@pytest.mark.parametrize(
    "src, dst, expected",
    [
        ("Trust", "Outside-Untrust", "egress"),       # internal -> external
        ("Outside-Untrust", "Trust", "ingress"),      # external -> internal
        ("DMZ", "Outside-Untrust", "egress"),         # DMZ -> external
        ("Outside-Untrust", "DMZ", "ingress"),        # external -> DMZ
        ("Trust", "DMZ", None),                       # internal -> DMZ
        ("DMZ", "Trust", None),                       # DMZ -> internal
        ("Trust", "Users", None),                     # internal -> internal
        ("WAN", "Internet", None),                    # external -> external
        ("Never-Seen-Before", "WAN", "egress"),       # unknown zone = inside
        ("outside-untrust", "LAN", "ingress"),        # case-insensitive
        ("LAN", "INTERNET", "egress"),
    ],
)
def test_determine_direction(src, dst, expected, config):
    assert t.determine_direction(src, dst, config) == expected


def test_determine_direction_with_no_external_zones(config):
    config["zones"] = {}
    assert t.determine_direction("Trust", "Outside-Untrust", config) is None


# --- CSV payload extraction -----------------------------------------------------

def test_extract_csv_payload_strips_syslog_prefix():
    raw = "<14>Sep 24 12:00:00 fw-01 1,2026/09/24 12:00:00,SERIAL,THREAT,url"
    assert t.extract_csv_payload(raw) == "1,2026/09/24 12:00:00,SERIAL,THREAT,url"


def test_extract_csv_payload_without_prefix():
    raw = "1,2026/09/24 12:00:00,SERIAL,THREAT,url"
    assert t.extract_csv_payload(raw) == raw


def test_extract_csv_payload_fallback_uses_last_separator_before_first_comma():
    assert t.extract_csv_payload("host: a,b,c") == "a,b,c"
    assert t.extract_csv_payload("no commas here") == "no commas here"


def test_safe_field_strips_quotes_and_defaults():
    fields = ['"quoted"', " 'x' ", "plain"]
    assert t.safe_field(fields, 0) == "quoted"
    assert t.safe_field(fields, 1) == "x"
    assert t.safe_field(fields, 99, "dflt") == "dflt"


# --- process_syslog ingestion ---------------------------------------------------

def test_new_ua_is_recorded_with_all_fields(conn, config, no_alerts):
    t.process_syslog(
        build_url_log(
            user_agent="curl/8.4.0",
            src_ip="10.1.1.1",
            dst_ip="203.0.113.5",
            action="block-url",
            url="bad.example.com/x",
            category="malware",
            device_serial="SER1",
            device_name="fw-a",
        ),
        conn,
        config,
    )
    (row,) = rows(conn)
    assert row["user_agent"] == "curl/8.4.0"
    assert row["direction"] == "egress"
    assert row["device_serial"] == "SER1"
    assert row["device_name"] == "fw-a"
    assert row["last_src_ip"] == "10.1.1.1"
    assert row["last_dst_ip"] == "203.0.113.5"
    assert row["last_action"] == "block-url"
    assert row["last_url"] == "bad.example.com/x"
    assert row["url_category"] == "malware"
    assert row["hit_count"] == 1
    assert row["first_seen"] == row["last_seen"]
    assert "curl/8.4.0" in row["last_raw_payload"]
    assert len(no_alerts) == 1


def test_repeat_ua_increments_and_updates_latest_fields_without_alerting(conn, config, no_alerts):
    t.process_syslog(build_url_log(user_agent="UA", dst_ip="203.0.113.1", action="alert"), conn, config)
    conn.execute("UPDATE user_agents SET first_seen = '2000-01-01 00:00:00'")
    t.process_syslog(build_url_log(user_agent="UA", dst_ip="203.0.113.2", action="block-url"), conn, config)
    (row,) = rows(conn)
    assert row["hit_count"] == 2
    assert row["first_seen"] == "2000-01-01 00:00:00"  # preserved on update
    assert row["last_dst_ip"] == "203.0.113.2"
    assert row["last_action"] == "block-url"
    assert len(no_alerts) == 1  # only the first sighting alerts


def test_burst_within_the_same_second_alerts_only_once(conn, config, no_alerts):
    """Regression: "new" used to be first_seen == last_seen, which has
    one-second resolution - a new UA's second request inside that same
    second fired a duplicate alert."""
    for _ in range(5):
        t.process_syslog(build_url_log(user_agent="burst/1.0"), conn, config)
    assert rows(conn)[0]["hit_count"] == 5
    assert len(no_alerts) == 1


def test_same_ua_on_two_firewalls_is_two_rows_and_two_alerts(conn, config, no_alerts):
    for serial in ("SER1", "SER2"):
        t.process_syslog(build_url_log(user_agent="UA", device_serial=serial), conn, config)
    assert sorted(r["device_serial"] for r in rows(conn)) == ["SER1", "SER2"]
    assert len(no_alerts) == 2  # "new on THIS firewall" is deliberate


def test_same_ua_both_directions_is_two_rows(conn, config, no_alerts):
    t.process_syslog(build_url_log(user_agent="UA"), conn, config)
    t.process_syslog(
        build_url_log(user_agent="UA", src_zone="Outside-Untrust", dst_zone="DMZ"), conn, config
    )
    assert sorted(r["direction"] for r in rows(conn)) == ["egress", "ingress"]


def test_missing_device_fields_fall_back(conn, config, no_alerts):
    t.process_syslog(build_url_log(user_agent="UA", device_serial="", device_name=""), conn, config)
    (row,) = rows(conn)
    assert row["device_serial"] == "unknown"
    assert row["device_name"] == "unknown"


def test_blank_device_name_falls_back_to_serial(conn, config, no_alerts):
    t.process_syslog(build_url_log(user_agent="UA", device_serial="SER9", device_name=""), conn, config)
    assert rows(conn)[0]["device_name"] == "SER9"


@pytest.mark.parametrize(
    "overrides",
    [
        {"log_type": "TRAFFIC"},                               # not a URL log
        {"user_agent": ""},                                    # no UA
        {"user_agent": "unknown"},
        {"user_agent": "Unknown"},
        {"src_zone": "Trust", "dst_zone": "Users"},            # unclassified direction
    ],
)
def test_dropped_logs_write_nothing(overrides, conn, config, no_alerts):
    kwargs = {"user_agent": "UA", **overrides}
    t.process_syslog(build_url_log(**kwargs), conn, config)
    assert rows(conn) == []
    assert no_alerts == []


def test_url_log_type_is_accepted(conn, config, no_alerts):
    t.process_syslog(build_url_log(user_agent="UA", log_type="URL"), conn, config)
    assert len(rows(conn)) == 1


def test_garbage_packets_do_not_raise(conn, config, no_alerts):
    for junk in (b"", b"\xff\xfe\x00garbage", b"hello", b"a,b,c", b'1,2026/01/01 "unterminated'):
        t.process_syslog(junk, conn, config)
    assert rows(conn) == []


def test_hostile_strings_are_stored_literally(conn, config, no_alerts):
    # Parameterized SQL: a UA that looks like SQL is data, not a statement.
    evil = "x'); DROP TABLE user_agents; -- <script>alert(1)</script>"
    t.process_syslog(build_url_log(user_agent=evil, device_name="fw'--"), conn, config)
    (row,) = rows(conn)
    assert row["user_agent"] == evil
    assert row["device_name"] == "fw'--"


def test_database_errors_are_logged_not_raised(conn, config, no_alerts, caplog):
    conn.execute("DROP TABLE user_agents")
    t.process_syslog(build_url_log(user_agent="UA"), conn, config)
    assert "Database error" in caplog.text


# --- schema / migration ---------------------------------------------------------

def test_init_db_is_idempotent_and_uses_wal(db_path):
    t.init_db(db_path).close()
    conn = t.init_db(db_path)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    conn.close()


def test_init_db_adds_missing_columns_to_an_older_table(db_path):
    old = sqlite3.connect(db_path)
    old.execute(
        "CREATE TABLE user_agents (user_agent TEXT NOT NULL, direction TEXT NOT NULL, "
        "first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL, "
        "PRIMARY KEY (user_agent, direction))"
    )
    old.commit()
    old.close()
    conn = t.init_db(db_path)
    columns = {r[1] for r in conn.execute("PRAGMA table_info(user_agents)")}
    conn.close()
    assert {"device_serial", "device_name", "last_url", "url_category", "hit_count"} <= columns


def test_direction_check_constraint(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO user_agents (user_agent, direction, first_seen, last_seen) "
            "VALUES ('ua', 'sideways', 'x', 'x')"
        )


# --- Google Chat alerts ---------------------------------------------------------

@pytest.mark.parametrize(
    "raw, expected",
    [
        ("*bold*", "∗bold∗"),
        ("_it_", "‗it‗"),
        ("~s~", "∼s∼"),
        ("`code`", "'code'"),
        ("<https://evil.example|click me>", "‹https://evil.example¦click me›"),
        ("plain/1.0", "plain/1.0"),
        ("", ""),
        (None, None),
    ],
)
def test_sanitize_for_chat(raw, expected):
    assert t.sanitize_for_chat(raw) == expected


def test_send_gchat_alert_sanitizes_every_attacker_field(monkeypatch):
    sent = []
    monkeypatch.setattr(t.requests, "post", lambda url, json, timeout: sent.append((url, json, timeout)))
    t.send_gchat_alert(
        "https://chat.example.invalid/hook",
        ua="<https://evil.example|Update now>",
        direction="egress",
        src_ip="*1*",
        dst_ip="_2_",
        action="`allow`",
        timestamp="2026-09-24 12:00:00",
        device_name="~fw~",
    )
    ((url, payload, timeout),) = sent
    text = payload["text"]
    assert url == "https://chat.example.invalid/hook"
    assert timeout == 5
    # Only this app's own markup survives; nothing from the packet can
    # open a link or change formatting.
    assert "<https://evil.example|" not in text
    assert "‹https://evil.example¦Update now›" in text
    assert "`∗1∗`" in text and "`‗2‗`" in text and "`'allow'`" in text and "`∼fw∼`" in text
    assert text.startswith("🚨 *New Egress User-Agent Detected* 🚨")


def test_send_gchat_alert_disabled_without_webhook(monkeypatch):
    monkeypatch.setattr(t.requests, "post", lambda *a, **k: pytest.fail("should not post"))
    t.send_gchat_alert("", "ua", "egress", "1", "2", "a", "now")


def test_send_gchat_alert_swallows_network_errors(monkeypatch, caplog):
    def boom(*a, **k):
        raise t.requests.ConnectionError("down")

    monkeypatch.setattr(t.requests, "post", boom)
    t.send_gchat_alert("https://chat.example.invalid/hook", "ua", "egress", "1", "2", "a", "now")
    assert "Failed to send GChat webhook alert" in caplog.text


def test_new_ua_triggers_real_alert_path_with_webhook(conn, config, monkeypatch):
    sent = []
    monkeypatch.setattr(t.requests, "post", lambda url, json, timeout: sent.append(json))
    config["alerts"]["gchat_webhook_url"] = "https://chat.example.invalid/hook"
    t.process_syslog(build_url_log(user_agent="*evil*", device_name="fw-a"), conn, config)
    t.process_syslog(build_url_log(user_agent="*evil*", device_name="fw-a"), conn, config)
    assert len(sent) == 1
    assert "∗evil∗" in sent[0]["text"]


# --- DB path override -----------------------------------------------------------

def test_main_honors_db_path_env_var(monkeypatch, tmp_path, config):
    """main() should open SENTRY_UA_DB_PATH instead of config.yaml's
    db_path. Stops right after init_db by making socket creation fail."""
    target = str(tmp_path / "from_env.db")
    opened = []
    config["database"] = {"db_path": "from_config.db"}
    config["network"] = {"listen_ip": "127.0.0.1", "listen_port": 0}
    monkeypatch.setattr(t, "load_config", lambda: config)
    monkeypatch.setattr(t, "init_db", lambda path: opened.append(path))

    class Stop(Exception):
        pass

    def no_socket(*a, **k):
        raise Stop

    monkeypatch.setattr(t.socket, "socket", no_socket)
    monkeypatch.setenv("SENTRY_UA_DB_PATH", target)
    with pytest.raises(Stop):
        t.main()
    assert opened == [target]

    opened.clear()
    monkeypatch.delenv("SENTRY_UA_DB_PATH")
    with pytest.raises(Stop):
        t.main()
    assert opened == ["from_config.db"]
