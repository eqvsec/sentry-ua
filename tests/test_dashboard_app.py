"""End-to-end smoke tests: the real dashboard.py script, run headless via
Streamlit's AppTest against a demo database.

AppTest reports st.context.ip_address as a MagicMock (not a real address),
which the dashboard ACL correctly rejects as "not an IP" - so these tests
route a fixed, real test IP through the real allow-list logic instead of
bypassing the gate.
"""
import shutil

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

import sentry_ua.config
from conftest import REPO_ROOT
from sentry_ua import data

TEST_CLIENT_IP = "10.0.0.5"


@pytest.fixture
def app_env(tmp_path, monkeypatch, demo_db):
    """Runs the app from a scratch working directory (its own config.yaml,
    the demo DB via SENTRY_UA_DB_PATH) so nothing touches the real repo
    config or database."""
    shutil.copy(REPO_ROOT / "config.yaml", tmp_path / "config.yaml")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SENTRY_UA_DB_PATH", demo_db)
    real_check = sentry_ua.config.is_ip_allowed
    monkeypatch.setattr(
        sentry_ua.config, "is_ip_allowed", lambda _ip, acl: real_check(TEST_CLIENT_IP, acl)
    )
    # load_data()/load_devices() are st.cache_data'd per process; don't let
    # one test's database leak into the next.
    st.cache_data.clear()
    yield tmp_path
    st.cache_data.clear()


def run_app(**query_params):
    at = AppTest.from_file(str(REPO_ROOT / "dashboard.py"), default_timeout=60)
    for key, value in query_params.items():
        at.query_params[key] = value
    at.run()
    return at


def assert_clean(at):
    assert not at.exception, [e.value for e in at.exception]
    assert not at.warning, [w.value for w in at.warning]


def tile_labels(at):
    return {b.key: b.label for b in at.button if b.key and b.key.startswith("tile_button_")}


def test_renders_with_demo_data(app_env, demo_db):
    at = run_app()
    assert_clean(at)
    df = data.load_data(demo_db)
    tiles = tile_labels(at)
    assert tiles["tile_button_all"].endswith(f"/   {len(df)}")
    assert tiles["tile_button_egress"].endswith(f"/   {(df['Direction'] == 'egress').sum()}")
    assert tiles["tile_button_ingress"].endswith(f"/   {(df['Direction'] == 'ingress').sum()}")
    assert "sentry" in at.markdown[-1].value.lower()  # footer made it to the end


def test_tiles_edit_the_search_box(app_env):
    at = run_app()
    at.button(key="tile_button_suspicious").click().run()
    assert at.text_input(key="search_query").value == "(suspicious)"
    at.button(key="tile_button_egress").click().run()
    assert at.text_input(key="search_query").value == "((suspicious) and (egress))"
    at.button(key="tile_button_ingress").click().run()
    assert at.text_input(key="search_query").value == "((suspicious) and (ingress))"
    at.button(key="tile_button_all").click().run()
    assert at.text_input(key="search_query").value == "(suspicious)"
    assert at.query_params["q"] == ["(suspicious)"]
    assert_clean(at)


def test_reset_clears_the_query(app_env):
    at = run_app()
    at.text_input(key="search_query").set_value("curl").run()
    assert not at.button(key="reset_filters_button").disabled
    at.button(key="reset_filters_button").click().run()
    assert at.text_input(key="search_query").value == ""
    assert at.button(key="reset_filters_button").disabled
    assert_clean(at)


def test_device_scope_from_query_param(app_env, demo_db):
    at = run_app(device="PA-DEMO-0002")
    assert_clean(at)
    scoped = data.load_data(demo_db, "PA-DEMO-0002")
    assert tile_labels(at)["tile_button_all"].endswith(f"/   {len(scoped)}")
    assert at.selectbox(key="device_selector").value == "fw-branch-east"


def test_unknown_device_param_falls_back_to_all(app_env, demo_db):
    at = run_app(device="' OR 1=1 --")
    assert_clean(at)
    assert at.selectbox(key="device_selector").value == "All Firewalls"
    assert tile_labels(at)["tile_button_all"].endswith(f"/   {len(data.load_data(demo_db))}")


def test_event_inspector_dialog_renders(app_env):
    at = run_app()
    at.session_state["selected_ua"] = ("curl/8.4.0", "egress")
    at.run()
    assert_clean(at)
    assert any("curl/8.4.0" in c.value for c in at.code)  # raw syslog payload block


def inspector_iframes(at):
    return [el for el in at.get("iframe")]


def decode_iframe_doc(el):
    import base64

    prefix = "data:text/html;charset=utf-8;base64,"
    assert el.proto.src.startswith(prefix)
    return base64.b64decode(el.proto.src[len(prefix):]).decode("utf-8")


def test_inspector_iframe_is_an_isolated_data_url(app_env):
    """The tiles must load from a data: URL (opaque origin), never as an
    inline HTML string - current Streamlit embeds HTML strings (and the
    deprecated components.html) same-origin with the app."""
    at = run_app()
    at.session_state["selected_ua"] = ("curl/8.4.0", "egress")
    at.run()
    assert_clean(at)
    (frame,) = inspector_iframes(at)
    assert not frame.proto.srcdoc
    doc = decode_iframe_doc(frame)
    assert "curl/8.4.0" in doc and "event-tile" in doc


def test_hostile_user_agent_is_escaped_inside_the_inspector(app_env, monkeypatch, tmp_path):
    import palo_ua_tracker
    from sentry_ua.demo import DEMO_CONFIG, build_url_log

    hostile = "<img src=x onerror=alert(document.cookie)>"
    db = str(tmp_path / "hostile.db")
    conn = palo_ua_tracker.init_db(db)
    palo_ua_tracker.process_syslog(
        build_url_log(user_agent=hostile, url='x.example.com/"><script>alert(2)</script>'), conn, DEMO_CONFIG
    )
    conn.close()
    monkeypatch.setenv("SENTRY_UA_DB_PATH", db)
    st.cache_data.clear()

    at = run_app()
    at.session_state["selected_ua"] = (hostile, "egress")
    at.run()
    assert_clean(at)
    doc = decode_iframe_doc(inspector_iframes(at)[0])
    assert hostile not in doc and "<script>alert(2)" not in doc
    assert "&lt;img src=x onerror=alert(document.cookie)&gt;" in doc


def test_q_param_seeds_the_search_box(app_env):
    at = run_app(q="(suspicious)")
    assert_clean(at)
    assert at.text_input(key="search_query").value == "(suspicious)"
    assert tile_labels(at)["tile_button_suspicious"]
    assert at.query_params["q"] == ["(suspicious)"]


def test_prefs_cookie_is_long_lived(app_env, monkeypatch):
    """CookieController.set() defaults to a one-day expiry; the prefs
    cookie must override it or "settings survive closing the tab" lapses a
    day after the last change."""
    from datetime import datetime, timedelta

    import streamlit_cookies_controller

    calls = []
    monkeypatch.setattr(
        streamlit_cookies_controller.CookieController, "set",
        lambda self, name, value, **kwargs: calls.append((name, value, kwargs)),
    )
    at = run_app()
    at.button(key="tile_button_suspicious").click().run()
    name, value, kwargs = calls[-1]
    assert name == "sentry_ua_prefs"
    assert '"q": "(suspicious)"' in value
    assert kwargs["expires"] > datetime.now() + timedelta(days=300)


def test_settings_dialog_opens(app_env):
    at = run_app()
    at.button(key="settings_gear").click().run()
    assert_clean(at)
    assert at.radio(key="theme_radio").value == "Night Ops"


@pytest.mark.parametrize("theme", ["night", "graphite", "amber", "not-a-theme"])
def test_every_theme_renders(app_env, theme):
    at = run_app(theme=theme)
    assert_clean(at)


def test_missing_database_shows_waiting_message(app_env, monkeypatch, tmp_path):
    monkeypatch.setenv("SENTRY_UA_DB_PATH", str(tmp_path / "not-there.db"))
    at = run_app()
    assert not at.exception
    assert any("Waiting for database connection" in w.value for w in at.warning)


# --- dashboard.allowed_sources gate --------------------------------------------

def set_dashboard_acl(workdir, entries):
    import yaml

    path = workdir / "config.yaml"
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    cfg["dashboard"]["allowed_sources"] = entries
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")


def test_acl_denies_client_not_on_list(app_env):
    set_dashboard_acl(app_env, ["192.0.2.0/24"])
    at = run_app()
    assert not at.exception
    assert len(at.markdown) == 1 and "Access Denied" in at.markdown[0].value
    assert len(at.button) == 0  # nothing else rendered - no UI, no telemetry


def test_acl_allows_client_on_list(app_env):
    set_dashboard_acl(app_env, ["192.0.2.0/24", f"{TEST_CLIENT_IP}"])
    at = run_app()
    assert_clean(at)
    assert tile_labels(at)


def test_acl_invalid_entries_warn_but_never_lock_out(app_env):
    set_dashboard_acl(app_env, ["definitely-not-an-ip"])
    at = run_app()
    assert not at.exception
    assert any("definitely-not-an-ip" in w.value for w in at.warning)
    assert tile_labels(at)  # fell back to 0.0.0.0/0, as documented


def test_non_ip_client_value_is_denied(tmp_path, monkeypatch, demo_db):
    """Without the test-IP shim: AppTest's MagicMock "address" must be
    denied under a restrictive list (fail closed on garbage)."""
    shutil.copy(REPO_ROOT / "config.yaml", tmp_path / "config.yaml")
    set_dashboard_acl(tmp_path, ["10.0.0.0/8"])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SENTRY_UA_DB_PATH", demo_db)
    at = run_app()
    assert "Access Denied" in at.markdown[0].value
    assert len(at.button) == 0
