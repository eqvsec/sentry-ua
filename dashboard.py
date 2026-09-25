import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

import yaml

import altair as alt
import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from streamlit_cookies_controller import CookieController
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode

from sentry_ua import APP_VERSION
from sentry_ua import data as data_layer
from sentry_ua import ui_helpers
from sentry_ua.config import (
    REFRESH_OPTIONS,
    build_ip_acl,
    is_ip_allowed,
    load_config,
    load_dashboard_defaults,
    resolve_db_path,
)
from sentry_ua.data import (
    PANOS_APPLICATION_INDEX,
    PANOS_RULE_NAME_INDEX,
    PANOS_SOURCE_USER_INDEX,
    extract_raw_field,
    extract_url_from_raw,
)
from sentry_ua.query import (
    SUSPICIOUS_JS_REGEX_SOURCE,
    SUSPICIOUS_REGEX,
    apply_search_query,
    ast_add_predicate,
    ast_contains_predicate,
    ast_strip_predicate,
    ast_to_query_text,
    parse_pan_style_query,
)
from sentry_ua.theme import THEMES, app_css
from sentry_ua.ui_helpers import (
    action_class,
    isolated_iframe_src,
    parse_chart_point_click,
    render_event_tile,
)


# -----------------------------------------------------------------------------
# PAGE / APP STATE
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Sentry UA",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="collapsed",
)


def _check_dashboard_acl():
    """Runs before anything else renders. See config.yaml's dashboard.
    allowed_sources for the full caveat: st.context.ip_address is the real
    TCP peer address as long as Streamlit is reached directly (this app's
    default setup), but Streamlit's own docs call it unsuitable for
    security if a reverse proxy sits in front - a host firewall is the
    real, unspoofable version of this control.

    The parsing/membership logic lives in sentry_ua.config (build_ip_acl,
    is_ip_allowed) so it can be unit-tested; the gate itself stays here."""
    try:
        config = load_config()
    except (OSError, yaml.YAMLError):
        return  # No config to enforce against yet - don't lock out setup.

    allowed_sources = (config.get("dashboard", {}) or {}).get("allowed_sources", ["0.0.0.0/0"])
    acl, invalid_entries = build_ip_acl(allowed_sources)
    for entry in invalid_entries:
        st.warning(f"Ignoring invalid dashboard.allowed_sources entry in config.yaml: {entry!r}")

    client_ip = st.context.ip_address
    if client_ip is None:
        # Localhost (and some local/dev connections) reports None - that's
        # the machine the dashboard is running on, not a remote visitor,
        # so it's always allowed regardless of the configured ACL.
        return

    if not is_ip_allowed(client_ip, acl):
        st.markdown(
            "<div style='max-width:520px;margin:15vh auto;text-align:center;"
            "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;"
            "color:#e6edf0;'>"
            "<div style='font-size:1.4rem;font-weight:700;margin-bottom:10px;'>Access Denied</div>"
            "<div style='color:#819098;font-size:.85rem;'>"
            "Your address isn't on this dashboard's allow-list. Contact your "
            "administrator, or see config.yaml's dashboard.allowed_sources."
            "</div></div>",
            unsafe_allow_html=True,
        )
        st.stop()


_check_dashboard_acl()


def _load_db_path():
    """Same database the collector writes: SENTRY_UA_DB_PATH if set, else
    config.yaml's database.db_path. (Earlier versions hardcoded
    user_agents.db here regardless of config.)"""
    try:
        config = load_config()
    except (OSError, yaml.YAMLError):
        config = {}
    return resolve_db_path(config)


DB_PATH = _load_db_path()

# Preferences (theme, refresh rate, firewall selection, search) live in TWO
# places, deliberately, not one:
#
#   1. st.query_params (the URL) is still the live, moment-to-moment source
#      of truth every getter below reads from - it's genuinely per-browser
#      (just the address bar) with no cross-user leakage, and it's what
#      makes a link shareable/bookmarkable with a specific view baked in.
#      This app runs multi-user on a shared server, which already ruled out
#      a plain file next to dashboard.py early on: that would be one
#      global value every visitor reads AND overwrites, so one person
#      picking a theme would silently change it for everyone else.
#
#   2. A single browser cookie is the durable BACKSTOP. Query params alone
#      don't survive closing the tab and opening a fresh one - a blank URL
#      has no params, so everything reset. On a cold load with no query
#      params at all, whatever was last saved to the cookie seeds them, so
#      settings genuinely survive across sessions; from then on the cookie
#      is just kept in sync with the URL going forward. Both still per-
#      browser only, so this doesn't reintroduce the shared-file problem -
#      a cookie is set by this browser, sent back only by this browser.
#
# This needed streamlit_cookies_controller, a small third-party component -
# there's no built-in Streamlit API for browser cookies/localStorage, and an
# earlier note here pointed out that components.html's own sandboxed iframe
# specifically can't reach localStorage. That's still true for the event
# inspector's popup (now an st.iframe loaded from a data: URL - an opaque
# origin, deliberately - see isolated_iframe_src), but doesn't apply to a real
# bidirectional custom component like this one, which runs its own iframe
# with a proper JS<->Python data channel back to session_state.
PREFS_COOKIE_NAME = "sentry_ua_prefs"
# CookieController.set() defaults to a cookie that expires ONE DAY after it
# was last written, and it's only rewritten when a preference changes - so
# without an explicit expiry, "settings survive closing the tab" quietly
# lapsed a day after the last change.
PREFS_COOKIE_LIFETIME = timedelta(days=365)
_cookie_controller = CookieController()


def _save_prefs_cookie():
    """Mirrors the current query params into the durable cookie. Called
    from every setter below, right after it updates st.query_params, so the
    cookie never drifts out of sync with whatever the URL currently says.
    Best-effort: a cookie write failing (e.g. the component hasn't finished
    loading yet) shouldn't be able to break the app - worst case, that one
    change just doesn't survive closing the tab, exactly like before this
    feature existed."""
    payload = {
        key: st.query_params.get(key, "")
        for key in ("theme", "refresh", "device", "q")
    }
    payload = {k: v for k, v in payload.items() if v}
    try:
        _cookie_controller.set(
            PREFS_COOKIE_NAME,
            json.dumps(payload),
            expires=datetime.now() + PREFS_COOKIE_LIFETIME,
        )
    except Exception:
        pass


_COOKIE_WARMUP_MAX_ATTEMPTS = 3


def _bootstrap_prefs_from_cookie():
    """Runs once, before anything else reads st.query_params. If the URL
    already has state in it - a real bookmark, a share, or just mid-session
    navigation - that wins and the cookie is left alone entirely; the
    cookie only ever fills in a genuinely blank URL.

    The cookie component needs a full round trip to the browser before it
    can report back a cookie's value to Python: the frontend iframe has to
    mount, its JS has to run and read document.cookie, then post the value
    back over the websocket - on a genuinely cold page load (the whole
    Streamlit app bootstrapping for the first time, not just this one
    component), that can take more than one script run to land, especially
    under load or a slow connection. An earlier version of this function
    only retried ONCE (a single silent st.rerun()) before giving up for the
    rest of the session - which meant a slow-to-mount component looked
    exactly like "no cookie exists," intermittently, purely depending on
    how fast that round trip happened to complete that particular visit.
    This retries up to _COOKIE_WARMUP_MAX_ATTEMPTS times instead of once,
    still bounded so a session with genuinely no cookie doesn't loop
    forever."""
    if st.query_params:
        return
    if st.session_state.get("_cookie_bootstrap_done"):
        return
    try:
        all_cookies = _cookie_controller.getAll()
    except Exception:
        all_cookies = {}
    if not all_cookies:
        attempts = st.session_state.get("_cookie_warmup_attempts", 0)
        if attempts < _COOKIE_WARMUP_MAX_ATTEMPTS:
            st.session_state._cookie_warmup_attempts = attempts + 1
            st.rerun()
        # Retries exhausted - proceed with whatever we have (nothing, most
        # likely a session with no saved cookie at all) rather than
        # retrying indefinitely.
    st.session_state._cookie_bootstrap_done = True
    raw = (all_cookies or {}).get(PREFS_COOKIE_NAME)
    if not raw:
        return
    try:
        saved = json.loads(raw)
    except (TypeError, ValueError):
        return
    for key in ("theme", "refresh", "device", "q"):
        value = saved.get(key)
        if value:
            st.query_params[key] = str(value)


_bootstrap_prefs_from_cookie()


def get_refresh_seconds():
    value = st.query_params.get("refresh", str(load_dashboard_defaults()))
    if isinstance(value, list):
        value = value[0] if value else str(load_dashboard_defaults())
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = load_dashboard_defaults()
    return value if value in REFRESH_OPTIONS else load_dashboard_defaults()


def set_refresh_seconds(seconds):
    st.query_params["refresh"] = str(seconds)
    _save_prefs_cookie()


def get_theme_key():
    value = st.query_params.get("theme", "night")
    if isinstance(value, list):
        value = value[0] if value else "night"
    return value if value in THEMES else "night"


def set_theme(theme_key):
    st.query_params["theme"] = theme_key
    _save_prefs_cookie()
    st.session_state.pop("selected_ua", None)
    st.rerun()


THEME_KEY = get_theme_key()
THEME = THEMES[THEME_KEY]


def get_search_query():
    value = st.query_params.get("q", "")
    if isinstance(value, list):
        value = value[0] if value else ""
    return value


def set_search_query(new_text):
    """Central place any code that programmatically edits the search box
    (currently just the metric tiles) writes through - keeps session_state,
    the URL, and the "did this change" tracking used to avoid redundant
    query-param writes all in sync in one spot."""
    st.session_state.search_query = new_text
    if new_text:
        st.query_params["q"] = new_text
    else:
        st.query_params.pop("q", None)
    st.session_state._last_persisted_search_query = new_text
    _save_prefs_cookie()


def sync_query_predicate(predicate_name, mutually_exclusive_with=None):
    """Toggles predicate_name (one of "egress", "ingress", "suspicious") in
    the search box: on if it's currently absent, off if present. This is
    what makes the tiles and the search box two views of the same state -
    the tile edits the query text; the query text (re-parsed) is what
    decides whether the tile shows as pressed. mutually_exclusive_with
    strips those other predicate names first when turning this one on (used
    for egress/ingress, which stay mutually exclusive on the tile side even
    though the query language itself doesn't enforce that - a hand-typed
    "(egress) and (ingress)" is left exactly as written and correctly
    matches nothing, same as any other contradiction someone writes on
    purpose)."""
    current_text = (st.session_state.get("search_query") or "").strip()
    if current_text:
        ast, parsed_ok, leftover = parse_pan_style_query(current_text)
    else:
        ast, parsed_ok, leftover = None, True, None
    if not parsed_ok:
        # Nothing structured to build on top of (plain text, or something
        # that doesn't parse at all) - preserve the whole existing text as a
        # trailing free-text clause and start a fresh structured prefix for
        # the predicate, the same hybrid pattern the query language already
        # supports for a manually-typed query.
        leftover = current_text
        ast = None

    if ast_contains_predicate(ast, predicate_name):
        ast = ast_strip_predicate(ast, predicate_name)
    else:
        if mutually_exclusive_with:
            for other in mutually_exclusive_with:
                ast = ast_strip_predicate(ast, other)
        ast = ast_add_predicate(ast, predicate_name)

    structured_text = ast_to_query_text(ast)
    if leftover:
        new_text = f"{structured_text} {leftover}".strip() if structured_text else leftover
    else:
        new_text = structured_text
    set_search_query(new_text)


def clear_direction_predicates():
    """The "All" tile: unlike Egress/Ingress/Suspicious, this isn't a
    toggle - clicking it always ensures neither direction predicate is
    present, leaving Suspicious and anything else already in the box
    untouched (mirroring the old tile_filter="all" behavior of "no
    direction constraint", without disturbing the rest of the query)."""
    current_text = (st.session_state.get("search_query") or "").strip()
    if current_text:
        ast, parsed_ok, leftover = parse_pan_style_query(current_text)
    else:
        ast, parsed_ok, leftover = None, True, None
    if not parsed_ok:
        leftover = current_text
        ast = None
    ast = ast_strip_predicate(ast, "egress")
    ast = ast_strip_predicate(ast, "ingress")
    structured_text = ast_to_query_text(ast)
    if leftover:
        new_text = f"{structured_text} {leftover}".strip() if structured_text else leftover
    else:
        new_text = structured_text
    set_search_query(new_text)


def reset_filters():
    # This must run as an on_click callback, not as inline code after
    # st.button(...). Callbacks run BEFORE the script reruns and widgets are
    # re-instantiated, so it's safe to assign st.session_state.search_query
    # here. Doing the same assignment inline further down (after the
    # search_query text_input had already been instantiated in that same
    # run) is exactly what previously raised: "st.session_state.search_query
    # cannot be modified after the widget with key search_query is
    # instantiated."
    st.session_state.search_query = ""
    st.session_state._last_persisted_search_query = ""
    st.session_state.pop("telemetry_grid_state", None)
    st.session_state.pop("selected_ua", None)
    # chart_ua is no longer set anywhere (chart clicks only open the dialog,
    # they don't filter the table) - this pop is just a defensive no-op in
    # case a session still carries a stale value from before that change.
    st.session_state.pop("chart_ua", None)
    st.session_state.pop("_last_grid_selection_key", None)
    # Vega-Lite persists the chart's own click-selection across reruns too,
    # the same way AG Grid persists its row selection - clearing this lets a
    # later click on the very same bar register as new again, rather than
    # looking unchanged and being ignored by the "only adopt on genuine
    # change" guard in the chart's click handler.
    st.session_state.pop("_last_chart_click_key", None)
    st.session_state.pop("_last_donut_click_key", None)
    st.query_params.pop("q", None)
    _save_prefs_cookie()
    # Reset intentionally only touches table/chart filtering (search, tile,
    # selections) - theme and refresh rate are separate settings and are
    # left completely alone here, by design.
    # AG Grid keeps its OWN row-selection state tied to its widget `key`,
    # entirely independent of anything above. Popping selected_ua here
    # doesn't tell the grid widget itself to forget which row it still
    # considers selected - so on the very next render, the grid keeps
    # reporting that same old row, and the code that reads grid selections
    # re-derives selected_ua right back from it, reopening the dialog even
    # though it was supposedly reset. Bumping this nonce forces a brand-new
    # AG Grid widget instance (via a new key) with no carried-over selection,
    # the same trick already used to force a fresh grid on a chart click.
    st.session_state.grid_reset_nonce = st.session_state.get("grid_reset_nonce", 0) + 1


# -----------------------------------------------------------------------------
# CSS
# -----------------------------------------------------------------------------
st.markdown(app_css(THEME), unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# DATA
# -----------------------------------------------------------------------------
# The query language, data-loading SQL, and inspector helpers live in the
# sentry_ua package (plain Python, no Streamlit, unit-tested on their own).
# Only the Streamlit-specific caching is added here.
@st.cache_data(ttl=5)
def load_devices():
    return data_layer.load_devices(DB_PATH)


@st.cache_data(ttl=5)
def load_data(device_serial=None):
    return data_layer.load_data(DB_PATH, device_serial)


@st.cache_data(ttl=3600, show_spinner=False)
def lookup_ip_country(ip_str):
    return ui_helpers.lookup_ip_country(ip_str)


def get_selected_device():
    value = st.query_params.get("device", "")
    if isinstance(value, list):
        value = value[0] if value else ""
    return value


def set_selected_device(device_serial):
    if device_serial:
        st.query_params["device"] = device_serial
    else:
        st.query_params.pop("device", None)
    _save_prefs_cookie()
    # A UA/direction selected under one device scope may not exist (or may
    # mean something different) under another - drop it rather than show a
    # stale popup, same reasoning as set_theme().
    st.session_state.pop("selected_ua", None)
    st.rerun()


# -----------------------------------------------------------------------------
# HEADER
# -----------------------------------------------------------------------------
refresh_seconds = get_refresh_seconds()

if "show_settings_dialog" not in st.session_state:
    st.session_state.show_settings_dialog = False
if "autorefresh_paused" not in st.session_state:
    st.session_state.autorefresh_paused = False


def toggle_autorefresh():
    st.session_state.autorefresh_paused = not st.session_state.autorefresh_paused


def manual_refresh():
    """On-demand refresh regardless of the autorefresh/pause state or the
    5-second data cache: clears load_data()'s and load_devices()'s cached
    results so the rerun Streamlit triggers after any button click actually
    re-queries the database, rather than replaying whatever was already
    cached from up to 5 seconds ago."""
    load_data.clear()
    load_devices.clear()


head_col1, head_col2 = st.columns([5.7, 2.3], vertical_alignment="center")
with head_col1:
    st.markdown(
        '<div class="brand">'
        '<span class="brand-main">SENTRY<span class="brand-slash">//</span>UA</span>'
        '<span class="brand-sub">USER-AGENT TELEMETRY</span>'
        '</div>',
        unsafe_allow_html=True,
    )
with head_col2:
    refresh_col, play_col, gear_col = st.columns(
        [0.34, 0.33, 0.33], gap="small", vertical_alignment="center"
    )
    with refresh_col:
        st.button(
            "⟳",
            key="manual_refresh",
            help="Refresh now",
            width="stretch",
            on_click=manual_refresh,
        )
    with play_col:
        paused = st.session_state.autorefresh_paused
        # Two lines (⏸) while it's actively refreshing - clicking pauses;
        # a play triangle (▶) while paused - clicking resumes.
        icon = "▶" if paused else "⏸"
        # on_click, not "if st.button(...): mutate; st.rerun()". An earlier
        # version used the latter and still intermittently left the icon
        # stuck on its old state after the first click - the button's own
        # label is fixed (from the pre-click `paused` value) at the point
        # st.button() is called, and if a near-simultaneous OTHER
        # rerun-triggering event was already in flight (the periodic
        # autorefresh timer is exactly such a trigger, and pausing is
        # exactly the click most likely to race it right at the moment
        # it's about to fire), there was a window where that race could
        # still leave a stale label on screen despite the manual
        # st.rerun(). A callback closes that window entirely: Streamlit
        # runs on_click for whichever triggering event actually won
        # BEFORE the script body executes top-to-bottom on that run, so by
        # the time `icon = ...` is computed here, session_state already
        # reflects the toggle - no manual rerun needed, and no ordering
        # ambiguity to race against.
        st.button(
            icon,
            key="autorefresh_toggle",
            help="Resume auto-refresh" if paused else "Pause auto-refresh",
            width="stretch",
            on_click=toggle_autorefresh,
        )
    with gear_col:
        if st.button("⚙", key="settings_gear", help="Settings", width="stretch"):
            st.session_state.show_settings_dialog = True

if st.session_state.show_settings_dialog:
    @st.dialog("Settings", width="small", dismissible=False)
    def show_settings_dialog():
        # dismissible=False + this explicit Close button, rather than the
        # dialog's native click-outside/Escape/X dismiss, for the same
        # reason the event inspector dialog uses this pattern: Streamlit
        # gives no callback for a native dismiss, which made closing
        # impossible to detect reliably. scope="app" is made explicit
        # because a dialog behaves like an st.fragment, and a
        # fragment-scoped rerun would only re-run this dialog function
        # itself rather than the outer script that decides whether to
        # invoke it at all.
        _spacer, close_col = st.columns([0.82, 0.18])
        with close_col:
            if st.button("✕", key="close_settings_dialog", width="stretch", help="Close"):
                st.session_state.show_settings_dialog = False
                st.rerun(scope="app")

        st.markdown('<div class="settings-popover-title">Theme</div>', unsafe_allow_html=True)
        theme_keys = list(THEMES.keys())
        theme_names = [THEMES[k]["name"] for k in theme_keys]
        picked_name = st.radio(
            "Theme",
            theme_names,
            index=theme_keys.index(THEME_KEY),
            key="theme_radio",
            label_visibility="collapsed",
        )
        picked_theme_key = theme_keys[theme_names.index(picked_name)]
        if picked_theme_key != THEME_KEY:
            set_theme(picked_theme_key)

        st.markdown('<div class="settings-popover-title">Refresh Rate</div>', unsafe_allow_html=True)
        refresh_label = st.selectbox(
            "Refresh Rate",
            list(REFRESH_OPTIONS.values()),
            index=list(REFRESH_OPTIONS).index(refresh_seconds),
            key="refresh_selector",
            label_visibility="collapsed",
        )
        selected_refresh = next(k for k, v in REFRESH_OPTIONS.items() if v == refresh_label)
        if selected_refresh != refresh_seconds:
            set_refresh_seconds(selected_refresh)

        st.markdown('<div class="settings-popover-title">About</div>', unsafe_allow_html=True)
        st.markdown(
            f'''
            <div class="about-block">
                <div class="about-author">eqvsec</div>
                <div class="about-motto">esse quam videri</div>
                <div class="about-links">
                    <a href="https://eqvsec.com" target="_blank" rel="noopener noreferrer">eqvsec.com</a>
                    <span class="about-sep">·</span>
                    <a href="https://eqvsec.net" target="_blank" rel="noopener noreferrer">eqvsec.net</a>
                    <span class="about-sep">·</span>
                    <a href="https://x.com/eqv_sec" target="_blank" rel="noopener noreferrer">@eqv_sec</a>
                    <span class="about-sep">·</span>
                    <a href="https://github.com/eqvsec" target="_blank" rel="noopener noreferrer">GitHub</a>
                </div>
                <div class="about-version">Sentry UA v{APP_VERSION} &middot; MIT License</div>
            </div>
            ''',
            unsafe_allow_html=True,
        )

    show_settings_dialog()

# An earlier revision tried pausing this while the event inspector dialog
# was open, and later tried inferring "the user dismissed the dialog" from
# various signals (an unexpected rerun, whether it coincided with an
# autorefresh tick, a grace period after opening). All of that was fighting
# the same underlying problem: Streamlit gives no direct callback for a
# native dismiss (clicking outside, Escape, or the dialog's own X), so
# detecting it was always a guess, and every heuristic attempt had its own
# edge cases - closing right after opening, or reopening while the person
# was just clicking around elsewhere. Both dialogs are now opened with
# dismissible=False specifically to remove that guesswork: the native
# dismiss paths are disabled, and the only way to close either one is an
# explicit in-dialog Close button with a plain, deterministic on_click -
# neither dialog's open/closed state depends on autorefresh in any way
# anymore. That decoupling is what makes it safe to reintroduce a genuine,
# user-controlled pause here (the header's play/pause toggle) without
# resurrecting the earlier race conditions: pausing this is now a plain,
# independent on/off switch with no bearing on whether a dialog stays open.
if not st.session_state.autorefresh_paused:
    st_autorefresh(interval=refresh_seconds * 1000, key="ua_dashboard_refresh")

# -----------------------------------------------------------------------------
# FIREWALL SCOPE (multi-firewall, Panorama-style)
# -----------------------------------------------------------------------------
# Firewalls aren't defined anywhere in config.yaml - every PAN-OS syslog
# self-identifies its sending device (serial + hostname), so the list below
# is discovered straight from the database. "All Firewalls" shows
# fleet-wide aggregated totals (hit counts summed across every device,
# detail fields from whichever device most recently reported); picking one
# by hostname scopes everything - metrics, chart, table, export, search - to
# just that device. The dropdown displays hostname; device_serial (stable
# across hostname renames) is what's actually persisted in the URL.
#
# Only the *resolution* happens here - what's currently selected, validated
# against what's actually in the database - since load_data() needs it right
# away. The dropdown WIDGET itself is rendered later, on the search row (see
# "Filter / Search" below), but reads/writes these same variables/query
# param either way.
try:
    devices_df = load_devices()
except Exception:
    # Most likely the database doesn't exist yet (the collector hasn't
    # received its first log). This used to sit outside the try below and
    # surfaced as a raw traceback, file paths and all, instead of the
    # friendly message - now load_data() inside that try reports it.
    devices_df = pd.DataFrame(columns=["Device Serial", "Device Name", "Last Seen"])
selected_device_serial = get_selected_device()
device_labels_by_serial = (
    dict(zip(devices_df["Device Serial"], devices_df["Device Name"]))
    if not devices_df.empty else {}
)
if selected_device_serial and selected_device_serial not in device_labels_by_serial:
    # Either the URL points at a device that's since dropped out of the DB,
    # or this is a fresh/rebuilt database - fall back to All rather than
    # silently showing an empty dashboard.
    selected_device_serial = ""
selected_device_label = device_labels_by_serial.get(selected_device_serial, "All Firewalls")

try:
    df = load_data(selected_device_serial or None)
    if "Last URL" not in df.columns:
        df["Last URL"] = ""
    missing_url = df["Last URL"].fillna("").astype(str).str.strip().eq("")
    if "Raw Payload" in df.columns and missing_url.any():
        df.loc[missing_url, "Last URL"] = df.loc[missing_url, "Raw Payload"].map(extract_url_from_raw)

    if "selected_ua" not in st.session_state:
        st.session_state.selected_ua = None
    if "search_query" not in st.session_state:
        st.session_state.search_query = get_search_query()

    # Metrics
    total_uas = len(df)
    egress_count = len(df[df["Direction"] == "egress"])
    ingress_count = len(df[df["Direction"] == "ingress"])
    suspicious_count = (
        sum(1 for ua in df["User-Agent"] if SUSPICIOUS_REGEX.search(str(ua)))
        if not df.empty else 0
    )

    # The tiles are now editors of the search box rather than a separate
    # filtering mechanism - a tile's pressed state comes from re-parsing
    # whatever's currently in the box and checking whether the
    # corresponding predicate is present in it, and clicking a tile edits
    # that text (see sync_query_predicate / clear_direction_predicates).
    # This is computed once here and reused below for the actual filtering
    # too, so the tiles and the filter can never disagree with each other.
    _current_query_text = (st.session_state.search_query or "").strip()
    if _current_query_text:
        _tile_ast, _tile_ast_ok, _ = parse_pan_style_query(_current_query_text)
    else:
        _tile_ast, _tile_ast_ok = None, True

    def _tile_is_active(name):
        return _tile_ast_ok and ast_contains_predicate(_tile_ast, name)

    egress_active = _tile_is_active("egress")
    ingress_active = _tile_is_active("ingress")
    suspicious_active = _tile_is_active("suspicious")

    def metric_tile(container, label, value, key_suffix, active, on_click):
        with container.container(key=f"metric_tile_{key_suffix}"):
            st.button(
                f"{label}   /   {value:,}",
                key=f"tile_button_{key_suffix}",
                width="stretch",
                type="primary" if active else "secondary",
                on_click=on_click,
            )

    m1, m2, m3, m4 = st.columns(4)
    # "All" shows pressed whenever neither direction predicate is present -
    # not a toggle itself, just the direction group's "nothing selected"
    # state, mirroring how it looked before this tiles-edit-the-query change.
    metric_tile(m1, "UNIQUE UAs", total_uas, "all", not egress_active and not ingress_active, clear_direction_predicates)
    metric_tile(m2, "EGRESS", egress_count, "egress", egress_active, lambda: sync_query_predicate("egress", ("ingress",)))
    metric_tile(m3, "INGRESS", ingress_count, "ingress", ingress_active, lambda: sync_query_predicate("ingress", ("egress",)))
    metric_tile(m4, "SUSPICIOUS", suspicious_count, "suspicious", suspicious_active, lambda: sync_query_predicate("suspicious"))

    # Filters. The search box itself is rendered further down, directly above
    # the table — but we need its value now to compute filtered_df (which
    # feeds both the chart and the table). Reading it from session_state
    # here, before the widget is instantiated later in the script, is safe
    # and is how Streamlit apps normally decouple "where a value is used"
    # from "where its widget is drawn."
    search_query = st.session_state.get("search_query", "")

    # Bumped by reset_filters. Used to key both the chart and the AG Grid
    # table so Reset forces genuinely fresh widget instances for both,
    # rather than ones that still remember an old selection - Vega-Lite
    # persists a chart's click-selection across reruns the same way AG Grid
    # persists its row selection, tied to the widget's key either way.
    reset_nonce = st.session_state.get("grid_reset_nonce", 0)

    filtered_df = df.copy()

    # All filtering (direction, suspicious, and everything else) now flows
    # through the search box's query alone - the tiles just edit its text
    # (egress_active/ingress_active/suspicious_active were already computed
    # above from the same parsed query, which is what drives the tiles'
    # pressed state; this is what actually applies it to the data). The
    # structured-vs-plain-fallback signal apply_search_query also returns
    # isn't surfaced anywhere anymore now that the chip is gone, hence `_`.
    if search_query:
        filtered_df, _ = apply_search_query(filtered_df, search_query)

    # Compact, clickable chart. A selected bar becomes the first row in the
    # table, and clicking it also opens the same event inspector dialog a
    # table-row click does.
    if not filtered_df.empty:
        with st.expander("HIT DISTRIBUTION", expanded=False):
            tab_bars, tab_donut = st.tabs(["Bars", "Donut"])

            with tab_bars:
                chart_data = filtered_df.sort_values(
                    by="Hit Count", ascending=False
                ).head(15)
                # The selection key includes Direction, not just User-Agent: a UA
                # can appear as two stacked, differently-colored segments (one
                # per direction) at the same x position, and without Direction in
                # the key a click couldn't tell those two segments apart.
                chart_selection = alt.selection_point(
                    name="ua_click",
                    fields=["User-Agent", "Direction"],
                    on="click",
                    clear="dblclick",
                    empty=True,
                )
                chart = (
                    alt.Chart(chart_data)
                    .mark_bar(cursor="pointer")
                    .encode(
                        x=alt.X(
                            "User-Agent",
                            sort=alt.EncodingSortField(
                                field="Hit Count", op="sum", order="descending"
                            ),
                            # labelOverlap defaults to thinning out (hiding) tick
                            # labels that Vega-Lite thinks would collide, which is
                            # why only some User-Agent labels were showing.
                            # Disabling that forces every one to render.
                            axis=alt.Axis(labelAngle=-35, labelLimit=150, labelOverlap=False),
                        ),
                        y=alt.Y("Hit Count:Q", title=None),
                        color=alt.Color(
                            "Direction:N",
                            scale=alt.Scale(
                                domain=["egress", "ingress"],
                                range=THEME["chart"],
                            ),
                            legend=alt.Legend(title="Direction"),
                        ),
                        opacity=alt.condition(
                            chart_selection, alt.value(1.0), alt.value(.72)
                        ),
                        tooltip=[
                            "User-Agent",
                            "Hit Count",
                            "Direction",
                            "Last Action",
                        ],
                    )
                    .add_params(chart_selection)
                    .properties(height=205, background="transparent")
                    .configure_view(strokeOpacity=0)
                    .configure_axis(
                        labelColor=THEME["muted"],
                        titleColor=THEME["muted"],
                        gridColor=THEME["border"],
                        domainColor=THEME["border"],
                    )
                    .configure_legend(
                        labelColor=THEME["text"],
                        titleColor=THEME["muted"],
                    )
                )
                chart_event = st.altair_chart(
                    chart,
                    width="stretch",
                    key=f"hit_distribution_chart_{reset_nonce}",
                    on_select="rerun",
                    selection_mode="ua_click",
                )

                try:
                    selection_state = getattr(chart_event, "selection", {}) or {}
                    parsed = parse_chart_point_click(
                        selection_state, "ua_click", ["User-Agent", "Direction"]
                    )
                    clicked_ua = parsed.get("User-Agent")
                    if clicked_ua:
                        clicked_ua = str(clicked_ua)
                        clicked_direction = parsed.get("Direction")
                        if clicked_direction is None:
                            # Direction wasn't in the payload (or came back in a
                            # shape parse_chart_point_click didn't recognize) -
                            # resolve it from chart_data itself instead of
                            # requiring Vega-Lite to hand back a second field.
                            # If a UA appears under both directions in the
                            # chart, the higher hit-count one wins.
                            ua_rows = chart_data[chart_data["User-Agent"].astype(str) == clicked_ua]
                            if not ua_rows.empty:
                                clicked_direction = ua_rows.sort_values(
                                    "Hit Count", ascending=False
                                ).iloc[0]["Direction"]
                        click_key = f"{clicked_ua}\x1f{clicked_direction}"
                        # Vega-Lite persists this chart's OWN click-selection
                        # across reruns, tied to its widget key, entirely
                        # independent of session_state - the same way AG Grid
                        # persists its own row selection. Without this guard,
                        # it would unconditionally re-report the same old
                        # click on EVERY rerun (not just the one where it
                        # happened) and keep re-setting selected_ua right
                        # back to it, which would silently reopen the dialog
                        # right after the user closed it.
                        if click_key != st.session_state.get("_last_chart_click_key"):
                            if clicked_direction is not None:
                                # Same (User-Agent, Direction) tuple format the
                                # table's row-selection handler below uses, so
                                # this opens the identical inspector dialog.
                                # A chart click only opens the dialog - it
                                # doesn't filter the table (that was tried and
                                # reverted; the click is purely "show me this
                                # one event", the same as clicking its row).
                                st.session_state.selected_ua = (clicked_ua, str(clicked_direction))
                        st.session_state._last_chart_click_key = click_key
                    else:
                        st.session_state._last_chart_click_key = None
                except Exception:
                    pass

            with tab_donut:
                # Top 5 User-Agents by hit count, combined across directions
                # (a single UA can show up under both egress and ingress, and
                # the donut is meant to answer "which UAs dominate", not
                # "which UA+direction pairs"). Everything past the top 5 is
                # folded into a single "Other" slice so this stays readable
                # regardless of how long-tailed the traffic is.
                donut_totals = (
                    filtered_df.groupby("User-Agent", as_index=False)["Hit Count"]
                    .sum()
                    .sort_values("Hit Count", ascending=False)
                )
                total_hits = int(donut_totals["Hit Count"].sum())
                top_n = 5
                donut_rows = donut_totals.head(top_n).copy()
                rest = donut_totals.iloc[top_n:]
                if not rest.empty:
                    other_row = pd.DataFrame([{
                        "User-Agent": f"Other ({len(rest)} UAs)",
                        "Hit Count": int(rest["Hit Count"].sum()),
                    }])
                    donut_rows = pd.concat([donut_rows, other_row], ignore_index=True)
                donut_rows["Share"] = (
                    donut_rows["Hit Count"] / total_hits * 100 if total_hits else 0.0
                )

                donut_colors = THEME["donut"][: len(donut_rows)]
                donut_domain = list(donut_rows["User-Agent"])

                # bind="legend" is what makes the legend entries themselves
                # clickable, in addition to the default click-on-mark
                # behavior a point selection already gets from on="click" -
                # together that's "both the donut section and the key
                # items" per the ask. Only User-Agent is needed as the
                # selection key here (unlike the bar chart, which also needs
                # Direction to disambiguate stacked segments) since the
                # donut already collapses direction away.
                donut_selection = alt.selection_point(
                    name="donut_click",
                    fields=["User-Agent"],
                    on="click",
                    clear="dblclick",
                    bind="legend",
                    empty=True,
                )

                arc = (
                    alt.Chart(donut_rows)
                    .mark_arc(innerRadius=58, outerRadius=95, stroke=THEME["bg"], strokeWidth=2, cursor="pointer")
                    .encode(
                        theta=alt.Theta("Hit Count:Q", stack=True),
                        order=alt.Order("Hit Count:Q", sort="descending"),
                        color=alt.Color(
                            "User-Agent:N",
                            scale=alt.Scale(domain=donut_domain, range=donut_colors),
                            legend=alt.Legend(
                                title=None,
                                orient="right",
                                columns=1,
                                labelLimit=230,
                                symbolSize=170,
                                symbolStrokeWidth=0,
                                labelFontSize=12,
                                rowPadding=8,
                                labelColor=THEME["text"],
                            ),
                        ),
                        opacity=alt.condition(donut_selection, alt.value(1.0), alt.value(.55)),
                        tooltip=[
                            alt.Tooltip("User-Agent:N", title="User-Agent"),
                            alt.Tooltip("Hit Count:Q", title="Hits", format=","),
                            alt.Tooltip("Share:Q", title="% of total", format=".1f"),
                        ],
                    )
                    .add_params(donut_selection)
                )
                # Vega-Lite centers a mark_text layer with no positional
                # encoding in the middle of the plotting area by default,
                # which is what lands these two labels in the donut's hole.
                center_total = (
                    alt.Chart(pd.DataFrame({"v": [1]}))
                    .mark_text(size=24, fontWeight="bold", color=THEME["text"], dy=-6)
                    .encode(text=alt.value(f"{total_hits:,}"))
                )
                center_label = (
                    alt.Chart(pd.DataFrame({"v": [1]}))
                    .mark_text(size=9, color=THEME["muted"], dy=13)
                    .encode(text=alt.value("TOTAL HITS"))
                )
                donut_chart = (
                    alt.layer(arc, center_total, center_label)
                    .properties(height=280, background="transparent")
                    .configure_view(strokeOpacity=0)
                )
                donut_event = st.altair_chart(
                    donut_chart,
                    width="stretch",
                    key=f"hit_distribution_donut_{reset_nonce}",
                    on_select="rerun",
                    selection_mode="donut_click",
                )

                try:
                    donut_selection_state = getattr(donut_event, "selection", {}) or {}
                    donut_parsed = parse_chart_point_click(
                        donut_selection_state, "donut_click", ["User-Agent"]
                    )
                    donut_clicked_ua = donut_parsed.get("User-Agent")
                    if donut_clicked_ua:
                        donut_clicked_ua = str(donut_clicked_ua)
                        # Same "only adopt on genuine change" guard as the bar
                        # chart: Vega-Lite persists this donut's own
                        # click-selection across reruns tied to its widget
                        # key, independent of session_state, so without this
                        # it would keep re-reporting the same old click on
                        # every rerun rather than just the one it happened on.
                        if donut_clicked_ua != st.session_state.get("_last_donut_click_key"):
                            # "Other (N UAs)" is a synthetic rollup, not a
                            # real User-Agent value - there's no single event
                            # to open, so clicking it is a no-op.
                            if not donut_clicked_ua.startswith("Other ("):
                                # The donut collapses direction away (it sums
                                # a UA's hits across egress+ingress), but the
                                # inspector dialog needs one specific row -
                                # same tie-break as the bar chart: whichever
                                # direction has the higher hit count wins.
                                # Behaves exactly like a bar chart click: this
                                # only opens the dialog, it doesn't filter
                                # the table.
                                ua_rows = filtered_df[
                                    filtered_df["User-Agent"].astype(str) == donut_clicked_ua
                                ]
                                if not ua_rows.empty:
                                    donut_direction = ua_rows.sort_values(
                                        "Hit Count", ascending=False
                                    ).iloc[0]["Direction"]
                                    st.session_state.selected_ua = (donut_clicked_ua, str(donut_direction))
                            st.session_state._last_donut_click_key = donut_clicked_ua
                    else:
                        st.session_state._last_donut_click_key = None
                except Exception:
                    pass

                st.caption(
                    "Click a slice or a legend entry to open that User-Agent's "
                    "last matching event. \"Other\" groups multiple UAs and isn't clickable."
                )

    # table_df is what the table and the export reflect. Chart clicks
    # (bar or donut) no longer filter it - they only open the inspector
    # dialog for the clicked UA, the same as clicking its row in the table.
    table_df = filtered_df

    export_df = table_df.drop(columns=["Raw Payload"], errors="ignore")
    csv_bytes = export_df.to_csv(index=False).encode("utf-8")

    export_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    export_name_parts = ["user_agents"]
    if selected_device_serial:
        device_slug = re.sub(r"[^A-Za-z0-9]+", "-", selected_device_label).strip("-").lower()
        if device_slug:
            export_name_parts.append(device_slug)
    if egress_active:
        export_name_parts.append("egress")
    if ingress_active:
        export_name_parts.append("ingress")
    if suspicious_active:
        export_name_parts.append("suspicious")
    export_name_parts.append(export_timestamp)
    export_file_name = "_".join(export_name_parts) + ".csv"

    any_filter_active = bool(search_query)

    # Search bar + Export/Reset, all on one row directly above the table.
    # The search box doubles as the filter indicator now (see
    # sync_query_predicate/clear_direction_predicates above) - a separate
    # chip showing "TILE / egress" etc. was redundant with the tiles' own
    # pressed state, and truncated/overflowed on longer queries anyway, so
    # it's gone entirely; the search box's own width absorbs the space it
    # used to occupy. vertical_alignment keeps the text input and buttons on
    # a shared baseline; scoped CSS below removes the input's reserved label
    # space and normalizes both to the same height.
    st.markdown('<div class="section-label">Firewall / Filter / Search</div>', unsafe_allow_html=True)
    with st.container(key="filter_toolbar"):
        device_col, search_col, export_col, reset_col = st.columns(
            [2.0, 5.5, 0.85, 0.85], vertical_alignment="center"
        )
        with device_col:
            if devices_df.empty:
                st.selectbox(
                    "Firewall",
                    ["All Firewalls"],
                    index=0,
                    disabled=True,
                    label_visibility="collapsed",
                    key="device_selector_empty",
                    help="No firewalls have reported telemetry yet.",
                )
            else:
                device_options = ["All Firewalls"] + list(devices_df["Device Name"])
                current_index = (
                    device_options.index(selected_device_label)
                    if selected_device_label in device_options else 0
                )
                picked_label = st.selectbox(
                    "Firewall",
                    device_options,
                    index=current_index,
                    label_visibility="collapsed",
                    key="device_selector",
                    help=(
                        "Panorama-style device scope. All Firewalls aggregates "
                        "hit counts fleet-wide; picking a firewall by hostname "
                        "scopes the whole dashboard - metrics, chart, table, "
                        "export, and search - to just that device."
                    ),
                )
                if picked_label == "All Firewalls":
                    picked_serial = ""
                else:
                    picked_serial = devices_df.loc[
                        devices_df["Device Name"] == picked_label, "Device Serial"
                    ].iloc[0]
                if picked_serial != selected_device_serial:
                    set_selected_device(picked_serial)
        with search_col:
            # search_query is seeded from ?q= (or the cookie) near the top of
            # the script, but on a browser's first load that run is often
            # interrupted - the cookie component's first mount triggers a
            # rerun - before it gets this far. A value set in a run that
            # never created the widget isn't pushed to the browser when the
            # widget does get created on the next run, so the browser
            # started the box at its "" default, reported that back on the
            # following rerun, and the sync below then popped ?q= - a shared
            # filter link intermittently opened unfiltered. Re-asserting the
            # value here, in the same run that creates the widget, until the
            # widget has rendered once, makes Streamlit send it as a
            # genuinely new value.
            if not st.session_state.get("_search_widget_rendered"):
                st.session_state.search_query = st.session_state.search_query
            st.text_input(
                "Global Search",
                placeholder="search all fields, or try: (suspicious) and (addr.src in 10.0.0.0/8)",
                label_visibility="collapsed",
                key="search_query",
                help=(
                    "Plain text searches every column. Or use a PAN-OS-style filter, "
                    "with parentheses for grouping:\n\n"
                    "`((addr in 10.0.0.0/8) or (addr in 172.25.0.0/16)) and "
                    "(url contains claude)`\n\n"
                    "**Fields:** `user_agent`, `url`, `action`, `addr.src`, `addr.dst`, "
                    "`addr` (matches either src or dst), `device` (hostname), "
                    "`device.serial`\n"
                    "**Standalone filters:** `suspicious`, `egress`, `ingress` - these are "
                    "what the metric tiles above toggle for you, e.g. `(suspicious)`\n"
                    "**Operators:** `eq`, `neq`, `contains` (text fields), `in` (CIDR, IP fields)\n"
                    "**Combine with:** `and`, `or`, `not` / `!`, and parentheses (nest as deep as needed)\n\n"
                    "Values can be bare (`claude`, `curl/8.0`, `013101001234`) or "
                    "quoted (`'Mozilla/5.0 (Windows)'`) - quotes are only required for "
                    "a value with spaces or parentheses, one starting with `'` or `!`, "
                    "or one that is `and`, `or`, or `not`.\n\n"
                    "A query can mix structured syntax with trailing free text, e.g. "
                    "`(user_agent contains 'Mozilla') 10.200.36.70` - the trailing part "
                    "is ANDed in as an ordinary search-every-column match.\n\n"
                    "Example: `(suspicious) and (addr.src in 10.0.0.0/8) and (egress)`\n\n"
                    "For First Seen, Last Seen, or Hit Count, use the table's own column "
                    "sort/filter instead."
                ),
            )
            st.session_state._search_widget_rendered = True
            # Kept in sync with the URL only when it actually changed, not
            # on every render - otherwise a routine autorefresh tick would
            # rewrite query params for no reason.
            if st.session_state.search_query != st.session_state.get("_last_persisted_search_query"):
                if st.session_state.search_query:
                    st.query_params["q"] = st.session_state.search_query
                else:
                    st.query_params.pop("q", None)
                st.session_state._last_persisted_search_query = st.session_state.search_query
                _save_prefs_cookie()
        with export_col:
            st.download_button(
                label="⤓ EXPORT",
                data=csv_bytes,
                file_name=export_file_name,
                mime="text/csv",
                width="stretch",
            )
        with reset_col:
            st.button(
                "↺ RESET",
                width="stretch",
                on_click=reset_filters,
                key="reset_filters_button",
                disabled=not any_filter_active,
                help="No filters are currently applied" if not any_filter_active else None,
            )

    # -------------------------------------------------------------------------
    # AG GRID TELEMETRY TABLE
    # -------------------------------------------------------------------------
    # table_df reflects tile+search filtering only now - chart clicks (bar
    # or donut) just open the inspector dialog, they don't filter this.
    grid_df = table_df.drop(columns=["Raw Payload", "Device Serial"], errors="ignore").copy()

    # Stable row identity lets AG Grid preserve selection while the database
    # refreshes and rows are re-ordered.
    grid_df["_row_id"] = (
        grid_df["User-Agent"].astype(str) + "\x1f" + grid_df["Direction"].astype(str)
    )

    gb = GridOptionsBuilder.from_dataframe(grid_df)
    gb.configure_default_column(
        sortable=True,
        filter=True,
        resizable=True,
        minWidth=95,
        suppressHeaderMenuButton=False,
    )
    gb.configure_column("User-Agent", header_name="User-Agent", minWidth=260, filter="agTextColumnFilter")
    gb.configure_column("Last URL", header_name="Last URL", minWidth=220, filter="agTextColumnFilter", tooltipField="Last URL")
    gb.configure_column("Hit Count", header_name="Hits", minWidth=85, width=90, filter="agNumberColumnFilter")
    gb.configure_column("Direction", header_name="Direction", minWidth=105, width=110, filter="agTextColumnFilter")
    gb.configure_column("Device Name", header_name="Firewall", minWidth=130, width=145, filter="agTextColumnFilter")
    gb.configure_column("Last Action", header_name="Last Action", minWidth=115, width=120, filter="agTextColumnFilter")
    gb.configure_column("Last Src IP", header_name="Last Src IP", minWidth=135, width=145, filter="agTextColumnFilter")
    gb.configure_column("Last Dst IP", header_name="Last Dst IP", minWidth=135, width=145, filter="agTextColumnFilter")
    gb.configure_column("First Seen (UTC)", header_name="First Seen", minWidth=165, width=175, filter="agDateColumnFilter")
    gb.configure_column("Last Seen (UTC)", header_name="Last Seen", minWidth=165, width=175, filter="agDateColumnFilter")
    gb.configure_column("_row_id", hide=True, suppressColumnsToolPanel=True)

    grid_options = gb.build()
    grid_options["getRowId"] = JsCode("function(params) { return params.data._row_id; }")
    # Built from the same SUSPICIOUS_PATTERNS list the Suspicious tile and
    # the (suspicious) predicate use, rather than a hand-copied JS regex
    # literal that could drift out of sync with it.
    grid_options["rowClassRules"] = {
        "ua-suspicious-row": JsCode(
            "function(params) {\n"
            f"    return new RegExp({SUSPICIOUS_JS_REGEX_SOURCE}, 'i')"
            ".test(String(params.data['User-Agent'] || ''));\n"
            "}"
        )
    }
    grid_options["animateRows"] = False
    grid_options["suppressCellFocus"] = True
    grid_options["suppressRowHoverHighlight"] = False
    # AG Grid 32.2+ object form of row selection. This replaces
    # GridOptionsBuilder.configure_selection(), which still emits the
    # deprecated string form ("single") plus five legacy flags
    # (suppressRowClickSelection, rowMultiSelectWithClick, ...) that each
    # log a deprecation warning in the browser and are slated for removal -
    # the same kind of silent breakage components.html turned out to be.
    # Same behavior: one row at a time, selected by clicking it, no
    # checkbox column.
    grid_options["rowSelection"] = {
        "mode": "singleRow",
        "checkboxes": False,
        "enableClickSelection": True,
    }
    grid_options["enableCellTextSelection"] = True
    grid_options["tooltipShowDelay"] = 350
    grid_options["pagination"] = True
    grid_options["paginationPageSize"] = 25
    grid_options["paginationPageSizeSelector"] = [25, 50, 100]
    grid_options["defaultColDef"] = {
        **grid_options.get("defaultColDef", {}),
        "sortable": True,
        "filter": True,
        "resizable": True,
        "floatingFilter": False,
    }

    # Restore the last AG Grid state after a Streamlit rerun. streamlit-aggrid
    # exposes grid_state, and AG Grid accepts it through initialState.
    saved_grid_state = st.session_state.get("telemetry_grid_state")
    if saved_grid_state:
        grid_options["initialState"] = saved_grid_state

    grid_custom_css = {
        ".ag-root-wrapper": {
            "background-color": f"{THEME['panel']} !important",
            "border": f"1px solid {THEME['border']} !important",
            "border-radius": "7px !important",
            "overflow": "hidden !important",
        },
        ".ag-header": {
            "background-color": f"{THEME['panel2']} !important",
            "border-bottom": f"1px solid {THEME['border']} !important",
        },
        ".ag-header-cell-text": {
            "color": f"{THEME['text']} !important",
            "font-family": "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace !important",
        },
        ".ag-row": {
            "background-color": f"{THEME['panel']} !important",
            "border-bottom": f"1px solid {THEME['border']} !important",
        },
        ".ag-cell": {
            "color": f"{THEME['text']} !important",
            "font-family": "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace !important",
        },
        ".ag-row-hover:not(.ag-row-selected):not(.ua-suspicious-row)": {"background-color": f"{THEME['accent_dim']} !important"},
        ".ag-row-selected:not(.ua-suspicious-row)": {
            "background-color": f"{THEME['accent_dim']} !important",
            "border-left": f"2px solid {THEME['accent']} !important",
        },
        ".ag-row-selected:not(.ua-suspicious-row) .ag-cell": {
            "background-color": "transparent !important",
            "border-top": "0 !important",
            "border-bottom": "0 !important",
        },
        ".ua-suspicious-row": {
            "background-color": f"{THEME['suspicious_bg']} !important",
            "color": f"{THEME['suspicious_text']} !important",
            "font-weight": "600 !important",
            "border-left": f"2px solid {THEME['suspicious_border']} !important",
        },
        ".ua-suspicious-row.ag-row-hover": {
            "background-color": f"{THEME['suspicious_bg']} !important",
        },
        ".ag-row-selected.ua-suspicious-row": {
            "background-color": f"{THEME['suspicious_selected_bg']} !important",
            "color": f"{THEME['suspicious_selected_text']} !important",
            "font-weight": "800 !important",
            "border-left": f"3px solid {THEME['suspicious_border']} !important",
        },
        ".ag-cell-focus, .ag-cell-no-focus": {
            "border": "none !important",
            "outline": "none !important",
        },
    }

    st.markdown(
        '<div class="section-label">Telemetry</div>',
        unsafe_allow_html=True,
    )

    # reset_nonce was already read near the top of this section (shared with
    # the chart's key above). AG Grid remembers its own row selection
    # per-key across reruns; bumping this nonce forces a brand-new,
    # unselected grid instance instead of one that still thinks the old row
    # is selected.
    #
    # The filter signature is folded into the key too, rather than passed
    # as AgGrid(..., reload_data=...): an earlier version used reload_data
    # to force a real reload specifically on the run the filter criteria
    # changed (a new search term, tile, or chart-driven filter), while
    # reload_data=False preserved sort/scroll/selection state on every
    # other (filter-unchanged) refresh - fixing a bug where the table would
    # filter, then a moment later revert toward what it already had
    # rendered. Newer streamlit-aggrid releases silently no-op that
    # parameter ("DeprecationWarning: The 'reload_data' parameter has been
    # removed and has no effect"), which would have quietly brought that
    # bug back. Changing `key` itself has the same effect without depending
    # on that parameter at all: Streamlit always mounts a genuinely fresh
    # component when its key changes, so a filter change gets a clean
    # reload while an unchanged filter keeps the same key (and therefore
    # AG Grid's own preserved sort/scroll/selection) across routine
    # autorefresh ticks.
    filter_signature = "|".join(str(part) for part in (search_query, selected_device_serial))
    filter_sig_hash = hashlib.md5(filter_signature.encode()).hexdigest()[:10]
    grid_key = f"ua_telemetry_grid_{reset_nonce}_{filter_sig_hash}"

    grid_response = AgGrid(
        grid_df,
        gridOptions=grid_options,
        height=430,
        theme="streamlit",
        custom_css=grid_custom_css,
        allow_unsafe_jscode=True,
        key=grid_key,
        update_on=["sortChanged", "filterChanged", "selectionChanged", "stateUpdated"],
    )

    # Capture grid state immediately after any grid event. It is kept in
    # session_state so the next 5/10/15/... second refresh restores it.
    try:
        if getattr(grid_response, "grid_state", None):
            st.session_state.telemetry_grid_state = grid_response.grid_state
    except Exception:
        pass

    # Persist selection by stable identity rather than by row number.
    # streamlit-aggrid has returned selected_rows as both list-like and
    # DataFrame-like values across releases, so normalize it explicitly.
    try:
        selected_rows = getattr(grid_response, "selected_rows", None)
        if selected_rows is None:
            selected_rows = grid_response.get("selected_rows", [])

        if isinstance(selected_rows, pd.DataFrame):
            selected_records = selected_rows.to_dict("records")
        elif isinstance(selected_rows, dict):
            selected_records = [selected_rows]
        else:
            selected_records = list(selected_rows or [])

        if selected_records:
            selected_row = selected_records[0]
            if selected_row.get("User-Agent") is not None:
                grid_selection_key = f"{selected_row['Direction']}\x1f{selected_row['User-Agent']}"
                # AG Grid persists its own row-selection state across
                # reruns, tied to its widget key, independent of anything
                # session_state does. Without this check, it would
                # unconditionally re-report the same old row on EVERY
                # rerun (not just the one where the user actually clicked
                # it) and blindly overwrite selected_ua - clobbering a
                # fresher value something else (like a chart click) just
                # set this same run, and reopening a dialog someone had
                # just intentionally closed via Reset. Only adopt it when
                # it's genuinely different from what we last observed.
                if grid_selection_key != st.session_state.get("_last_grid_selection_key"):
                    st.session_state.selected_ua = (
                        str(selected_row["User-Agent"]),
                        str(selected_row["Direction"]),
                    )
                st.session_state._last_grid_selection_key = grid_selection_key
        else:
            st.session_state._last_grid_selection_key = None
    except Exception:
        pass

    # Inspector follows the selected UA across refreshes. With the dialog now
    # opened dismissible=False (see the note near show_syslog_inspector),
    # selected_ua only ever changes through code this app controls directly -
    # a new table/chart selection, the in-dialog Close button, or Reset - so
    # there's no more inference needed here at all: just show it whenever a
    # selection is active, on every run.
    selected = None
    if st.session_state.selected_ua:
        target_ua, target_direction = st.session_state.selected_ua
        matches = df[
            (df["User-Agent"] == target_ua)
            & (df["Direction"] == target_direction)
        ]
        if not matches.empty:
            selected = matches.iloc[0]

    if selected is not None:
        @st.dialog("Last Matching Event", width="large", dismissible=False)
        def show_syslog_inspector(row, direction, ua):
            # dismissible=False disables the native click-outside/Escape/X
            # dismiss entirely - Streamlit gives no callback for those, which
            # is what made closing impossible to detect reliably (the dialog
            # would sometimes close right after opening, or reopen later
            # while doing something unrelated elsewhere on the page). This
            # button is the only way to close it now, and its effect is
            # exactly what it looks like: no inference required.
            #
            # scope="app" is made explicit (it's already st.rerun()'s
            # default) because a dialog behaves like an st.fragment, and a
            # fragment-scoped rerun would only re-run this dialog function
            # itself rather than the outer script that decides whether to
            # invoke it at all - which would just redraw the same dialog
            # instead of closing it.
            _spacer, close_col = st.columns([0.93, 0.07])
            with close_col:
                if st.button("✕", key="close_inspector_dialog", width="stretch", help="Close"):
                    st.session_state.selected_ua = None
                    st.rerun(scope="app")

            action = str(row["Last Action"])
            action_css = action_class(action)
            url_value = str(row.get("Last URL", "") or "").strip()
            category_value = str(row.get("URL Category", "") or "").strip()
            ua_value = str(ua)
            raw_payload = row.get("Raw Payload", "")
            rule_name_value = extract_raw_field(raw_payload, PANOS_RULE_NAME_INDEX)
            source_user_value = extract_raw_field(raw_payload, PANOS_SOURCE_USER_INDEX)
            application_value = extract_raw_field(raw_payload, PANOS_APPLICATION_INDEX)

            # Built by sentry_ua.ui_helpers.render_event_tile (escaping and
            # all), with this app's cached country lookup plugged in.
            def tile_html(*args, **kwargs):
                return render_event_tile(*args, country_lookup=lookup_ip_country, **kwargs)

            # Grouped for a security-analyst read, top to bottom: what
            # matched (UA + PAN-OS's own App-ID classification alongside it,
            # a useful cross-check against a spoofed UA string) -> the policy
            # outcome (Action/Direction) -> which firewall enforced it
            # (Firewall/Serial Number - most useful right after direction,
            # since it answers "where did this happen" before drilling into
            # rule/category detail; in "All Firewalls" scope this is
            # whichever device most recently reported this pair) -> rule
            # context (Category/Rule) -> who (Source User) and how often
            # (Hits) -> the full URL on its own row, since it's usually the
            # longest field and benefits most from the extra width -> the
            # network pair (Source/Destination IP, together as requested)
            # -> timing.
            device_name_value = str(row.get("Device Name", "") or "").strip()
            device_serial_value = str(row.get("Device Serial", "") or "").strip()
            tiles = [
                tile_html("User-Agent", ua_value),
                tile_html("Application", application_value),
                tile_html("Action", action, action_css),
                tile_html("Direction", direction),
                # In "All Firewalls" scope this is whichever device most
                # recently reported this UA+direction pair - the same
                # "latest device's detail fields" rule every other detail
                # tile already follows in that scope.
                tile_html("Firewall", device_name_value),
                tile_html("Serial Number", device_serial_value),
                tile_html("URL Category", category_value),
                tile_html("Rule Name", rule_name_value),
                tile_html("Source User", source_user_value),
                tile_html("Hits", f"{int(row['Hit Count']):,}"),
                tile_html("Last URL", url_value, "event-tile-url event-tile-wide", link=True, url_lookup=True),
                tile_html("Last Source", row["Last Src IP"], ip_lookup=True),
                tile_html("Last Destination", row["Last Dst IP"], ip_lookup=True),
                tile_html("First Seen UTC", row["First Seen (UTC)"]),
                tile_html("Last Seen UTC", row["Last Seen (UTC)"]),
            ]
            event_doc = """<!doctype html><html><head><style>
            * { box-sizing:border-box; }
            body { margin:0; background:transparent; color:__TEXT__; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
            .event-tile-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; }
            .event-tile { position:relative; height:76px; padding:10px 40px 9px 11px; border:1px solid __BORDER__; border-radius:5px; background:__PANEL2__; overflow:hidden; }
            .event-tile-wide { grid-column:1 / -1; }
            .event-tile-ioc { padding-right:96px; }
            .event-tile-label { color:__MUTED__; font-size:9px; letter-spacing:.8px; text-transform:uppercase; margin-bottom:6px; }
            .event-tile-value { color:__TEXT__; font-size:12px; line-height:1.35; overflow-wrap:anywhere; max-height:48px; overflow:auto; }
            .event-tile-value a { color:__ACCENT__; text-decoration:none; }
            .event-tile-value a:hover { text-decoration:underline; }
            .event-tile-flag { margin-right:4px; font-size:20px; line-height:1; vertical-align:-3px; }
            .event-tile-country-code { margin-right:6px; color:__MUTED__; font-size:11px; }
            .event-tile-tag { display:inline-block; margin-right:6px; padding:1px 4px; font-size:8px; letter-spacing:.5px; border:1px solid __BORDER__; border-radius:3px; color:__MUTED__; vertical-align:middle; }
            .event-tile-actions { position:absolute; top:7px; right:7px; display:flex; align-items:center; gap:4px; opacity:0; transition:opacity .12s ease; }
            .event-tile:hover .event-tile-actions { opacity:1; }
            .event-copy { box-sizing:border-box; width:23px; height:23px; display:flex; align-items:center; justify-content:center; border:1px solid __BORDER__; border-radius:4px; background:__PANEL__; color:__MUTED__; font-size:9px; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; text-decoration:none; cursor:pointer; }
            .event-copy:hover { color:__ACCENT__; border-color:__ACCENT__; }
            </style></head><body><div class="event-tile-grid">__TILES__</div>
            <script>
            // This document is a data: URL (an opaque origin - see
            // isolated_iframe_src), which isn't a secure context, so
            // navigator.clipboard doesn't exist here; calling it threw
            // before the old .catch() fallback could ever run. Feature-
            // check it, and fall back to execCommand('copy') (allowed on a
            // real click), showing a check mark only when the copy worked.
            function copyValue(btn){
                const value = btn.getAttribute('data-copy-value') || '';
                const show = (ok) => { btn.textContent = ok ? '✓' : '✗'; setTimeout(()=>btn.textContent='⧉', 900); };
                const legacyCopy = () => {
                    const ta = document.createElement('textarea');
                    ta.value = value; document.body.appendChild(ta); ta.select();
                    let ok = false;
                    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
                    ta.remove(); show(ok);
                };
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(value).then(() => show(true)).catch(legacyCopy);
                } else {
                    legacyCopy();
                }
            }</script></body></html>"""
            # This iframe is a genuinely separate document (a data: URL -
            # see isolated_iframe_src) with no access to the parent page's
            # CSS, so it needs literal color values handed in rather than
            # var(--...).
            event_doc = (event_doc.replace("__TEXT__", THEME["text"]).replace("__BORDER__", THEME["border"])
                         .replace("__PANEL2__", THEME["panel2"]).replace("__MUTED__", THEME["muted"])
                         .replace("__ACCENT__", THEME["accent"]).replace("__PANEL__", THEME["panel"])
                         .replace("__TILES__", ''.join(tiles)))
            # 8 grid rows now (was 7, +1 for Firewall/Serial Number): 7
            # paired rows + 1 full-width Last URL row.
            # height = rows*76 + (rows-1)*8 gaps + ~20 breathing room.
            st.iframe(isolated_iframe_src(event_doc), height=684)
            st.markdown('<div class="section-label event-raw-label">Raw Syslog Payload</div>', unsafe_allow_html=True)
            st.code(str(row["Raw Payload"]), language="text")

        show_syslog_inspector(selected, target_direction, target_ua)

except Exception as e:
    st.warning(f"Waiting for database connection... ({e})")

st.markdown(
    f'''
    <div class="page-footer">
        <span>SENTRY//UA v{APP_VERSION}</span>
        <span class="footer-sep">·</span>
        <span>MIT License</span>
        <span class="footer-sep">·</span>
        <span>eqvsec</span>
        <span class="footer-sep">·</span>
        <a href="https://github.com/eqvsec" target="_blank" rel="noopener noreferrer">GitHub</a>
    </div>
    ''',
    unsafe_allow_html=True,
)
