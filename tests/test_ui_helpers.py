"""sentry_ua.ui_helpers: URL normalization, chart click parsing, IP
classification, the country lookup, and - most importantly - that the
event inspector's HTML tiles escape every attacker-reachable value."""
import html
import re
from html.parser import HTMLParser

import pytest

from sentry_ua import ui_helpers as u


# --- URL normalization ----------------------------------------------------------

@pytest.mark.parametrize(
    "value, expected",
    [
        ("www.example.com/path", (True, "http://www.example.com/path")),  # PAN-OS's usual scheme-less form
        ("example.com", (True, "http://example.com")),
        ("https://example.com/a", (True, "https://example.com/a")),
        ("HTTP://EXAMPLE.COM", (True, "HTTP://EXAMPLE.COM")),
        ("198.51.100.23/payload.bin", (True, "http://198.51.100.23/payload.bin")),
        ("", (False, "")),
        (None, (False, "")),
        ("localhost/x", (False, "")),          # no dot in host part
        ("not a url.com", (False, "")),        # whitespace
    ],
)
def test_normalize_url_value(value, expected):
    assert u.normalize_url_value(value) == expected


def test_javascript_scheme_is_never_treated_as_a_bare_domain():
    # "javascript:alert(1).x" has a dot before the first slash - it must
    # still only ever come out as an http:// link target, never a
    # javascript: one.
    is_url, href = u.normalize_url_value("javascript:alert(1).x")
    assert not is_url or href.startswith("http://")


# --- chart click payload shapes -------------------------------------------------

@pytest.mark.parametrize(
    "state",
    [
        {"ua_click": {"User-Agent": ["curl"], "Direction": ["egress"]}},                 # shape 1
        {"ua_click": [{"User-Agent": "curl", "Direction": "egress", "Hit Count": 3}]},   # shape 2
        {"ua_click": {"vlPoint": {"or": []}, "User-Agent": ["curl"], "Direction": ["egress"]}},  # shape 3
        {"ua_click": {"User-Agent": "curl", "Direction": "egress"}},                     # scalars
    ],
)
def test_parse_chart_point_click_shapes(state):
    assert u.parse_chart_point_click(state, "ua_click", ["User-Agent", "Direction"]) == {
        "User-Agent": "curl",
        "Direction": "egress",
    }


@pytest.mark.parametrize(
    "state",
    [None, {}, {"ua_click": None}, {"ua_click": []}, {"ua_click": {"User-Agent": []}}, {"other": {}}, 42],
)
def test_parse_chart_point_click_empty(state):
    assert u.parse_chart_point_click(state, "ua_click", ["User-Agent", "Direction"]) == {
        "User-Agent": None,
        "Direction": None,
    }


# --- small classifiers ----------------------------------------------------------

@pytest.mark.parametrize(
    "action, css",
    [("block-url", "danger"), ("BLOCK-CONTINUE", "danger"), ("override-lockout", "danger"),
     ("alert", "warn"), ("continue", "warn"), ("allow", "action"), ("", "action"), (None, "action")],
)
def test_action_class(action, css):
    assert u.action_class(action) == css


@pytest.mark.parametrize(
    "code, flag",
    [("us", "🇺🇸"), ("DE", "🇩🇪"), ("", ""), (None, ""), ("USA", ""), ("1A", "")],
)
def test_country_flag_emoji(code, flag):
    assert u.country_flag_emoji(code) == flag


@pytest.mark.parametrize(
    "ip, category",
    [
        ("8.8.8.8", "global"),
        ("10.1.2.3", "private"),
        ("192.168.0.1", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link-local"),
        ("224.0.0.1", "multicast"),
        ("0.0.0.0", "unspecified"),
        ("2001:4860:4860::8888", "global"),
        ("fe80::1", "link-local"),
        ("not-an-ip", None),
        (None, None),
    ],
)
def test_classify_ip(ip, category):
    assert u.classify_ip(ip)[0] == category


# --- IP -> country lookup -------------------------------------------------------

class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


def test_lookup_uses_https_and_parses_success(monkeypatch):
    seen = []

    def fake_get(url, timeout):
        seen.append((url, timeout))
        return FakeResponse({"success": True, "country_code": "US", "country": "United States"})

    monkeypatch.setattr(u.requests, "get", fake_get)
    assert u.lookup_ip_country("8.8.8.8") == ("US", "United States")
    ((url, timeout),) = seen
    # Documented security fix: the IOC must never go out over plaintext HTTP.
    assert url == "https://ipwho.is/8.8.8.8"
    assert timeout <= 2


@pytest.mark.parametrize("payload", [{"success": False}, {}, None])
def test_lookup_failure_payloads(monkeypatch, payload):
    monkeypatch.setattr(u.requests, "get", lambda url, timeout: FakeResponse(payload))
    assert u.lookup_ip_country("8.8.8.8") == (None, None)


def test_lookup_never_raises(monkeypatch):
    def boom(url, timeout):
        raise u.requests.Timeout("slow")

    monkeypatch.setattr(u.requests, "get", boom)
    assert u.lookup_ip_country("8.8.8.8") == (None, None)


# --- event inspector tiles: escaping --------------------------------------------

def no_lookup(ip):
    return None, None


def tile(label, value, **kwargs):
    kwargs.setdefault("country_lookup", no_lookup)
    return u.render_event_tile(label, value, **kwargs)


PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "' onmouseover='alert(1)",
    '</div><svg onload=alert(1)>',
]

ALLOWED_TAGS = {"div", "a", "button", "span"}
ALLOWED_ATTRS = {"class", "title", "href", "target", "rel", "data-copy-value", "onclick"}


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def assert_no_injected_markup(rendered, payload):
    """Parses the tile as a browser would and checks that the only
    elements/attributes present are the ones render_event_tile itself
    emits - i.e. nothing in `payload` became markup."""
    assert payload not in rendered
    parser = _Collector()
    parser.feed(rendered)
    parser.close()
    for tag, attrs in parser.tags:
        assert tag in ALLOWED_TAGS, tag
        assert set(attrs) <= ALLOWED_ATTRS, attrs
        if "onclick" in attrs:
            # The only handler ever emitted: the copy button's fixed call.
            assert (tag, attrs["onclick"]) == ("button", "copyValue(this)")


@pytest.mark.parametrize("payload", PAYLOADS)
def test_plain_tile_escapes_value_and_copy_attribute(payload):
    rendered = tile("User-Agent", payload)
    assert_no_injected_markup(rendered, payload)
    assert html.escape(payload) in rendered
    assert f'data-copy-value="{html.escape(payload, quote=True)}"' in rendered


@pytest.mark.parametrize("payload", PAYLOADS)
def test_label_is_escaped(payload):
    assert_no_injected_markup(tile(payload, "x"), payload)


@pytest.mark.parametrize("payload", PAYLOADS)
def test_url_tile_escapes_href_text_and_lookup_links(payload):
    value = f"evil.example.com/{payload}"
    rendered = tile("Last URL", value, link=True, url_lookup=True)
    assert_no_injected_markup(rendered, payload)
    hrefs = re.findall(r'href="([^"]*)"', rendered)
    # A value containing whitespace isn't treated as a URL at all (no links);
    # otherwise: the link itself, VT search, Go.
    assert len(hrefs) == (0 if " " in value else 3)
    for href in hrefs:
        assert href.startswith(("http://", "https://www.virustotal.com/gui/search/"))
        assert "<" not in href and '"' not in href


def test_url_tile_never_links_non_http_schemes():
    for value in ("javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "vbscript:x"):
        rendered = tile("Last URL", value, link=True, url_lookup=True)
        assert 'href="javascript:' not in rendered
        assert 'href="data:' not in rendered
        assert 'href="vbscript:' not in rendered


def test_url_tile_display_text_is_unmodified_but_href_gets_scheme():
    rendered = tile("Last URL", "www.example.com/a?b=1&c=2", link=True, url_lookup=True)
    assert '>www.example.com/a?b=1&amp;c=2</a>' in rendered
    assert 'href="http://www.example.com/a?b=1&amp;c=2"' in rendered
    assert "https://www.virustotal.com/gui/search/http%3A%2F%2Fwww.example.com%2Fa%3Fb%3D1%26c%3D2" in rendered


def test_public_ip_tile_gets_flag_and_lookup_links():
    rendered = tile("Last Destination", "8.8.8.8", ip_lookup=True,
                    country_lookup=lambda ip: ("US", "United States"))
    assert "🇺🇸" in rendered and "(US)" in rendered
    assert 'href="https://www.virustotal.com/gui/ip-address/8.8.8.8"' in rendered
    assert 'href="https://www.abuseipdb.com/check/8.8.8.8"' in rendered


def test_country_lookup_result_is_escaped():
    # The lookup response is third-party data too.
    rendered = tile("Last Destination", "8.8.8.8", ip_lookup=True,
                    country_lookup=lambda ip: ("US", '"><script>alert(1)</script>'))
    assert "<script>" not in rendered


def test_private_ip_tile_gets_tag_and_no_lookup(monkeypatch):
    called = []
    rendered = tile("Last Source", "10.1.2.3", ip_lookup=True,
                    country_lookup=lambda ip: called.append(ip) or ("US", "x"))
    assert called == []  # private IPs are never sent to the lookup service
    assert "PRIVATE" in rendered
    assert "virustotal" not in rendered


def test_hostile_ip_field_is_not_looked_up_or_linked():
    payload = "8.8.8.8<script>"
    called = []
    rendered = tile("Last Source", payload, ip_lookup=True, country_lookup=lambda ip: called.append(ip))
    assert called == []
    assert "<script>" not in rendered
    assert "virustotal" not in rendered


def test_empty_value_shows_dash():
    assert ">—</div>" in tile("Rule Name", "")
    assert ">—</div>" in tile("Rule Name", None)


# --- inspector iframe isolation ---------------------------------------------

def test_isolated_iframe_src_is_a_data_url_that_round_trips():
    import base64

    doc = "<!doctype html><p>café ⧉ <b>x</b></p>"
    src = u.isolated_iframe_src(doc)
    prefix = "data:text/html;charset=utf-8;base64,"
    assert src.startswith(prefix)
    assert base64.b64decode(src[len(prefix):]).decode("utf-8") == doc


def test_isolated_iframe_src_contains_no_raw_markup():
    # Base64 means nothing in the document can break out of the src
    # attribute or be interpreted by the parent page.
    src = u.isolated_iframe_src('"><script>alert(1)</script>')
    assert "<" not in src and '"' not in src and "'" not in src
