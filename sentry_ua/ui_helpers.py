"""Small presentation helpers for the event inspector and charts: URL
normalization, chart click-payload parsing, action styling, IP
classification, the (uncached) IP -> country lookup, and the event
inspector's HTML tile renderer.

No Streamlit here - dashboard.py adds st.cache_data around the lookup."""
import base64
import html
import ipaddress
import re
import urllib.parse

import requests


def normalize_url_value(value):
    """PAN-OS's URL Filtering log field is conventionally just <domain>/
    <path>, with no http(s):// scheme prefix at all - the firewall doesn't
    log the scheme separately there. A strict "^https?://" check therefore
    silently treated every one of these as "not a URL": no hyperlink, no
    VirusTotal/Go buttons, even though the field was genuinely populated.

    Returns (is_url, href): href always carries an explicit scheme (http://
    assumed when none is present, since that's usable as a link target and
    for lookups either way) so it's ready to use as-is; is_url is False only
    for values that don't look like a domain+path at all (empty, or
    something with whitespace or no dot in the host part, which is unlikely
    to genuinely be one)."""
    if not value:
        return False, ""
    if re.match(r"^https?://", value, re.IGNORECASE):
        return True, value
    host_part = value.split("/", 1)[0]
    if " " not in value and "." in host_part:
        return True, f"http://{value}"
    return False, ""


def parse_chart_point_click(selection_state, param_name, fields):
    """Defensively pull the clicked datum's field values out of a Vega-Lite
    point-selection payload returned via st.altair_chart(on_select="rerun").

    Different Streamlit/Altair versions/configurations have been observed to
    shape this differently, so several known shapes are tried in order
    instead of assuming just one:
      1. {"User-Agent": ["value"], "Direction": ["value"]}   (dict of
         parallel lists, keyed by the field name given to fields=[...])
      2. [{"User-Agent": "value", "Direction": "value", ...}]  (a list of
         full selected-record dicts)
      3. {"vlPoint": {...}, "User-Agent": [...], ...}  (some versions nest
         point-selection metadata under a "vlPoint" key alongside the
         per-field lists)

    Returns a dict of {field: value_or_None}; every requested field is a key
    even if it couldn't be resolved, so callers can check individually.
    """
    result = {field: None for field in fields}
    if not isinstance(selection_state, dict):
        try:
            selection_state = dict(selection_state)
        except Exception:
            return result

    point = selection_state.get(param_name)
    if not point:
        return result

    # Shape 2: list of full record dicts.
    if isinstance(point, list):
        if not point:
            return result
        first = point[0]
        if isinstance(first, dict):
            for field in fields:
                if field in first:
                    result[field] = first[field]
        return result

    # Shapes 1 and 3: dict-like, field name -> value or parallel list.
    if isinstance(point, dict):
        for field in fields:
            values = point.get(field)
            if values is None:
                continue
            if isinstance(values, (list, tuple)):
                if values:
                    result[field] = values[0]
            else:
                result[field] = values
        return result

    return result


def action_class(action):
    action = str(action).lower()
    if action in {"block-url", "block-continue", "block-override", "override-lockout"}:
        return "danger"
    if action in {"alert", "continue", "override"}:
        return "warn"
    return "action"


def country_flag_emoji(country_code):
    """ISO 3166-1 alpha-2 code -> flag emoji, via the regional-indicator trick.
    No image assets involved, so it renders anywhere the browser/OS has an
    emoji font with flag support."""
    if not country_code or len(country_code) != 2 or not country_code.isalpha():
        return ""
    country_code = country_code.upper()
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code)


def classify_ip(ip_str):
    """Return (category, label) for an IP string.
    category is one of: "global", "private", "loopback", "link-local",
    "multicast", "reserved", "unspecified", or None if it doesn't parse."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return None, None
    if ip_obj.is_loopback:
        return "loopback", "Loopback address"
    if ip_obj.is_link_local:
        return "link-local", "Link-local address"
    if ip_obj.is_multicast:
        return "multicast", "Multicast address"
    if ip_obj.is_unspecified:
        return "unspecified", "Unspecified address"
    if ip_obj.is_private:
        return "private", "Private address (RFC 1918/4193)"
    if ip_obj.is_reserved:
        return "reserved", "Reserved address"
    return "global", None


def lookup_ip_country(ip_str):
    """Best-effort public IP -> ISO country lookup. Returns (code, name) or
    (None, None) on any failure; never raises, since this only decorates the
    UI and shouldn't be able to break the dialog if the network is slow or
    unavailable.

    Uses ipwho.is rather than ip-api.com: every public IP an analyst opens
    the inspector for gets sent to this lookup, and ip-api.com's free tier
    is HTTP-only (HTTPS requires a paid key) - plaintext, so the IOC being
    investigated is visible to anyone on the network path. ipwho.is offers
    the same no-API-key JSON lookup over HTTPS."""
    try:
        resp = requests.get(f"https://ipwho.is/{ip_str}", timeout=1.5)
        data = resp.json()
        if data.get("success"):
            return data.get("country_code"), data.get("country")
    except Exception:
        pass
    return None, None


def render_event_tile(label, value, extra_class="", link=False, ip_lookup=False, url_lookup=False,
                      country_lookup=lookup_ip_country):
    """One event-inspector tile as an HTML string. Every value rendered here
    can come straight from an unauthenticated syslog packet, so every piece
    of it - text, href, title, and data-* attributes - goes through
    html.escape(). country_lookup is injectable so dashboard.py can pass its
    st.cache_data-wrapped lookup (and tests can pass a stub that never
    touches the network)."""
    value = str(value) if value is not None else ""
    display = value if value else "—"

    ip_category = ip_category_label = None
    country_code = country_name = None
    if ip_lookup and value:
        ip_category, ip_category_label = classify_ip(value)
        if ip_category == "global":
            country_code, country_name = country_lookup(value)

    is_url, url_href = normalize_url_value(value)
    if link and is_url:
        safe_href = html.escape(url_href, quote=True)
        # Display text stays exactly as the log recorded it - we
        # don't rewrite the visible value just because href
        # needed an assumed scheme added for it to work as a link.
        safe_text = html.escape(value, quote=True)
        display_html = f'<a href="{safe_href}" target="_blank" rel="noopener noreferrer">{safe_text}</a>'
    else:
        display_html = html.escape(display)

    # A resolved public IP gets a country flag; anything private,
    # loopback, link-local, etc. gets a small tag instead, since a
    # flag/VT/AbuseIPDB lookup is meaningless for those.
    flag = country_flag_emoji(country_code) if country_code else ""
    if flag:
        flag_title = html.escape(country_name or country_code, quote=True)
        code_label = html.escape(country_code.upper())
        display_html = (
            f'<span class="event-tile-flag" title="{flag_title}">{flag}</span>'
            f'<span class="event-tile-country-code">({code_label})</span>{display_html}'
        )
    elif ip_category and ip_category != "global":
        tag_title = html.escape(ip_category_label or ip_category, quote=True)
        display_html = f'<span class="event-tile-tag" title="{tag_title}">{ip_category.upper()}</span>{display_html}'

    # The value to copy is passed via a data-* attribute (HTML-escaped
    # once) rather than inlined into the onclick handler. Embedding
    # json.dumps(value) directly inside an onclick="..." attribute
    # breaks on the FIRST character, because json.dumps wraps every
    # string in double quotes, which prematurely closes the
    # double-quoted onclick attribute itself.
    copy_value_attr = html.escape(value, quote=True)
    action_buttons = []
    has_triple_actions = False
    if ip_category == "global":
        has_triple_actions = True
        ip_quoted = urllib.parse.quote(value, safe=":")
        vt_url = html.escape(f"https://www.virustotal.com/gui/ip-address/{ip_quoted}", quote=True)
        abuse_url = html.escape(f"https://www.abuseipdb.com/check/{ip_quoted}", quote=True)
        action_buttons.append(
            f'<a class="event-copy" title="Look up on VirusTotal" target="_blank" rel="noopener noreferrer" href="{vt_url}">VT</a>'
        )
        action_buttons.append(
            f'<a class="event-copy" title="Look up on AbuseIPDB" target="_blank" rel="noopener noreferrer" href="{abuse_url}">AB</a>'
        )
    elif url_lookup and is_url:
        has_triple_actions = True
        # VirusTotal's "gui/url/<id>" links need their own base64
        # identifier scheme; the public search endpoint takes a
        # plain URL-encoded URL and gets to the same place
        # without needing to replicate that hashing ourselves.
        url_quoted = urllib.parse.quote(url_href, safe="")
        vt_search_url = html.escape(f"https://www.virustotal.com/gui/search/{url_quoted}", quote=True)
        go_url = html.escape(url_href, quote=True)
        action_buttons.append(
            f'<a class="event-copy" title="Look up on VirusTotal" target="_blank" rel="noopener noreferrer" href="{vt_search_url}">VT</a>'
        )
        action_buttons.append(
            f'<a class="event-copy" title="Open URL in a new tab" target="_blank" rel="noopener noreferrer" href="{go_url}">Go</a>'
        )
    action_buttons.append(
        f'<button class="event-copy" title="Copy" data-copy-value="{copy_value_attr}" onclick="copyValue(this)">⧉</button>'
    )

    tile_classes = extra_class
    if has_triple_actions:
        tile_classes = f"{tile_classes} event-tile-ioc".strip()

    return (
        f'<div class="event-tile {tile_classes}">'
        f'<div class="event-tile-label">{html.escape(label)}</div>'
        f'<div class="event-tile-value">{display_html}</div>'
        f'<div class="event-tile-actions">{"".join(action_buttons)}</div>'
        f'</div>'
    )


def isolated_iframe_src(html_doc):
    """The event inspector's tile document as a base64 data: URL, for
    st.iframe(). A data: URL document gets an opaque origin, so it can't
    reach the Streamlit app's DOM, cookies, or session no matter what
    sandbox flags the iframe carries - and every tile value in it comes
    straight from unauthenticated syslog.

    That isolation used to come from components.html's sandbox (no
    allow-same-origin). Current Streamlit renders components.html through
    st.iframe instead, which embeds an HTML *string* with
    allow-same-origin + allow-scripts - same-origin with the app - so
    passing the HTML as a data: URL is what keeps the inspector a separate
    origin. (html.escape() on every value remains the primary defense; this
    is the layer behind it.)"""
    encoded = base64.b64encode(html_doc.encode("utf-8")).decode("ascii")
    return f"data:text/html;charset=utf-8;base64,{encoded}"
