"""Theme palettes and the app-wide CSS block.

Pure data/string building - no Streamlit calls here, so this can be
imported (and tested) without a running Streamlit app. dashboard.py
picks the active theme and injects app_css(THEME) via st.markdown.
"""

THEMES = {
    "night": {
        "name": "Night Ops",
        "accent": "#57f287",
        "accent_dim": "rgba(87, 242, 135, 0.16)",
        "bg": "#080b0d",
        "panel": "#0d1215",
        "panel2": "#11181c",
        "border": "#1e2a30",
        "text": "#e6edf0",
        "muted": "#819098",
        "danger": "#ff5c70",
        "warn": "#f4c95d",
        "chart": ["#57f287", "#36b9ff"],
        "donut": ["#57f287", "#36b9ff", "#f4c95d", "#ff5c70", "#a78bfa", "#2a363c"],
        "suspicious_bg": "rgba(255, 75, 75, 0.16)",
        "suspicious_text": "#ff9aa6",
        "suspicious_border": "#ff4b5b",
        "suspicious_selected_bg": "rgba(255, 75, 75, 0.28)",
        "suspicious_selected_text": "#ffd6da",
    },
    "graphite": {
        "name": "Graphite",
        "accent": "#72a7ff",
        "accent_dim": "rgba(114, 167, 255, 0.15)",
        "bg": "#0b0d10",
        "panel": "#111419",
        "panel2": "#171b21",
        "border": "#29313a",
        "text": "#e7ebef",
        "muted": "#89939e",
        "danger": "#ff6577",
        "warn": "#e8c66b",
        "chart": ["#72a7ff", "#8b9eff"],
        "donut": ["#72a7ff", "#8b9eff", "#e8c66b", "#ff6577", "#5fd4c4", "#333c46"],
        "suspicious_bg": "rgba(255, 75, 75, 0.16)",
        "suspicious_text": "#ff9aa6",
        "suspicious_border": "#ff4b5b",
        "suspicious_selected_bg": "rgba(255, 75, 75, 0.28)",
        "suspicious_selected_text": "#ffd6da",
    },
    "amber": {
        "name": "Amber Console",
        "accent": "#ffb454",
        "accent_dim": "rgba(255, 180, 84, 0.14)",
        "bg": "#0b0a08",
        "panel": "#13110e",
        "panel2": "#1a1712",
        "border": "#302a20",
        "text": "#eee9df",
        "muted": "#9b9283",
        "danger": "#ff6b5e",
        "warn": "#ffd166",
        "chart": ["#ffb454", "#ff7a59"],
        "donut": ["#ffb454", "#ff7a59", "#ffd166", "#ff6b5e", "#8ec9ff", "#332c22"],
        "suspicious_bg": "rgba(255, 75, 75, 0.16)",
        "suspicious_text": "#ff9aa6",
        "suspicious_border": "#ff4b5b",
        "suspicious_selected_bg": "rgba(255, 75, 75, 0.28)",
        "suspicious_selected_text": "#ffd6da",
    },
}


def app_css(THEME):
    """The dashboard's global <style> block, with the given theme's
    colors substituted in as CSS custom properties. Moved verbatim out of
    dashboard.py - the CSS itself is unchanged."""
    return (
    f"""
    <style>
        :root {{
            --accent: {THEME['accent']};
            --accent-dim: {THEME['accent_dim']};
            --bg: {THEME['bg']};
            --panel: {THEME['panel']};
            --panel2: {THEME['panel2']};
            --border: {THEME['border']};
            --text: {THEME['text']};
            --muted: {THEME['muted']};
            --danger: {THEME['danger']};
            --warn: {THEME['warn']};
        }}

        .stApp {{
            background: linear-gradient(180deg, var(--bg) 0%, var(--bg) 100%);
            color: var(--text);
        }}

        /* The streamlit_cookies_controller component is a purely functional,
           invisible helper (it only talks to document.cookie) - it has no
           UI of its own and should never occupy layout space. Its iframe's
           actual rendered height is set dynamically by its own JS reporting
           a size back to Streamlit; that self-reported size can apparently
           lag/go stale on some reruns (observed correlating with the grid
           going empty, though the underlying cause is almost certainly
           re-mount/reporting timing rather than row count itself), leaving
           real box height where there should be none - visible as a gap
           between the header and the top of the viewport, since this
           component is instantiated at module scope before anything else
           in the script renders. Forcing it to true zero height via CSS
           sidesteps the self-reported-size race entirely rather than
           chasing its exact trigger - the component's JS still runs and
           still reads/writes cookies normally with display:none, since
           that only affects rendering, not script execution. */
        div:has(> iframe[title*="cookie_controller"]) {{
            display: none !important;
            height: 0 !important;
            margin: 0 !important;
            padding: 0 !important;
        }}
        header[data-testid="stHeader"] {{ display: none !important; }}
        #MainMenu {{ visibility: hidden !important; }}
        footer {{ visibility: hidden !important; }}

        .block-container {{
            max-width: 1820px;
            padding-top: .7rem;
            padding-bottom: 1.4rem;
            padding-left: 1.35rem;
            padding-right: 1.35rem;
        }}
        h1, h2, h3, p, label {{ color: var(--text); }}

        .brand {{
            display: flex;
            align-items: baseline;
            gap: 10px;
            min-height: 28px;
        }}
        .brand-main {{
            color: var(--text);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 1.42rem;
            font-weight: 760;
            letter-spacing: -1px;
        }}
        .brand-slash {{ color: var(--accent); }}
        .brand-sub {{
            color: var(--muted);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .62rem;
            letter-spacing: 1.5px;
            text-transform: uppercase;
        }}
        .statusline {{
            color: var(--muted);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .61rem;
            text-align: right;
            padding-top: 3px;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 5px;
            white-space: nowrap;
        }}
        .live {{ color: var(--accent); }}
        .status-sep {{ color: var(--border); }}

        .section-label {{
            color: var(--muted);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .59rem;
            letter-spacing: 1.25px;
            text-transform: uppercase;
            margin: 10px 0 5px 1px;
        }}
        .micro {{
            color: var(--muted);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .59rem;
            letter-spacing: .45px;
        }}

        /* Compact, identical-height filter tiles. */
        .st-key-metric_tile_all button,
        .st-key-metric_tile_egress button,
        .st-key-metric_tile_ingress button,
        .st-key-metric_tile_suspicious button {{
            height: 64px !important;
            min-height: 64px !important;
            max-height: 64px !important;
            padding: 8px 13px !important;
            margin: 0 !important;
            background: linear-gradient(180deg, var(--panel2), var(--panel)) !important;
            color: var(--text) !important;
            border: 1px solid var(--border) !important;
            border-radius: 6px !important;
            box-shadow: none !important;
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .72rem;
            font-weight: 520;
            text-align: left;
            justify-content: flex-start;
        }}
        .st-key-metric_tile_all button:hover,
        .st-key-metric_tile_egress button:hover,
        .st-key-metric_tile_ingress button:hover,
        .st-key-metric_tile_suspicious button:hover {{
            border-color: var(--accent) !important;
            color: var(--accent) !important;
        }}

        .stButton > button {{
            border-color: var(--border) !important;
            background: var(--panel) !important;
            color: var(--muted) !important;
            border-radius: 5px !important;
        }}
        .stButton > button:hover {{
            border-color: var(--accent) !important;
            color: var(--accent) !important;
        }}
        .stTextInput input,
        .stSelectbox div[data-baseweb="select"] {{
            background-color: var(--panel) !important;
            border-color: var(--border) !important;
            color: var(--text) !important;
        }}

        /* Header controls: a manual refresh button, the play/pause
           autorefresh toggle, and the settings gear - three compact square
           icon buttons, right-aligned as a group. Same shrink-wrap-then-
           right-align technique used elsewhere in the header (the columns
           default to large proportional widths regardless of how small a
           button is, so without this the buttons would sit far apart with
           a lot of dead space between them rather than snug next to each
           other). */
        div[data-testid="stHorizontalBlock"]:has(.st-key-settings_gear) {{
            align-items: center !important;
            justify-content: flex-end !important;
            gap: 8px !important;
        }}
        div[data-testid="stColumn"]:has(.st-key-manual_refresh),
        div[data-testid="stColumn"]:has(.st-key-autorefresh_toggle),
        div[data-testid="stColumn"]:has(.st-key-settings_gear) {{
            flex: 0 0 auto !important;
            width: auto !important;
            min-width: 0 !important;
        }}
        .st-key-manual_refresh,
        .st-key-autorefresh_toggle,
        .st-key-settings_gear {{
            margin: 0 !important;
            width: auto !important;
        }}
        .st-key-manual_refresh button,
        .st-key-autorefresh_toggle button,
        .st-key-settings_gear button {{
            width: 28px !important;
            min-width: 28px !important;
            max-width: 28px !important;
            height: 28px !important;
            min-height: 28px !important;
            max-height: 28px !important;
            padding: 0 !important;
            margin: 0 !important;
            border-radius: 4px !important;
            font-size: .85rem !important;
        }}
        /* Settings dialog's own Close button - same square icon style,
           pulled up to sit on the same line as the dialog's own title, the
           same technique used for the event inspector's Close button. */
        .st-key-close_settings_dialog {{
            margin: -48px 0 20px 0 !important;
            margin-left: auto !important;
            position: relative;
            z-index: 5;
        }}
        .st-key-close_settings_dialog button {{
            width: 28px !important;
            min-width: 28px !important;
            max-width: 28px !important;
            height: 28px !important;
            min-height: 28px !important;
            max-height: 28px !important;
            padding: 0 !important;
            margin: 0 !important;
            border-radius: 4px !important;
            font-size: .85rem !important;
        }}
        .settings-popover-title {{
            color: var(--muted);
            font-size: 10px;
            letter-spacing: .8px;
            text-transform: uppercase;
            margin: 12px 0 6px 0;
        }}
        .settings-popover-title:first-child {{
            margin-top: 0;
        }}
        .about-block {{
            border-top: 1px solid var(--border);
            margin-top: 4px;
            padding-top: 10px;
        }}
        .about-author {{
            color: var(--text);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .78rem;
            font-weight: 700;
            letter-spacing: .4px;
        }}
        .about-motto {{
            color: var(--muted);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .65rem;
            font-style: italic;
            margin-top: 2px;
        }}
        .about-links {{
            margin-top: 8px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .65rem;
        }}
        .about-links a {{
            color: var(--accent);
            text-decoration: none;
        }}
        .about-links a:hover {{
            text-decoration: underline;
        }}
        .about-sep {{
            color: var(--border);
            margin: 0 6px;
        }}
        .about-version {{
            color: var(--muted);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .58rem;
            letter-spacing: .5px;
            margin-top: 10px;
        }}
        .page-footer {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            margin-top: 22px;
            padding-top: 12px;
            border-top: 1px solid var(--border);
            color: var(--muted);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .58rem;
            letter-spacing: .4px;
        }}
        .page-footer a {{
            color: var(--muted);
            text-decoration: none;
        }}
        .page-footer a:hover {{
            color: var(--accent);
        }}
        .page-footer .footer-sep {{
            color: var(--border);
        }}
        /* Event inspector dialog's Close button - same compact square icon
           style as the header's theme toggle. Pulled up with a negative
           margin so it sits on the same line as the dialog's own "Last
           Matching Event" title rather than on its own row below it -
           Streamlit renders that title itself, so there's no element of
           ours to place literally inside that row; this is the closest
           equivalent without reaching into Streamlit's internal DOM
           structure, which isn't a documented/stable target. The exact
           offset may need a small nudge once you can see it rendered. */
        .st-key-close_inspector_dialog {{
            margin: -48px 0 20px 0 !important;
            margin-left: auto !important;
            position: relative;
            z-index: 5;
        }}
        .st-key-close_inspector_dialog button {{
            width: 28px !important;
            min-width: 28px !important;
            max-width: 28px !important;
            height: 28px !important;
            min-height: 28px !important;
            max-height: 28px !important;
            padding: 0 !important;
            margin: 0 !important;
            border-radius: 4px !important;
            font-size: .85rem !important;
        }}
        .st-key-refresh_selector [data-testid="stWidgetLabel"] {{
            display: none !important;
        }}
        .st-key-refresh_selector [data-baseweb="select"],
        .st-key-refresh_selector [data-baseweb="select"] > div {{
            min-height: 28px !important;
            height: 28px !important;
            max-height: 28px !important;
            box-sizing: border-box !important;
            overflow: hidden !important;
        }}
        .st-key-refresh_selector [data-baseweb="select"] > div {{
            padding-top: 0 !important;
            padding-bottom: 0 !important;
        }}
        /* The value container and the indicator (chevron) wrapper are both
           direct children of the control div above. BaseWeb gives each of
           them their own min-height (around 38px by default); since
           min-height always wins over a shorter height in the CSS box model,
           that would otherwise keep the closed control taller than
           intended. Reset min-height on both so the 28px cap takes effect. */
        .st-key-refresh_selector [data-baseweb="select"] > div > div {{
            min-height: 0 !important;
            height: 26px !important;
            max-height: 26px !important;
            padding-top: 0 !important;
            padding-bottom: 0 !important;
            align-items: center !important;
        }}
        .st-key-refresh_selector [data-baseweb="select"] [data-baseweb="select-value-container"] {{
            padding-top: 0 !important;
            padding-bottom: 0 !important;
            min-height: 0 !important;
            height: 26px !important;
            max-height: 26px !important;
            align-items: center !important;
        }}
        .st-key-refresh_selector [data-baseweb="select"] * {{
            line-height: 26px !important;
        }}
        .st-key-metric_tile_all button[kind="primary"],
        .st-key-metric_tile_egress button[kind="primary"],
        .st-key-metric_tile_ingress button[kind="primary"],
        .st-key-metric_tile_suspicious button[kind="primary"] {{
            border-color: var(--accent) !important;
            background: var(--accent-dim) !important;
            color: var(--accent) !important;
            box-shadow: inset 0 0 0 1px var(--accent) !important;
        }}

        .stDialog {{
            background: var(--panel) !important;
        }}
        .event-tile-grid {{
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 8px;
            margin-top: 10px;
        }}
        .event-tile {{
            position: relative;
            min-height: 68px;
            box-sizing: border-box;
            padding: 10px 34px 10px 11px;
            border: 1px solid var(--border);
            border-radius: 5px;
            background: var(--panel2);
            overflow: hidden;
        }}
        .event-tile-label {{
            color: var(--muted);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .55rem;
            letter-spacing: .8px;
            text-transform: uppercase;
            margin-bottom: 5px;
        }}
        .event-tile-value {{
            color: var(--text);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .72rem;
            line-height: 1.35;
            overflow-wrap: anywhere;
        }}
        .event-copy {{
            position: absolute;
            top: 7px;
            right: 7px;
            width: 23px;
            height: 23px;
            padding: 0;
            border: 1px solid var(--border);
            border-radius: 4px;
            background: var(--panel);
            color: var(--muted);
            font: 11px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            cursor: pointer;
            opacity: 0;
            transition: opacity .12s ease, color .12s ease, border-color .12s ease;
        }}
        .event-tile:hover .event-copy {{ opacity: 1; }}
        .event-copy:hover {{ color: var(--accent); border-color: var(--accent); }}
        .event-tile-url .event-tile-value a {{ color: var(--accent); text-decoration: none; }}
        .event-tile-url .event-tile-value a:hover {{ text-decoration: underline; }}
        .event-raw-label {{ margin-top: 14px; }}
        [data-testid="stDialog"] .inspector-modal-content {{
            margin-top: -4px;
        }}
        .kv-wide {{
            grid-column: 1 / -1;
        }}
        .stDialog .stCodeBlock {{
            max-height: 360px;
            overflow: auto;
        }}

        /* Search bar + filter chip + Export/Reset row. Same underlying issue
           as the header refresh selector: a text_input's collapsed label
           still reserves vertical space by default, which would otherwise
           knock it out of alignment with the buttons and chip beside it. */
        .st-key-filter_toolbar [data-testid="stWidgetLabel"] {{
            display: none !important;
        }}
        .st-key-filter_toolbar .stTextInput,
        .st-key-filter_toolbar .stButton,
        .st-key-filter_toolbar [data-testid="stDownloadButton"] {{
            margin: 0 !important;
        }}
        .st-key-filter_toolbar .stTextInput input {{
            height: 38px !important;
            box-sizing: border-box !important;
        }}
        .st-key-filter_toolbar .stButton > button,
        .st-key-filter_toolbar [data-testid="stDownloadButton"] > button {{
            height: 38px !important;
            min-height: 38px !important;
            max-height: 38px !important;
            box-sizing: border-box !important;
            font-size: .62rem !important;
            letter-spacing: .5px;
        }}
        /* The filter chip is a plain st.markdown div, which doesn't carry the
           same reserved-label spacing as a widget, but Streamlit still wraps
           it in its own element container with default margins that don't
           necessarily match the widgets beside it - enough to knock the chip
           a few pixels off the shared baseline. Zero every wrapper's margin
           and force the markdown container itself to the same 38px, flex-
           centered, so the chip lines up regardless of Streamlit version. */
        .st-key-filter_toolbar [data-testid="stElementContainer"],
        .st-key-filter_toolbar .element-container {{
            margin: 0 !important;
        }}

        .inspector {{
            background: linear-gradient(180deg, var(--panel2), var(--panel));
            border: 1px solid var(--border);
            border-left: 3px solid var(--accent);
            border-radius: 6px;
            padding: 12px 14px 11px;
            margin-top: 8px;
        }}
        .inspector-title {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .67rem;
            letter-spacing: 1.2px;
            text-transform: uppercase;
            color: var(--accent);
            margin-bottom: 5px;
        }}
        .inspector-ua {{
            color: var(--text);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .78rem;
            word-break: break-word;
        }}
        .kv {{
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 6px;
            margin-top: 8px;
        }}
        .kv-item {{
            background: rgba(255,255,255,.012);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 6px 8px;
        }}
        .kv-label {{
            color: var(--muted);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .54rem;
            text-transform: uppercase;
            letter-spacing: .8px;
        }}
        .kv-value {{
            color: var(--text);
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: .67rem;
            margin-top: 2px;
            word-break: break-word;
        }}
        .action {{ color: var(--accent); }}
        .danger {{ color: var(--danger); }}
        .warn {{ color: var(--warn); }}
        .muted {{ color: var(--muted); }}

        @media (max-width: 900px) {{
            .brand-sub {{ display: none; }}
            .kv {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
            .block-container {{ padding-left: .8rem; padding-right: .8rem; }}
        }}
    </style>
    """
    )
