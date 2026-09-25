"""Sentry UA - supporting modules for dashboard.py.

The dashboard's Streamlit page script (dashboard.py) stays at the repo root
so `streamlit run dashboard.py` keeps working unchanged; everything in this
package is plain Python with no Streamlit calls, so it can be imported and
unit-tested without a running app.
"""

# Bump this on every release worth distinguishing - shown in the Settings
# dialog's About section and in the footer at the bottom of the page, so a
# bug report or screenshot always carries which version it's from.
APP_VERSION = "1.0.0"
