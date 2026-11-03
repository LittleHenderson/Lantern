"""Simple/Advanced is one setting kept by `lantern serve`: saved by POST /api/settings, read back by GET /api/state
after a restart, and handed to the Atlas (report.html in the app's iframe) as LANTERN_LIVE.view_mode."""

import json
import re
import shutil
import threading
from http.server import ThreadingHTTPServer

from lantern.server import App, Handler, Store

from test_server import FIX, call, wait


def _start(home):
    store = Store(home)
    store.root.mkdir(exist_ok=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Handler.app = App(store, "tok-123", httpd.server_address[1])
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def _live(html: str) -> dict:
    m = re.search(r"window\.LANTERN_LIVE = (\{.*?\});</script>", html)
    assert m, "the report carries no LANTERN_LIVE"
    return json.loads(m.group(1))


def test_view_mode_round_trip_reaches_the_report(tmp_path):
    repo = tmp_path / "shop"
    shutil.copytree(FIX / "shop", repo)
    home = tmp_path / "home"
    httpd, base = _start(home)
    try:
        _, st = call(base, "/api/state")
        assert st["settings"]["view_mode"] == "simple"                     # the default
        _, p = call(base, "/api/projects", "POST", {"path": str(repo)})
        _, job = call(base, f"/api/projects/{p['id']}/analyze", "POST", {})
        assert wait(base, job["id"])["status"] == "done"
        assert _live(call(base, f"/p/{p['id']}/report.html")[1])["view_mode"] == "simple"

        code, r = call(base, "/api/settings", "POST", {"view_mode": "advanced"})
        assert code == 200 and r["settings"]["view_mode"] == "advanced"
        assert _live(call(base, f"/p/{p['id']}/report.html")[1])["view_mode"] == "advanced"
        # anything else is read as simple, never stored raw
        assert call(base, "/api/settings", "POST", {"view_mode": "<script>"})[1]["settings"]["view_mode"] == "simple"
        call(base, "/api/settings", "POST", {"view_mode": "advanced"})
        # without the write header the setting cannot be changed
        assert call(base, "/api/settings", "POST", {"view_mode": "simple"}, token=None)[0] == 403
    finally:
        httpd.shutdown()
        httpd.server_close()

    # a restart reads it back from settings.json
    assert json.loads((home / "settings.json").read_text(encoding="utf-8"))["view_mode"] == "advanced"
    httpd, base = _start(home)
    try:
        assert call(base, "/api/state")[1]["settings"]["view_mode"] == "advanced"
        pid = call(base, "/api/state")[1]["projects"][0]["id"]
        assert _live(call(base, f"/p/{pid}/report.html")[1])["view_mode"] == "advanced"
    finally:
        httpd.shutdown()
        httpd.server_close()
