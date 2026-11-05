"""tools/uptime.py (the 30-minute live check) tells up, down, slow and behind apart, against local fake services."""
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import uptime  # noqa: E402


def serve(body, status=200, delay=0.0):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            time.sleep(delay)
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass
    httpd = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


@pytest.fixture
def summary(tmp_path):
    return tmp_path / "summary.md"


def test_both_up_and_current(capsys, summary):
    c, cu = serve({"ok": True, "service": "lantern-cloud", "version": "0.1.0", "engine": "0.10.0"})
    g, gu = serve({"ok": True, "version": "0.2.2", "model": "claude-haiku-5-5"})
    try:
        assert uptime.main(["--cloud", cu, "--gateway", gu, "--expect-engine", "0.10.0", "--summary", str(summary)]) == 0
    finally:
        c.shutdown()
        g.shutdown()
    out = capsys.readouterr().out
    assert "| lantern-cloud |" in out and "| ok |" in out and "engine 0.10.0" in out and "model claude-haiku-5-5" in out
    assert "## Uptime" in summary.read_text(encoding="utf-8")


def test_down_slow_and_not_ok_fail(capsys):
    port_closed = serve({})[0]
    url = f"http://127.0.0.1:{port_closed.server_address[1]}"
    port_closed.shutdown()
    port_closed.server_close()
    assert uptime.main(["--cloud", url]) == 1
    assert "DOWN" in capsys.readouterr().out
    s, su = serve({"ok": False, "version": "0.1.0"})
    try:
        assert uptime.main(["--gateway", su]) == 1
        assert "| DOWN |" in capsys.readouterr().out                 # answered, but not ok
    finally:
        s.shutdown()
    s, su = serve({"ok": True}, delay=0.6)
    try:
        assert uptime.main(["--gateway", su, "--slow-s", "0.2"]) == 1
        assert "| SLOW |" in capsys.readouterr().out
    finally:
        s.shutdown()
    s, su = serve({"error": "boom"}, status=500)
    try:
        assert uptime.main(["--cloud", su]) == 1
        assert "HTTP 500" in capsys.readouterr().out
    finally:
        s.shutdown()


def test_an_old_live_engine_is_behind(capsys):
    c, cu = serve({"ok": True, "service": "lantern-cloud", "version": "0.1.0", "engine": "0.9.0"})
    try:
        assert uptime.main(["--cloud", cu, "--expect-engine", "v0.10.0"]) == 1
        out = capsys.readouterr().out
        assert "BEHIND" in out and "redeploy" in out
        assert uptime.main(["--cloud", cu]) == 0                       # with no expectation, up is enough
        assert uptime.main(["--cloud", cu, "--expect-engine", "0.9.0"]) == 0
    finally:
        c.shutdown()


def test_version_order():
    assert uptime.vtuple("v0.10.0") > uptime.vtuple("0.9.9") and uptime.vtuple("0.10.0") == uptime.vtuple("0.10.0")
    assert uptime.vtuple("0.11.0rc1") > uptime.vtuple("0.10.0")
