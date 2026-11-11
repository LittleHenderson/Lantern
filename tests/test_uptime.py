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
    s, su = serve({"ok": True}, delay=0.5)                          # the script waits 3x --slow-s; leave Windows room
    try:
        assert uptime.main(["--gateway", su, "--slow-s", "0.4"]) == 1
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


def test_clean_up_that_is_behind_fails_the_check(capsys):
    """lantern-cloud's health says one word about its own clean-up (stage 7): files of deleted runs that have waited
    for more than a day to be removed are an email to the owner, not a line nobody reads."""
    c, cu = serve({"ok": True, "service": "lantern-cloud", "version": "0.1.0", "engine": "0.10.0", "cleanup": "behind"})
    try:
        assert uptime.main(["--cloud", cu]) == 1
        got = capsys.readouterr()
        assert "| lantern-cloud clean-up |" in got.out and "| OWED |" in got.out and "/v1/admin/stats" in got.out
        assert "FAIL lantern-cloud clean-up" in got.err
    finally:
        c.shutdown()
    c, cu = serve({"ok": True, "service": "lantern-cloud", "version": "0.1.0", "cleanup": "unknown"})
    try:
        assert uptime.main(["--cloud", cu]) == 1
        assert "| UNKNOWN |" in capsys.readouterr().out
    finally:
        c.shutdown()


def test_clean_up_that_is_up_to_date_or_not_mentioned_passes(capsys):
    """The safe twins: "ok", and a live service from before the word existed (the check runs from the newest code
    against whatever is deployed)."""
    for body in ({"ok": True, "service": "lantern-cloud", "version": "0.1.0", "cleanup": "ok"},
                 {"ok": True, "service": "lantern-cloud", "version": "0.1.0"}):
        c, cu = serve(body)
        try:
            assert uptime.main(["--cloud", cu]) == 0
            assert "clean-up" not in capsys.readouterr().out
        finally:
            c.shutdown()
    g, gu = serve({"ok": True, "version": "0.2.5", "cleanup": "behind"})     # only lantern-cloud says this word
    try:
        assert uptime.main(["--gateway", gu]) == 0
    finally:
        g.shutdown()
