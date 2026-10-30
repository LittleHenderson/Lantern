import base64
import hashlib
import json
import re

from lantern.report import read_bundle, render, safe_json, write_report

HOSTILE = ["</script><script>alert(1)</script>", "<!--<script>", "<!-- <script> -->", "]]>", "  ", "&lt;"]


def test_data_cannot_change_how_the_page_parses(tmp_path):
    """A docstring or route path like `<!--<script>` must not swallow the template's closing tag (it used to blank
    the whole report), and `</script>` must not end the data early."""
    bundle = {"graph": {"nodes": [{"id": "x", "doc": s} for s in HOSTILE]}, "texts": HOSTILE}
    html = render(bundle)
    data_part = html.split('id="lantern-data">', 1)[1].split("</script>", 1)[0]
    assert "<" not in data_part and ">" not in data_part
    assert json.loads(data_part) == bundle
    p = tmp_path / "report.html"
    p.write_text(html, encoding="utf-8")
    assert read_bundle(p) == bundle


def test_live_settings_and_nonce():
    html = render({"graph": {}}, live={"token": "t</script>"}, nonce="abc")
    assert 'window.LANTERN_LIVE = {"token":"t\\u003c/script\\u003e"}' in html
    assert "<script>" not in html and html.count('<script nonce="abc">') == 2


def test_safe_json_round_trips():
    for s in HOSTILE:
        assert json.loads(safe_json(s)) == s


def _policy(html: str) -> str:
    m = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)"', html)
    assert m, "the page carries no content policy"
    return m.group(1)


def _script_bodies(text: str) -> list[str]:
    return [m.group(2) for m in re.finditer(r"<script([^>]*)>(.*?)</script>", text, re.S)
            if "application/json" not in m.group(1)]


def test_standalone_report_carries_a_hash_content_policy():
    """A report opened from disk has no server to send headers, so the page carries its own policy: only scripts
    whose SHA-256 is listed may run, which refuses inline handlers and javascript: URLs planted in the data."""
    html = render({"graph": {}}, live={"token": "t"}, nonce="abc")
    policy = _policy(html)
    scripts = policy.split("script-src ")[1].split(";")[0]
    assert "'unsafe-inline'" not in scripts and "nonce-" not in scripts
    assert "default-src 'none'" in policy and "base-uri 'none'" in policy
    bodies = _script_bodies(html)
    assert len(bodies) == 2   # the live settings and the viewer; the data block is JSON and never runs
    for body in bodies:
        digest = base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode()
        assert f"'sha256-{digest}'" in scripts
    assert html.index("Content-Security-Policy") < html.index("<script")


def test_written_report_hashes_match_its_bytes(tmp_path):
    """The hashes cover the script bytes exactly as written, so the file must not be rewritten with CRLF
    (Windows) or the browser would refuse the report's own script."""
    from lantern.engine import build_graph
    (tmp_path / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    out = tmp_path / ".lantern"
    out.mkdir()
    path = write_report(out, build_graph(tmp_path), None, None)
    raw = path.read_bytes()
    assert b"\r\n" not in raw
    text = raw.decode("utf-8")
    scripts = _policy(text).split("script-src ")[1].split(";")[0]
    for body in _script_bodies(text):
        digest = base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode()
        assert f"'sha256-{digest}'" in scripts
    assert read_bundle(path)["graph"]["repo_root"]
