import json

from lantern.report import read_bundle, render, safe_json

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
