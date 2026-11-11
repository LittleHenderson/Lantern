"""How to use Lantern: the guide page with animated demos, served by `lantern serve` and by lantern-cloud at /guide,
linked from the main menu of both. The demos are fixed data played by one player; every numbered step has an
instruction (gold words), and the page keeps the app's look and its script policy."""

import re
import sys
import threading
import urllib.request
from html.parser import HTMLParser
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from lantern import guide
from lantern.server import App, Handler, Store

ROOT = Path(__file__).resolve().parents[1]
APP_HTML = (guide.VIEWER / "app.html").read_text(encoding="utf-8")
SRC = (guide.VIEWER / "guide.html").read_text(encoding="utf-8")


def test_the_page_is_built_from_the_app_and_every_script_carries_the_nonce():
    html, nonce = guide.page("9.9.9", "/")
    assert "/*__APP_" not in html and "<!--__APP_" not in html and "__OPEN_HREF__" not in html
    assert html.count("<script") == html.count(f'<script nonce="{nonce}">') == 1
    assert guide.app_parts(APP_HTML)["style"][:200] in html   # the app's own tokens and styles
    assert "Lantern 9.9.9" in html
    assert re.search(r'<a class="btn primary openbtn" href="/">Open Lantern</a>', html)


def test_open_link_must_stay_on_this_site():
    for bad in ("https://evil.example/", "javascript:alert(1)", "//evil.example", '/"><script>'):
        with pytest.raises(ValueError):
            guide.page("1", bad)


def test_a_changed_app_page_fails_loudly():
    with pytest.raises(ValueError, match="changed shape"):
        guide.app_parts(APP_HTML.replace("// Icons: fixed markup, never data.", "// icons"))


class _Steps(HTMLParser):
    """Each numbered step (an <li> in ol.steps) and whether it holds a span.do."""

    def __init__(self):
        super().__init__()
        self.in_steps = self.in_li = False
        self.items = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "ol" and a.get("class") == "steps":
            self.in_steps = True
        elif tag == "li" and self.in_steps:
            self.in_li = True
            self.items.append({"do": False, "text": ""})
        elif tag == "span" and self.in_li and a.get("class") == "do":
            self.items[-1]["do"] = True

    def handle_endtag(self, tag):
        if tag == "ol":
            self.in_steps = False
        elif tag == "li":
            self.in_li = False

    def handle_data(self, data):
        if self.in_li:
            self.items[-1]["text"] += data


def test_every_numbered_step_has_an_instruction_and_every_section_a_demo():
    p = _Steps()
    p.feed(SRC)
    assert len(p.items) >= 36
    assert [i["text"] for i in p.items if not i["do"]] == []
    sections = re.findall(r'<section class="gsec[^"]*" id="(how-[a-z-]+)"', SRC)
    assert len(sections) == 15                                   # tour, 12 tasks, shortcuts, honest note
    videos = re.findall(r'data-video="([a-z]+)"', SRC)
    assert len(videos) == 13 and len(set(videos)) == 13
    for v in videos:                                             # each demo's data exists, with 4 to 9 scenes
        m = re.search(rf"\n  {v}: \{{title: '([^']|\\')+', scenes: \[(.*?)\n  \]\}},", SRC, re.S)
        assert m, v
        n = len(re.findall(r"^\s+\{(?:off|on|cur|cls|set|world)", m.group(2), re.M))
        assert 4 <= n <= 9, (v, n)
    assert SRC.count('class="info"') >= 13                        # a Good to know box per task, plus the shortcuts


def test_the_page_keeps_the_owner_s_three_kinds_of_text_and_less_motion():
    assert "Glowing gold words</span> = do this" in SRC and "Plain text = what you'll see" in SRC
    assert "Blue boxes</span> = good to know" in SRC
    assert "animation:glow 2.6s ease-in-out infinite" in SRC
    assert "@media (prefers-reduced-motion: reduce)" in SRC and "text-decoration-thickness:2px" in SRC
    assert "Animated demo · not a screen recording" in SRC
    assert "aria-live', 'polite'" in SRC and "setAttribute('role', 'img')" in SRC
    assert "IntersectionObserver" in SRC and "STEP_MS = 4600" in SRC
    # captions and labels are placed as text, never as HTML
    player = SRC[SRC.index("class Player"):SRC.index("// the contents list")]
    assert "innerHTML" not in player.replace("this.cursor.innerHTML = '<span class=\"ring\"></span>' + CURSOR_SVG;", "")
    # no section id may collide with an id the app's stylesheet styles (#ask is a fixed panel there)
    styled = set(re.findall(r"#([a-z][a-z-]*)\{", guide.app_parts(APP_HTML)["style"]))
    ids = set(re.findall(r'\bid="([^"]+)"', SRC))
    assert not (ids & styled) - {"theme", "home"}


def test_both_menus_link_to_the_guide():
    site = (ROOT / "cloud" / "lantern_cloud" / "site" / "index.html").read_text(encoding="utf-8")
    for page in (APP_HTML, site):
        assert '<button data-v="guide" aria-label="How to use Lantern"' in page
        assert "<span>How to use Lantern</span>" in page
        assert "b.dataset.v === 'guide') { location.href = '/guide'" in page


@pytest.fixture()
def srv(tmp_path):
    store = Store(tmp_path / "home")
    store.root.mkdir()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    Handler.app = App(store, "tok-123", port)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def test_lantern_serve_sends_the_guide_with_its_script_policy(srv):
    with urllib.request.urlopen(srv + "/guide") as r:   # fixed content: no sign-in link needed
        body = r.read().decode("utf-8")
        csp = r.headers["Content-Security-Policy"]
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    assert f'<script nonce="{nonce}">' in body and "How to use Lantern" in body
    assert "tok-123" not in body


def test_the_website_sends_the_guide(tmp_path):
    pytest.importorskip("fastapi")
    httpx = pytest.importorskip("httpx")
    sys.path.insert(0, str(ROOT / "gateway"))
    sys.path.insert(0, str(ROOT / "cloud"))
    from fastapi.testclient import TestClient
    from lantern_cloud.app import create_app
    from lantern_cloud.settings import Settings
    s = Settings(gateway_url="http://gateway.test/v1", public_url="https://lantern.example", db_path=str(tmp_path / "c.db"),
                 results_dir=str(tmp_path / "r"), work_dir=str(tmp_path / "w"), audits=False)
    c = TestClient(create_app(s, transport=httpx.MockTransport(lambda r: httpx.Response(404)), start_worker=False),
                   base_url="https://lantern.example")
    r = c.get("/guide")
    assert r.status_code == 200 and "How to use Lantern" in r.text
    nonce = re.search(r"'nonce-([^']+)'", r.headers["content-security-policy"]).group(1)
    assert f'<script nonce="{nonce}">' in r.text
    assert r.headers["cache-control"] == "no-store"
    assert 'href="/">Open Lantern</a>' in r.text                 # the landing intro still plays on the way in
