"""The cloud website: one page that looks and behaves like the Lantern app, because it is built from the app.

The app's stylesheet, typefaces, brand mark, icons, readiness ring, appearance switch and backdrop are read from
`lantern/viewer/app.html` (the same file `lantern serve` sends) when the service starts, and placed into
`site/index.html`. Change the app and the website follows; a test fails if an anchor this module reads from the app
disappears, so the two can never drift apart quietly.

Every page is sent with a fresh nonce and the same Content-Security-Policy as the app (`lantern.server._csp`), so only
our own scripts run. Data shown on the page arrives from the JSON API and goes through `esc()` before it touches HTML.
"""

from __future__ import annotations

import re
import secrets
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).resolve().parent / "site"


def _viewer() -> Path:
    import lantern
    return Path(lantern.__file__).resolve().parent / "viewer"


# What the website takes from the app, and the text that marks where each piece starts and ends.
JS_BLOCKS = (
    ("const esc = ", "\n"),                                                         # the escaper, one line
    ("// Icons: fixed markup, never data.", "document.getElementById('theme').onclick"),  # icons, ring, appearance
    ("// ---------------------------------------------------------------- backdrop", "function setBackdrop"),
    ("// ---------------------------------------------------------------- Terminal drawer (design 5a/5b)",  # the drawer
     "// ---------------------------------------------------------------- Terminal drawer: the app's commands"),
)


def _between(text: str, start: str, end: str) -> str:
    i = text.index(start)
    j = text.index(end, i + len(start))
    return text[i:j]


def app_parts(app_html: str) -> dict:
    """The pieces of the app the website reuses. ValueError when the app no longer has one of them."""
    try:
        style = _between(app_html, "<style>", "</style>")[len("<style>"):]
        fonts = re.search(r'<link href="https://fonts\.googleapis\.com/[^"]+" rel="stylesheet">', app_html).group(0)
        brand = re.search(r'<span class="mark" aria-hidden="true">.*?</span><span>Lantern</span>', app_html).group(0)
        js = "\n".join(_between(app_html, a, b).rstrip() for a, b in JS_BLOCKS)
    except (ValueError, AttributeError) as e:
        raise ValueError(f"the app page changed shape; update lantern_cloud/site.py ({e})") from None
    if "</script" in js.lower() or "</style" in style.lower():
        raise ValueError("unexpected closing tag in a shared piece")
    return {"style": style, "fonts": fonts, "brand": brand, "js": js}


@lru_cache(maxsize=1)
def _template(version: str) -> str:
    parts = app_parts((_viewer() / "app.html").read_text(encoding="utf-8"))
    page = (HERE / "index.html").read_text(encoding="utf-8")
    for key in ("style", "fonts", "brand", "js"):
        page = page.replace(f"/*__APP_{key.upper()}__*/", parts[key]).replace(f"<!--__APP_{key.upper()}__-->", parts[key])
    return page.replace("__VERSION__", version)


def page(version: str, per_day: int | None = None, everyone: int | None = None) -> tuple[str, str]:
    """(html, nonce) for the website, with the nonce on every script tag. The help page says how many checks a day
    an account gets and how many everyone together: `per_day` and `everyone` are the limits the service runs with
    (`Settings.runs_per_day`, `global_runs_per_day`), so the page never names a number of its own (until 2026-11-13
    it said 50 where the service had been set to 300). A page built outside a service names the limits a service
    started here would have."""
    if per_day is None or everyone is None:
        from .settings import Settings
        s = Settings()
        per_day = s.runs_per_day if per_day is None else per_day
        everyone = s.global_runs_per_day if everyone is None else everyone
    nonce = secrets.token_urlsafe(16)
    html = _template(version).replace("__ALL_RUNS_PER_DAY__", f"{int(everyone):,}").replace("__RUNS_PER_DAY__", f"{int(per_day):,}")
    html = html.replace("<script>", f'<script nonce="{nonce}">')
    return html.replace('<script src="/', f'<script nonce="{nonce}" src="/'), nonce


# The intro's scripts, served from this origin so the page's nonce CSP covers them (no outside script host).
INTRO_FILES = ("react.production.min.js", "react-dom.production.min.js", "intro-runtime.js", "intro.js")


def asset(name: str) -> tuple[bytes, str] | None:
    """The PWA files: the icon is the app's own; the manifest and service worker are the website's."""
    if name == "icon.svg":
        return (_viewer() / "icon.svg").read_bytes(), "image/svg+xml"
    if name == "manifest.webmanifest":
        return (HERE / "manifest.webmanifest").read_bytes(), "application/manifest+json"
    if name == "sw.js":
        return (HERE / "sw.js").read_bytes(), "text/javascript"
    if name in INTRO_FILES:   # the landing page's intro (site/intro, copied here; a test keeps them equal) and React
        return (HERE / name).read_bytes(), "text/javascript"
    return None
