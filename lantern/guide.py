"""The "How to use Lantern" guide: one page with short animated demos, served at `/guide` by `lantern serve` and by
lantern-cloud.

The page (`viewer/guide.html`) borrows the app's stylesheet, typefaces, brand mark, icons and appearance switch from
`viewer/app.html` when it is built, so it looks like the app and follows the same light/dark choice. The demos are
drawn by one small player from fixed data in the page; nothing on it comes from a user or a project, and every caption
is placed with `textContent`, never as HTML. The page is sent with a fresh nonce and the app's Content-Security-Policy.
"""

from __future__ import annotations

import re
import secrets
from functools import lru_cache
from pathlib import Path

VIEWER = Path(__file__).resolve().parent / "viewer"

# The app's icons and appearance switch, between these two markers (the website takes the same block).
ICONS_START = "// Icons: fixed markup, never data."
ICONS_END = "document.getElementById('theme').onclick"


def _between(text: str, start: str, end: str) -> str:
    i = text.index(start)
    return text[i:text.index(end, i + len(start))]


def app_parts(app_html: str) -> dict:
    """The pieces of the app the guide reuses. ValueError when the app no longer has one of them."""
    try:
        style = _between(app_html, "<style>", "</style>")[len("<style>"):]
        fonts = re.search(r'<link href="https://fonts\.googleapis\.com/[^"]+" rel="stylesheet">', app_html).group(0)
        brand = re.search(r'<span class="mark" aria-hidden="true">.*?</span><span>Lantern</span>', app_html).group(0)
        esc = _between(app_html, "const esc = ", "\n")
        js = esc + "\n" + _between(app_html, ICONS_START, ICONS_END).rstrip()
    except (ValueError, AttributeError) as e:
        raise ValueError(f"the app page changed shape; update lantern/guide.py ({e})") from None
    if "</script" in js.lower() or "</style" in style.lower():
        raise ValueError("unexpected closing tag in a shared piece")
    return {"style": style, "fonts": fonts, "brand": brand, "js": js}


@lru_cache(maxsize=4)
def _template(version: str, open_href: str) -> str:
    parts = app_parts((VIEWER / "app.html").read_text(encoding="utf-8"))
    page = (VIEWER / "guide.html").read_text(encoding="utf-8")
    for key in ("style", "fonts", "brand", "js"):
        page = page.replace(f"/*__APP_{key.upper()}__*/", parts[key]).replace(f"<!--__APP_{key.upper()}__-->", parts[key])
    return page.replace("__OPEN_HREF__", open_href).replace("__VERSION__", version)


def page(version: str, open_href: str = "/") -> tuple[str, str]:
    """(html, nonce) for the guide, with the nonce on every script tag. `open_href` is where "Open Lantern" goes."""
    if not re.fullmatch(r"/[A-Za-z0-9/#?=._-]*", open_href) or open_href.startswith("//"):
        raise ValueError("open_href must be a path on this site")
    nonce = secrets.token_urlsafe(16)
    return _template(version, open_href).replace("<script>", f'<script nonce="{nonce}">'), nonce
