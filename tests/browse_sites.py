"""Two small sites for the browser checks (docs/browser.md), written at test time: `pages`, a folder of plain pages,
and `app`, a FastAPI app. Each is written safe, or with one planted problem of `PLANTED` that changes only its own
pieces: an edit puts new text in place of text that stands exactly once in one file of the safe site, or adds a file.

Written before the checks were built (a firm pass or fail, stage 5, step 1): `PLANTED` says, for each problem, the one
check that must come out broken and the one code it must give; `SAFE` says what each site written safe gives. None of
it is copied from a real project."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

PAGES = {
    "index.html": """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Corner bakery</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<nav><a href="index.html">Home</a> <a href="about.html">About</a> <a href="contact.html">Contact</a></nav>
<main>
<h1>Corner bakery</h1>
<p>Fresh bread every morning.</p>
<p><button type="button" id="hours">Opening hours</button></p>
<p id="hours-text" hidden>Monday to Saturday, 7 to 19.</p>
<form id="search" action="index.html">
<label for="q">Search the shelves</label> <input id="q" name="q" type="search">
<button type="submit">Find</button>
</form>
<ul id="results"></ul>
<p><img src="bread.svg" alt="A loaf of bread" width="64" height="64"></p>
</main>
<script src="app.js"></script>
</body>
</html>
""",
    "app.js": """"use strict";
document.getElementById("hours").addEventListener("click", function () {
  document.getElementById("hours-text").hidden = false;
});
document.getElementById("search").addEventListener("submit", function (event) {
  event.preventDefault();
  var list = document.getElementById("results");
  var item = document.createElement("li");
  item.textContent = "On the shelf: " + document.getElementById("q").value;
  list.replaceChildren(item);
});
// the end of the page's script
""",
    "style.css": """body { font-family: sans-serif; margin: 2rem; line-height: 1.5; }
body.compact { line-height: 1.2; }
.menu { cursor: pointer; }
a:focus-visible, button:focus-visible, input:focus-visible { outline: 3px solid #0F7B74; outline-offset: 2px; }
""",
    "bread.svg": """<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
<ellipse cx="32" cy="36" rx="26" ry="16" fill="#c8913a"/>
</svg>
""",
    "about.html": """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>About the bakery</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<main>
<h1>About the bakery</h1>
<p>Baking since 1987.</p>
<p><a href="index.html">Back to the shop</a></p>
</main>
</body>
</html>
""",
    "contact.html": """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Write to the bakery</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<main>
<h1>Write to us</h1>
<form action="thanks.html" method="get">
<p><label for="name">Your name</label> <input id="name" name="name" required></p>
<p><label for="email">Your e-mail address</label> <input id="email" name="email" type="email" required></p>
<p><button type="submit">Send</button></p>
</form>
<p><a href="index.html">Back to the shop</a></p>
</main>
</body>
</html>
""",
    "thanks.html": """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Thank you</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<main>
<h1>Thank you</h1>
<p>We will write back soon.</p>
<p><a href="index.html">Back to the shop</a></p>
</main>
</body>
</html>
""",
}

APP = {
    "app.py": '''"""A small bakery app for Lantern's browser checks (written by tests/browse_sites.py)."""
import asyncio
import html
import secrets
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

app = FastAPI()
SESSIONS: dict[str, str] = {}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>' + title + "</title></head><body>"
        '<nav><a href="/">Home</a> <a href="/stats">Numbers</a> <a href="/report">Report</a> '
        '<a href="/today">Today</a> <a href="/contact">Contact</a> <a href="/account">Your account</a></nav>'
        "<main><h1>" + title + "</h1>" + body + "</main></body></html>", status_code=status)


def require_login(request: Request) -> str:
    user = SESSIONS.get(request.cookies.get("session", ""))
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in first")
    return user


async def fields(request: Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs((await request.body()).decode("utf-8")).items()}


@app.get("/")
def home():
    return page("Bakery", "<p>Fresh bread every morning.</p>")


@app.get("/stats")
def stats():
    sold, days = 120, 4
    return page("Numbers", f"<p>{sold // days} loaves a day.</p>")


@app.get("/report")
def report():
    return page("Report", "<p>All ovens work.</p>")


@app.get("/today")
async def today():
    await asyncio.sleep(0)
    return page("Today", "<p>Rye and spelt.</p>")


@app.get("/contact")
def contact_form():
    return page("Contact", '<form method="post" action="/contact"><p><label for="name">Your name</label> '
                '<input id="name" name="name"></p><p><label for="msg">Message</label> '
                '<textarea id="msg" name="msg"></textarea></p><p><button type="submit">Send</button></p></form>')


@app.post("/contact")
async def contact(request: Request):
    sent = await fields(request)
    return page("Thanks", "<p>Thank you, " + html.escape(sent.get("name", "")) + ".</p>")


@app.get("/login")
def login_page():
    response = page("Sign in", '<form method="post" action="/login"><p><label for="user">Name</label> '
                    '<input id="user" name="user"></p><p><label for="pw">Password</label> '
                    '<input id="pw" name="pw" type="password"></p><p><button type="submit">Sign in</button></p></form>')
    response.set_cookie("session", secrets.token_urlsafe(16), httponly=True, samesite="lax")
    return response


@app.post("/login")
async def login(request: Request):
    await fields(request)
    return page("Sign in", "<p>That name and password do not match.</p>", status=401)


@app.get("/account")
def account(user: str = Depends(require_login)):
    return page("Your account", "<p>Signed in as " + html.escape(user) + ".</p>")
''',
}

SITES = {"pages": PAGES, "app": APP}
END = "// the end of the page's script\n"


def _then(line: str) -> tuple[str, str, str]:
    """An edit that adds a line at the end of the page's script."""
    return ("app.js", END, line + "\n" + END)


@dataclass(frozen=True)
class Planted:
    site: str                   # "pages" or "app"
    check: str                  # the one check that must come out broken
    code: str                   # the one code it must give
    what: str                   # the problem, in plain words
    edits: tuple                # (file, text of the safe file it replaces or None for a new file, new text)
    asks: str = ""              # for `outside`: the address the page asks another computer for


PLANTED: dict[str, Planted] = {
    # pages: a folder of plain pages, served from the folder
    "blank-page": Planted("pages", "opens", "empty", "a page with an empty body", (
        ("blank.html", None, '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>Blank</title>\n'
                             "</head>\n<body>\n</body>\n</html>\n"),)),
    "script-raises": Planted("pages", "script", "raised", "the page's script raises an error at its end", (
        _then("document.title.notThere();"),)),
    "console-error": Planted("pages", "script", "console-error", "the page's script writes an error", (
        _then('console.error("The saved basket could not be read.");'),)),
    "module-missing": Planted("pages", "script", "not-loaded", "the page names a script that is not there", (
        ("index.html", '<script src="app.js"></script>', '<script src="app.js"></script>\n<script src="widgets.js"></script>'),)),
    "dead-link": Planted("pages", "leads", "dead-link", "a link to a page that is not there", (
        ("about.html", '<p><a href="index.html">Back to the shop</a></p>',
         '<p><a href="index.html">Back to the shop</a></p>\n<p><a href="old-prices.html">Old prices</a></p>'),)),
    "empty-link": Planted("pages", "leads", "empty-link", "a link that leads nowhere", (
        ("index.html", "<p>Fresh bread every morning.</p>", '<p>Fresh bread every morning. <a href="#">More news</a></p>'),)),
    "dead-button": Planted("pages", "leads", "dead-button", "a button whose handler is never put on", (
        ("app.js", 'document.getElementById("hours").addEventListener("click", function () {\n'
                   '  document.getElementById("hours-text").hidden = false;\n});\n', ""),)),
    "button-raises": Planted("pages", "leads", "button-raises", "a button's handler looks for a misspelt id", (
        ("app.js", 'document.getElementById("hours-text").hidden = false;', 'document.getElementById("hours-txt").hidden = false;'),)),
    "form-raises": Planted("pages", "forms", "form-raises", "the search form's handler raises when it is sent", (
        ("app.js", "list.replaceChildren(item);", "list.replaceChild(item);"),)),
    "outside-script": Planted("pages", "outside", "outside-script", "an analytics script from another computer", (
        ("index.html", '<link rel="stylesheet" href="style.css">',
         '<link rel="stylesheet" href="style.css">\n<script src="https://cdn.example.com/analytics.js" async></script>'),),
        asks="cdn.example.com"),
    "outside-pixel": Planted("pages", "outside", "outside-file", "a tracking picture from another computer", (
        ("index.html", '<ul id="results"></ul>',
         '<ul id="results"></ul>\n<img src="https://pixel.example.net/p.gif" alt="" width="1" height="1">'),),
        asks="pixel.example.net"),
    "outside-fetch": Planted("pages", "outside", "outside-file", "the page's script sends to another service", (
        _then('fetch("https://api.example.org/collect", { method: "POST", body: "{}" }).catch(function () {});'),),
        asks="api.example.org"),
    "div-button": Planted("pages", "keyboard", "not-reached", "a menu made of a div that answers a click", (
        ("index.html", "<main>\n<h1>Corner bakery</h1>",
         '<main>\n<div class="menu" id="menu">Menu</div>\n<ul id="menu-list" hidden><li>Bread</li><li>Cakes</li></ul>\n'
         "<h1>Corner bakery</h1>"),
        _then('document.getElementById("menu").addEventListener("click", function () {\n'
              '  var list = document.getElementById("menu-list");\n  list.hidden = !list.hidden;\n});'))),
    "no-label": Planted("pages", "keyboard", "no-label", "a phone field with no label", (
        ("contact.html", '<input id="email" name="email" type="email" required></p>',
         '<input id="email" name="email" type="email" required></p>\n<p><input name="phone" type="tel"></p>'),)),
    "no-name": Planted("pages", "keyboard", "no-name", "an icon button holding only a drawing", (
        ("index.html", '<p id="hours-text" hidden>',
         '<p><button type="button" id="compact"><svg aria-hidden="true" width="12" height="12" viewBox="0 0 12 12">'
         '<path d="M1 6h10" stroke="black"></path></svg></button></p>\n<p id="hours-text" hidden>'),
        _then('document.getElementById("compact").addEventListener("click", function () {\n'
              '  document.body.classList.toggle("compact");\n});'))),
    "focus-trap": Planted("pages", "keyboard", "trapped", "a field that swallows Tab", (
        ("index.html", '<ul id="results"></ul>',
         '<ul id="results"></ul>\n<p><label for="code">Discount code</label> <input id="code" name="code"></p>'),
        _then('document.getElementById("code").addEventListener("keydown", function (event) {\n'
              '  if (event.key === "Tab") { event.preventDefault(); }\n});'))),
    "no-focus-ring": Planted("pages", "keyboard", "no-focus-ring", "no outline on any control", (
        ("style.css", "a:focus-visible, button:focus-visible, input:focus-visible { outline: 3px solid #0F7B74; outline-offset: 2px; }",
         "a:focus, button:focus, input:focus { outline: none; }"),)),
    # app: a FastAPI app, started in the sealed box
    "route-raises": Planted("app", "opens", "server-error", "a route that divides by zero", (
        ("app.py", "sold, days = 120, 4", "sold, days = 120, 0"),)),
    "named-404": Planted("app", "opens", "not-found", "a route that always answers 404", (
        ("app.py", 'return page("Report", "<p>All ovens work.</p>")', "raise HTTPException(status_code=404)"),)),
    "hangs": Planted("app", "opens", "no-answer", "a route that never answers", (
        ("app.py", "await asyncio.sleep(0)", "await asyncio.sleep(3600)"),)),
    "form-error": Planted("app", "forms", "form-error", "the contact handler reads a misspelt field", (
        ("app.py", 'html.escape(sent.get("name", ""))', 'html.escape(sent["nmae"])'),)),
    "form-nowhere": Planted("app", "forms", "form-nowhere", "the contact form is sent where no route answers", (
        ("app.py", '<form method="post" action="/contact">', '<form method="post" action="/send">'),)),
    "visitor-let-in": Planted("app", "visitor", "let-in", "the login check falls back to a default person", (
        ("app.py", 'SESSIONS.get(request.cookies.get("session", ""))', 'SESSIONS.get(request.cookies.get("session", ""), "guest")'),)),
    "headers-said-not-sent": Planted("app", "protections", "said-not-sent", "the policy is set only under /api", (
        ("app.py", '    response.headers["Content-Security-Policy"] = "default-src \'self\'"\n'
                   '    response.headers["X-Frame-Options"] = "DENY"\n',
         '    if request.url.path.startswith("/api"):\n'
         '        response.headers["Content-Security-Policy"] = "default-src \'self\'"\n'
         '        response.headers["X-Frame-Options"] = "DENY"\n'),)),
    "cookie-open": Planted("app", "protections", "cookie-open", "the session cookie is set without httponly", (
        ("app.py", ', httponly=True, samesite="lax")', ")"),)),
}

# What each site written safe gives, check by check: `pages` has no sign-in, and what a host would send with plain
# pages is not in the folder; `app` has no script.
SAFE = {
    "pages": {"opens": "held", "script": "held", "leads": "held", "forms": "held", "visitor": "nothing-to-check",
              "protections": "not-run", "outside": "held", "keyboard": "held"},
    "app": {"opens": "held", "script": "nothing-to-check", "leads": "held", "forms": "held", "visitor": "held",
            "protections": "held", "outside": "held", "keyboard": "held"},
}


def files(site: str, planted: str | None = None) -> dict[str, str]:
    """The site's files, name to text: written safe, or with the one planted problem named."""
    out = dict(SITES[site])
    if planted is None:
        return out
    p = PLANTED[planted]
    if p.site != site:
        raise ValueError(f"{planted} is planted in {p.site}, not in {site}")
    for name, old, new in p.edits:
        if old is None:
            if name in out:
                raise ValueError(f"{planted}: {name} is already there")
            out[name] = new
            continue
        if out[name].count(old) != 1:
            raise ValueError(f"{planted}: the text to replace stands {out[name].count(old)} times in {name}")
        out[name] = out[name].replace(old, new)
    return out


def write(folder, site: str, planted: str | None = None) -> Path:
    """Write the site into `folder` (made here) and give the folder."""
    folder = Path(folder)
    folder.mkdir(parents=True)
    for name, text in files(site, planted).items():
        (folder / name).write_text(text, encoding="utf-8", newline="\n")
    return folder
