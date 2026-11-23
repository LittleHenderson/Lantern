"""Two small sites for the browser checks (docs/browser.md), written at test time: `pages`, a folder of plain pages,
and `app`, a FastAPI app. Each is written safe, or with one planted problem of `PLANTED` that changes only its own
pieces: an edit puts new text in place of text that stands exactly once in one file of the safe site, or adds a file.

Written before the checks were built (a firm pass or fail, stage 5, step 1): `PLANTED` says, for each problem, the one
check that must come out broken and the one code it must give; `SAFE` says what each site written safe gives.
`LOOKALIKES` (step 2, written before each fix it guards): versions that look like a problem to a careless check and
are not one, or where the run itself can only say "undecided", each with what it must give. None of it is copied from
a real project."""

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
    # 2026-11-22, the browser benchmark's first whole run: each of these three was missed or given another code there
    # an outline set to 0 changes its width and, like `outline: none`, draws nothing
    "no-focus-ring-zero": Planted("pages", "keyboard", "no-focus-ring", "the outline set to 0 on every control", (
        ("style.css", "a:focus-visible, button:focus-visible, input:focus-visible { outline: 3px solid #0F7B74; outline-offset: 2px; }",
         "a:focus, button:focus, input:focus { outline: 0; }"),)),
    # a field that swallows Tab before the page's buttons: the trap is the problem, and what Tab never got to past it
    # is not called out of reach
    "focus-trap-first": Planted("pages", "keyboard", "trapped", "a field that swallows Tab, before the page's buttons", (
        ("index.html", "<p>Fresh bread every morning.</p>",
         '<p>Fresh bread every morning.</p>\n<p><label for="code">Discount code</label> <input id="code" name="code"></p>'),
        _then('document.getElementById("code").addEventListener("keydown", function (event) {\n'
              '  if (event.key === "Tab") { event.preventDefault(); }\n});'))),
    # a script from another computer that the page's own policy lets in: the browser asks for it (the twin of the
    # look-alike `policy-keeps-out`)
    "outside-script-let-in": Planted("pages", "outside", "outside-script",
                                     "an analytics script from another computer that the page's own policy lets in", (
        ("index.html", "<title>Corner bakery</title>",
         '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\' '
         'https://stats.example.org">\n<title>Corner bakery</title>'),
        ("index.html", '<script src="app.js"></script>',
         '<script src="https://stats.example.org/count.js" async></script>\n<script src="app.js"></script>')),
        asks="stats.example.org"),
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


@dataclass(frozen=True)
class Lookalike:
    site: str                   # "pages" or "app"
    what: str                   # what it is, in plain words
    edits: tuple                # as `Planted.edits`
    gives: tuple = ()           # (check, outcome, codes) where it differs from the safe site; every other check as SAFE
    asks: str = ""              # for `outside`: the address the page asks another computer for
    says: tuple = ()            # (check, words) the check's reason must hold; a held check not named here gives none


MAP = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Where to find us</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<p><a href="index.html">The shop</a> <a href="contact.html">Write to us</a></p>
</body>
</html>
"""

JOIN = ('<p><button type="button" id="join">Join the newsletter</button></p>\n'
        '<p id="join-text" hidden>Thank you: the newsletter comes on Fridays.</p>')
JOIN_JS = """"use strict";
// The newsletter: once this browser has joined, the button has nothing more to do
function joined() {
  return localStorage.getItem("joined") === "1" || sessionStorage.getItem("joined") === "1"
    || document.cookie.split("; ").indexOf("joined=1") >= 0 || window.name === "joined";
}
document.getElementById("join").addEventListener("click", function () {
  if (joined()) { return; }
  localStorage.setItem("joined", "1");
  sessionStorage.setItem("joined", "1");
  document.cookie = "joined=1; path=/; SameSite=Lax";
  window.name = "joined";
  document.getElementById("join-text").hidden = false;
});
"""

ACCOUNT = '    return page("Your account", "<p>Signed in as " + html.escape(user) + ".</p>")\n'
ORDERS_APP = '''

ORDERS = {1: "Two rye loaves", 2: "A seed cake"}
COLLECTED: set[int] = set()
ORDERS_JS = """'use strict';
document.getElementById("orders").addEventListener("click", function (event) {
  var button = event.target.closest("button[data-order]");
  if (!button) { return; }
  fetch("/orders/" + button.dataset.order + "/collected", { method: "POST" }).then(function () {
    button.closest("li").remove();
  });
});
"""


@app.get("/orders")
def orders():
    rows = "".join("<li>" + html.escape(name) + ' <button type="button" data-order="' + str(number) + '">Collected</button>'
                   "</li>" for number, name in ORDERS.items() if number not in COLLECTED)
    return page("Orders", '<ul id="orders">' + rows + '</ul><form method="post" action="/orders"><p><label for="order">'
                'A new order</label> <input id="order" name="order" required></p><p><button type="submit">Add</button>'
                '</p></form><script src="/static/orders.js"></script>')


@app.post("/orders")
async def add_order(request: Request):
    sent = await fields(request)
    ORDERS[max(ORDERS) + 1] = sent.get("order", "")
    return orders()


@app.post("/orders/{number}/collected")
def collected(number: int):
    COLLECTED.add(number)
    return {"collected": number}


@app.get("/static/{name}")
def static(name: str):
    if name != "orders.js":
        raise HTTPException(status_code=404)
    return Response(ORDERS_JS, media_type="text/javascript")
'''

VISITS_APP = '''

VISITS = [0]
VISITS_JS = """'use strict';
document.getElementById("seen").addEventListener("click", function () {
  document.getElementById("seen-text").hidden = false;
});
"""


@app.get("/visits")
def visits():
    VISITS[0] += 1
    times = "1 time" if VISITS[0] == 1 else str(VISITS[0]) + " times"
    return page("Visits", '<p><button type="button" id="seen">Seen ' + times + '</button></p>'
                '<p id="seen-text" hidden>Thank you for coming back.</p><script src="/static/visits.js"></script>')


@app.get("/static/{name}")
def static(name: str):
    if name != "visits.js":
        raise HTTPException(status_code=404)
    return Response(VISITS_JS, media_type="text/javascript")
'''

NOTES_APP = '''

NOTE_VISITS = [0]


@app.get("/notes")
def notes():
    NOTE_VISITS[0] += 1
    return page("Notes", '<form method="post" action="/notes?visit=' + str(NOTE_VISITS[0]) + '"><p><label for="note">'
                'A note</label> <input id="note" name="note"></p><p><button type="submit">Keep it</button></p></form>')


@app.post("/notes")
async def keep_note(request: Request):
    await fields(request)
    return page("Notes", "<p>Kept.</p>")
'''

FORM_ORDERS_APP = '''

ORDERS = {1: "Two rye loaves", 2: "A seed cake"}
COLLECTED: set[int] = set()


@app.get("/orders")
def orders():
    rows = "".join("<li>" + html.escape(name) + ' <form method="post" action="/orders/collected">'
                   '<input type="hidden" name="order" value="' + str(number) + '"><button type="submit">Collected'
                   "</button></form></li>" for number, name in ORDERS.items() if number not in COLLECTED)
    return page("Orders", "<ul>" + rows + '</ul><form method="post" action="/orders"><p><label for="order">'
                'A new order</label> <input id="order" name="order" required></p><p><button type="submit">Add</button>'
                "</p></form>")


@app.post("/orders/collected")
async def collected(request: Request):
    sent = await fields(request)
    number = int(sent.get("order", "0"))
    if number not in ORDERS or number in COLLECTED:
        raise HTTPException(status_code=404)
    COLLECTED.add(number)
    return orders()


@app.post("/orders")
async def add_order(request: Request):
    sent = await fields(request)
    ORDERS[max(ORDERS) + 1] = sent.get("order", "")
    return orders()
'''

TOKEN_APP = '''

TOKENS: set[str] = set()


@app.get("/feedback")
def feedback_form():
    token = secrets.token_urlsafe(8)
    TOKENS.add(token)
    return page("Feedback", '<form method="post" action="/feedback"><input type="hidden" name="token" value="' + token
                + '"><p><label for="said">What you think</label> <input id="said" name="said"></p><p><button '
                'type="submit">Send</button></p></form>')


@app.post("/feedback")
async def feedback(request: Request):
    sent = await fields(request)
    if sent.get("token") not in TOKENS:
        raise HTTPException(status_code=400, detail="Open the form again")
    return page("Feedback", "<p>Thank you.</p>")
'''

LOOKALIKES: dict[str, Lookalike] = {
    # Tab moves on inside each of these while the page's own place for the keyboard stays the same: no trap
    "frame": Lookalike("pages", "a page of the site shown in a frame of another, with two links", (
        ("about.html", "<p>Baking since 1987.</p>",
         '<p>Baking since 1987.</p>\n<p><iframe src="map.html" title="Where to find us" width="320" height="80">'
         "</iframe></p>"),
        ("map.html", None, MAP))),
    "date-field": Lookalike("pages", "a date field, which Tab goes through part by part", (
        ("contact.html", '<input id="email" name="email" type="email" required></p>',
         '<input id="email" name="email" type="email" required></p>\n'
         '<p><label for="day">A good day to call</label> <input id="day" name="day" type="date"></p>'),)),
    "component": Lookalike("pages", "a part of the page with a tree of its own (a shadow root) holding two buttons", (
        ("index.html", '<p id="hours-text" hidden>', '<p><shop-size></shop-size></p>\n<p id="hours-text" hidden>'),
        _then('customElements.define("shop-size", class extends HTMLElement {\n'
              '  connectedCallback() {\n'
              '    var root = this.attachShadow({ mode: "open" });\n'
              '    ["Smaller", "Larger"].forEach(function (name) {\n'
              '      var b = document.createElement("button");\n'
              '      b.type = "button";\n'
              '      b.textContent = name;\n'
              '      root.appendChild(b);\n'
              '    });\n'
              '  }\n'
              '});'))),
    # a page that listens for keys, on its page with one link: Tab can still leave the link
    "keys-on-page": Lookalike("pages", "a page that listens for keys and has one link", (
        ("thanks.html", "</main>\n</body>",
         '</main>\n<script>\ndocument.addEventListener("keydown", function (event) {\n'
         '  if (event.key === "Escape") { location.href = "index.html"; }\n});\n</script>\n</body>'),)),
    # what answers a click but cannot be seen is not asked to be reached with Tab
    "hidden-handler": Lookalike("pages", "a hidden element that answers a click", (
        ("index.html", '<p id="hours-text" hidden>', '<div id="welcome" hidden>Welcome back</div>\n<p id="hours-text" hidden>'),
        _then('document.getElementById("welcome").addEventListener("click", function () {\n'
              '  document.getElementById("welcome").hidden = true;\n});'))),
    # the page's script needs a library from another computer, which the run refuses: what the page's script would
    # have done there is undecided, and the request itself is the `outside` check's
    "outside-library": Lookalike("pages", "the page's script needs a library from another computer", (
        ("index.html", '<script src="app.js"></script>',
         '<script src="https://cdn.example.com/shelf.js"></script>\n<script src="app.js"></script>'),
        ("app.js", '"use strict";\n', '"use strict";\nShelf.start();\n')),
        gives=(("script", "inconclusive", ()), ("leads", "inconclusive", ()), ("forms", "inconclusive", ()),
               ("outside", "broken", ("outside-script",))),
        asks="cdn.example.com"),
    # a cover that fades away as the page opens, as a start screen does: the page is looked at and its controls are
    # clicked once the cover has gone, and what answers a click on the cover is hidden by then
    "fading-cover": Lookalike("pages", "a cover over the page that fades away as the page opens", (
        ("index.html", "<body>\n<nav>", '<body>\n<div id="cover"><div id="cover-skip">Skip</div></div>\n<nav>'),
        ("style.css", "outline-offset: 2px; }\n",
         "outline-offset: 2px; }\n#cover { position: fixed; inset: 0; background: #2b2118; color: #fff;"
         " transition: opacity 1.5s, visibility 1.5s; }\n#cover.gone { opacity: 0; visibility: hidden; }\n"),
        _then('document.getElementById("cover-skip").addEventListener("click", function () {});\n'
              'window.addEventListener("load", function () {\n'
              '  setTimeout(function () {\n'
              '    var cover = document.getElementById("cover");\n'
              '    getComputedStyle(cover).opacity;\n'
              '    cover.className = "gone";\n'
              '  }, 50);\n'
              '});'))),
    # a button on two pages that does what it says once and keeps in the browser that it was done (in its storage,
    # its session's storage, a cookie and the window's name): each page and each click is a first visit, so the
    # button works on both pages (2026-11-22, the browser benchmark's first run: until then a click and the page
    # after it started from what the steps before them had left in the browser)
    "kept-in-browser": Lookalike("pages", "a newsletter button on two pages that has nothing more to do once used", (
        ("index.html", '<ul id="results"></ul>', '<ul id="results"></ul>\n' + JOIN),
        ("index.html", '<script src="app.js"></script>', '<script src="app.js"></script>\n<script src="join.js"></script>'),
        ("about.html", '<p><a href="index.html">Back to the shop</a></p>',
         '<p><a href="index.html">Back to the shop</a></p>\n' + JOIN),
        ("about.html", "</main>\n</body>", '</main>\n<script src="join.js"></script>\n</body>'),
        ("join.js", None, JOIN_JS))),
    # two orders that a click marks collected on the app's server, beside a form whose field must be filled: the
    # click after the first finds its own button again, which now stands where the form's button stood (what a site
    # keeps on its own server is not emptied between the steps)
    "kept-on-server": Lookalike("app", "two orders that a click marks collected on the app's server", (
        ("app.py", "from fastapi.responses import HTMLResponse\n", "from fastapi.responses import HTMLResponse, Response\n"),
        ("app.py", ACCOUNT, ACCOUNT + ORDERS_APP)),
        gives=(("script", "held", ()),)),
    # a button whose words change each time its page is opened (the count of visits, kept on the app's server): on
    # the page opened anew for the click no control has the words first seen, so Lantern cannot tell which control it
    # was, clicks none, and the check's reason says how many were not clicked (2026-11-22)
    "words-change": Lookalike("app", "a button whose words count the visits to its page", (
        ("app.py", "from fastapi.responses import HTMLResponse\n", "from fastapi.responses import HTMLResponse, Response\n"),
        ("app.py", ACCOUNT, ACCOUNT + VISITS_APP)),
        gives=(("script", "held", ()),), says=(("leads", "1 control not clicked"),)),
    # the same for a form: a form whose address carries the count of visits to its page is not found again on the
    # page opened anew, so it is not sent, and the forms check's reason says so (2026-11-22)
    "form-address-changes": Lookalike("app", "a form whose address counts the visits to its page", (
        ("app.py", ACCOUNT, ACCOUNT + NOTES_APP),), says=(("forms", "1 form not sent"),)),
    # two orders, each with a form of its own that marks it collected on the app's server, sent to one address with
    # the order's number in a hidden field, beside a form for a new order: each form is found again by its address,
    # its method and the names of its fields, wherever what the server keeps has moved it (2026-11-22: until then the
    # form at the same place among the page's forms was sent, whatever it was)
    "forms-kept-on-server": Lookalike("app", "two orders, each with its own form that marks it collected on the server", (
        ("app.py", ACCOUNT, ACCOUNT + FORM_ORDERS_APP),)),
    # a form with a hidden token the app makes anew at each visit, as most sites do against forged requests: it is the
    # same form at every visit, so it is found again and sent (2026-11-22)
    "form-token": Lookalike("app", "a form with a hidden token the app makes anew at each visit", (
        ("app.py", ACCOUNT, ACCOUNT + TOKEN_APP),)),
    # 2026-11-22, the browser benchmark's first whole run. A script from another computer that the page's own policy
    # keeps out (here written in the page): the browser stops it before it is sent, so nothing is asked of that
    # computer, and the outside check's reason says how many such requests it did not count
    "policy-keeps-out": Lookalike("pages", "a chat widget from another computer that the page's own policy keeps out", (
        ("index.html", "<title>Corner bakery</title>",
         '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">\n<title>Corner bakery</title>'),
        ("index.html", '<script src="app.js"></script>',
         '<script src="https://chat.example.net/widget.js" async></script>\n<script src="app.js"></script>')),
        says=(("outside", "1 request for another computer not counted"),)),
    # the same with the policy the app sends with every answer; the page now names a script, so the script check
    # has one to look at
    "policy-keeps-out-app": Lookalike("app", "a chat widget from another computer that the app's own policy keeps out", (
        ("app.py", '"</main></body></html>"',
         "\"</main><script src='https://chat.example.net/widget.js' async></script></body></html>\""),),
        gives=(("script", "held", ()),), says=(("outside", "for another computer not counted"),)),
    # a button the page has switched off, with a handler for when it is switched on: nobody can use it, so it is not
    # clicked, and it is not asked to be reached with Tab
    "switched-off": Lookalike("pages", "a button that is switched off, with a handler for when it is switched on", (
        ("index.html", '<p id="hours-text" hidden>',
         '<p><button type="button" id="preorder" disabled>Pre-order (opens on Monday)</button></p>\n'
         '<p id="hours-text" hidden>'),
        _then('document.getElementById("preorder").addEventListener("click", function () {\n'
              '  document.getElementById("preorder").textContent = "Asked for";\n});'))),
    # a button that prints the page: what the click does is the browser's own print dialog
    "print-button": Lookalike("pages", "a button that prints the page", (
        ("about.html", '<p><a href="index.html">Back to the shop</a></p>',
         '<p><button type="button" id="print">Print this page</button></p>\n'
         '<p><a href="index.html">Back to the shop</a></p>'),
        ("about.html", "</main>\n</body>",
         '</main>\n<script>\ndocument.getElementById("print").addEventListener("click", function () {\n'
         '  window.print();\n});\n</script>\n</body>'))),
    # a page with more controls than the keyboard walk presses Tab for, then a button: what the walk did not get to is
    # not called out of reach
    "long-page": Lookalike("pages", "a page with more links than the keyboard walk presses Tab for, then a button", (
        ("about.html", "<p>Baking since 1987.</p>",
         "<p>Baking since 1987.</p>\n<ul>\n" + "".join(f'<li><a href="index.html">Loaf {n}</a></li>\n'
                                                     for n in range(1, 91)) + "</ul>\n"
         '<p><button type="button" id="more">Show more years</button></p>\n<p id="years" hidden>1987 to now.</p>'),
        ("about.html", "</main>\n</body>",
         '</main>\n<script>\ndocument.getElementById("more").addEventListener("click", function () {\n'
         '  document.getElementById("years").hidden = false;\n});\n</script>\n</body>'))),
}


def files(site: str, planted: str | None = None) -> dict[str, str]:
    """The site's files, name to text: written safe, or with the one planted problem or look-alike named."""
    out = dict(SITES[site])
    if planted is None:
        return out
    p = PLANTED.get(planted) or LOOKALIKES[planted]
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
    """Write the site into `folder` (made here), safe or with the one planted problem or look-alike named, and give
    the folder."""
    folder = Path(folder)
    folder.mkdir(parents=True)
    for name, text in files(site, planted).items():
        (folder / name).write_text(text, encoding="utf-8", newline="\n")
    return folder
