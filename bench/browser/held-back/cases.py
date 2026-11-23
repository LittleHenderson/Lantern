"""The browser benchmark's held-back part: two sites that are run once, at the end of the stage, on the code as it is
then, and never while the checks are being built or fixed (bench/browser/README.md). Written down on 2026-11-22,
before the first run of any part of the benchmark.

* bikes: a bike shop's plain pages, built into `public/` (the folder a hosting service serves): a map drawn on a
  canvas, routes in a folder of their own, a price list read from data in the page, a booking form.
* clinic: a clinic's FastAPI app whose pages are shells that their own scripts fill in from the app's API, with forms
  sent as JSON, a sign-in, and a session cookie for every visitor.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from define import Family, Version  # noqa: E402  (bench/browser/define.py)

PAGES_SAFE = {"opens": "held", "script": "held", "leads": "held", "forms": "held", "visitor": "nothing-to-check",
              "protections": "not-run", "outside": "held", "keyboard": "held"}

FAMILIES = {
    "bikes": Family("bikes", "pages", "a bike shop's plain pages, built into public/", dict(PAGES_SAFE)),
    "clinic": Family("clinic", "app", "a clinic's FastAPI app whose pages fill themselves from its own API",
                     {c: "held" for c in PAGES_SAFE}),
}

INDEX = "public/index.html"
PRICES = "public/prices.html"
BOOK = "public/book.html"
RIVER = "public/routes/river-loop.html"
HILL = "public/routes/hill-climb.html"
SITE_JS = "public/js/site.js"
SITE_CSS = "public/css/site.css"
RING = "outline: 3px solid var(--ring); outline-offset: 2px;"

PAGES = "clinic/pages.py"
API = "clinic/api.py"
MAIN = "clinic/main.py"
SETTINGS = "clinic/settings.py"
CSS = "clinic/static/site.css"
HOME_JS = "clinic/static/js/home.js"
BOOK_JS = "clinic/static/js/book.js"
HEADERS = ('        response.headers["X-Frame-Options"] = "DENY"\n'
           '        response.headers["X-Content-Type-Options"] = "nosniff"\n'
           '        response.headers["Referrer-Policy"] = "same-origin"\n'
           '        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"\n')

GPX = """<?xml version="1.0" encoding="UTF-8"?>
<gpx version="1.1" creator="Ridgeline Bikes" xmlns="http://www.topografix.com/GPX/1/1">
<trk><name>The river loop</name><trkseg>
<trkpt lat="47.6101" lon="-122.2015"></trkpt>
<trkpt lat="47.6154" lon="-122.1932"></trkpt>
<trkpt lat="47.6120" lon="-122.1841"></trkpt>
<trkpt lat="47.6101" lon="-122.2015"></trkpt>
</trkseg></trk>
</gpx>
"""


def V(family, kind, what, edits=(), gives=None, seen=(), planted=(), beyond=""):
    return Version(family, kind, what, tuple(edits), dict(gives or {}), tuple(seen), tuple(planted), beyond)


VERSIONS = {
    # ---- bikes: plain pages in public/
    "bikes": V("bikes", "safe", "the bike shop's pages as they are"),
    "b-blank-map": V("bikes", "planted", "the map's script was renamed and the map page still names the old file, so "
                     "its canvas stays blank", (
        ("rename", "public/js/map.js", "public/js/trail-map.js"),),
        {"opens": ("broken", ("empty",)), "script": ("broken", ("not-loaded",))},
        (("empty", "/map.html"), ("not-loaded", "/map.html")), (("script", "not-loaded"),),
        beyond="a canvas on which nothing was drawn shows nothing, so the page is `empty`: docs/browser.md counts a "
               "drawing that can be seen"),
    "b-raised": V("bikes", "planted", "the price list's data in the page has a comma too many, and the script that "
                  "reads it stops there", (
        ("replace", PRICES, '"tax": 0.2}</script>', '"tax": 0.2,}</script>'),),
        # the tax button's handler is put on after the list is read, so it is never put on
        {"script": ("broken", ("raised",)), "leads": ("broken", ("dead-button",))},
        (("raised", "/prices.html"), ("dead-button", "/prices.html")), (("script", "raised"),)),
    "b-console-error": V("bikes", "planted", "the group rides' data file was renamed; the start page's script says so "
                         "with console.error", (
        ("rename", "public/data/rides.json", "public/data/rides-2026.json"),),
        {"script": ("broken", ("console-error",))}, (("console-error", "/index.html"),), (("script", "console-error"),)),
    "b-not-loaded": V("bikes", "planted", "the hill climb's page names the shared script as if it stood in the "
                      "top folder", (
        ("replace", HILL, '<script src="../js/site.js"></script>', '<script src="js/site.js"></script>'),),
        # without the script the photo button has no handler and the climb button calls a function that is not there
        {"script": ("broken", ("not-loaded",)), "leads": ("broken", ("button-raises", "dead-button"))},
        (("not-loaded", "/routes/hill-climb.html"), ("dead-button", "/routes/hill-climb.html"),
         ("button-raises", "/routes/hill-climb.html")), (("script", "not-loaded"),)),
    "b-dead-link": V("bikes", "planted", "the start page links to the river loop under a name it never had", (
        ("replace", INDEX, '<a href="routes/river-loop.html">River loop</a>',
         '<a href="routes/river_loop.html">River loop</a>'),),
        {"leads": ("broken", ("dead-link",))}, (("dead-link", "/index.html"),), (("leads", "dead-link"),)),
    "b-empty-link": V("bikes", "planted", "a link to the groups' part of the price list names a place the page does "
                      "not have", (
        ("replace", PRICES, '<section id="groups">',
         '<p><a href="#group-prices">Prices for groups</a></p>\n<section id="groups">'),),
        {"leads": ("broken", ("empty-link",))}, (("empty-link", "/prices.html"),), (("leads", "empty-link"),)),
    "b-void-link": V("bikes", "planted", "the link to the rental terms was meant to open them by script, which was "
                     "never written", (
        ("replace", BOOK, '<p><a href="terms.html">Read the rental terms</a></p>',
         '<p><a href="javascript:void(0)">Read the rental terms</a></p>'),),
        {"leads": ("broken", ("empty-link",))}, (("empty-link", "/book.html"),), (("leads", "empty-link"),),
        beyond="`javascript:void(0)` is one of the links like `href=\"#\"` that docs/browser.md calls leading nowhere"),
    "b-dead-button": V("bikes", "planted", "the tax button's handler asks whether the element clicked is the button "
                       "itself, and the click lands on its label", (
        ("replace", SITE_JS, 'var button = event.target.closest("button.vat");',
         'var button = event.target.classList.contains("vat") ? event.target : null;'),),
        {"leads": ("broken", ("dead-button",))}, (("dead-button", "/prices.html"),), (("leads", "dead-button"),)),
    "b-button-raises": V("bikes", "planted", "the hill climb's button calls its function under another spelling", (
        ("replace", HILL, 'onclick="showClimb(this)"', 'onclick="showclimb(this)"'),),
        {"leads": ("broken", ("button-raises",))}, (("button-raises", "/routes/hill-climb.html"),),
        (("leads", "button-raises"),)),
    "b-form-nowhere": V("bikes", "planted", "the booking form is posted to a plain page, which takes no post", (
        ("replace", BOOK, '<form id="booking" action="booked.html" method="get">',
         '<form id="booking" action="booked.html" method="post">'),),
        {"forms": ("broken", ("form-nowhere",))}, (("form-nowhere", "/book.html"),), (("forms", "form-nowhere"),)),
    "b-form-raises": V("bikes", "planted", "the booking form's handler reads the phone field under another name", (
        ("replace", SITE_JS, 'tel: booking.elements.tel.value.replace(/[^0-9+]/g, ""),',
         'tel: booking.elements.phone.value.replace(/[^0-9+]/g, ""),'),),
        {"forms": ("broken", ("form-raises",))}, (("form-raises", "/book.html"),), (("forms", "form-raises"),)),
    "b-outside-script": V("bikes", "planted", "the shared script adds a visit counter from another computer to every "
                          "page", (
        ("replace", SITE_JS, "  // The opening hours on the start page",
         '  // Visits counted by the statistics service\n'
         '  var stats = document.createElement("script");\n'
         '  stats.src = "https://stats.example-pulse.net/count.js";\n'
         '  stats.async = true;\n'
         '  document.head.appendChild(stats);\n\n'
         "  // The opening hours on the start page"),),
        {"outside": ("broken", ("outside-script",))}, (("outside-script", "/index.html"),),
        (("outside", "outside-script"),)),
    "b-outside-file": V("bikes", "planted", "the start page's picture comes from a photo service", (
        ("replace", INDEX, '<p><img src="img/ridge.svg" alt="The ridge road at sunset" width="480" height="240"></p>',
         '<p><img src="https://photos.example-pics.net/ridge-sunset.jpg" alt="The ridge road at sunset" width="480" '
         'height="240"></p>'),),
        {"outside": ("broken", ("outside-file",))}, (("outside-file", "/index.html"),), (("outside", "outside-file"),)),
    "b-no-name": V("bikes", "planted", "one of the two icon links in the footer lost its label", (
        ("replace", INDEX, '<a href="https://social.example-net.org/@ridgeline" aria-label="Ridgeline Bikes on Social">',
         '<a href="https://social.example-net.org/@ridgeline">'),),
        {"keyboard": ("broken", ("no-name",))}, (("no-name", "/index.html"),), (("keyboard", "no-name"),)),
    "b-no-label": V("bikes", "planted", "the bike list's label no longer names its field", (
        ("replace", BOOK, '<label for="bike">Bike</label>', '<label>Bike</label>'),),
        {"keyboard": ("broken", ("no-label",))}, (("no-label", "/book.html"),), (("keyboard", "no-label"),)),
    "b-not-reached": V("bikes", "planted", "the river loop's photo is opened by clicking a small picture of it "
                       "instead of a button", (
        ("replace", RIVER, '<p><button type="button" class="zoom">Show the photo</button></p>',
         '<p><img class="zoom" src="../img/river.svg" alt="The river path at dawn: click to see it larger" '
         'width="240" height="150"></p>'),),
        {"keyboard": ("broken", ("not-reached",))}, (("not-reached", "/routes/river-loop.html"),),
        (("keyboard", "not-reached"),)),
    "b-no-focus-ring": V("bikes", "planted", "the outline that shows where the keyboard is was drawn in no colour", (
        ("replace", SITE_CSS, RING, "outline: 2px solid transparent;"),),
        {"keyboard": ("broken", ("no-focus-ring",))}, (("no-focus-ring", "/index.html"),),
        (("keyboard", "no-focus-ring"),)),
    "b-trapped": V("bikes", "planted", "the notes field takes Tab for itself and writes a tab into the text", (
        ("replace", SITE_JS, '    booking.addEventListener("submit", function () {',
         '    booking.elements.notes.addEventListener("keydown", function (event) {\n'
         '      if (event.key !== "Tab") return;\n'
         '      event.preventDefault();\n'
         '      var notes = event.target, at = notes.selectionStart;\n'
         '      notes.value = notes.value.slice(0, at) + "\\t" + notes.value.slice(notes.selectionEnd);\n'
         '      notes.selectionStart = notes.selectionEnd = at + 1;\n'
         '    });\n'
         '    booking.addEventListener("submit", function () {'),),
        {"keyboard": ("broken", ("trapped",))}, (("trapped", "/book.html"),), (("keyboard", "trapped"),)),
    "bl-skip-link": V("bikes", "look-alike", "a link to skip to the content, out of sight until the keyboard reaches "
                      "it", (
        ("replace", INDEX, "<body>\n", '<body>\n<a class="skip" href="#main">Skip to the content</a>\n'),
        ("replace", INDEX, "<main>", '<main id="main">'),
        ("replace", SITE_CSS, ".social { display: flex; gap: .75rem; }",
         ".social { display: flex; gap: .75rem; }\n"
         ".skip { position: absolute; left: -999px; top: .5rem; padding: .5rem 1rem; background: #fff; }\n"
         ".skip:focus { left: 1rem; }")),
        beyond="a link to a place the page has is no link that leads nowhere"),
    "bl-section-link": V("bikes", "look-alike", "a link to the groups' part of the price list, which is there", (
        ("replace", PRICES, '<section id="groups">', '<p><a href="#groups">Prices for groups</a></p>\n'
                                                     '<section id="groups">'),),
        beyond="a link to a place the page has is no link that leads nowhere"),
    "bl-ring-shadow": V("bikes", "look-alike", "the outline drawn in no colour, and a ring drawn as a shadow instead", (
        ("replace", SITE_CSS, RING, "outline: 2px solid transparent; box-shadow: 0 0 0 3px var(--ring);"),),
        beyond="a ring drawn as a shadow shows where the keyboard is"),
    "bl-download-link": V("bikes", "look-alike", "a link to the river loop's route as a file for a bike computer", (
        ("add", "public/files/river-loop.gpx", GPX),
        ("replace", RIVER, "</main>", '<p><a href="../files/river-loop.gpx" download>The route for a bike computer '
                                      "(GPX)</a></p>\n</main>")),
        beyond="a link to a file of the folder that is not a page leads somewhere, and the file is not one of the "
               "pages (`opens` takes the `.html` files)"),
    "bl-phone-link": V("bikes", "look-alike", "a link that calls the shop", (
        ("replace", INDEX, '<p>Ridgeline Bikes, 4 Quarry Lane. ',
         '<p><a href="tel:+15555550142">Call the shop</a></p>\n<p>Ridgeline Bikes, 4 Quarry Lane. '),),
        beyond="a `tel:` link is not an address of the site, like the `mailto:` link the safe site has, and is not "
               "counted"),
    "bl-missing-data": V("bikes", "look-alike", "the trail news file is not there, and the page says there is none", (
        ("remove", "public/data/news.json"),),
        beyond="a data file the page's script asks for is not a script the page names (`not-loaded`), and the "
               "browser's own line about a load that failed is not the site's `console.error`"),

    # ---- clinic: an app whose pages ask its own API
    "clinic": V("clinic", "safe", "the clinic's app as it is"),
    "c-server-error": V("clinic", "planted", "an appointment set to last no minutes: the free times divide by it", (
        ("replace", SETTINGS, "SLOT_MINUTES = 20 ", "SLOT_MINUTES = 0  "),),
        {"opens": ("broken", ("server-error",))}, (("server-error", "/api/slots"),), (("opens", "server-error"),),
        beyond="a page that answers with a server error comes without the headers the code sets for every response (its middleware never ran for it). docs/browser.md does not say whether that is said-not-sent; written down: it is not, the fault is the opens check's alone, as a page that does not open is the opens check's and not the leads check's."),
    "c-not-found": V("clinic", "planted", "bookings switched off, so the booking page answers that it is not there", (
        ("replace", SETTINGS, "BOOKING_OPEN = True ", "BOOKING_OPEN = False"),),
        {"opens": ("broken", ("not-found",))}, (("not-found", "/book"),), (("opens", "not-found"),)),
    "c-no-answer": V("clinic", "planted", "the waiting time waits for a change with no end", (
        ("replace", SETTINGS, "WAIT_TIMEOUT = 0.2 ", "WAIT_TIMEOUT = None"),),
        {"opens": ("broken", ("no-answer",))}, (("no-answer", "/api/waiting"),), (("opens", "no-answer"),)),
    "c-empty": V("clinic", "planted", "the help pages' language set to one they are not written in", (
        ("replace", SETTINGS, 'LANGUAGE = "en"   ', 'LANGUAGE = "en-GB"'),),
        {"opens": ("broken", ("empty",))}, (("empty", "/help"),), (("opens", "empty"),)),
    "c-raised": V("clinic", "planted", "a patient's page reads appointments from the answer that asks for a sign-in", (
        ("replace", "clinic/static/js/me.js", "    if (answer.status === 401) { showSignIn(); return null; }\n", ""),),
        {"script": ("broken", ("raised",))}, (("raised", "/me"),), (("script", "raised"),),
        beyond="an error in a promise that nothing catches is an error the page's script raises"),
    "c-console-error": V("clinic", "planted", "one free time came without its id, and the booking page's script "
                         "says so with console.error", (
        ("replace", "clinic/data.py", '{"id": "t3", "time": "Monday 10:40", "doctor": "Dr Lind"}',
         '{"time": "Monday 10:40", "doctor": "Dr Lind"}'),),
        {"script": ("broken", ("console-error",))}, (("console-error", "/book"),), (("script", "console-error"),)),
    "c-not-loaded": V("clinic", "planted", "the start page's script was renamed and the page still names the old "
                      "file", (
        ("rename", HOME_JS, "clinic/static/js/start.js"),),
        # without it the notice's close button has no handler and the way to the clinic is a link to "#"
        {"script": ("broken", ("not-loaded",)), "leads": ("broken", ("dead-button", "empty-link"))},
        (("not-loaded", "/"), ("dead-button", "/"), ("empty-link", "/")), (("script", "not-loaded"),)),
    "c-dead-link": V("clinic", "planted", "the menu links to the patients' page under its old address", (
        ("replace", PAGES, '<a href="/me">My appointments</a>', '<a href="/appointments">My appointments</a>'),),
        {"leads": ("broken", ("dead-link",))}, (("dead-link", "/"),), (("leads", "dead-link"),)),
    "c-empty-link": V("clinic", "planted", "the way to the clinic's handler looks for its link under a misspelt id", (
        ("replace", HOME_JS, 'document.getElementById("directions");', 'document.getElementById("direction");'),),
        {"leads": ("broken", ("empty-link",))}, (("empty-link", "/"),), (("leads", "empty-link"),)),
    "c-dead-button": V("clinic", "planted", "the button that shows every free time looks for the list under a "
                       "misspelt id, quietly", (
        ("replace", BOOK_JS, 'document.getElementById("time-list")?.toggleAttribute("hidden");',
         'document.getElementById("time-lists")?.toggleAttribute("hidden");'),),
        {"leads": ("broken", ("dead-button",))}, (("dead-button", "/book"),), (("leads", "dead-button"),)),
    "c-button-raises": V("clinic", "planted", "the sooner-time button writes its answer into a note that is not "
                         "there, after the API answered", (
        ("replace", BOOK_JS, 'document.getElementById("sooner-note").textContent = slots.length',
         'document.getElementById("soon-note").textContent = slots.length'),),
        {"leads": ("broken", ("button-raises",))}, (("button-raises", "/book"),), (("leads", "button-raises"),),
        beyond="an error raised in a promise a click started, which nothing catches, is an error the click raises"),
    "c-form-error": V("clinic", "planted", "the booking API calls a method strings do not have", (
        ("replace", API, 'email = str(body.get("email", "")).strip().lower()',
         'email = str(body.get("email", "")).strip().lowercase()'),),
        {"forms": ("broken", ("form-error",))}, (("form-error", "/book"),), (("forms", "form-error"),),
        beyond="a form the page's script sends with fetch is sent to the address the script asks"),
    "c-form-nowhere": V("clinic", "planted", "the question form is sent to an address the API does not have", (
        ("replace", PAGES, 'action="/api/question"', 'action="/api/questions"'),),
        {"forms": ("broken", ("form-nowhere",))}, (("form-nowhere", "/help"),), (("forms", "form-nowhere"),),
        beyond="a form the page's script sends with fetch is sent to the address the script asks"),
    "c-form-raises": V("clinic", "planted", "the booking form's handler reads the e-mail field under another name", (
        ("replace", BOOK_JS, "      email: form.elements.email.value,", "      email: form.elements.mail.value,"),),
        {"forms": ("broken", ("form-raises",))}, (("form-raises", "/book"),), (("forms", "form-raises"),)),
    "c-let-in": V("clinic", "planted", "the sign-in check falls back to a test patient's card", (
        ("replace", API, 'card = data.SESSIONS.get(request.cookies.get("clinic_session", ""))',
         'card = data.SESSIONS.get(request.cookies.get("clinic_session", ""), "40218877")'),),
        {"visitor": ("broken", ("let-in",))}, (("let-in", "/api/me/appointments"),), (("visitor", "let-in"),)),
    "c-said-not-sent": V("clinic", "planted", "the answers' headers are set only on pages, and not on the API's "
                         "answers", (
        ("replace", MAIN, HEADERS,
         '        if response.headers.get("content-type", "").startswith("text/html"):\n'
         + "".join("    " + line + "\n" for line in HEADERS.splitlines())),),
        {"protections": ("broken", ("said-not-sent",))}, (("said-not-sent", "/api/clinic"),),
        (("protections", "said-not-sent"),)),
    "c-cookie-open": V("clinic", "planted", "the session cookie is set without HttpOnly", (
        ("replace", MAIN, 'secrets.token_urlsafe(24), httponly=True, samesite="lax")',
         'secrets.token_urlsafe(24), httponly=False, samesite="lax")'),),
        {"protections": ("broken", ("cookie-open",))}, (("cookie-open", "/"),), (("protections", "cookie-open"),)),
    "c-outside-script": V("clinic", "planted", "the help page loads a nurses' chat from another computer", (
        ("replace", PAGES, "'<p id=\"question-note\" role=\"status\"></p>')",
         "'<p id=\"question-note\" role=\"status\"></p>'\n"
         "        '<script src=\"https://chat.example-care.net/widget.js\" async></script>')"),),
        {"outside": ("broken", ("outside-script",))}, (("outside-script", "/help"),), (("outside", "outside-script"),)),
    "c-outside-file": V("clinic", "planted", "the start page tells a metrics service of each visit", (
        ("replace", HOME_JS, '  fetch("/api/clinic")',
         '  navigator.sendBeacon("https://metrics.example-health.net/visit", JSON.stringify({ page: '
         'location.pathname }));\n  fetch("/api/clinic")'),),
        {"outside": ("broken", ("outside-file",))}, (("outside-file", "/"),), (("outside", "outside-file"),)),
    "c-no-name": V("clinic", "planted", "the notice's close button, a drawing only, lost its label", (
        ("replace", PAGES, '<button type="button" class="close" id="close-notice" aria-label="Close the notice">',
         '<button type="button" class="close" id="close-notice">'),),
        {"keyboard": ("broken", ("no-name",))}, (("no-name", "/"),), (("keyboard", "no-name"),)),
    "c-no-label": V("clinic", "planted", "the reason field is labelled by an id that is not there", (
        ("replace", PAGES, 'aria-labelledby="reason-label"', 'aria-labelledby="reason-text"'),),
        {"keyboard": ("broken", ("no-label",))}, (("no-label", "/book"),), (("keyboard", "no-label"),)),
    "c-not-reached": V("clinic", "planted", "one help topic is a piece of text that answers a click", (
        ("replace", PAGES, '<button type="button" class="topic" data-panel="results">Test results</button>',
         '<span class="topic" data-panel="results">Test results</span>'),),
        {"keyboard": ("broken", ("not-reached",))}, (("not-reached", "/help"),), (("keyboard", "not-reached"),)),
    "c-no-focus-ring": V("clinic", "planted", "buttons lose the outline that shows where the keyboard is", (
        ("replace", CSS, ":focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; }",
         ":focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; }\n"
         "button:focus-visible { outline: none; }"),),
        {"keyboard": ("broken", ("no-focus-ring",))}, (("no-focus-ring", "/"),), (("keyboard", "no-focus-ring"),)),
    "c-trapped": V("clinic", "planted", "the card number field takes the keyboard back while its number does not "
                   "look right", (
        ("replace", "clinic/static/js/signin.js",
         '    note.textContent = looksRight || !card.value ? "" : "Use the 8 digits on the front of your card.";\n',
         '    note.textContent = looksRight || !card.value ? "" : "Use the 8 digits on the front of your card.";\n'
         "    if (!looksRight) setTimeout(function () { card.focus(); }, 0);\n"),),
        {"keyboard": ("broken", ("trapped",))}, (("trapped", "/signin"),), (("keyboard", "trapped"),)),
    "cl-theme-cookie": V("clinic", "look-alike", "a cookie for the colour theme, set without HttpOnly so the pages' "
                         "script can read it", (
        ("replace", MAIN, "        return response\n",
         '        if "theme" not in request.cookies:\n'
         '            response.set_cookie("theme", "light", samesite="lax")\n'
         "        return response\n"),),
        beyond="a cookie named for a colour theme is not named like a sign-in"),
    "cl-refuses-short-question": V("clinic", "look-alike", "the question API refuses a question under 30 letters", (
        ("replace", API, "    if not text:\n", "    if len(text) < 30:\n"),)),
    "cl-live-dot": V("clinic", "look-alike", "a dot beside the waiting time that pulses for as long as the page is "
                     "open", (
        ("replace", PAGES, "'<p>Phone: <span id=\"phone\">555-0100</span></p>'",
         "'<p class=\"live\"><span class=\"dot\" aria-hidden=\"true\"></span> Walk-in waiting time: about 15 "
         "minutes</p>'\n        '<p>Phone: <span id=\"phone\">555-0100</span></p>'"),
        ("replace", CSS, ".error { color: #a12622; }",
         ".error { color: #a12622; }\n"
         ".dot { display: inline-block; width: .6rem; height: .6rem; border-radius: 50%; background: #2e9d5b; "
         "animation: pulse 1.2s ease-in-out infinite; }\n"
         "@keyframes pulse { 50% { opacity: .3; } }")),
        beyond="docs/browser.md: an animation that goes on for ever does not hold the page up"),
    "cl-confirm-button": V("clinic", "look-alike", "a button whose only answer is a question in the browser's own "
                           "dialog", (
        ("replace", PAGES, "'<p><button type=\"submit\">Sign in</button></p>'\n          '</form>')",
         "'<p><button type=\"submit\">Sign in</button></p>'\n          '</form>'\n"
         "          '<p><button type=\"button\" id=\"forget\">Forget this browser</button></p>')"),
        ("replace", "clinic/static/js/signin.js", "  if (!card) return;\n",
         '  var forget = document.getElementById("forget");\n'
         "  if (forget) {\n"
         '    forget.addEventListener("click", function () {\n'
         '      if (window.confirm("Forget the card number kept in this browser?")) localStorage.removeItem("card");\n'
         "    });\n"
         "  }\n"
         "  if (!card) return;\n")),
        beyond="docs/browser.md: a dialog is something a click did"),
}
