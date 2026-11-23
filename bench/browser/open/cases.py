"""The browser benchmark's open part: three sites built against, each safe, with planted problems and with look-alikes
(bench/browser/README.md). Written down on 2026-11-22, before the first run of any of them.

* garden: a community garden's plain pages, served as they are, with folders of their own for style, script and
  pictures.
* tasks: a list of tasks built into `dist/` the way a single-page app is: one page that its script draws whole.
* library: a library's FastAPI app with a sign-in, a stylesheet, a script and a logo.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from define import Family, Version  # noqa: E402  (bench/browser/define.py)

PAGES_SAFE = {"opens": "held", "script": "held", "leads": "held", "forms": "held", "visitor": "nothing-to-check",
              "protections": "not-run", "outside": "held", "keyboard": "held"}

FAMILIES = {
    "garden": Family("garden", "pages", "a community garden's plain pages, served as they are", dict(PAGES_SAFE)),
    "tasks": Family("tasks", "pages", "a list of tasks built into dist/, one page its script draws whole",
                    dict(PAGES_SAFE)),
    "library": Family("library", "app", "a library's FastAPI app with a sign-in",
                      {c: "held" for c in PAGES_SAFE}),
}

MAIN = "js/main.js"
LAST = "  // The size picked last time on the plot list"     # the last part of the garden's script


def _before_last(text: str) -> tuple:
    """An edit that puts a part into the garden's script before its last one."""
    return ("replace", MAIN, LAST, text + "\n\n" + LAST)


WINTER = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Winter hours - Elm Street Community Garden</title>
<link rel="stylesheet" href="css/site.css">
</head>
<body>
<main hidden>
<h1>Winter hours</h1>
<p>From November to February the gate closes at four.</p>
</main>
</body>
</html>
"""

GARDEN_MAP = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Map - Elm Street Community Garden</title>
</head>
<body>
<svg width="360" height="240" viewBox="0 0 360 240" role="img" aria-label="The garden from above">
<rect x="0" y="0" width="360" height="240" fill="#e9f1e1"/>
<rect x="20" y="20" width="150" height="90" fill="#7fb069"/>
<rect x="190" y="20" width="150" height="90" fill="#7fb069"/>
<rect x="20" y="130" width="320" height="90" fill="#a3c585"/>
<circle cx="180" cy="120" r="14" fill="#2f6b2f"/>
</svg>
</body>
</html>
"""

APP_JS = "dist/assets/app-7c41d2.js"
APP_CSS = "dist/assets/app-7c41d2.css"
CSS_END = "body.compact .task{padding:.25rem .5rem}"
HASHCHANGE = 'window.addEventListener("hashchange", render);'
PIN_PART = "  // Signing in: the PIN can be shown while it is typed"
LAYOUT_END = "'<script src=\"/static/site.js\"></script></body></html>', status_code=status)"
WIDGET = ("'<script src=\"/static/site.js\"></script>'\n"
          "        '<script src=\"https://widget.example-chat.net/loader.js\" async></script></body></html>', "
          "status_code=status)")


def _site_js(text: str) -> tuple:
    """An edit that puts a part into the library's script before its last one."""
    return ("replace", "static/site.js", PIN_PART, text + "\n\n" + PIN_PART)


def V(family, kind, what, edits=(), gives=None, seen=(), planted=(), beyond=""):
    return Version(family, kind, what, tuple(edits), dict(gives or {}), tuple(seen), tuple(planted), beyond)


VERSIONS = {
    # ---- garden: plain pages
    "garden": V("garden", "safe", "the garden's five pages as they are"),
    "g-empty-page": V("garden", "planted", "a page whose whole content is hidden while it is being written", (
        ("add", "winter.html", WINTER),), {"opens": ("broken", ("empty",))}, (("empty", "/winter.html"),),
        (("opens", "empty"),)),
    "g-script-raises": V("garden", "planted", "the script shared by every page uses the plot list's field on pages "
                         "that have none, and stops there", (
        ("replace", MAIN, '  var size = document.getElementById("size");\n  if (size) {\n'
                          '    size.addEventListener("change", function () {\n'
                          '      document.querySelectorAll("#plots tbody tr").forEach(function (row) {\n'
                          '        row.hidden = size.value !== "all" && row.dataset.size !== size.value;\n'
                          '      });\n'
                          '      localStorage.setItem("garden-prefs", JSON.stringify({ size: size.value }));\n'
                          '    });\n  }\n',
         '  var size = document.getElementById("size");\n'
         '  size.addEventListener("change", function () {\n'
         '    document.querySelectorAll("#plots tbody tr").forEach(function (row) {\n'
         '      row.hidden = size.value !== "all" && row.dataset.size !== size.value;\n'
         '    });\n'
         '    localStorage.setItem("garden-prefs", JSON.stringify({ size: size.value }));\n'
         '  });\n'),),
        # it stops before the reminders are put on (their buttons are dead), and the page that answers the join form
        # raises as it loads, which is the form's (an error raised while a form is sent belongs to `forms`)
        {"script": ("broken", ("raised",)), "leads": ("broken", ("dead-button",)),
         "forms": ("broken", ("form-raises",))},
        (("raised", "/index.html"), ("dead-button", "/events.html"), ("form-raises", "/join.html")),
        (("script", "raised"),),
        beyond="an error raised while the page that answers a sent form loads is raised while the form is sent, "
               "which docs/browser.md gives to the forms check"),
    "g-console-error": V("garden", "planted", "the script writes an error on every page that has no events", (
        ("replace", MAIN, '  document.querySelectorAll("button.remind").forEach(function (button) {',
         '  var buttons = document.querySelectorAll("button.remind");\n'
         '  if (!buttons.length) console.error("garden: no events on this page");\n'
         '  buttons.forEach(function (button) {'),),
        {"script": ("broken", ("console-error",))}, (("console-error", "/index.html"),), (("script", "console-error"),)),
    "g-script-missing": V("garden", "planted", "the script was renamed and the pages still name the old file", (
        ("rename", MAIN, "js/site.js"),),
        {"script": ("broken", ("not-loaded",)), "leads": ("broken", ("dead-button",))},
        (("not-loaded", "/index.html"), ("dead-button", "/index.html"), ("dead-button", "/events.html")),
        (("script", "not-loaded"),)),
    "g-dead-link": V("garden", "planted", "the plot list links to the join page by a name it had before", (
        ("replace", "plots.html", '<p><a href="join.html">Ask for a plot</a></p>',
         '<p><a href="apply.html">Ask for a plot</a></p>'),),
        {"leads": ("broken", ("dead-link",))}, (("dead-link", "/plots.html"),), (("leads", "dead-link"),)),
    "g-empty-link": V("garden", "planted", "a link to the rules that was never filled in", (
        ("replace", "index.html", "<h2>This season</h2>", '<p><a href="#">Read the garden rules</a></p>\n'
                                                          "<h2>This season</h2>"),),
        {"leads": ("broken", ("empty-link",))}, (("empty-link", "/index.html"),), (("leads", "empty-link"),)),
    "g-dead-button": V("garden", "planted", "one reminder button got another class, so its handler is not put on", (
        ("replace", "events.html", '<button type="button" class="remind" data-event="picnic">Remind me</button>',
         '<button type="button" class="reminder" data-event="picnic">Remind me</button>'),),
        {"leads": ("broken", ("dead-button",))}, (("dead-button", "/events.html"),), (("leads", "dead-button"),)),
    "g-button-raises": V("garden", "planted", "a reminder's note was renamed, and its button's handler looks for it", (
        ("replace", "events.html", '<span class="note" id="note-harvest"></span>',
         '<span class="note" id="note-harvest-supper"></span>'),),
        {"leads": ("broken", ("button-raises",))}, (("button-raises", "/events.html"),), (("leads", "button-raises"),)),
    "g-form-nowhere": V("garden", "planted", "the join form is sent to a page that is not there", (
        ("replace", "join.html", '<form id="join" action="joined.html" method="get">',
         '<form id="join" action="thanks.html" method="get">'),),
        {"forms": ("broken", ("form-nowhere",))}, (("form-nowhere", "/join.html"),), (("forms", "form-nowhere"),)),
    "g-form-raises": V("garden", "planted", "the join form's handler tidies a field under a misspelt id", (
        _before_last('  // Join: tidy the address before it is sent\n'
                     '  var join = document.getElementById("join");\n'
                     '  if (join) {\n'
                     '    join.addEventListener("submit", function () {\n'
                     '      var address = document.getElementById("e-mail");\n'
                     '      address.value = address.value.trim().toLowerCase();\n'
                     '    });\n'
                     '  }'),),
        {"forms": ("broken", ("form-raises",))}, (("form-raises", "/join.html"),), (("forms", "form-raises"),)),
    "g-outside-script": V("garden", "planted", "a visitor counter from another computer on the home page", (
        ("replace", "index.html", '<link rel="stylesheet" href="css/site.css">\n</head>',
         '<link rel="stylesheet" href="css/site.css">\n'
         '<script async src="https://stats.example-counter.net/count.js"></script>\n</head>'),),
        {"outside": ("broken", ("outside-script",))}, (("outside-script", "/index.html"),),
        (("outside", "outside-script"),)),
    "g-outside-file": V("garden", "planted", "the stylesheet takes its font from another computer", (
        ("replace", "css/site.css", "body { font-family: Georgia, serif;",
         '@import url("https://fonts.example-type.net/css2?family=Lora");\nbody { font-family: Lora, Georgia, serif;'),),
        {"outside": ("broken", ("outside-file",))}, (("outside-file", "/index.html"),), (("outside", "outside-file"),)),
    "g-no-name": V("garden", "planted", "the leaf picture became a link home with an empty alt", (
        ("replace", "index.html", '<p><img src="img/leaf.svg" alt="A green leaf" width="48" height="48"></p>',
         '<p><a href="index.html"><img src="img/leaf.svg" alt="" width="48" height="48"></a></p>'),),
        {"keyboard": ("broken", ("no-name",))}, (("no-name", "/index.html"),), (("keyboard", "no-name"),)),
    "g-no-label": V("garden", "planted", "the e-mail field's label names a misspelt id", (
        ("replace", "join.html", '<label for="email">E-mail address</label>', '<label for="e-mail">E-mail address</label>'),),
        {"keyboard": ("broken", ("no-label",))}, (("no-label", "/join.html"),), (("keyboard", "no-label"),)),
    "g-not-reached": V("garden", "planted", "the plot list's rows open the join form when clicked, and Tab cannot "
                       "reach them", (
        _before_last('  // The plot list: a row opens the form for that size of plot\n'
                     '  document.querySelectorAll("#plots tbody tr").forEach(function (row) {\n'
                     '    row.addEventListener("click", function () {\n'
                     '      location.href = "join.html?plot=" + row.dataset.size;\n'
                     '    });\n'
                     '  });'),),
        {"keyboard": ("broken", ("not-reached",))}, (("not-reached", "/plots.html"),), (("keyboard", "not-reached"),)),
    "g-no-focus-ring": V("garden", "planted", "the stylesheet takes the outline off every control", (
        ("replace", "css/site.css", "button { font: inherit; }",
         "button { font: inherit; }\na:focus, button:focus, input:focus, select:focus { outline: none; }"),),
        {"keyboard": ("broken", ("no-focus-ring",))}, (("no-focus-ring", "/index.html"),),
        (("keyboard", "no-focus-ring"),)),
    "g-trapped": V("garden", "planted", "the name field keeps the keyboard until something is typed in it", (
        _before_last('  // Join: the name has to be filled in before the keyboard moves on\n'
                     '  var name = document.getElementById("name");\n'
                     '  if (name) {\n'
                     '    name.addEventListener("keydown", function (event) {\n'
                     '      if (event.key === "Tab" && !name.value.trim()) {\n'
                     '        event.preventDefault();\n'
                     '      }\n'
                     '    });\n'
                     '  }'),),
        {"keyboard": ("broken", ("trapped",))}, (("trapped", "/join.html"),), (("keyboard", "trapped"),)),
    "gl-disabled-button": V("garden", "look-alike", "a disabled button: the waiting list is full", (
        ("replace", "plots.html", '<p><a href="join.html">Ask for a plot</a></p>',
         '<p><a href="join.html">Ask for a plot</a></p>\n'
         '<p><button type="button" disabled>The waiting list is full</button></p>'),),
        beyond="a disabled button is not offered to be clicked, so it is no dead button; docs/browser.md does not "
               "say so in words"),
    "gl-print-button": V("garden", "look-alike", "a button that prints the list of events", (
        ("replace", "events.html", "</ul>\n</main>",
         '</ul>\n<p><button type="button" id="print">Print this list</button></p>\n</main>'),
        _before_last('  // Events: a printed list for the shed door\n'
                     '  var print = document.getElementById("print");\n'
                     '  if (print) {\n'
                     '    print.addEventListener("click", function () {\n'
                     '      window.print();\n'
                     '    });\n'
                     '  }'))),
    "gl-section-link": V("garden", "look-alike", "a link to the rules further down the same page", (
        ("replace", "join.html", "<h1>Join the garden</h1>",
         '<h1>Join the garden</h1>\n<p>Please read <a href="#rules">the garden rules</a> first.</p>'),
        ("replace", "join.html", "</form>\n</main>",
         '</form>\n<h2 id="rules">The garden rules</h2>\n<ol>\n<li>Keep the paths clear.</li>\n'
         "<li>Water in the evening.</li>\n<li>Share what you cannot eat.</li>\n</ol>\n</main>"))),
    "gl-drawing-page": V("garden", "look-alike", "a page that holds only a drawing of the garden, and no text", (
        ("add", "map.html", GARDEN_MAP),)),
    "gl-outside-link": V("garden", "look-alike", "a link to the garden's page on the town's website", (
        ("replace", "index.html", "<li>The water butts are full again</li>\n</ul>",
         "<li>The water butts are full again</li>\n</ul>\n"
         '<p>The town lists every garden: <a href="https://allotments.example.gov/elm-street">our page there</a>.</p>'),)),
    "gl-outside-form": V("garden", "look-alike", "a newsletter form sent to another computer", (
        ("replace", "index.html", "</ul>\n</main>",
         '</ul>\n<form action="https://lists.example.net/subscribe" method="post">\n'
         '<p><label for="news">E-mail for the newsletter</label> <input id="news" name="email" type="email"> '
         '<button type="submit">Subscribe</button></p>\n</form>\n</main>'),)),
    "gl-console-info": V("garden", "look-alike", "the script writes a line of information, not an error", (
        ("replace", MAIN, '(function () {\n  "use strict";\n',
         '(function () {\n  "use strict";\n  console.info("Elm Street garden, 2026 pages");\n'),)),
    "gl-icon-button": V("garden", "look-alike", "a reminder button that shows a bell and has a label for its name", (
        ("replace", "events.html", '<button type="button" class="remind" data-event="seed-swap">Remind me</button>',
         '<button type="button" class="remind" data-event="seed-swap" aria-label="Remind me of the seed swap">'
         '<svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16">'
         '<path d="M8 1a4 4 0 0 0-4 4v3l-2 3h12l-2-3V5a4 4 0 0 0-4-4z" fill="currentColor"/></svg></button>'),)),

    # ---- tasks: one page its script draws whole
    "tasks": V("tasks", "safe", "the list of tasks as it is built"),
    "t-chunk-missing": V("tasks", "planted", "the page names the script of an earlier build: nothing is drawn", (
        ("rename", APP_JS, "dist/assets/app-9f03be.js"),),
        {"opens": ("broken", ("empty",)), "script": ("broken", ("not-loaded",)), "leads": ("nothing-to-check", ()),
         "forms": ("nothing-to-check", ()), "keyboard": ("nothing-to-check", ())},
        (("empty", "/index.html"), ("not-loaded", "/index.html")), (("script", "not-loaded"), ("opens", "empty"))),
    "t-raises-on-load": V("tasks", "planted", "the last line reads a setting that was never saved, and raises", (
        ("replace", APP_JS, 'const settings = JSON.parse(localStorage.getItem("tasks-settings") || "{}");',
         'const settings = JSON.parse(localStorage.getItem("tasks-settings"));'),),
        {"script": ("broken", ("raised",))}, (("raised", "/index.html"),), (("script", "raised"),)),
    "t-console-error": V("tasks", "planted", "the script writes an error when nothing was saved yet", (
        ("replace", APP_JS, "  return saved ? JSON.parse(saved) : FIRST.slice();",
         '  if (!saved) console.error("tasks: nothing saved yet, starting from the first list");\n'
         "  return saved ? JSON.parse(saved) : FIRST.slice();"),),
        {"script": ("broken", ("console-error",))}, (("console-error", "/index.html"),), (("script", "console-error"),)),
    "t-button-raises": V("tasks", "planted", "the Done button's handler reads a data field under its old name", (
        ("replace", APP_JS, "Number(done.dataset.done)", "Number(done.dataset.task)"),),
        {"leads": ("broken", ("button-raises",))}, (("button-raises", "/index.html"),), (("leads", "button-raises"),)),
    "t-dead-button": V("tasks", "planted", "the click handler looks for the Done buttons under a misspelt name", (
        ("replace", APP_JS, 'event.target.closest("button[data-done]")', 'event.target.closest("button[data-dome]")'),),
        {"leads": ("broken", ("dead-button",))}, (("dead-button", "/index.html"),), (("leads", "dead-button"),)),
    "t-form-raises": V("tasks", "planted", "the add form's handler reads the field under another name", (
        ("replace", APP_JS, "form.elements.title.value.trim()", "form.elements.task.value.trim()"),),
        {"forms": ("broken", ("form-raises",))}, (("form-raises", "/index.html"),), (("forms", "form-raises"),)),
    "t-outside-api": V("tasks", "planted", "a tip of the day asked of another service", (
        ("replace", APP_JS, HASHCHANGE + "\nrender();\n",
         HASHCHANGE + "\nrender();\n\n// A tip for the day, from the tips service\n"
         'fetch("https://api.tips.example.net/today")\n'
         "  .then((answer) => answer.json())\n"
         '  .then((tip) => app.append(el("p", { class: "tip" }, tip.text)))\n'
         "  .catch(() => {});\n"),),
        {"outside": ("broken", ("outside-file",))}, (("outside-file", "/index.html"),), (("outside", "outside-file"),)),
    "t-trapped": V("tasks", "planted", "Tab finishes a task's name in the new-task field, as in a terminal", (
        ("replace", APP_JS, HASHCHANGE,
         "// Tab finishes the name of a task, as in a terminal\n"
         'document.addEventListener("keydown", (event) => {\n'
         '  if (event.key === "Tab" && document.activeElement && document.activeElement.id === "task-title") {\n'
         "    event.preventDefault();\n"
         "  }\n"
         "});\n\n" + HASHCHANGE),),
        {"keyboard": ("broken", ("trapped",))}, (("trapped", "/index.html"),), (("keyboard", "trapped"),)),
    "t-no-label": V("tasks", "planted", "the new-task field's label names another id", (
        ("replace", APP_JS, 'el("label", { for: "task-title" }, "New task")', 'el("label", { for: "new-task" }, "New task")'),),
        {"keyboard": ("broken", ("no-label",))}, (("no-label", "/index.html"),), (("keyboard", "no-label"),)),
    "t-no-focus-ring": V("tasks", "planted", "the stylesheet takes the outline off links, buttons and fields", (
        ("replace", APP_CSS, CSS_END, CSS_END + "a:focus,button:focus,input:focus{outline:0}"),),
        {"keyboard": ("broken", ("no-focus-ring",))}, (("no-focus-ring", "/index.html"),),
        (("keyboard", "no-focus-ring"),)),
    "t-blank-render": V("tasks", "planted", "the list shown first was renamed, so the first visit draws nothing", (
        ("replace", APP_JS, 'const name = location.hash.replace(/^#\\//, "") || "today";',
         'const name = location.hash.replace(/^#\\//, "") || "inbox";'),),
        {"opens": ("broken", ("empty",)), "leads": ("nothing-to-check", ()), "forms": ("nothing-to-check", ()),
         "keyboard": ("nothing-to-check", ())},
        (("empty", "/index.html"),), (("opens", "empty"),)),
    "t-dead-link": V("tasks", "planted", "a link to a settings page that a server would have to answer", (
        ("replace", APP_JS,
         '  for (const [name, label] of Object.entries(LISTS)) nav.append(el("a", { href: "#/" + name }, label));',
         '  for (const [name, label] of Object.entries(LISTS)) nav.append(el("a", { href: "#/" + name }, label));\n'
         '  nav.append(el("a", { href: "/settings" }, "Settings"));'),),
        {"leads": ("broken", ("dead-link",))}, (("dead-link", "/index.html"),), (("leads", "dead-link"),)),
    "tl-ring-by-shadow": V("tasks", "look-alike", "no outline, but a shadow shows where the keyboard is", (
        ("replace", APP_CSS, CSS_END, CSS_END + "a:focus,button:focus,input:focus{outline:0;box-shadow:0 0 0 3px #9aa6ff}"),)),
    "tl-wrapped-label": V("tasks", "look-alike", "the new-task field sits inside its label, with no id", (
        ("replace", APP_JS,
         '  form.append(el("label", { for: "task-title" }, "New task"));\n'
         '  form.append(el("input", { id: "task-title", name: "title", required: "" }));\n',
         '  const label = el("label", {}, "New task ");\n'
         '  label.append(el("input", { name: "title", required: "" }));\n'
         "  form.append(label);\n"),)),
    "tl-shortcut-keys": V("tasks", "look-alike", 'the page listens for keys: "n" starts a new task', (
        ("replace", APP_JS, HASHCHANGE,
         '// "n" starts a new task\n'
         'document.addEventListener("keydown", (event) => {\n'
         '  if (event.key === "n" && !(event.target instanceof HTMLInputElement)) {\n'
         '    const field = document.getElementById("task-title");\n'
         "    if (field) {\n"
         "      event.preventDefault();\n"
         "      field.focus();\n"
         "    }\n"
         "  }\n"
         "});\n\n" + HASHCHANGE),)),
    "tl-cdn-library": V("tasks", "look-alike", "a date library from another computer, which the script then needs", (
        ("replace", "dist/index.html", '<script type="module" src="assets/app-7c41d2.js"></script>',
         '<script src="https://cdn.example-jsdelivr.net/npm/dayjs@1.11.10/dayjs.min.js"></script>\n'
         '<script type="module" src="assets/app-7c41d2.js"></script>'),
        ("replace", APP_JS, 'document.body.classList.toggle("compact", Boolean(settings.compact));\n',
         'document.body.classList.toggle("compact", Boolean(settings.compact));\n\n'
         "// Today's date above the lists\n"
         'app.prepend(el("p", { class: "date" }, "Today is " + dayjs().format("dddd D MMMM")));\n')),
        # the script's error may come from the library that was refused: undecided, so `script` cannot tell
        {"script": ("inconclusive", ()), "outside": ("broken", ("outside-script",))},
        (("outside-script", "/index.html"),)),

    # ---- library: a FastAPI app with a sign-in
    "library": V("library", "safe", "the library's app as it is"),
    "l-server-error": V("library", "planted", "the book of the week is one no longer in the catalogue", (
        ("replace", "app/data.py", "FEATURED = 3                    # the book of the week",
         "FEATURED = 7                    # the book of the week"),),
        {"opens": ("broken", ("server-error",))}, (("server-error", "/"),), (("opens", "server-error"),),
        beyond="a page that answers with a server error comes without the headers the code sets for every response (its middleware never ran for it). docs/browser.md does not say whether that is said-not-sent; written down: it is not, the fault is the opens check's alone, as a page that does not open is the opens check's and not the leads check's."),
    "l-not-found": V("library", "planted", "the branch's name is written with a capital, so its events are not found", (
        ("replace", "app/data.py", 'BRANCH = "riverside"', 'BRANCH = "Riverside"'),),
        {"opens": ("broken", ("not-found",))}, (("not-found", "/events"),), (("opens", "not-found"),)),
    "l-no-answer": V("library", "planted", "the catalogue waits for the books to be read in, which nothing does", (
        ("replace", "app/catalogue.py", "CATALOGUE_READY.set()           # the books are read in when the app starts",
         "# CATALOGUE_READY is set once the books have been read in"),),
        {"opens": ("broken", ("no-answer",))}, (("no-answer", "/catalogue"),), (("opens", "no-answer"),)),
    "l-form-error": V("library", "planted", "the suggestion form's handler writes to a misspelt list", (
        ("replace", "app/suggest.py", "data.SUGGESTIONS.append(", "data.SUGGESTION.append("),),
        {"forms": ("broken", ("form-error",))}, (("form-error", "/suggest"),), (("forms", "form-error"),),
        beyond="the answer to the sent form is a page with a server error, which comes without the headers the code sets for every response (its middleware never ran for it). docs/browser.md does not say whether that is said-not-sent; written down: it is not, the fault is the forms check's alone."),
    "l-form-nowhere": V("library", "planted", "the search form is sent to an address no route answers", (
        ("replace", "app/pages.py", 'action="/search"', 'action="/find"'),),
        {"forms": ("broken", ("form-nowhere",))}, (("form-nowhere", "/"),), (("forms", "form-nowhere"),)),
    "l-let-in": V("library", "planted", "a developer's shortcut left on: every visitor is a demo reader", (
        ("replace", "app/data.py", "DEBUG = False                   # True only on a developer's own computer",
         # in two parts (2026-11-22, README): written whole, Lantern's readiness check read it as Lantern's own
         "DEBUG = " + "True                    # True only on a developer's own computer"),),
        {"visitor": ("broken", ("let-in",))}, (("let-in", "/account"),), (("visitor", "let-in"),)),
    "l-said-not-sent": V("library", "planted", "the protections are left off the events page", (
        ("replace", "app/main.py", "    response = await call_next(request)\n",
         "    response = await call_next(request)\n"
         '    if request.url.path == "/events":      # the town\'s own site shows our events in a frame\n'
         "        return response\n"),),
        {"protections": ("broken", ("said-not-sent",))}, (("said-not-sent", "/events"),),
        (("protections", "said-not-sent"),)),
    "l-cookie-open": V("library", "planted", "the session cookie is set without HttpOnly", (
        ("replace", "app/main.py", 'response.set_cookie("sid", secrets.token_urlsafe(24), httponly=True, samesite="lax")',
         'response.set_cookie("sid", secrets.token_urlsafe(24), samesite="lax")'),),
        {"protections": ("broken", ("cookie-open",))}, (("cookie-open", "/"),), (("protections", "cookie-open"),)),
    "l-dead-link": V("library", "planted", "the book of the week links to an address without its s", (
        ("replace", "app/catalogue.py", """f'<p>Book of the week: <a href="/books/{data.FEATURED}">""",
         """f'<p>Book of the week: <a href="/book/{data.FEATURED}">"""),),
        {"leads": ("broken", ("dead-link",))}, (("dead-link", "/"),), (("leads", "dead-link"),)),
    "l-button-raises": V("library", "planted", "the shelf button counts the rows into a part of the page that is gone", (
        ("replace", "static/site.js",
         '      document.querySelectorAll("#books tbody tr").forEach(function (row) {\n'
         '        row.hidden = only && row.dataset.shelf !== "yes";\n'
         "      });\n",
         '      document.querySelectorAll("#books tbody tr").forEach(function (row) {\n'
         '        row.hidden = only && row.dataset.shelf !== "yes";\n'
         "      });\n"
         '      document.getElementById("shown-count").textContent =\n'
         '        String(document.querySelectorAll("#books tbody tr:not([hidden])").length);\n'),),
        {"leads": ("broken", ("button-raises",))}, (("button-raises", "/catalogue"),), (("leads", "button-raises"),)),
    "l-outside-script": V("library", "planted", "a chat widget from another computer, let in by the site's own policy", (
        ("replace", "app/main.py", "\"default-src 'self'\"",
         "\"default-src 'self'; script-src 'self' https://widget.example-chat.net\""),
        ("replace", "app/pages.py", LAYOUT_END, WIDGET)),
        {"outside": ("broken", ("outside-script",))}, (("outside-script", "/"),), (("outside", "outside-script"),)),
    "l-no-name": V("library", "planted", "the logo that leads home has an empty alt", (
        ("replace", "app/pages.py", 'alt="Riverside Library, home"', 'alt=""'),),
        {"keyboard": ("broken", ("no-name",))}, (("no-name", "/"),), (("keyboard", "no-name"),)),
    "l-no-label": V("library", "planted", "the field for the number of copies lost its label", (
        ("replace", "app/suggest.py",
         """'<p><label for="copies">How many copies</label> <input id="copies" name="copies" inputmode="numeric"></p>'""",
         """'<p>How many copies <input id="copies" name="copies" inputmode="numeric"></p>'"""),),
        {"keyboard": ("broken", ("no-label",))}, (("no-label", "/suggest"),), (("keyboard", "no-label"),)),
    "l-not-reached": V("library", "planted", "the shelf toggle is a piece of text that answers a click", (
        ("replace", "app/catalogue.py",
         """'<p><button type="button" id="on-shelf" aria-pressed="false">Show only books on the '""",
         """'<p><span class="toggle" id="on-shelf" aria-pressed="false">Show only books on the '"""),
        ("replace", "app/catalogue.py", "'shelf</button></p>", "'shelf</span></p>")),
        {"keyboard": ("broken", ("not-reached",))}, (("not-reached", "/catalogue"),), (("keyboard", "not-reached"),)),
    "l-no-focus-ring": V("library", "planted", "the stylesheet takes the outline off everything", (
        ("replace", "static/site.css", ".search { margin: 1rem 0; }", ".search { margin: 1rem 0; }\n*:focus { outline: none; }"),),
        {"keyboard": ("broken", ("no-focus-ring",))}, (("no-focus-ring", "/"),), (("keyboard", "no-focus-ring"),)),
    "l-trapped": V("library", "planted", "the PIN field keeps the keyboard until it has four digits", (
        _site_js("  // Signing in: the keyboard moves on from the PIN once it has its four digits\n"
                 '  var pinField = document.getElementById("pin");\n'
                 "  if (pinField) {\n"
                 '    pinField.addEventListener("keydown", function (event) {\n'
                 '      if (event.key === "Tab" && pinField.value.length < 4) {\n'
                 "        event.preventDefault();\n"
                 "      }\n"
                 "    });\n"
                 "  }"),),
        {"keyboard": ("broken", ("trapped",))}, (("trapped", "/login"),), (("keyboard", "trapped"),)),
    "l-not-loaded": V("library", "planted", "every page names a script by a name the static folder does not have", (
        ("replace", "app/pages.py", LAYOUT_END, LAYOUT_END.replace("/static/site.js", "/static/app.js")),),
        {"script": ("broken", ("not-loaded",)), "leads": ("broken", ("dead-button",))},
        (("not-loaded", "/"), ("dead-button", "/catalogue")), (("script", "not-loaded"),)),
    "ll-csp-blocks-widget": V("library", "look-alike", "a chat widget from another computer that the site's own "
                              "policy keeps out", (
        ("replace", "app/pages.py", LAYOUT_END, WIDGET),),
        beyond="the browser does not ask another computer for a script the page's own Content-Security-Policy "
               "refuses, so `outside` holds; its own line about the refused load is not counted, as docs/browser.md "
               "says"),
    "ll-icon-search": V("library", "look-alike", "the search button shows a magnifying glass and has a label", (
        ("replace", "app/pages.py", '<button type="submit">Search</button></form>',
         '<button type="submit" aria-label="Search"><svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16">'
         '<circle cx="7" cy="7" r="5" fill="none" stroke="currentColor" stroke-width="2"/>'
         '<path d="M11 11l4 4" stroke="currentColor" stroke-width="2"/></svg></button></form>'),)),
    "ll-clickable-rows": V("library", "look-alike", "a whole row of the catalogue leads to its book; the link is in it", (
        _site_js("  // The catalogue: a whole row leads to its book\n"
                 '  document.querySelectorAll("#books tbody tr").forEach(function (row) {\n'
                 '    row.addEventListener("click", function (event) {\n'
                 '      var link = row.querySelector("a");\n'
                 "      if (link && event.target !== link) {\n"
                 "        link.click();\n"
                 "      }\n"
                 "    });\n"
                 "  });"),)),
    "ll-slash-shortcut": V("library", "look-alike", 'the page listens for keys: "/" goes to the search field', (
        _site_js('  // "/" goes to the search field, wherever it is on the page\n'
                 '  document.addEventListener("keydown", function (event) {\n'
                 '    var q = document.getElementById("q");\n'
                 '    if (event.key === "/" && q && document.activeElement !== q) {\n'
                 "      event.preventDefault();\n"
                 "      q.focus();\n"
                 "    }\n"
                 "  });"),)),
    "ll-health-json": V("library", "look-alike", "an address that answers data, not a page", (
        ("replace", "app/main.py", "app.include_router(suggest.router)\n",
         'app.include_router(suggest.router)\n\n\n@app.get("/health")\ndef health():\n    return {"status": "ok"}\n'),)),
    "ll-form-refused": V("library", "look-alike", "the suggestion form refuses a number of copies that is no number", (
        ("replace", "app/suggest.py", "    count = int(copies) if copies.strip().isdigit() else 1\n",
         "    if not copies.strip().isdigit():\n"
         '        return layout("Suggest a book", "<p>How many copies: please write a number.</p>" + FORM, status=422)\n'
         "    count = int(copies)\n"),)),
}
