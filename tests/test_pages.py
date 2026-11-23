"""The app page and the report are each one whole script: every function they call must be defined in them.

2026-11-09: the "Scan incomplete" note on the app's home screen called `arr()`, a helper that exists only in
report.html. The Python tests never open the page in a browser, so the suite stayed green while the home screen drew
nothing (the browser job in CI caught it). This reads each page's script with the grammar Lantern uses for JavaScript
and names every plain call (`f()` or `new F()`) whose function the page declares nowhere and that is not one of the
browser's own. guide.html and the cloud website are left out: they are put together from parts of app.html when the
server starts, so their files alone are not the whole script."""
import re

import pytest
from tree_sitter import Parser

import lantern_files
from lantern.js_frontend import LANGS, inline_script

VIEWER = lantern_files.VIEWER                # the package Python loaded: a release tests the installed one
# the browser's and the language's own functions and classes, which a page calls without defining them
BROWSER = frozenset("""
    fetch setTimeout clearTimeout setInterval clearInterval requestAnimationFrame cancelAnimationFrame queueMicrotask
    encodeURIComponent decodeURIComponent parseInt parseFloat isNaN isFinite structuredClone atob btoa
    String Number Boolean Array Object Date Promise RegExp Map Set WeakMap WeakSet Symbol Error TypeError RangeError
    URL URLSearchParams FormData Blob File FileReader Image Event CustomEvent KeyboardEvent MouseEvent EventSource
    AbortController MutationObserver ResizeObserver IntersectionObserver TextEncoder TextDecoder Uint8Array DOMParser
    alert confirm matchMedia getComputedStyle addEventListener removeEventListener scrollTo scrollBy
""".split())


def _bound(node, out: set[str]) -> None:
    """The names a declaration target or a parameter introduces (plain, defaulted, destructured, rest)."""
    if node is None:
        return
    if node.type in ("identifier", "shorthand_property_identifier_pattern"):
        out.add(node.text.decode("utf-8"))
    elif node.type == "assignment_pattern":
        _bound(node.child_by_field_name("left"), out)
    elif node.type == "pair_pattern":
        _bound(node.child_by_field_name("value"), out)
    else:
        for c in node.named_children:
            _bound(c, out)


def _walk(node, declared: set[str], called: list[tuple[str, int]]) -> None:
    t = node.type
    if t in ("function_declaration", "generator_function_declaration", "function_expression", "class_declaration", "class"):
        _bound(node.child_by_field_name("name"), declared)
    elif t == "variable_declarator":
        _bound(node.child_by_field_name("name"), declared)
    elif t == "formal_parameters":
        _bound(node, declared)
    elif t in ("arrow_function", "catch_clause"):
        _bound(node.child_by_field_name("parameter"), declared)
    elif t == "for_in_statement":
        _bound(node.child_by_field_name("left"), declared)
    elif t == "assignment_expression":
        left = node.child_by_field_name("left")      # `window.askAbout = …` makes `askAbout()` a plain call
        if left is not None and left.type == "member_expression" and \
                left.child_by_field_name("object").text in (b"window", b"globalThis", b"self"):
            declared.add(left.child_by_field_name("property").text.decode("utf-8"))
    if t in ("call_expression", "new_expression"):
        f = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        if f is not None and f.type == "identifier":
            called.append((f.text.decode("utf-8"), f.start_point[0] + 1))
    for c in node.children:
        _walk(c, declared, called)


def undefined_calls(page: bytes) -> dict[str, list[int]]:
    """{name: [line numbers in the page]} for every plain call to a function the page's script never declares."""
    js = inline_script(page)
    assert js is not None, "the page has no script"
    tree = Parser(LANGS[".js"]).parse(js)
    assert not tree.root_node.has_error, "the page's script does not parse"
    declared: set[str] = set()
    called: list[tuple[str, int]] = []
    _walk(tree.root_node, declared, called)
    out: dict[str, list[int]] = {}
    for name, line in called:
        if name not in declared and name not in BROWSER:
            out.setdefault(name, []).append(line)
    return out


@pytest.mark.parametrize("page", ["app.html", "report.html"])
def test_a_page_calls_only_functions_it_defines(page):
    assert undefined_calls((VIEWER / page).read_bytes()) == {}


def test_a_sheet_stays_inside_the_window_and_the_test_sheets_buttons_stay_in_view():
    """2026-11-13: two new fields made the "Watch my tests run" sheet 984 px tall. In a window 900 px high its
    "Confirm and run" button sat below the window, and neither the sheet nor what is behind it scrolled, so nobody
    could press it (the browser job caught it: its click waited 30 seconds and gave up). The released sheet (642 px)
    fitted a window 720 px high and had the same fault in one 600 px high and on a phone: 1,003 px in a window of
    844. The Python tests open no browser, so this reads the rules that hold a sheet to the window; the browser job
    measures the real thing (`sheetFits` in tools/viewer_smoke.js: a desktop, a short laptop and two phones)."""
    page = lantern_files.page("app.html")
    wanted = (".sheetwrap", ".sheet", ".sheet.split", ".sheet.split .shbody", ".sheet.split .acts")
    rules = {}
    for line in page.split("<style>", 1)[1].split("</style>", 1)[0].splitlines():
        for selector in wanted:
            if line.startswith(selector + "{"):
                rules[selector] = line.split("{", 1)[1].split("}", 1)[0]
    assert set(rules) == set(wanted), sorted(rules)
    wrap, sheet, split, body, acts = (dict(d.split(":", 1) for d in rules[s].split(";") if ":" in d) for s in wanted)
    assert wrap["position"] == "fixed" and wrap["padding"] == "20px"
    # never taller than the window less the wrap's padding above and below, and it scrolls by itself
    assert "max-height:calc(100vh - 40px);max-height:calc(100dvh - 40px)" in rules[".sheet"]   # the second where known
    assert sheet["overflow-y"] == "auto"
    # a sheet with a row of buttons: a column whose upper part scrolls and whose row of buttons does not
    assert split["display"] == "flex" and split["flex-direction"] == "column" and split["overflow"] == "hidden"
    assert body["overflow-y"] == "auto" and body["min-height"] == "0" and acts["flex"] == "none"
    assert '<div class="sheet split" role="dialog" aria-label="Watch my tests run"><div class="shbody">' in page
    # and nothing that floats over the page lies on them: Ask Lantern's pill did, on a phone, on the Run button's end
    ask = int(page.split("#ask{", 1)[1].split("z-index:", 1)[1].split(";", 1)[0])
    assert ".sheetwrap.top{z-index:%d}" % (ask + 10) in page and "el.className = 'sheetwrap top'; el.id = 'sheet';" in page
    assert '</div></div>\n    <div class="row acts"><button class="btn" id="shskip">' in page   # the row is outside what scrolls
    # what the server refuses is written at the end of what scrolls, where it is seen, and brought into view
    assert "body.insertAdjacentHTML('beforeend', note('err'" in page and "body.lastElementChild.scrollIntoView" in page
    smoke = (lantern_files.ROOT / "tools" / "viewer_smoke.js").read_text(encoding="utf-8")
    assert smoke.count("await sheetFits(p, name, errs, step, ") == 2 and "[1280, 600]" in smoke and "[360, 640]" in smoke


def test_the_check_sees_a_missing_helper_and_only_that():
    """The check itself: a helper that is not there is named with its line; declared names of every kind, the
    browser's own functions and method calls are not."""
    page = (b"<html><body><script>\n"
            b"const esc = s => String(s);\n"
            b"function draw({ items = [], ...rest }, [first], cb = () => 1) { return cb(first, rest); }\n"
            b"window.askAbout = id => id;\n"
            b"try { draw({}, []); askAbout(1); new Map(); fetch('/x'); [].map(esc); } catch (err) { esc(err); }\n"
            b"for (const k in {}) { esc(k); }\n"
            b"document.body.innerHTML = `${esc(arr([]).join(','))}`;\n"
            b"</script></body></html>\n")
    assert undefined_calls(page) == {"arr": [7]}



# what a fold's title (`<summary>`) may not hold: a screen reader reads the whole title as one button, so a control
# inside it can be neither named nor pressed on its own (axe-core's rule nested-interactive, which it counts serious)
CONTROL = re.compile(r"<(?:button|a|input|select|textarea|details|summary|label)\b|\btabindex\s*=|\bcontenteditable\b", re.I)
TITLE = re.compile(r"<summary\b[^>]*>(.*?)</summary>", re.S | re.I)


def controls_in_titles(text: str) -> list[int]:
    """The line of every fold's title that holds another control: a button, a link, a field, a label, another fold,
    or anything made reachable with Tab."""
    return [text.count("\n", 0, m.start()) + 1 for m in TITLE.finditer(text) if CONTROL.search(m.group(1))]


def files_with_folds() -> dict[str, str]:
    """{name: text} of every file of Lantern's own that writes a fold: its pages, its modules (the Evidence page, the
    change receipt, the comment on a pull request), and the website's and the gateway's pages and modules."""
    paths = [*sorted(VIEWER.glob("*.html")), *lantern_files.modules(deep=True)]
    for part in ("cloud", "gateway"):
        paths += sorted((lantern_files.ROOT / part).rglob("*.py")) + sorted((lantern_files.ROOT / part).rglob("*.html"))
    texts = {lantern_files.named(p): p.read_text(encoding="utf-8") for p in paths}
    return {name: text for name, text in texts.items() if TITLE.search(text)}


def test_no_folds_title_holds_another_control():
    """2026-11-22: the Advanced readiness page put a "Write file" button inside the title of each starter file's
    fold (since 2026-11-02). The browser job's accessibility checker first opened that page in the app with starter
    files to write when the app's "Show the pictures" was checked there (stage 5, step 3 of a firm pass or fail),
    and failed it: 2 controls nested in another. The Python tests open no browser, so this reads every fold's title
    in the files that write one; the browser job looks at the real page (`a11y.axe` in tools/viewer_smoke.js)."""
    found = files_with_folds()
    assert {"lantern/viewer/app.html", "lantern/viewer/report.html", "lantern/evidence.py",
            "cloud/lantern_cloud/site/index.html"} <= set(found), sorted(found)       # else the wrong folder was read
    assert {name: lines for name, text in found.items() if (lines := controls_in_titles(text))} == {}


def test_the_fold_check_sees_a_control_in_a_title_and_only_that():
    """The check itself: a button, a link, a field or a reachable part in a title is named with its line; text, an
    icon, bold words and a control right after the title are not."""
    text = ("<details><summary>${icon('file')}<b>Dockerfile</b><span class=\"note\">why</span></summary>"
            "<pre>x</pre></details><button>Write file</button>\n"
            "<details><summary>Why?</summary><a href=\"#x\">more</a></details>\n"
            "<details class=\"starter\"><summary>${n} <button class=\"btn sm\">Write file</button></summary></details>\n"
            "<details><SUMMARY>a <a href=\"#x\">link</a></SUMMARY></details>\n"
            "<details><summary>a <input type=\"checkbox\"> box</summary></details>\n"
            "<details><summary><span tabindex=\"0\">reachable</span></summary></details>\n"
            "<details><summary>an <abbr title=\"x\">abbr</abbr> and <b>bold</b></summary></details>\n")
    assert controls_in_titles(text) == [3, 4, 5, 6]
