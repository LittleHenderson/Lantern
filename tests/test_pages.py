"""The app page and the report are each one whole script: every function they call must be defined in them.

2026-11-09: the "Scan incomplete" note on the app's home screen called `arr()`, a helper that exists only in
report.html. The Python tests never open the page in a browser, so the suite stayed green while the home screen drew
nothing (the browser job in CI caught it). This reads each page's script with the grammar Lantern uses for JavaScript
and names every plain call (`f()` or `new F()`) whose function the page declares nowhere and that is not one of the
browser's own. guide.html and the cloud website are left out: they are put together from parts of app.html when the
server starts, so their files alone are not the whole script."""
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
