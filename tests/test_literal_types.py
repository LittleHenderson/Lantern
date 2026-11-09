"""Calls on a local that is always a built-in literal (`out = []; out.append(x)`) are counted as built-in calls, not
left untraced. Paired: any other binding of the name (a branch, a loop, a parameter, `except ... as`, a lambda) keeps
the call untraced, and a method the type does not have is never guessed. Built-in calls are never drawn as edges."""

from lantern.engine import build_graph
from lantern.graph import Graph

SAFE = '''
def f():
    out = []
    out.append(1)
    seen = {}
    seen.get("a")
    name = ", ".join(["a"])
    name.upper()
    s = f"x{1}"
    s.strip()
    words = sorted(["b"])
    words.index("b")
    n = 0
    n += 1
'''

UNSAFE = '''
import json


class Box:
    def append(self, x):
        return x


def loop():
    for item in [Box()]:
        item.append(2)


def from_call():
    data = json.loads("[]")
    data.pop("x")


def param(out):
    out = []
    out.append(3)


def no_such_method():
    out = []
    out.nosuch()


def rebound_by_except():
    out = []
    try:
        pass
    except ValueError as out:
        pass
    out.append(1)


def two_types():
    out = []
    out = ""
    out.append(1)


def lambda_shadow():
    x = []
    return lambda x: x.append(1)


def numbers():
    total = 0
    total += 0.5
    total.is_integer()
'''


def _graph(tmp_path, src):
    (tmp_path / "m.py").write_text(src, encoding="utf-8")
    return build_graph(tmp_path)


def test_calls_on_literal_locals_are_counted_as_builtin(tmp_path):
    g = _graph(tmp_path, SAFE)
    assert g.builtin_calls == 6   # five methods and sorted() itself
    assert not g.unresolved
    assert not any(e.dst.startswith("ext:builtins") for e in g.edges)   # counted, never drawn


def test_any_other_binding_keeps_the_call_untraced(tmp_path):
    g = _graph(tmp_path, UNSAFE)
    assert g.builtin_calls == 0, g.unresolved
    for text in ("item.append", "out.append", "out.nosuch", "x.append", "total.is_integer"):
        assert text in g.unresolved, (text, g.unresolved)


def test_the_builtin_count_is_in_the_denominator_and_survives_save_and_load(tmp_path):
    g = _graph(tmp_path, SAFE + "\n\ndef h(v):\n    v.thing()\n    print(len('a'))\n")
    c = g.call_sites()
    assert c["builtin"] == 8 and c["unresolved"] == 1
    assert c["total"] == sum(v for k, v in c.items() if k not in ("total", "unresolved_in_tests", "unresolved_kinds"))
    g.save(tmp_path / "g.json")
    assert Graph.load(tmp_path / "g.json").call_sites()["builtin"] == 8


def test_a_name_rebound_from_an_inner_function_or_a_match_case_stays_untraced(tmp_path):
    g = _graph(tmp_path, '''
class Box:
    def append(self, x):
        return x


def outer():
    items = []

    def inner():
        nonlocal items
        items = Box()
    inner()
    items.append(1)


def matcher(v):
    got = []
    match v:
        case [*got]:
            pass
    got.append(1)
''')
    assert "items.append" in g.unresolved and "got.append" in g.unresolved, g.unresolved


# from the independent review (2026-11-09): `list()` is only the built-in when nothing rebinds the name `list`
def test_a_repo_function_named_list_keeps_its_real_edge(tmp_path):
    g = _graph(tmp_path, '''
class Box:
    def append(self, value):
        return value


def list() -> Box:
    return Box()


def run():
    out = list()
    out.append(1)
''')
    assert g.builtin_calls == 0
    assert any(e.src == "py:m.run" and e.dst == "py:m.Box.append" for e in g.edges), [(e.src, e.dst) for e in g.edges]


def test_a_parameter_named_list_is_not_the_builtin(tmp_path):
    g = _graph(tmp_path, "def run(list):\n    out = list()\n    out.append(1)\n")
    assert g.builtin_calls == 0
    assert "out.append" in g.unresolved, g.unresolved


def test_an_imported_or_assigned_name_list_is_not_the_builtin(tmp_path):
    g = _graph(tmp_path, "from mylib import list\n\n\ndef run():\n    out = list()\n    out.append(1)\n\n\n"
                         "dict = make()\n\n\ndef other():\n    seen = dict()\n    seen.get(1)\n")
    assert g.builtin_calls == 0, g.unresolved


def test_the_real_builtin_list_is_still_counted(tmp_path):
    g = _graph(tmp_path, "def run(items, n: int, d: dict[str, list] = None):\n    out = list(items)\n"
                         "    out.append(str(n))\n")
    assert g.builtin_calls == 3, g.unresolved   # list(), str() and out.append: annotations do not rebind a name
