"""A file its parser is not through with in time (lantern/deep.py: `Timed`, `slow`).

The parsers are tree-sitter's. The time one takes is its own, and tree-sitter-dart's grows far faster than the file
on a type written inside itself inside a function (`List<List<…>>`: 4,000 levels 7.5 seconds, 10,000 levels 66,
40,000 not through after two minutes; measured). One such file kept the whole check waiting. Now a parser gets
`deep.PARSE_SECONDS` for one file; a file it is not through with is on the map as a file, is named as not read, and
everything else is read as before. Each such file here stands beside a twin a few levels deep that must be read.
"""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from lantern import deep
from lantern.engine import build_graph

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(__file__).parent / "fixtures"
DEEP = 8000          # levels of a type written inside itself: about a minute for the parser on a 2026 laptop
VERY_DEEP = 16000    # for the whole check with the limit as it ships: several minutes without one
FEW = 40             # a type nobody would blink at
SLOW = "lib/a_grid.dart"     # first by name, so the files after it are read by a parser that was stopped once

PUBSPEC = "name: grid\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\ndependencies:\n  flutter:\n    sdk: flutter\n"
HOME = ("import 'package:flutter/material.dart';\nimport 'store.dart';\n\n"
        "void main() {\n  final store = Store();\n  store.load('all');\n  show(store);\n}\n\n"
        "void show(Store store) {\n  store.count();\n}\n")
STORE = ("class Store {\n  int n = 0;\n\n  void load(String which) {\n    n = n + 1;\n  }\n\n"
         "  int count() {\n    return n;\n  }\n}\n")


def grid(levels: int) -> str:
    """A file with one function that holds a type written inside itself `levels` times, and one line a line rule
    finds whether or not the file was parsed."""
    return ("import 'package:flutter/material.dart';\n\n"
            "int grid(int x) {\n  " + "List<" * levels + "int" + ">" * levels + " y = x;\n  return x;\n}\n\n"
            "void save(String token) {\n  print('token ' + token);\n}\n")


def project(folder: Path, levels: int | None) -> Path:
    files = {"pubspec.yaml": PUBSPEC, "lib/home.dart": HOME, "lib/store.dart": STORE}
    if levels is not None:
        files[SLOW] = grid(levels)
    for rel, text in files.items():
        p = folder / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return folder


def calls(g) -> set:
    return {(e.src, e.dst, e.via, e.confidence) for e in g.call_edges()}


def test_a_file_the_parser_is_not_through_with_is_left_and_named(tmp_path, monkeypatch):
    monkeypatch.setattr(deep, "PARSE_SECONDS", 1)
    began = time.monotonic()
    g = build_graph(project(tmp_path, DEEP))
    took = time.monotonic() - began
    assert took < 20, f"the map took {took:.1f} seconds with a limit of 1 second for one file"
    assert deep.read_slow(g.meta) == (1, [SLOW], 1)
    assert deep.read(g.meta) == (0, [], [])                 # no piece nested too deep and no reader stopped: another thing
    assert f"dt:{SLOW}" in g.nodes                           # the file is on the map as a file,
    assert not [n for n in g.nodes.values() if n.file == SLOW and n.id != f"dt:{SLOW}"]   # and nothing written in it is
    assert {"dt:main", "dt:show", "dt:Store.load", "dt:Store.count"} <= set(g.nodes)       # the files after it are read
    assert g.meta["languages"]["dart"]["files"] == 2        # the files the reader read
    line = deep.line_words(g.meta)
    assert line == f"1 file took its parser longer than 1 second and was not read ({SLOW})"
    told = deep.words(g.meta)
    assert len(told) == 1 and SLOW in told[0] and "longer than 1 second" in told[0]
    assert "no path leads through" in told[0] and "line by line" in told[0]


def test_the_same_type_a_few_levels_deep_is_read(tmp_path):
    g = build_graph(project(tmp_path, FEW))
    assert "too_deep" not in g.meta and deep.read_slow(g.meta) == (0, [], 0)
    assert deep.line_words(g.meta) == "" and deep.words(g.meta) == []
    assert {"dt:grid", "dt:save", "dt:main", "dt:show", "dt:Store.load", "dt:Store.count"} <= set(g.nodes)
    assert g.meta["languages"]["dart"]["files"] == 3


def test_the_files_after_it_are_read_as_if_it_were_not_there(tmp_path, monkeypatch):
    monkeypatch.setattr(deep, "PARSE_SECONDS", 1)
    alone = build_graph(project(tmp_path / "alone" / "app", None))
    beside = build_graph(project(tmp_path / "beside" / "app", DEEP))
    assert calls(alone) == calls(beside) and len(calls(alone)) == 3
    assert set(beside.nodes) - set(alone.nodes) == {f"dt:{SLOW}"}
    for nid, n in alone.nodes.items():
        m = beside.nodes[nid]
        assert (n.kind, n.file, n.start_line, n.end_line, n.signature, n.fingerprint, n.entry) == \
               (m.kind, m.file, m.start_line, m.end_line, m.signature, m.fingerprint, m.entry), nid


def test_a_large_ordinary_file_is_read_whole(tmp_path):
    """The limit as it ships is nowhere near a file of ordinary code: the largest file the reader takes is parsed
    in under a second."""
    unit = "".join(p.read_text(encoding="utf-8") for p in sorted((FIX / "flutterapp" / "lib").rglob("*.dart")))
    unit = unit.replace("import ", "// import ")
    classes = len(re.findall(r"^class ", unit, re.M))
    parts, n = [], 0
    while sum(map(len, parts)) < 600_000:
        parts.append(re.sub(r"^class ", f"class K{n}", unit, flags=re.M))
        n += 1
    project(tmp_path, None)
    (tmp_path / "lib" / "many.dart").write_text("".join(parts), encoding="utf-8")
    g = build_graph(tmp_path)
    assert "too_deep" not in g.meta
    assert classes >= 5 and n > 100
    assert len([x for x in g.nodes.values() if x.file == "lib/many.dart" and x.kind == "class"]) == classes * n


def test_the_whole_check_ends_and_says_what_it_did_not_read(tmp_path):
    """`lantern analyze` with the limit as it ships, in a process of its own: it ends, names the file in its log and
    in the Evidence Report's Limits, and the line rules still read that file."""
    folder, out = project(tmp_path / "app", VERY_DEEP), tmp_path / "out"
    env = dict(os.environ, LANTERN_CACHE="off")
    began = time.monotonic()
    try:
        r = subprocess.run([sys.executable, "-m", "lantern.cli", "analyze", str(folder), "--out", str(out), "--offline"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90, env=env,
                           cwd=str(ROOT))
    except subprocess.TimeoutExpired:
        pytest.fail(f"the check was not through after 90 seconds: one file with a type written inside itself "
                    f"{VERY_DEEP} times kept it waiting")
    took = time.monotonic() - began
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    said = [ln for ln in (r.stdout + r.stderr).splitlines() if ln.startswith("deep ")]
    assert len(said) == 1 and said[0].endswith(
        f"1 file took its parser longer than {deep.PARSE_SECONDS} seconds and was not read ({SLOW})"), said
    graph = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    assert deep.read_slow(graph["meta"]) == (1, [SLOW], deep.PARSE_SECONDS)
    ids = {n["id"] for n in graph["nodes"]}
    assert {f"dt:{SLOW}", "dt:main", "dt:show", "dt:Store.load", "dt:Store.count"} <= ids and "dt:grid" not in ids
    limits = json.loads((out / "evidence.json").read_text(encoding="utf-8"))["limits"]
    told = [x for x in limits if "took its parser longer than" in x]
    assert len(told) == 1 and SLOW in told[0], limits
    assert "took its parser longer than" in (out / "evidence.html").read_text(encoding="utf-8")
    found = json.loads((out / "security.json").read_text(encoding="utf-8"))["findings"]
    assert [f for f in found if f["rule"] == "LF-LOG-SENSITIVE" and f["file"] == SLOW], [f["rule"] for f in found]
    assert took < 90


def test_what_was_written_down_is_read_back_whatever_its_shape():
    nothing = (None, [], "x", {}, {"too_deep": None}, {"too_deep": {"slow": None}}, {"too_deep": {"slow": ["a.dart"]}},
               {"too_deep": {"slow": {"count": "1", "files": ["a.dart"]}}},
               {"too_deep": {"slow": {"count": True, "files": ["a.dart"]}}},
               {"too_deep": {"slow": {"count": -2, "files": ["a.dart"]}}},
               {"too_deep": {"slow": {"count": 1.0, "files": ["a.dart"]}}},
               {"too_deep": {"slow": {"count": 1, "files": "a.dart"}}},
               {"too_deep": {"slow": {"count": 1, "files": [3, None, ["a.dart"]]}}},
               {"too_deep": {"slow": {"count": 1}}}, {"too_deep": {"slow": {"files": ["a.dart"]}}})
    for meta in nothing:
        assert deep.read_slow(meta) == (0, [], 0) and deep.words(meta) == [] and deep.line_words(meta) == "", meta
    # the seconds are said only when they are a whole number a limit could be
    for seconds in (None, "10", True, -1, 0, 2.5, 10 ** 9):
        meta = {"too_deep": {"slow": {"count": 2, "files": ["a.dart", "b.dart"], "seconds": seconds}}}
        assert deep.read_slow(meta) == (2, ["a.dart", "b.dart"], 0)
        assert deep.line_words(meta) == "2 files took their parser longer than Lantern waits and were not read " \
                                        "(a.dart, b.dart)"
    # beside pieces nested too deep and a reader that stopped, each is said
    meta = {"too_deep": {"pieces": 1, "files": ["a.py"], "readers": ["go"],
                         "slow": {"count": 1, "files": ["a.dart"], "seconds": 10}}}
    line = deep.line_words(meta)
    assert line.startswith("1 piece of code nested deeper than Lantern follows was not read to the end (a.py); ")
    assert "; 1 file took its parser longer than 10 seconds and was not read (a.dart)" in line
    assert len(deep.words(meta)) == 3


def test_the_words_count_and_cut_what_they_name():
    odd = "x" * 500 + "\n\x1b[31m<b>.dart"
    many = {"too_deep": {"slow": {"count": 45, "files": [odd, "b.dart", "c.dart", "d.dart", "e.dart"], "seconds": 10}}}
    line, words = deep.line_words(many), deep.words(many)
    assert line.startswith("45 files took their parser longer than 10 seconds and were not read (")
    assert "b.dart, c.dart and 42 more)" in line                 # the count is of all of them, not of the names kept
    assert len(words) == 1 and words[0].startswith("45 files of the project took their parser longer than 10 seconds")
    for text in (line, *words):
        assert "\n" not in text and "\x1b" not in text and "x" * 121 not in text and len(text) < 700, text


def test_forty_files_are_named_and_the_rest_counted():
    from lantern.graph import Graph
    g = Graph(repo_root="/nowhere")
    for i in range(45):
        deep.slow((g, "dart"), f"lib/f{i}.dart")
    deep.slow(None, "lib/no-map.dart")                           # a reader used with no map writes nothing down
    rec = g.meta["too_deep"]["slow"]
    assert rec["count"] == 45 and len(rec["files"]) == deep.MOST == 40 and rec["readers"] == ["dart"]
    assert rec["seconds"] == deep.PARSE_SECONDS
    assert deep.read_slow(g.meta) == (45, [f"lib/f{i}.dart" for i in range(40)], deep.PARSE_SECONDS)


class Own:
    """A stand-in for the library up to 0.25: the limit is the parser's own, and a parse that reaches it raises."""
    timeout_micros = 0

    def __init__(self, takes):
        self.takes, self.resets, self.asked = takes, 0, []

    def parse(self, src):
        self.asked.append((src, self.timeout_micros))
        if self.takes * 1_000_000 > self.timeout_micros:
            time.sleep(self.timeout_micros / 1_000_000)
            raise ValueError("Parsing failed")
        return ("tree", src)

    def reset(self):
        self.resets += 1


class Asked:
    """A stand-in for the library from 0.26: a parse asks a function as it goes whether to stop, and only when the
    file is handed over through a function that reads it."""

    def __init__(self, takes):
        self.takes, self.resets, self.asked = takes, 0, []

    def parse(self, src, old_tree=None, progress_callback=None):
        self.asked.append(("read" if callable(src) else "bytes", old_tree))
        if old_tree is not None:
            return ("tree", src, "from", old_tree)
        text, at = b"", 0
        while True:
            piece = src(at, (0, 0))
            if not piece:
                break
            text, at = text + piece, at + len(piece)
        end = time.monotonic() + self.takes
        while time.monotonic() < end:
            if progress_callback(None):
                raise ValueError("Parsing failed")
            time.sleep(0.01)
        return ("first", text)

    def reset(self):
        self.resets += 1


@pytest.mark.parametrize("make", [Own, Asked])
def test_each_way_of_stopping_a_parser(make, monkeypatch):
    monkeypatch.setattr(deep, "PARSE_SECONDS", 0.3)
    src = b"x" * 200_000 + "é".encode() * 10
    quick = make(0)
    tree = deep.Timed(quick).parse(src)
    assert tree[0] == "tree" and tree[1] == src and quick.resets == 0
    if make is Asked:                # the tree handed on has the file's own bytes behind it, not the reading function
        assert quick.asked == [("read", None), ("bytes", ("first", src))]
    else:
        assert quick.asked == [(src, 300_000)]
    slow = make(5)
    began = time.monotonic()
    assert deep.Timed(slow).parse(src) is None
    assert 0.25 < time.monotonic() - began < 3 and slow.resets == 1     # stopped at the limit, and made ready again


@pytest.mark.parametrize("make", [Own, Asked])
def test_a_parse_that_fails_before_the_limit_is_not_called_slow(make, monkeypatch):
    """Only the clock makes a file one the parser was not through with. Anything else the library refuses is an
    error as it was, not a file quietly left out."""
    monkeypatch.setattr(deep, "PARSE_SECONDS", 30)

    class Refuses(make):
        def parse(self, *a, **k):
            raise ValueError("Parsing failed")

    with pytest.raises(ValueError):
        deep.Timed(Refuses(0)).parse(b"void main() {}\n")


def test_the_installed_parser_is_stopped_and_reads_the_next_file_as_a_new_one_would(monkeypatch):
    from lantern import dart_frontend
    monkeypatch.setattr(deep, "PARSE_SECONDS", 1)
    timed, fresh = dart_frontend._parser(), dart_frontend._parser()
    assert isinstance(timed, deep.Timed)
    began = time.monotonic()
    assert timed.parse(grid(DEEP).encode()) is None
    assert time.monotonic() - began < 15
    for text in (HOME, STORE, grid(FEW), "", "class { ((( int x = ; }} void g( {\n"):
        a, b = timed.parse(text.encode()), fresh.parse(text.encode())
        assert str(a.root_node) == str(b.root_node) and a.root_node.text == b.root_node.text == text.encode()


def _nodes(tree) -> list:
    out, stack = [], [tree.root_node]
    while stack:
        x = stack.pop()
        out.append((x.type, x.start_byte, x.end_byte, x.start_point, x.end_point, x.is_named, x.has_error, x.text))
        stack.extend(x.children)
    return out


def test_a_tree_read_under_the_limit_is_the_tree_read_without_one():
    """Every node, its place and its text, for the sample's files and for files a reading in pieces could trip on:
    a character of several bytes across the end of a piece, bytes that are no text, Windows line ends, a file
    with mistakes, an empty one."""
    import tree_sitter as ts
    import tree_sitter_dart as td
    from lantern import dart_frontend
    plain, timed = ts.Parser(ts.Language(td.language())), dart_frontend._parser()
    texts = [p.read_bytes() for p in sorted((FIX / "flutterapp").rglob("*.dart"))]
    assert len(texts) >= 6
    line = "void f{} () {{ var s = 'café € \U0001F600'; }}\n"
    long = "".join(line.format(i) for i in range(6000)).encode()          # 250,000 bytes and more: several pieces
    texts += [long, b"x" * 65535 + "€".encode() + b" y;\n", long.replace(b"\n", b"\r\n"),
              b"void f() { var s = '\xff\xfe caf\xc3\xa9 \xe2\x82'; }\r\n" * 500,
              long[:90_000] + b"\nclass { ((( int x = ; }} void g( {\n" + long[90_000:], b"", b"\xef\xbb\xbfvoid main() {}\n"]
    for src in texts:
        assert _nodes(timed.parse(src)) == _nodes(plain.parse(src)), src[:60]
