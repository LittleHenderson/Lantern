"""The map inside a report, written column by column (directive point 10): lantern/columns.py and the page's own
`unpackGraph`.

A report used to hold the map row by row: every node and every link a table of its own with every field's name, and
every link naming its two functions in full. For Django that was 52 of the report's 74 MB, and most of the time a
phone needs to open the report is the time it needs to take the file in. Nothing may be lost by writing it another
way, so every test here is about the same thing: what comes back out is exactly what went in (the same rows, the
same fields in the same order, the same values of the same kind), in Python and in the page, for the samples' own
maps and for maps no Lantern would write.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from lantern import columns, engine, report
from lantern.report import read_bundle, render

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLES = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir() and p.name != "old_results")
VIEWER = Path(report.__file__).parent / "viewer" / "report.html"


def _text(x) -> str:
    """One text for a value: the same text only for the same rows, fields in the same order, values of the same kind
    (`1`, `1.0` and `true` are three texts)."""
    return json.dumps(x, separators=(",", ":"), ensure_ascii=False)


def _through_a_file(x):
    return json.loads(_text(x))


def _node(i: int, **more) -> dict:
    return {"id": f"py:app.f{i}", "kind": "callable", "name": f"f{i}", "qualname": f"app.f{i}", "file": "app.py",
            "start_line": i, "end_line": i + 1, "parent": "py:app", "fingerprint": None, "signature": f"def f{i}()",
            "docstring": None, "decorators": [], "entry": None, "lane": "server", **more}


def _edge(a: int, b: int, **more) -> dict:
    return {"src": f"py:app.f{a}", "dst": f"py:app.f{b}", "kind": "calls", "confidence": "resolved", "lines": [a],
            "via": "name", "detail": None, **more}


def _graph(nodes, edges, **more) -> dict:
    return {"schema": 7, "repo_root": "/x", "meta": {"languages": {"python": 3}}, "nodes": nodes, "edges": edges,
            "unresolved": {"x.y": 2}, "unresolved_totals": {"call_sites": 2}, **more}


PLAIN = _graph([{"id": "py:app", "kind": "module", "name": "app", "qualname": "app", "file": "app.py", "start_line": 1,
                 "end_line": 40, "parent": None, "fingerprint": None, "signature": None, "docstring": "The app.",
                 "decorators": [], "entry": None, "lane": None}] + [_node(i) for i in range(1, 30)],
               [_edge(i, i + 1) for i in range(1, 29)])

# Maps no Lantern writes: what a report that somebody changed, or a later Lantern, may hold. Each must come back as
# it went in, packed or left as it is.
ODD = {
    "no rows": _graph([], []),
    "one row each": _graph([_node(1)], [_edge(1, 1)]),
    "every row the same": _graph([_node(1)] * 5, [_edge(1, 1)] * 5),
    "a row that is no table": _graph([_node(1), "x", _node(2)], [_edge(1, 2), None]),
    "rows with other fields": _graph([_node(1), {"id": "py:x"}], [_edge(1, 2), {"src": "a"}]),
    "fields in another order": _graph([_node(1), dict(reversed(list(_node(2).items())))], [_edge(1, 2)]),
    "an id twice": _graph([_node(1), _node(1), _node(2)], [_edge(1, 2), _edge(2, 1), _edge(1, 1)]),
    "a link to nowhere": _graph([_node(1), _node(2)], [_edge(1, 9), _edge(9, 2), _edge(1, 2)]),
    "ids that are no text": _graph([_node(1, id=7), _node(2, id=None), _node(3, id=["x"]), _node(4, id=True)],
                                   [_edge(1, 2, src=7, dst=None), _edge(1, 2, src=0, dst=1), _edge(1, 2, src=True),
                                    _edge(1, 2, src=[3], dst={"a": 1}), _edge(1, 2, src=1.0, dst="py:app.f4")]),
    "numbers, yes and no": _graph([_node(i, start_line=v, end_line=w) for i, (v, w) in enumerate(
        [(1, 1.0), (True, False), (0, None), (-1, 1e300), (1.5, "1"), ("", " "), (None, 0.0), (2 ** 70, -0.0)])], []),
    "values that repeat": _graph([_node(i, lane=["a", None, 1, True, 1.0, "a", "", False][i % 8]) for i in range(40)],
                                 [_edge(i % 5, i % 7, via=[None, "name", "import"][i % 3]) for i in range(60)]),
    "lists and tables that repeat": _graph([_node(i, decorators=[["@a"], [], ["@a"], [["x"]], {"k": [1]}][i % 5],
                                                  entry=[None, {"kind": "route", "detail": "GET /"}][i % 2])
                                            for i in range(20)], [_edge(1, 2, lines=[[1, 2], [], [1, 2]][i % 3])
                                                                  for i in range(20)]),
    "a field named like the page's own": _graph([{"id": "a", "__proto__": 1}, {"id": "b", "__proto__": 2}],
                                                [{"src": "a", "constructor": 1}, {"src": "b", "constructor": 2}]),
    "fields that are numbers": _graph([{"2": "b", "1": "a", "id": "x"}, {"2": "d", "1": "c", "id": "y"}], []),
    "no fields at all": _graph([{}, {}, {}], [{}]),
    "nodes that are no list": _graph({"a": 1}, "edges"),
    "no nodes at all": {"schema": 7, "edges": [_edge(1, 2), _edge(2, 1)]},
    "it says it is packed": _graph([_node(1), _node(2)], [_edge(1, 2)], packed=1),
    "it says so in another way": _graph([_node(1), _node(2)], [_edge(1, 2)], packed=None),
    "text of every kind": _graph([_node(i, name=s) for i, s in enumerate(
        ["</script>", "<!--", "  ", "\x00\x1f", "é€😀", "\\u003c", '"', "'", "\n", "a" * 5000])], []),
    "packed inside the rows": _graph([_node(1, entry={"keys": ["a"], "n": 1, "cols": [["v", [1]]]})], []),
    "not a map": {"nodes": 1},
    "empty": {},
}


@pytest.mark.parametrize("name", ["plain", *ODD])
def test_what_comes_back_is_exactly_what_went_in(name):
    graph = PLAIN if name == "plain" else ODD[name]
    before = _text(graph)
    packed = columns.pack_graph(graph)
    assert _text(graph) == before                                        # packing changes nothing it was handed
    assert _text(columns.unpack_graph(packed)) == before
    assert _text(columns.unpack_graph(_through_a_file(packed))) == before      # and through a file, as in a report
    again = columns.pack_graph(columns.unpack_graph(packed))
    assert _text(again) == _text(packed)                                 # the same map is always written the same way


@pytest.mark.parametrize("sample", SAMPLES)
def test_a_samples_own_map_comes_back_as_it_was(sample):
    graph = _through_a_file(engine.build_graph(FIXTURES / sample).to_dict())
    packed = columns.pack_graph(graph)
    assert packed.get("packed") == columns.FORM
    assert _text(columns.unpack_graph(_through_a_file(packed))) == _text(graph)
    assert len(_text(packed)) < 0.62 * len(_text(graph))                 # and it is a good deal smaller


def test_the_packed_map_says_what_it_is_and_keeps_the_rest():
    packed = columns.pack_graph(PLAIN)
    assert list(packed) == [*PLAIN, "packed"] and packed["packed"] == columns.FORM == 1
    for part in ("schema", "repo_root", "meta", "unresolved", "unresolved_totals"):
        assert packed[part] == PLAIN[part]
    nodes, edges = packed["nodes"], packed["edges"]
    assert nodes["keys"] == list(PLAIN["nodes"][0]) and nodes["n"] == 30 and edges["n"] == 28
    how = {k: c[0] for k, c in zip(edges["keys"], edges["cols"])}
    assert how == {"src": "r", "dst": "r", "kind": "c", "confidence": "c", "lines": "v", "via": "c", "detail": "c"}
    assert edges["cols"][0][1][:3] == [1, 2, 3]                          # a link names its function by its place
    assert {k: c[0] for k, c in zip(nodes["keys"], nodes["cols"])}["parent"] == "r"
    assert nodes["cols"][nodes["keys"].index("parent")][1][:2] == [[None], 0]     # what is no id stands as itself


def test_every_row_that_comes_back_is_its_own():
    back = columns.unpack_graph(_through_a_file(columns.pack_graph(ODD["lists and tables that repeat"])))
    back["nodes"][0]["decorators"].append("@changed")
    back["nodes"][1]["entry"]["kind"] = "changed"
    assert back["nodes"][2]["decorators"] == ["@a"] and back["nodes"][3]["entry"] == {"kind": "route", "detail": "GET /"}
    plain = columns.unpack_graph(PLAIN)
    assert plain == PLAIN and plain["nodes"] is PLAIN["nodes"]           # a map that is not packed is handed back


def _packed(**changes) -> dict:
    p = _through_a_file(columns.pack_graph(PLAIN))
    for where, value in changes.items():
        part, _, field = where.partition("_")
        if field:
            p[part][field] = value
        else:
            p[part] = value
    return p


def _col(part: str, key: str, col) -> dict:
    p = _through_a_file(columns.pack_graph(PLAIN))
    p[part]["cols"][p[part]["keys"].index(key)] = col
    return p


N, E = 30, 28
NOT_OURS = {
    "another form": _packed(packed=2),
    "a form that is yes": _packed(packed=True),
    "no rows where rows must be": _packed(nodes=7),
    "rows with no count": _packed(nodes_n=None),
    "a count that is yes": _packed(nodes_n=True),
    "a count below nothing": _packed(nodes_n=-1),
    "more rows than any column has": _packed(nodes_n=N + 1),
    "a count nobody can hold": _packed(edges_n=10 ** 12),
    "fields that are no list": _packed(nodes_keys="id"),
    "a field that is no text": _packed(edges_keys=["src", "dst", "kind", "confidence", "lines", "via", 7]),
    "the same field twice": _packed(edges_keys=["src", "dst", "kind", "confidence", "lines", "via", "via"]),
    "a field the page would take for its own": _packed(edges_keys=["src", "dst", "kind", "confidence", "lines", "via",
                                                                    "__proto__"]),
    "fewer columns than fields": _packed(edges_cols=[["c", 1]]),
    "columns that are no list": _packed(edges_cols={"a": 1}),
    "a column of no kind": _col("edges", "via", ["x", []]),
    "a column that is no list": _col("edges", "via", "v"),
    "a column that is short": _col("edges", "lines", ["v", [[1]] * (E - 1)]),
    "a column that is long": _col("edges", "lines", ["v", [[1]] * (E + 1)]),
    "values that are no list": _col("edges", "lines", ["v", "x" * E]),
    "the same value for all, and it is a list": _col("edges", "via", ["c", ["x"]]),
    "a list of values with a table in it": _col("edges", "via", ["t", [{"a": 1}], [0] * E]),
    "a place past the list of values": _col("edges", "via", ["t", ["a", "b"], [0] * (E - 1) + [2]]),
    "a place before the list of values": _col("edges", "via", ["t", ["a", "b"], [0] * (E - 1) + [-1]]),
    "a place that is yes": _col("edges", "via", ["t", ["a", "b"], [0] * (E - 1) + [True]]),
    "a place that is not whole": _col("edges", "via", ["t", ["a", "b"], [0] * (E - 1) + [1.0]]),
    "places that are short": _col("edges", "via", ["t", ["a"], [0] * (E - 1)]),
    "a function past the last one": _col("edges", "src", ["r", [0] * (E - 1) + [N]]),
    "a function before the first": _col("edges", "src", ["r", [0] * (E - 1) + [-1]]),
    "a function that is yes": _col("edges", "src", ["r", [0] * (E - 1) + [False]]),
    "a function that is text": _col("edges", "src", ["r", [0] * (E - 1) + ["py:app.f1"]]),
    "a value in a box of two": _col("edges", "src", ["r", [0] * (E - 1) + [["a", "b"]]]),
    "a value in an empty box": _col("edges", "src", ["r", [0] * (E - 1) + [[]]]),
    "a function where no node can be named": _col("nodes", "id", ["r", [0] * N]),
    "nothing but the same value for all": _packed(edges_cols=[["c", 1]] * 7),
}


@pytest.mark.parametrize("name", list(NOT_OURS))
def test_a_packed_map_of_another_shape_is_refused_in_words(name):
    with pytest.raises(ValueError, match="analyze again"):
        columns.unpack_graph(NOT_OURS[name])


def test_a_count_nobody_can_hold_makes_no_rows():
    p = _packed(edges_n=10 ** 12, edges_cols=[["c", 1]] * 7)             # no column has a list: nothing bounds the count
    with pytest.raises(ValueError, match="analyze again"):
        columns.unpack_graph(p)                                          # refused before a single row is made


# ----------------------------------------------------------------------------- in a report
def _data_block(html: str) -> dict:
    return json.loads(html.split('id="lantern-data">', 1)[1].split("</script>", 1)[0])


def test_a_report_holds_the_map_packed_and_gives_it_back_whole(tmp_path):
    bundle = {"version": "x", "graph": _through_a_file(PLAIN), "security": {"findings": []}, "sources": {"py:app.f1": "a"}}
    before = _text(bundle)
    html = render(bundle)
    assert _text(bundle) == before                                       # the caller's bundle is not changed
    held = _data_block(html)
    assert held["graph"]["packed"] == 1 and not isinstance(held["graph"]["nodes"], list)
    assert {k: v for k, v in held.items() if k != "graph"} == {k: v for k, v in bundle.items() if k != "graph"}
    p = tmp_path / "report.html"
    p.write_text(html, encoding="utf-8")
    assert _text(read_bundle(p)) == before
    assert render(read_bundle(p)) == html                                # a page made again from a report is that report


def test_a_report_an_older_lantern_wrote_is_still_read(tmp_path):
    for old in sorted((FIXTURES / "old_results").glob("*/report.html")):
        data = read_bundle(old)
        assert isinstance(data["graph"]["nodes"], list) and data["graph"]["nodes"], old
        assert "packed" not in data["graph"]
    plain = (tmp_path / "report.html")
    plain.write_text('<script type="application/json" id="lantern-data">' + _text({"graph": PLAIN}) + "</script>",
                     encoding="utf-8")
    assert _text(read_bundle(plain)["graph"]) == _text(PLAIN)


def test_a_report_whose_packed_map_is_not_ours_is_refused_in_words(tmp_path):
    p = tmp_path / "report.html"
    for name, graph in NOT_OURS.items():
        p.write_text('<script type="application/json" id="lantern-data">' + _text({"graph": graph}) + "</script>",
                     encoding="utf-8")
        try:
            read_bundle(p)
        except ValueError as exc:
            assert "analyze again" in str(exc), name
        else:
            raise AssertionError(f"read as if Lantern wrote it: {name}")


def test_a_bundle_with_no_map_is_written_as_it_is():
    for bundle in ({"graph": {}}, {"graph": None}, {}, {"graph": {"nodes": [{"id": "x", "doc": "<"}]}}):
        assert _data_block(render(bundle)) == bundle or _data_block(render(bundle))["graph"].get("packed") == 1


# ----------------------------------------------------------------------------- in the page
def _unpack_in_the_page(graphs: list, tmp_path: Path) -> list:
    """What the page's own `unpackGraph` makes of each packed map, run by Node on the function's text."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    html = VIEWER.read_text(encoding="utf-8")
    m = re.search(r"^function unpackGraph\(g\) \{.*?^\}\n", html, re.S | re.M)
    assert m, "the page has no unpackGraph"
    (tmp_path / "in.json").write_text(_text(graphs), encoding="utf-8")
    (tmp_path / "run.js").write_text(
        m.group(0) + "\nconst fs = require('fs');\n"
        "const out = JSON.parse(fs.readFileSync(process.argv[2], 'utf8')).map(g => {\n"
        "  try { return { ok: unpackGraph(g) }; } catch (e) { return { threw: String(e) }; }\n});\n"
        "fs.writeFileSync(process.argv[3], JSON.stringify(out));\n", encoding="utf-8")
    r = subprocess.run([node, str(tmp_path / "run.js"), str(tmp_path / "in.json"), str(tmp_path / "out.json")],
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert r.returncode == 0, r.stderr
    return json.loads((tmp_path / "out.json").read_text(encoding="utf-8"), object_pairs_hook=lambda kv: ("table", kv))


def _in_order(x):
    return json.loads(_text(x), object_pairs_hook=lambda kv: ("table", kv))


# what a page reads differently from Python whatever the map is written as: a number past what it can hold, a field
# named with a number (the page puts those first), a lone half of a character
SAME_IN_THE_PAGE = [n for n in ODD if n not in ("numbers, yes and no", "fields that are numbers")]


def test_the_page_turns_the_packed_map_back_into_the_same_rows(tmp_path):
    graphs = [PLAIN] + [ODD[n] for n in SAME_IN_THE_PAGE]
    graphs += [_through_a_file(engine.build_graph(FIXTURES / s).to_dict()) for s in ("shop", "phpapp", "nextapp")]
    got = _unpack_in_the_page([_through_a_file(columns.pack_graph(g)) for g in graphs], tmp_path)
    for graph, (_, pairs) in zip(graphs, got):
        answer = dict(pairs)
        assert "threw" not in answer, answer
        assert answer["ok"] == _in_order(graph)                           # the same rows, fields in the same order


def test_the_page_makes_a_row_of_its_own_for_every_link(tmp_path):
    graph = _graph([_node(1), _node(2)], [_edge(1, 2), _edge(1, 2)])
    (tmp_path / "x").mkdir()
    got = _unpack_in_the_page([_through_a_file(columns.pack_graph(graph)), graph], tmp_path / "x")
    assert dict(got[0][1])["ok"] == _in_order(graph) == dict(got[1][1])["ok"]      # a map that is not packed: as it is


def test_the_page_stops_at_a_packed_map_that_is_not_ours(tmp_path):
    names = [n for n in NOT_OURS if n != "a place that is not whole"]      # `1.0` in a file is the page's `1`
    got = _unpack_in_the_page([NOT_OURS[n] for n in names], tmp_path)
    for name, (_, pairs) in zip(names, got):
        assert "threw" in dict(pairs), name                               # no half-made map is drawn
