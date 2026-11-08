"""Big projects still give a report a browser can open: built bundles are not mapped, long lines are cut."""

from pathlib import Path

from lantern import report
from lantern.graph import Graph, Node
from lantern.js_frontend import built_bundle, discover


def test_a_built_bundle_is_not_mapped_whatever_its_name(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text("export function load() {\n  return fetch('/api/items');\n}\n" * 2000,
                                             encoding="utf-8")
    one_line = "const a=" + ",".join(f"function(){{return {i}}}" for i in range(6000)) + ";\n"
    (tmp_path / "_tmp_playground_bundle.js").write_text(one_line * 3, encoding="utf-8")
    (tmp_path / "small.js").write_text("x" * 60_000, encoding="utf-8")          # one 60 KB line
    found = {p.name for p in discover(tmp_path)}
    assert "app.js" in found and "_tmp_playground_bundle.js" not in found
    assert built_bundle(tmp_path / "small.js") and not built_bundle(tmp_path / "src" / "app.js")


def test_the_report_cuts_very_long_lines_and_keeps_line_numbers(tmp_path: Path, monkeypatch):
    (tmp_path / "a.py").write_text("def f():\n    x = '" + "y" * 10_000 + "'\n    return x\n", encoding="utf-8")
    g = Graph(str(tmp_path))
    g.add_node(Node(id="py:a.f", kind="callable", name="f", qualname="a.f", file="a.py", start_line=1, end_line=3))
    g.add_node(Node(id="py:a.g", kind="callable", name="g", qualname="a.g", file="a.py", start_line=1, end_line=1))
    src = report.collect_sources(g)["py:a.f"]
    lines = src.split("\n")
    assert len(lines) == 3 and lines[2] == "    return x" and len(lines[1]) <= report.MAX_LINE_CHARS + 2
    monkeypatch.setattr(report, "MAX_TOTAL_CHARS", 10)
    assert list(report.collect_sources(g)) == ["py:a.f"]       # past the budget, later functions show no lines
