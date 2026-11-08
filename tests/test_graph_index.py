"""The callees/callers/nodes_in indexes give the same answers as a full scan, also after more edges are added."""

from lantern.graph import CALLS, CONTAINS, MAY_CALL, Graph, Node


def _scan(g, nid, side):
    return [e for e in g.call_edges() if getattr(e, side) == nid]


def test_indexes_match_a_full_scan_and_follow_new_edges():
    g = Graph("/r")
    for i in range(6):
        g.add_node(Node(id=f"n{i}", kind="callable", name=f"n{i}", qualname=f"n{i}", file=f"f{i % 2}.py",
                        start_line=i, end_line=i + 1))
    g.add_edge("n0", "n1")
    g.add_edge("n0", "n2", kind=MAY_CALL)
    g.add_edge("n0", "n3", kind=CONTAINS)
    for n in g.nodes:
        assert g.callees(n) == _scan(g, n, "src") and g.callers(n) == _scan(g, n, "dst")
    g.add_edge("n4", "n1", kind=CALLS)
    g.add_edge("n0", "n1", line=7)          # same edge again: no new entry, the line is kept
    assert [e.src for e in g.callers("n1")] == ["n0", "n4"]
    assert g.callees("n0")[0].lines == [7]
    g.callees("n0").clear()                 # a caller changing the list leaves the graph alone
    assert len(g.callees("n0")) == 2
    assert [n.id for n in g.nodes_in("f0.py")] == ["n0", "n2", "n4"]
    g.add_node(Node(id="n9", kind="callable", name="n9", qualname="n9", file="f0.py"))
    assert [n.id for n in g.nodes_in("f0.py")][-1] == "n9"
    assert g.nodes_in("missing.py") == []
