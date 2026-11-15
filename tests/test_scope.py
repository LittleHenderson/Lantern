"""Per-layer permissions (directive: user first, step 4): a report cut down to the layers one person may see. The
cut is made on the server, so nothing about a hidden layer reaches that person's browser; a call into a hidden
layer ends at a sealed node that says only that the layer is there."""

import itertools
import json
import shutil
import sys
from pathlib import Path

import pytest

from lantern import scope
from lantern.report import read_bundle
from lantern.server import result_page

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def shop(tmp_path_factory):
    """The shop fixture analyzed once: it has code in all four layers."""
    src = tmp_path_factory.mktemp("src") / "shop"
    shutil.copytree(ROOT / "tests" / "fixtures" / "shop", src)
    out = tmp_path_factory.mktemp("out")
    from lantern.cli import main
    argv = sys.argv
    sys.argv = ["lantern", "analyze", str(src), "--out", str(out), "--offline"]
    try:
        main()
    except SystemExit:
        pass
    finally:
        sys.argv = argv
    data = read_bundle(out / "report.html")
    assert {n.get("lane") for n in data["graph"]["nodes"]} >= set(scope.LANES)
    return out, data


def hidden_words(data, lanes):
    """Names only a hidden layer's own code has: its files, qualified names and ids (none a visible node uses)."""
    nodes = data["graph"]["nodes"]
    seen = {str(v) for n in nodes if n.get("lane") in lanes or n.get("lane") is None
            for v in (n.get("file"), n.get("qualname"), n.get("id"), n.get("name")) if v}
    # a library a hidden layer calls (sqlite3.connect) is no secret: visible code can call it by name too
    words = {str(v) for n in nodes if n.get("lane") not in lanes and n.get("lane") is not None and n["kind"] != "external"
             for v in (n.get("file"), n.get("qualname"), n.get("id")) if v}
    return {w for w in words if len(w) >= 6 and not any(w in s for s in seen)}


SUBSETS = [c for k in (1, 2, 3) for c in itertools.combinations(scope.LANES, k)]


@pytest.mark.parametrize("lanes", SUBSETS, ids=lambda c: scope.code(c))
def test_nothing_about_a_hidden_layer_is_left(shop, lanes):
    out, data = shop
    d = scope.scope_bundle(data, list(lanes))
    text = json.dumps(d)
    leaked = sorted(w for w in hidden_words(data, lanes) if w in text)
    assert leaked == [], leaked
    assert d["scope"]["lanes"] == list(lanes)
    for n in d["graph"]["nodes"]:
        assert n.get("lane") in lanes or n.get("lane") is None or n.get("sealed")
    ids = {n["id"] for n in d["graph"]["nodes"]}
    for e in d["graph"]["edges"]:
        assert e["src"] in ids and e["dst"] in ids
    # every finding kept is on a node they can see, and the counts are recounted from what is kept
    for f in d["security"].get("findings") or []:
        assert f["node"] in ids
    assert len(d["security"].get("findings") or []) <= len(data["security"].get("findings") or [])
    # the original bundle is untouched
    assert "scope" not in data


def test_a_call_into_a_hidden_layer_ends_at_a_sealed_node(shop):
    out, data = shop
    lane_of = {n["id"]: n.get("lane") for n in data["graph"]["nodes"]}
    crossing = [e for e in data["graph"]["edges"] if e["kind"] in scope.LINK_KINDS
                and lane_of.get(e["src"]) == "frontend" and lane_of.get(e["dst"]) not in ("frontend", None)]
    if not crossing:
        pytest.skip("the fixture has no call from the frontend into another layer")
    d = scope.scope_bundle(data, ["frontend"])
    sealed = {n["id"]: n for n in d["graph"]["nodes"] if n.get("sealed")}
    for e in crossing:
        sid = scope.sealed_id(lane_of[e["dst"]])
        assert sid in sealed and sealed[sid]["kind"] == "external" and sealed[sid]["file"] is None
        assert any(x["src"] == e["src"] and x["dst"] == sid for x in d["graph"]["edges"])
    assert all(n["name"].startswith("Something in the ") for n in sealed.values())


def test_every_layer_is_the_whole_report_and_bad_choices_are_refused(shop):
    out, data = shop
    assert scope.scope_bundle(data, None) is data
    assert scope.scope_bundle(data, list(scope.LANES)) is data
    assert scope.parse(["server", "browser"]) == ("browser", "server")
    for bad in ([], ["api"], "server", [1], {"server": 1}):
        with pytest.raises(ValueError):
            scope.parse(bad)
    assert scope.code(("browser", "server")) == "bs" and scope.decode("bs") == ("browser", "server")
    assert scope.decode("all") is None and scope.decode("bfsd") is None
    for bad in ("", "x", "bb", "all2"):
        with pytest.raises(ValueError):
            scope.decode(bad)


def test_the_page_is_built_from_the_cut_and_whole_app_files_are_refused(shop):
    out, data = shop
    words = hidden_words(data, ("frontend", "browser"))
    code, body, ctype, headers = result_page(out, "report.html", None, ("browser", "frontend"))
    assert code == 200 and "nonce-" in headers["Content-Security-Policy"]
    assert not [w for w in words if w in body]
    page = read_bundle_from(body)
    assert page["scope"]["lanes"] == ["browser", "frontend"]
    for name in ("evidence.html", "graph.json", "security.json"):
        if (out / name).exists() or name == "evidence.html":
            assert result_page(out, name, None, ("browser", "frontend"))[0] == 403
    assert result_page(out, "badge.svg", None, ("browser",))[0] == 200
    # with every layer, nothing changes
    assert result_page(out, "report.html", None, None)[0] == 200
    assert "scope" not in read_bundle_from(result_page(out, "report.html", None, None)[1])


def read_bundle_from(html: str) -> dict:
    import tempfile
    with tempfile.TemporaryDirectory() as t:
        p = Path(t) / "report.html"
        p.write_text(html, encoding="utf-8")
        return read_bundle(p)
