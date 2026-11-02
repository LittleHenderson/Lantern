"""Stack lanes (the stack strip): deterministic, from file path and entry kind only."""

from lantern import engine, lanes, security
from lantern.graph import Graph, Node


def _n(nid, file=None, entry=None):
    return Node(id=nid, kind="callable", name=nid.rsplit("::", 1)[-1], qualname=nid, file=file, entry=entry)


def test_lane_rules():
    servers = {"js:app/api/export/route"}
    assert lanes.lane_of(_n("py:shop.app.export"), servers) == "server"
    assert lanes.lane_of(_n("go:x/y::Handler"), servers) == "server"
    assert lanes.lane_of(_n("js:web/src/pages/Admin::Admin", "web/src/pages/Admin.tsx", {"kind": "page", "detail": "/admin"}), servers) == "browser"
    assert lanes.lane_of(_n("js:web/src/main", "web/src/main.tsx", {"kind": "main", "detail": "app start (web/src/main.tsx)"}), servers) == "browser"
    assert lanes.lane_of(_n("js:web/src/components/Bio::Bio", "web/src/components/Bio.tsx"), servers) == "frontend"
    assert lanes.lane_of(_n("js:app/api/export/route::POST", "app/api/export/route.ts"), servers) == "server"
    assert lanes.lane_of(_n("ext:subprocess.call"), servers) == "data"
    assert lanes.lane_of(_n("ext:sqlite3.connect().execute"), servers) == "data"
    assert lanes.lane_of(_n("ext:@prisma/client.PrismaClient().user.findMany"), servers) == "data"
    assert lanes.lane_of(_n("ext:fetch"), servers) == "data"
    assert lanes.lane_of(_n("ext:json.dumps"), servers) is None
    assert lanes.lane_of(_n("ext:HTTP GET /api/items"), servers) == "server"
    assert lanes.lane_of(_n("ext:HTTP GET api.stripe.com/v1/charges"), servers) == "data"


def test_server_modules_from_entries_and_paths():
    g = Graph("/r")
    g.add_node(_n("js:server/index", "server/index.ts"))
    g.add_node(_n("js:server/index::listUsers", "server/index.ts"))
    g.add_node(_n("js:src/api/users", "src/api/users.ts"))
    g.add_node(_n("js:src/api/users::handler", "src/api/users.ts", {"kind": "route", "detail": "GET /users"}))
    g.add_node(_n("js:src/api/users::helper", "src/api/users.ts"))
    g.add_node(_n("js:src/App::App", "src/App.tsx"))
    counts = lanes.assign(g)
    assert g.nodes["js:server/index::listUsers"].lane == "server"      # path rule
    assert g.nodes["js:src/api/users::helper"].lane == "server"        # sits beside a route handler
    assert g.nodes["js:src/App::App"].lane == "frontend"
    assert counts["server"] == 5 and counts["frontend"] == 1
    assert g.meta["lanes"] == counts


def test_lane_for_file_fallback():
    assert lanes.lane_for_file("settings.py") == "server"
    assert lanes.lane_for_file(".env") == "server"
    assert lanes.lane_for_file("src/pages/Admin.tsx") == "frontend"
    assert lanes.lane_for_file("pages/api/x.ts") == "server"
    assert lanes.lane_for_file("README.md") is None


def test_shop_findings_carry_hot_lane_and_lanes():
    g = engine.build_graph("tests/fixtures/shop")
    assert g.meta["lanes"]["browser"] >= 2 and g.meta["lanes"]["data"] >= 1
    sec = security.scan(g, offline=True)
    by_file = {}
    for f in sec["findings"]:
        assert f["hot_lane"] in lanes.LANES
        assert f["lanes"] == [l for l in lanes.LANES if l in set(f["lanes"])]   # fixed order, no repeats
        assert f["hot_lane"] in f["lanes"]
        by_file.setdefault(f["file"], []).append(f)
    shell = [f for f in by_file["shop/app.py"] if f["rank"] == "critical"][0]
    assert shell["hot_lane"] == "server"
    assert shell["lanes"] == ["browser", "frontend", "server", "data"]        # the Export path crosses the whole stack
    assert by_file["web/src/pages/Admin.tsx"][0]["hot_lane"] == "frontend"


def test_lane_survives_json_round_trip(tmp_path):
    g = engine.build_graph("tests/fixtures/shop")
    g.save(tmp_path / "g.json")
    g2 = Graph.load(tmp_path / "g.json")
    assert {n.lane for n in g2.nodes.values()} >= {"browser", "frontend", "server", "data"}


def test_evidence_rows_carry_the_glyph_escaped():
    from lantern import evidence
    g = engine.build_graph("tests/fixtures/shop")
    sec = security.scan(g, offline=True)
    f = next(x for x in sec["findings"] if x["rank"] == "critical" and x["file"] == "shop/app.py")
    f["hot_lane"] = "server<img src=x onerror=alert(1)>"     # a planted lane is ignored, never rendered
    html = evidence.render_html(evidence.build(g, sec, None, None, None, None))
    assert "<span class='glyph' title='Browser → Frontend → Server → Data'>" in html
    assert "On the <b>Server</b>" in html
    assert "onerror" not in html
