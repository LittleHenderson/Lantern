"""Results saved by an older Lantern open in this one (test checklist, "Upgrades").

tests/fixtures/old_results/<version>/ holds the JSON result files that Lantern v0.9.0 and v0.10.0 wrote for the shop
sample (graph, security, readiness, evidence, run, baseline; the HTML pages are rebuilt from these, never served as
stored). Everything that reads results must take them without a crash: the pages `lantern serve` and the cloud service
build (report, evidence, badge, JSON), the Projects screen's summary, Ask Lantern's facts, the SARIF export, the
connector's tools, the scenario and lane attachers, and `lantern verify` (which may say DIFFERENT, never fail to run).
"""
import json
import shutil
from pathlib import Path

import pytest

from lantern import ask, exporters, lanes, scenarios
from lantern.graph import Graph
from lantern.server import App, Store, result_page

OLD = Path(__file__).parent / "fixtures" / "old_results"
SHOP = Path(__file__).parent / "fixtures" / "shop"
VERSIONS = sorted(p.name for p in OLD.iterdir() if p.is_dir())


@pytest.fixture(params=VERSIONS)
def project(request, tmp_path):
    repo = tmp_path / "shop"
    shutil.copytree(SHOP, repo)
    shutil.copytree(OLD / request.param, repo / ".lantern")
    return repo


def test_pages_are_rebuilt_from_old_results(project):
    out = project / ".lantern"
    for name in ("report.html", "evidence.html", "badge.svg", "graph.json", "readiness.json", "security.json"):
        code, body, ctype, headers = result_page(out, name, None)
        assert code == 200, (name, code, body[:200])
        assert body and "Content-Security-Policy" in headers or name.endswith((".json", ".svg")), name
    code, body, _, _ = result_page(out, "report.html", None)
    assert "lantern-data" in body and "Traceback" not in body
    code, body, _, _ = result_page(out, "evidence.html", None)
    assert "Evidence Report" in body
    # `lantern report` (rebuild the pages from the stored data with this version's templates) works on them too
    from lantern.pipeline import rebuild_outputs
    rebuilt = rebuild_outputs(out, project)
    assert Path(rebuilt).exists()
    code, body, _, _ = result_page(out, "report.html", None)
    assert code == 200 and "lantern-data" in body


def test_the_projects_screen_and_ask_lantern_read_old_results(project, tmp_path, monkeypatch):
    monkeypatch.setenv("LANTERN_CONFIG_DIR", str(tmp_path / "cfg"))
    app = App(Store(tmp_path / "home"), "tok", 0)
    p = app.store.add_project(project)
    s = app.summary(p)
    assert s["grade"] in ("A", "B", "C", "D", "F") and isinstance(s.get("counts"), dict)
    facts = ask.facts(project)
    assert "Findings open:" in facts and "Readiness:" in facts and "Routes:" in facts


def test_exports_connector_and_attachers_take_old_results(project):
    out = project / ".lantern"
    sec = json.loads((out / "security.json").read_text(encoding="utf-8"))
    g = Graph.load(out / "graph.json")
    sarif = exporters.sarif(sec, project)
    assert sarif["runs"][0]["results"], "no findings exported"
    # fields that later versions added (scenario, lanes) are filled in from the facts, not required to be there
    scenarios.attach(sec["findings"], g)
    assert all(isinstance(f.get("scenario"), dict) for f in sec["findings"])
    lanes.assign(g)
    assert g.meta.get("lanes")
    from lantern.mcp_server import Projects, tool_findings, tool_readiness
    P = Projects(extra=[str(project)])
    fnd = tool_findings(P, {"project": str(project)})
    assert fnd["data"]["findings"] and fnd["data"]["cannot_close"] is True and fnd["text"]
    rd = tool_readiness(P, {"project": str(project)})
    assert rd["data"]["grade"] and rd["data"]["score"] is not None


def test_verify_runs_against_an_old_evidence_file(project):
    from lantern.evidence import verify
    old = json.loads((project / ".lantern" / "evidence.json").read_text(encoding="utf-8"))
    res = verify(project, old["digest"], old, offline=True)
    assert res["match"] in (True, False)        # the code and the tools moved on; what matters is that it runs and says so
    assert res["rerun"] and res["report"] == old["digest"]


def test_graph_round_trip_keeps_old_edges(project):
    g = Graph.load(project / ".lantern" / "graph.json")
    assert len(g.nodes) > 30 and len(g.edges) > 30
    (project / "again.json").write_text(json.dumps(g.to_dict()), encoding="utf-8")
    again = Graph.load(project / "again.json")
    assert set(again.nodes) == set(g.nodes) and len(again.edges) == len(g.edges)
