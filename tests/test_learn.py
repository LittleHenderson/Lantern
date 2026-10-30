"""Starter apps: every planted problem is found, every documented fix clears its step, and the templates never leak
into Lantern's own audit."""

import json
import shutil

import pytest
from test_server import call, srv, wait  # noqa: F401  (srv is a fixture)

from lantern import learn, pipeline
from lantern.cli import main
from lantern.security import load_accepted, save_accepted

CHECK_KINDS = {"analyzed", "cleared", "accepted_or_cleared", "deps_clean", "protection", "exists", "explained",
               "observed", "fixed"}
FINDING_STEPS = {"cleared", "accepted_or_cleared", "protection"}


def quiet(_line):
    pass


def test_catalog_is_well_formed():
    cat = learn.catalog()
    assert [s["id"] for s in cat] == ["notes-api", "todo-next", "recipe-box", "link-shortener"]
    for entry in cat:
        s = learn.get(entry["id"])
        files, fixes = learn.template_files(s["id"]), learn.template_files(s["id"], "solution")
        assert files and fixes
        assert len({st["id"] for st in s["steps"]}) == len(s["steps"])
        for st in s["steps"]:
            assert st["feature"] in learn.FEATURES, st
            assert not st.get("check") or st["check"]["kind"] in CHECK_KINDS, st
            for f in st.get("fix_files", []):
                assert f in fixes, f"{s['id']}: step {st['id']} points at {f}, which has no fixed version"
        for f in s.get("solution_delete", []):
            assert f in files


def test_templates_are_invisible_to_lanterns_own_audit():
    """Only .tmpl files: no .py/.ts/.json/.env/requirements file Lantern's scanners would pick up."""
    for p in learn.ROOT.rglob("*"):
        if p.is_file():
            assert p.suffix == ".tmpl" and not p.name.startswith("."), p


@pytest.mark.parametrize("sid", learn.ids())
def test_planted_problems_are_found_and_fixes_clear_them(sid, tmp_path):
    s = learn.get(sid)
    repo = tmp_path / sid
    learn.scaffold(sid, repo)
    out = pipeline.out_dir(repo)
    pipeline.analyze(repo, out, log=quiet, offline=True)
    before = {x["id"]: x for x in learn.progress(sid, repo)["steps"]}
    for st in s["steps"]:
        if st.get("check", {}).get("kind") in FINDING_STEPS:
            assert before[st["id"]]["status"] == "todo", (st["id"], before[st["id"]])
    assert before["analyze"]["status"] == "done" and before["evidence"]["status"] == "todo"

    # Apply every documented fix the way a learner would, then accept what the guide says to accept.
    for rel, src in learn.template_files(sid, "solution").items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, repo / rel)
    for rel in s.get("solution_delete", []):
        (repo / rel).unlink()
    pipeline.analyze(repo, out, log=quiet, offline=True)
    accept = [st["check"] for st in s["steps"] if st.get("check", {}).get("kind") == "accepted_or_cleared"]
    if accept:
        acc = load_accepted(repo)
        for f in json.loads((out / "security.json").read_text(encoding="utf-8"))["findings"]:
            if any(f["rule"] in c["rules"] and c.get("match", "") in f["title"] for c in accept):
                acc[f["id"]] = {"id": f["id"], "rule": f["rule"], "file": f["file"], "line": f["line"],
                                "title": f["title"], "reason": "Accepted on purpose, as the guide explains", "by": "test",
                                "date": "2026-10-30"}
        save_accepted(repo, acc)
        pipeline.analyze(repo, out, log=quiet, offline=True)

    after = {x["id"]: x for x in learn.progress(sid, repo)["steps"]}
    for st in s["steps"]:
        if st.get("check", {}).get("kind") in FINDING_STEPS | {"fixed"}:
            assert after[st["id"]]["status"] == "done", (st["id"], after[st["id"]])
    sec = json.loads((out / "security.json").read_text(encoding="utf-8"))
    assert not [f for f in sec["findings"] if not f["in_tests"] and f["status"] == "open"
                and f["rank"] in ("critical", "high", "medium")]


def test_scaffold_never_overwrites_and_marker_is_validated(tmp_path):
    d = tmp_path / "app"
    files = learn.scaffold("notes-api", d)
    assert "TUTORIAL.md" in files and (d / ".gitignore").exists() and (d / "app/main.py").exists()
    assert "## Step 4. Fix the critical one" in (d / "TUTORIAL.md").read_text(encoding="utf-8")
    assert learn.starter_of(d) == "notes-api"
    with pytest.raises(ValueError):
        learn.scaffold("notes-api", d)
    with pytest.raises(ValueError):
        learn.scaffold("../etc", tmp_path / "x")
    (d / learn.MARKER).write_text(json.dumps({"starter": "../../secret"}), encoding="utf-8")
    assert learn.starter_of(d) is None
    (d / learn.MARKER).write_text("not json", encoding="utf-8")
    assert learn.starter_of(d) is None


def test_progress_ignores_planted_results(tmp_path):
    d = tmp_path / "app"
    learn.scaffold("notes-api", d)
    out = d / ".lantern"
    out.mkdir()
    (out / "security.json").write_text(json.dumps({"findings": "<script>", "tools": 3}), encoding="utf-8")
    (out / "readiness.json").write_text("[1, 2]", encoding="utf-8")
    pr = learn.progress("notes-api", d)
    assert pr["steps"][0]["status"] == "done"
    assert pr["total"] + pr["explore"] == len(pr["steps"])   # the counter and the list agree
    assert all(isinstance(s["why"], str) and "<" not in s["why"] for s in pr["steps"])


def test_solution_text_stays_inside_the_templates():
    assert "hashlib.scrypt" in learn.solution_text("notes-api", "app/auth.py")
    assert learn.solution_text("notes-api", "../../cli.py") is None
    assert learn.solution_text("notes-api", "app/main.py") is None


def test_cli_learn(tmp_path, capsys, monkeypatch):
    assert main(["learn"]) == 0
    assert "link-shortener" in capsys.readouterr().out
    d = tmp_path / "notes"
    assert main(["learn", "notes-api", str(d), "--offline"]) == 0
    assert (d / ".lantern/baseline.json").exists()   # the "before" for the Evidence Report
    capsys.readouterr()
    assert main(["learn", "--check", str(d)]) == 0
    out = capsys.readouterr().out
    assert "[ ] 4. Fix the critical one" in out and "checked steps done" in out
    monkeypatch.chdir(d)
    assert main(["learn", "--show-fix", "app/db.py"]) == 0
    assert "AND text LIKE ?" in capsys.readouterr().out
    assert main(["learn", "notes-api", str(d)]) == 2


def test_server_learn_flow(srv, tmp_path):  # noqa: F811  (the fixture imported above)
    base, _store = srv
    st, d = call(base, "/api/starters")
    assert st == 200 and len(d["starters"]) == 4
    st, full = call(base, "/api/starters/recipe-box")
    assert st == 200 and full["steps"][2]["id"] == "eval"
    assert call(base, "/api/starters/nope")[0] == 404
    assert call(base, "/api/starters", "POST", {"id": "recipe-box"}, token="wrong")[0] == 403
    st, r = call(base, "/api/starters", "POST", {"id": "recipe-box", "parent": str(tmp_path / "learn")})
    assert st == 201 and r["project"]["starter"] == "recipe-box"
    assert wait(base, r["job"]["id"])["status"] == "done"
    pid = r["project"]["id"]
    st, pr = call(base, f"/api/projects/{pid}/learn")
    assert st == 200 and pr["steps"][2]["status"] == "todo"
    st, again = call(base, "/api/starters", "POST", {"id": "recipe-box", "parent": str(tmp_path / "learn")})
    assert again["project"]["path"].endswith("recipe-box-2")
    wait(base, again["job"]["id"])
    st, fix = call(base, "/api/starters/recipe-box/fix?file=web/src/pages/RecipePage.tsx")
    assert st == 200 and "eval" not in fix["text"]
    assert call(base, "/api/starters/recipe-box/fix?file=../../server.py")[0] == 404
    st, state = call(base, "/api/state")
    assert {p["starter"] for p in state["projects"]} == {"recipe-box"}
