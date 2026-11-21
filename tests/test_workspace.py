"""Several projects read as one map (roadmap of 2026-11-14, stage 6, part 1: `lantern workspace`).

A web app and the API it calls often live in repositories of their own. Each dangerous shape (a link the map must not
make, a file a member must not bring in, a list of members a project must not plant) sits beside a safe twin that
must still work."""
import ast
import importlib
import json
import os
import pkgutil
import re
import subprocess
from pathlib import Path

import pytest

from lantern import evidence, remote, workspace
from lantern.cli import main
from lantern.engine import build_graph
from lantern.graph import POSSIBLE, RESOLVED
from links_here import PIPES, needs_links
from test_server import call, srv, wait  # noqa: F401  (srv is a fixture)


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


WEB = {
    "package.json": json.dumps({"name": "web", "dependencies": {"react": "18.3.1"}}),
    "src/api.ts": ("export async function listNotes() {\n"
                   "  const res = await fetch(\"/api/notes\")\n"
                   "  return res.json()\n"
                   "}\n"
                   "export async function removeNote(id: string) {\n"
                   "  return fetch(`/api/notes/${id}`, { method: \"DELETE\" })\n"
                   "}\n"),
}
API = {
    "main.py": ("from fastapi import FastAPI\n\n"
                "app = FastAPI()\n\n\n"
                "@app.get(\"/api/notes\")\n"
                "def list_notes():\n"
                "    return []\n\n\n"
                "@app.delete(\"/api/notes/{note_id}\")\n"
                "def remove_note(note_id: int):\n"
                "    return {\"ok\": True}\n"),
    "requirements.txt": "fastapi==0.115.0\n",
}
USERS_ONLY = {
    "main.py": ("from fastapi import FastAPI\n\n"
                "app = FastAPI()\n\n\n"
                "@app.get(\"/api/users\")\n"
                "def list_users():\n"
                "    return []\n"),
}


def _edge(g, src, dst):
    for e in g.edges:
        if e.src == src and e.dst == dst:
            return e
    return None


@pytest.fixture
def two(tmp_path):
    return _write(tmp_path / "src" / "web", WEB), _write(tmp_path / "src" / "api", API)


# ------------------------------------------------------------------------------------------- page to server, across


def test_a_page_of_one_project_is_linked_to_the_route_of_another(two):
    web, api = two
    # before: the web project alone sends its requests nowhere the map knows
    alone = build_graph(web)
    assert _edge(alone, "js:src/api::listNotes", "ext:HTTP GET /api/notes") is not None
    rec = workspace.make([str(web), str(api)], name="notes")
    assert [m["name"] for m in rec["members"]] == ["web", "api"]
    g = build_graph(workspace.folder_of("notes"))
    e = _edge(g, "js:web/src/api::listNotes", "py:api.main.list_notes")
    assert e is not None and e.via == "http-exact" and e.confidence == RESOLVED and e.detail == "GET /api/notes"
    d = _edge(g, "js:web/src/api::removeNote", "py:api.main.remove_note")
    assert d is not None and d.via == "http-exact" and d.confidence == RESOLVED
    ws = g.meta["workspace"]
    assert ws["name"] == "notes" and [m["name"] for m in ws["members"]] == ["web", "api"]
    assert ws["across"]["requests"] == 2 and ws["across"]["code"] == 0
    rows = {(r["from"], r["to"], r["call"], r["route"], r["via"], r["confidence"]) for r in ws["across"]["rows"]}
    assert ("web", "api", "GET /api/notes", "GET /api/notes", "http-exact", RESOLVED) in rows
    assert ("web", "api", "DELETE /api/notes/{}", "DELETE /api/notes/{note_id}", "http-exact", RESOLVED) in rows
    assert ws["shared"] == {"names": 0, "examples": []}


def test_projects_that_do_not_answer_each_other_stay_apart(tmp_path):
    web = _write(tmp_path / "src" / "web", WEB)
    users = _write(tmp_path / "src" / "users", USERS_ONLY)
    workspace.make([str(web), str(users)], name="apart")
    g = build_graph(workspace.folder_of("apart"))
    assert _edge(g, "js:web/src/api::listNotes", "ext:HTTP GET /api/notes") is not None
    assert not [e for e in g.edges if e.dst.startswith("py:users.") and e.src.startswith("js:")]
    assert g.meta["workspace"]["across"] == {"requests": 0, "code": 0, "rows": [], "more": 0}


def test_each_project_reads_inside_the_map_as_it_reads_alone(two, tmp_path):
    """Nothing inside a member changes because another member is beside it: its own links are the links of the
    member checked alone (in a folder of the same name, so the names on the map are the same)."""
    web, api = two
    workspace.make([str(web), str(api)], name="same")
    g = build_graph(workspace.folder_of("same"))
    for name, files in (("web", WEB), ("api", API)):
        solo = build_graph(_write(tmp_path / f"solo-{name}" / name, files).parent)
        assert _own_links(g, name) == _own_links(solo, name)


def _own_links(graph, name):
    return {(e.src, e.dst, e.via, e.confidence) for e in graph.edges
            if graph.nodes.get(e.src) and (graph.nodes[e.src].file or "").startswith(name + "/")
            and not (e.via or "").startswith("http-")}


# ------------------------------------------------------------------------------- what the map must not make up


JAVA_APP = ("package {pkg};\n"
            "public class App {{\n"
            "  public void run() {{ {call}(); }}\n"
            "  void {call}() {{}}\n"
            "}}\n")


def test_a_name_two_projects_share_is_not_trusted(tmp_path):
    """Two projects made from one template write the same package and class. Lantern reads a name once, so the map
    holds one node for two classes: every link that touches it is only possible, and the name is listed."""
    a = _write(tmp_path / "src" / "billing", {"src/main/java/com/example/demo/App.java":
                                              JAVA_APP.format(pkg="com.example.demo", call="helper")})
    b = _write(tmp_path / "src" / "shipping", {"src/main/java/com/example/demo/App.java":
                                               JAVA_APP.format(pkg="com.example.demo", call="other")})
    rec = workspace.make([str(a), str(b)], name="shared")
    assert "jv:com.example.demo.App.run" in rec["shared"] and "jv:com.example.demo.App" in rec["shared"]
    g = build_graph(workspace.folder_of("shared"))
    touching = [e for e in g.edges if e.src == "jv:com.example.demo.App.run" or e.dst == "jv:com.example.demo.App.run"]
    assert touching and all(e.confidence == POSSIBLE for e in touching)
    sh = g.meta["workspace"]["shared"]
    assert sh["names"] >= 2 and "com.example.demo.App.run (billing, shipping)" in sh["examples"]


def test_names_that_differ_are_trusted_as_before(tmp_path):
    a = _write(tmp_path / "src" / "billing", {"src/main/java/com/acme/billing/App.java":
                                              JAVA_APP.format(pkg="com.acme.billing", call="helper")})
    b = _write(tmp_path / "src" / "shipping", {"src/main/java/com/acme/shipping/App.java":
                                               JAVA_APP.format(pkg="com.acme.shipping", call="other")})
    rec = workspace.make([str(a), str(b)], name="apartnames")
    assert rec["shared"] == []
    g = build_graph(workspace.folder_of("apartnames"))
    e = _edge(g, "jv:com.acme.billing.App.run", "jv:com.acme.billing.App.helper")
    assert e is not None and e.confidence == RESOLVED
    assert g.meta["workspace"]["shared"] == {"names": 0, "examples": []}


def test_code_of_one_project_that_names_a_module_of_another_is_only_possible(tmp_path):
    """Alone, the API's `from textutil import clean` is a library. Beside a project that has a `textutil.py`, the map
    could take it for that file; whether the API installs that project is not read, so the link is only possible."""
    api = _write(tmp_path / "src" / "api", {"handlers.py": "from textutil import clean\n\n\ndef handle():\n"
                                                           "    return clean('x')\n"})
    kit = _write(tmp_path / "src" / "textkit", {"textutil.py": "def clean(s):\n    return s.strip()\n"})
    workspace.make([str(api), str(kit)], name="codelink")
    g = build_graph(workspace.folder_of("codelink"))
    e = _edge(g, "py:api.handlers.handle", "py:textkit.textutil.clean")
    assert e is not None and e.confidence == POSSIBLE
    across = g.meta["workspace"]["across"]
    assert across["code"] == 1 and across["requests"] == 0
    row = across["rows"][0]
    assert (row["from"], row["to"], row["kind"], row["confidence"]) == ("api", "textkit", "code", POSSIBLE)
    site = [s for s in g.sites if s["caller"] == "py:api.handlers.handle" and s["callee"] == "clean"]
    assert site and site[0]["outcome"] == "possible"


def test_code_that_stays_in_its_own_project_keeps_its_links(tmp_path):
    a = _write(tmp_path / "src" / "api", {"textutil.py": "def clean(s):\n    return s.strip()\n",
                                          "handlers.py": "from textutil import clean\n\n\ndef handle():\n"
                                                         "    return clean('x')\n"})
    b = _write(tmp_path / "src" / "tools", {"other.py": "def tidy(s):\n    return s\n"})
    workspace.make([str(a), str(b)], name="ownlink")
    g = build_graph(workspace.folder_of("ownlink"))
    e = _edge(g, "py:api.handlers.handle", "py:api.textutil.clean")
    assert e is not None and e.confidence == RESOLVED
    assert g.meta["workspace"]["across"]["code"] == 0


# ------------------------------------------------------------------------- only the person's command names members


def test_a_list_of_members_a_project_brings_is_never_read(two, tmp_path):
    web, api = two
    for name in ("lantern-workspace.json", "workspace.json", ".lantern-workspace.json"):
        (web / name).write_text(json.dumps({"kind": "lantern-workspace", "schema": 1, "name": "x",
                                            "members": [{"name": "api", "source": str(api)}]}), encoding="utf-8")
    g = build_graph(web)
    assert "workspace" not in g.meta
    assert _edge(g, "js:src/api::listNotes", "ext:HTTP GET /api/notes") is not None


def test_a_folder_among_the_workspaces_with_no_record_of_lantern_is_a_plain_project(tmp_path):
    folder = workspace.home() / "byhand"
    _write(folder / "web", WEB)
    _write(folder / "api", API)
    g = build_graph(folder)
    assert "workspace" not in g.meta


def test_a_folder_of_that_name_that_lantern_did_not_make_is_never_replaced(two, tmp_path):
    web, api = two
    kept = workspace.home() / "notes"
    _write(kept, {"mine/plan.txt": "my own file\n"})
    with pytest.raises(workspace.Refused, match="not a workspace"):
        workspace.make([str(web), str(api)], name="notes")
    assert (kept / "mine" / "plan.txt").read_text(encoding="utf-8") == "my own file\n"
    assert sorted(p.name for p in workspace.home().iterdir()) == ["notes"]     # nothing of the attempt is left
    # a file of the record's name that Lantern did not write is not replaced either
    (workspace.home() / "drafts.json").write_text("my notes\n", encoding="utf-8")
    with pytest.raises(workspace.Refused, match="not a workspace"):
        workspace.make([str(web), str(api)], name="drafts")
    assert (workspace.home() / "drafts.json").read_text(encoding="utf-8") == "my notes\n"
    # a record of Lantern's own beside a folder it did not make: the folder is neither replaced nor removed
    workspace.make([str(web), str(api)], name="mixed")
    folder = workspace.folder_of("mixed")
    workspace.remove("mixed")
    _write(folder, {"mine/plan.txt": "my own file\n"})
    (workspace.home() / "mixed.json").write_text(json.dumps(
        {"kind": "lantern-workspace", "schema": 1, "name": "mixed",
         "members": [{"name": "web", "source": str(web)}, {"name": "api", "source": str(api)}]}), encoding="utf-8")
    with pytest.raises(workspace.Refused, match="not a workspace"):
        workspace.make([str(web), str(api)], name="mixed")
    with pytest.raises(workspace.Refused, match="not a workspace"):
        workspace.remove("mixed")
    assert (folder / "mine" / "plan.txt").read_text(encoding="utf-8") == "my own file\n"
    # the twin: a workspace Lantern made is made again in its place, and removed
    first = workspace.make([str(web), str(api)], name="kept")
    (web / "src" / "more.ts").write_text("export const more = () => fetch(\"/api/notes\")\n", encoding="utf-8")
    again = workspace.make([str(web), str(api)], name="kept")
    assert again["made"] >= first["made"] and (workspace.folder_of("kept") / "web" / "src" / "more.ts").is_file()
    workspace.remove("kept")
    assert not os.path.lexists(workspace.folder_of("kept"))


@needs_links
def test_a_record_that_is_a_link_is_not_read(two, tmp_path):
    web, api = two
    workspace.make([str(web), str(api)], name="linked")
    rec = workspace.home() / "linked.json"
    planted = tmp_path / "planted.json"
    planted.write_text(rec.read_text(encoding="utf-8"), encoding="utf-8")
    rec.unlink()
    os.symlink(planted, rec)
    assert workspace.record_for(workspace.folder_of("linked")) is None
    assert "workspace" not in build_graph(workspace.folder_of("linked")).meta


# ---------------------------------------------------------------------------------------- what a copy brings in


@needs_links
def test_a_member_is_copied_without_what_leads_out_of_it(two, tmp_path):
    web, api = two
    outside = _write(tmp_path / "outside", {"secret.txt": "not the project's\n"})
    os.symlink(outside / "secret.txt", web / "src" / "leak.txt")
    os.symlink(outside, web / "src" / "folder-out")
    os.symlink("api.ts", web / "src" / "again.ts")
    if PIPES:                                                   # Windows has no pipe among its files
        os.mkfifo(web / "src" / "pipe")
    _write(web, {".git/config": "[core]\n", ".lantern/security.json": "{}", "node_modules/x/index.js": "x\n"})
    rec = workspace.make([str(web), str(api)], name="copied")
    there = workspace.folder_of("copied") / "web"
    assert (there / "src" / "api.ts").read_text(encoding="utf-8") == WEB["src/api.ts"]
    assert os.path.islink(there / "src" / "again.ts") and os.readlink(there / "src" / "again.ts") == "api.ts"
    for gone in ("src/leak.txt", "src/folder-out", "src/pipe", ".git", ".lantern", "node_modules"):
        assert not os.path.lexists(there / gone), gone
    left = rec["members"][0]["left_out"]
    assert left["link-out"] == 2 and left.get("kind", 0) == (1 if PIPES else 0) and left["folder"] == 3


def test_names_of_members(tmp_path):
    a = _write(tmp_path / "x" / "Web App!", WEB)
    b = _write(tmp_path / "y" / "web app", API)
    c = _write(tmp_path / "z" / "tests", USERS_ONLY)
    rec = workspace.make([str(a), str(b), f"users={c}"], name="names")
    assert [m["name"] for m in rec["members"]] == ["web-app", "web-app-2", "users"]
    # a name a reader gives a meaning of its own (test code, a folder every reader leaves out) is never a member's
    for bad in ("tests", "build", "vendor", "node_modules", ".hidden", "a/b", ""):
        with pytest.raises(workspace.Refused):
            workspace.make([f"{bad}={a}", str(b)], name="badname")
    # a member left unnamed whose folder has such a name gets a name of its own
    rec = workspace.make([str(c), str(b)], name="renamed")
    assert rec["members"][0]["name"] == "tests-project"


def test_what_a_workspace_cannot_be(two, tmp_path, monkeypatch):
    web, api = two
    with pytest.raises(workspace.Refused, match="two"):
        workspace.make([str(web)], name="one")
    with pytest.raises(workspace.Refused, match="twice"):
        workspace.make([str(web), str(web)], name="same")
    with pytest.raises(workspace.Refused, match="not a folder"):
        workspace.make([str(web), str(tmp_path / "nothing")], name="missing")
    for bad in ("../up", "a b", "", "x" * 80):
        with pytest.raises(workspace.Refused):
            workspace.make([str(web), str(api)], name=bad)
    # a member that holds the place the workspaces are kept would be copied into itself
    monkeypatch.setenv("LANTERN_HOME", str(web / "home"))
    with pytest.raises(workspace.Refused, match="holds"):
        workspace.make([str(web), str(api)], name="inside")


def test_a_repository_link_is_cloned_and_its_commit_recorded(tmp_path, monkeypatch):
    src = _write(tmp_path / "remote-api", API)
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com"]
    subprocess.run(git + ["init", "-q", str(src)], check=True)
    subprocess.run(git + ["add", "."], cwd=src, check=True)
    subprocess.run(git + ["commit", "-q", "-m", "one"], cwd=src, check=True)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=src, capture_output=True, text=True,
                            check=True).stdout.strip()
    asked = []

    def clone(link, log=None, dest=None, root=None):
        asked.append(link)
        dest = tmp_path / "clones" / "api"
        remote.fetch(src.as_uri(), dest)
        return dest

    monkeypatch.setattr(remote, "clone", clone)
    web = _write(tmp_path / "src" / "web", WEB)
    rec = workspace.make([str(web), "https://github.com/acme/api"], name="linked-api")
    assert asked == ["https://github.com/acme/api"]
    m = rec["members"][1]
    assert (m["name"], m["from"], m["source"], m["commit"]) == ("api", "link", "https://github.com/acme/api", commit)
    g = build_graph(workspace.folder_of("linked-api"))
    assert g.meta["workspace"]["across"]["requests"] == 2


# ---------------------------------------------------------------------------------- the command and the evidence


def test_the_command_makes_checks_lists_and_removes_a_workspace(two, tmp_path, capsys):
    web, api = two
    out = tmp_path / "out"
    assert main(["workspace", str(web), str(api), "--name", "notes", "--offline", "--out", str(out)]) == 0
    said = capsys.readouterr()
    assert "2 requests from one project answered by another" in said.out
    assert (out / "graph.json").is_file() and (out / "report.html").is_file()
    graph = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    assert graph["meta"]["workspace"]["across"]["requests"] == 2
    # checked again: the members are copied anew from where they came from
    (web / "src" / "more.ts").write_text("export const more = () => fetch(\"/api/notes\")\n", encoding="utf-8")
    assert main(["workspace", "--name", "notes", "--offline", "--out", str(out)]) == 0
    assert "3 requests from one project answered by another" in capsys.readouterr().out
    assert main(["workspace", "--list"]) == 0
    listed = capsys.readouterr().out
    assert "notes" in listed and "web" in listed and "api" in listed
    assert main(["workspace", "--remove", "notes"]) == 0
    assert not workspace.folder_of("notes").exists() and not (workspace.home() / "notes.json").exists()
    assert main(["workspace", "--name", "notes", "--offline"]) == 2


def test_the_app_makes_a_workspace_in_a_job_and_checks_it(two, srv):  # noqa: F811
    """The app's way to the same command: several folders or links in one request. The workspace is listed at once
    under the name it will have, made and checked in a job; what cannot be one is refused before anything is listed."""
    base, store = srv
    web, api = two
    code, r = call(base, "/api/projects", "POST", {"paths": [str(web), str(api)]})
    assert code == 202 and r["job"]["kind"] == "workspace" and r["project"]["name"] == "web-api"
    assert Path(r["project"]["path"]) == workspace.folder_of("web-api").resolve()
    j = wait(base, r["job"]["id"], timeout=120)
    assert j["status"] == "done", j
    assert [m["name"] for m in workspace.record_for(workspace.folder_of("web-api"))["members"]] == ["web", "api"]
    _, st = call(base, "/api/state")
    p = next(x for x in st["projects"] if x["id"] == r["project"]["id"])
    assert p["has_report"]
    graph = json.loads((workspace.folder_of("web-api") / ".lantern" / "graph.json").read_text(encoding="utf-8"))
    assert graph["meta"]["workspace"]["across"]["requests"] == 2
    listed = len(store.projects())
    # refused before anything is listed: one project, a name that cannot be one, a member under a name a reader reads
    (workspace.home() / "kept").mkdir(parents=True)
    (workspace.home() / "kept" / "notes.txt").write_text("mine\n", encoding="utf-8")
    for bad in ({"paths": [str(web)]}, {"paths": [str(web), str(api)], "name": "Not A Name"},
                {"paths": [f"tests={web}", str(api)]}, {"paths": [str(web), str(api)], "name": "kept"},
                {"paths": [str(web), 7]}, {"paths": "not a list"}):
        code, r = call(base, "/api/projects", "POST", bad)
        assert code == 400 and r.get("error"), (bad, r)
    assert len(store.projects()) == listed
    assert (workspace.home() / "kept" / "notes.txt").read_text(encoding="utf-8") == "mine\n"
    # one folder is still one project, as before
    code, r = call(base, "/api/projects", "POST", {"path": str(web)})
    assert code == 200 and r["path"] == str(web.resolve())


def test_the_evidence_names_each_member_and_its_commit(two, tmp_path):
    web, api = two
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com"]
    subprocess.run(git + ["init", "-q", str(api)], check=True)
    subprocess.run(git + ["add", "."], cwd=api, check=True)
    subprocess.run(git + ["commit", "-q", "-m", "one"], cwd=api, check=True)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=api, capture_output=True, text=True,
                            check=True).stdout.strip()
    workspace.make([str(web), str(api)], name="proof")
    out = tmp_path / "out"
    assert main(["analyze", str(workspace.folder_of("proof")), "--offline", "--out", str(out)]) == 0
    ev = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    rows = {m["name"]: m for m in ev["provenance"]["workspace"]["members"]}
    assert rows["api"]["commit"] == commit and rows["web"]["commit"] is None
    assert ev["payload"]["workspace"] == {"members": ["web:", f"api:{commit}"], "shared": 0}
    page = (out / "evidence.html").read_text(encoding="utf-8")
    assert "Projects in this map" in page and commit[:12] in page
    # a project of its own has no such part, so its digest is what it was
    plain = tmp_path / "plain"
    assert main(["analyze", str(web), "--offline", "--out", str(plain)]) == 0
    ev = json.loads((plain / "evidence.json").read_text(encoding="utf-8"))
    assert "workspace" not in ev["payload"] and "workspace" not in ev["provenance"]


def test_a_workspace_is_verified_like_any_project(two, tmp_path):
    web, api = two
    workspace.make([str(web), str(api)], name="again")
    out = tmp_path / "out"
    folder = workspace.folder_of("again")
    assert main(["analyze", str(folder), "--offline", "--out", str(out)]) == 0
    want, old = evidence.read_digest(out / "evidence.json")
    r = evidence.verify(folder, want, old, offline=True, beside=out)
    assert r["match"], r.get("differs")


# ------------------------------------------------------------- a member reads as it reads alone, address included
# Found while checking where Lantern's readers reckon a project's top (2026-11-17): the address of a plain PHP page
# is its path from the top of the project
# (below a web root such as public/ where there is one). In a workspace the member's folder was part of that path,
# so a page that answers at /admin/delete.php alone answered at /legacy/admin/delete.php in the map.

LEGACY = {"index.php": "<?php\necho 'Notes';\n",
          "admin/delete.php": "<?php\n$id = $_GET['id'];\n$db->query(\"DELETE FROM notes WHERE id = \" . $id);\n"}


def test_a_page_answers_at_the_address_it_has_alone(tmp_path):
    legacy = _write(tmp_path / "src" / "legacy", LEGACY)
    site = _write(tmp_path / "src" / "site", {"package.json": json.dumps({"name": "site"}),
                                              "src/admin.ts": "export const drop = (id: string) =>\n"
                                                              "  fetch(`/admin/delete.php?id=${id}`)\n"})
    alone = {n.entry["detail"] for n in build_graph(legacy).entry_points()}
    assert "ANY /admin/delete.php" in alone
    workspace.make([str(legacy), str(site)], name="pages")
    g = build_graph(workspace.folder_of("pages"))
    inside = {n.entry["detail"] for n in g.entry_points() if (n.file or "").startswith("legacy/")}
    assert inside == alone
    e = _edge(g, "js:site/src/admin::drop", "php:legacy/admin/delete.php")
    assert e is not None and e.via == "http-exact" and e.confidence == RESOLVED


def test_a_page_under_a_web_root_answers_below_it_as_before(tmp_path):
    shop = _write(tmp_path / "src" / "shop", {"public/" + k: v for k, v in LEGACY.items()})
    alone = {n.entry["detail"] for n in build_graph(shop).entry_points()}
    assert "ANY /admin/delete.php" in alone
    other = _write(tmp_path / "src" / "other", {"main.py": "def f():\n    return 1\n"})
    workspace.make([str(shop), str(other)], name="webroot")
    g = build_graph(workspace.folder_of("webroot"))
    assert {n.entry["detail"] for n in g.entry_points() if (n.file or "").startswith("shop/")} == alone


# ------------------------------------------------------- rules about a project's own folders, inside a workspace

KIT = {"package.json": json.dumps({"devDependencies": {"@sveltejs/kit": "2.5.0", "svelte": "5.0.0"}}),
       "svelte.config.js": 'import adapter from "@sveltejs/adapter-auto";\nexport default { kit: { adapter: adapter() } };\n',
       "src/routes/+page.svelte": "<h1>Home</h1>\n",
       "src/routes/api/run/+server.ts": 'import { runJob } from "$lib/server/jobs";\n'
                                       "export const POST = async (event) => runJob(event);\n",
       "src/lib/server/jobs.ts": 'import { exec } from "child_process";\n'
                                 'export function runJob(event) {\n  exec(event.url.searchParams.get("cmd"));\n}\n'}
TOOL = {"package.json": json.dumps({"dependencies": {"express": "4.19.2"}}),
        "src/jobs.js": 'const { exec } = require("child_process");\n'
                       "function runJob(event) {\n  exec(event.cmd);\n}\nmodule.exports = { runJob };\n"}


def _shell(g, top):
    from lantern.security import scan
    return sorted(f["file"] for f in scan(g, offline=True)["findings"]
                  if f["rule"] == "LT-SHELL" and (f.get("file") or "").startswith(top))


def test_a_project_called_server_beside_a_sveltekit_project_reads_as_alone(tmp_path):
    """A SvelteKit project's rule for its helpers in a `server/` folder (`flow_rules.KIT_SERVER_FILE`) gives the name
    `server` a meaning; the name is left usable (`LEFT_USABLE`), and this is the reading it must keep: a project of a
    workspace called `server` is read as when it is alone, and the SvelteKit project's own server folder as before."""
    web, tool = _write(tmp_path / "src" / "web", KIT), _write(tmp_path / "src" / "server", TOOL)
    assert _shell(build_graph(tool), "") == []                        # alone: `event` is nobody's request
    workspace.make([f"web={web}", f"server={tool}"], name="kit")
    g = build_graph(workspace.folder_of("kit"))
    assert _shell(g, "server/") == []
    # the twin: the SvelteKit project's own server folder is still read as handed the request
    assert _shell(g, "web/") == ["web/src/lib/server/jobs.ts"]


# ----------------------------------------------------------------------------------- the names a member never has

LANTERN = Path(workspace.__file__).parent
# `(^|/)`, `(?:^|/)`, `(^|[/\\])`, `(/|^)`: a pattern about a whole folder's name
ANCHOR = re.compile(r"\((?:\?:)?(?:\^\|(?:/|\[/\\\\\])|(?:/|\[/\\\\\])\|\^)\)")
RE_CALLS = {"compile", "search", "match", "fullmatch", "sub", "subn", "findall", "finditer", "split"}
FLAGS = {"I": re.I, "IGNORECASE": re.I, "M": re.M, "MULTILINE": re.M, "S": re.S, "DOTALL": re.S, "X": re.X,
         "VERBOSE": re.X, "A": re.A, "ASCII": re.A}
NEUTRAL = "q9z8"
# what a rule may be asked about below a folder: files of every kind a reader or a rule looks at
ENDS = ("x", "x.py", "x.js", "x.ts", "x.tsx", "x.jsx", "x.mjs", "x.vue", "x.svelte", "x.php", "x.go", "x.dart", "x.rb",
        "x.rake", "x.erb", "x.java", "x.kt", "x.swift", "x.cs", "x.cshtml", "x.cpp", "x.c", "x.h", "x.rs", "x.html",
        "x.sql", "x.json", "x.yml", "x.toml", "x.xml", "x.gradle", "x.md", "x.txt", "x.ipynb", ".env", "a/x.ts",
        "a/b/x.py", "package.json", "AndroidManifest.xml", "Info.plist", "pubspec.yaml", "Cargo.toml", "main.go",
        "index.php", "page.tsx", "route.ts", "+page.server.ts", "x.server.ts", "middleware.ts", "schema.rb")
# Rules about a folder's name whose names a member may still have, each with the reason
LEFT_USABLE = {
    ("lanes", "netlify/"): "where a file is drawn (a folder called api or server in the server's lane): a member's "
                           "name says of its files what such a folder says in one repository",
    ("protections", "magic-link"): "a route's address, not a file's place",
    ("protections", "lambda)/"): "whether a protection card counts a file's requests as the browser's; the cards "
                                 "never change a finding or the score",
    ("flow_rules", "(^|/)server/"): "a SvelteKit project's helpers in a server folder: read as alone, "
                                    "test_a_project_called_server_beside_a_sveltekit_project_reads_as_alone",
}
# Lantern's own lists of folder names a reader or a rule reads by name: left out, a Python environment judged by what
# it holds, the folder a hosting file's headers are published from, left out of an agent's copy
NAME_SETS = (("python_frontend", "SKIP_DIRS"), ("python_frontend", "ENV_NAMES"), ("java_frontend", "SKIP_JAVA_DIRS"),
             ("dart_frontend", "SKIP_DART"), ("swift_frontend", "SKIP_SWIFT"), ("headers", "PUBLISHED"),
             ("agents", "COPY_ALSO_SKIPS"), ("workspace", "NOT_COPIED"))
# The names the 15 sample projects read differently under, by bench/workspace.py's way of comparing (2026-11-17,
# 66 everyday names tried; the 39 others read the same)
FOUND_BY_TRIAL = ("test", "tests", "spec", "e2e", "example", "sample", "mocks", "docs", "lib", "app", "src", "config",
                  "templates", "views", "routes", "pages", "database", "migrations", "scripts", "tools", "packages",
                  "bin", "out", "target", "build", "dist", "vendor")
EVERYDAY = ("web", "api", "server", "client", "frontend", "backend", "mobile", "admin", "worker", "site", "shared",
            "common", "core", "ios", "android", "notes", "payments", "auth", "data", "web-app", "mobile-app",
            "api-service")


def _flags(call) -> int:
    f = 0
    for a in ast.walk(ast.Module(body=[ast.Expr(x) for x in call.args[1:] + [k.value for k in call.keywords]],
                                 type_ignores=[])):
        if isinstance(a, ast.Attribute) and isinstance(a.value, ast.Name) and a.value.id == "re" and a.attr in FLAGS:
            f |= FLAGS[a.attr]
    return f


def _folder_rules() -> dict[tuple[str, str, int], re.Pattern]:
    """Every pattern of Lantern's own about a whole folder's name: written in a call of `re` anywhere in the package
    (read from its source, with the call's flags), or kept at a module's top however it was put together."""
    out = {}
    for f in sorted(LANTERN.glob("*.py")):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in RE_CALLS
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "re" and node.args
                    and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
                    and ANCHOR.search(node.args[0].value)):
                flags = _flags(node)
                out[(f.stem, node.args[0].value, flags)] = re.compile(node.args[0].value, flags)
    import lantern
    for m in pkgutil.iter_modules(lantern.__path__):
        for v in vars(importlib.import_module(f"lantern.{m.name}")).values():
            if isinstance(v, re.Pattern) and isinstance(v.pattern, str) and ANCHOR.search(v.pattern):
                out[(m.name, v.pattern, v.flags & ~re.U)] = v
    return out


def _words(text: str) -> set[str]:
    out = set()
    for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9_-]*", text):
        for x in {w.lower(), w.lower()[:-1] if w.lower().endswith("s") else w.lower(), w.lower() + "s"}:
            if workspace.NAME.fullmatch(x):
                out.add(x)
    return out


def _given_a_meaning() -> tuple[dict[str, set], set[str]]:
    """The names Lantern's folder rules give a meaning (`{name: rules}`), found by asking each rule about a file under
    that name and under a name no rule knows: every word of the rules, the same word with something before or after
    it (a rule may read a part of a folder's name), and the name Lantern makes in place of each refused one; and the
    beginnings of names they give one (`cmake-build-…`)."""
    rules = {k: p for k, p in _folder_rules().items()
             if not any(k[0] == mod and part in k[1] for (mod, part) in LEFT_USABLE)}
    words = set(FOUND_BY_TRIAL) | set(EVERYDAY)
    for (_, text, _) in rules:
        words |= _words(text)
    shapes = set(words)
    for w in words:
        shapes |= {x for x in (f"q9-{w}", f"{w}-q9", f"q9{w}", f"{w}q9", workspace._made_name(w))
                   if workspace.NAME.fullmatch(x)}
    neutral = {(k, e): bool(p.search(f"{NEUTRAL}/{e}")) for k, p in rules.items() for e in ENDS}
    names: dict[str, set] = {}
    for w in sorted(shapes):
        for k, p in rules.items():
            if any(bool(p.search(f"{w}/{e}")) != neutral[k, e] for e in ENDS):
                names.setdefault(w, set()).add(f"{k[0]}: {k[1][:60]}")
    starts = {w for w in words if w.endswith("-") and any(
        any(bool(p.search(f"{w}zz9/{e}")) != neutral[k, e] for e in ENDS) for k, p in rules.items())}
    for mod, attr in NAME_SETS:
        for x in getattr(importlib.import_module(f"lantern.{mod}"), attr):
            if workspace.NAME.fullmatch(x):
                names.setdefault(x, set()).add(f"{mod}.{attr}")
    return names, starts


def test_no_project_is_given_a_name_a_folder_rule_of_lantern_gives_a_meaning():
    """A member's name is the folder its copy is in, so a name that a rule of Lantern's own reads as a folder of tests,
    of examples, of built files, one a reader leaves out, a web root or a folder of templates would change what is read
    of the project (as for 27 of 66 names on the samples). The names are found from the rules themselves: a new rule
    about a folder's name fails this test until its names are refused or it is said why they need not be."""
    names, starts = _given_a_meaning()
    assert len(_folder_rules()) > 60
    missing = {n: sorted(r)[:2] for n, r in names.items() if workspace._usable(n)}
    assert not missing, f"names a folder rule gives a meaning, still usable: {missing}"
    assert starts == {"cmake-build-", "bazel-"} and all(not workspace._usable(s + "x") for s in starts)
    # the rules are not the only way a folder's name is read: the trial on the samples found these, all refused too
    assert not [n for n in FOUND_BY_TRIAL if workspace._usable(n)]
    # and everyday names stay usable: the rules give none of them a meaning that changes what is read
    assert [n for n in EVERYDAY if not workspace._usable(n)] == []
    assert {"test", "build", "vendor", "docs", "app", "src", "env", "www"} <= set(names)
    # every name Lantern makes in place of a refused one can be used and means nothing to a rule
    made = {n: workspace._made_name(n) for n in names}
    assert all(workspace._usable(m) and m not in names for m in made.values()), made
    assert made["docs"] == "docs-project"
    assert workspace._made_name("cmake-build-debug") == "project-cmake-build-debug-project"


def test_what_is_never_copied_is_left_out_by_every_reader_too():
    """A folder that is not copied must be one no reader reads, or the copy would read less than the project."""
    from lantern.python_frontend import SKIP_DIRS
    assert workspace.NOT_COPIED <= SKIP_DIRS
