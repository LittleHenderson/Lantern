"""What changed, inside the app (`lantern serve`; roadmap of 2026-11-14, stage 2): the job that compares the last
commit with the files as they are now, the page that shows the receipt, and the terminal's `diff`.

The results folder of a project may come with the project, so the page is never the file on disk: it is built again
from the receipt's data, by Lantern's own template, with no script in it."""
import json
import urllib.error
import urllib.request

from pathlib import Path

import pytest
from test_commit_copy import commit
from test_diff import BASE, EXPORT_OPEN, changed, write
from test_server import call, srv, wait  # noqa: F401  (srv: the app on 127.0.0.1 with its token)

import lantern
from lantern.server import TERMINAL_HELP, TerminalRefused, run_terminal_command

ONLY_IN_SOURCE = "status_code=401"      # a piece of a line of the sample app that no result names


def get(base, path):
    req = urllib.request.Request(base + path, headers={"Cookie": "lantern_token=tok-123", "X-Lantern-Token": "tok-123"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8")


def project(base, repo) -> str:
    code, p = call(base, "/api/projects", "POST", {"path": str(repo)})
    assert code == 200, p
    return (p.get("project") or p)["id"]


def test_what_changed_compares_the_last_commit_with_the_files_as_they_are(srv, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    base, _ = srv
    repo = tmp_path / "notes"
    commit(repo, BASE)
    write(repo, changed(BASE, app=EXPORT_OPEN))                  # a change that is not committed yet
    pid = project(base, repo)
    assert get(base, f"/p/{pid}/change.html")[0] == 404          # nothing compared yet
    code, job = call(base, f"/api/projects/{pid}/change", "POST", {})
    assert code == 202 and job["kind"] == "change", job
    done = wait(base, job["id"], timeout=180)
    assert done["status"] == "done", done
    r = done["result"]
    assert r["compared"] is True and r["same"] is False and "1 new door" in r["line"], r
    assert r["counts"]["doors_added"] == 1 and "→" in r["release"]
    assert any(line.startswith("before  checking commit") for line in done["log"])
    code, headers, page = get(base, f"/p/{pid}/change.html")
    assert code == 200 and "POST /api/admin/export" in page and "<script" not in page
    rules = headers["Content-Security-Policy"]
    assert "default-src 'none'" in rules and "script-src" not in rules and "frame-ancestors 'self'" in rules
    # the comparison has a folder of its own: the project's results are as they were (it had none)
    assert sorted(p.name for p in (repo / ".lantern").iterdir()) == ["change"]
    for side in ("before", "after"):        # the two checks' own reports hold source, as the app's setting says
        assert ONLY_IN_SOURCE in (repo / ".lantern" / "change" / side / "report.html").read_text(encoding="utf-8")
    assert not call(base, "/api/state")[1]["projects"][0]["has_report"]
    # a version that is not there is said in a sentence, and what was compared before stays
    code, job = call(base, f"/api/projects/{pid}/change", "POST", {"range": "HEAD~3"})
    r = wait(base, job["id"], timeout=180)["result"]
    assert r["compared"] is False and "git did not find the commit 'HEAD~3' stands for" in r["why"]
    assert get(base, f"/p/{pid}/change.html")[0] == 200
    for odd in (5, ["HEAD"], "x" * 400, "HEAD\nx"):
        assert call(base, f"/api/projects/{pid}/change", "POST", {"range": odd})[0] == 400, odd


def test_the_persons_choice_to_keep_source_out_of_reports_holds_for_both_checks(srv, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    base, _ = srv
    repo = tmp_path / "notes"
    commit(repo, BASE)
    write(repo, changed(BASE, app=EXPORT_OPEN))
    pid = project(base, repo)
    code, said = call(base, "/api/settings", "POST", {"privacy": "structure"})
    assert code == 200 and said["settings"]["privacy"] == "structure", said
    code, job = call(base, f"/api/projects/{pid}/change", "POST", {})
    done = wait(base, job["id"], timeout=180)
    assert done["status"] == "done" and done["result"]["compared"] is True, done
    for side in ("before", "after"):
        report = (repo / ".lantern" / "change" / side / "report.html").read_text(encoding="utf-8")
        assert ONLY_IN_SOURCE not in report and "list_notes" in report, side
    assert "POST /api/admin/export" in get(base, f"/p/{pid}/change.html")[2]     # the receipt names routes, not source


def test_a_folder_that_is_no_repository_is_said_so(srv, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    base, _ = srv
    write(tmp_path / "plain", BASE)
    pid = project(base, tmp_path / "plain")
    code, job = call(base, f"/api/projects/{pid}/change", "POST", {})
    done = wait(base, job["id"], timeout=180)
    assert done["status"] == "done" and done["result"]["compared"] is False
    assert "is in no git repository Lantern reads" in done["result"]["why"]
    code, _, page = get(base, f"/p/{pid}/change.html")
    assert code == 404 and "No change was compared yet" in page


def test_the_page_is_built_from_the_data_and_never_the_file_that_lies_there(srv, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    base, _ = srv
    repo = tmp_path / "notes"
    commit(repo, BASE)
    write(repo, changed(BASE, app=EXPORT_OPEN))
    pid = project(base, repo)
    code, job = call(base, f"/api/projects/{pid}/change", "POST", {})
    assert wait(base, job["id"], timeout=180)["status"] == "done"
    where = repo / ".lantern" / "change"
    # what a project could bring along: a page of its own under the page's name, and data with markup in it
    (where / "change.html").write_text("<script>alert(1)</script>PLANTED", encoding="utf-8")
    data = (where / "change.json").read_text(encoding="utf-8")
    assert "POST /api/admin/export" in data
    (where / "change.json").write_text(data.replace("POST /api/admin/export", "<img src=x onerror=alert(1)>"),
                                       encoding="utf-8")
    code, _, page = get(base, f"/p/{pid}/change.html")
    assert code == 200 and "PLANTED" not in page and "<script" not in page
    assert "<img" not in page and "&lt;img src=x onerror=alert(1)&gt;" in page
    # data of another shape is no page, and no error either
    for odd in ('{"schema": 99}', "[1, 2]", "{", json.dumps({"schema": 1, "doors": 7})):
        (where / "change.json").write_text(odd, encoding="utf-8")
        code, _, page = get(base, f"/p/{pid}/change.html")
        assert code in (404, 409) and "PLANTED" not in page and "Traceback" not in page, (odd, code)


def test_the_terminal_takes_diff_with_the_two_versions_and_nothing_else(tmp_path):
    class Jobs:
        def start(self, pid, kind, fn, stop=None):
            return {"id": "j1", "kind": kind, "status": "running"}

    class Store:
        def settings(self):
            return {"privacy": "full"}

    class App:
        jobs = Jobs()
        store = Store()
    app, p, repo, out = App(), {"id": "x"}, tmp_path, tmp_path / ".lantern"
    for argv in (["diff"], ["lantern", "diff"], ["diff", "HEAD~1"], ["diff", "main..feature"], ["diff", "v1.2.0...HEAD"],
                 ["diff", "--offline"], ["diff", "main...", "--offline"]):
        assert run_terminal_command(app, p, repo, out, argv)["job"]["kind"] == "change", argv
    for argv in (["diff", "--out", "/tmp/elsewhere"], ["diff", "--base-results", "/etc"], ["diff", "a", "b"],
                 ["diff", "$(id)"], ["diff", "main; rm -rf /"], ["diff", "../other"], ["diff", "--format", "json"],
                 ["diff", "HEAD@{1}"], ["diff", "-x"]):
        with pytest.raises(TerminalRefused):
            run_terminal_command(app, p, repo, out, argv)


def test_the_page_has_one_button_for_it_and_the_words_about_a_refusal_are_the_servers():
    page = (Path(lantern.__file__).parent / "viewer" / "app.html").read_text(encoding="utf-8")
    assert page.count('id="whatchanged"') == 1                      # one button on a project's screen, no new tab
    assert "/change`, {method: 'POST', body: {}}" in page          # the last commit and the files as they are now
    assert "String(r.why" in page and "none(e.message)" in page    # why nothing was compared: said by the server
    assert "openIn(body.querySelector('iframe'), `/p/${p.id}/change.html`)" in page
    assert page.count(".sub #whatchanged span") == 2               # an icon where the screen is narrow, as its neighbour
    for text in (page, TERMINAL_HELP):
        assert "diff [BASE..HEAD] [--offline]" in text
