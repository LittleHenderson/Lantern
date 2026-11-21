"""A check before each push (`lantern hook install`, `lantern diff --require not-blocked`; roadmap of 2026-11-14,
stage 6, part 2).

What a push sends is compared with what the other side already has, by the same two checks as `lantern diff`, and
the push is stopped when the change itself brings what blocks a release: a critical or high finding that is new,
that a page or route reaches only now, that is ranked critical or high only now or that is open again (a secret
written into a file is one), and a request the page still makes that a route answered before and none answers now.
Each stands beside a twin that looks alike and is none: a harmless change; the risky helper called by something no
door reaches; page and server renamed together; a project that was blocked before the change, for what was there
already, and stays so; a key's place kept by filler. The hook is the person's: Lantern writes one only where none
is, never replaces or removes one it did not write, and says so where git would never run it.
"""
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
from links_here import needs_links
from test_commit_copy import WHEN, commit, git
from test_diff import BACKUP, BACKUP_NIGHTLY, BACKUP_ROUTE, BASE, SHELL_LINE, SHELL_LINE_SAID, Checks, changed

from lantern import cli, diff, hook


@pytest.fixture(scope="module")
def checks(tmp_path_factory):
    return Checks(tmp_path_factory.mktemp("hook"))


def kinds(rows) -> list[tuple]:
    return [(r["kind"], r.get("part"), (r.get("finding") or r.get("link") or {}).get("file")) for r in rows]


# ------------------------------------------------------------------------------- what in a change blocks a release
def test_a_new_serious_finding_blocks_the_change(checks):
    pytest.importorskip("bandit")
    r = checks.receipt(BASE, changed(changed(BASE, store=BACKUP), app=BACKUP_ROUTE))
    rows = diff.blockers(r)
    assert ("finding", "new", "api/store.py") in kinds(rows), rows
    shell = [x for x in rows if x["kind"] == "finding" and x["finding"]["rule"] == "B602"]
    assert shell and shell[0]["finding"]["rank"] == "critical"
    assert "new critical finding B602 at api/store.py:" in shell[0]["words"]


def test_a_finding_a_door_reaches_only_now_blocks_although_the_project_was_blocked_before(checks):
    pytest.importorskip("bandit")
    base = changed(BASE, store=BACKUP)          # the helper was there, no door reached it
    r = checks.receipt(base, changed(base, app=BACKUP_ROUTE))
    assert r["release"]["before"]["decision"] == "Blocked"
    rows = diff.blockers(r)
    assert ("finding", "now_reached", "api/store.py") in kinds(rows), rows
    assert all(x["part"] != "new" for x in rows if x["kind"] == "finding")
    reached = [x for x in rows if x["part"] == "now_reached"]
    assert "reached by POST /api/backup only now" in reached[0]["words"]


def test_a_project_blocked_before_whose_change_adds_nothing_serious_is_not_blocked_by_it(checks):
    """The twin: the project is Blocked before and after, for a finding that was there before; the change itself (a
    harmless helper) brings nothing that blocks."""
    pytest.importorskip("bandit")
    base = changed(changed(BASE, store=BACKUP), app=BACKUP_ROUTE)
    r = checks.receipt(base, changed(base, store="\n\ndef shout(text):\n    return text.upper()\n"))
    assert r["release"]["before"]["decision"] == "Blocked" and r["release"]["after"]["decision"] == "Blocked"
    assert r["release"]["after"]["counts"]["critical"] and r["findings"]["new"] == [] and diff.blockers(r) == []


def test_the_same_helper_called_by_something_no_door_reaches_does_not_block(checks):
    pytest.importorskip("bandit")
    base = changed(BASE, store=BACKUP)
    r = checks.receipt(base, changed(base, store=BACKUP_NIGHTLY))
    assert r["findings"]["now_reached"] == [] and diff.blockers(r) == []


def test_a_serious_finding_accepted_in_the_change_with_a_written_reason_does_not_block(checks):
    """A finding the change accepts with a person's written reason (here a `# nosec` comment on a line no request
    data reaches) is the person's decision, listed as accepted in the change, and does not stop the push. The twin:
    the same line without the comment is a new serious finding, and blocks."""
    pytest.importorskip("bandit")
    risky = changed(BASE, store=BACKUP)                # a shell command that no caller is known to reach: high
    r = checks.receipt(BASE, risky)
    assert [(x["part"], x["finding"]["rule"]) for x in diff.blockers(r) if x["kind"] == "finding"] == [("new", "B602")]
    r = checks.receipt(BASE, changed(risky, store=(SHELL_LINE, SHELL_LINE_SAID)))
    assert [f["rule"] for f in r["findings"]["accepted"]] == ["B602"]
    assert not any(x["kind"] == "finding" and x["finding"]["rule"] == "B602" for x in diff.blockers(r)), diff.blockers(r)


def test_a_request_the_page_still_makes_that_no_route_answers_now_blocks(checks):
    r = checks.receipt(BASE, changed(BASE, app=('@app.delete("/api/notes/{note_id}")',
                                                '@app.delete("/api/note/{note_id}")')))
    rows = diff.blockers(r)
    assert kinds(rows) == [("link", None, "web/src/api.js")], rows
    assert rows[0]["words"].startswith("a request the page still makes that no route answers now: DELETE /api/notes/{}")


def test_page_and_server_renamed_together_do_not_block(checks):
    r = checks.receipt(BASE, changed(BASE, app=('@app.delete("/api/notes/{note_id}")', '@app.delete("/api/note/{note_id}")'),
                                     api=("fetch(`/api/notes/${id}`", "fetch(`/api/note/${id}`")))
    assert diff.blockers(r) == []


def test_a_new_request_no_route_of_this_project_answers_does_not_block(checks):
    """The server that answers it may be another project (`lantern workspace`): named in the receipt, not a stop."""
    more = '\nexport async function pinNote(id) {\n  await fetch(`/api/notes/${id}/pin`, { method: "POST" });\n}\n'
    r = checks.receipt(BASE, changed(BASE, api=more))
    assert r["links"]["unanswered"] and diff.blockers(r) == []


def key_line(filler: bool) -> str:
    # built here, never written out in this file: a key-shaped text in a file of the repository is refused by GitHub
    tail = "x" * 24 if filler else "".join("Qz7Kp2Lm9Wd4Rt6Yh8Vb3Nc5"[i] for i in range(24))
    return 'export const PAYMENTS = "' + "sk_" + "live_" + tail + '";\n'


def test_a_secret_written_into_a_file_blocks_and_a_place_kept_by_filler_does_not(checks):
    leak = dict(BASE, **{"web/src/keys.js": key_line(filler=False)})
    rows = diff.blockers(checks.receipt(BASE, leak))
    secret = [x for x in rows if x["kind"] == "finding" and x["finding"]["file"] == "web/src/keys.js"]
    assert secret and secret[0]["words"].startswith("a secret written into a file: new"), rows
    filler = dict(BASE, **{"web/src/keys.js": key_line(filler=True)})
    assert diff.blockers(checks.receipt(BASE, filler)) == []


def test_a_change_of_comments_and_spacing_does_not_block(checks):
    head = changed(BASE, app=("def list_notes(user=Depends(current_user)):\n",
                              "def list_notes(user = Depends(current_user)):  # everything this user wrote\n"))
    assert diff.blockers(checks.receipt(BASE, head)) == []


# ------------------------------------------------------------------------------- lantern diff --require not-blocked
def two_commits(tmp_path: Path, head_files: dict) -> tuple[Path, str, str]:
    repo = tmp_path / "notes"
    a = commit(repo, BASE, "base")
    for rel in [r for r in BASE if r not in head_files]:
        (repo / rel).unlink()
    b = commit(repo, head_files, "change")
    return repo, a, b


def test_diff_with_require_not_blocked_ends_with_1_when_the_change_blocks(tmp_path, capsys):
    pytest.importorskip("bandit")
    repo, a, b = two_commits(tmp_path, changed(changed(BASE, store=BACKUP), app=BACKUP_ROUTE))
    code = cli.main(["diff", str(repo), f"{a}..{b}", "--offline", "--require", "not-blocked",
                     "--out", str(tmp_path / "out")])
    err = capsys.readouterr().err
    assert code == 1, err
    assert "fail    this change brings what blocks a release" in err
    assert re.search(r"fail      - new critical finding B602 at api/store\.py:\d+", err), err


def test_diff_with_require_not_blocked_ends_with_0_for_its_harmless_twin(tmp_path, capsys):
    head = changed(BASE, store="\n\ndef shout(text):\n    return text.upper()\n")
    repo, a, b = two_commits(tmp_path, head)
    code = cli.main(["diff", str(repo), f"{a}..{b}", "--offline", "--require", "not-blocked",
                     "--out", str(tmp_path / "out")])
    out = capsys.readouterr()
    assert code == 0, out.err
    assert "pass    this change brings nothing that blocks a release" in out.out + out.err


# ---------------------------------------------------------------------------------------------- the hook itself
def pre_push(repo: Path) -> Path:
    return repo / ".git" / "hooks" / "pre-push"


def test_the_hook_is_written_where_none_is_and_taken_away_again(tmp_path, capsys):
    repo = tmp_path / "p"
    commit(repo, {"a.txt": "one\n"})
    assert cli.main(["hook", "status", str(repo)]) == 0
    assert "is not on" in capsys.readouterr().out
    assert cli.main(["hook", "install", str(repo)]) == 0
    text = pre_push(repo).read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh\n" + hook.MARK) and "\r" not in text
    assert "hook" in text and "run" in text and "--no-verify" in text
    if os.name != "nt":
        assert os.stat(pre_push(repo)).st_mode & stat.S_IXUSR
        # git starts a hook as the person who pushes: nobody else may change it or needs to run it
        others = stat.S_IWGRP | stat.S_IWOTH | stat.S_IXGRP | stat.S_IXOTH
        assert not os.stat(pre_push(repo)).st_mode & others
    assert cli.main(["hook", "status", str(repo)]) == 0
    assert "is on" in capsys.readouterr().out
    assert cli.main(["hook", "install", str(repo)]) == 0          # again: Lantern's own hook is written anew
    assert pre_push(repo).read_text(encoding="utf-8") == text
    assert cli.main(["hook", "remove", str(repo)]) == 0
    assert not pre_push(repo).exists()
    assert cli.main(["hook", "remove", str(repo)]) == 0           # nothing of Lantern's there: nothing to do
    assert "no pre-push hook of Lantern's" in capsys.readouterr().out


def test_a_hook_lantern_did_not_write_is_never_replaced_or_removed(tmp_path, capsys):
    repo = tmp_path / "p"
    commit(repo, {"a.txt": "one\n"})
    mine = "#!/bin/sh\n# my own check\nexit 0\n"
    pre_push(repo).parent.mkdir(parents=True, exist_ok=True)
    pre_push(repo).write_text(mine, encoding="utf-8")
    assert cli.main(["hook", "install", str(repo)]) == 2
    err = capsys.readouterr().err
    assert "Lantern did not write it" in err and hook.own_line() in err     # and the line to put into it
    assert cli.main(["hook", "remove", str(repo)]) == 2
    assert pre_push(repo).read_text(encoding="utf-8") == mine
    assert cli.main(["hook", "status", str(repo)]) == 0
    assert "of your own" in capsys.readouterr().out


@needs_links
def test_a_hook_that_is_a_link_is_not_lanterns_and_what_it_names_is_left_alone(tmp_path, capsys):
    repo = tmp_path / "p"
    commit(repo, {"a.txt": "one\n"})
    elsewhere = tmp_path / "shared-hook"
    elsewhere.write_text("#!/bin/sh\n" + hook.MARK + "\nexit 0\n", encoding="utf-8")
    pre_push(repo).parent.mkdir(parents=True, exist_ok=True)
    pre_push(repo).symlink_to(elsewhere)
    assert cli.main(["hook", "install", str(repo)]) == 2
    assert cli.main(["hook", "remove", str(repo)]) == 2
    assert pre_push(repo).is_symlink() and elsewhere.read_text(encoding="utf-8").endswith("exit 0\n")


def test_a_repository_that_runs_its_hooks_from_another_folder_is_told_so(tmp_path, capsys):
    repo = tmp_path / "p"
    commit(repo, {"a.txt": "one\n"})
    git("config", "core.hooksPath", ".husky", cwd=repo)
    assert cli.main(["hook", "install", str(repo)]) == 2
    err = capsys.readouterr().err
    assert "core.hooksPath" in err and ".husky" in err and hook.own_line() in err
    assert not pre_push(repo).exists()


def test_a_folder_in_no_repository_is_said_so(tmp_path, capsys):
    (tmp_path / "plain").mkdir()
    assert cli.main(["hook", "install", str(tmp_path / "plain")]) == 2
    assert "no git repository" in capsys.readouterr().err


def test_what_git_hands_the_hook_is_read_as_it_is_written_and_nothing_else(tmp_path):
    repo = tmp_path / "p"
    commit(repo, {"a.txt": "one\n"})
    said = []
    assert hook.run(repo, "origin", ["refs/heads/main abc refs/heads/main def"], say=said.append) == 2
    assert any("could not read" in line for line in said)
    said.clear()
    zero = "0" * 40
    assert hook.run(repo, "origin", [f"(delete) {zero} refs/heads/old {'1' * 40}"], say=said.append) == 0
    assert any("nothing to check" in line for line in said)
    assert hook.run(repo, "origin", [], say=said.append) == 0


# ------------------------------------------------------------------------------- a real push, with git's own hook
def push(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "core.autocrlf=false", "push", *args], cwd=repo, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", env={**os.environ, **WHEN})


def remote_has(remote: Path, branch: str) -> str | None:
    r = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], cwd=remote,
                       capture_output=True, text=True, encoding="utf-8")
    return r.stdout.strip() or None


def test_a_push_that_brings_a_serious_finding_is_stopped_and_its_harmless_twin_goes_through(tmp_path):
    pytest.importorskip("bandit")
    remote = tmp_path / "remote.git"
    git("init", "-q", "--bare", str(remote), cwd=tmp_path)
    repo = tmp_path / "notes"
    first = commit(repo, BASE, "base")
    git("remote", "add", "origin", str(remote), cwd=repo)
    assert push(repo, "-q", "origin", "main").returncode == 0      # before the hook: what the other side has
    assert cli.main(["hook", "install", str(repo)]) == 0

    safe = commit(repo, changed(BASE, store="\n\ndef shout(text):\n    return text.upper()\n"), "harmless")
    p = push(repo, "origin", "main")
    assert p.returncode == 0, p.stderr
    assert remote_has(remote, "main") == safe
    assert "nothing in it blocks a release" in p.stderr, p.stderr

    fault = commit(repo, changed(changed(changed(BASE, store="\n\ndef shout(text):\n    return text.upper()\n"),
                                         store=BACKUP), app=BACKUP_ROUTE), "backup")
    p = push(repo, "origin", "main")
    assert p.returncode != 0, p.stderr
    assert remote_has(remote, "main") == safe                     # what the other side has did not move
    assert "stopped: this push brings what blocks a release" in p.stderr, p.stderr
    assert re.search(r"new critical finding B602 at api/store\.py:\d+", p.stderr), p.stderr
    assert "git push --no-verify" in p.stderr
    receipt = repo / ".lantern" / "push" / "main" / "change.md"
    assert receipt.is_file() and f"the push of main ({fault[:10]})" in receipt.read_text(encoding="utf-8")
    assert ".lantern/push" not in git("status", "--porcelain", "--untracked-files=all", cwd=repo)   # never committed

    git("reset", "-q", "--hard", safe, cwd=repo)                  # a new branch with a harmless change
    git("checkout", "-q", "-b", "feature", cwd=repo)
    branch = commit(repo, changed(BASE, store="\n\ndef shout(text):\n    return text.upper()\n\n\n"
                                               "def whisper(text):\n    return text.lower()\n"), "more")
    p = push(repo, "origin", "feature")
    assert p.returncode == 0, p.stderr
    assert remote_has(remote, "feature") == branch
    assert f"after {safe[:12]}" in p.stderr, p.stderr             # compared with where it parted from main
    p = push(repo, "origin", ":feature")                          # taking a branch away sends no code
    assert p.returncode == 0 and remote_has(remote, "feature") is None, p.stderr
    assert first != safe


def test_the_first_push_to_an_empty_remote_is_compared_with_nothing(tmp_path):
    """No commit of the other side to compare with: everything pushed is new, so a serious finding anywhere in it
    stops the push, and code with none goes through."""
    pytest.importorskip("bandit")
    for name, files, stopped in (("clean", BASE, False),
                                 ("risky", changed(changed(BASE, store=BACKUP), app=BACKUP_ROUTE), True)):
        remote = tmp_path / f"{name}.git"
        git("init", "-q", "--bare", str(remote), cwd=tmp_path)
        repo = tmp_path / name
        head = commit(repo, files, "first")
        git("remote", "add", "origin", str(remote), cwd=repo)
        assert cli.main(["hook", "install", str(repo)]) == 0
        p = push(repo, "origin", "main")
        assert (p.returncode != 0) is stopped, p.stderr
        assert "after nothing (nothing: the first push of this code)" in p.stderr, p.stderr
        assert remote_has(remote, "main") == (None if stopped else head)


def test_the_hook_never_runs_a_lantern_the_project_brings(tmp_path):
    """The hook runs the Lantern that wrote it. git starts a hook in the project's own folder, and Python puts the
    folder it starts in first on its path: a `lantern` package of the project's own would be imported in place of
    Lantern's and run on every push, as the project's code. The hook starts Python with `-P`, so that folder is not
    on its path."""
    remote = tmp_path / "remote.git"
    git("init", "-q", "--bare", str(remote), cwd=tmp_path)
    repo = tmp_path / "notes"
    ran = tmp_path / "PLANTED-RAN"
    planted = {"lantern/__init__.py": f"open({str(ran)!r}, 'w').close()\n",
               "lantern/cli.py": "def main(argv=None):\n    return 0\n"}
    commit(repo, {**BASE, **planted}, "base")
    git("remote", "add", "origin", str(remote), cwd=repo)
    assert push(repo, "-q", "origin", "main").returncode == 0
    assert cli.main(["hook", "install", str(repo)]) == 0
    head = commit(repo, {**changed(BASE, store="\n\ndef shout(text):\n    return text.upper()\n"), **planted}, "more")
    p = push(repo, "origin", "main")
    assert p.returncode == 0, p.stderr
    assert "lantern  checking the push of main" in p.stderr and "nothing in it blocks a release" in p.stderr, p.stderr
    assert not ran.exists()
    assert remote_has(remote, "main") == head


def test_a_tag_is_checked_like_a_branch(tmp_path):
    """git hands the hook a tag by the tag's own object, not by the commit it names: the check reads the commit. A
    tag on a harmless commit goes through; a tag on a commit that brings a serious finding is stopped, and the other
    side does not get it."""
    pytest.importorskip("bandit")
    remote = tmp_path / "remote.git"
    git("init", "-q", "--bare", str(remote), cwd=tmp_path)
    repo = tmp_path / "notes"
    commit(repo, BASE, "base")
    git("remote", "add", "origin", str(remote), cwd=repo)
    assert push(repo, "-q", "origin", "main").returncode == 0
    assert cli.main(["hook", "install", str(repo)]) == 0
    safe = commit(repo, changed(BASE, store="\n\ndef shout(text):\n    return text.upper()\n"), "harmless")
    git("tag", "-a", "v1", "-m", "one", cwd=repo)
    commit(repo, changed(changed(changed(BASE, store="\n\ndef shout(text):\n    return text.upper()\n"),
                                 store=BACKUP), app=BACKUP_ROUTE), "backup")
    git("tag", "-a", "v2", "-m", "two", cwd=repo)
    p = push(repo, "origin", "v1")
    assert p.returncode == 0, p.stderr
    assert f"checking the push of v1: {safe[:12]}" in p.stderr, p.stderr
    p = push(repo, "origin", "v2")
    assert p.returncode != 0 and "stopped: this push brings what blocks a release" in p.stderr, p.stderr
    tags = git("tag", "--list", cwd=remote).split()
    assert tags == ["v1"], tags


@pytest.mark.skipif(os.name == "nt", reason="the line is for a hook git runs with its own shell; started here by sh")
def test_the_line_for_a_hook_of_ones_own_runs_this_lantern_too(tmp_path):
    """Where git runs hooks from another folder, Lantern gives the one line to add to the person's own hook. That line
    runs this Lantern, as Lantern's own hook does: not one the project brings, and not whichever one the Python finds
    by itself. Until 2026-11-17 it was `python -P -m lantern.cli hook run`, which runs the Lantern that Python finds
    (on the computer this was written on: an older copy installed for editing, which has no `hook` command)."""
    line = hook.own_line()
    assert Path(hook.__file__).resolve().parent.parent.as_posix() in line and " -P " in line, line
    project = tmp_path / "project"
    (project / "lantern").mkdir(parents=True)
    (project / "lantern" / "__init__.py").write_text("raise SystemExit('the project ran')\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    r = subprocess.run(["sh", "-c", line], input="not what git says\n", cwd=project, env=env, capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    assert r.returncode == 2 and "could not read what git said is being pushed" in r.stderr, r.stderr


@needs_links
def test_a_receipts_folder_the_project_brings_as_a_link_is_not_written_through(tmp_path):
    """A project can bring `.lantern/push` as a link to a folder anywhere on the computer. Lantern writes nothing
    through it, no receipt and no `.gitignore`: the push is stopped as one Lantern could not check, with the reason.
    The twin is every other push here, whose receipts folder Lantern makes itself."""
    remote = tmp_path / "remote.git"
    git("init", "-q", "--bare", str(remote), cwd=tmp_path)
    repo = tmp_path / "notes"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (repo / ".lantern").mkdir(parents=True)
    (repo / ".lantern" / "push").symlink_to(elsewhere, target_is_directory=True)
    first = commit(repo, BASE, "base")                            # the link is part of the project's commit
    git("remote", "add", "origin", str(remote), cwd=repo)
    assert push(repo, "-q", "origin", "main").returncode == 0
    assert cli.main(["hook", "install", str(repo)]) == 0
    commit(repo, changed(BASE, store="\n\ndef shout(text):\n    return text.upper()\n"), "more")
    p = push(repo, "origin", "main")
    assert p.returncode != 0 and "could not check the push of main" in p.stderr and "is a link" in p.stderr, p.stderr
    assert "git push --no-verify" in p.stderr
    assert list(elsewhere.iterdir()) == []
    assert remote_has(remote, "main") == first
