"""`lantern fix brief` and `lantern fix check` (`lantern/cli.py`, `pipeline.fix_check`, `lantern/suggest.py`; roadmap of
2026-11-14, stage 3).

The small app of `tests/test_fixcheck.py` again, this time through the command a person types. A fix stands either
in the project itself or in another folder (the candidate). A candidate's change is put onto a copy of Lantern's own,
checked there, and written out as a patch only when every part of the contract held; a trick is refused, a true fix
whose tests were not run is incomplete, and neither is written out. Nothing here changes the project.
"""
import json
import os
import shutil
import subprocess

import pytest
from links_here import needs_links
from test_fixcheck import BASE, COMPUTED, SKIPPED_FOLDER, TEST_CUT, TRUE_FIX, write

from lantern import cli, fixcheck, pipeline, suggest

TESTS = ["--", "python", "-m", "pytest", "-q"]
PLAIN = ["-c", "core.autocrlf=false", "-c", "core.safecrlf=false"]      # git as a plain patch tool, on every system


@pytest.fixture(scope="module")
def checked(tmp_path_factory):
    """The app, checked once for the whole file."""
    repo = tmp_path_factory.mktemp("fixcmd") / "notes"
    write(repo, BASE)
    pipeline.analyze(repo, pipeline.out_dir(repo), log=lambda m: None, offline=True)
    return repo


@pytest.fixture
def notes(checked, tmp_path, monkeypatch):
    """A copy of the checked app for one test, and an empty folder of Lantern's own."""
    monkeypatch.setenv("LANTERN_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    repo = tmp_path / "work" / "notes"
    shutil.copytree(checked, repo)
    return repo


def finding(repo, rule="B602") -> str:
    sec = json.loads((repo / ".lantern" / "security.json").read_text(encoding="utf-8"))
    return next(f["id"] for f in sec["findings"] if f["rule"] == rule and not f.get("in_tests"))


def run(args, capsys):
    code = cli.main([str(a) for a in args])
    said = capsys.readouterr()
    return code, said.out, said.err


def folder_with(tmp_path, name: str, files: dict):
    d = tmp_path / "candidates" / name / "notes-with-the-fix"       # not the project's name, on purpose
    write(d, files)
    return d


def put(repo, files: dict) -> None:
    """The project's own files become `files` (its results folder stays)."""
    for p in sorted(repo.rglob("*"), reverse=True):
        rel = p.relative_to(repo).as_posix()
        if p.is_file() and not rel.startswith(".lantern/") and rel not in files:
            p.unlink()
    write(repo, files)


def everything(root) -> dict:
    """Every file under a folder with what it holds."""
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def kept_notes(home) -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(home.rglob("brief.json"))]


# ------------------------------------------------------------------------------------------------- the brief
def test_the_brief_says_where_how_and_what_a_fix_has_to_show(notes, tmp_path, capsys):
    fid, before = finding(notes), everything(notes)
    code, out, err = run(["fix", "brief", notes, fid[:8]], capsys)
    assert code == 0, err
    assert out.startswith(f"Fix brief for {fid}: [critical] B602") and "api/store.py" in out
    assert "How it is reached:" in out and "POST /api/backup" in out
    assert "How the value gets there:" in out and "arrives with the request" in out
    for i, part in enumerate(fixcheck.ITEMS, 1):
        assert f"  {i}. {part}: " in out
    assert f"lantern fix check {notes} {fid} -- " in out
    assert "Nothing here accepts or closes a finding" in out
    assert everything(notes) == before                          # the project is as it was, its results too
    [note] = kept_notes(tmp_path / "home")                      # the check as it is now is kept, in Lantern's folder
    assert note["finding"] == fid and note["how"] == "brief"
    code, out, err = run(["fix", "brief", notes, fid, "--format", "json"], capsys)
    data = json.loads(out)
    assert code == 0 and data["finding"]["id"] == fid and [p["id"] for p in data["contract"]] == list(fixcheck.ITEMS)
    assert data["path"][-1]["file"] == "api/store.py" and data["flow"]["steps"]


def test_a_brief_for_what_is_not_open_and_for_a_project_never_checked(notes, tmp_path, capsys):
    code, out, err = run(["fix", "brief", notes, "no-such-finding"], capsys)
    assert code == 2 and "is not an open finding" in err and not out
    bare = tmp_path / "bare"
    write(bare, {"app.py": "print('x')\n"})
    code, out, err = run(["fix", "brief", bare, "anything"], capsys)
    assert code == 2 and "lantern analyze" in err
    code, out, err = run(["fix", "check", bare, "anything"], capsys)
    assert code == 2 and "lantern analyze" in err
    assert not kept_notes(tmp_path / "home")


# ------------------------------------------------------------------------------- a fix that stands in another folder
def test_a_trick_in_another_folder_is_refused_and_nothing_is_written(notes, tmp_path, capsys):
    fid, before = finding(notes), everything(notes)
    there = folder_with(tmp_path, "computed", COMPUTED)
    code, out, err = run(["fix", "check", notes, fid, "--candidate", there, "--suggest", tmp_path / "fix.patch",
                          "--offline"], capsys)
    assert code == 1, err
    assert "Compared with the project's last check." in out
    assert "Refused: the fix of B602 at api/store.py" in out and "[broken] calls: " in out and "getattr(subprocess" in out
    assert "[held] gone: " in out                               # the finding no longer shows, which is the trick
    assert "note    no suggested change was written: The fix is refused" in err
    assert not (tmp_path / "fix.patch").exists()
    assert everything(notes) == before and everything(there) == {k: v.encode() for k, v in COMPUTED.items()}
    assert not kept_notes(tmp_path / "home")                    # the project did not change, so nothing is kept


def test_code_the_candidate_hides_in_a_folder_lantern_leaves_out_is_found_in_the_candidate(notes, tmp_path, capsys):
    """Lantern's copy holds the project with the candidate's change to the files Lantern reads, so a file the
    candidate puts under `build/` is not on it. The one question asked of the disk is asked of the candidate."""
    there = folder_with(tmp_path, "skipped", SKIPPED_FOLDER)
    code, out, err = run(["fix", "check", notes, finding(notes), "--candidate", there, "--offline"], capsys)
    assert code == 1, err
    assert "[broken] calls: " in out and "build/helpers.py, in a folder Lantern does not read" in out


def test_a_true_fix_whose_tests_were_not_run_is_incomplete_and_is_not_written_out(notes, tmp_path, capsys):
    fid = finding(notes)
    there = folder_with(tmp_path, "true", TRUE_FIX)
    code, out, err = run(["fix", "check", notes, fid, "--candidate", there, "--suggest", tmp_path / "fix.patch",
                          "--offline"], capsys)
    assert code == 3, err
    assert "Incomplete: the fix of B602" in out and "[not-shown] tests: The tests were not run in this check." in out
    assert f"lantern fix check {notes} {fid} -- <test command>" in out
    assert "no suggested change was written: Nothing is broken, but 1 part" in err
    assert not (tmp_path / "fix.patch").exists()
    code, out, err = run(["fix", "check", notes, fid, "--candidate", folder_with(tmp_path, "cut", TEST_CUT),
                          "--offline", "--format", "json"], capsys)
    data = json.loads(out)
    assert code == 1 and data["verdict"] == "refused" and data["contract"]["broken"] == ["tests"]
    assert data["candidate"] is True and data["files"] == ["api/store.py", "tests/test_store.py"]
    assert data["tests_ran"] is False and data["suggestion"] is None


def test_a_true_fix_with_its_tests_run_passes_and_what_is_written_out_is_that_fix(notes, tmp_path, capsys):
    """Nothing stands in for the sandbox here: the tests run on Lantern's copy of the project with the change."""
    fid, before = finding(notes), everything(notes)
    there = folder_with(tmp_path, "true", TRUE_FIX)
    patch = tmp_path / "fix.patch"
    code, out, err = run(["fix", "check", notes, fid, "--candidate", there, "--suggest", patch, "--offline", *TESTS],
                         capsys)
    assert code == 0, (out, err[-3000:])
    assert "Passed: the fix of B602 at api/store.py" in out and "The fix passed: all 7 parts of the contract held." in out
    assert "[held] tests: Every test that was there before the fix is there (2 tests now)." in out
    assert f"wrote   {patch} (the suggested change; Lantern applied nothing)" in out
    assert "tests   " in err and not any(x.startswith("tests   release") for x in err.splitlines())
    assert everything(notes) == before                          # Lantern applied nothing
    assert not kept_notes(tmp_path / "home")
    assert b"\r" not in patch.read_bytes()                      # as the files are: no line end of this system's own
    text = patch.read_text(encoding="utf-8")
    assert text.startswith("# A suggested change, checked by Lantern: the fix of B602 at api/store.py:")
    assert "diff --git a/api/store.py b/api/store.py\n" in text and "+import re\n" in text
    applied = tmp_path / "applied"
    write(applied, BASE)
    done = subprocess.run(["git", *PLAIN, "apply", str(patch)], cwd=applied, capture_output=True, text=True,
                          encoding="utf-8")
    assert done.returncode == 0, done.stderr
    assert everything(applied) == {k: v.encode() for k, v in TRUE_FIX.items()}


def test_a_fix_of_files_whose_lines_end_the_windows_way_is_written_out_as_those_files_are(tmp_path, monkeypatch,
                                                                                         capsys):
    """A patch's lines end as the lines of the files it changes end. Every line of this project ends with CR LF, as
    an editor on Windows leaves it, and what is written out has to apply to exactly those files: a patch written
    the way a report is written would end each of those lines with CR CR LF on Windows."""
    def dos(files: dict) -> dict:
        return {rel: text.replace("\n", "\r\n") for rel, text in files.items()}

    monkeypatch.setenv("LANTERN_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LANTERN_OFFLINE", "1")
    repo = tmp_path / "work" / "notes"
    write(repo, dos(BASE))
    pipeline.analyze(repo, pipeline.out_dir(repo), log=lambda m: None, offline=True)
    there, patch = folder_with(tmp_path, "true", dos(TRUE_FIX)), tmp_path / "fix.patch"
    code, out, err = run(["fix", "check", repo, finding(repo), "--candidate", there, "--suggest", patch, "--offline",
                          *TESTS], capsys)
    assert code == 0, (out, err[-3000:])
    assert "The fix passed: all 7 parts of the contract held." in out
    data = patch.read_bytes()
    said, change = data.split(b"diff --git ", 1)
    assert said.startswith(b"# A suggested change, checked by Lantern") and b"\r" not in said    # Lantern's own lines
    assert b"\n+import re\r\n" in change and b"\r\r" not in change                               # the files' lines
    applied = tmp_path / "applied"
    write(applied, dos(BASE))
    done = subprocess.run(["git", *PLAIN, "apply", "--whitespace=nowarn", str(patch)], cwd=applied,
                          capture_output=True, text=True, encoding="utf-8")
    assert done.returncode == 0, done.stderr
    assert everything(applied) == {k: v.encode() for k, v in dos(TRUE_FIX).items()}


# ------------------------------------------------------------------------------- a fix made in the project itself
def test_a_fix_that_was_refused_cannot_pass_by_being_checked_again(notes, tmp_path, capsys):
    """First a trick, checked and refused. Then the true fix, checked with its tests: it is compared with the check
    from before the trick, which the first check kept, and passes. After a pass that check is let go."""
    fid, home = finding(notes), tmp_path / "home"
    put(notes, COMPUTED)
    code, out, err = run(["fix", "check", notes, fid, "--offline"], capsys)
    assert code == 1 and "Refused: the fix of B602" in out and "[broken] calls: " in out, err
    assert [n["how"] for n in kept_notes(home)] == ["first-check"]
    assert finding(notes, "B324") and not any(                       # the project's own results are of the trick now
        f["id"] == fid for f in json.loads((notes / ".lantern" / "security.json").read_text())["findings"])
    code, out, err = run(["fix", "check", notes, fid, "--offline"], capsys)      # the same trick again: the same answer
    assert code == 1 and "kept when the fix was first checked" in out
    put(notes, TRUE_FIX)
    code, out, err = run(["fix", "check", notes, fid, "--offline", "--format", "json", *TESTS], capsys)
    data = json.loads(out)
    assert code == 0, (data["contract"]["words"], err[-3000:])
    assert data["verdict"] == "passed" and data["compared_with"]["what"] == "first-check"
    assert data["tests_ran"] is True and data["candidate"] is False and data["suggestion"] is None
    assert not kept_notes(home)
    code, out, err = run(["fix", "check", notes, fid, "--offline"], capsys)
    assert code == 2 and "is not an open finding of the check made before the fix" in err


def test_a_brief_asked_for_first_is_what_the_fix_is_compared_with(notes, tmp_path, capsys):
    fid = finding(notes)
    assert run(["fix", "brief", notes, fid], capsys)[0] == 0
    put(notes, TRUE_FIX)
    pipeline.analyze(notes, pipeline.out_dir(notes), log=lambda m: None, offline=True)      # analyzed in between
    code, out, err = run(["fix", "check", notes, fid, "--offline"], capsys)
    assert code == 3, err
    assert "Compared with the check kept when the fix brief was asked for" in out and "Incomplete: the fix of B602" in out
    assert [n["how"] for n in kept_notes(tmp_path / "home")] == ["brief"]       # not passed yet: still kept


# ------------------------------------------------------------------------------------------- what is not checked
def test_what_the_command_refuses_before_it_reads_anything(notes, tmp_path, capsys):
    fid, before = finding(notes), everything(notes)
    there = folder_with(tmp_path, "true", TRUE_FIX)
    for args, words in [
        (["--suggest", tmp_path / "x.patch"], "give --candidate"),
        (["--candidate", tmp_path / "nothing-there"], "The candidate is not a folder"),
        (["--candidate", notes], "The candidate is the project's own folder"),
        (["--candidate", notes / "api"], "lies inside the project's folder"),
        (["--candidate", notes.parent], "lies inside the project's folder"),
        (["--candidate", folder_with(tmp_path, "same", BASE)], "there is no change to check"),
        (["--candidate", there, "--", "rm", "-rf", "x"], "only a test command can run here"),
    ]:
        code, out, err = run(["fix", "check", notes, fid, "--offline", *args], capsys)
        assert code == 2 and words in err and not out, (args, err)
    assert everything(notes) == before and not (tmp_path / "x.patch").exists()
    code, out, err = run(["fix", "check", notes, "no-such-finding", "--candidate", there, "--offline"], capsys)
    assert code == 2 and "is not an open finding of the check made before the fix" in err


# ------------------------------------------------------------------------------- the copy and the suggested change
OLD = {
    "app/main.py": "import os\n\n\ndef main():\n    return os.getcwd()\n",
    "app/old.py": "def gone():\n    return 1\n",
    "app/empty_then_gone.txt": "",
    "notes/read me.txt": "one\ntwo\nthree\n",
    "notes/no_end.txt": "first\nlast line with no end",
    "notes/dos.txt": "a\r\nb\r\nc\r\n",
    "notes/page.txt": "before the form feed\x0cafter it\nnext\n",
    "tool.sh": "#!/bin/sh\necho one\n",
    "same.txt": "the same on both sides\n",
}
NEW = {
    "app/main.py": "import os\nimport sys\n\n\ndef main():\n    return os.getcwd(), sys.argv\n",
    "app/new.py": "def came():\n    return 2\n",
    "app/empty_new.txt": "",
    "notes/read me.txt": "one\n2\nthree\n",
    "notes/no_end.txt": "first\nlast line, still with no end",
    "notes/dos.txt": "a\r\nB\r\nc\r\n",
    "notes/page.txt": "before the form feed\x0cafter it, changed\nnext\n",
    "tool.sh": "#!/bin/sh\necho two\n",
    "same.txt": "the same on both sides\n",
}


def two_folders(tmp_path, old=OLD, new=NEW):
    a, b = tmp_path / "project" / "thing", tmp_path / "with-fix" / "thing-fixed"
    for root, files in ((a, old), (b, new)):
        for rel, text in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(text.encode("utf-8"))
    return a, b


def test_the_copy_is_the_project_with_exactly_the_candidates_change(tmp_path):
    a, b = two_folders(tmp_path)
    (a / "node_modules" / "lib").mkdir(parents=True)
    (a / "node_modules" / "lib" / "index.js").write_bytes(b"module.exports = 1\n")
    (b / "node_modules" / "lib").mkdir(parents=True)
    (b / "node_modules" / "lib" / "index.js").write_bytes(b"module.exports = 'changed by the candidate'\n")
    (b / "build").mkdir()
    (b / "build" / "hidden.py").write_bytes(b"print('only in the candidate')\n")
    got = suggest.change(a, b)
    assert got["files"] == ["app/empty_new.txt", "app/empty_then_gone.txt", "app/main.py", "app/new.py", "app/old.py",
                            "notes/dos.txt", "notes/no_end.txt", "notes/page.txt", "notes/read me.txt", "tool.sh"]
    light, whole = tmp_path / "own" / "light" / "thing", tmp_path / "own" / "whole" / "thing"
    suggest.lay(a, b, light, got)
    assert everything(light) == {k: v.encode("utf-8") for k, v in NEW.items()}           # what Lantern reads
    suggest.lay(a, b, whole, got, whole=True)
    assert everything(whole) == {**{k: v.encode("utf-8") for k, v in NEW.items()},
                                 "node_modules/lib/index.js": b"module.exports = 1\n"}       # the project's, not the candidate's
    assert everything(a) == {**{k: v.encode("utf-8") for k, v in OLD.items()}, "node_modules/lib/index.js": b"module.exports = 1\n"}


@needs_links
def test_nothing_is_written_through_a_link_that_came_with_the_project(tmp_path):
    a, b = two_folders(tmp_path, {"app/main.py": "x = 1\n"}, {"app/main.py": "x = 1\n", "linked/new.py": "y = 2\n"})
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, a / "linked")
    with pytest.raises(ValueError, match="where the project has a link or a file"):
        suggest.lay(a, b, tmp_path / "own" / "thing", suggest.change(a, b), whole=True)
    assert not any(outside.iterdir())


def test_the_suggested_change_is_one_git_applies_and_gives_the_candidates_files(tmp_path):
    a, b = two_folders(tmp_path)
    if os.name != "nt":
        os.chmod(b / "tool.sh", 0o755)
    text, why = suggest.patch(a, b, suggest.change(a, b), ["first line", "second\nline with a break"])
    assert why is None
    assert text.startswith("# first line\n# second?line with a break\ndiff --git a/app/empty_new.txt b/app/empty_new.txt\n")
    assert "new file mode 100644\n--- /dev/null\n+++ b/app/new.py\n" in text
    assert "deleted file mode 100644\n--- a/app/old.py\n+++ /dev/null\n" in text
    assert "--- a/notes/read me.txt\t\n+++ b/notes/read me.txt\t\n" in text
    assert text.count("\\ No newline at end of file\n") == 2
    assert "same.txt" not in text
    target = tmp_path / "applied"
    shutil.copytree(a, target)
    done = subprocess.run(["git", *PLAIN, "apply", "--whitespace=nowarn", "-"], cwd=target,
                          input=text.encode("utf-8"), capture_output=True)
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    assert everything(target) == {k: v.encode("utf-8") for k, v in NEW.items()}
    if os.name != "nt":
        assert os.stat(target / "tool.sh").st_mode & 0o111 and "old mode 100644\nnew mode 100755\n" in text


@pytest.mark.parametrize("old, new, why", [
    ({"a.bin": "x"}, {"a.bin": b"\xff\xfe\x00"}, "a.bin is not text a patch can carry"),
    ({"a.txt": "x\n"}, {"a.txt": "x\x00y\n"}, "a.txt is not text a patch can carry"),
    ({"a.txt": "x\n"}, {"a.txt": "x\n", "café.txt": "y\n"}, "a name a patch cannot carry"),
    ({"a.txt": "x\n"}, {"a.txt": "x\n", " lead.txt": "y\n"}, "a name a patch cannot carry"),
    ({"a.txt": "x\n"}, {"a.txt": "y" * (suggest.MOST_FILE + 1)}, "or is over 2 MB"),
])
def test_a_change_that_text_cannot_carry_is_said_and_not_written(tmp_path, old, new, why):
    a, b = tmp_path / "p" / "thing", tmp_path / "c" / "thing"
    for root, files in ((a, old), (b, new)):
        for rel, data in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    text, said = suggest.patch(a, b, suggest.change(a, b))
    assert text is None and why in said
