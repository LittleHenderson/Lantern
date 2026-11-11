"""Lantern writes its results into the results folder and nowhere else (2026-11-10, directive stage 7, part 3).

The results folder lies inside the analysed project by default (`PATH/.lantern`), and a project comes from anywhere: a
link somebody sent, a zip, a clone. Until this date every result file was written with a plain `write_text`, which
follows a link and waits on a pipe:

* a project that brought `.lantern/security.json` as a link to a file of the person's own had that file overwritten
  with Lantern's results (so with every file `analyze` and `explain` write, and with `lantern-accepted.json`);
* one that brought `.lantern` itself as a link to a folder had Lantern's files made in that folder;
* a pipe under a result file's name held the run up for good, and a folder there ended it with a Python error.

Now each file is written beside its place and moved there in one step (`results.write`), which puts Lantern's file in
the link's place and leaves what the link pointed at alone; a results folder that is a link, or is reached through
one inside the project, is refused in plain words before anything is analysed (`results.folder`).
"""
import json
import os
import re
import threading
from pathlib import Path

import pytest

import lantern
from lantern import explain, pipeline, results, security
from lantern.cli import main

needs_links = pytest.mark.skipif(os.name != "posix", reason="needs a POSIX system (symbolic links, pipes)")
APP = {"app.py": "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"}
MINE = "the person's own file\n"
# every file `lantern analyze` writes anew on each run
WRITTEN = ("security.json", "graph.json", "calls.json", "readiness.json", "run.json", "report.html", "evidence.html",
           "evidence.json", "badge.svg")


@pytest.fixture(autouse=True)
def _nothing_left_to_say():
    """What a write met is kept until a run asks for it; a test leaves none of it for the tests after it."""
    yield
    results.said()


def _write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _project(tmp_path: Path) -> tuple[Path, Path]:
    """A tiny project, and a file of the person's own that lies outside it."""
    repo = _write(tmp_path / "project", APP)
    mine = tmp_path / "mine.txt"
    mine.write_text(MINE, encoding="utf-8")
    return repo, mine


def _left_alone(tmp_path: Path) -> bool:
    """Nothing but the project and the person's file is in the folder above, and the file says what it said."""
    return sorted(p.name for p in tmp_path.iterdir()) == ["mine.txt", "project"] \
        and (tmp_path / "mine.txt").read_text(encoding="utf-8") == MINE


# ---------------------------------------------------------------------------- a link under a result file's name

@needs_links
@pytest.mark.parametrize("name", WRITTEN)
def test_what_a_link_under_a_result_files_name_points_at_is_left_alone(name, tmp_path, capsys):
    repo, mine = _project(tmp_path)
    (repo / ".lantern").mkdir()
    os.symlink(mine, repo / ".lantern" / name)
    assert main(["analyze", str(repo), "--offline"]) == 0
    assert _left_alone(tmp_path), "the run wrote outside the project"       # before: Lantern's results were in mine.txt
    made = repo / ".lantern" / name
    assert not made.is_symlink() and made.is_file() and made.stat().st_size > 100     # Lantern's own file is in its place
    said = capsys.readouterr().out
    assert f"{name} in the results folder was a link" in said               # and the run says what it met there


@needs_links
def test_a_link_that_points_nowhere_is_replaced_too(tmp_path):
    """Written through, such a link would make a new file wherever it points."""
    repo, _mine = _project(tmp_path)
    (repo / ".lantern").mkdir()
    os.symlink(tmp_path / "made-by-lantern.json", repo / ".lantern" / "security.json")
    assert main(["analyze", str(repo), "--offline"]) == 0
    assert _left_alone(tmp_path) and not (repo / ".lantern" / "security.json").is_symlink()


def test_a_result_file_is_whole_or_as_it_was(tmp_path, monkeypatch):
    """A write that stops half-way (a full disk, the program stopped) leaves the file of the run before, and nothing
    half-written beside it. Before, the file was cut to nothing first and filled afterwards."""
    out = tmp_path / "out"
    out.mkdir()
    results.write(out / "security.json", '{"findings": []}')
    assert json.loads((out / "security.json").read_text(encoding="utf-8")) == {"findings": []}
    with pytest.raises(UnicodeEncodeError):                                 # a text that cannot be written to the end
        results.write(out / "security.json", '{"findings": ["\ud800"]}')
    assert json.loads((out / "security.json").read_text(encoding="utf-8")) == {"findings": []}   # before: an empty file
    assert sorted(p.name for p in out.iterdir()) == ["security.json"]

    beside = []

    def full(tmp, path):
        beside.append(Path(tmp))
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(results.os, "replace", full)
    with pytest.raises(OSError):
        results.write(out / "security.json", '{"findings": [1]}')
    monkeypatch.undo()
    assert json.loads((out / "security.json").read_text(encoding="utf-8")) == {"findings": []}
    assert sorted(p.name for p in out.iterdir()) == ["security.json"]
    # written beside its place, under a name nobody can know beforehand (16 random hex digits), and taken away again
    assert len(beside) == 1 and beside[0].parent == out
    assert re.fullmatch(r"\.security\.json\.[0-9a-f]{16}\.part", beside[0].name), beside[0].name


@needs_links
def test_a_link_is_as_it_was_when_the_write_does_not_end(tmp_path, monkeypatch):
    """The link is taken away only by the step that puts Lantern's file in its place. (On Windows it has to go first.)"""
    out = tmp_path / "out"
    out.mkdir()
    mine = tmp_path / "mine.txt"
    mine.write_text(MINE, encoding="utf-8")
    os.symlink(mine, out / "run.json")

    def full(tmp, path):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(results.os, "replace", full)
    with pytest.raises(OSError):
        results.write(out / "run.json", "{}")
    monkeypatch.undo()
    assert os.readlink(out / "run.json") == str(mine) and mine.read_text(encoding="utf-8") == MINE
    assert sorted(p.name for p in out.iterdir()) == ["run.json"]
    assert results.said(out) == []                                          # nothing was replaced, so nothing is said


def test_a_replace_the_system_refuses_is_tried_again_only_on_windows(tmp_path, monkeypatch):
    """Windows refuses to replace a file while another program reads it (a virus scanner, the app's own reader), and
    lets it through a moment later: there the replace is tried for a second. Anywhere else a refusal is final and is
    not waited on."""
    tried, waited = [], []

    def refused(tmp, path):
        tried.append((tmp, path))
        raise PermissionError(13, "Access is denied")
    monkeypatch.setattr(results.os, "replace", refused)
    monkeypatch.setattr(results.time, "sleep", waited.append)
    with pytest.raises(PermissionError):
        results._replace("a", "b")
    assert len(tried) == (50 if os.name == "nt" else 1) and len(waited) == len(tried) - 1
    assert set(tried) == {("a", "b")}
    tried.clear()
    waited.clear()
    with pytest.raises(PermissionError):                                    # every try refused: as many tries as said
        results._replace("a", "b", tries=3)
    assert len(tried) == 3 and waited == [0.02, 0.02]
    tried.clear()
    waited.clear()

    def refused_twice(tmp, path):
        tried.append((tmp, path))
        if len(tried) < 3:
            raise PermissionError(13, "Access is denied")
    monkeypatch.setattr(results.os, "replace", refused_twice)
    results._replace("a", "b", tries=5)                                     # let through at the third try: no more
    assert len(tried) == 3 and waited == [0.02, 0.02]


def test_a_result_file_is_written_as_any_other_file_of_the_person(tmp_path):
    """Not more closed than before (the report is opened by a browser, and by whoever the folder is shared with), and
    with the line ends it had: the report's own script is checked against a hash of its bytes."""
    out = tmp_path / "out"
    out.mkdir()
    plain = out / "plain.txt"
    plain.write_text("x", encoding="utf-8")
    results.write(out / "report.html", "one\ntwo\n", newline="\n")
    assert (out / "report.html").read_bytes() == b"one\ntwo\n"
    if os.name == "posix":
        assert (out / "report.html").stat().st_mode & 0o777 == plain.stat().st_mode & 0o777
    results.write(out / "run.json", "one\ntwo\n")
    assert (out / "run.json").read_bytes() == ("one" + os.linesep + "two" + os.linesep).encode()


# ---------------------------------------------------------------------------- a folder or a pipe under such a name

@pytest.mark.parametrize("name", ["security.json", "report.html"])       # the first file a run writes, and a later one
def test_a_folder_under_a_result_files_name_ends_the_run_in_plain_words(name, tmp_path, capsys):
    repo, _mine = _project(tmp_path)
    (repo / ".lantern" / name).mkdir(parents=True)
    (repo / ".lantern" / name / "kept.txt").write_text("kept", encoding="utf-8")
    assert main(["analyze", str(repo), "--offline"]) == 2                   # before: IsADirectoryError and a traceback
    err = capsys.readouterr().err
    assert name in err and "is a folder" in err and "Traceback" not in err
    assert (repo / ".lantern" / name / "kept.txt").read_text(encoding="utf-8") == "kept"
    # said before the run, not after it: found at the end, the files of this run would lie beside those of the one before
    assert sorted(x.name for x in (repo / ".lantern").iterdir()) == [name]


def _into(done: list, repo: Path) -> None:
    done.append(main(["analyze", str(repo), "--offline"]))


@needs_links
@pytest.mark.parametrize("name", ["security.json", "report.html"])
def test_a_pipe_under_a_result_files_name_does_not_hold_the_run_up(name, tmp_path):
    """Opening a pipe nobody reads from, to write to it, never comes back."""
    repo, _mine = _project(tmp_path)
    (repo / ".lantern").mkdir()
    os.mkfifo(repo / ".lantern" / name)
    done: list = []
    run = threading.Thread(target=_into, args=(done, repo), daemon=True)
    run.start()
    run.join(120)
    try:
        assert done == [0], "the run is still waiting for the pipe"
        assert (repo / ".lantern" / name).is_file()
    finally:
        if not done:                                                        # let the waiting write go, whatever the result
            try:
                os.close(os.open(repo / ".lantern" / name, os.O_RDONLY | os.O_NONBLOCK))
            except OSError:
                pass


# ---------------------------------------------------------------------------- the results folder itself

@needs_links
@pytest.mark.parametrize("command", ["analyze", "report", "evidence", "explain", "export"])
def test_a_results_folder_that_is_a_link_is_refused(command, tmp_path, capsys):
    repo, _mine = _project(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, repo / ".lantern")
    args = {"analyze": ["--offline"], "export": ["--sarif", str(tmp_path / "x.sarif")], "explain": ["--yes"]}.get(command, [])
    assert main([command, str(repo), *args]) == 2
    err = capsys.readouterr().err
    assert ".lantern" in err and "is a link" in err and "--out" in err and "Traceback" not in err
    assert list(elsewhere.iterdir()) == [], "Lantern made files in the folder the link points at"
    assert not (tmp_path / "x.sarif").exists()


@needs_links
def test_a_results_folder_that_is_a_link_to_nowhere_is_refused_in_the_same_words(tmp_path, capsys):
    repo, _mine = _project(tmp_path)
    os.symlink(tmp_path / "not-there", repo / ".lantern")
    assert main(["analyze", str(repo), "--offline"]) == 2                   # before: FileExistsError and a traceback
    assert "is a link" in capsys.readouterr().err and not (tmp_path / "not-there").exists()


def test_a_file_where_the_results_folder_belongs_is_refused_in_plain_words(tmp_path, capsys):
    repo, _mine = _project(tmp_path)
    (repo / ".lantern").write_text("not a folder", encoding="utf-8")
    assert main(["analyze", str(repo), "--offline"]) == 2
    err = capsys.readouterr().err
    assert ".lantern" in err and "is not a folder" in err and "Traceback" not in err
    assert (repo / ".lantern").read_text(encoding="utf-8") == "not a folder"


@needs_links
def test_a_results_folder_named_inside_the_project_is_not_reached_through_a_link(tmp_path, capsys):
    """`--out` is the person's own word, but the folders of the project it goes through came with the project."""
    repo, _mine = _project(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, repo / "build")
    assert main(["analyze", str(repo), "--offline", "--out", str(repo / "build" / "lantern")]) == 2
    assert "is a link" in capsys.readouterr().err and list(elsewhere.iterdir()) == []


@needs_links
def test_a_results_folder_of_the_persons_own_choice_may_be_a_link(tmp_path):
    """The safe twin: a link outside the project is the person's own (results kept on another disk)."""
    repo, _mine = _project(tmp_path)
    kept = tmp_path / "another-disk"
    kept.mkdir()
    os.symlink(kept, tmp_path / "results")
    assert main(["analyze", str(repo), "--offline", "--out", str(tmp_path / "results")]) == 0
    assert (kept / "report.html").is_file() and not (repo / ".lantern").exists()


def test_the_results_folder_is_made_when_it_is_not_there_and_used_when_it_is(tmp_path):
    """The safe twins: what every run did before."""
    repo, _mine = _project(tmp_path)
    assert results.folder(repo) == repo / ".lantern" and (repo / ".lantern").is_dir()
    (repo / ".lantern" / "kept.txt").write_text("kept", encoding="utf-8")
    assert results.folder(repo) == repo / ".lantern" and (repo / ".lantern" / "kept.txt").is_file()
    deep = tmp_path / "a" / "b" / "c"
    assert results.folder(repo, deep) == deep and deep.is_dir()             # --out: made with the folders above it
    inside = repo / "results" / "lantern"
    assert results.folder(repo, inside) == inside and inside.is_dir()       # and inside the project, through real folders
    assert pipeline.out_dir(repo) == repo / ".lantern"


# ---------------------------------------------------------------------------- explanations and their cache

@needs_links
def test_the_cache_of_explanations_is_not_kept_through_a_link(tmp_path):
    out = tmp_path / "out"
    elsewhere = tmp_path / "elsewhere"
    out.mkdir()
    elsewhere.mkdir()
    os.symlink(elsewhere, out / "cache")
    with pytest.raises(results.Refused) as said:
        explain.Cache(out / "cache")
    assert "cache" in str(said.value) and "is a link" in str(said.value)
    (out / "cache").unlink()
    cache = explain.Cache(out / "cache")                                    # the twin: a real folder, made when missing
    mine = tmp_path / "mine.txt"
    mine.write_text(MINE, encoding="utf-8")
    os.symlink(mine, out / "cache" / "abc.json")
    cache.put("abc", {"lens1": {"summary": "words"}})
    assert mine.read_text(encoding="utf-8") == MINE and list(elsewhere.iterdir()) == []
    assert cache.get("abc") == {"lens1": {"summary": "words"}} and not (out / "cache" / "abc.json").is_symlink()


# ---------------------------------------------------------------------------- lantern accept

@needs_links
def test_accepting_a_finding_does_not_write_through_a_link(tmp_path):
    """`lantern-accepted.json` lies in the project's own folder, so it comes with the project as well."""
    repo, mine = _project(tmp_path)
    os.symlink(mine, repo / security.ACCEPTED_FILE)
    security.save_accepted(repo, {"F1": {"id": "F1", "reason": "reviewed by the team lead"}})
    assert _left_alone(tmp_path)
    kept = repo / security.ACCEPTED_FILE
    assert not kept.is_symlink() and json.loads(kept.read_text(encoding="utf-8"))["accepted"][0]["id"] == "F1"


# ---------------------------------------------------------------------------- what the run says, what stays as it was

@needs_links
def test_what_a_write_met_is_said_once(tmp_path):
    out, other = tmp_path / "out", tmp_path / "other"
    out.mkdir()
    other.mkdir()
    mine = tmp_path / "mine.txt"
    mine.write_text(MINE, encoding="utf-8")
    os.symlink(mine, out / "run.json")
    os.mkfifo(out / "graph.json")
    os.symlink(mine, other / "run.json")
    for folder, name in ((out, "run.json"), (out, "graph.json"), (out, "calls.json"), (other, "run.json")):
        results.write(folder / name, "{}")
    assert results.said(out) == [
        "run.json in the results folder was a link; Lantern put its own file in its place and left what the link "
        "pointed at alone",
        "graph.json in the results folder was not a plain file (a pipe or a device); Lantern put its own file in its "
        "place"]                                                            # nothing about calls.json: nothing was there
    assert results.said(out) == []                                          # each sentence once
    assert len(results.said(other)) == 1 and results.said(other) == []      # the other folder's was still there to ask for
    for _again in range(2):                                                 # met twice before anybody asked: said once
        (out / "run.json").unlink()
        os.symlink(mine, out / "run.json")
        results.write(out / "run.json", "{}")
    assert len(results.said(out)) == 1
    assert mine.read_text(encoding="utf-8") == MINE


@needs_links
def test_no_more_than_200_sentences_wait_to_be_said(tmp_path):
    """An app that is left open for weeks and never asked keeps a fixed number of sentences, not all of them."""
    out = tmp_path / "out"
    out.mkdir()
    mine = tmp_path / "mine.txt"
    mine.write_text(MINE, encoding="utf-8")
    for n in range(201):
        os.symlink(mine, out / f"{n}.json")
        results.write(out / f"{n}.json", "{}")
    waiting = results.said(out)
    assert len(waiting) == 200 and waiting[0].startswith("0.json ") and waiting[-1].startswith("199.json ")
    assert mine.read_text(encoding="utf-8") == MINE                         # the 201st was replaced like the others
    assert not (out / "200.json").is_symlink()


@pytest.mark.skipif(os.name != "posix", reason="needs a POSIX system (file modes)")
def test_a_file_the_person_closed_to_others_stays_closed(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    kept = out / "security.json"
    kept.write_text("{}", encoding="utf-8")
    kept.chmod(0o600)
    results.write(kept, '{"findings": []}')
    assert kept.stat().st_mode & 0o777 == 0o600 and json.loads(kept.read_text(encoding="utf-8")) == {"findings": []}


def test_a_file_this_user_may_not_change_is_said_before_the_run(tmp_path, monkeypatch, capsys):
    """Writing the older way stopped at a result file its owner had marked read-only (with a Python error, after the
    whole analysis). Moving a new file into its place would not stop at all, so Lantern asks first."""
    repo, _mine = _project(tmp_path)
    assert main(["analyze", str(repo), "--offline"]) == 0
    kept = repo / ".lantern" / "report.html"
    before = _stamp(repo / ".lantern")
    capsys.readouterr()
    real = os.access

    def access(path, mode, **how):                                          # the system's answer for a read-only file
        return False if Path(path) == kept else real(path, mode, **how)
    monkeypatch.setattr(results.os, "access", access)
    assert main(["analyze", str(repo), "--offline"]) == 2
    err = capsys.readouterr().err
    assert "report.html" in err and "may not be changed by this user" in err and "Traceback" not in err
    assert _stamp(repo / ".lantern") == before                              # said before the run: no file of it is there
    with pytest.raises(results.Refused):
        results.write(kept, "another report")
    assert _stamp(repo / ".lantern") == before


def test_a_read_only_result_file_is_left_as_it_is(tmp_path):
    """The same against the system itself (not as root, who may change any file)."""
    out = tmp_path / "out"
    out.mkdir()
    kept = out / "baseline.json"
    kept.write_text("{}", encoding="utf-8")
    kept.chmod(0o444)
    try:
        if os.access(kept, os.W_OK):
            pytest.skip("this user may change any file (root): a read-only mark does not hold here")
        with pytest.raises(results.Refused) as said:
            results.write(kept, '{"first": 1}')
        assert "baseline.json" in str(said.value) and "read-only" in str(said.value)
        assert kept.read_text(encoding="utf-8") == "{}" and [x.name for x in out.iterdir()] == ["baseline.json"]
    finally:
        kept.chmod(0o644)


def test_no_result_file_is_written_any_other_way():
    """What keeps a later change from bringing the old way back: the modules that write result files hold no plain
    write of their own."""
    for name in ("pipeline.py", "graph.py", "calls.py", "evidence.py", "report.py", "explain.py", "security.py"):
        text = (Path(lantern.__file__).parent / name).read_text(encoding="utf-8")
        assert ".write_text(" not in text and ".write_bytes(" not in text and "open(" not in text, name


# ---------------------------------------------------------------------------- the results folder, named other ways

def test_a_results_folder_named_from_where_the_person_stands(tmp_path, monkeypatch):
    """The safe twin: `--out results` without a full path, given back as it was named."""
    repo, _mine = _project(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert results.folder(repo, "kept/here") == Path("kept/here") and (tmp_path / "kept" / "here").is_dir()
    assert main(["analyze", str(repo), "--offline", "--out", "kept/here"]) == 0
    assert (tmp_path / "kept" / "here" / "report.html").is_file() and not (repo / ".lantern").exists()


@needs_links
def test_a_project_reached_through_a_link_of_the_persons_own(tmp_path):
    """A shortcut to the project is the person's own and changes nothing; a link inside the project is refused by
    whatever way its folder is named."""
    repo, _mine = _project(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(repo, tmp_path / "shortcut")
    assert results.folder(tmp_path / "shortcut") == tmp_path / "shortcut" / ".lantern"
    assert main(["analyze", str(tmp_path / "shortcut"), "--offline"]) == 0
    assert (repo / ".lantern" / "report.html").is_file()
    os.symlink(elsewhere, repo / "build")
    with pytest.raises(results.Refused):
        results.folder(repo, tmp_path / "shortcut" / "build" / "out")
    with pytest.raises(results.Refused):
        results.folder(tmp_path / "shortcut", repo / "build" / "out")
    assert list(elsewhere.iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="needs Windows (a junction)")
def test_a_results_folder_that_is_a_junction_is_refused(tmp_path, capsys):
    """Windows: a junction is a link to a folder that any user may make."""
    import _winapi
    repo, _mine = _project(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _winapi.CreateJunction(str(elsewhere), str(repo / ".lantern"))
    assert main(["analyze", str(repo), "--offline"]) == 2
    err = capsys.readouterr().err
    assert ".lantern" in err and "is a link" in err and "Traceback" not in err
    assert list(elsewhere.iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="needs Windows (a junction)")
def test_on_windows_a_junction_under_a_result_files_name_is_replaced_as_itself(tmp_path):
    import _winapi
    out, kept = tmp_path / "out", tmp_path / "kept"
    out.mkdir()
    kept.mkdir()
    (kept / "mine.txt").write_text(MINE, encoding="utf-8")
    _winapi.CreateJunction(str(kept), str(out / "report.html"))
    results.write(out / "report.html", "<p>the report</p>", newline="\n")
    assert (out / "report.html").read_bytes() == b"<p>the report</p>"
    assert [x.name for x in kept.iterdir()] == ["mine.txt"] and (kept / "mine.txt").read_text(encoding="utf-8") == MINE
    assert results.said(out) == ["report.html in the results folder was a link; Lantern put its own file in its "
                                 "place and left what the link pointed at alone"]


@pytest.mark.skipif(os.name != "nt", reason="needs Windows (its symbolic links)")
def test_on_windows_a_symbolic_link_under_a_result_files_name_is_replaced_as_itself(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    mine = tmp_path / "mine.txt"
    mine.write_text(MINE, encoding="utf-8")
    try:
        os.symlink(mine, out / "run.json")
    except OSError:
        pytest.skip("this Windows sign-in may not make symbolic links")
    results.write(out / "run.json", "{}")
    assert (out / "run.json").read_bytes() == b"{}" and not (out / "run.json").is_symlink()
    assert mine.read_text(encoding="utf-8") == MINE


# ---------------------------------------------------------------------------- the cache, read

def test_a_file_where_the_cache_belongs_is_refused_in_plain_words(tmp_path):
    (tmp_path / "cache").write_text("not a folder", encoding="utf-8")
    with pytest.raises(results.Refused) as said:
        explain.Cache(tmp_path / "cache")
    assert "cache" in str(said.value) and "is not a folder" in str(said.value)
    assert (tmp_path / "cache").read_text(encoding="utf-8") == "not a folder"


def test_the_cache_folder_is_made_when_missing_and_used_when_there(tmp_path):
    """The safe twin of the two refusals: an ordinary cache folder, on the first run and on every later one."""
    first = explain.Cache(tmp_path / "out" / "cache")
    first.put("abc", {"lens1": {"summary": "words"}})
    assert (tmp_path / "out" / "cache").is_dir()
    assert explain.Cache(tmp_path / "out" / "cache").get("abc") == {"lens1": {"summary": "words"}}


@needs_links
def test_the_cache_reads_no_link_and_waits_on_no_pipe(tmp_path):
    cache = explain.Cache(tmp_path / "cache")
    record = tmp_path / "record.json"
    record.write_text('{"lens1": {"summary": "words of another project"}}', encoding="utf-8")
    os.symlink(record, tmp_path / "cache" / "abc.json")
    assert cache.get("abc") is None                                         # before: the linked file's record
    os.mkfifo(tmp_path / "cache" / "def.json")
    done: list = []
    ask = threading.Thread(target=lambda: done.append(cache.get("def")), daemon=True)
    ask.start()
    ask.join(20)
    try:
        assert done == [None], "the cache is still waiting for the pipe"
    finally:
        if not done:
            try:
                os.close(os.open(tmp_path / "cache" / "def.json", os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
    cache.put("ghi", {"lens1": {"summary": "words"}})                       # the twin: a record of its own comes back
    assert cache.get("ghi") == {"lens1": {"summary": "words"}}


# ---------------------------------------------------------------------------- export, the app, the connector

@needs_links
def test_export_puts_its_file_in_the_place_of_a_link_that_came_with_the_project(tmp_path, capsys):
    repo, mine = _project(tmp_path)
    assert main(["analyze", str(repo), "--offline"]) == 0
    os.symlink(mine, repo / "findings.sarif")
    capsys.readouterr()
    assert main(["export", str(repo), "--sarif", str(repo / "findings.sarif")]) == 0
    assert _left_alone(tmp_path) and not (repo / "findings.sarif").is_symlink()
    assert json.loads((repo / "findings.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert "findings.sarif in the project folder was a link" in capsys.readouterr().err


@needs_links
def test_export_follows_a_link_of_the_persons_own(tmp_path):
    """The safe twin: a name outside the project is the person's, written as they wrote it (`latest.sarif` kept as a
    link to the newest report, `/dev/stdout`)."""
    repo, _mine = _project(tmp_path)
    assert main(["analyze", str(repo), "--offline"]) == 0
    (tmp_path / "reports").mkdir()
    os.symlink(tmp_path / "reports" / "today.sarif", tmp_path / "latest.sarif")
    assert main(["export", str(repo), "--sarif", str(tmp_path / "latest.sarif")]) == 0
    assert (tmp_path / "latest.sarif").is_symlink()
    assert json.loads((tmp_path / "reports" / "today.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"


def _stamp(folder: Path) -> list:
    return sorted((x.name, x.stat().st_mtime_ns, x.stat().st_size) for x in folder.iterdir())


@needs_links
def test_the_app_reads_and_writes_nothing_through_a_linked_results_folder(tmp_path):
    """The link points at the results of another project of the person: the card must not show them as this
    project's, and a check must not replace them."""
    from lantern.server import App, Store
    repo, _mine = _project(tmp_path)
    other = _write(tmp_path / "other", APP)
    elsewhere = tmp_path / "elsewhere"
    assert main(["analyze", str(other), "--offline", "--out", str(elsewhere)]) == 0
    before = _stamp(elsewhere)
    os.symlink(elsewhere, repo / ".lantern")
    store = Store(tmp_path / "home")
    store.root.mkdir()
    app = App(store, "tok", 0)
    p = store.add_project(repo)
    card = app.summary(p)
    assert card["has_report"] is False and card["score"] is None and card["counts"] is None    # before: the other project's
    with pytest.raises(results.Refused) as said:
        app.out(p)
    assert "is a link" in str(said.value) and _stamp(elsewhere) == before
    (repo / ".lantern").unlink()                                            # the twin: a results folder of its own
    pipeline.analyze(repo, app.out(p), log=lambda line: None, offline=True)
    card = app.summary(p)
    assert card["has_report"] is True and isinstance(card["score"], int) and card["counts"]["critical"] >= 0


def test_a_folder_the_system_will_not_show_is_not_called_a_link(tmp_path, monkeypatch):
    """Where the system refuses the look itself (a folder above that is closed to this user), Lantern claims nothing
    about a link: the app's card goes on to its read and making the folder goes on to the system, which both say why."""
    repo, _mine = _project(tmp_path)

    def closed(path):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(results, "_look", closed)
    assert results.link_in_project(repo, repo / ".lantern") is False
    assert results.folder(repo) == repo / ".lantern" and (repo / ".lantern").is_dir()


@needs_links
def test_the_connector_checks_nothing_into_a_linked_results_folder(tmp_path, monkeypatch):
    """`lantern_recheck` names the results folder itself, so the check is made again where the run starts."""
    from lantern.mcp_server import Projects, Server
    monkeypatch.setenv("LANTERN_HOME", str(tmp_path / "home"))
    repo, _mine = _project(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    assert main(["analyze", str(repo), "--offline", "--out", str(elsewhere)]) == 0
    finding = json.loads((elsewhere / "security.json").read_text(encoding="utf-8"))["findings"][0]["id"]
    before = _stamp(elsewhere)
    os.symlink(elsewhere, repo / ".lantern")
    server = Server(Projects([str(repo)]))
    for tool, args in (("lantern_analyze", {}), ("lantern_recheck", {"finding": finding})):
        answer = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                "params": {"name": tool, "arguments": {"project": "project", "offline": True, **args}}})
        said = answer["result"]
        assert said["isError"] and "is a link" in said["content"][0]["text"], tool
        assert "Traceback" not in said["content"][0]["text"] and _stamp(elsewhere) == before, tool
