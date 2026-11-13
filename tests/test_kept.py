"""Directive point 10: work kept between runs (`lantern/kept.py`), and the proof that it changes no result.

    the same question, the same answer     a kept answer is used only for exactly the question it was worked out
                                            for: the same bytes under the same name, the same code doing the work
    what comes back is what went in         every value a reader keeps reads back equal, with the same types and
                                            in the same order; what is not plain data is not kept at all
    an entry that is not whole is none      cut short, of another shape, somebody else's, a link: the work is done
    never in the project                    nothing is written to or read from the analysed folder
    with and without, the same results      every sample app gives the same result files with kept work off, on
                                            and empty, and on and full
    off where it must be                    `LANTERN_CACHE=off`, the cloud's runs, `lantern verify`
    bounded                                 what nobody asked for in a month goes; the folder stays under its cap
"""
import json
import os
import shutil
import sys
import threading
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path

import pytest

import lantern_files
from lantern import cli, evidence, kept, pipeline, python_frontend, scanresult, security

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bench"))
import speed  # noqa: E402  (bench/speed.py)

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLES = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir() and p.name != "old_results")
QUIET = lambda line: None  # noqa: E731


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    """Every test keeps its work in a folder of its own, and starts with kept work switched on."""
    monkeypatch.setenv("LANTERN_HOME", str(tmp_path / "lantern-home"))
    monkeypatch.delenv("LANTERN_CACHE", raising=False)
    monkeypatch.delenv("LANTERN_CACHE_MB", raising=False)
    monkeypatch.delenv("LANTERN_CLOUD_RUN", raising=False)


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def same(a, b, where="value"):
    """Equal, of the same types all the way down, and in the same order."""
    assert type(a) is type(b), (where, type(a), type(b))
    if is_dataclass(a):
        for f in fields(a):
            same(getattr(a, f.name), getattr(b, f.name), f"{where}.{f.name}")
    elif isinstance(a, dict):
        assert list(a) == list(b), where
        for (ka, va), (kb, vb) in zip(a.items(), b.items()):
            same(ka, kb, f"{where} key")
            same(va, vb, f"{where}[{ka!r}]")
    elif isinstance(a, (list, tuple)):
        assert len(a) == len(b), where
        for i, (x, y) in enumerate(zip(a, b)):
            same(x, y, f"{where}[{i}]")
    else:
        assert a == b, where


@dataclass
class Inner:
    name: str
    at: tuple[int, int] | None = None
    tags: set[str] = field(default_factory=set)


@dataclass
class Outer:
    title: str
    rows: list[Inner] = field(default_factory=list)
    by_name: dict[str, Inner] = field(default_factory=dict)
    odd: object = None


@dataclass
class NotNamed:
    x: int = 0


@dataclass
class Bare:
    """A record with no fields at all: its name is the whole of it."""


SHELF = kept.Shelf("test-values", classes=(Inner, Outer, Bare))

VALUES = [
    None, True, False, 0, -7, 2 ** 70, 1.5, -0.0, float("inf"), "", "text", "café ſ \U0001f512", "\ud800 half a pair",
    "\x01t looks like a mark", [], [1, "two", None], ["\x01t", 1], ["\x01c", "Inner", "x", None, []], [["\x01s"], []],
    (), (1, 2), ((1, 2), (3,)), ("\x01l",), set(), {"b", "a"}, frozenset(), frozenset({1, 2}), {(1, 2), (3, 4)},
    {}, {"a": 1, "b": [1, (2, 3)]}, {"z": 1, "a": 2}, {1: "one", 2: "two"}, {(1, 2): "pair", None: "nothing", True: "yes"},
    {"\x01t": 1}, {"k": {"\x01c": []}},
    Inner("f"), Inner("g", (3, 4), {"x", "y"}),
    Outer("o", [Inner("a"), Inner("b", (1, 1))], {"a": Inner("a", None, {"t"})}, odd=[(1, {"k": frozenset({"v"})})]),
    [Outer("deep", odd={"list": [Inner("z")], "tuple": (Inner("y"),)})],
    Bare(), [Bare(), Inner("beside")],
    Inner(3, (1, 2)),       # a record's first field need not be text
]


@pytest.mark.parametrize("i", range(len(VALUES)))
def test_what_is_kept_reads_back_as_it_was(i):
    value = VALUES[i]
    key = SHELF.key("value", str(i))
    assert key and SHELF.get(key) is kept.NOTHING
    assert SHELF.put(key, value)
    same(SHELF.get(key), value)
    same(SHELF.get(key), value)         # and again: reading takes nothing away


class Text(str):
    pass


@pytest.mark.parametrize("value", [Path("/somewhere/else"), b"bytes", object(), NotNamed(1), [NotNamed(2)], Text("mine"),
                                   {"k": Path("x")}, Inner(Text("name")), lambda: 1, {1, 2}.__iter__(), 3 + 4j])
def test_what_is_not_plain_data_is_not_kept(value):
    key = SHELF.key("not kept")
    assert not SHELF.put(key, value)
    assert SHELF.get(key) is kept.NOTHING
    assert kept.size() == (0, 0)


def test_a_record_class_must_be_named_to_be_read():
    key = SHELF.key("k")
    assert SHELF.put(key, Inner("f"))
    other = kept.Shelf("test-values", classes=(Outer,))     # the same kind of work, read by code that names no Inner
    assert other.key("k") != key                            # ... which is another question in the first place
    assert other._read(key) is kept.NOTHING                 # ... and could not read the answer if it were not


def test_only_record_classes_can_be_named_for_a_kind_of_kept_work():
    for wrong in (Path, int, Inner("an instance, not the class")):
        with pytest.raises(TypeError, match="only record classes"):
            kept.Shelf("test-other", classes=(wrong,))
    for wrong in ("Not A Kind", "", "../python-file", "9lives"):
        with pytest.raises(ValueError, match="small letters"):
            kept.Shelf(wrong)


def test_the_key_is_the_whole_question(monkeypatch):
    k = SHELF.key
    assert k("a", "b") == k("a", "b") and len(k("a", "b")) == 64
    different = {k("a", "b"), k("a", "c"), k("b", "a"), k("ab"), k("a", "b", ""), k("a", b"b\0"), k("a"), k(),
                 k("ab", "c"), k("a", "bc"), kept.Shelf("test-other", classes=(Inner, Outer)).key("a", "b"),
                 kept.Shelf("test-values", classes=(Inner,)).key("a", "b")}
    assert len(different) == 12
    assert k("a", b"b") == k("a", "b")                      # text and its bytes are one part
    before = k("a", "b")
    # another Lantern (any file of its code changed), another Python, another parser library: another question
    monkeypatch.setitem(kept._DIGESTS, "", b"another lantern")
    again = kept.Shelf("test-values", classes=(Inner, Outer))
    assert again.key("a", "b") not in (None, before)
    with_lib = kept.Shelf("test-values", classes=(Inner, Outer), libraries=("json",))
    with_other = kept.Shelf("test-values", classes=(Inner, Outer), libraries=("re",))
    assert len({again.key("a"), with_lib.key("a"), with_other.key("a")}) == 3
    monkeypatch.setitem(kept._DIGESTS, "json", b"json as it was upgraded")
    assert kept.Shelf("test-values", classes=(Inner, Outer), libraries=("json",)).key("a") != with_lib.key("a")


def test_code_that_cannot_be_read_keeps_nothing(monkeypatch):
    gone = kept.Shelf("test-values", classes=(Inner,), libraries=("a_library_that_is_not_installed",))
    assert gone.stamp() is None and gone.key("a") is None
    assert not gone.put(gone.key("a"), 1) and gone.get(gone.key("a")) is kept.NOTHING
    monkeypatch.setitem(kept._DIGESTS, "", None)            # Lantern's own files could not be read
    assert kept.Shelf("test-values").key("a") is None


def test_the_stamp_reads_every_file_of_the_code(tmp_path, monkeypatch):
    pkg = _write(tmp_path / "lib" / "kept_probe_lib", {"__init__.py": "X = 1\n", "inner/deep.py": "Y = 2\n",
                                                        "data.bin": "compiled part\n"})
    monkeypatch.syspath_prepend(str(pkg.parent))
    monkeypatch.delitem(sys.modules, "kept_probe_lib", raising=False)

    def stamp():
        kept._DIGESTS.pop("kept_probe_lib", None)
        return kept.Shelf("test-values", libraries=("kept_probe_lib",)).stamp()

    first = stamp()
    assert first and stamp() == first
    for name, text in (("inner/deep.py", "Y = 3\n"), ("data.bin", "compiled anew\n"), ("added.py", "Z = 1\n")):
        _write(pkg, {name: text})
        changed = stamp()
        assert changed != first, name
        first = changed
    _write(pkg, {"__pycache__/x.pyc": "what Python wrote for itself"})
    assert stamp() == first
    kept._DIGESTS.pop("kept_probe_lib", None)


@pytest.mark.parametrize("said, on", [("off", False), ("OFF", False), (" 0 ", False), ("no", False), ("false", False),
                                      ("", True), ("on", True), ("1", True), ("anything else", True)])
def test_the_switch(monkeypatch, said, on):
    monkeypatch.setenv("LANTERN_CACHE", said)
    assert kept.on() is on
    assert (SHELF.key("a") is not None) is on
    assert SHELF.put(SHELF.key("a"), [1]) is on
    assert (SHELF.get(SHELF.key("a")) == [1]) is on


def test_off_in_the_clouds_runs_and_inside_without(monkeypatch):
    assert kept.on()
    with kept.without():
        assert not kept.on() and SHELF.key("a") is None
        with kept.without():
            assert not kept.on()
        assert not kept.on()
    assert kept.on()
    seen = []
    t = threading.Thread(target=lambda: seen.append(kept.on()))      # a block is for the code inside it only
    with kept.without():
        t.start()
        t.join()
    assert seen == [True]
    monkeypatch.setenv("LANTERN_CLOUD_RUN", "1")
    assert not kept.on()


# ------------------------------------------------------------------------------------------- an entry that is not whole
def _entry(key: str) -> Path:
    return SHELF._path(key)


def test_an_entry_that_is_not_whole_is_no_entry(tmp_path):
    key, other = SHELF.key("one"), SHELF.key("two")
    assert SHELF.put(key, Outer("o", [Inner("a")])) and SHELF.put(other, [1, 2])
    whole = _entry(key).read_bytes()
    for what, data in [("cut short", whole[: len(whole) // 2]), ("empty", b""), ("not JSON", b"\x00\x01 no"),
                       ("a list", b"[1]"), ("no answer in it", json.dumps({"k": key}).encode()),
                       ("another question's", _entry(other).read_bytes()),
                       ("a record of another shape", json.dumps({"k": key, "v": ["\x01c", "Inner", "only one"]}).encode()),
                       ("a record with a field too many",
                        json.dumps({"k": key, "v": ["\x01c", "Inner", "a", None, ["\x01s"], "one more"]}).encode()),
                       ("a class nobody named", json.dumps({"k": key, "v": ["\x01c", "Path", "/etc/passwd"]}).encode()),
                       ("a class's name that is no text", json.dumps({"k": key, "v": ["\x01c", 7]}).encode()),
                       ("a mark nobody knows", json.dumps({"k": key, "v": ["\x01x", 1]}).encode()),
                       ("a table that is no table", json.dumps({"k": key, "v": ["\x01d", 1]}).encode()),
                       ("a set of lists", json.dumps({"k": key, "v": ["\x01s", [1]]}).encode()),
                       ("not UTF-8", b'{"k": "' + key.encode() + b'", "v": "\xff"}')]:
        _entry(key).write_bytes(data)
        assert SHELF.get(key) is kept.NOTHING, what
    _entry(key).write_bytes(whole)
    same(SHELF.get(key), Outer("o", [Inner("a")]))      # the safe twin: the whole entry is read


@pytest.mark.skipif(sys.platform == "win32", reason="needs the right to make a link")
def test_an_entry_is_never_read_through_a_link(tmp_path):
    key, other = SHELF.key("one"), SHELF.key("two")
    assert SHELF.put(other, "the other answer")
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_bytes(json.dumps({"k": key, "v": "planted"}).encode())
    _entry(key).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(elsewhere, _entry(key))
    assert SHELF.get(key) is kept.NOTHING
    os.unlink(_entry(key))
    _entry(key).mkdir()                                  # a folder under an entry's name
    assert SHELF.get(key) is kept.NOTHING and not SHELF.put(key, "x") or SHELF.get(key) is kept.NOTHING
    assert SHELF.get(other) == "the other answer"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_what_is_kept_is_closed_to_other_users():
    key = SHELF.key("private")
    assert SHELF.put(key, ["names and lines of the code"])
    entry = _entry(key)
    assert entry.stat().st_mode & 0o777 == 0o600
    for folder in (entry.parent, entry.parent.parent, kept.home()):
        assert folder.stat().st_mode & 0o777 == 0o700, folder
    assert not [p for p in entry.parent.iterdir() if p.name.endswith(".tmp")]       # nothing half-written is left
    assert kept.tidy(now=entry.stat().st_mtime, force=True) == 0 and entry.exists()
    assert (kept.home() / ".tidied").stat().st_mode & 0o777 == 0o600                # the mark of the last look too


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX owners")
def test_an_entry_of_another_user_is_not_used(monkeypatch):
    key = SHELF.key("whose")
    assert SHELF.put(key, [1]) and SHELF.get(key) == [1]
    me = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: me + 1)       # as if somebody else had put the entry there
    assert SHELF.get(key) is kept.NOTHING


def _race(key, value, writers: int = 6, times: int = 20) -> list[bool]:
    """What every write said, when `writers` threads each put the same answer under the same key `times` times."""
    done = []

    def write():
        for _ in range(times):
            done.append(SHELF.put(key, value))

    threads = [threading.Thread(target=write) for _ in range(writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return done


def test_two_writers_of_one_answer_leave_one_whole_entry(monkeypatch):
    """Linux and macOS never refuse to put a finished file in an entry's place, so there every writer keeps its
    answer. Windows refuses while another writer is putting the same entry there (PermissionError; the first run of
    this test on Windows showed it, 2026-11-12): that write is not kept and says so, the other writer's is, and it
    is the same answer. On every system: no write is lost for any other reason, the entry is whole, nothing
    unfinished is left."""
    key = SHELF.key("raced")
    value = Outer("o", [Inner(str(i), (i, i)) for i in range(300)])
    refused, real = [], os.replace

    def replace(src, dst):
        try:
            real(src, dst)
        except OSError as exc:
            refused.append(type(exc).__name__)
            raise

    monkeypatch.setattr(os, "replace", replace)
    done = _race(key, value)
    assert len(done) == 120 and any(done)
    assert done.count(False) == len(refused) and set(refused) <= {"PermissionError"}
    if os.name == "posix":
        assert all(done)
    same(SHELF.get(key), value)
    assert kept.size()[0] == 1 and not list(kept._entries(left=True))


def test_a_write_the_system_refuses_beside_another_writer_is_not_kept_and_breaks_nothing(monkeypatch):
    """What Windows does to two writers of one entry, played on every system: while one writer is putting its file
    in the entry's place, the other's is refused. The first writer here holds the place until a second has come and
    been refused, so the meeting happens in every run."""
    key = SHELF.key("raced, the way Windows answers")
    value = Outer("o", [Inner(str(i), (i, i)) for i in range(300)])
    busy, met, refused, real = threading.Lock(), threading.Event(), [], os.replace

    def replace(src, dst):
        if not busy.acquire(blocking=False):
            refused.append(Path(dst).name)
            met.set()
            raise PermissionError(13, "Access is denied", str(dst))
        try:
            met.wait(10)
            real(src, dst)
        finally:
            busy.release()

    monkeypatch.setattr(os, "replace", replace)
    done = _race(key, value)
    assert refused and set(refused) == {kept.Shelf._path(SHELF, key).name}
    assert len(done) == 120 and any(done) and done.count(False) == len(refused)
    same(SHELF.get(key), value)
    assert kept.size()[0] == 1 and not list(kept._entries(left=True))


# ------------------------------------------------------------------------------------------- the Python reader
def _python_files() -> list[Path]:
    """Every Python file of this repository: Lantern itself (the package Python loaded, wherever it is installed),
    and from the checkout the sample apps, its services, tools and tests."""
    root = Path(__file__).resolve().parents[1]
    return lantern_files.modules(deep=True) + [
        p for folder in ("gateway", "cloud", "tools", "bench", "examples", "tests")
        for p in sorted((root / folder).rglob("*.py")) if "old_results" not in p.parts]


def test_a_python_file_reads_the_same_from_kept_work(tmp_path):
    """Every Python file of the sample apps and of Lantern itself: read with kept work off, read and kept, and read
    back from what was kept. The three are equal in every field, with the same types, in the same order."""
    from tree_sitter import Parser
    parser = Parser(python_frontend.PY_LANGUAGE)
    files = _python_files()
    assert len(files) > 100
    defs = calls = 0
    for path in files:
        repo = path.parent
        with kept.without():
            plain = python_frontend.parse_module(path, "pkg." + path.stem, repo, parser)
        with kept.tally() as first:
            fresh = python_frontend.parse_module(path, "pkg." + path.stem, repo, parser)
        with kept.tally() as second:
            again = python_frontend.parse_module(path, "pkg." + path.stem, repo, parser)
        assert first.table() == {"python-file": {"reused": 0, "anew": 1}}, path
        assert second.table() == {"python-file": {"reused": 1, "anew": 0}}, path
        same(fresh, plain, path.name)
        same(again, plain, path.name)
        assert again.path == path
        defs += len(plain.defs)
        calls += len(plain.calls)
    assert defs > 2000 and calls > 20000        # the proof is not about empty files


def test_a_python_file_is_read_anew_when_anything_about_it_changed(tmp_path):
    from tree_sitter import Parser
    parser = Parser(python_frontend.PY_LANGUAGE)
    repo = _write(tmp_path / "p", {"pkg/a.py": "def f():\n    return g()\n", "pkg/b.py": "def f():\n    return g()\n"})

    def read(rel, mod):
        with kept.tally() as t:
            info = python_frontend.parse_module(repo / rel, mod, repo, parser)
        return info, t.table()["python-file"]["reused"]

    assert read("pkg/a.py", "pkg.a")[1] == 0
    info, reused = read("pkg/a.py", "pkg.a")
    assert reused == 1 and info.rel == "pkg/a.py" and info.name == "pkg.a" and info.path == repo / "pkg/a.py"
    assert read("pkg/b.py", "pkg.b")[1] == 0                # the same bytes under another name: another question
    assert read("pkg/a.py", "other.a")[1] == 0              # the same file read as another module
    (repo / "pkg/a.py").write_text("def f():\n    return h()\n", encoding="utf-8")
    info, reused = read("pkg/a.py", "pkg.a")
    assert reused == 0 and [c.text for c in info.calls] == ["h"]
    (repo / "pkg/a.py").write_text("def f():\n    return g()\n", encoding="utf-8")
    info, reused = read("pkg/a.py", "pkg.a")                # changed back: the first answer is the answer again
    assert reused == 1 and [c.text for c in info.calls] == ["g"]
    moved = tmp_path / "moved"
    shutil.copytree(repo, moved)
    with kept.tally() as t:                                  # the same project in another folder: the answer holds
        info = python_frontend.parse_module(moved / "pkg/a.py", "pkg.a", moved, parser)   # nothing of where it lay
    assert t.table()["python-file"]["reused"] == 1 and info.path == moved / "pkg/a.py"


# ------------------------------------------------------------------------------------------- whole runs
SMALL = {
    "app.py": "import subprocess\n\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n"
              "@app.route('/run')\ndef run():\n    return subprocess.check_output('ls ' + request.args['d'], shell=True)\n",
    "helpers.py": "import hashlib\n\n\ndef mark(text):\n    return hashlib.md5(text.encode()).hexdigest()\n",
    "web/main.js": "export function go() { return fetch('/run?d=' + location.hash) }\n",
    "requirements.txt": "flask==3.0.0\n",
}


def _all_files(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


@pytest.mark.parametrize("sample", SAMPLES)
def test_a_sample_gives_the_same_results_with_kept_work_and_without(sample, tmp_path, monkeypatch):
    repo = tmp_path / sample
    shutil.copytree(FIXTURES / sample, repo, ignore=shutil.ignore_patterns(".lantern", "node_modules", "__pycache__"))
    before = _all_files(repo)
    monkeypatch.setenv("LANTERN_CACHE", "off")
    pipeline.analyze(repo, tmp_path / "off", log=QUIET, offline=True)
    assert kept.size() == (0, 0)
    monkeypatch.delenv("LANTERN_CACHE")
    pipeline.analyze(repo, tmp_path / "empty", log=QUIET, offline=True)
    said = []
    pipeline.analyze(repo, tmp_path / "full", log=said.append, offline=True)
    off, empty, full = (speed.fingerprint(tmp_path / name) for name in ("off", "empty", "full"))
    assert len(off) == 11 and len(off[speed.REPORT_DATA]) == 64     # every result file, and what the report holds
    assert speed.differing(off, empty) == [] and speed.differing(off, full) == []
    assert _all_files(repo) == before                   # nothing was written into the project
    run = json.loads((tmp_path / "full" / "run.json").read_text(encoding="utf-8"))
    if any(name.endswith(".py") for name in before):
        assert run["kept"]["python-file"]["reused"] > 0 and run["kept"]["python-file"]["anew"] == 0
        assert any(line.startswith("kept    ") and "python-file" in line for line in said)
        assert "kept" not in json.loads((tmp_path / "off" / "run.json").read_text(encoding="utf-8"))
    for name in ("security.json", "readiness.json", "evidence.json", "report.html", "graph.json"):
        assert '"kept"' not in (tmp_path / "full" / name).read_text(encoding="utf-8"), name


def test_nothing_is_kept_in_the_project_or_its_results(tmp_path):
    repo = _write(tmp_path / "p", SMALL)
    before = _all_files(repo)
    out = repo / ".lantern"
    pipeline.analyze(repo, out, log=QUIET, offline=True)
    pipeline.analyze(repo, out, log=QUIET, offline=True)
    now = _all_files(repo)
    assert {n for n in now if not n.startswith(".lantern/")} == set(before)
    assert not [n for n in now if "cache" in n.lower()]
    n, size = kept.size()
    assert n >= 3 and size > 0
    assert all(Path(os.environ["LANTERN_HOME"]) in path.parents for path, _ in kept._entries())


# ------------------------------------------------------------------------------------------- Bandit
def _count_bandit(monkeypatch) -> list:
    started = []
    real = scanresult.run_tool

    def run_tool(cmd, **kw):
        if "bandit" in cmd:
            started.append(list(cmd))
        return real(cmd, **kw)

    monkeypatch.setattr(scanresult, "run_tool", run_tool)
    return started


def _still(findings_and_record):
    findings, record = findings_and_record
    return findings, {k: v for k, v in record.items() if k != "duration_ms"}


def test_bandit_is_not_run_again_on_the_same_files(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL)
    started = _count_bandit(monkeypatch)
    first = security.run_bandit(repo)
    assert len(started) == 1 and first[1]["state"] == "ok" and {f["rule"] for f in first[0]} >= {"B602", "B324"}
    with kept.tally() as t:
        again = security.run_bandit(repo)
    assert len(started) == 1 and t.table() == {"bandit": {"reused": 1, "anew": 0}}
    assert _still(again) == _still(first)
    # a file that is not Python changed: the question to Bandit is the same
    (repo / "web/main.js").write_text("export const x = 1\n", encoding="utf-8")
    (repo / "notes.txt").write_text("nothing Bandit reads\n", encoding="utf-8")
    assert _still(security.run_bandit(repo)) == _still(first) and len(started) == 1


CHANGES = {
    "a Python file changed": lambda repo: (repo / "helpers.py").write_text("import hashlib\n\n\ndef mark(t):\n    return 1\n",
                                                                           encoding="utf-8"),
    "a Python file added": lambda repo: (repo / "more.py").write_text("import pickle\n", encoding="utf-8"),
    "a Python file added in a folder": lambda repo: _write(repo, {"deep/er/x.py": "eval(input())\n"}),
    "a Python file removed": lambda repo: (repo / "helpers.py").unlink(),
    "a Python file renamed": lambda repo: (repo / "helpers.py").rename(repo / "helper.py"),
    "a .pyw file added": lambda repo: (repo / "tool.pyw").write_text("import pickle\n", encoding="utf-8"),
    "a folder Bandit is told to leave out appeared": lambda repo: _write(repo, {"node_modules/x/y.py": "eval('1')\n"}),
}


@pytest.mark.parametrize("what", sorted(CHANGES))
def test_bandit_runs_again_when_the_files_it_reads_are_not_the_same(what, tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL)
    started = _count_bandit(monkeypatch)
    security.run_bandit(repo)
    security.run_bandit(repo)
    assert len(started) == 1
    CHANGES[what](repo)
    with kept.tally() as t:
        after = security.run_bandit(repo)
    assert len(started) == 2 and t.table() == {"bandit": {"reused": 0, "anew": 1}}, what
    with kept.without():
        plain = security.run_bandit(repo)
    assert len(started) == 3 and _still(after) == _still(plain)


def test_bandit_runs_again_in_another_folder_and_with_other_plugins(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL)
    started = _count_bandit(monkeypatch)
    first = security.run_bandit(repo)
    copy = tmp_path / "copy"
    shutil.copytree(repo, copy)
    there = security.run_bandit(copy)       # Bandit writes full paths: what it said about one folder is about that one
    assert len(started) == 2 and [f["file"] for f in there[0]] == [f["file"] for f in first[0]]
    from importlib import metadata
    real = metadata.entry_points

    class Extra:
        name, value, dist = "extra_check", "somebody.plugin:check", None

    monkeypatch.setattr(metadata, "entry_points", lambda **kw: list(real(**kw)) + [Extra])
    security.run_bandit(repo)               # a plug-in was installed for Bandit since: it may find other things
    assert len(started) == 3


def test_a_bandit_run_that_did_not_end_as_a_scan_is_not_kept(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL)
    answers = [scanresult.ToolRun(2, "", "bandit: something went wrong"),
               scanresult.ToolRun(None, timed_out=True),
               scanresult.ToolRun(None, error="OSError: no such program"),
               scanresult.ToolRun(0, "this is not JSON", ""),
               scanresult.ToolRun(1, json.dumps({"errors": []}), "")]
    real = scanresult.run_tool
    started = []

    def run_tool(cmd, **kw):
        started.append(1)
        return answers.pop(0) if answers else real(cmd, **kw)

    monkeypatch.setattr(scanresult, "run_tool", run_tool)
    for state in ("failed", "timeout", "failed", "failed", "failed"):
        assert security.run_bandit(repo)[1]["state"] == state
    assert len(started) == 5 and kept.size() == (0, 0)
    assert security.run_bandit(repo)[1]["state"] == "ok" and len(started) == 6     # the real one: run, and kept
    assert security.run_bandit(repo)[1]["state"] == "ok" and len(started) == 6


def test_what_bandit_could_not_read_is_said_again_from_kept_work(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", dict(SMALL, **{"broken.py": "def broken(:\n    pass\n"}))
    started = _count_bandit(monkeypatch)
    first = security.run_bandit(repo)
    again = security.run_bandit(repo)
    assert len(started) == 1 and first[1]["state"] == "partial" and "broken.py" in first[1]["errors"][0]
    assert _still(again) == _still(first)


def test_a_nosec_comment_is_read_in_every_run(tmp_path, monkeypatch):
    """What Bandit said is kept; what the project's comments say about it is read from the files in every run."""
    repo = _write(tmp_path / "p", {"a.py": "import hashlib\n\n\ndef mark(t):\n    return hashlib.md5(t).hexdigest()\n"})
    started = _count_bandit(monkeypatch)
    plain = security.run_bandit(repo)[0]
    assert plain and not plain[0].get("nosec")
    (repo / "notes.md").write_text("a change Bandit does not read\n", encoding="utf-8")
    assert security.run_bandit(repo)[0] == plain and len(started) == 1
    (repo / "a.py").write_text("import hashlib\n\n\ndef mark(t):\n    return hashlib.md5(t).hexdigest()  # nosec B324 a "
                               "file's name on disk, nothing secret\n", encoding="utf-8")
    said = security.run_bandit(repo)[0]
    assert len(started) == 2 and said[0]["nosec"]["reason"]


# ------------------------------------------------------------------------------------------- where it is off
def test_verify_does_all_of_the_work_again(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL)
    out = tmp_path / "out"
    pipeline.analyze(repo, out, log=QUIET, offline=True)
    pipeline.analyze(repo, out, log=QUIET, offline=True)
    started = _count_bandit(monkeypatch)
    parsed = []
    real = python_frontend._visit_body
    monkeypatch.setattr(python_frontend, "_visit_body", lambda *a, **kw: (parsed.append(1), real(*a, **kw))[1])
    pipeline.analyze(repo, out, log=QUIET, offline=True)
    assert not started and not parsed                       # an ordinary run: everything from kept work
    ev = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    with kept.tally() as t:
        res = evidence.verify(repo, ev["digest"], ev.get("payload"), offline=True, beside=out)
    assert res["match"] is True
    assert len(started) == 1 and len(parsed) == 2           # Bandit was run and both Python files were read again
    assert t.table() == {}                                  # nothing was asked of kept work
    assert kept.on()


def test_a_cloud_run_keeps_nothing_and_uses_nothing(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL)
    pipeline.analyze(repo, tmp_path / "here", log=QUIET, offline=True)
    kept_here = kept.size()
    assert kept_here[0] >= 3
    monkeypatch.setenv("LANTERN_CLOUD_RUN", "1")
    started = _count_bandit(monkeypatch)
    said = []
    pipeline.analyze(repo, tmp_path / "cloud", log=said.append, offline=True)
    assert len(started) == 1 and kept.size() == kept_here
    assert not [line for line in said if line.startswith("kept ")]
    assert "kept" not in json.loads((tmp_path / "cloud" / "run.json").read_text(encoding="utf-8"))


def test_the_scanners_beside_the_reading_are_counted_with_the_run(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL)
    monkeypatch.setenv("LANTERN_JOBS", "2")
    pipeline.analyze(repo, tmp_path / "one", log=QUIET, offline=True)
    first = json.loads((tmp_path / "one" / "run.json").read_text(encoding="utf-8"))["kept"]
    assert first["bandit"] == {"reused": 0, "anew": 1} and first["python-file"] == {"reused": 0, "anew": 2}
    pipeline.analyze(repo, tmp_path / "two", log=QUIET, offline=True)
    second = json.loads((tmp_path / "two" / "run.json").read_text(encoding="utf-8"))["kept"]
    assert second["bandit"] == {"reused": 1, "anew": 0} and second["python-file"] == {"reused": 2, "anew": 0}
    assert kept.current() is None                            # the count ended with its run


# ------------------------------------------------------------------------------------------- bounded
DAY = 86400


def _aged(key: str, days: float, now: float) -> Path:
    p = _entry(key)
    os.utime(p, (now - days * DAY, now - days * DAY))
    return p


def test_what_nobody_asked_for_in_a_month_goes(tmp_path):
    now = 2_000_000_000.0
    keys = {name: SHELF.key(name) for name in ("fresh", "a week", "29 days", "30 days", "31 days", "a year")}
    for k in keys.values():
        assert SHELF.put(k, ["x" * 100])
    for name, days in (("fresh", 0), ("a week", 7), ("29 days", 29), ("30 days", 30), ("31 days", 31), ("a year", 365)):
        _aged(keys[name], days, now)
    stray = kept.home() / "test-values" / "notes.txt"
    stray.write_text("not an entry\n", encoding="utf-8")
    assert kept.tidy(now=now) == 2
    assert {name for name, k in keys.items() if _entry(k).exists()} == {"fresh", "a week", "29 days", "30 days"}
    assert stray.exists()                                    # only what is an entry by its name and place is ever removed
    assert kept.tidy(now=now + 3600) == 0                    # looked at the whole folder an hour ago: not again
    _aged(keys["a week"], 40, now)                           # with "30 days", now an hour over: two go
    assert kept.tidy(now=now + 3600) == 0 and kept.tidy(now=now + 3600, force=True) == 2
    assert kept.tidy(now=now + 3600 + DAY - 1) == 0          # a second short of a day since the last look
    assert kept.tidy(now=now + 3600 + DAY) == 1              # a day since: looked at again, and "29 days" is over 30 now
    assert {name for name, k in keys.items() if _entry(k).exists()} == {"fresh"}


def test_the_folder_stays_under_its_cap_and_the_least_recently_used_go_first(monkeypatch):
    now = 2_000_000_000.0
    keys = [SHELF.key("entry", str(i)) for i in range(10)]
    for i, k in enumerate(keys):
        assert SHELF.put(k, "x" * 1000)
        _aged(k, i, now)                                     # entry 0 was used today, entry 9 nine days ago
    each = _entry(keys[0]).stat().st_size
    monkeypatch.setattr(kept, "cap_bytes", lambda: each * 5)
    removed = kept.tidy(now=now, force=True)
    left = [i for i, k in enumerate(keys) if _entry(k).exists()]
    assert removed == 6 and left == [0, 1, 2, 3]             # down to four fifths of the cap, the oldest gone
    monkeypatch.setattr(kept, "cap_bytes", lambda: each * 4)
    assert kept.tidy(now=now, force=True) == 0               # exactly at the cap is not over it
    monkeypatch.setattr(kept, "cap_bytes", lambda: each * 100)
    assert kept.tidy(now=now, force=True) == 0


@pytest.mark.parametrize("said, mb", [("", 1024), ("2048", 2048), ("1", 16), ("0", 16), ("many", 1024), ("-5", 1024)])
def test_the_cap_is_read_from_the_environment(monkeypatch, said, mb):
    monkeypatch.setenv("LANTERN_CACHE_MB", said)
    assert kept.cap_bytes() == mb * 1024 * 1024


def test_an_entry_that_is_used_is_not_an_old_entry(tmp_path):
    key = SHELF.key("used")
    assert SHELF.put(key, [1])
    old = 1_000_000_000.0
    os.utime(_entry(key), (old, old))
    assert SHELF.get(key) == [1]
    assert _entry(key).stat().st_mtime > old + 365 * DAY     # asked for now: it carries today's date again


def test_what_a_cut_off_write_left_is_removed_a_day_later():
    key = SHELF.key("whole")
    assert SHELF.put(key, [1])
    now = 2_000_000_000.0
    _aged(key, 0, now)
    left = _entry(key).with_name("." + "ab" * 31 + ".123.456.tmp")
    left.write_bytes(b'{"k": "half')
    os.utime(left, (now - 3600, now - 3600))
    assert kept.tidy(now=now, force=True) == 0 and left.exists()         # an hour old: a write may be under way
    os.utime(left, (now - DAY, now - DAY))
    assert kept.tidy(now=now, force=True) == 0 and left.exists()         # a day to the second: not yet over a day
    os.utime(left, (now - 2 * DAY, now - 2 * DAY))
    assert kept.tidy(now=now, force=True) == 1 and not left.exists() and _entry(key).exists()


def test_a_write_that_is_cut_off_leaves_a_file_the_tidy_up_knows(monkeypatch):
    """The name a half-written entry has while it is written is the name `tidy` looks for a day later."""
    class Cut(BaseException):
        pass

    def cut(src, dst):
        raise Cut()

    key = SHELF.key("never whole")
    with monkeypatch.context() as only_here:
        only_here.setattr(os, "replace", cut)
        with pytest.raises(Cut):
            SHELF.put(key, ["half"])
    left = list(_entry(key).parent.iterdir())
    assert len(left) == 1 and left[0].name.startswith("." + key[2:] + ".") and left[0].name.endswith(".tmp")
    assert SHELF.get(key) is kept.NOTHING and kept.size() == (0, 0)
    now = 2_000_000_000.0
    os.utime(left[0], (now - 2 * DAY, now - 2 * DAY))
    assert kept.tidy(now=now, force=True) == 1 and not left[0].exists()


@pytest.mark.skipif(sys.platform == "win32", reason="needs the right to make a link")
def test_clearing_removes_entries_and_nothing_else(tmp_path):
    keys = [SHELF.key("entry", str(i)) for i in range(5)]
    for k in keys:
        assert SHELF.put(k, [1])
    precious = tmp_path / "precious.json"
    precious.write_text("{}", encoding="utf-8")
    folder = _entry(keys[0]).parent
    os.symlink(precious, folder / ("cd" * 31 + ".json"))                 # named like an entry, and a link out
    # a folder somewhere else that is laid out like kept work, with a file named like an entry in it
    theirs = tmp_path / "theirs" / "ab" / ("ef" * 31 + ".json")
    theirs.parent.mkdir(parents=True)
    theirs.write_text("{}", encoding="utf-8")
    os.symlink(tmp_path / "theirs", kept.home() / "test-linked")         # a kind's folder that is a link to it
    os.symlink(tmp_path / "theirs" / "ab", kept.home() / "test-values" / "ab")   # and a part's folder that is one
    # files named like entries where no entry is ever written: beside the kinds, in a folder that is no kind's,
    # and in a kind's folder that is no part's
    strays = [kept.home() / ("ef" * 31 + ".json"), kept.home() / "Not_A_Kind" / "ab" / ("ef" * 31 + ".json"),
              kept.home() / "test-values" / "abc" / ("ef" * 31 + ".json")]
    for stray in strays:
        stray.parent.mkdir(parents=True, exist_ok=True)
        stray.write_text("{}", encoding="utf-8")
    (kept.home() / "README.txt").write_text("the person's own note\n", encoding="utf-8")
    assert kept.size()[0] == 5
    assert kept.tidy(now=4_000_000_000.0, force=True) == 5               # decades on, every entry is an old entry
    assert kept.size() == (0, 0)
    for k in keys:
        assert SHELF.put(k, [1])
    assert kept.size()[0] == 5
    assert kept.clear() == (5, 0)
    assert kept.size() == (0, 0)
    assert precious.read_text(encoding="utf-8") == "{}" and (kept.home() / "README.txt").exists()
    assert (folder / ("cd" * 31 + ".json")).is_symlink()
    assert theirs.read_text(encoding="utf-8") == "{}"                    # nothing was removed through a link
    assert all(stray.read_text(encoding="utf-8") == "{}" for stray in strays)


def test_clearing_says_how_many_entries_would_not_go(monkeypatch):
    keys = [SHELF.key("entry", str(i)) for i in range(5)]
    for k in keys:
        assert SHELF.put(k, [1])
    held = {_entry(keys[1]), _entry(keys[3])}
    unlink = os.unlink

    def some_stay(path, *a, **kw):
        if Path(path) in held:
            raise PermissionError("in use")
        return unlink(path, *a, **kw)

    monkeypatch.setattr(os, "unlink", some_stay)
    assert kept.clear() == (3, 2)
    assert kept.size()[0] == 2 and all(p.exists() for p in held)
    monkeypatch.setattr(os, "unlink", unlink)
    assert kept.clear() == (2, 0) and kept.size() == (0, 0)


def test_a_home_that_is_not_there_yet_is_made_with_the_folders_above_it(tmp_path, monkeypatch):
    monkeypatch.setenv("LANTERN_HOME", str(tmp_path / "not" / "there" / "yet"))
    key = SHELF.key("first of all")
    assert SHELF.put(key, [1]) is True and SHELF.get(key) == [1]
    assert kept.home() == tmp_path / "not" / "there" / "yet" / "cache" and kept.size()[0] == 1


def test_an_answer_over_the_size_is_not_kept_and_not_read(monkeypatch):
    key, other = SHELF.key("just fits"), SHELF.key("one more")
    assert SHELF.put(key, "x" * 500)
    size = _entry(key).stat().st_size
    monkeypatch.setattr(kept, "MAX_ENTRY", size)                         # exactly as long as may be kept
    assert SHELF.put(key, "y" * 500) is True and SHELF.get(key) == "y" * 500
    assert SHELF.put(other, "x" * 501) is False and not _entry(other).exists()   # one more is not written
    monkeypatch.setattr(kept, "MAX_ENTRY", size - 1)
    assert SHELF.get(key) is kept.NOTHING                                # and one that is there is not read
    monkeypatch.setattr(kept, "MAX_ENTRY", size)
    assert SHELF.get(key) == "y" * 500


def test_tidying_never_stops_a_run(tmp_path, monkeypatch):
    repo = _write(tmp_path / "p", SMALL)
    monkeypatch.setattr(kept, "_entries", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("the disk said no")))
    Path(os.environ["LANTERN_HOME"]).mkdir(parents=True, exist_ok=True)
    kept.home().mkdir()
    assert kept.tidy(force=True) == 0
    pipeline.analyze(repo, tmp_path / "out", log=QUIET, offline=True)


def test_a_home_that_cannot_be_written_keeps_nothing_and_stops_nothing(tmp_path, monkeypatch):
    blocked = tmp_path / "a-file-not-a-folder"
    blocked.write_text("in the way\n", encoding="utf-8")
    monkeypatch.setenv("LANTERN_HOME", str(blocked))
    assert not SHELF.put(SHELF.key("a"), [1]) and SHELF.get(SHELF.key("a")) is kept.NOTHING
    assert kept.size() == (0, 0) and kept.clear() == (0, 0) and kept.tidy(force=True) == 0
    repo = _write(tmp_path / "p", SMALL)
    monkeypatch.setenv("LANTERN_CACHE", "off")
    pipeline.analyze(repo, tmp_path / "off", log=QUIET, offline=True)
    monkeypatch.delenv("LANTERN_CACHE")
    pipeline.analyze(repo, tmp_path / "on", log=QUIET, offline=True)
    assert speed.differing(speed.fingerprint(tmp_path / "off"), speed.fingerprint(tmp_path / "on")) == []


# ------------------------------------------------------------------------------------------- the command
def test_the_command_says_what_is_kept_and_clears_it(tmp_path, capsys):
    repo = _write(tmp_path / "p", SMALL)
    assert cli.main(["cache"]) == 0
    assert "nothing is kept" in capsys.readouterr().out.lower()
    pipeline.analyze(repo, tmp_path / "out", log=QUIET, offline=True)
    n, size = kept.size()
    assert cli.main(["cache"]) == 0
    said = capsys.readouterr().out
    assert f"{n} " in said and str(kept.home()) in said and "LANTERN_CACHE=off" in said
    assert cli.main(["cache", "--clear"]) == 0
    assert f"{n} " in capsys.readouterr().out and kept.size() == (0, 0)
