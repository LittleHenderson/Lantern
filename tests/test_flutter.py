"""Flutter apps: the Dart reader (lantern/dart_frontend.py) and lantern/flutter.py (screens, links, LF-* checks)."""

from pathlib import Path

import pytest

from lantern.engine import build_graph
from lantern.readiness import assess
from lantern.security import scan

FIX = Path(__file__).parent / "fixtures"
HOME = "dt:_HomeScreenState@lib/screens/home_screen.dart"


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


@pytest.fixture(scope="module")
def notes():
    g = build_graph(FIX / "flutterapp")
    sec = scan(g)
    return g, sec, assess(g, sec)


def edges(g):
    return {(e.src, e.dst): e for e in g.call_edges()}


def by_rule(sec, rule):
    return [f for f in sec["findings"] if f["rule"] == rule]


def test_dart_is_mapped(notes):
    g, _, _ = notes
    dt = g.meta["languages"]["dart"]
    assert dt["files"] == 6 and dt["types"] == 7
    assert g.nodes[HOME].signature == "class _HomeScreenState: State (state of HomeScreen)"   # private: carries its file
    assert g.nodes["dt:NoteDb.find"].parent == "dt:NoteDb"


def test_calls_resolve_the_dart_ways(notes):
    g, _, _ = notes
    e = edges(g)
    assert e[("dt:NoteDb.find", "dt:NoteDb.open")].via == "name"
    assert e[("dt:main", "dt:Links.listen")].via == "assoc"                         # a static method
    assert e[("dt:Links.listen", "dt:Links.openNote")].via == "name"                # inside a closure
    assert e[("dt:Links.openNote", "dt:NoteDb.find")].via == "receiver-type"         # NoteDb().find(id)
    assert e[(HOME + "._load", "dt:NoteDb.all")].via == "receiver-type"              # `final db = NoteDb();`
    assert e[(HOME + ".build", HOME + "._load")].via == "callback"                   # onPressed: _load
    assert e[("dt:main", "dt:NotesApp.new")].via == "constructor"
    built = e[("dt:NotesApp.build", HOME + ".build")]                                # HomeScreen() → its State's build
    assert built.via == "flutter-build" and built.confidence == "inferred"
    assert (HOME + "._load", "ext:SharedPreferences.getInstance") in e


def test_interfaces_fan_out(tmp_path):
    _write(tmp_path, {"lib/a.dart": "abstract class Store { void load(); }\nclass Disk implements Store { void load() {} }\n"
                                    "class Mem extends Store { void load() {} }\n"
                                    "class Repo { final Store s; Repo(this.s); void go() { s.load(); } }\n"})
    g = build_graph(tmp_path)
    got = {(e.dst, e.confidence) for e in g.call_edges() if e.src == "dt:Repo.go"}
    assert got == {("dt:Disk.load", "possible"), ("dt:Mem.load", "possible")}


def test_screens_and_links(notes):
    g, _, _ = notes
    e = {n.id: n.entry for n in g.entry_points()}
    assert g.meta["flutter"]["roots"] == [""] and g.meta["platform"] == "android"
    assert e[HOME + ".build"]["detail"] == "HomeScreen screen · build"        # home: HomeScreen()
    assert e["dt:NoteView.build"]["detail"] == "NoteView screen · build"      # routes / MaterialPageRoute
    assert "dt:NoteTile.build" not in e                                       # a row, not a screen
    assert e["dt:Links.openNote"]["detail"].startswith("LINK Links handles links")
    assert e["dt:main"]["kind"] == "main" and e["dt:test/widget_test.dart"]["kind"] == "test"
    assert g.nodes["dt:NoteView.build"].lane == "browser" and g.nodes["dt:NoteDb.find"].lane == "frontend"


def test_a_link_reaching_a_query_is_critical(notes):
    _, sec, _ = notes
    f = by_rule(sec, "LF-SQL-CONCAT")[0]
    assert f["node"] == "dt:NoteDb.find" and f["rank"] == "critical"
    assert f["reachable"]["entry"] == "dt:Links.openNote" and f["input"] == {"via": "parameter `id`"}
    assert f["headline"] == "Another app or a link can change what your app's database is asked"


def test_every_planted_problem_is_found(notes):
    _, sec, _ = notes
    rules = {f["rule"] for f in sec["findings"]}
    assert {"LF-SQL-CONCAT", "LF-TLS-OFF", "LF-PREFS-SECRET", "LF-LOG-SENSITIVE", "LF-CLEARTEXT-URL"} <= rules
    assert by_rule(sec, "LF-TLS-OFF")[0]["rank"] == "high"
    assert "flutter_secure_storage" in by_rule(sec, "LF-PREFS-SECRET")[0]["scenario"]["after_fix"]
    assert "SecTrust" not in str(by_rule(sec, "LF-TLS-OFF")[0]["scenario"])


def test_readiness_counts_the_flutter_template_test_as_a_sample(notes):
    _, _, r = notes
    checks = {c["id"]: c for cat in r["categories"] for c in cat["checks"]}
    assert checks["tests-exist"]["status"] == "partial"


def test_generated_and_platform_dart_is_skipped(tmp_path):
    _write(tmp_path, {"pubspec.yaml": "name: a\ndependencies:\n  flutter:\n    sdk: flutter\n",
                      "lib/main.dart": "void main() {}\n", "lib/model.g.dart": "class Gen {}\n",
                      "ios/Runner/GeneratedPluginRegistrant.dart": "class Reg {}\n"})
    g = build_graph(tmp_path)
    assert "dt:Gen" not in g.nodes and "dt:Reg" not in g.nodes and "dt:main" in g.nodes


def test_a_broken_dart_file_does_not_stop_the_map(tmp_path):
    _write(tmp_path, {"lib/bad.dart": "class Bad { void x( {\n", "lib/good.dart": "int ok() => 1;\n"})
    g = build_graph(tmp_path)
    assert "dt:ok" in g.nodes


def test_a_flutter_app_without_native_folders_is_graded_as_a_flutter_app(tmp_path):
    _write(tmp_path, {"pubspec.yaml": "name: a\ndependencies:\n  flutter:\n    sdk: flutter\n  dio: ^5.0.0\n",
                      "lib/main.dart": "import 'package:dio/dio.dart';\nvoid main() { print('hi'); Dio().get('/x'); }\n"})
    g = build_graph(tmp_path)
    sec = scan(g)
    r = assess(g, sec)
    checks = {c["id"]: c for cat in r["categories"] for c in cat["checks"]}
    assert g.meta["platform"] == "flutter" and r["shape"] == "Flutter app"
    assert checks["obs-print"]["status"] == "fail" and checks["pkg-lock"]["status"] == "fail"
    assert checks["res-timeout"]["status"] == "fail"
    assert any("flutter_secure_storage" in t for t in r["advice"])
