"""One bad file never sinks the analysis (test checklist 3.5).

Every reader gets a deliberately garbled file beside a good one, in the same repository: cut off mid-function,
random bytes, a NUL byte, text that is not UTF-8, and a manifest that does not parse. The whole run (map, findings,
readiness, report) must finish, the good file's function must be on the map, and the garbled file must not crash
or hang anything. Fuzzing proper (random mutation of real files) runs in bench/fuzz.py, outside CI.
"""
import json
import os
import random
from pathlib import Path

import pytest

from lantern.engine import build_graph
from lantern.readiness import assess
from lantern.report import write_report
from lantern.security import scan

GOOD = {
    "py/app.py": "def good_py():\n    return 1\n",
    "js/app.ts": "export function goodJs() { return 1 }\n",
    "go/go.mod": "module example.com/good\n\ngo 1.22\n",
    "go/main.go": "package main\n\nfunc goodGo() int { return 1 }\n",
    "rs/Cargo.toml": "[package]\nname = \"good\"\nversion = \"0.1.0\"\n",
    "rs/src/lib.rs": "pub fn good_rs() -> i32 { 1 }\n",
    "jv/src/main/java/com/g/Good.java": "package com.g;\npublic class Good { public int goodJv() { return 1; } }\n",
    "kt/src/main/kotlin/com/g/GoodKt.kt": "package com.g\nfun goodKt(): Int = 1\n",
    "sw/Good.swift": "func goodSw() -> Int { return 1 }\n",
    "dt/lib/good.dart": "int goodDt() => 1;\n",
    "cs/Good.cs": "namespace G { public class Good { public int GoodCs() { return 1; } } }\n",
    "php/good.php": "<?php\nfunction good_php() { return 1; }\n",
    "rb/good.rb": "def good_rb\n  1\nend\n",
    "cc/good.cpp": "int goodCc() { return 1; }\n",
}

# Each garbled file sits in the same folder as a good file of its language, so the reader cannot skip the folder.
GARBLED_TEXT = {
    "py/broken.py": "def broken(:\n    if True\n        return ((((\n\x00\nclass :\n",
    "js/broken.tsx": "export const <div>{{{ function ( => {\n`unterminated ${ \n",
    "go/broken.go": "package main\n\nfunc broken( {\n\tx := \n}}}}}\n",
    "rs/src/broken.rs": "fn broken( -> {\n  let = ;\n  impl for {\n",
    "jv/src/main/java/com/g/Broken.java": "package com.g;\npublic class { void ( { if ( {\n",
    "kt/src/main/kotlin/com/g/Broken.kt": "package com.g\nfun ( : = {\n  when {\n",
    "sw/Broken.swift": "struct : { func ( -> {\n  guard let else\n",
    "dt/lib/broken.dart": "class extends {\n  Widget build( {\n    return (\n",
    "cs/Broken.cs": "namespace { public class { public ( { =>\n",
    "php/broken.php": "<?php\nfunction ( { if ( {\n  echo <<<EOT\n",
    "rb/broken.rb": "def\n  class <\n    if\n  end\n",
    "cc/broken.cpp": "template<class> struct { void ( { #if\n",
    # manifests that do not parse
    "js/package.json": '{"name": "broken", "dependencies": {',
    "go/go.sum": "\x00\x01\x02 not a sum",
    "rs/Cargo.lock": "[[package]\nname = \n",
    "dt/pubspec.yaml": "name: broken\ndependencies:\n  flutter:\n    sdk: flutter\n  - broken list\n: : :\n",
    "jv/pom.xml": "<project><dependencies><dependency><groupId>x</dependency></project",
    "jv/build.gradle": "dependencies {\n  implementation(\n",
    "kt/AndroidManifest.xml": "<manifest package=\"a\"><application><activity android:name=\".A\"><intent-filter>",
    "sw/Info.plist": "<?xml version=\"1.0\"?><plist><dict><key>CFBundleName</key><string>",
    "cs/Broken.csproj": "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>",
    "php/composer.json": "{\"require\": {\"laravel/framework\": ",
    "rb/Gemfile": "source 'https://rubygems.org'\ngem\ngem 'rails', ",
    "rb/Gemfile.lock": "GEM\n  specs:\n    rails (\n",
    "cc/CMakeLists.txt": "project(\nadd_executable(",
}


def _write_all(root: Path):
    for rel, text in GOOD.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    for rel, text in GARBLED_TEXT.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode("utf-8"))
    rnd = random.Random(7)
    for lang in ("py", "js", "go", "rs", "jv/src/main/java/com/g", "kt/src/main/kotlin/com/g", "sw", "dt/lib", "cs", "php", "rb", "cc"):
        ext = {"py": ".py", "js": ".js", "go": ".go", "rs": ".rs", "jv/src/main/java/com/g": ".java", "kt/src/main/kotlin/com/g": ".kt",
               "sw": ".swift", "dt/lib": ".dart", "cs": ".cs", "php": ".php", "rb": ".rb", "cc": ".cc"}[lang]
        # random bytes, including sequences that are not UTF-8, and one that is mostly brackets
        (root / lang / f"noise{ext}").write_bytes(bytes(rnd.randrange(256) for _ in range(4000)))
        (root / lang / f"brackets{ext}").write_text("".join(rnd.choice("(){}[]<>;,.\n") for _ in range(6000)), encoding="utf-8")
        (root / lang / f"latin{ext}").write_bytes("def caf\xe9(): pass\n// caf\xe9\n".encode("latin-1"))


def test_garbled_files_do_not_stop_the_analysis(tmp_path):
    _write_all(tmp_path)
    g = build_graph(tmp_path)
    names = {n.qualname.rsplit(".", 1)[-1].rsplit("::", 1)[-1] for n in g.nodes.values()}
    for want in ("good_py", "goodJs", "goodGo", "good_rs", "goodJv", "goodKt", "goodSw", "goodDt", "GoodCs", "good_php",
                 "good_rb", "goodCc"):
        assert any(want in n for n in names), f"{want} missing from the map: {sorted(names)[:40]}"
    sec = scan(g, offline=True)
    rd = assess(g, sec)
    out = tmp_path / ".lantern"
    out.mkdir(exist_ok=True)
    (out / "graph.json").write_text(json.dumps(g.to_dict()), encoding="utf-8")
    (out / "security.json").write_text(json.dumps(sec), encoding="utf-8")
    (out / "readiness.json").write_text(json.dumps(rd), encoding="utf-8")
    write_report(out, g, sec, {}, "full", readiness=rd)
    assert (out / "report.html").stat().st_size > 10000
    assert rd["score"] >= 0 and isinstance(sec["findings"], list)


@pytest.mark.parametrize("rel", sorted(GARBLED_TEXT))
def test_each_garbled_file_alone(tmp_path, rel):
    """The same, one garbled file at a time, so a failure names the file."""
    for g_rel, text in GOOD.items():
        if g_rel.split("/")[0] == rel.split("/")[0]:
            p = tmp_path / g_rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(GARBLED_TEXT[rel].encode("utf-8"))
    g = build_graph(tmp_path)
    sec = scan(g, offline=True)
    assess(g, sec)
    assert any(n.kind == "callable" for n in g.nodes.values()), "the good file's function is missing"


def test_unreadable_file_is_skipped(tmp_path):
    """A file the process may not read (permissions) is skipped, not fatal."""
    if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        pytest.skip("permissions are not enforced here")
    (tmp_path / "good.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    bad = tmp_path / "secret.py"
    bad.write_text("def hidden():\n    return 2\n", encoding="utf-8")
    bad.chmod(0)
    try:
        g = build_graph(tmp_path)
        assert "py:good.ok" in g.nodes
    finally:
        bad.chmod(0o644)


def test_import_cycles_do_not_recurse_forever(tmp_path):
    """Two package files that re-export a name from each other (Django has such pairs): the call is left unresolved,
    the process does not hit the recursion limit."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("from .a import thing\n", encoding="utf-8")
    (pkg / "a.py").write_text("from .b import thing\n", encoding="utf-8")
    (pkg / "b.py").write_text("from .a import thing\n", encoding="utf-8")
    (pkg / "use.py").write_text("from . import thing\n\ndef go():\n    return thing()\n", encoding="utf-8")
    g = build_graph(tmp_path)
    assert "py:pkg.use.go" in g.nodes


def test_php_parents_in_a_circle_do_not_loop_forever(tmp_path):
    """Two PHP classes that extend each other (a mistake real code contains, and what the Laravel framework's size
    exposed): a property read through the parent chain stops instead of looping, and the map is still built."""
    (tmp_path / "a.php").write_text(
        "<?php\nnamespace App;\nclass A extends B {\n  public Svc $svc;\n  function run() { return $this->svc->go(); }\n}\n",
        encoding="utf-8")
    (tmp_path / "b.php").write_text("<?php\nnamespace App;\nclass B extends A {\n  function other() { return $this->nothing->go(); }\n}\n",
                                    encoding="utf-8")
    (tmp_path / "svc.php").write_text("<?php\nnamespace App;\nclass Svc {\n  function go() { return 1; }\n}\n", encoding="utf-8")
    g = build_graph(tmp_path)
    assert "php:App.A.run" in g.nodes and "php:App.Svc.go" in g.nodes
    assert any(e.src == "php:App.A.run" and e.dst == "php:App.Svc.go" for e in g.edges)
