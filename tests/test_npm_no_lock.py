"""With no lock file, npm is handed a package.json Lantern wrote: names and versions for the store, nothing else.

A project's JavaScript tests run on the libraries its `package.json` names, fetched for the run. Where a lock file
fixes them, every entry of the lock file is looked at before npm is started (`depaudit._npm_stage`). Where there is
none, the project's own `package.json` was handed to `npm install` as it was (until 2026-11-15), and npm does what
such a file says: a library may be "a folder of this computer" (`file:`, a path), a repository or an address
anywhere, and `workspaces` and `overrides` name more of the same. The folder a project names that way was read by
npm and put beside the copy the project's own tests then run on.

Each refusal has its twin: the same project with names and versions for the store is fetched as before.
"""
import json
from pathlib import Path

import pytest
from stores import NpmStore
from test_libraries import _js_project, _named, _online, needs_npm

from lantern import libraries, sandbox

QUIET = lambda line: None       # noqa: E731
PRIVATE = "the private line 7341 of a folder that is not in the project"


@pytest.fixture()
def npmstore():
    with NpmStore() as store:
        yield store


def _no_lock(tmp_path: Path, store: NpmStore, **more) -> Path:
    """The sample project without its lock file; `more` is laid over its package.json."""
    repo = _js_project(tmp_path / "proj", store)
    (repo / "package-lock.json").unlink()
    manifest = json.loads((repo / "package.json").read_text(encoding="utf-8"))
    manifest["dependencies"]["stage2-sample"] = "^1.0.0"
    for key, value in more.items():
        if isinstance(value, dict) and isinstance(manifest.get(key), dict):
            manifest[key].update(value)
        else:
            manifest[key] = value
    (repo / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    return repo


def _somebodys(tmp_path: Path) -> Path:
    """A folder of this computer that is no part of the project, laid out as a package."""
    out = tmp_path / "somebody" / "private-pkg"
    out.mkdir(parents=True)
    (out / "package.json").write_text(json.dumps({"name": "private-pkg", "version": "9.9.9", "main": "index.js"}),
                                      encoding="utf-8")
    (out / "index.js").write_text(f"exports.said = {PRIVATE!r};\n", encoding="utf-8")
    return out


def _started(monkeypatch) -> list:
    """Every start of a fetching program in this test: (its command, the package.json it was started on)."""
    seen, real = [], libraries._Fetch.run

    def run(self, cmd, cwd, *args, **kwargs):
        p = Path(cwd) / "package.json"
        seen.append((list(cmd), json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None))
        return real(self, cmd, cwd, *args, **kwargs)
    monkeypatch.setattr(libraries._Fetch, "run", run)
    return seen


def _with(out: Path, said):
    """`said` with every `{out}` in it written as the folder `out`."""
    return json.loads(json.dumps(said).replace("{out}", out.as_posix()))


ELSEWHERE = ["file:{out}", "{out}", "file:../../somebody/private-pkg", "../../somebody/private-pkg", "./private-pkg",
             "~/private-pkg", "link:{out}", "portal:{out}", "workspace:*", "private-pkg-9.9.9.tgz",
             "git+https://example.invalid/a/b.git", "git://example.invalid/a/b.git", "github:a/b", "a/b",
             "https://example.invalid/b-1.0.0.tgz", "npm:../private-pkg", "npm:x@file:{out}", "npm:x@npm:y@1.0.0",
             "npm:", "C:\\private-pkg", "latest#x", "1.0.0 || file:{out}", ".5", ["1.0.0"], {"version": "1.0.0"}, 1]


@needs_npm
@pytest.mark.parametrize("source", ELSEWHERE, ids=[str(s)[:30] for s in ELSEWHERE])
def test_with_no_lock_file_a_library_from_anywhere_but_the_store_is_not_fetched(source, tmp_path, monkeypatch, npmstore):
    """Before: `npm install` was started on the project's own package.json, read the folder it names (here one of
    somebody else's) and the tests ran with it beside them."""
    out = _somebodys(tmp_path)
    repo = _no_lock(tmp_path, npmstore, dependencies={"private-pkg": _with(out, source)})
    started = _started(monkeypatch)
    _online(monkeypatch, npm=npmstore)
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(repo, ["npm", "test"], log=QUIET)
    assert libraries.ELSEWHERE in str(e.value) and "package.json" in str(e.value)
    assert started == [] and npmstore.seen == []                # npm was not started, and the store was not asked
    assert PRIVATE not in str(e.value) and out.as_posix() not in str(e.value)


@needs_npm
@pytest.mark.parametrize("name", ["../private-pkg", "/abs/private-pkg", "a b", "@scope", "@/x", "x/y/z", ""])
def test_a_library_under_a_name_that_is_no_package_name_is_not_fetched(name, tmp_path, monkeypatch, npmstore):
    repo = _no_lock(tmp_path, npmstore, devDependencies={name: "1.0.0"})
    started = _started(monkeypatch)
    _online(monkeypatch, npm=npmstore)
    with pytest.raises(sandbox.NoLibraries):
        sandbox.run(repo, ["npm", "test"], log=QUIET)
    assert started == [] and npmstore.seen == []


OVERRIDES = [{"stage2-sample": "file:{out}"}, {"x": {"y": "git+https://example.invalid/a/b.git"}}, {"x": {".": "{out}"}},
             {"x@npm:y": "1.0.0"}, {"x@file:{out}": "1.0.0"}, {"x": ["1.0.0"]}, {"x": 1}, {"x": "$../y"},
             {"../x": "1.0.0"}, {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": "1.0.0"}}}}}}}}}}]


@needs_npm
@pytest.mark.parametrize("said", OVERRIDES, ids=[json.dumps(s)[:30] for s in OVERRIDES])
def test_an_override_that_is_no_name_and_version_for_the_store_is_not_handed_to_npm(said, tmp_path, monkeypatch, npmstore):
    """`overrides` say which version of a library every other library gets, and npm reads a folder or an address
    there as it does beside a library's name."""
    out = _somebodys(tmp_path)
    repo = _no_lock(tmp_path, npmstore, overrides=_with(out, said))
    started = _started(monkeypatch)
    _online(monkeypatch, npm=npmstore)
    with pytest.raises(sandbox.NoLibraries) as e:
        sandbox.run(repo, ["npm", "test"], log=QUIET)
    assert libraries.ELSEWHERE in str(e.value) and "overrides" in str(e.value)
    assert started == [] and npmstore.seen == [] and out.as_posix() not in str(e.value)


@needs_npm
def test_names_and_versions_for_the_store_are_fetched_as_before_and_nothing_else_reaches_npm(tmp_path, monkeypatch, npmstore):
    """The twin. The project asks the store for its libraries in the four places a package.json has, each by a
    version, a range, a tag or the store's name for it; a library it can do without is left to it; its overrides
    are versions. The tests run on them. Whatever else its package.json holds is not handed to npm: its scripts,
    its settings, and the folders it names as workspaces (said in the record's notes)."""
    out = _somebodys(tmp_path)
    for name in ("stage2-dev", "stage2-peer", "stage2-opt"):
        npmstore.add(name, "1.2.3", {"index.js": f"exports.name = {name!r};\n"})
    # (npm refuses an override of a library the project names itself unless it says the same: these name others)
    overrides = {"stage2-absent": " 1.0.0 ", "stage2-other@>=1": {"stage2-absent": "$stage2-sample", ".": "1.2.3"}}
    repo = _no_lock(tmp_path, npmstore,
                    dependencies={"sample-again": "npm:stage2-sample@^1.0.0"},
                    devDependencies={"stage2-dev": "latest"},
                    peerDependencies={"stage2-peer": ">=1.0.0 <2", "stage2-nowhere": "*"},
                    peerDependenciesMeta={"stage2-peer": {"optional": False}, "stage2-nowhere": {"optional": True, "x": out.as_posix()},
                                          "stage2-unnamed": {"optional": True}},
                    optionalDependencies={"stage2-opt": " 1.x "}, overrides=overrides,
                    workspaces=[out.parent.as_posix() + "/*"], resolutions={"stage2-sample": "file:" + out.as_posix()},
                    bundleDependencies=["stage2-sample"], config={"registry": "https://example.invalid/"},
                    publishConfig={"registry": "https://example.invalid/"},
                    scripts={"test": "node test.js", "preinstall": "node -e \"process.exit(3)\""})
    started = _started(monkeypatch)
    _online(monkeypatch, npm=npmstore)
    res = sandbox.run(repo, ["npm", "test"], log=QUIET)
    assert res["returncode"] == 0, res["output_tail"]
    assert {"stage2-sample", "stage2-dev", "stage2-peer", "stage2-opt"} <= set(_named(res))
    assert "stage2-nowhere" not in _named(res)
    cmd, handed = started[0]
    assert handed == {"name": "lantern-run", "version": "0.0.0", "private": True,
                      "dependencies": {"stage2-sample": "^1.0.0", "sample-again": "npm:stage2-sample@^1.0.0"},
                      "devDependencies": {"stage2-dev": "latest"}, "optionalDependencies": {"stage2-opt": "1.x"},
                      "peerDependencies": {"stage2-peer": ">=1.0.0 <2", "stage2-nowhere": "*"},
                      "peerDependenciesMeta": {"stage2-nowhere": {"optional": True}},
                      "overrides": {"stage2-absent": "1.0.0",
                                    "stage2-other@>=1": {"stage2-absent": "$stage2-sample", ".": "1.2.3"}}}
    notes = " ".join(res["libraries"]["notes"])
    assert "workspaces" in notes and "no lock file" in notes
    assert PRIVATE not in json.dumps(res["libraries"]) and out.as_posix() not in json.dumps(res["libraries"])
    # git is no way out for npm either: the program it is told to use for a library kept in a repository is none
    told = [a for a in cmd if a.startswith("--git=")]
    assert len(told) == 1 and not Path(told[0][len("--git="):]).exists()


@needs_npm
@pytest.mark.parametrize("far", ["git+https://example.invalid/far.git", "https://example.invalid/far-1.0.0.tgz"])
def test_a_library_of_the_store_that_wants_one_from_elsewhere_stops_the_fetch(far, tmp_path, monkeypatch, npmstore):
    """What a library of the store asks for in turn is the store's word, not the project's; one from a repository
    or another address is still not fetched, and the tests do not run on half of the libraries."""
    repo = _no_lock(tmp_path, npmstore)
    npmstore.add("stage2-sample", "1.0.0", {"index.js": "exports.answer = () => 42;\n"}, more={"dependencies": {"far": far}})
    _online(monkeypatch, npm=npmstore)
    with pytest.raises(sandbox.Unavailable):
        sandbox.run(repo, ["npm", "test"], log=QUIET)


def test_what_a_package_json_may_write_beside_a_librarys_name():
    for wanted in ("1.0.0", "^1.0.0", "~1.2", ">=1.0.0 <2", "1.x", "*", "", "latest", "next", "1.0.0-rc.1", "=1.0.0",
                   "v1.0.0", "1.0.0 || ^2.0.0", "1.0.0 - 1.5.0", " ^1.0.0 ", "1.0.0+build.5", "beta",
                   "npm:stage2-sample@1.0.0", "npm:@scope/pkg@^2", "npm:pkg", " npm:pkg@latest "):
        assert libraries.from_the_store(wanted), wanted
    for wanted in ELSEWHERE + ["x" * 200, "a\nb", "1.0.0\x00", "file:", "x.tar", "x.TAR.GZ", "@x", "a:b", "\\\\host\\x",
                               "npm:pkg@x.tgz", "npm:pkg@.5", "npm:a b", "NPM:pkg", None, True]:
        assert not libraries.from_the_store(wanted), wanted


def test_what_npm_took_is_read_from_its_own_record():
    """After a fetch with no lock file, npm's own record must name the store for every package; one it linked, or
    took from another address, means no test runs on them."""
    url = "https://store.example.invalid/npm/"
    final = {"packages": {"": {"name": "lantern-run"},
                          "node_modules/a": {"version": "1.0.0", "resolved": url + "a/-/a-1.0.0.tgz"},
                          "node_modules/b": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz"},
                          "node_modules/a/node_modules/c": {"version": "1.0.0", "inBundle": True}}}
    assert libraries.not_from_the_store(final, url) == 0
    # a store that keeps its files beside its pages, on the host the doorkeeper lets through
    final["packages"]["node_modules/h"] = {"version": "1.0.0", "resolved": "https://store.example.invalid/files/h-1.0.0.tgz"}
    assert libraries.not_from_the_store(final, url) == 1
    assert libraries.not_from_the_store(final, url, [["store.example.invalid", 443]]) == 0
    final["packages"]["node_modules/d"] = {"resolved": "../somebody/private-pkg", "link": True}
    final["packages"]["../somebody/private-pkg"] = {"name": "private-pkg", "version": "9.9.9"}
    final["packages"]["node_modules/e"] = {"version": "1.0.0", "resolved": "git+ssh://git@example.invalid/e.git#abc"}
    final["packages"]["node_modules/f"] = {"version": "1.0.0", "resolved": "file:../f"}
    final["packages"]["node_modules/g"] = {"version": "1.0.0"}
    final["packages"]["node_modules/i"] = {"version": "1.0.0", "resolved": "https://user@store.example.invalid/i.tgz"}
    final["packages"]["node_modules/j"] = {"version": "1.0.0", "resolved": "https://store.example.invalid:8443/j.tgz"}
    assert libraries.not_from_the_store(final, url, [["store.example.invalid", 443]]) == 7
    assert libraries.not_from_the_store({}, url) == 0 and libraries.not_from_the_store({"packages": "x"}, url) == 0
