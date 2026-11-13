"""What a project holds that Lantern takes for code or software and did not read (2026-11-12).

A real site kept 17 Python files, 12,518 lines, as `<name>.py.txt` and ran them in the browser, beside a copy of the
runtime that runs them in `vendor/`. No reader and no scanner opened one of them, and the report said nothing: the
Python scanner read "ok" on 0 files, the release decision's scanners criterion said every scanner had covered
everything, and the libraries criterion said the project lists no libraries.

`survey(repo)` names two kinds of thing (an empty table when the project holds neither):

`renamed`  code kept under another name: `<name>.<code ending>.<cover>` (`engine.py.txt`, `main.py.tmpl`,
           `app.js.bak`; `CODE`, `COVERS`). No reader of Lantern opens such a file, so no map, no path and none of
           Lantern's own checks covers it. Python kept as text (`.py.txt`) is handed to Bandit (`security.run_bandit`,
           `python_as_text`), which reads any file it is given by name. Code kept as text that no scanner reads
           (`as_text_unscanned`) leaves the release decision's scanners criterion `missing`: text is kept that way to
           be loaded. A template or a left-over copy (`.tmpl`, `.bak`) is named in the Evidence Limits only.
`copied`   software copied into the project: what lies under a folder named `vendor`, which every reader leaves out
           as not the project's own code. A copy that brings a `package.json` with a name and one exact version is
           looked up by that name and version (`depaudit.run_copied_audit`, OSV, ecosystem npm); code files with no
           such file above them are counted as `unnamed` and cannot be looked up. A package manager's own folder
           (Composer's, Go's, Bundler's: `MANAGED`) is not a copy: its lock file says what is in it.

Names and counts only: nothing here opens a file but a copy's `package.json` (through `project_text`, so never
through a link that leads out of the project) and a renamed file to count its lines."""

from __future__ import annotations

import os
import re
from pathlib import Path

from . import listing, manifest
from .python_frontend import inside_repo, project_bytes, project_text, skipped_dir

CODE = ("py", "pyw", "js", "mjs", "cjs", "jsx", "ts", "tsx", "go", "rs", "java", "kt", "swift", "dart", "cs", "php",
        "rb", "c", "cc", "cpp")
COVERS = ("txt", "tmpl", "template", "bak", "orig", "old")
RENAMED = re.compile(r"\.(" + "|".join(CODE) + r")\.(" + "|".join(COVERS) + r")$", re.I)
AS_TEXT = ".txt"                            # code kept as text: there to be loaded
PYTHON_AS_TEXT = (".py.txt", ".pyw.txt")    # what Bandit is handed
MOST_HANDED = 400                           # files handed to Bandit by name (each is a word of its command line)
COUNT_BYTES = 8 * 1024 * 1024               # a renamed file's lines are counted in its first 8 MB
KEEP = 5                                    # examples kept of each kind

VENDOR = "vendor"
# What a package manager's own `vendor` folder holds: Composer, Go modules, Bundler
MANAGED = ("autoload.php", "composer", "modules.txt", "bundle", "cache")
COPIED_CODE = (".js", ".mjs", ".cjs", ".ts", ".wasm", ".py", ".php", ".rb", ".jar", ".dll", ".so", ".dylib")
NPM_NAME = re.compile(r"(?=.{1,214}\Z)(?:@[a-z0-9][a-z0-9._~\-]*/)?[a-z0-9][a-z0-9._~\-]*")
NPM_VERSION = re.compile(r"(?=.{1,100}\Z)[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?")
MAX_DEPTH = 6                               # folders below `vendor` that are looked into
# A copy kept for the tests or inside a sample app is not software the project ships: the dependency audits leave
# such folders' dependency files out the same way (`depaudit.TEST_DIR_RE`)
NOT_SHIPPED = re.compile(r"(^|/)(tests?|__tests__|fixtures|examples?)/")
MAX_NAMES = 20_000                          # names looked at under the `vendor` folders of one project
MANIFEST_CHARS = 1_000_000


def renamed(repo: Path) -> list[tuple[str, str]]:
    """The project's files that hold code under another name, as (path in the project, ending such as `.py.txt`)."""
    out = []
    for path, _parts in listing.files(repo):
        m = RENAMED.search(path.name)
        if m:
            out.append((path.relative_to(repo).as_posix(), f".{m.group(1).lower()}.{m.group(2).lower()}"))
    return sorted(out)


def python_as_text(repo: Path) -> list[str]:
    """The renamed files Bandit is handed: Python kept as text, the first `MOST_HANDED` by name."""
    return [rel for rel, ending in renamed(repo) if ending in PYTHON_AS_TEXT][:MOST_HANDED]


def _lines(repo: Path, rel: str) -> int:
    try:
        data = project_bytes(repo / rel, repo, COUNT_BYTES)
    except OSError:
        return 0
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


def _vendor_folders(repo: Path) -> list[Path]:
    """Every folder named `vendor` in the project that is not inside another folder Lantern leaves out, is no link,
    is not a package manager's own, and is not kept for the tests or a sample app (`NOT_SHIPPED`)."""
    out = []
    top = os.fspath(repo)
    for dirpath, dirnames, _filenames in os.walk(top):
        keep = []
        for d in sorted(dirnames):
            full = os.path.join(dirpath, d)
            if d == VENDOR:
                rel = os.path.relpath(full, top).replace(os.sep, "/") + "/"
                if not os.path.islink(full) and not NOT_SHIPPED.search(rel) and \
                        not any(os.path.lexists(os.path.join(full, m)) for m in MANAGED):
                    out.append(Path(full))
            elif not skipped_dir(dirpath, d) and not os.path.islink(full):
                keep.append(d)
        dirnames[:] = keep
    return out


def _copy(repo: Path, manifest_path: Path) -> dict | None:
    """What a copy's `package.json` says it is: a published name and one exact version, or None."""
    if not inside_repo(manifest_path, repo):
        return None
    try:
        text = project_text(manifest_path, repo, MANIFEST_CHARS)
    except OSError:
        return None
    data = manifest.table(manifest.parse_json(text))
    name, version = manifest.text(data.get("name")), manifest.text(data.get("version"))
    if data.get("private") is True or not NPM_NAME.fullmatch(name or "") or not NPM_VERSION.fullmatch(version or ""):
        return None
    at = re.search(r"\"version\"\s*:", text)
    return {"name": name, "version": version, "at": manifest_path.parent.relative_to(repo).as_posix(),
            "file": manifest_path.relative_to(repo).as_posix(), "line": text.count("\n", 0, at.start()) + 1 if at else 1}


def copied(repo: Path) -> dict:
    """The software copied into the project's `vendor` folders: the copies that say what they are (`named`), and the
    code files that belong to none of them (`unnamed`, with the first few as examples). `cut_short`: a folder lay
    deeper than `MAX_DEPTH`, or there were more names than `MAX_NAMES`, so part of what lies there was not looked at."""
    named: list[dict] = []
    loose: list[str] = []
    seen = folders = 0
    cut = False
    for vendor in _vendor_folders(repo):
        folders += 1
        base = len(vendor.parts)
        for dirpath, dirnames, filenames in os.walk(vendor):
            here = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames if d != "node_modules" and not os.path.islink(os.path.join(dirpath, d)))
            if len(here.parts) - base >= MAX_DEPTH and dirnames:
                dirnames[:] = []
                cut = True
            seen += len(filenames)
            if seen > MAX_NAMES:
                cut = True
                break
            if "package.json" in filenames:
                got = _copy(repo, here / "package.json")
                if got:
                    named.append(got)
                    dirnames[:] = []            # what lies beneath belongs to this copy
                    continue
            for fn in sorted(filenames):
                p = here / fn
                if fn.lower().endswith(COPIED_CODE) and inside_repo(p, repo):
                    loose.append(p.relative_to(repo).as_posix())
    if not named and not loose and not cut:
        return {}
    return {"folders": folders, "named": named, "unnamed": len(loose), "unnamed_examples": loose[:KEEP],
            "cut_short": cut}


def survey(repo: Path, scanned: list[str] | None = None) -> dict:
    """What the project holds that was not read, as a table for the results (`security.json` `not_read`): `renamed`
    and `copied`, each only when there is something to say. `scanned`: the renamed files a scanner was handed."""
    repo = Path(repo)
    out: dict = {}
    files = renamed(repo)
    if files:
        scanned = set(scanned if scanned is not None else python_as_text(repo))
        endings: dict[str, int] = {}
        for _rel, ending in files:
            endings[ending] = endings.get(ending, 0) + 1
        unscanned = [rel for rel, ending in files if ending.endswith(AS_TEXT) and rel not in scanned]
        out["renamed"] = {
            "files": len(files), "lines": sum(_lines(repo, rel) for rel, _ in files),
            "endings": dict(sorted(endings.items())), "examples": [rel for rel, _ in files][:KEEP],
            "scanned": sum(1 for rel, _ in files if rel in scanned),
            "as_text_unscanned": len(unscanned), "as_text_unscanned_examples": unscanned[:KEEP]}
    got = copied(repo)
    if got:
        out["copied"] = {"folders": got["folders"], "unnamed": got["unnamed"], "unnamed_examples": got["unnamed_examples"],
                         "named": [f"{c['name']} {c['version']} ({c['at']})" for c in got["named"]][:KEEP],
                         "copies": len(got["named"]), "cut_short": got["cut_short"]}
    return out
