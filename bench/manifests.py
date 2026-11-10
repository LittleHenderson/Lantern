"""Manifest sweep: a project file that parses and has the wrong shape must not stop the analysis (2026-11-10).

    python bench/manifests.py [--only js:package.json,py:pyproject.toml] [--depth 1] [--jobs 4] [--work DIR] [--json FILE]
                              [--engine CHECKOUT]

A manifest comes with the project, so it is as untrusted as the code. `"dependencies": "x"`, `paths = 5`, a list where
a table belongs: each is valid JSON or TOML, and until this date such a file ended `lantern analyze` with a Python
error. Here every file of KINDS is taken from a tiny project of its kind; every value in its tree is replaced, one at
a time, by each value of REPLACEMENTS that is of another type or content, and the whole analysis (map, findings,
readiness, report, evidence) runs offline on the result, in this process. A Python error is a find: the finds are
listed by the innermost line of Lantern's own code, and the run exits 1.

Measured with this file on 2026-11-10: on the code before (374d241, `--engine` pointed at a checkout of it) 839 of
11,652 variants stopped the analysis, at 50 lines of the code in 11 files (manifests 478 of 5,994, dependency files
163 of 1,791, earlier results 198 of 1,397, the text group 0 of 2,470); with that day's readers 0 of 11,652.

Three groups of files (`Kind.group`):
  manifest    read by structure: package.json, tsconfig.json, app.json, pyproject.toml, Pipfile, a notebook, a pack,
              lantern-accepted.json. An odd value costs the fact it would have given (`lantern/manifest.py`).
  dependency  lock files and the Gradle catalog: what is no package name and version is named in the audit's record
              (`depaudit.Odd`). For the sweep the wall behind the audits (`depaudit.guarded`) is taken away, so that
              an error it would have hidden is a find here.
  results     what an earlier run left in the results folder (security.json, baseline.json, explanations.json): a
              file that is cut off or changed by hand is passed over and said so (`pipeline.earlier`).
A fourth, `text`, holds files that are read as text today (firebase.json, composer.json, Cargo.toml, ...): they are
kept in the sweep for the day a reader takes one of them by structure.

Deterministic, no network (tools/netguard), about two minutes with `--jobs 4`. Bandit is another program and reads
none of these files, so it is left out. `--engine CHECKOUT` sweeps the `lantern` of another checkout with this same
file, for a before and after. Not part of CI: `tests/test_manifests.py` runs the cases this sweep found, and the top
level of every file, on every CI run. Run it after changing how any of these files is read.
"""
from __future__ import annotations

import argparse
import copy
import json
import multiprocessing as mp
import signal
import sys
import tempfile
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "netguard"))
import lantern_netguard as netguard  # noqa: E402  (tools/netguard: every benchmark starts isolated)

# One of each shape a JSON or TOML value can have, and the mixes that have tripped a reader: empty and not, a number
# where a name belongs, a table whose values are tables, lists or numbers, a list of lists. Then four texts for code
# that takes a text for a file's name: one with a NUL in it (`Path.resolve` raises ValueError), one longer than a
# name may be (`exists()` raises OSError), one that leads out of the project, and the root folder, which has no name
# (`with_name` raises ValueError).
REPLACEMENTS = [[], {}, "x", "", 5, 0, 1.5, None, True, ["x"], [5], [[1]], [{"x": 1}], {"x": 1}, {"x": "y"}, {"x": {"y": 1}},
                {"x": ["y"]}, "a\x00b", "x" * 5000, "../../../outside", "/"]

JS_SRC = {
    "src/App.tsx": "import { helper } from '@/lib/helper'\nimport { other } from '~lib'\nimport express from 'express'\n"
                   "export default function App() { helper(); other(); return <div onClick={helper}>x</div> }\n",
    "src/lib/helper.ts": "export function helper() { return fetch('/api/items') }\n",
    "src/lib/other.ts": "export function other() { return 1 }\n",      # found only through tsconfig's `~lib`
    "pages/index.js": "export default function Home() { return null }\n",
    "pages/api/items.js": "export default function handler(req, res) { res.json([]) }\n",
    "server.js": "const express = require('express')\nconst app = express()\napp.get('/api/items', (req, res) => res.json([]))\n",
    "App.js": "import { Linking } from 'react-native'\nexport default function App() { return null }\n",
    "app/index.js": "export default function Start() { return null }\n",
    "app.py": "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n",
}
PACKAGE = {"name": "app", "version": "1.0.0", "private": True, "type": "module", "main": "server.js",
           "scripts": {"dev": "next dev", "build": "next build", "test": "vitest run", "start": "node server.js", "lint": "eslint ."},
           "dependencies": {"react": "18.2.0", "next": "14.0.0", "express": "4.18.2", "expo": "50.0.0", "expo-router": "3.0.0",
                            "react-native": "0.73.0", "@supabase/supabase-js": "2.0.0", "firebase": "10.0.0", "@acme/ui": "workspace:*"},
           "devDependencies": {"typescript": "5.3.0", "vitest": "1.0.0", "jest": "29.0.0", "eslint": "8.0.0"},
           "workspaces": ["packages/*"], "engines": {"node": ">=18"}, "jest": {"preset": "jest-expo"},
           "browserslist": ["defaults"], "packageManager": "pnpm@8.0.0", "bin": {"app": "server.js"},
           "peerDependencies": {"react": "*"}, "optionalDependencies": {"fsevents": "2.3.3"},
           "overrides": {"semver": "7.5.4"}, "exports": {".": "./server.js"}}
TSCONFIG = {"extends": "./base.json",
            "compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./src/*"], "~lib": ["./src/lib/other"]}, "strict": True,
                                "jsx": "react-jsx", "rootDir": "src", "outDir": "dist", "allowJs": True},
            "include": ["src", "pages"], "exclude": ["node_modules"], "references": [{"path": "./packages/ui"}], "files": ["server.js"]}
APP_JSON = {"expo": {"name": "app", "slug": "app", "scheme": "myapp", "version": "1.0.0",
                     "ios": {"bundleIdentifier": "com.x.app", "infoPlist": {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
                                                                            "NSCameraUsageDescription": "x"}},
                     "android": {"package": "com.x.app", "permissions": ["CAMERA", "READ_CONTACTS"], "allowBackup": True,
                                 "intentFilters": [{"action": "VIEW", "data": [{"scheme": "https", "host": "x.example"}]}]},
                     "plugins": ["expo-router", ["expo-camera", {"cameraPermission": "x"}]], "extra": {"apiKey": "x"}},
            "name": "app", "displayName": "App"}
PYPROJECT = {"project": {"name": "app", "version": "0.1.0", "dependencies": ["flask>=2", "requests==2.31.0", "django==4.2"],
                         "optional-dependencies": {"dev": ["pytest>=8"], "scan": ["bandit"]}, "scripts": {"app": "app:run"},
                         "requires-python": ">=3.11", "dynamic": ["readme"], "license": {"text": "MIT"},
                         "authors": [{"name": "x"}], "urls": {"Homepage": "https://x.example"}},
             "build-system": {"requires": ["setuptools>=68"], "build-backend": "setuptools.build_meta"},
             "dependency-groups": {"dev": ["pytest", {"include-group": "lint"}], "lint": ["ruff"]},
             "tool": {"poetry": {"name": "app", "version": "0.1.0",
                                 "dependencies": {"python": "^3.11", "flask": "2.0.1", "sqlalchemy": {"version": "2.0", "extras": ["x"]}},
                                 "group": {"dev": {"dependencies": {"pytest": "^8"}}}, "dev-dependencies": {"black": "*"},
                                 "scripts": {"app": "app:run"}, "packages": [{"include": "app"}]},
                      "pytest": {"ini_options": {"testpaths": ["tests"], "addopts": "-q"}},
                      "ruff": {"line-length": 100, "lint": {"select": ["E"]}}, "uv": {"dev-dependencies": ["pytest"]},
                      "setuptools": {"packages": {"find": {"where": ["."]}}}, "coverage": {"run": {"source": ["app"]}},
                      "mypy": {"strict": True}, "pdm": {"dev-dependencies": {"test": ["pytest"]}},
                      "hatch": {"envs": {"default": {"dependencies": ["pytest"]}}}, "bandit": {"exclude_dirs": ["tests"]}}}
PACK = {"pack": "mine", "version": "1", "about": "a project's own pack", "homepage": "https://x.example",
        "requires": {"files": ["app.py"], "text": ["flask"]},
        "rules": [{"id": "LP-MINE-SYSTEM", "title": "A shell command is started", "severity": "LOW", "cwe": 78, "files": ["**/*.py"],
                   "pattern": "os\\.system", "unless": "allowed-here", "confidence": "LOW", "fix": "Use a list of arguments.",
                   "more": "A shell reads the whole line.", "category": "code"}],
        "entries": [{"kind": "route", "files": ["**/*.py"], "pattern": "add_url_rule\\(['\"]([^'\"]+)['\"],\\s*view_func=(\\w+)",
                     "detail": "ANY {1}", "handler": "{2}"}]}
PY_SRC = {"app.py": "import os\nfrom flask import Flask\napp = Flask(__name__)\n\n\ndef run():\n    os.system('ls')\n\n\n"
                    "app.add_url_rule('/run', view_func=run)\n",
          "requirements.txt": "flask==2.0.1\n", "tests/test_app.py": "def test_x():\n    assert True\n",
          "lantern-packs/mine.json": json.dumps(PACK)}
PIPFILE = {"source": [{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": True}],
           "packages": {"flask": "==2.0.1", "requests": {"version": "*", "extras": ["socks"]}}, "dev-packages": {"pytest": "*"},
           "requires": {"python_version": "3.11"}, "scripts": {"test": "pytest"}}
NOTEBOOK = {"cells": [{"cell_type": "code", "execution_count": 1, "metadata": {},
                       "source": ["import openai\n", "client = openai.OpenAI()\n",
                                  "client.chat.completions.create(model='m', messages=[])\n"],
                       "outputs": [{"output_type": "stream", "name": "stdout", "text": ["hello\n"]},
                                   {"output_type": "execute_result", "data": {"text/plain": ["'x'"]}, "metadata": {},
                                    "execution_count": 1}]},
                      {"cell_type": "markdown", "metadata": {}, "source": "notes"}],
            "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                         "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 5}
ACCEPTED = {"accepted": [{"id": "FINDING", "reason": "known and reviewed by the team", "by": "me", "date": "2026-11-01"}],
            "version": 1}
UV_LOCK = {"version": 1, "requires-python": ">=3.11",
           "package": [{"name": "flask", "version": "2.0.1", "source": {"registry": "https://pypi.org/simple"},
                        "dependencies": [{"name": "click"}], "sdist": {"url": "https://x.example/f.tar.gz", "hash": "sha256:00"}},
                       {"name": "app", "version": "0.1.0", "source": {"editable": "."}}]}
PIPFILE_LOCK = {"_meta": {"hash": {"sha256": "00"}, "pipfile-spec": 6, "requires": {"python_version": "3.11"}, "sources": []},
                "default": {"flask": {"hashes": ["sha256:00"], "index": "pypi", "version": "==2.0.1"},
                            "ours": {"git": "https://x.example/ours.git", "ref": "abc"}},
                "develop": {"pytest": {"version": "==8.0.0"}}}
COMPOSER = {"name": "acme/app", "type": "project", "require": {"php": "^8.1", "laravel/framework": "^10.0", "guzzlehttp/guzzle": "7.8.0"},
            "require-dev": {"phpunit/phpunit": "^10"}, "autoload": {"psr-4": {"App\\": "app/"}, "files": ["helpers.php"]},
            "autoload-dev": {"psr-4": {"Tests\\": "tests/"}}, "scripts": {"test": "phpunit", "post-install-cmd": ["@php artisan x"]},
            "config": {"allow-plugins": {"x/y": True}}, "extra": {"laravel": {"dont-discover": []}}, "minimum-stability": "stable",
            "repositories": [{"type": "vcs", "url": "https://x.example/r.git"}]}
COMPOSER_LOCK = {"_readme": ["x"], "content-hash": "00",
                 "packages": [{"name": "laravel/framework", "version": "v10.0.0", "source": {"type": "git", "url": "https://x.example"},
                               "require": {"php": "^8.1"}, "type": "library"},
                              {"name": "acme/fork", "version": "dev-main"}],
                 "packages-dev": [{"name": "phpunit/phpunit", "version": "10.0.0"}], "aliases": [], "minimum-stability": "stable",
                 "platform": {"php": "^8.1"}}
PHP_SRC = {"index.php": "<?php\n$id = $_GET['id'];\necho $id;\n", "routes/web.php": "<?php\nRoute::get('/x', function () { return 1; });\n",
           "app/Http/Controllers/A.php": "<?php\nnamespace App\\Http\\Controllers;\nclass A { public function show() { return 1; } }\n"}
CATALOG = {"versions": {"gson": "2.8.5", "kotlin": {"strictly": "1.9.0"}},
           "libraries": {"gson": {"module": "com.google.code.gson:gson", "version": {"ref": "gson"}},
                         "okhttp": {"group": "com.squareup.okhttp3", "name": "okhttp", "version": "4.12.0"},
                         "plain": "com.example:plain:1.2.3", "bom": {"module": "com.example:bom"}},
           "bundles": {"net": ["okhttp"]}, "plugins": {"android": {"id": "com.android.application", "version": "8.2.0"}}}
JV_SRC = {"app/build.gradle": "dependencies {\n    implementation 'com.example:a:1.0'\n}\n",
          "app/src/main/java/com/x/A.java": "package com.x;\npublic class A { public int a() { return 1; } }\n"}
CARGO = {"package": {"name": "app", "version": "0.1.0", "edition": "2021"},
         "dependencies": {"axum": "0.7", "serde": {"version": "1", "features": ["derive"]}, "tokio": {"version": "1", "features": ["full"]}},
         "dev-dependencies": {"tempfile": "3"}, "workspace": {"members": ["crates/a"], "dependencies": {"anyhow": "1"}},
         "bin": [{"name": "app", "path": "src/main.rs"}], "lib": {"name": "app", "path": "src/lib.rs"}, "features": {"default": []}}
RS_SRC = {"src/main.rs": "use axum::{routing::get, Router};\nasync fn items() -> &'static str { \"x\" }\n"
                         "#[tokio::main]\nasync fn main() { let _app: Router = Router::new().route(\"/items\", get(items)); }\n",
          "src/lib.rs": "pub fn helper() {}\n", "crates/a/Cargo.toml": "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
          "crates/a/src/lib.rs": "pub fn a() {}\n"}
FIREBASE = {"firestore": {"rules": "firestore.rules"},
            "hosting": {"public": "dist", "rewrites": [{"source": "**", "destination": "/index.html"}],
                        "headers": [{"source": "**", "headers": [{"key": "X", "value": "y"}]}]},
            "functions": {"source": "functions"}, "storage": {"rules": "storage.rules"}, "database": {"rules": "database.rules.json"}}
DATABASE_RULES = {"rules": {".read": True, ".write": "auth != null", "users": {"$uid": {".read": "$uid === auth.uid"}}}}
VERCEL = {"headers": [{"source": "/(.*)", "headers": [{"key": "X-Frame-Options", "value": "DENY"}]}],
          "rewrites": [{"source": "/a", "destination": "/b"}], "functions": {"api/*.js": {"maxDuration": 10}},
          "crons": [{"path": "/api/cron", "schedule": "0 0 * * *"}]}
APPSETTINGS = {"ConnectionStrings": {"Default": "Server=x;Database=y"}, "Logging": {"LogLevel": {"Default": "Information"}},
               "Jwt": {"Issuer": "y"}, "AllowedHosts": "*"}
CS_SRC = {"Program.cs": "var builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\n"
                        "app.MapGet(\"/items\", () => \"x\");\napp.Run();\n",
          "App.csproj": "<Project Sdk=\"Microsoft.NET.Sdk.Web\"><PropertyGroup><TargetFramework>net8.0</TargetFramework>"
                        "</PropertyGroup></Project>\n"}
# What an earlier run leaves in the results folder; "FINDING" and "IDS" stand for the tiny project's own finding id
# and the engine's id version, put in when the project is written (Project.__init__).
SECURITY = {"id_version": "IDS", "findings": [{"id": "FINDING", "rule": "LP-MINE-SYSTEM", "rank": "low", "status": "open"}],
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 1}, "tools": [{"tool": "bandit", "state": "ok"}]}
BASELINE = {"date": "2026-11-01", "commit": "0123abc", "id_version": "IDS",
            "readiness": {"score": 50, "grade": "F", "categories": {"Security": 10, "Tests": None}},
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 1},
            "findings": {"FINDING": {"rule": "LP-MINE-SYSTEM", "rank": "low", "title": "x", "file": "app.py", "line": 7},
                         "0000000000aa": {"rule": "B602", "rank": "high", "title": "gone since", "file": "old.py", "line": 3}}}
EXPLANATIONS = {"metaphor": {"world": "a kitchen", "roles": {"py:app.run": "the cook"}},
                "explanations": {"py:app.run": {"prompt_version": "lens-v4", "technical": "Starts ls.", "everyday": "Lists files.",
                                                "mapped": [{"metaphor": "the cook", "technical": "run", "anchor": "run"}],
                                                "scenario": "A tester opens /run."}},
                "stats": {"model": "stand-in/model", "validated": 1, "failed": 0, "cached": 0, "stopped": None}}


@dataclass(frozen=True)
class Kind:
    src: dict            # the tiny project's other files
    name: str            # the swept file, from the project's top (or from the results folder)
    tree: object         # what it says when it is as it should be
    fmt: str = "json"    # or "toml"
    group: str = "manifest"
    where: str = "repo"  # or "out": the results folder


JS_ALL = JS_SRC | {"package.json": json.dumps(PACKAGE), "tsconfig.json": json.dumps(TSCONFIG), "app.json": json.dumps(APP_JSON)}
KINDS = {
    "js:package.json": Kind(JS_ALL, "package.json", PACKAGE),
    "js:tsconfig.json": Kind(JS_ALL, "tsconfig.json", TSCONFIG),
    "js:app.json": Kind(JS_ALL, "app.json", APP_JSON),
    "py:pyproject.toml": Kind(PY_SRC, "pyproject.toml", PYPROJECT, "toml"),
    "py:Pipfile": Kind(PY_SRC, "Pipfile", PIPFILE, "toml"),
    "py:notebook.ipynb": Kind(PY_SRC, "notes/try.ipynb", NOTEBOOK),
    "any:lantern-accepted.json": Kind(PY_SRC, "lantern-accepted.json", ACCEPTED),
    "any:lantern-packs": Kind(PY_SRC, "lantern-packs/mine.json", PACK),
    "py:uv.lock": Kind(PY_SRC, "uv.lock", UV_LOCK, "toml", "dependency"),
    "py:Pipfile.lock": Kind(PY_SRC, "Pipfile.lock", PIPFILE_LOCK, "json", "dependency"),
    "php:composer.lock": Kind(PHP_SRC | {"composer.json": json.dumps(COMPOSER)}, "composer.lock", COMPOSER_LOCK, "json", "dependency"),
    "jv:libs.versions.toml": Kind(JV_SRC, "gradle/libs.versions.toml", CATALOG, "toml", "dependency"),
    "out:security.json": Kind(PY_SRC, "security.json", SECURITY, "json", "results", "out"),
    "out:baseline.json": Kind(PY_SRC, "baseline.json", BASELINE, "json", "results", "out"),
    "out:explanations.json": Kind(PY_SRC, "explanations.json", EXPLANATIONS, "json", "results", "out"),
    "js:firebase.json": Kind(JS_ALL | {"firestore.rules": "service cloud.firestore {}\n",
                                       "database.rules.json": json.dumps(DATABASE_RULES)}, "firebase.json", FIREBASE, "json", "text"),
    "js:database.rules.json": Kind(JS_ALL | {"firebase.json": json.dumps(FIREBASE)}, "database.rules.json", DATABASE_RULES, "json", "text"),
    "js:vercel.json": Kind(JS_ALL, "vercel.json", VERCEL, "json", "text"),
    "php:composer.json": Kind(PHP_SRC, "composer.json", COMPOSER, "json", "text"),
    "rust:Cargo.toml": Kind(RS_SRC, "Cargo.toml", CARGO, "toml", "text"),
    "cs:appsettings.json": Kind(CS_SRC, "appsettings.json", APPSETTINGS, "json", "text"),
}


def _toml_value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    return "{ " + ", ".join(f"{json.dumps(k)} = {_toml_value(x)}" for k, x in v.items()) + " }"


def _has_nothing(v) -> bool:
    return v is None or (isinstance(v, list) and any(_has_nothing(x) for x in v)) \
        or (isinstance(v, dict) and any(_has_nothing(x) for x in v.values()))


def text_of(tree, fmt: str) -> str | None:
    """`tree` as the file's text; None when the format cannot say it (TOML has no "nothing", and its top is a table)."""
    if fmt == "json":
        return json.dumps(tree)
    if not isinstance(tree, dict) or _has_nothing(tree):
        return None
    return "".join(f"{json.dumps(k)} = {_toml_value(v)}\n" for k, v in tree.items())


def places(tree, at=()):
    """Every place in the tree, the top included, as the keys that lead to it."""
    yield at
    if isinstance(tree, dict):
        for k, v in tree.items():
            yield from places(v, at + (k,))
    elif isinstance(tree, list):
        for i, v in enumerate(tree):
            yield from places(v, at + (i,))


def value_at(tree, at):
    for k in at:
        tree = tree[k]
    return tree


def swapped(tree, at, value):
    """A copy of `tree` with `value` at the place `at`."""
    if not at:
        return copy.deepcopy(value)
    new = copy.deepcopy(tree)
    node = new
    for k in at[:-1]:
        node = node[k]
    node[at[-1]] = copy.deepcopy(value)
    return new


def name_of(at) -> str:
    return ".".join(map(str, at)) or "(top)"


def variants(tree, fmt: str, replacements=None, depth: int | None = None):
    """(place, replacement, the file's text) for every swap of one value: each place at most `depth` keys down (all,
    when None) with each replacement that differs from what is there."""
    for at in places(tree):
        if depth is not None and len(at) > depth:
            continue
        here = value_at(tree, at)
        for r in REPLACEMENTS if replacements is None else replacements:
            if here == r and type(here) is type(r):
                continue
            text = text_of(swapped(tree, at, r), fmt)
            if text is not None:
                yield at, r, text


class Hang(Exception):
    """One analysis ran longer than the sweep allows."""


def _alarm(_signum, _frame):
    raise Hang("no result in time")


class Project:
    """One tiny project on disk, its results folder, and the swept file. The engine is loaded from this checkout (or
    from `engine`, another checkout: today's sweep can measure the code of another day), Bandit is left out, and the
    wall behind the audits is taken away (see the top of this file)."""

    def __init__(self, key: str, work: Path, engine: Path | None = None):
        want = Path(engine).resolve() if engine else ROOT
        if str(want) not in sys.path:
            sys.path.insert(0, str(want))
        from lantern import depaudit, pipeline, scanresult, security
        self.engine = Path(pipeline.__file__).resolve().parents[1]      # what is measured, said with the result
        if engine and self.engine != want:                              # never measure one engine and name another
            raise RuntimeError(f"lantern is already loaded from {self.engine}, not from {want}")
        self._analyze = pipeline.analyze
        self._bandit = lambda repo, applicable=True: ([], scanresult.record("bandit", "ok", role="left out of the sweep"))
        self._security, self._depaudit = security, depaudit
        self.key, self.kind = key, KINDS[key]
        self.repo, self.out = work / "repo", work / "out"
        for rel, body in self.kind.src.items():
            p = self.repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        self.out.mkdir(parents=True, exist_ok=True)
        self.file = (self.out if self.kind.where == "out" else self.repo) / self.kind.name
        self.file.parent.mkdir(parents=True, exist_ok=True)
        self.tree = self.kind.tree
        if self.kind.src is PY_SRC:          # the tiny project's own finding, for the files that name one
            self.write(None)
            self.run()
            sec = json.loads((self.out / "security.json").read_text(encoding="utf-8"))
            fid = next((f["id"] for f in sec["findings"] if f["rule"] == "LP-MINE-SYSTEM"), None)
            if fid is None:
                raise RuntimeError(f"{key}: the tiny project's own finding is missing, so the sweep would prove nothing")
            self.tree = json.loads(json.dumps(self.tree).replace("FINDING", fid).replace('"IDS"', json.dumps(sec["id_version"])))
            for p in self.out.iterdir():     # start from an empty results folder
                p.unlink() if p.is_file() else None
        self.write(None)

    def write(self, text: str | None) -> None:
        """The swept file with `text` (None: as it should be)."""
        self.file.write_text(text_of(self.tree, self.kind.fmt) if text is None else text, encoding="utf-8")

    def run(self) -> dict:
        """The whole analysis, as `lantern analyze --offline` runs it."""
        # (an engine from before 2026-11-10 has no such wall: there is then nothing to take away)
        real = self._security.run_bandit, getattr(self._depaudit, "guarded", None)
        self._security.run_bandit = self._bandit
        self._depaudit.guarded = lambda tool, fn, repo, no_network: fn(repo, no_network)
        try:
            return self._analyze(self.repo, self.out, offline=True, log=lambda *_a, **_k: None)
        finally:
            self._security.run_bandit, self._depaudit.guarded = real

    def stops(self, text: str | None, seconds: int = 0) -> str | None:
        """None when the analysis finishes with the swept file as `text`; else the error and the innermost line of
        Lantern's code it came from. `seconds`: a wall clock for one run (POSIX, main thread)."""
        self.write(text)
        timed = bool(seconds) and hasattr(signal, "SIGALRM")
        if timed:
            before = signal.signal(signal.SIGALRM, _alarm)
            signal.alarm(seconds)
        try:
            self.run()
            return None
        except Exception as exc:  # noqa: BLE001 - every error is a find
            tb = traceback.extract_tb(exc.__traceback__)
            ours = [f for f in tb if "lantern" in Path(f.filename).parts] or list(tb)
            return f"{type(exc).__name__} at {Path(ours[-1].filename).name}:{ours[-1].lineno} in {ours[-1].name}"
        finally:
            if timed:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, before)


def sweep(key: str, work: Path, replacements=None, depth: int | None = None, seconds: int = 0,
          engine: Path | None = None) -> dict:
    """Every variant of one file. {"key", "engine", "runs", "finds": {where: [[place, replacement], ...]}}."""
    try:                                # the file as it should be comes first: when that stops, nothing else is tried
        project = Project(key, work, engine)
        twin = project.stops(None, seconds)
    except Exception as exc:  # noqa: BLE001 - said as a find, like every other error
        twin = type(exc).__name__ + " while the tiny project was set up"
    if twin:
        return {"key": key, "engine": None, "runs": 1, "finds": {twin + " (the file as it should be)": [["(none)", "null"]]}}
    runs, finds = 0, {}
    for at, r, text in variants(project.tree, project.kind.fmt, replacements, depth):
        runs += 1
        where = project.stops(text, seconds)
        if where:
            finds.setdefault(where, []).append([name_of(at), json.dumps(r)])
    project.write(None)
    return {"key": key, "engine": str(project.engine), "runs": runs, "finds": finds}


def _one(args) -> dict:
    key, work, seconds, depth, engine = args
    return sweep(key, Path(work) / key.replace(":", "_").replace("/", "_"), depth=depth, seconds=seconds,
                 engine=Path(engine) if engine else None)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", default="", help="comma-separated keys of KINDS (default: all)")
    ap.add_argument("--depth", type=int, default=None, help="only values this many levels down (1: a quick pass)")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--seconds", type=int, default=60, help="wall clock for one analysis")
    ap.add_argument("--work", default="", help="folder for the tiny projects (default: a temporary one)")
    ap.add_argument("--json", default="", help="write the results here as JSON")
    ap.add_argument("--engine", default="", help="another checkout whose `lantern` is swept (default: this one)")
    a = ap.parse_args(argv)
    keys = [k for k in a.only.split(",") if k] or list(KINDS)
    unknown = [k for k in keys if k not in KINDS]
    if unknown:
        print(f"unknown: {', '.join(unknown)}; the keys are: {', '.join(KINDS)}", file=sys.stderr)
        return 2
    guard = netguard.begin()                      # isolated (tools/netguard); this benchmark needs no network at all
    work = Path(a.work or tempfile.mkdtemp(prefix="lantern-manifests-"))
    t0 = time.time()
    jobs = [(k, str(work), a.seconds, a.depth, a.engine) for k in keys]
    if a.jobs > 1:
        with mp.Pool(a.jobs) as pool:
            results = pool.map(_one, jobs, chunksize=1)
    else:
        results = [_one(j) for j in jobs]
    runs = sum(r["runs"] for r in results)
    stopped = sum(len(v) for r in results for v in r["finds"].values())
    lines = sorted({w.split(" at ", 1)[-1] for r in results for w in r["finds"]})
    for r in results:
        n = sum(len(v) for v in r["finds"].values())
        print(f"{r['key']:26} {KINDS[r['key']].group:10} {r['runs']:5} variants, {n:4} stopped the analysis")
        for where, cases in sorted(r["finds"].items()):
            print(f"    {where:62} {len(cases):4}, e.g. {cases[0][0]} = {cases[0][1]}")
    print(f"{runs} variants of {len(results)} files in {time.time() - t0:.0f} s: {stopped} stopped the analysis, "
          f"at {len(lines)} line(s) of the code")
    if a.json:
        engines = sorted({r["engine"] for r in results if r["engine"]})
        Path(a.json).write_text(json.dumps({"engine": engines, "runs": runs, "stopped": stopped, "lines": lines,
                                            "files": results}, indent=1), encoding="utf-8")
    refused = netguard.end(guard)
    return 1 if stopped or refused else 0


if __name__ == "__main__":
    mp.set_start_method("spawn" if sys.platform != "linux" else "fork")
    sys.exit(main())
