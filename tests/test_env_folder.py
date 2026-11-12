"""A folder named `env` (round 3 of directive point 4, 2026-11-11).

Until then every reader left out any folder named `env`, anywhere in a project, as a Python environment
(`python -m venv env`). A project's own folder of that name (`config/env/`, `src/env/`) was therefore not read at
all: no function of it on the map, no rule run on it, no finding. Found with a settings file of my own in
`config/env/`. Now the name alone is not enough: the folder is left out only where it holds what an environment
holds (`lantern.python_frontend.is_environment`). Each case below has its twin."""

import re
from pathlib import Path

import pytest

from lantern import python_frontend, websec
from lantern.engine import build_graph

OWN = {
    "Cargo.toml": '[package]\nname = "app"\nversion = "0.1.0"\n',
    "go.mod": "module example.com/app\n\ngo 1.22\n",
    "pyproject.toml": '[project]\nname="app"\nversion="0"\n',
    "package.json": '{"name": "app", "dependencies": {"express": "4.19.2"}}',
    "src/env/a.py": "def from_python():\n    return 1\n",
    "src/env/b.js": "function fromJs() {\n  return 1\n}\nmodule.exports = { fromJs }\n",
    "src/env/c.go": "package env\n\nfunc FromGo() int {\n\treturn 1\n}\n",
    "src/env/mod.rs": "pub fn from_rust() -> i32 {\n    1\n}\n",
    "src/env/D.java": "package env;\n\npublic class D {\n    int fromJava() {\n        return 1;\n    }\n}\n",
    "src/env/e.kt": "package env\n\nfun fromKotlin(): Int {\n    return 1\n}\n",
    "src/env/f.swift": "func fromSwift() -> Int {\n    return 1\n}\n",
    "src/env/g.dart": "int fromDart() {\n  return 1;\n}\n",
    "src/env/H.cs": "namespace Env\n{\n    public class H\n    {\n        public int FromCs() { return 1; }\n    }\n}\n",
    "src/env/i.php": "<?php\nfunction from_php() {\n    return 1;\n}\n",
    "src/env/j.rb": "def from_ruby\n  1\nend\n",
    "src/env/k.cpp": "int from_cpp() {\n    return 1;\n}\n",
}
ENVIRONMENTS = {
    "made by `python -m venv`": ["pyvenv.cfg"],
    "made by conda": ["conda-meta/history"],
    "an older virtualenv": ["bin/activate"],
    "on Windows": ["Scripts/python.exe"],
    "only its library folder is left": ["lib/python3.12/os.py"],
}


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _read_files(root):
    return {n.file for n in build_graph(root).nodes.values() if n.file and n.file.startswith("src/env/")}


def test_code_in_a_projects_own_folder_named_env_is_on_the_map_in_every_language(tmp_path):
    _write(tmp_path, OWN)
    assert _read_files(tmp_path) == {rel for rel in OWN if rel.startswith("src/env/")}


@pytest.mark.parametrize("case", sorted(ENVIRONMENTS))
def test_a_python_environment_named_env_is_still_left_out(tmp_path, case):
    _write(tmp_path, {**OWN, **{"src/env/" + rel: "" for rel in ENVIRONMENTS[case]}})
    assert _read_files(tmp_path) == set()


def test_an_environment_at_the_top_and_a_folder_of_the_projects_own_below(tmp_path):
    _write(tmp_path, {"pyproject.toml": OWN["pyproject.toml"], "env/pyvenv.cfg": "home = /usr/bin\n",
                      "env/lib/python3.12/site-packages/lib_x/__init__.py": "def lib():\n    return 1\n",
                      "env/lib/python3.12/json_copy.py": "def stdlib():\n    return 1\n",
                      "app/env/settings.py": "def load():\n    return {}\n"})
    files = {n.file for n in build_graph(tmp_path).nodes.values() if n.file}
    assert files == {"app/env/settings.py"}, files


def test_the_rules_run_on_a_settings_file_in_a_folder_named_env(tmp_path):
    files = {"config/env/all.js": "module.exports = {\n  port: 3000,\n  cookieSecret: 'made-up-signing-text'\n}\n",
             "views/env/page.ejs": "<div><%- bio %></div>\n"}
    _write(tmp_path, files)
    assert [(f["file"], f["line"]) for f in websec.inline_secrets(tmp_path)] == [("config/env/all.js", 3)]
    assert [(f["file"], f["line"]) for f in websec.template_rules(tmp_path)] == [("views/env/page.ejs", 1)]
    _write(tmp_path, {"config/env/pyvenv.cfg": "", "views/env/pyvenv.cfg": ""})
    assert websec.inline_secrets(tmp_path) == [] and websec.template_rules(tmp_path) == []


def test_the_other_names_are_left_out_as_before(tmp_path):
    _write(tmp_path, {"pyproject.toml": OWN["pyproject.toml"], "app/main.py": "def main():\n    return 1\n",
                      **{f"{d}/x.py": "def f():\n    return 1\n"
                         for d in ("venv", ".venv", ".env", "node_modules", "build", "dist", "site-packages")}})
    assert {n.file for n in build_graph(tmp_path).nodes.values() if n.file} == {"app/main.py"}


def test_a_folder_is_asked_what_it_holds_not_what_it_points_at(tmp_path):
    # `env/bin/python` is a link to a program outside the project in a real environment, and a link to nothing in
    # one that was copied from another computer: the link's being there is the sign, it is never followed
    env = tmp_path / "env"
    (env / "bin").mkdir(parents=True)
    try:
        (env / "bin" / "python").symlink_to(tmp_path / "nowhere" / "python3")
    except OSError:
        pytest.skip("this system makes no links here")
    assert python_frontend.is_environment(env)
    assert not python_frontend.is_environment(tmp_path / "bin")


def test_no_reader_leaves_a_folder_out_by_its_name_alone():
    """Every reader asks `skipped` / `skipped_dir`; a new one that tests `in SKIP_DIRS` itself would leave out a
    project's own `env` folder again, or read an environment."""
    root = Path(python_frontend.__file__).parent
    said = re.compile(r"\bin\s+SKIP_DIRS\b|SKIP_DIRS\s*[|&]")
    found = [f"{p.name}:{i}" for p in sorted(root.glob("*.py")) for i, ln in enumerate(
        p.read_text(encoding="utf-8").splitlines(), 1)
        if said.search(ln) and not (p.name == "python_frontend.py" and "def skipped" in "".join(
            p.read_text(encoding="utf-8").splitlines()[max(0, i - 12):i]))]
    assert found == [], found
