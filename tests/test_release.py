"""Release plumbing: one version everywhere, a CHANGELOG section per release, `serve --check`, scanners that say they are off."""
import subprocess
import sys
import tomllib
from pathlib import Path

import lantern
from lantern import security

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import changelog_section  # noqa: E402


def test_one_version():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert meta["version"] == lantern.__version__ == "0.9.0"
    assert meta["scripts"]["lantern"] == "lantern.cli:main"
    assert meta["urls"]["Issues"].endswith("/issues") and meta["urls"]["Homepage"].startswith("https://")
    assert set(meta["optional-dependencies"]) >= {"scan", "dev"}


def test_changelog_section_for_tags():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert changelog_section.section(text, lantern.__version__)
    assert changelog_section.section(text, "v0.9.0-rc1") == changelog_section.section(text, "0.9.0")
    assert changelog_section.section(text, "v9.9.9") is None
    two = "## 1.1.0\nnew\n\n## 1.0.0\nold\n"
    assert changelog_section.section(two, "v1.1.0") == "new\n" and changelog_section.section(two, "1.0.0") == "old\n"


def test_serve_check(tmp_path):
    env = {**__import__("os").environ, "LANTERN_HOME": str(tmp_path / "home")}
    r = subprocess.run([sys.executable, "-m", "lantern.cli", "serve", str(ROOT / "tests/fixtures/shop"), "--check",
                        "--port", "8901"], capture_output=True, text=True, encoding="utf-8", env=env, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "?token=" in r.stdout and "the app answered" in r.stdout
    assert not (tmp_path / "home" / "projects.json").exists() or "shop" not in (tmp_path / "home" / "projects.json").read_text(encoding="utf-8")
    bad = subprocess.run([sys.executable, "-m", "lantern.cli", "serve", str(tmp_path / "nope"), "--check"],
                         capture_output=True, text=True, encoding="utf-8", env=env, timeout=60)
    assert bad.returncode == 2


def test_bandit_missing_says_so(tmp_path, monkeypatch):
    import importlib.util
    real = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, "find_spec", lambda n, *a: None if n == "bandit" else real(n, *a))
    found, info = security.run_bandit(tmp_path)
    assert found == [] and info["status"].startswith("skipped: not installed") and "lantern[scan]" in info["status"]
