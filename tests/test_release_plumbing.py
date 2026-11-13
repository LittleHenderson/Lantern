"""Release plumbing: one version everywhere, a CHANGELOG section per release that fits the release page, `serve --check`,
scanners that say they are off, one install command for testers.

The first five tests were `tests/test_release.py` until 2026-11-12. That day the file was written anew for the release
decision (Blocked, Incomplete, Passed) and these five went with the old text by mistake: from then until this file
nothing checked that the version is one version, that a release has its CHANGELOG section, or that the README, the
site and the testers' guide give the same pinned install command. They are back as they were, under this name."""
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
    assert meta["version"] == lantern.__version__ == "0.10.0"
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


def test_tester_guide_and_issue_form():
    """docs/try-lantern.md has the eight sections in order, and README, the site and the guide give one install command."""
    import re
    root = Path(__file__).parents[1]
    doc = (root / "docs/try-lantern.md").read_text(encoding="utf-8")
    heads = re.findall(r"^## (\d)\. (.+)$", doc, re.M)
    assert [n for n, _ in heads] == [str(i) for i in range(1, 9)]
    words = ["what it does", "install", "run", "what to look at", "explanations", "what runs where", "how to report", "uninstall"]
    assert all(w in h.lower() for w, (_, h) in zip(words, heads)), heads
    assert "[ocr]" in doc and "tesseract" in doc.lower()
    cmd = 'pip install "lantern[scan] @ git+https://github.com/LittleHenderson/Lantern'
    readme, site = (root / "README.md").read_text(encoding="utf-8"), (root / "site/index.html").read_text(encoding="utf-8")
    pinned = lambda text: set(re.findall(re.escape(cmd) + r'[^"]*"', text))  # noqa: E731
    assert pinned(doc) == pinned(readme) == pinned(site) and len(pinned(doc)) == 1
    import lantern as _l
    assert pinned(doc) == {cmd + f'@v{_l.__version__}"'}            # testers install the tagged release
    assert "docs/try-lantern.md" in readme and "docs/try-lantern.md" in site
    form = (root / ".github/ISSUE_TEMPLATE/tester-report.yml").read_text(encoding="utf-8")
    assert 'labels: ["tester", "v0.9"]' in form and "id: version" in form
    cfg = (root / ".github/ISSUE_TEMPLATE/config.yml").read_text(encoding="utf-8")
    assert "blank_issues_enabled: false" in cfg and "docs/try-lantern.md" in cfg


# ---- the release page takes only so much text (2026-11-12) ----------------------------------------------------------
#
# The release workflow hands a version's CHANGELOG section to GitHub as the text of the Release. GitHub refuses a
# Release whose text is over 125,000 characters, and it refuses at the very last step, after the build and the tests
# against the wheel. On 2026-11-12 the section waiting to be released was 193,835 characters long.

def test_notes_too_long_for_the_release_page_are_refused_at_the_first_step(tmp_path, capsys):
    """`tools/changelog_section.py` is the workflow's second step. A section GitHub would refuse ends it with 1 and a
    sentence that says how long it is, so the release stops before anything is built."""
    long = tmp_path / "CHANGELOG.md"
    long.write_text("## 2.0.0\n\n" + "- a change, told at length\n" * 5000 + "\n## 1.0.0\n\nold\n", encoding="utf-8")
    size = len(changelog_section.section(long.read_text(encoding="utf-8"), "2.0.0"))
    assert size == 135_000 > changelog_section.LIMIT
    assert changelog_section.main(["v2.0.0", str(long)]) == 1
    out, err = capsys.readouterr()
    assert out == "" and "v2.0.0" in err and "135,000" in err and f"{changelog_section.LIMIT:,}" in err, err
    assert changelog_section.main(["v1.0.0", str(long)]) == 0 and capsys.readouterr().out == "old\n"


def test_a_section_that_just_fits_goes_out_and_one_character_more_does_not(tmp_path, capsys):
    """The twin: the limit is the limit, not a guess below it. The text is counted as GitHub receives it."""
    def notes(n):
        p = tmp_path / f"{n}.md"
        p.write_text("## 3.0.0\n" + "x" * (n - 1) + "\n", encoding="utf-8")
        return str(p)
    assert changelog_section.main(["3.0.0", notes(changelog_section.LIMIT)]) == 0
    assert len(capsys.readouterr().out) == changelog_section.LIMIT
    assert changelog_section.main(["3.0.0", notes(changelog_section.LIMIT + 1)]) == 1


def test_this_versions_notes_are_short_enough_to_be_read_on_the_release_page():
    """What goes on the release page is a summary a tester reads. The whole list of changes stays in CHANGELOG.md,
    under a heading of its own (`## <version>: every change`), which is not part of the summary."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    notes = changelog_section.section(text, lantern.__version__)
    assert notes and len(notes) <= 30_000, len(notes or "")
    both = "## 4.0.0\n\nthe summary\n\n## 4.0.0: every change\n\n- one\n- two\n\n## 3.0.0\n\nold\n"
    assert changelog_section.section(both, "v4.0.0") == "the summary\n"
