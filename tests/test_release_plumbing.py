"""Release plumbing: one version everywhere, a CHANGELOG section per release that fits the release page, `serve --check`,
scanners that say they are off, one install command for testers.

The first five tests were `tests/test_release.py` until 2026-11-12. That day the file was written anew for the release
decision (Blocked, Incomplete, Passed) and these five went with the old text by mistake: from then until this file
nothing checked that the version is one version, that a release has its CHANGELOG section, or that the README, the
site and the testers' guide give the same pinned install command. They are back as they were, under this name."""
import ast
import re
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
    assert meta["version"] == lantern.__version__ == "0.11.0"
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

def test_notes_too_long_for_the_release_page_are_refused_before_anything_is_built(tmp_path, capsys):
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


# ---- the release tests the installed package, with the checkout's lantern/ folder moved away (2026-11-12) -----------
#
# `.github/workflows/release.yml`, job `test-wheel`: the package is built, `lantern/` is moved out of the checkout and
# every test runs against what was installed, so a file that is missing from the package shows. A test that reaches
# for Lantern's own files through the checkout then finds none. A trial of the 0.11.0 release ended that way with 12
# tests failed, and three more had walked a folder that was gone and passed on nothing. At 0.10.0 one such test
# failed after the tag was pushed (#88). `tests/lantern_files.py` says where the package is.

CHECKOUT_FOLDERS = {"gateway", "cloud", "tests", "tools", "bench", "examples", "cloud/lantern_cloud",
                    "gateway/lantern_gateway"}


def _from_the_checkout(source: str) -> list[str]:
    """The lines of a test file that reach for Lantern's package through the checkout: a path put together with the
    folder name `lantern` on a place worked out from the file's own (`ROOT / "lantern"`,
    `Path(__file__).parents[1] / "lantern" / "viewer"`), and a list of the checkout's source folders with `lantern`
    among them (`for folder in ("lantern", "gateway")`)."""
    tree = ast.parse(source)
    here = {"__file__"}                      # the names that hold a place worked out from this file's own
    grew = True
    while grew:
        grew = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(isinstance(n, ast.Name) and n.id in here for n in ast.walk(node.value)):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id not in here:
                        here.add(target.id)
                        grew = True
    found = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and isinstance(node.right, ast.Constant)
                and isinstance(node.right.value, str)
                and (node.right.value == "lantern" or node.right.value.startswith("lantern/"))
                and any(isinstance(n, ast.Name) and n.id in here for n in ast.walk(node.left))):
            found.append(f"line {node.lineno}: a path to `lantern` from the test file's own place")
        if isinstance(node, (ast.Tuple, ast.List)) and node.elts and all(
                isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts):
            words = {e.value for e in node.elts}
            if "lantern" in words and words & CHECKOUT_FOLDERS:
                found.append(f"line {node.lineno}: `lantern` in a list of the checkout's folders")
    return found


def test_no_test_looks_for_lanterns_own_files_in_the_checkout():
    """Each way a test reached for the package through the checkout, beside the ways that stay right when the
    package is installed and the folder is gone. Then every test file is read."""
    for wrong in ('ROOT = Path(__file__).parents[1]\npage = (ROOT / "lantern" / "viewer" / "app.html").read_text()\n',
                  'html = (Path(__file__).parents[1] / "lantern" / "viewer" / "report.html").read_text()\n',
                  'HERE = Path(__file__).parent\nTOP = HERE.parent\nfor p in (TOP / "lantern").glob("*.py"):\n    pass\n',
                  'ROOT = Path(__file__).parents[1]\nsource = (ROOT / "lantern/depaudit.py").read_text()\n',
                  'for folder in ("lantern", "cloud/lantern_cloud", "gateway"):\n    pass\n'):
        assert _from_the_checkout(wrong), wrong
    for right in ('import lantern\npage = (Path(lantern.__file__).parent / "viewer" / "app.html").read_text()\n',
                  'from lantern_files import PACKAGE\nsource = (PACKAGE / "depaudit.py").read_text()\n',
                  'def test_it(tmp_path):\n    out = tmp_path / "results" / "lantern"\n',
                  'cmd = ["lantern", "analyze", "--offline"]\n',
                  'ROOT = Path(__file__).parents[1]\ntext = (ROOT / "gateway" / "pyproject.toml").read_text()\n'):
        assert not _from_the_checkout(right), right
    tests = sorted((ROOT / "tests").glob("*.py"))
    assert len(tests) > 90
    found = {p.name: lines for p in tests if p.name != "lantern_files.py"
             for lines in [_from_the_checkout(p.read_text(encoding="utf-8"))] if lines}
    assert not found, found


def test_the_place_tests_are_sent_to_is_the_package_python_loaded():
    """`tests/lantern_files.py`: the folder Python loaded Lantern from, with its pages and its modules in it, and a
    name for each file that does not depend on where that folder is."""
    import lantern_files
    assert lantern_files.PACKAGE == Path(lantern.__file__).resolve().parent
    assert "<title>" in lantern_files.page("report.html") and "<title>" in lantern_files.page("app.html")
    top, deep = lantern_files.modules(), lantern_files.modules(deep=True)
    assert lantern_files.PACKAGE / "engine.py" in top and set(top) <= set(deep) and len(top) > lantern_files.FEWEST
    assert lantern_files.named(lantern_files.PACKAGE / "engine.py") == "lantern/engine.py"
    assert lantern_files.named(ROOT / "tests" / "conftest.py") == "tests/conftest.py"


def test_a_rehearsal_does_all_a_tag_does_and_publishes_nothing():
    """`release.yml` can be started by hand ("Run workflow"): the build, the tests against the built wheel and the
    look at the live gateway run as for a tag, and the one job that may write to the repository runs only for a
    pushed tag. A rehearsal has no tag, so the version is the package's own."""
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    head, jobs = text.split("\njobs:\n", 1)
    assert head.endswith('on:\n  push:\n    tags: ["v*"]\n  workflow_dispatch:\npermissions:\n  contents: read')
    names = re.findall(r"^  ([a-z-]+):$", jobs, re.M)
    assert names == ["build", "test-wheel", "gateway-up", "publish"]
    publish = jobs[jobs.index("\n  publish:\n"):]
    assert "    needs: [build, test-wheel, gateway-up]\n    if: github.event_name == 'push'" in publish
    assert text.count("contents: write") == 1 and "contents: write" in publish     # the only job that may write
    assert len(re.findall(r"^    if:", jobs, re.M)) == 1                # a rehearsal leaves no other job out
    assert text.count("gh release create") == 1 and "gh release create" in publish
    build = jobs[: jobs.index("\n  test-wheel:\n")]
    version, notes, built = (build.index(word) for word in (
        "- name: Tag matches the package version", "- name: The CHANGELOG has a section", "python -m build"))
    assert version < notes < built                      # too long a section stops the release before anything is built
    step = build[version:notes]
    assert 'if [ "$GITHUB_EVENT_NAME" = "workflow_dispatch" ]; then' in step
    assert 'echo "RELEASE_NAME=v$ver" >> "$GITHUB_ENV"' in step and 'echo "RELEASE_NAME=$GITHUB_REF_NAME" >> "$GITHUB_ENV"' in step
    assert 'python tools/changelog_section.py "$RELEASE_NAME" > release-notes.md' in build[notes:built]
    assert "${{" not in build[version:built]            # names reach the shell as variables, never as text of the script
