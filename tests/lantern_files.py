"""Where Lantern's own files are, for the tests that read them.

A release is built as a package, the checkout's `lantern/` folder is moved away, and every test is run against the
installed package (`.github/workflows/release.yml`, job `test-wheel`): that is how a file left out of the package
shows. A test that reads `lantern/viewer/report.html`, or walks Lantern's modules, through the checkout's path finds
no file there, or walks a folder that is gone and passes having read nothing. On 2026-11-12 a trial of the 0.11.0
release ended with twelve tests failed that way and three more that had passed on nothing; at 0.10.0 one failed so
after the tag was pushed (#88).

So a test asks here. In a checkout the two are the same folder.
`tests/test_release_plumbing.py::test_no_test_looks_for_lanterns_own_files_in_the_checkout` reads the test files."""
from __future__ import annotations

from pathlib import Path

import lantern

ROOT = Path(__file__).resolve().parents[1]           # the checkout: tests, tools, bench, docs, cloud, gateway
PACKAGE = Path(lantern.__file__).resolve().parent    # Lantern as Python loaded it: the checkout's folder or the installed one
VIEWER = PACKAGE / "viewer"
FEWEST = 50                                          # Lantern has more modules than this; fewer means the wrong folder


def page(name: str) -> str:
    """One of Lantern's pages (`report.html`, `app.html`, `guide.html`) as the package ships it."""
    return (VIEWER / name).read_text(encoding="utf-8")


def modules(deep: bool = False) -> list[Path]:
    """Lantern's own Python files: the package's top folder, with `deep` every folder below it too. Never none: a
    walk that found no file must not read as "nothing wrong"."""
    found = sorted(PACKAGE.rglob("*.py") if deep else PACKAGE.glob("*.py"))
    assert len(found) > FEWEST, f"{len(found)} Python files in {PACKAGE}: that is not Lantern"
    return found


def named(path: Path) -> str:
    """`lantern/x.py` for a file of the package wherever it is installed; any other file from the checkout's top."""
    path = Path(path).resolve()
    if path.is_relative_to(PACKAGE):
        return "lantern/" + path.relative_to(PACKAGE).as_posix()
    return path.relative_to(ROOT).as_posix()
