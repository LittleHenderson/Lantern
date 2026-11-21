"""What this computer lets a test make among its files, asked of the system itself (a firm pass or fail, stage 4,
2026-11-20).

Until then a test that makes a symbolic link was skipped on Windows whatever the computer allowed ("a link needs a
right Windows gives few users"), and so was every test that makes a pipe among the files beside one: on GitHub's
Windows machines, whose user may make links, they were not run there, among them most tests of what Lantern does
with a link that comes with a project. Now such a test asks here: `needs_links` skips only where this user may make
no link, `needs_pipes` only where the system has no pipe among its files (Windows has none; a named pipe there is
not a file of a folder), and `needs_long_paths` only where a path longer than Windows' old limit of 260 characters
cannot be made (Windows asks for a setting of its own; the tests that make one were skipped on every Windows).
"""
from __future__ import annotations

import os
import tempfile

import pytest


def _links() -> bool:
    """Can this user make a link to a file and a link to a folder here? (Windows asks for a right of its own.)"""
    try:
        with tempfile.TemporaryDirectory(prefix="lantern-links-") as place:
            folder, file = os.path.join(place, "folder"), os.path.join(place, "file")
            os.mkdir(folder)
            with open(file, "w", encoding="utf-8") as f:
                f.write("x")
            os.symlink(file, os.path.join(place, "to-file"))
            os.symlink(folder, os.path.join(place, "to-folder"), target_is_directory=True)
            return os.path.islink(os.path.join(place, "to-file")) and os.path.islink(os.path.join(place, "to-folder"))
    except (OSError, NotImplementedError, AttributeError):
        return False


def _long_paths() -> bool:
    """Can a file be made here at a path of more than 300 characters?"""
    try:
        with tempfile.TemporaryDirectory(prefix="lantern-long-") as place:
            deep = os.path.join(place, *[f"a-folder-with-a-rather-long-name-{i}-{'x' * 20}" for i in range(6)])
            os.makedirs(deep)
            with open(os.path.join(deep, "file"), "w", encoding="utf-8") as f:
                f.write("x")
            return len(os.path.join(deep, "file")) > 300 and os.path.isfile(os.path.join(deep, "file"))
    except OSError:
        return False


def link(text, at, folder: bool | None = None) -> None:
    """A link at `at` whose text is `text`, made the way this system's own tools make one (found on GitHub's Windows
    machine, 2026-11-20: a test that wrote a link's text with `/` there made a link that leads nowhere, so a safe
    twin failed and a dangerous one passed whatever Lantern did). On Windows the text gets Windows' own separator,
    as `mklink` writes it and git for Windows when it checks a link out, and the link is one to a folder where the
    place it names is a folder (Windows asks which one a link is when it is made): `folder` says so where that place
    is not there yet. Elsewhere it is `os.symlink` as it is."""
    text = os.fspath(text)
    if os.name != "nt":
        os.symlink(text, at)
        return
    text = text.replace("/", "\\")
    if folder is None:
        folder = os.path.isdir(os.path.join(os.path.dirname(os.fspath(at)), text))
    os.symlink(text, at, target_is_directory=folder)


def link_text(at) -> str:
    """A link's text as it was written. For a link that names a full path, Windows' `os.readlink` hands back the
    name it keeps for the system, which begins with `\\\\?\\` (found on GitHub's Windows machine, 2026-11-20)."""
    text = os.readlink(at)
    return text[4:] if os.name == "nt" and text.startswith("\\\\?\\") else text


LINKS = _links()
PIPES = hasattr(os, "mkfifo")
LONG_PATHS = _long_paths()
needs_links = pytest.mark.skipif(not LINKS, reason="this system does not let this user make a symbolic link")
needs_pipes = pytest.mark.skipif(not PIPES, reason="this system has no pipe among its files (Windows)")
needs_long_paths = pytest.mark.skipif(not LONG_PATHS, reason="this system makes no path of more than 300 characters "
                                      "(on Windows that needs a setting of its own)")
