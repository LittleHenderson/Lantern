"""Probes for tests/test_isolation.py: a test file, or one test, that needs a library which is not installed.

Not collected by a normal run (the file name does not start with test_). PROBE_MISSING_AT says what needs the missing
library: `file` (the whole file is skipped while it is imported, and pytest counts it as one skipped test whatever it
holds), `test` (one test is skipped), or nothing (no test needs it). The last test is skipped every time for another
reason: that is not a missing library, and the rule may not count it as one.
"""
import os

import pytest

MISSING = "a_library_nobody_installed_for_lantern"

if os.environ.get("PROBE_MISSING_AT") == "file":
    pytest.importorskip(MISSING)


def test_that_needs_the_library():
    if os.environ.get("PROBE_MISSING_AT") == "test":
        pytest.importorskip(MISSING)


def test_that_needs_nothing():
    pass


def test_that_needs_another_computer():
    pytest.skip("this needs a kind of computer that is not here")
