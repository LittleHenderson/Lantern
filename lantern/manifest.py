"""What a project's own files say, taken by shape (2026-11-10, directive stage 7).

package.json, tsconfig.json, app.json, pyproject.toml, Pipfile, a pack in `lantern-packs/`, `lantern-accepted.json`, a
notebook: each comes with the project, and a file that parses can still hold anything where a table, a list or a
word belongs (`"dependencies": "x"`, `paths = 5`). A reader asks here for the shape it needs and gets an empty one when
the file says something else, so an odd value costs the one fact it would have given and never the analysis. Until
that date such a file stopped `lantern analyze` with a Python error. `bench/manifests.py` swaps every value of every
such file for 21 other values and runs the whole analysis on each: on the code before, 839 of its 11,652 files
stopped it, at 50 lines of the code (478 of 5,994 for the files named above; the others were dependency files and
earlier results), and none does now. `tests/test_manifests.py` keeps the cases it found.

These are for what the project says. A file Lantern wrote itself and reads back, and an answer from a tool, have
checks of their own (`pipeline.earlier`, `scanresult.parse_json`). The dependency files are stricter still: what in
them is no package name and version is named in the audit's record (`depaudit.Odd`)."""
from __future__ import annotations

import json
import tomllib


def parse_json(text):
    """What a JSON text says, or None when it is not valid JSON (cut off, nested deeper than Python follows). The
    mark some editors put first in a file is taken off."""
    try:
        return json.loads(text.removeprefix("\ufeff")) if isinstance(text, str) else None
    except (ValueError, RecursionError):
        return None


def parse_toml(text) -> dict:
    """The table a TOML text holds; an empty one when it is not valid TOML."""
    try:
        return tomllib.loads(text.removeprefix("\ufeff")) if isinstance(text, str) else {}
    except (ValueError, RecursionError):
        return {}


def table(value) -> dict:
    """`value` when it is a table (a JSON object, a TOML table), else an empty one."""
    return value if isinstance(value, dict) else {}


def rows(value) -> list:
    """`value` when it is a list, else an empty one. A word is not a list of its letters."""
    return value if isinstance(value, list) else []


def text(value, default: str = "") -> str:
    """`value` when it is text, else `default`."""
    return value if isinstance(value, str) else default


def texts(value) -> list[str]:
    """The texts in a list; whatever else the list holds is left out, and a word alone is no list."""
    return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []


def tables(value) -> list[dict]:
    """The tables in a list; whatever else the list holds is left out."""
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []
