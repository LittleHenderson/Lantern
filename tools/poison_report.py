"""Write a copy of a report whose data is hostile: every string gets an HTML payload appended and every number is
replaced by one. The viewer must show the payload as text everywhere; if any of it lands in the page as markup,
`tools/viewer_smoke.js` fails (it looks for the payload's `data-pwn` attribute and for a changed title).

Usage: python tools/poison_report.py IN/report.html OUT/report.html [--only KEY,KEY]

`--only scenario` poisons only the values under those keys and keeps everything else intact, so the screens that
show them still render (poisoning every rank and number hides most findings, and the parts of the page that show
them, such as scenarios, would then never be drawn).
"""

from __future__ import annotations

import sys
from pathlib import Path

from lantern.report import read_bundle, render

PAYLOAD = "<img src=x onerror=\"document.title='PWNED'\" data-pwn>"


def poison(o):
    if isinstance(o, dict):
        return {k: poison(v) for k, v in o.items()}
    if isinstance(o, list):
        return [poison(v) for v in o]
    if isinstance(o, bool) or o is None:
        return o
    if isinstance(o, (int, float)):
        return PAYLOAD
    if isinstance(o, str):
        return o + PAYLOAD
    return o


def poison_only(o, keys: set[str]):
    """Poison only the values under `keys` (anywhere in the data); the rest stays as it was."""
    if isinstance(o, dict):
        return {k: poison(v) if k in keys else poison_only(v, keys) for k, v in o.items()}
    if isinstance(o, list):
        return [poison_only(v, keys) for v in o]
    return o


def main(argv: list[str]) -> int:
    only = None
    if len(argv) == 5 and argv[3] == "--only":
        only, argv = set(argv[4].split(",")), argv[:3]
    if len(argv) != 3:
        print(__doc__)
        return 2
    src, dst = Path(argv[1]), Path(argv[2])
    dst.parent.mkdir(parents=True, exist_ok=True)
    data = read_bundle(src)
    dst.write_text(render(poison_only(data, only) if only else poison(data)), encoding="utf-8", newline="\n")
    print(dst)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
