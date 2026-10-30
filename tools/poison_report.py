"""Write a copy of a report whose data is hostile: every string gets an HTML payload appended and every number is
replaced by one. The viewer must show the payload as text everywhere; if any of it lands in the page as markup,
`tools/viewer_smoke.js` fails (it looks for the payload's `data-pwn` attribute and for a changed title).

Usage: python tools/poison_report.py IN/report.html OUT/report.html
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


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    src, dst = Path(argv[1]), Path(argv[2])
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(render(poison(read_bundle(src))), encoding="utf-8", newline="\n")
    print(dst)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
