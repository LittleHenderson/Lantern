"""Print the CHANGELOG.md section for a version or tag (used by the release workflow).

    python tools/changelog_section.py v0.9.0-rc1      # '## 0.9.0-rc1' if present, else '## 0.9.0'

Exits 1 when neither heading exists, so a release never goes out with an empty body.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def section(text: str, version: str) -> str | None:
    version = version.removeprefix("refs/tags/").lstrip("v")
    base = re.sub(r"[-.]?(rc|a|b|dev)\d*$", "", version)
    for want in dict.fromkeys((version, base)):
        m = re.search(rf"^## {re.escape(want)}[ \t]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
        if m and m.group(1).strip():
            return m.group(1).strip() + "\n"
    return None


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[1] / "CHANGELOG.md"
    body = section(path.read_text(encoding="utf-8"), argv[0])
    if body is None:
        print(f"CHANGELOG.md has no section for {argv[0]}", file=sys.stderr)
        return 1
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
