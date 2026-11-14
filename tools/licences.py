"""Every library Lantern itself depends on has a licence that allows shipping it (MIT, BSD, Apache 2.0, PSF, ISC,
MPL 2.0, HPND/MIT-CMU for Pillow, the Unlicense). Anything else, or an unknown licence, fails the build so a person
reads it. Also, with --lock-matches, checks requirements-lock.txt still names every library pyproject.toml declares
(a refresh was forgotten when a dependency was added).

    pip install pip-licenses && python tools/licences.py
"""
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ALLOWED = re.compile(r"MIT|BSD|Apache|PSF|Python Software Foundation|ISC|MPL|Mozilla Public License|HPND|"
                     r"Historical Permission|Unlicense|CMU|Zero-Clause|0BSD", re.I)
ROOT = Path(__file__).resolve().parents[1]


def declared() -> list[str]:
    d = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    names = list(d["dependencies"])
    for ex in d.get("optional-dependencies", {}).values():
        names += ex
    return sorted({re.split(r"[><=!\[;@ ]", n)[0].strip().lower().replace("_", "-") for n in names})


def check_licences() -> int:
    # --with-system: pip is one of the libraries Lantern names, and the tool leaves pip out unless told to list it
    out = subprocess.run([sys.executable, "-m", "piplicenses", "--format=json", "--from=mixed", "--with-urls",
                          "--with-system"],
                         capture_output=True, text=True, encoding="utf-8", check=False)
    if out.returncode:
        print(out.stderr or out.stdout)
        return 2
    rows = json.loads(out.stdout)
    want = set(declared())
    bad = 0
    for r in sorted(rows, key=lambda r: r["Name"].lower()):
        name = r["Name"].lower().replace("_", "-")
        if name not in want:
            continue
        lic = r.get("License") or ""
        ok = bool(ALLOWED.search(lic))
        print(f"{'ok  ' if ok else 'BAD '} {r['Name']:24} {r['Version']:10} {lic}")
        bad += not ok
    missing = want - {r["Name"].lower().replace("_", "-") for r in rows}
    for m in sorted(missing):
        print(f"?    {m:24} not installed here, licence not read")
    return 1 if bad else 0


def check_lock() -> int:
    lock = (ROOT / "requirements-lock.txt").read_text(encoding="utf-8")
    pinned = {m.group(1).lower().replace("_", "-") for m in re.finditer(r"^([A-Za-z0-9_.-]+)==", lock, re.M)}
    missing = [n for n in declared() if n not in pinned]
    for m in missing:
        print(f"requirements-lock.txt does not pin {m}: refresh it (see the file's header)")
    print(f"lock file pins {len(pinned)} libraries; {len(declared())} declared, {len(missing)} missing")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(check_lock() if "--lock-matches" in sys.argv else check_licences())
