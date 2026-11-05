"""Lantern must pass its own readiness checks, the way it must pass its own security audit (CLAUDE.md principle 4).

    lantern analyze . --out /tmp/self && python tools/self_readiness.py /tmp/self/readiness.json

Fails when the grade is below A, or any check is `fail`, or a `partial` check is not in ALLOWED_PARTIAL (each entry
says why it is allowed; keep the list short and honest). Prints every check that is not a pass.
"""
import json
import sys

ALLOWED_PARTIAL: dict[str, str] = {}
MIN_SCORE = 90


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python tools/self_readiness.py READINESS.json")
        return 2
    with open(argv[1], encoding="utf-8") as f:
        r = json.load(f)
    bad = []
    for cat in r["categories"]:
        for ch in cat["checks"]:
            if ch["status"] == "pass" or ch["status"] == "skip":
                continue
            line = f"{ch['status']:7} {cat['key']}/{ch['id']}: {ch['evidence']}"
            if ch["status"] == "partial" and ch["id"] in ALLOWED_PARTIAL:
                print("allowed", line, "--", ALLOWED_PARTIAL[ch["id"]])
                continue
            bad.append(line)
    print(f"readiness {r['score']}/100 grade {r['grade']} ({r['shape']})")
    for b in bad:
        print(b)
    if r["grade"] != "A" or r["score"] < MIN_SCORE or bad:
        print("FAIL: Lantern does not pass its own readiness checks")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
