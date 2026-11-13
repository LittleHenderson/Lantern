"""Lantern must pass its own readiness checks, the way it must pass its own security audit (CLAUDE.md principle 4).

    lantern analyze . --out /tmp/self && python tools/self_readiness.py /tmp/self/readiness.json

Fails when the grade is below A, or any check is `fail`, or a `partial` check is not in ALLOWED_PARTIAL, or a check
that the release decision requires was skipped and is not in ALLOWED_SKIP, or the release decision is Blocked, or
it is Incomplete for anything that is not in ALLOWED_MISSING (each entry says why it is allowed; keep the lists
short and honest). Prints every check that is not a pass, the skipped ones too, and the decision with what it is
missing.

This step reads Lantern's code and never runs its tests, so its decision cannot be Passed: the tests are run by
CI's test jobs, on every push, and a release is cut only when those are green. That one gap is allowed here, by
name; anything else that is missing stops CI.
"""
import json
import sys

ALLOWED_PARTIAL: dict[str, str] = {}
# Checks the release decision requires that this step cannot have run.
ALLOWED_SKIP: dict[str, str] = {
    "tests-pass": "this step reads the code and does not run the tests; CI's test jobs run them on every push",
}
# Criteria of the release decision that may be missing here, and nothing else may.
ALLOWED_MISSING: dict[str, str] = {
    "tests": "this step reads the code and does not run the tests; CI's test jobs run them on every push",
}
MIN_SCORE = 90


def _release(r: dict) -> tuple[list[str], list[str]]:
    """(lines to print, reasons to fail) for the release decision in a readiness file."""
    rel = r.get("release")
    if not isinstance(rel, dict) or rel.get("decision") not in ("Blocked", "Incomplete", "Passed"):
        return [], ["no release decision in the file (written by a Lantern older than this check?)"]
    said, bad = [f"release {rel['decision']}"], []
    crit = [c for c in rel.get("criteria") or [] if isinstance(c, dict)]
    for c in crit:
        if c.get("required") is False or c.get("state") in ("passed", "not-applicable"):
            continue
        line = f"{c.get('state')} {c.get('id')}: {c.get('why')}"
        if c.get("state") == "missing" and c.get("id") in ALLOWED_MISSING:
            said.append(f"allowed missing {c.get('id')}: {c.get('why')} -- {ALLOWED_MISSING[c['id']]}")
        else:                                 # failed, missing and not allowed, or a state this check does not know
            bad.append(line)
    if rel["decision"] == "Blocked" and not bad:
        bad.append("the decision is Blocked")
    return said, bad


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python tools/self_readiness.py READINESS.json")
        return 2
    with open(argv[1], encoding="utf-8") as f:
        r = json.load(f)
    bad = []
    for cat in r["categories"]:
        for ch in cat["checks"]:
            if ch["status"] == "pass":
                continue
            line = f"{ch['status']:7} {cat['key']}/{ch['id']}: {ch['evidence']}"
            if ch["status"] == "skip":        # said every time: a skipped check is not a passed one
                if not ch.get("required"):
                    print(line)
                elif ch["id"] in ALLOWED_SKIP:
                    print("allowed", line, "--", ALLOWED_SKIP[ch["id"]])
                else:
                    bad.append(line + " (required, and skipped)")
                continue
            if ch["status"] == "partial" and ch["id"] in ALLOWED_PARTIAL:
                print("allowed", line, "--", ALLOWED_PARTIAL[ch["id"]])
                continue
            bad.append(line)
    print(f"readiness {r['score']}/100 grade {r['grade']} ({r['shape']})")
    said, held = _release(r)
    for line in said:
        print(line)
    bad += held
    for b in bad:
        print(b)
    if r["grade"] != "A" or r["score"] < MIN_SCORE or bad:
        print("FAIL: Lantern does not pass its own readiness checks")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
