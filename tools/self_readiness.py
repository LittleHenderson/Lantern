"""Lantern must pass its own readiness checks, the way it must pass its own security audit (CLAUDE.md principle 4).

    lantern analyze . --out /tmp/self && python tools/self_readiness.py /tmp/self/readiness.json

Fails when the grade is below A, or any check is `fail` and is not in ALLOWED_FAIL (a check there may fail only
while the repository still shows the reason it gives), or a `partial` check is not in ALLOWED_PARTIAL, or a check
that the release decision requires was skipped and is not in ALLOWED_SKIP, or the release decision is Blocked, or
it is Incomplete for anything that is not in ALLOWED_MISSING (each entry says why it is allowed; keep the lists
short and honest). Prints every check that is not a pass, the skipped ones too, and the decision with what it is
missing.

This step reads Lantern's code and never runs its tests, so its decision cannot be Passed: the tests are run by
CI's test jobs, on every push, and a release is cut only when those are green. That one gap is allowed here, by
name; anything else that is missing stops CI.
"""
import json
import re
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _stage(text: str) -> list[str]:
    """The instructions of a Dockerfile's last stage (the image it builds): comments left out, continued lines joined."""
    out, cur = [], ""
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("#") or (not s and not cur):
            continue
        if s.endswith("\\"):
            cur += s[:-1] + " "
            continue
        out.append(cur + s)
        cur = ""
    if cur:
        out.append(cur)
    starts = [i for i, ins in enumerate(out) if re.match(r"FROM\s", ins, re.I)]
    return out[starts[-1]:] if starts else out


def _env(stage: list[str], name: str) -> str | None:
    """The value the image's last ENV gives `name`, or None when none does (or when a line cannot be read)."""
    value = None
    for ins in stage:
        m = re.match(r"ENV\s+(.*)", ins, re.I | re.S)
        if not m:
            continue
        try:
            words = shlex.split(m.group(1))
        except ValueError:
            return None
        if words and "=" not in words[0]:          # the older form: ENV NAME value (one variable, the rest its value)
            if words[0] == name:
                value = " ".join(words[1:])
            continue
        for w in words:
            k, _, v = w.partition("=")
            if k == name:
                value = v
    return value


def _not_root(stage: list[str]) -> bool:
    users = [m.group(1) for ins in stage if (m := re.match(r"USER\s+(\S+)", ins, re.I))]
    return bool(users) and users[-1].split(":")[0] not in ("root", "0")


def _last(stage: list[str], word: str) -> str | None:
    """What follows the image's last `word` instruction (CMD, ENTRYPOINT), or None when it has none."""
    found = None
    for ins in stage:
        m = re.match(rf"{word}\s+(.*)", ins, re.I | re.S)
        if m:
            found = m.group(1).strip()
    return found


# Options of Python that take no value: the words a command may hold between the program and `-m`.
PYTHON_FLAGS = {"-I", "-E", "-s", "-S", "-B", "-u", "-O", "-OO", "-P", "-q"}
SWITCHER = "lantern_cloud.switcher"


def _switcher_first(stage: list[str]) -> bool:
    """The image's first program is its switcher, and the service's command comes after it: no ENTRYPOINT (which
    would make the command its arguments), and a command in the form that starts no shell, which is Python with
    nothing but options before `-m lantern_cloud.switcher`, then `--`, then a command."""
    if _last(stage, "ENTRYPOINT") is not None:
        return False
    cmd = _last(stage, "CMD")
    if cmd is None or not cmd.startswith("["):
        return False
    try:
        words = json.loads(cmd)
    except ValueError:
        return False
    if not (isinstance(words, list) and len(words) > 4 and all(isinstance(w, str) for w in words)):
        return False
    if not re.fullmatch(r"(?:/usr(?:/local)?/bin/)?python3?(?:\.\d+)?", words[0]) or "-m" not in words:
        return False
    at = words.index("-m")
    return (all(w in PYTHON_FLAGS for w in words[1:at]) and words[at + 1:at + 3] == [SWITCHER, "--"]
            and len(words) > at + 3)


def _steps_apart(root: Path) -> str | None:
    """None while the repository shows why the website's image may start as root: root is its switcher's alone (the
    image's first program, cloud/lantern_cloud/switcher.py), which starts the service as an ordinary user it names
    (`LANTERN_CLOUD_SERVICE_USER`, not root and not nobody) with its own places on one disk (`LANTERN_CLOUD_DATA`)
    and each check's steps as a user of that check's own, which only root can switch to; the image requires each
    check's steps to run apart (`LANTERN_CLOUD_STEPS_APART=required`, cloud/lantern_cloud/apart.py); and every other
    image of the project names a user that is not root, so the check's failure can only be about this image.
    Otherwise what no longer holds."""
    from lantern.readiness import Repo
    site = root / "cloud" / "Dockerfile"
    if not site.is_file():
        return "there is no cloud/Dockerfile"
    stage = _stage(site.read_text(encoding="utf-8"))
    if _env(stage, "LANTERN_CLOUD_STEPS_APART") != "required":
        return "the image cloud/Dockerfile builds does not set LANTERN_CLOUD_STEPS_APART=required"
    if not _switcher_first(stage):
        return ("the image cloud/Dockerfile builds does not start its switcher first "
                f'(CMD ["python", "-I", "-m", "{SWITCHER}", "--", <the service\'s command>], no ENTRYPOINT)')
    service = _env(stage, "LANTERN_CLOUD_SERVICE_USER")
    if not service or service.strip() != service or service in ("root", "0", "nobody", "65534"):
        return "the image cloud/Dockerfile builds names no ordinary user for its service (LANTERN_CLOUD_SERVICE_USER)"
    data = _env(stage, "LANTERN_CLOUD_DATA")
    if not data or not data.startswith("/") or data.rstrip("/") == "":
        return "the image cloud/Dockerfile builds names no folder of the service's own (LANTERN_CLOUD_DATA)"
    for f in Repo(root).project_files:          # the files the readiness checks read (the tests' own are not)
        if f.rsplit("/", 1)[-1].lower() == "dockerfile" and f != "cloud/Dockerfile":
            if not _not_root(_stage((root / f).read_text(encoding="utf-8", errors="replace"))):
                return f"{f} names no user other than root"
    return None


# Checks that may fail here, each with its reason and what must still hold for it (`holds(root)`: None, or what no
# longer holds, and then the failure stops CI as any other does).
ALLOWED_FAIL = {
    "pkg-user": ("the website's image (cloud/Dockerfile) starts as root for its switcher alone, which starts the "
                 "service as an ordinary user of its own and each check's steps as a user of that check's own, which "
                 "only root can switch to; neither the service nor a step runs as root (the owner's answer of "
                 "2026-11-20: root narrowed to the small part that starts the steps)", _steps_apart),
}
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


def main(argv: list[str], root: Path = ROOT) -> int:
    if len(argv) != 2:
        print("usage: python tools/self_readiness.py READINESS.json")
        return 2
    with open(argv[1], encoding="utf-8") as f:
        r = json.load(f)
    bad, failed = [], set()
    for cat in r["categories"]:
        for ch in cat["checks"]:
            if ch["status"] == "pass":
                continue
            line = f"{ch['status']:7} {cat['key']}/{ch['id']}: {ch['evidence']}"
            if ch["status"] == "fail" and ch["id"] in ALLOWED_FAIL:
                failed.add(ch["id"])
                why, holds = ALLOWED_FAIL[ch["id"]]
                gone = holds(root)
                if gone is None:
                    print("allowed", line, "--", why)
                else:
                    bad.append(f"{line} (allowed only while {why}; but {gone})")
                continue
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
    for cid in sorted(set(ALLOWED_FAIL) - failed):
        print(f"ALLOWED_FAIL lists {cid}, and {cid} passed here or was not run: take it off when it is no longer needed")
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
