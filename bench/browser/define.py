"""What the browser benchmark's versions are made of, and how a run of one is compared with what was written down for
it (bench/browser/README.md). Written on 2026-11-22, before the benchmark's first run, and part of its definition hash:
a change here is a new definition, like a change to a site or a case.

A family is one site, written safe (`sites/<family>/`, every file a `.tmpl`, dot-files as `dot.<name>`, so Lantern's own
audit never reads them). A version is that site with a few exact edits: the safe site itself, a planted problem, or a
look-alike (something a careless check would take for a problem, or where the run can only say it cannot tell). What a
version must give is written down for all eight checks: the family's safe outcomes, changed where `gives` says.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

# The eight checks and their codes, as docs/browser.md writes them (tests/test_browser_bench.py holds them to
# lantern/browse.py, so a renamed code shows there and not as a silent miss here).
CODES = {
    "opens": ("server-error", "not-found", "no-answer", "empty"),
    "script": ("raised", "console-error", "not-loaded"),
    "leads": ("dead-link", "empty-link", "dead-button", "button-raises"),
    "forms": ("form-error", "form-nowhere", "form-raises"),
    "visitor": ("let-in",),
    "protections": ("said-not-sent", "cookie-open"),
    "outside": ("outside-script", "outside-file"),
    "keyboard": ("no-name", "no-label", "not-reached", "no-focus-ring", "trapped"),
}
CHECKS = tuple(CODES)
OUTCOMES = ("held", "broken", "inconclusive", "nothing-to-check", "not-run")
KINDS = ("safe", "planted", "look-alike")
SAFE = "safe"                   # the name of every family's safe version


@dataclass(frozen=True)
class Family:
    name: str                   # its folder under sites/
    kind: str                   # "pages" (plain files, served as they are) or "app" (started in the sealed box)
    what: str                   # in plain words
    safe: dict                  # check -> the outcome on the safe site, for all eight


@dataclass(frozen=True)
class Version:
    family: str
    kind: str                   # "safe", "planted" or "look-alike"
    what: str                   # in plain words
    edits: tuple = ()           # ("replace", file, old, new) | ("add", file, text) | ("remove", file)
                                # | ("rename", file, new name); `old` must stand exactly once in the file
    gives: dict = field(default_factory=dict)   # check -> (outcome, codes) where it differs from the safe site
    seen: tuple = ()            # (code, page): a row of that code, on that page, that is not undecided
    planted: tuple = ()         # (check, code): the problem a planted version carries
    beyond: str = ""            # where what is written down goes further than the words of docs/browser.md, and why


def expected(family: Family, version: Version) -> dict:
    """check -> (outcome, codes), for all eight."""
    out = {c: (family.safe[c], ()) for c in CHECKS}
    for check, (outcome, codes) in version.gives.items():
        out[check] = (outcome, tuple(sorted(codes)))
    return out


def faults(families: dict, versions: dict) -> list[str]:
    """What is wrong with the definitions themselves (empty when nothing): unknown checks, outcomes or codes, a
    planted version that gives no broken check with its code, a seen row of a code the version does not give."""
    out: list[str] = []
    for name, f in families.items():
        if f.kind not in ("pages", "app") or set(f.safe) != set(CHECKS) or any(o not in OUTCOMES for o in f.safe.values()):
            out.append(f"family {name}: kind or safe outcomes not as defined")
        if versions.get(name) is None or versions[name].kind != "safe" or versions[name].edits or versions[name].gives:
            out.append(f"family {name}: no safe version of the same name, or one with edits")
    for name, v in versions.items():
        if v.family not in families:
            out.append(f"{name}: no family {v.family}")
            continue
        if v.kind not in KINDS:
            out.append(f"{name}: kind {v.kind!r}")
        for check, (outcome, codes) in v.gives.items():
            if check not in CODES or outcome not in OUTCOMES:
                out.append(f"{name}: {check} {outcome}")
            elif bool(codes) != (outcome == "broken") or any(c not in CODES[check] for c in codes):
                out.append(f"{name}: {check} {outcome} with codes {codes}")
        want = expected(families[v.family], v)
        for code, page in v.seen:
            check = next((c for c, codes in CODES.items() if code in codes), None)
            if check is None or code not in want[check][1] or not page.startswith("/"):
                out.append(f"{name}: seen {code} on {page}, which it does not give")
        if v.kind == "planted":
            if not v.planted or any(code not in want.get(check, ("", ()))[1] for check, code in v.planted):
                out.append(f"{name}: planted {v.planted}, not given")
            if not all(any(code == s[0] for s in v.seen) for _, code in v.planted):
                out.append(f"{name}: no page written down for its planted code")
        elif v.planted:
            out.append(f"{name}: a {v.kind} with a planted problem")
    return out


def files(sites: Path, family: str, version: Version) -> dict[str, str]:
    """The version's files, name to text: the family's safe files with the version's edits made."""
    root = Path(sites) / family
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        rel = PurePosixPath(p.relative_to(root).as_posix())
        if not rel.name.endswith(".tmpl"):
            raise ValueError(f"{family}: {rel} is not a .tmpl file")
        name = rel.parent / rel.name[: -len(".tmpl")]
        name = PurePosixPath(*[("." + q[len("dot."):]) if q.startswith("dot.") else q for q in name.parts])
        out[name.as_posix()] = p.read_text(encoding="utf-8")
    for edit in version.edits:
        how, name = edit[0], edit[1]
        if how == "replace":
            old, new = edit[2], edit[3]
            if name not in out or out[name].count(old) != 1:
                raise ValueError(f"{family}: the text to replace stands {out.get(name, '').count(old)} times in {name}")
            out[name] = out[name].replace(old, new)
        elif how == "add":
            if name in out:
                raise ValueError(f"{family}: {name} is already there")
            out[name] = edit[2]
        elif how == "remove":
            del out[name]
        elif how == "rename":
            if edit[2] in out:
                raise ValueError(f"{family}: {edit[2]} is already there")
            out[edit[2]] = out.pop(name)
        else:
            raise ValueError(f"{family}: unknown edit {how!r}")
    return out


def build(sites: Path, family: str, version: Version, dest: Path) -> Path:
    """Write the version into `dest` (removed first when it is there) and give the folder."""
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    for name, text in files(sites, family, version).items():
        p = dest / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    return dest


def got(record: dict) -> dict:
    """check -> (outcome, codes) as a record of `lantern browse` gives them."""
    out = {c: ("missing", ()) for c in CHECKS}
    for c in record.get("checks") or []:
        if c.get("id") in out:
            out[c["id"]] = (c.get("outcome"), tuple(sorted(c.get("codes") or ())))
    return out


def compare(family: Family, version: Version, record: dict) -> dict:
    """How a run of `version` came out against what was written down for it:
    `as_written` (True when every check has the outcome and codes written down, and every seen row is there),
    `differences` (sentences), `found` (planted: the planted code given, on the page written down), `false_alarms`
    ((check, code) given that was not written down), `missed` ((check, code) written down and not given),
    `outcomes` ((check, written, given) where an outcome differs with no code involved)."""
    want, have = expected(family, version), got(record)
    diffs: list[str] = []
    false_alarms, missed, outcomes = [], [], []
    for check in CHECKS:
        (wo, wc), (ho, hc) = want[check], have[check]
        if (wo, wc) == (ho, hc):
            continue
        extra, lost = sorted(set(hc) - set(wc)), sorted(set(wc) - set(hc))
        false_alarms += [(check, c) for c in extra]
        missed += [(check, c) for c in lost]
        if not extra and not lost:
            outcomes.append((check, wo, ho))
        diffs.append(f"{check}: {ho} {list(hc) or ''} where {wo} {list(wc) or ''} was written down".replace(" ''", ""))
    rows = {c.get("id"): c.get("saw") or [] for c in record.get("checks") or []}
    absent = []
    for code, page in version.seen:
        check = next(c for c, codes in CODES.items() if code in codes)
        if not any(r.get("code") == code and r.get("page") == page and not r.get("undecided") for r in rows.get(check, [])):
            absent.append((code, page))
            diffs.append(f"{check}: no {code} seen on {page}")
    found = None
    if version.kind == "planted":
        found = all(code in have[check][1] and have[check][0] == "broken" and
                    not any(a[0] == code for a in absent) for check, code in version.planted)
    return {"as_written": not diffs, "differences": diffs, "found": found, "false_alarms": false_alarms,
            "missed": missed, "outcomes": outcomes, "absent": absent}
