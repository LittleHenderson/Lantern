"""What the plan Lantern writes by itself (`lantern behave PATH --init`) must show on Corkboard.

Nobody wrote this plan. For each version of the app, `lantern.behave_init.write` reads that version's own code and
writes `lantern-behaviour.json`, and `lantern.behave` runs it exactly as written. What it must show was written
down before its first run (2026-11-16) and stands here:

* `CAUGHT`: for each planted problem a first plan is expected to catch, the cases that break and how. A first
  plan asks three things of an app: is a visitor with no login turned away, is a row kept from somebody else who
  is signed in, are wrong passwords counted. The planted problems of those three kinds are its to catch.
* Every other planted problem (a token that ran out, an upload's name, an archive, a redirect, an address the app
  fetches, a request that fails half-way, two people on one team ...) is not: that takes a plan a person wrote,
  such as the one in `plan.py`, which catches all of them. On those versions, and on the safe app, no case may
  come out broken.
* A case that is not decided (Lantern made up a value the app does not take) must belong to a check the plan
  itself named on its list to look at first (`notes.review`), before anything was run.
"""
from __future__ import annotations

ACROSS = ("straight after", "after a restart", "on another worker")

CAUGHT: dict[str, dict[str, list[str]]] = {
    "no-login-list": {"get-notes/nobody": ["let-in"]},
    "other-team-read": {"get-notes-note-id/bob": ["leaked", "let-in"]},
    "other-user-change": {"put-notes-note-id/bob": ["let-in"]},
    "other-user-delete": {"delete-notes-note-id/bob": ["let-in"]},
    "refused-but-deleted": {"delete-notes-note-id/bob": ["refused-but-changed"]},
    "other-team-list": {"get-teams-team-id-notes/bob": ["let-in"]},
    "no-login-limit": {f"limit-post-login/{when}": ["unlimited"] for when in ACROSS},
    "limit-in-memory": {f"limit-post-login/{when}": ["forgotten"] for when in ACROSS[1:]},
}


def differences(planted: str | None, record: dict, plan: dict) -> list[str]:
    """Where a run of the plan Lantern wrote differs from what is written down above (empty when nowhere)."""
    want = CAUGHT.get(planted or "", {})
    named = {r.get("check") for r in (plan.get("notes") or {}).get("review") or []}
    got = {f"{o['check']}/{o['case']}": o for o in record.get("outcomes") or []}
    out = []
    if not record.get("ran"):
        return [f"the plan was not run: {record.get('why_not')}"]
    for case, codes in want.items():
        o = got.get(case)
        if o is None:
            out.append(f"{case}: the plan holds no such case")
        elif o["outcome"] != "broken" or sorted(o.get("codes") or []) != sorted(codes):
            out.append(f"{case}: written down as broken ({', '.join(codes)}), came out {o['outcome']}"
                       + (f" ({', '.join(sorted(o.get('codes') or []))})" if o.get("codes") else ""))
    for case, o in got.items():
        if case in want:
            continue
        if o["outcome"] == "broken":
            out.append(f"{case}: broken ({', '.join(sorted(o.get('codes') or []))}), which is not written down")
        elif o["outcome"] != "held" and o["check"] not in named:
            out.append(f"{case}: {o['outcome']}, and the plan did not name its check to look at first")
    return out
