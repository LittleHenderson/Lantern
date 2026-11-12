"""The behaviour plan for Corkboard (`bench/behaviour/apps.py`), and what must come out of it.

`plan()` is what a project would write as `lantern-behaviour.json`: how the app is loaded, the people, the set-up
and the checks. `EXPECTED` says, for each problem that can be planted, the cases that must come out broken and with
which codes; every other case must hold (or be one of `INCONCLUSIVE`). The table was worked out from the planted
piece's code before the first run, and a run that differs from it is a defect of the runner or of the table, to be
understood before either is changed.
"""
from __future__ import annotations

PRIVATE, SHARED, LOOM, LIST = "alice-private-7341", "alice-shared-2210", "loom-shared-5518", "milk, eggs"
DB = "{data}/corkboard.db"


def _word(name: str) -> str:
    """The pass phrase of a made-up person; nothing here is anybody's real one."""
    return f"{name}-likes-corkboards"


def _req(method: str, path: str, **more) -> dict:
    return {"method": method, "path": path, **more}


def _team(team: str, email: str, save: dict) -> dict:
    body = {"name": team, "email": email, "password": _word(email.split("@")[0])}
    return {"request": _req("POST", "/teams", json=body), "save": save}


def _member(invite: str, email: str, save: dict) -> dict:
    body = {"invite": invite, "email": email, "password": _word(email.split("@")[0])}
    return {"request": _req("POST", "/signup", json=body), "save": save}


def _sign_in(email: str) -> dict:
    name = email.split("@")[0]
    return {"request": _req("POST", "/login", json={"email": email, "password": _word(name)}),
            "save": {f"{name}_token": "json:token"}}


def _note(who: str, text: str, save: str, private: bool = False) -> dict:
    return {"request": _req("POST", "/notes", json={"text": text, "private": private}), "as": who,
            "save": {save: "json:id"}}


def _preview(check_id: str, url: str, about: str, **more) -> dict:
    return {"id": check_id, "kind": "address", "about": about, "who": "alice",
            "request": _req("POST", "/preview", json={"url": url}), **more}


def _go(check_id: str, target: str, about: str) -> dict:
    return {"id": check_id, "kind": "redirect", "about": about, "request": _req("GET", "/go", query={"next": target}),
            "good": _req("GET", "/go", query={"next": "/notes"})}


def plan() -> dict:
    transfer = _req("POST", "/transfer", json={"to": "{amir_id}", "amount": 30})
    return {
        "app": {"asgi": "corkboard.main:app",
                "env": {"CORKBOARD_DB": DB, "CORKBOARD_SECRET": "{secret}", "CORKBOARD_HASH_ROUNDS": "1000",
                        "CORKBOARD_DB_WAIT": "1"}},
        "state": {"sqlite": [DB], "folders": ["{data}/uploads"]},
        "tokens": {"hs256_secret": "{secret}"},
        "quiet_tables": ["audit", "login_attempts"],
        "names": {"files.inside.test": "10.0.0.5"},
        "people": {name: {"token": "{" + name + "_token}"} for name in ("tara", "alice", "amir", "olga", "bob", "alice_read")},
        "seed": [
            _team("Kiln", "tara@kiln.test", {"team_id": "json:team_id", "tara_id": "json:user_id", "invite": "json:invite"}),
            _member("{invite}", "alice@kiln.test", {"alice_id": "json:user_id"}),
            _member("{invite}", "amir@kiln.test", {"amir_id": "json:user_id"}),
            _team("Loom", "olga@loom.test", {"loom_id": "json:team_id", "olga_id": "json:user_id",
                                             "loom_invite": "json:invite"}),
            _member("{loom_invite}", "bob@loom.test", {"bob_id": "json:user_id"}),
            *[_sign_in(email) for email in ("tara@kiln.test", "alice@kiln.test", "amir@kiln.test", "olga@loom.test",
                                            "bob@loom.test")],
            {"request": _req("POST", "/tokens", json={"scope": "read"}), "as": "alice",
             "save": {"alice_read_token": "json:token"}},
            _note("alice", PRIVATE, "private_note", private=True),
            _note("alice", SHARED, "shared_note"),
            _note("olga", LOOM, "loom_note"),
            {"sql": {"db": DB, "run": "INSERT INTO coupons (code, amount) VALUES ('WELCOME', 50)"}},
            {"sql": {"db": DB, "run": "UPDATE users SET credits = 100 WHERE id = ?", "args": ["{alice_id}"]}},
            {"request": _req("POST", "/files", query={"name": "list.txt"}, text=LIST), "as": "alice",
             "save": {"alice_file": "json:id"}},
        ],
        "checks": [
            # ---------------------------------------------------------------- who may read
            {"id": "list-needs-login", "kind": "refuse", "about": "The list of notes is for people who are signed in",
             "request": _req("GET", "/notes"), "who": ["nobody"], "allowed": ["alice"], "must_not_say": [SHARED]},
            {"id": "private-note", "kind": "refuse", "about": "A private note is for its owner and the team's admin",
             "request": _req("GET", "/notes/{private_note}"), "who": ["amir", "olga", "nobody"],
             "allowed": ["alice", "tara"], "must_not_say": [PRIVATE]},
            {"id": "other-team-note", "kind": "refuse", "about": "A team's note is not for another team",
             "request": _req("GET", "/notes/{shared_note}"), "who": ["olga", "bob", "nobody"],
             "allowed": ["alice", "amir"], "must_not_say": [SHARED]},
            {"id": "list-hides-private", "kind": "hide", "about": "The list leaves out a teammate's private note",
             "request": _req("GET", "/notes"), "who": ["amir"], "shown_to": ["alice"], "must_not_say": [PRIVATE]},
            {"id": "list-hides-other-team", "kind": "hide", "about": "The list leaves out another team's notes",
             "request": _req("GET", "/notes"), "who": ["olga", "bob"], "shown_to": ["alice"], "must_not_say": [SHARED]},
            {"id": "team-list", "kind": "hide", "about": "A team's notes cannot be listed by its number from outside",
             "request": _req("GET", "/teams/{loom_id}/notes"), "who": ["alice", "tara"], "shown_to": ["olga"],
             "must_not_say": [LOOM]},
            {"id": "export-hides-other-team", "kind": "hide", "about": "The export holds the caller's team only",
             "request": _req("GET", "/export"), "who": ["olga"], "shown_to": ["alice"], "must_not_say": [SHARED]},
            {"id": "export-hides-private", "kind": "hide", "about": "The export leaves out a teammate's private note",
             "request": _req("GET", "/export"), "who": ["amir"], "shown_to": ["alice"], "must_not_say": [PRIVATE]},
            {"id": "file-read", "kind": "refuse", "about": "An uploaded file is for its team",
             "request": _req("GET", "/files/{alice_file}"), "who": ["olga", "nobody"], "allowed": ["alice", "amir"],
             "must_not_say": [LIST]},
            # ---------------------------------------------------------------- who may change
            {"id": "note-change", "kind": "refuse", "about": "Only a note's owner or the team's admin changes it",
             "request": _req("PUT", "/notes/{shared_note}", json={"text": "changed by somebody", "private": False}),
             "who": ["amir", "olga", "alice_read", "nobody"], "allowed": ["alice", "tara"]},
            {"id": "note-delete", "kind": "refuse", "about": "Only a note's owner or the team's admin deletes it",
             "request": _req("DELETE", "/notes/{shared_note}"), "who": ["amir", "olga", "alice_read", "nobody"],
             "allowed": ["alice", "tara"]},
            {"id": "remove-user", "kind": "refuse", "about": "Only the team's own admin removes a user",
             "request": _req("DELETE", "/admin/users/{amir_id}"), "who": ["alice", "olga", "alice_read", "nobody"],
             "allowed": ["tara"]},
            {"id": "read-only-token", "kind": "refuse", "about": "A token for reading cannot write",
             "request": _req("POST", "/notes", json={"text": "written with a token for reading"}),
             "who": ["alice_read"], "allowed": ["alice"]},
            # ---------------------------------------------------------------- sign-in tokens
            {"id": "tokens", "kind": "tokens", "about": "Only a sign-in the app issued, whole and in date, gets in",
             "request": _req("GET", "/me"), "who": "alice", "claims": {"sub": "{tara_id}"}},
            # ---------------------------------------------------------------- what is sent
            {"id": "profile-role", "kind": "keeps", "about": "The profile form cannot change a person's role",
             "request": _req("PATCH", "/me", json={"email": "alice@kiln.test", "role": "admin"}), "who": "alice",
             "after": _req("GET", "/me"), "expect": {"json:role": "member"}},
            {"id": "negative-transfer", "kind": "input", "about": "Credits cannot be given in a negative amount",
             "request": _req("POST", "/transfer", json={"to": "{amir_id}", "amount": -40}), "who": "alice",
             "good": _req("POST", "/transfer", json={"to": "{amir_id}", "amount": 5})},
            {"id": "huge-note", "kind": "input", "about": "A note of three million characters is refused",
             "request": _req("POST", "/notes", json={"text": {"$fill": 3000000}}), "who": "alice",
             "good": _req("POST", "/notes", json={"text": "an ordinary note"})},
            {"id": "huge-note-undeclared", "kind": "input", "about": "And when the request does not say how long it is",
             "request": _req("POST", "/notes", json={"text": {"$fill": 3000000}}, no_length=True), "who": "alice",
             "good": _req("POST", "/notes", json={"text": "an ordinary note"})},
            {"id": "huge-file", "kind": "input", "about": "An upload of three megabytes is refused",
             "request": _req("POST", "/files", query={"name": "big.txt"}, bytes=3000000), "who": "alice",
             "good": _req("POST", "/files", query={"name": "small.txt"}, bytes=1000)},
            # ---------------------------------------------------------------- uploads and archives
            {"id": "upload-name", "kind": "contain", "about": "An upload stays in the uploads folder whatever its name",
             "request": _req("POST", "/files", query={"name": "../../escape.txt"}, text="x"), "who": "alice"},
            {"id": "upload-page", "kind": "input", "about": "A web page is not accepted as an upload",
             "request": _req("POST", "/files", query={"name": "page.html"}, text="<script>alert(1)</script>"),
             "who": "alice", "good": _req("POST", "/files", query={"name": "ok.txt"}, text="x")},
            {"id": "upload-page-served", "kind": "keeps", "about": "An upload is never served back as a web page",
             "request": _req("POST", "/files", query={"name": "page.html"}, text="<script>alert(1)</script>"),
             "who": "alice", "save": {"new_file": "json:id"}, "after": _req("GET", "/files/{new_file}"),
             "expect_not": {"header:content-type": {"starts": "text/html"}}},
            {"id": "zip-names", "kind": "contain", "about": "A zip is unpacked inside its own folder whatever it names",
             "request": _req("POST", "/import", zip=[{"name": "../../../escape-from-zip.txt", "text": "x"}]),
             "who": "alice"},
            {"id": "zip-bomb", "kind": "input", "about": "A small zip that unpacks to twelve megabytes is refused",
             "request": _req("POST", "/import", zip=[{"name": "big.bin", "zeros": 12000000}]), "who": "alice",
             "good": _req("POST", "/import", zip=[{"name": "a.txt", "text": "x"}])},
            # ---------------------------------------------------------------- redirects
            _go("go-elsewhere", "https://evil.test/login", "The redirect after sign-in stays on this site"),
            _go("go-two-slashes", "//evil.test/login", "Also for an address written with two slashes"),
            _go("go-backslash", "/\\evil.test/login", "Also for an address written with a backslash"),
            # ---------------------------------------------------------------- addresses the app is sent to
            _preview("preview-internal", "http://169.254.169.254/latest/meta-data/", "The preview does not fetch a cloud's own address"),
            _preview("preview-loopback", "http://127.0.0.1:8000/admin", "Nor this computer"),
            _preview("preview-loopback-number", "http://2130706433/", "Nor this computer written as one number"),
            _preview("preview-loopback-v6", "http://[::1]:8080/", "Nor this computer in the newer spelling"),
            _preview("preview-localhost-caps", "http://LOCALHOST:8000/admin", "Nor this computer in capitals"),
            _preview("preview-other-site", "https://evil.test/", "Nor a site nobody listed"),
            _preview("preview-inside-name", "http://files.inside.test/report", "Nor a name that leads inside"),
            _preview("preview-known-site", "https://example.org/", "A listed site is the one address it may try",
                     may_reach=["example.org"]),
            # ---------------------------------------------------------------- too many tries
            {"id": "login-limit", "kind": "limit", "about": "Five wrong passwords lock the account",
             "request": _req("POST", "/login", json={"email": "alice@kiln.test", "password": "not-her-pass-phrase"}),
             "times": 5},
            # ---------------------------------------------------------------- at the same moment, again, half-way
            {"id": "coupon-once", "kind": "once", "about": "A coupon is redeemed once, also by two requests at once",
             "request": _req("POST", "/coupons/redeem", json={"code": "WELCOME"}), "who": "alice"},
            {"id": "transfer-retry", "kind": "retry", "about": "A transfer sent again with the same key is not repeated",
             "request": dict(transfer, headers={"Idempotency-Key": "pay-amir-1"}), "who": "alice"},
            {"id": "transfer-failures", "kind": "faults", "about": "A transfer happens whole or not at all",
             "request": transfer, "who": "alice",
             "then": {"request": _req("POST", "/notes", json={"text": "tara's ordinary note"}), "as": "tara"}},
            {"id": "remove-user-failures", "kind": "faults", "about": "Removing a user happens whole or not at all",
             "request": _req("DELETE", "/admin/users/{alice_id}"), "who": "tara",
             "then": {"request": _req("POST", "/notes", json={"text": "olga's ordinary note"}), "as": "olga"}},
        ],
    }


def _all(check: str, cases, codes) -> dict:
    return {f"{check}/{case}": list(codes) for case in cases}


LET_IN, LEAKED, CHANGED = ["let-in"], ["leaked"], ["refused-but-changed"]
FAILS, CUT = "the database fails at ", "the app is cut off before "

# planted id -> {"check/case": [codes]}: the cases that must come out broken; every other case holds
EXPECTED: dict[str, dict[str, list[str]]] = {
    "no-login-list": {"list-needs-login/nobody": ["let-in", "leaked"], "list-hides-private/amir": LEAKED,
                      **_all("list-hides-other-team", ("olga", "bob"), LEAKED)},
    "private-note-read": {"private-note/amir": ["let-in", "leaked"]},
    "other-team-read": _all("other-team-note", ("olga", "bob"), ["let-in", "leaked"]),
    "other-user-change": _all("note-change", ("amir", "olga"), LET_IN),
    "other-user-delete": _all("note-delete", ("amir", "olga"), LET_IN),
    "refused-but-deleted": _all("note-delete", ("amir", "olga"), CHANGED),
    "other-team-list": _all("team-list", ("alice", "tara"), LEAKED),
    "export-every-team": {"export-hides-other-team/olga": LEAKED},
    "member-removes-user": {"remove-user/alice": LET_IN},
    "other-team-admin": {"remove-user/olga": LET_IN},
    "expired-token": {"tokens/expired": LET_IN},
    "unsigned-token": _all("tokens", ("truncated", "altered", "unsigned", "other-key", "expired"), LET_IN),
    "scope-unchecked": {"read-only-token/alice_read": LET_IN, "note-change/alice_read": LET_IN,
                        "note-delete/alice_read": LET_IN},
    "role-in-profile": {"profile-role/the request": ["took-effect"]},
    "negative-transfer": {"negative-transfer/the bad request": ["accepted"]},
    "no-size-limit": {"huge-note/the bad request": ["accepted"], "huge-note-undeclared/the bad request": ["accepted"],
                      "huge-file/the bad request": ["accepted"]},
    "upload-name-escapes": {"upload-name/the request": ["outside-file"]},
    "upload-served-as-page": {"upload-page/the bad request": ["accepted"], "upload-page-served/the request": ["took-effect"]},
    "zip-entry-escapes": {"zip-names/the request": ["outside-file"]},
    "zip-bomb": {"zip-bomb/the bad request": ["accepted"]},
    "open-redirect": {"go-elsewhere/the request": ["sent-elsewhere"], "go-two-slashes/the request": ["sent-elsewhere"]},
    "redirect-half-checked": {"go-two-slashes/the request": ["sent-elsewhere"]},
    "fetch-any-address": {f"preview-{name}/the request": ["outside-address"] for name in
                          ("internal", "loopback", "loopback-number", "loopback-v6", "localhost-caps", "other-site",
                           "inside-name")},
    "fetch-half-checked": {f"preview-{name}/the request": ["outside-address"] for name in
                           ("internal", "loopback-number", "loopback-v6", "localhost-caps", "other-site", "inside-name")},
    "no-login-limit": _all("login-limit", ("straight after", "after a restart", "on another worker"), ["unlimited"]),
    "limit-in-memory": _all("login-limit", ("after a restart", "on another worker"), ["forgotten"]),
    "double-spend": {"coupon-once/at the same moment": ["raced"]},
    "no-undo": _all("transfer-failures", (FAILS + "write 2", FAILS + "write 3", FAILS + "commit 2", FAILS + "commit 3",
                                          CUT + "write 2", CUT + "write 3", CUT + "commit 2", CUT + "commit 3"), ["partial"]),
    "undo-by-hand": _all("transfer-failures", (CUT + "write 2", CUT + "write 3", CUT + "commit 2"), ["partial"]),
    "retry-repeats": _all("transfer-retry", ("sent again", "sent again after the answer was lost"), ["repeated"]),
    "shared-connection": {**_all("transfer-failures", (FAILS + "write 2", FAILS + "write 3", FAILS + "commit 1"), ["carried-over"]),
                          **_all("remove-user-failures", (FAILS + "write 2", FAILS + "commit 1"), ["carried-over"])},
}

# planted id -> the cases that say nothing there, because the one who may make the request is refused too
INCONCLUSIVE: dict[str, list[str]] = {
    "other-team-read": ["private-note/amir", "private-note/olga", "private-note/nobody"],   # the admin is refused as well
    # the planted export lists every team's notes that are not private, and so leaves the owner's own private note
    # out of her export too: that it is missing from a team-mate's export then proves nothing
    "export-every-team": ["export-hides-private/amir"],
}


def only(the_plan: dict, check_ids) -> dict:
    """The plan with these checks alone (the set-up, and each check's own controls, come with it)."""
    wanted = set(check_ids)
    return {**the_plan, "checks": [c for c in the_plan["checks"] if c["id"] in wanted]}


def own_checks(planted: str) -> list[str]:
    """The checks a planted problem must break, or leaves undecided."""
    return sorted({case.split("/", 1)[0] for case in [*EXPECTED[planted], *INCONCLUSIVE.get(planted, [])]})


def differences(planted: str | None, record: dict) -> list[str]:
    """Where a run of the plan (whole, or `only` some of its checks) differs from what is written down above, one
    line per case; empty when it does not. With nothing planted every case must hold."""
    if not record.get("ran"):
        return [f"not run: {record.get('why_not')}"]
    ran = {o["check"] for o in record["outcomes"]}
    want = {case: codes for case, codes in EXPECTED.get(planted or "", {}).items() if case.split("/", 1)[0] in ran}
    undecided = {case for case in INCONCLUSIVE.get(planted or "", []) if case.split("/", 1)[0] in ran}
    out, seen = [], set()
    for o in record["outcomes"]:
        case = f"{o['check']}/{o['case']}"
        seen.add(case)
        expected = ("broken", want[case]) if case in want else ("inconclusive", []) if case in undecided else ("held", [])
        got = (o["outcome"], o.get("codes") or [])
        if got != expected:
            out.append(f"{case}: came out {got[0]} {got[1] or ''}, written down as {expected[0]} {expected[1] or ''}; "
                       f"{o.get('why') or ''} saw {o.get('saw')}"[:500])
    return out + [f"{case}: no such case came out" for case in sorted((set(want) | undecided) - seen)]
