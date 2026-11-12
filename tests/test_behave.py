"""The behaviour runner (directive point 5): what `lantern.behave` reports about a running app, and what it must
not report. The apps here are a few lines each and need no library; the larger test app with its planted problems
is `bench/behaviour` (`tests/test_behaviour_apps.py`, and the planted versions further down)."""
import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from lantern import __version__, behave, cli, sandbox
from lantern import _behave_inside as inside

ROOT = Path(__file__).resolve().parents[1]
# Where the sandbox starts no app (Windows, `sandbox.NO_APPS`), the tests that start one are skipped with that reason.
# What a plan may hold, the judge and the token variants are tested everywhere.
starts_an_app = pytest.mark.skipif(bool(sandbox.NO_APPS), reason=f"no app is started here: {sandbox.NO_APPS}")


def _repo(folder: Path, app: str, plan: dict) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "app.py").write_text(app, encoding="utf-8")
    (folder / behave.PLAN_NAME).write_text(json.dumps(plan), encoding="utf-8")
    return folder


def _run(repo: Path) -> dict:
    record = behave.run(repo, log=lambda line: None)
    assert record["ran"], record["why_not"]
    return record


def _by_case(record: dict) -> dict:
    return {f"{o['check']}/{o['case']}": (o["outcome"], o.get("codes") or []) for o in record["outcomes"]}


# ------------------------------------------------------------------------------------------- where an app goes
# A page preview fetches the address a visitor gives. HEAD is the same for every version; each version has its
# own `allowed(host, port)`.
PREVIEW_HEAD = '''
import ipaddress, json, socket, urllib.parse, urllib.request

async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    body = b""
    while True:
        event = await receive()
        body += event.get("body", b"")
        if not event.get("more_body"):
            break
    url = json.loads(body or b"{}").get("url", "")
    parts = urllib.parse.urlsplit(url)
    status, text = 400, "That address cannot be previewed"
    if allowed(parts.hostname or "", parts.port or (443 if parts.scheme == "https" else 80)):
        try:
            with urllib.request.urlopen(url, timeout=3) as page:
                status, text = 200, page.read(200).decode("utf-8", "replace")
        except OSError as e:
            status, text = 502, "The page could not be fetched"
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": text.encode("utf-8")})
'''
FETCHES_ANYTHING = PREVIEW_HEAD + '''
def allowed(host, port):
    return True
'''
REFUSES_BY_WORDS = PREVIEW_HEAD + '''
def allowed(host, port):
    return not (host == "localhost" or host.startswith(("127.", "10.", "192.168.", "169.254.")))
'''
LOOKS_FIRST = PREVIEW_HEAD + '''
def allowed(host, port):
    # the usual defence: ask where the name leads, and refuse when it leads inside
    try:
        found = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False
    return all(ipaddress.ip_address(entry[4][0]).is_global for entry in found)
'''
LOOKS_FIRST_THE_OLD_WAY = PREVIEW_HEAD + '''
def allowed(host, port):
    try:
        return ipaddress.ip_address(socket.gethostbyname(host)).is_global
    except OSError:
        return False
'''
KNOWN_SITES_ONLY = PREVIEW_HEAD + '''
def allowed(host, port):
    return host in ("example.org", "docs.example.org")
'''


def _preview(check_id: str, url: str, **more) -> dict:
    return {"id": check_id, "kind": "address", "about": "The preview does not fetch " + url,
            "request": {"method": "POST", "path": "/preview", "json": {"url": url}}, **more}


# example.org and its like have no address inside the sandbox; the runner gives each name one, out of a range
# kept for examples, and the plan says which names lead inside.
PREVIEW_PLAN = {
    "app": {"asgi": "app:app"},
    "names": {"files.inside.test": "10.0.0.5", "printer.inside.test": "fd00::5"},
    "checks": [
        _preview("cloud", "http://169.254.169.254/latest/meta-data/"),
        _preview("loopback", "http://127.0.0.1:8000/admin"),
        _preview("one-number", "http://2130706433/"),
        _preview("newer-spelling", "http://[::1]:8080/"),
        _preview("inside-name", "http://files.inside.test/"),
        _preview("inside-name-newer", "http://printer.inside.test/"),
        _preview("known-site", "https://example.org/", may_reach=["example.org"]),
    ],
}
INSIDE = ("cloud", "loopback", "one-number", "newer-spelling", "inside-name", "inside-name-newer")
BROKEN = ("broken", ["outside-address"])


def _expected(broken) -> dict:
    return {f"{c['id']}/the request": BROKEN if c["id"] in broken else ("held", []) for c in PREVIEW_PLAN["checks"]}


@starts_an_app
@pytest.mark.parametrize("app, broken", [
    (FETCHES_ANYTHING, INSIDE),
    (REFUSES_BY_WORDS, ("one-number", "newer-spelling", "inside-name", "inside-name-newer")),
    (LOOKS_FIRST, ()),
    (LOOKS_FIRST_THE_OLD_WAY, ()),
], ids=["fetches-anything", "refuses-by-words", "looks-first", "looks-first-the-old-way"])
def test_an_app_that_sets_out_for_an_inside_address_is_reported_and_one_that_only_asks_where_a_name_leads_is_not(
        app, broken, tmp_path):
    record = _run(_repo(tmp_path / "preview", app, PREVIEW_PLAN))
    assert _by_case(record) == _expected(broken)


@starts_an_app
def test_what_was_asked_and_what_was_tried_is_written_beside_the_outcome(tmp_path):
    record = _run(_repo(tmp_path / "preview", FETCHES_ANYTHING, PREVIEW_PLAN))
    saw = {o["check"]: o["saw"] for o in record["outcomes"]}
    assert ["files.inside.test", "10.0.0.5"] in saw["inside-name"]["asked"]
    assert any("10.0.0.5" in line for line in saw["inside-name"]["tried"])
    assert any("::1" in line for line in saw["newer-spelling"]["tried"])
    known = saw["known-site"]["asked"]
    assert [name for name, address in known] == ["example.org"] and known[0][1].startswith(("198.51.100.", "203.0.113."))


@starts_an_app
def test_a_site_nobody_listed_is_an_outside_address_and_a_listed_one_is_not(tmp_path):
    plan = {"app": {"asgi": "app:app"}, "may_reach": ["status.example.org"], "checks": [
        _preview("unlisted", "https://evil.test/"),
        _preview("listed-for-this-check", "https://example.org/", may_reach=["example.org"]),
        _preview("listed-for-the-whole-plan", "https://status.example.org/"),
        _preview("in-capitals", "https://EXAMPLE.org./", may_reach=["example.org"])]}
    got = _by_case(_run(_repo(tmp_path / "preview", FETCHES_ANYTHING, plan)))
    assert got == {"unlisted/the request": BROKEN, "listed-for-this-check/the request": ("held", []),
                   "listed-for-the-whole-plan/the request": ("held", []), "in-capitals/the request": ("held", [])}
    assert _by_case(_run(_repo(tmp_path / "known", KNOWN_SITES_ONLY, plan)))["unlisted/the request"] == ("held", [])


@starts_an_app
def test_no_question_about_a_name_leaves_the_sandbox(tmp_path):
    # the app asks for names in every way Python has; none of them may reach the real resolver, which the guard
    # would refuse and write down as a lookup
    asks = PREVIEW_HEAD + '''
def allowed(host, port):
    socket.getaddrinfo(host, port)
    socket.getaddrinfo(host.encode("ascii"), str(port), socket.AF_INET, socket.SOCK_STREAM)
    socket.gethostbyname(host)
    socket.gethostbyname_ex(host)
    return False
'''
    plan = {"app": {"asgi": "app:app"}, "checks": [_preview("asks", "https://evil.test/")]}
    record = _run(_repo(tmp_path / "asks", asks, plan))
    assert _by_case(record) == {"asks/the request": ("held", [])}
    assert "tried" not in record["outcomes"][0]["saw"]


# The same page preview, fetching in the other usual ways, and in one way the runner cannot see.
FETCH_HEAD = '''
import json

async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    body = b""
    while True:
        event = await receive()
        body += event.get("body", b"")
        if not event.get("more_body"):
            break
    try:
        status, text = 200, await fetch(json.loads(body or b"{}").get("url", ""))
    except Exception:
        status, text = 502, "The page could not be fetched"
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": text.encode("utf-8")})
'''
WITH_HTTPX = FETCH_HEAD + '''
import httpx

async def fetch(url):
    async with httpx.AsyncClient(timeout=3) as client:
        return (await client.get(url)).text[:200]
'''
WITH_HTTPX_NOT_AWAITED = FETCH_HEAD + '''
import httpx

async def fetch(url):
    return httpx.get(url, timeout=3).text[:200]
'''
WITH_ASYNCIO = FETCH_HEAD + '''
import asyncio, urllib.parse

async def fetch(url):
    to = urllib.parse.urlsplit(url)
    reader, writer = await asyncio.wait_for(asyncio.open_connection(to.hostname, to.port or 80), 3)
    writer.close()
    return "connected"
'''
BELOW_PYTHON = FETCH_HEAD + '''
import ctypes, socket, struct, urllib.parse

libc = ctypes.CDLL(None)

async def fetch(url):
    # what a client or an event loop written in C does: the C library connects, and Python is told nothing
    to = urllib.parse.urlsplit(url)
    fd = libc.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    address = struct.pack("=HH4s8x", socket.AF_INET, socket.htons(to.port or 80), socket.inet_aton(to.hostname))
    libc.connect(fd, address, len(address))
    libc.close(fd)
    return "tried"
'''
FETCH_PLAN = {"app": {"asgi": "app:app"}, "names": {"files.inside.test": "10.0.0.5"},
              "checks": [_preview("loopback", "http://127.0.0.1:9/admin"), _preview("inside-name", "http://files.inside.test/")]}


@starts_an_app
@pytest.mark.parametrize("app", [WITH_HTTPX, WITH_HTTPX_NOT_AWAITED, WITH_ASYNCIO], ids=["httpx", "httpx-not-awaited", "asyncio"])
def test_the_usual_ways_to_fetch_a_page_are_seen_setting_out(app, tmp_path):
    if "httpx" in app:
        pytest.importorskip("httpx")
    record = _run(_repo(tmp_path / "fetch", app, FETCH_PLAN))
    assert _by_case(record) == {"loopback/the request": BROKEN, "inside-name/the request": BROKEN}


@starts_an_app
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the address is laid out the way Linux's C library reads it")
def test_a_connection_made_below_python_is_not_seen_which_is_a_known_limit(tmp_path):
    """Known and not fixed. The runner reads what the sandbox's guard refused, and the guard sees what Python does.
    An app that sets out through code that is not Python (a client or an event loop written in C; here the C library
    itself) is refused by the kernel where it has Landlock, nothing is written down, and the case comes out held.
    The day the runner sees such a connection this test fails, and is turned round."""
    plan = {**FETCH_PLAN, "checks": FETCH_PLAN["checks"][:1]}
    record = _run(_repo(tmp_path / "below", BELOW_PYTHON, plan))
    assert _by_case(record) == {"loopback/the request": ("held", [])}


def test_a_plan_cannot_give_a_name_anything_but_an_address_written_out():
    plan = {"app": {"asgi": "app:app"}, "checks": [_preview("x", "http://a.test/")]}
    assert behave.check({**plan, "names": {"a.test": "10.0.0.5", "b.test": "fd00::5"}})
    for names in ({"a.test": "b.test"}, {"a.test": "10.0.0"}, {"a.test": 5}, ["a.test"], {"": "10.0.0.5"}):
        with pytest.raises(behave.PlanError):
            behave.check({**plan, "names": names})
    with pytest.raises(behave.PlanError):
        behave.check({**plan, "may_reach": "example.org"})


# ------------------------------------------------------------------------------------------- sign-in tokens
def _token(secret: str = "s" * 32, **claims) -> str:
    return inside._signed({"alg": "HS256", "typ": "JWT"}, {"sub": "7", "exp": 4102444800, **claims}, secret)


def test_a_token_cut_short_is_the_same_kind_of_token_on_every_run():
    # cut anywhere, the leftover letters of the signature are sometimes whole text and sometimes not, and a
    # library that reads tokens without checking them refuses only the second: one app, two answers
    for n in range(40):
        token = _token(secret=f"secret-number-{n}-of-forty-000000000")
        cut = inside.token_variant(token, "truncated")
        head, body, signature = cut.split(".")
        assert (head, body) == tuple(token.split(".")[:2])
        assert len(signature) % 4 == 0 and len(signature) < len(token.split(".")[2]) and token.split(".")[2].startswith(signature)
        base64.urlsafe_b64decode(signature)                      # whole text: nothing left over
    assert inside.token_variant("opaque-session-0123456789", "truncated") == "opaque-session-012345"


def test_each_variant_of_a_token_is_what_its_name_says():
    token = _token()
    read = lambda t, part: json.loads(base64.urlsafe_b64decode(t.split(".")[part] + "=" * (-len(t.split(".")[part]) % 4)))  # noqa: E731
    assert inside.token_variant(token, "valid") == token and inside.token_variant(token, "none") is None
    assert inside.token_variant(token, "empty") == "" and "." not in inside.token_variant(token, "garbage")
    altered = inside.token_variant(token, "altered", claims={"sub": 9})
    assert read(altered, 1)["sub"] == "9" and altered.split(".")[2] == token.split(".")[2]
    unsigned = inside.token_variant(token, "unsigned")
    assert read(unsigned, 0)["alg"] == "none" and unsigned.endswith(".") and unsigned.split(".")[1] == token.split(".")[1]
    other = inside.token_variant(token, "other-key", claims={"sub": 9})
    assert read(other, 1)["sub"] == "9" and other.split(".")[2] != token.split(".")[2]
    expired = inside.token_variant(token, "expired", secret="s" * 32)
    assert read(expired, 1)["exp"] < 1700000000 + 10 ** 9 and read(expired, 1)["sub"] == "7"
    assert expired.split(".")[2] == inside._signed(read(expired, 0), read(expired, 1), "s" * 32).split(".")[2]
    for variant in ("altered", "unsigned", "other-key", "expired"):
        with pytest.raises(ValueError):
            inside.token_variant("opaque-session-0123456789", variant, secret="s" * 32)
    with pytest.raises(ValueError):
        inside.token_variant(token, "expired")                    # no test secret to sign it with


# ------------------------------------------------------------------------------------------- the judge, by hand
PEOPLE = {"alice": {"token": "a"}, "amir": {"token": "b"}}


def _judged(check: dict, probes: dict, **plan) -> dict:
    """The outcomes for one check, from steps written by hand: {"case": [step, ...]}."""
    plan = behave.check({"app": {"asgi": "app:app"}, "people": PEOPLE, "checks": [check], **plan})
    _inside, cases = behave.scene(plan)
    observed = {"probes": [{"id": f"{check['id']}/{case}", "steps": steps} for case, steps in probes.items()]}
    return {o["case"]: (o["outcome"], o.get("codes") or []) for o in behave.judge(plan, cases, observed)}


DELETE = {"id": "d", "kind": "refuse", "who": ["amir", "nobody"], "allowed": ["alice"],
          "request": {"method": "DELETE", "path": "/notes/1"}}
GONE = {"tables": {"notes": [0, 1, 0]}}
DONE = {"status": 204, "changes": GONE}


def test_a_refusal_counts_only_beside_a_request_that_worked_and_only_when_nothing_changed():
    def came_out(amir, alice=DONE, **plan):
        return _judged(DELETE, {"alice (may)": [alice], "amir": [amir], "nobody": [{"status": 401}]}, **plan)["amir"]
    assert came_out({"status": 403}) == ("held", [])
    assert came_out({"status": 404}) == ("held", [])
    assert came_out({"status": 204, "changes": GONE}) == ("broken", ["let-in"])
    assert came_out({"status": 403, "changes": GONE}) == ("broken", ["refused-but-changed"])
    assert came_out({"status": 500}) == ("broken", ["crashed"])
    assert came_out({"died": True}) == ("broken", ["crashed"])
    # a table the plan says may change on a refusal (a record of who tried) is not a change of the thing asked for
    wrote_it_down = {"status": 403, "changes": {"tables": {"audit": [1, 0, 0]}}}
    assert came_out(wrote_it_down) == ("broken", ["refused-but-changed"])
    assert came_out(wrote_it_down, quiet_tables=["audit"]) == ("held", [])
    assert came_out({"status": 403, "changes": {"files": {"count": 1, "added": ["x"], "removed": [], "changed": []}}}) \
        == ("broken", ["refused-but-changed"])
    # the one who may is refused too, or their request changes nothing: a refusal then proves nothing
    assert came_out({"status": 403}, alice={"status": 403}) == ("inconclusive", [])
    assert came_out({"status": 403}, alice={"status": 204}) == ("inconclusive", [])
    # but being let in is being let in, whatever the control did
    assert came_out({"status": 204, "changes": GONE}, alice={"status": 403}) == ("broken", ["let-in"])


def test_a_case_that_did_not_run_is_said_to_be_not_run_and_never_held():
    got = _judged(DELETE, {"alice (may)": [DONE], "amir": [{"not_run": "the app could not be started: no module"}]})
    assert got == {"amir": ("not-run", []), "nobody": ("not-run", [])}
    plan = behave.check({"app": {"asgi": "app:app"}, "people": PEOPLE, "checks": [DELETE]})
    outcomes = behave.judge(plan, behave.scene(plan)[1], {"probes": []})
    assert [o["why"] for o in outcomes] == ["the run ended before this case"] * 2
    assert behave.summary(outcomes) == {"held": 0, "broken": 0, "inconclusive": 0, "not-run": 2}


def test_what_must_stay_hidden_is_looked_for_in_the_answer_and_first_in_the_answer_of_the_one_who_may_see_it():
    check = {"id": "h", "kind": "hide", "who": ["amir"], "shown_to": ["alice"], "must_not_say": ["alice-private"],
             "request": {"path": "/notes"}}
    seen, unseen = {"status": 200, "body": '[{"text": "alice-private"}]'}, {"status": 200, "body": "[]"}
    assert _judged(check, {"alice (may)": [seen], "amir": [unseen]}) == {"amir": ("held", [])}
    assert _judged(check, {"alice (may)": [seen], "amir": [seen]}) == {"amir": ("broken", ["leaked"])}
    assert _judged(check, {"alice (may)": [unseen], "amir": [unseen]}) == {"amir": ("inconclusive", [])}
    assert _judged(check, {"alice (may)": [seen], "amir": [{"status": 500, "body": ""}]}) == {"amir": ("broken", ["crashed"])}


def test_writing_outside_the_apps_folders_is_broken_whatever_the_check_was_about():
    outside = {"status": 403, "changes": {"outside": {"count": 1, "added": ["../x"], "removed": [], "changed": []}}}
    assert _judged(DELETE, {"alice (may)": [DONE], "amir": [outside], "nobody": [{"status": 401}]})["amir"] \
        == ("broken", ["outside-file"])
    refused = {"status": 403, "blocked": ["write to /etc/cron.d/x"]}
    assert _judged(DELETE, {"alice (may)": [DONE], "amir": [refused], "nobody": [{"status": 401}]})["amir"] \
        == ("broken", ["outside-file"])
    # and the outcome names what was written there, and what was refused
    plan = behave.check({"app": {"asgi": "app:app"}, "people": PEOPLE, "checks": [DELETE]})
    wrote = {"status": 403, "changes": {"outside": {"count": 3, "added": ["world/x"], "removed": ["home/y"], "changed": ["z"]}}}
    probes = [{"id": "d/alice (may)", "steps": [DONE]}, {"id": "d/amir", "steps": [wrote]}, {"id": "d/nobody", "steps": [refused]}]
    saw = {o["case"]: o["saw"] for o in behave.judge(plan, behave.scene(plan)[1], {"probes": probes})}
    assert saw["amir"] == {"status": 403, "outside": ["world/x", "home/y", "z"]}
    assert saw["nobody"] == {"status": 403, "tried": ["write to /etc/cron.d/x"]}


def test_setting_out_for_an_address_is_read_from_what_was_refused_and_not_from_what_was_asked():
    check = _preview("p", "http://files.inside.test/")
    asked = {"status": 400, "asked": [["files.inside.test", "10.0.0.5", 80]]}
    went = dict(asked, status=502, blocked=["network connect ('10.0.0.5', 80)"])
    no_six = {"status": 502, "asked": [["::1", "::1", 8080]], "began": [["::1", 8080]]}
    past_the_runner = {"status": 502, "blocked": ["network lookup 'files.inside.test'"]}
    assert _judged(check, {"the request": [asked]}) == {"the request": ("held", [])}
    for step in (went, no_six, past_the_runner):
        assert _judged(check, {"the request": [step]}) == {"the request": ("broken", ["outside-address"])}
    for listed in ("files.inside.test", "FILES.inside.test.", "10.0.0.5"):
        assert _judged(dict(check, may_reach=[listed]), {"the request": [went]}) == {"the request": ("held", [])}
        assert _judged(check, {"the request": [went]}, may_reach=[listed]) == {"the request": ("held", [])}
    assert _judged(dict(check, may_reach=["other.test"]), {"the request": [went]}) == {"the request": ("broken", ["outside-address"])}
    # in any other kind of check an address is as much outside
    assert _judged(DELETE, {"alice (may)": [DONE], "amir": [dict(went, status=403)], "nobody": [{"status": 401}]})["amir"] \
        == ("broken", ["outside-address"])


TRANSFER = {"id": "t", "kind": "faults", "who": "alice", "request": {"method": "POST", "path": "/transfer"},
            "then": {"request": {"method": "POST", "path": "/notes"}, "as": "amir"}}
WHOLE, HALF, NOTE = {"tables": {"users": [0, 0, 2], "transfers": [1, 0, 0]}}, {"tables": {"users": [0, 0, 1]}}, \
    {"tables": {"notes": [1, 0, 0]}}


def _swept(*runs, plain=None) -> dict:
    plain = plain or [{"status": 200, "changes": WHOLE}]
    sweep = {"plain": plain, "then_alone": [{"status": 201, "changes": NOTE}],
             "runs": [{"fault": fault, "steps": steps} for fault, steps in runs]}
    plan = behave.check({"app": {"asgi": "app:app"}, "people": PEOPLE, "checks": [TRANSFER]})
    outcomes = behave.judge(plan, behave.scene(plan)[1], {"probes": [{"id": "t/failures", "sweep": sweep}]})
    return {o["case"]: (o["outcome"], o.get("codes") or []) for o in outcomes}


def test_a_request_made_to_fail_half_way_leaves_all_of_its_work_or_none_and_the_next_request_is_its_own():
    fails, cut = {"kind": "error", "on": "write", "at": 2}, {"kind": "kill", "on": "commit", "at": 1}
    then = {"status": 201, "changes": NOTE}
    both = {"tables": {**HALF["tables"], **NOTE["tables"]}}
    all_three = {"tables": {**WHOLE["tables"], **NOTE["tables"]}}
    assert _swept((fails, [{"status": 500}, then])) == {"the database fails at write 2": ("held", [])}
    assert _swept((cut, [{"died": True, "changes": WHOLE}, dict(then, changes=all_three)])) \
        == {"the app is cut off before commit 1": ("held", [])}
    assert _swept((fails, [{"status": 500, "changes": HALF}, dict(then, changes=both)])) \
        == {"the database fails at write 2": ("broken", ["partial"])}
    assert _swept((fails, [{"status": 500}, dict(then, changes=both)])) \
        == {"the database fails at write 2": ("broken", ["carried-over"])}
    assert _swept((fails, [{"status": 500}, {"status": 500}])) == {"the database fails at write 2": ("broken", ["stuck"])}
    assert _swept((fails, [{"status": 500}, {"died": True}])) == {"the database fails at write 2": ("broken", ["stuck"])}
    assert _swept(({"kind": "kill", "on": "answer", "at": 1}, [{"died": True, "changes": WHOLE}, dict(then, changes=all_three)])) \
        == {"the app is cut off before the answer leaves": ("held", [])}
    assert _swept((fails, [{"not_run": "the app could not be started"}])) == {"the database fails at write 2": ("not-run", [])}
    # a request that does not work without any failure says nothing about failures
    assert _swept((fails, [{"status": 500}, then]), plain=[{"status": 403}]) == {"failures": ("inconclusive", [])}


# ------------------------------------------------------------------------------------------- the plan
def test_a_plan_can_name_paths_of_the_app_and_never_an_address():
    base = {"app": {"asgi": "app:app"}, "people": PEOPLE, "state": {"sqlite": ["{data}/app.db"]}}
    ok = {"id": "x", "kind": "refuse", "who": ["amir"], "allowed": ["alice"], "request": {"path": "/notes/1"}}
    assert behave.check({**base, "checks": [ok]})

    def refused(**changed):
        plan = {**base, "checks": [ok], **changed}
        with pytest.raises(behave.PlanError):
            behave.check(plan)
    for path in ("https://lantern-cloud.fly.dev/v1/runs", "//evil.test/x", "notes", "http://127.0.0.1:8000/"):
        refused(checks=[dict(ok, request={"path": path})])
        refused(seed=[{"request": {"path": path}}])
        refused(checks=[{**ok, "kind": "input", "good": {"path": path}}])
    refused(checks=[dict(ok, request={"path": "/notes", "headers": {"Host": "lantern-cloud.fly.dev"}})])
    refused(checks=[dict(ok, request={"path": "/notes", "headers": {"hOsT": "x"}})])
    refused(seed=[{"sql": {"db": "/home/someone/prod.db", "run": "DELETE FROM users"}}])
    refused(seed=[{"sql": {"db": "{data}/other.db", "run": "DELETE FROM users"}}])
    assert behave.check({**base, "checks": [ok], "seed": [{"sql": {"db": "{data}/app.db", "run": "DELETE FROM users"}}]})
    refused(app={"asgi": "app/main.py"})
    refused(app={"asgi": "uvicorn app:app --host 0.0.0.0"})
    # the app's data is looked at, and the plan's own SQL is run, only in the folder the sandbox gives the app
    for elsewhere in ("/home/someone/app.db", "app.db", "{data}/../../someone/app.db", "~/app.db", "{data}\\..\\x.db",
                      "C:\\Users\\someone\\app.db"):
        refused(state={"sqlite": [elsewhere]})
        refused(state={"folders": [elsewhere]})
    assert behave.check({**base, "checks": [ok], "state": {"sqlite": ["{data}/a/b.db"], "folders": ["{data}/uploads"]}})
    for elsewhere in ("/srv/other", "../other", "a/../../other", "C:\\other"):
        refused(app={"asgi": "app:app", "cwd": elsewhere})
    assert behave.check({**base, "checks": [ok], "app": {"asgi": "app:app", "cwd": "backend/api"}})
    refused(checks=[])
    refused(checks=[ok, dict(ok)])                              # the same id twice
    refused(checks=[dict(ok, id="a/b")])
    refused(checks=[dict(ok, kind="attack")])
    refused(checks=[dict(ok, who=["somebody-else"])])
    refused(people={"alice": "token"})
    # a way of sending a token that this version does not know is said before the run, not as a case that was not run
    tokens = {"id": "t", "kind": "tokens", "who": "alice", "request": {"path": "/me"}}
    assert behave.check({**base, "checks": [dict(tokens, variants=["none", "garbage"])]})
    assert behave.check({**base, "checks": [tokens]})
    for unknown in (["missing"], ["none", "Expired"], "none", [], [1]):
        refused(checks=[dict(tokens, variants=unknown)])


def test_a_project_without_a_plan_is_not_run_and_says_so(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert behave.load(tmp_path) is None
    (tmp_path / "out").mkdir()
    record = behave.run(tmp_path, out=tmp_path / "out", log=lambda line: None)
    assert record["ran"] is False and behave.PLAN_NAME in record["why_not"] and record["outcomes"] == []
    assert json.loads((tmp_path / "out" / behave.RESULT_NAME).read_text(encoding="utf-8")) == record
    (tmp_path / behave.PLAN_NAME).write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(behave.PlanError):
        behave.run(tmp_path, log=lambda line: None)


# ------------------------------------------------------------------------------------------- the run itself
NOTES = '''
import json, os, sqlite3

DB = os.environ["NOTES_DB"]

def db():
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, text TEXT)")
    return conn

async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    body = b""
    while True:
        event = await receive()
        body += event.get("body", b"")
        if not event.get("more_body"):
            break
    who = dict(scope["headers"]).get(b"authorization", b"").decode().removeprefix("Bearer ")
    status, answer = 404, {}
    conn = db()
    try:
        if scope["method"] == "POST" and scope["path"] == "/notes" and who:
            cur = conn.execute("INSERT INTO notes (owner, text) VALUES (?, ?)", (who, json.loads(body)["text"]))
            conn.commit()
            status, answer = 201, {"id": cur.lastrowid}
        elif scope["method"] == "DELETE" and scope["path"].startswith("/notes/"):
            status, answer = delete(conn, who, int(scope["path"].rsplit("/", 1)[1]))
    finally:
        conn.close()
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": json.dumps(answer).encode()})
'''
DELETES_ITS_OWN = NOTES + '''
def delete(conn, who, note):
    row = conn.execute("SELECT owner FROM notes WHERE id = ?", (note,)).fetchone()
    if row is None or row[0] != who:
        return 403, {}
    conn.execute("DELETE FROM notes WHERE id = ?", (note,))
    conn.commit()
    return 204, {}
'''
DELETES_THEN_ASKS = NOTES + '''
def delete(conn, who, note):
    row = conn.execute("SELECT owner FROM notes WHERE id = ?", (note,)).fetchone()
    conn.execute("DELETE FROM notes WHERE id = ?", (note,))
    conn.commit()
    return (204, {}) if row is not None and row[0] == who else (403, {})
'''
NOTES_PLAN = {
    "app": {"asgi": "app:app", "env": {"NOTES_DB": "{data}/notes.db"}},
    "state": {"sqlite": ["{data}/notes.db"]},
    "people": {"alice": {"token": "alice"}, "amir": {"token": "amir"}},
    "seed": [{"request": {"method": "POST", "path": "/notes", "json": {"text": "milk"}}, "as": "alice", "save": {"note": "json:id"}}],
    "checks": [{"id": "delete", "kind": "refuse", "about": "Only its owner deletes a note", "who": ["amir", "nobody"],
                "allowed": ["alice"], "request": {"method": "DELETE", "path": "/notes/{note}"}}],
}


@starts_an_app
def test_a_refused_request_that_changed_the_database_all_the_same_is_broken_and_its_safe_twin_holds(tmp_path):
    safe = _by_case(_run(_repo(tmp_path / "safe", DELETES_ITS_OWN, NOTES_PLAN)))
    assert safe == {"delete/amir": ("held", []), "delete/nobody": ("held", [])}
    record = _run(_repo(tmp_path / "late", DELETES_THEN_ASKS, NOTES_PLAN))
    assert _by_case(record) == {"delete/amir": ("broken", ["refused-but-changed"]),
                                "delete/nobody": ("broken", ["refused-but-changed"])}
    saw = record["outcomes"][0]["saw"]
    assert saw["status"] == 403 and saw["changed"] == {"notes": [0, 1, 0]}      # answered "no", and the row is gone
    assert record["outcomes"][0]["said"] == behave.CODES["refused-but-changed"]


@starts_an_app
def test_an_app_that_a_function_makes_is_started_the_way_its_server_starts_it(tmp_path):
    made = DELETES_THEN_ASKS.replace("async def app(", "async def serve(") + "\n\ndef create_app():\n    return serve\n"
    plan = dict(NOTES_PLAN, app={**NOTES_PLAN["app"], "asgi": "app:create_app", "factory": True})
    record = _run(_repo(tmp_path / "made", made, plan))
    assert _by_case(record) == {"delete/amir": ("broken", ["refused-but-changed"]),
                                "delete/nobody": ("broken", ["refused-but-changed"])}
    # without the word, the function itself is taken for the app: nothing is asked of it and nothing counts as held
    plain = dict(NOTES_PLAN, app={**NOTES_PLAN["app"], "asgi": "app:create_app"})
    record = behave.run(_repo(tmp_path / "plain", made, plain), log=lambda line: None)
    assert record["summary"]["held"] == 0 and (not record["ran"] or record["summary"]["broken"] == 0)
    for bad in ("yes", 1, None):
        with pytest.raises(behave.PlanError):
            behave.check(dict(NOTES_PLAN, app={**NOTES_PLAN["app"], "factory": bad}))


@starts_an_app
def test_a_set_up_step_that_fails_stops_the_run_and_an_app_that_cannot_start_is_not_run(tmp_path):
    plan = {**NOTES_PLAN, "seed": [{"request": {"method": "POST", "path": "/nothing-here", "json": {}}, "as": "alice"}]}
    record = behave.run(_repo(tmp_path / "seed", DELETES_ITS_OWN, plan), log=lambda line: None)
    assert record["ran"] is False and "set-up failed at step 1" in record["why_not"] and "404" in record["why_not"]
    plan = {**NOTES_PLAN, "seed": [], "app": {"asgi": "missing_module:app"},
            "checks": [dict(NOTES_PLAN["checks"][0], request={"method": "DELETE", "path": "/notes/1"})]}
    record = behave.run(_repo(tmp_path / "gone", DELETES_ITS_OWN, plan), log=lambda line: None)
    assert record["ran"] and record["summary"] == {"held": 0, "broken": 0, "inconclusive": 0, "not-run": 2}
    assert all("could not be started" in o["why"] for o in record["outcomes"])


@starts_an_app
def test_the_command_ends_with_0_only_when_every_case_held_and_the_record_says_what_was_run(tmp_path, capsys):
    safe = _repo(tmp_path / "safe", DELETES_ITS_OWN, NOTES_PLAN)
    assert cli.main(["behave", str(safe), "--out", str(tmp_path / "o1")]) == 0
    said = capsys.readouterr().out
    assert "2 held, 0 broken, 0 undecided, 0 not run" in said and str(tmp_path / "o1" / behave.RESULT_NAME) in said
    first = json.loads((tmp_path / "o1" / behave.RESULT_NAME).read_text(encoding="utf-8"))
    assert first["ran"] and first["summary"] == {"held": 2, "broken": 0, "inconclusive": 0, "not-run": 0}
    of = first["of"]
    assert of["lantern"] == __version__ and of["commit"] is None and len(of["plan_sha256"]) == 64
    assert set(of) == {"plan_sha256", "commit", "dirty", "lantern", "python", "system"}

    late = _repo(tmp_path / "late", DELETES_THEN_ASKS, NOTES_PLAN)
    assert cli.main(["behave", str(late), "--out", str(tmp_path / "o2")]) == 1
    said = capsys.readouterr().out
    assert "2 broken" in said and "delete / amir" in said and "status 403" in said
    assert 'changed {"notes": [0, 1, 0]}' in said and behave.CODES["refused-but-changed"] in said
    second = json.loads((tmp_path / "o2" / behave.RESULT_NAME).read_text(encoding="utf-8"))
    assert second["of"]["plan_sha256"] == of["plan_sha256"]                  # the same plan, whatever the app did

    other = dict(NOTES_PLAN, checks=[dict(NOTES_PLAN["checks"][0], who=["amir"])])
    assert cli.main(["behave", str(_repo(tmp_path / "other", DELETES_ITS_OWN, other)), "--out", str(tmp_path / "o3")]) == 0
    third = json.loads((tmp_path / "o3" / behave.RESULT_NAME).read_text(encoding="utf-8"))
    assert third["of"]["plan_sha256"] != of["plan_sha256"] and third["summary"]["held"] == 1


def test_the_command_ends_with_2_where_there_is_no_plan_to_run_and_with_3_where_the_app_was_not_started(
        tmp_path, capsys, monkeypatch):
    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert cli.main(["behave", str(bare), "--out", str(tmp_path / "o1")]) == 2
    assert f"the project has no {behave.PLAN_NAME}" in capsys.readouterr().out
    record = json.loads((tmp_path / "o1" / behave.RESULT_NAME).read_text(encoding="utf-8"))
    assert record["ran"] is False and record["no_plan"] is True and record["of"]["plan_sha256"] is None

    (bare / behave.PLAN_NAME).write_text("[1, 2]", encoding="utf-8")
    assert cli.main(["behave", str(bare), "--out", str(tmp_path / "o2")]) == 2
    assert "cannot be used" in capsys.readouterr().err and not (tmp_path / "o2" / behave.RESULT_NAME).exists()
    assert cli.main(["behave", str(tmp_path / "nothing-here")]) == 2
    assert "is not a folder" in capsys.readouterr().err

    def refused(*a, **k):
        raise sandbox.Unavailable("this system refused the restriction the sandbox counts on")
    monkeypatch.setattr(sandbox, "run_inside", refused)
    repo = _repo(tmp_path / "safe", DELETES_ITS_OWN, NOTES_PLAN)
    assert cli.main(["behave", str(repo), "--out", str(tmp_path / "o3")]) == 3
    assert "the app was not started" in capsys.readouterr().out
    record = json.loads((tmp_path / "o3" / behave.RESULT_NAME).read_text(encoding="utf-8"))
    assert record["ran"] is False and "no_plan" not in record and "refused the restriction" in record["why_not"]
    assert record["outcomes"] == [] and record["summary"] == {"held": 0, "broken": 0, "inconclusive": 0, "not-run": 0}
    assert len(record["of"]["plan_sha256"]) == 64


@starts_an_app
def test_a_run_that_was_not_started_never_counts_as_held(tmp_path, capsys):
    plan = {**NOTES_PLAN, "seed": [], "app": {"asgi": "missing_module:app"},
            "checks": [dict(NOTES_PLAN["checks"][0], request={"method": "DELETE", "path": "/notes/1"})]}
    assert cli.main(["behave", str(_repo(tmp_path / "gone", DELETES_ITS_OWN, plan)), "--out", str(tmp_path / "o")]) == 1
    said = capsys.readouterr().out
    assert "0 held, 0 broken, 0 undecided, 2 not run" in said and "could not be started" in said


def test_the_app_is_not_started_where_the_sandbox_guard_is_not_in_place(tmp_path):
    scene = tmp_path / "scene.json"
    scene.write_text(json.dumps(behave.scene(behave.check(NOTES_PLAN))[0]), encoding="utf-8")
    repo = _repo(tmp_path / "repo", DELETES_ITS_OWN, NOTES_PLAN)
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    r = subprocess.run([sys.executable, "-m", "lantern._behave_inside", str(scene), str(tmp_path / "out.json"), str(repo)],
                       env=env, cwd=tmp_path, capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert r.returncode == 97 and "guard is not in place" in r.stdout and not (tmp_path / "out.json").exists()
    r = subprocess.run([sys.executable, "-m", "lantern._behave_inside", "worker", "app:app"], env=env, cwd=repo,
                       input="", capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert r.returncode == 97 and json.loads(r.stdout.splitlines()[0])["ready"] is False


def test_only_lanterns_own_driver_is_started_this_way(tmp_path):
    with pytest.raises(ValueError):
        sandbox.run_inside(tmp_path, "json.tool", {})
    with pytest.raises(ValueError):
        sandbox.run_inside(tmp_path, "lantern.cli", {})


def test_no_app_is_started_where_the_sandbox_starts_none_and_the_record_and_the_command_say_why(
        tmp_path, monkeypatch, capsys):
    """On Windows the sandbox cannot yet see what an app's event loop connects to (`sandbox.NO_APPS`), so a case
    there could come out held while a request left the computer. Nothing is started, and nothing is called held."""
    assert bool(sandbox.NO_APPS) is (sys.platform == "win32")

    def started(*args, **more):
        raise AssertionError("the sandbox started something")
    monkeypatch.setattr(sandbox, "NO_APPS", "here the sandbox cannot see what an app's event loop connects to")
    monkeypatch.setattr(sandbox, "_run_subprocess", started)
    repo = _repo(tmp_path / "repo", DELETES_ITS_OWN, NOTES_PLAN)
    record = behave.run(repo, log=lambda line: None)
    assert record["ran"] is False and record["outcomes"] == []
    assert "the app was not started" in record["why_not"] and "cannot see what an app's event loop" in record["why_not"]
    assert record["summary"] == {"held": 0, "broken": 0, "inconclusive": 0, "not-run": 0}
    assert cli.main(["behave", str(repo), "--out", str(tmp_path / "o")]) == 3
    assert "cannot see what an app's event loop" in capsys.readouterr().out
    assert json.loads((tmp_path / "o" / behave.RESULT_NAME).read_text(encoding="utf-8"))["ran"] is False
    assert _bench().main([str(tmp_path / "work")]) == 3 and not (tmp_path / "work").exists()


# --------------------------------------------------------------------------- apps that were not written for it
def _asks(method: str, path: str, **more) -> dict:
    return {"method": method, "path": path, **more}


HELLO = {"messages": [{"role": "user", "content": "hello"}]}
GATEWAY_PLAN = {
    "app": {"asgi": "lantern_gateway.app:create_app", "factory": True, "cwd": "gateway",
            "env": {"LANTERN_DB": "{data}/gateway.db", "LANTERN_ADMIN_SECRET": "{secret}",
                    "ANTHROPIC_API_KEY": "not-a-key-of-anybody"}},
    "state": {"sqlite": ["{data}/gateway.db"]},
    "people": {"owner": {"token": "{secret}"}, "tester": {"token": "{tester_token}"}},
    "seed": [{"request": _asks("POST", "/v1/tokens", json={"label": "tester"}), "as": "owner",
              "save": {"tester_token": "json:token"}}],
    "checks": [
        {"id": "mint", "kind": "refuse", "about": "Only the owner makes a token",
         "request": _asks("POST", "/v1/tokens", json={"label": "another"}), "who": ["tester", "nobody"], "allowed": ["owner"]},
        {"id": "stats", "kind": "refuse", "about": "Only the owner reads the numbers",
         "request": _asks("GET", "/v1/admin/stats"), "who": ["tester", "nobody"], "allowed": ["owner"]},
        {"id": "allowance", "kind": "refuse", "about": "What is left is told only to whoever is signed in",
         "request": _asks("GET", "/v1/allowance"), "who": ["nobody"], "allowed": ["tester"]},
        {"id": "sign-in", "kind": "tokens", "about": "Only a token the gateway made, whole, gets in",
         "request": _asks("GET", "/v1/whoami"), "who": "tester", "variants": ["none", "empty", "garbage", "truncated"]},
        {"id": "sign-out", "kind": "refuse", "about": "Nobody signs somebody else out",
         "request": _asks("POST", "/v1/auth/signout", json={}), "who": ["nobody"], "allowed": ["tester"]},
        {"id": "big-report", "kind": "input", "about": "A usage report of 5,000 bytes is refused",
         "request": _asks("POST", "/v1/usage", bytes=5000),
         "good": _asks("POST", "/v1/usage", json={"install": "0123456789abcdef" * 2, "features": {"analyze": 1}})},
        {"id": "chat-provider", "kind": "address", "about": "A chat request goes to the model provider and nowhere else",
         "request": _asks("POST", "/v1/chat/completions", json=HELLO), "who": "tester", "may_reach": ["api.anthropic.com"]},
        {"id": "chat-unlisted", "kind": "address", "about": "The same request when the plan lists no site",
         "request": _asks("POST", "/v1/chat/completions", json=HELLO), "who": "tester"},
    ],
}


@starts_an_app
def test_lanterns_own_gateway_is_started_as_it_is_and_asked(tmp_path):
    """An app that was not written for the runner: made by a function, set up from the environment, with a store
    of its own. Its code is copied as it is; only the plan is new."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    repo = tmp_path / "repo"
    shutil.copytree(ROOT / "gateway", repo / "gateway", ignore=shutil.ignore_patterns("__pycache__", "*.db"))
    (repo / behave.PLAN_NAME).write_text(json.dumps(GATEWAY_PLAN), encoding="utf-8")
    record = _run(repo)
    got = _by_case(record)
    assert {case: came for case, came in got.items() if came[0] != "held"} == {
        "chat-unlisted/the request": ("broken", ["outside-address"])}, got
    assert record["summary"] == {"held": 12, "broken": 1, "inconclusive": 0, "not-run": 0}
    saw = {f"{o['check']}/{o['case']}": o.get("saw") or {} for o in record["outcomes"]}
    # the provider's name was answered inside the sandbox, the connection was refused there, and the gateway said so
    for case in ("chat-provider/the request", "chat-unlisted/the request"):
        assert saw[case]["status"] == 502 and saw[case]["asked"] == [["api.anthropic.com", "198.51.100.1"]]
        assert "changed" not in saw[case]                           # and the person was charged nothing for it
    assert saw["big-report/the bad request"]["status"] == 413
    assert {saw[f"sign-in/{v}"]["status"] for v in ("none", "empty", "garbage", "truncated")} == {401}


SHOP_PLAN = {
    "app": {"asgi": "shop.app:app"},
    "state": {"folders": ["{data}/files"]},
    "checks": [
        {"id": "backup-name", "kind": "contain", "about": "A backup's name cannot make the server write somewhere else",
         "request": _asks("POST", "/backup", query={"name": "x; echo planted > {data}/../planted.txt #"})},
        {"id": "backup-plain", "kind": "contain", "about": "An ordinary name",
         "request": _asks("POST", "/backup", query={"name": "monday"})},
    ],
}


@starts_an_app
@pytest.mark.skipif(os.name != "posix", reason="the name sent is a line for a POSIX shell")
def test_the_shop_samples_planted_command_is_seen_as_a_file_the_request_chose(tmp_path):
    """`lantern analyze` reports the shop's backup route as a command built from the request. Here the request is
    sent, and the file it names is found where it said: seen, not read."""
    pytest.importorskip("fastapi")
    repo = tmp_path / "repo"
    shutil.copytree(ROOT / "tests" / "fixtures" / "shop", repo, ignore=shutil.ignore_patterns("__pycache__", "node_modules"))
    (repo / behave.PLAN_NAME).write_text(json.dumps(SHOP_PLAN), encoding="utf-8")
    record = _run(repo)
    planted, plain = record["outcomes"]
    assert planted["outcome"] == "broken" and "outside-file" in planted["codes"]
    assert planted["saw"]["outside"] == ["behave/world/planted.txt"]
    # the sample keeps its database beside its code, which is a read-only copy here: refused, said, nothing written
    assert plain["outcome"] == "broken" and "outside-file" in plain["codes"]
    assert plain["saw"]["tried"] == ["write to app.db"] and "outside" not in plain["saw"]


# ------------------------------------------------------------------------------------------- the planted problems
def _bench():
    spec = importlib.util.spec_from_file_location("behaviour_run", ROOT / "bench" / "behaviour" / "run_behaviour.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def corkboard():
    """Corkboard (bench/behaviour): a FastAPI app with sign-in tokens, the safe version and 31 with one planted
    problem each. tests/test_behaviour_apps.py tests the apps themselves."""
    pytest.importorskip("fastapi")
    pytest.importorskip("jwt")
    return _bench()


@starts_an_app
def test_the_safe_app_holds_in_every_case_of_the_whole_plan(corkboard, tmp_path):
    row = corkboard.run_one(tmp_path, corkboard.SAFE)
    assert row["differences"] == [], row["log"]
    assert row["summary"] == {"held": 80, "broken": 0, "inconclusive": 0, "not-run": 0}


@starts_an_app
def test_every_planted_problem_is_caught_by_the_cases_written_down_for_it_before_the_first_run(corkboard, tmp_path):
    """Each version runs the checks its problem names (`plan.EXPECTED`): those cases come out broken with those
    codes, the cases the problem leaves undecided come out so, and the other cases of the same checks hold.
    `bench/behaviour/run_behaviour.py` runs the whole plan against every version (no other case may break)."""
    names = list(corkboard.apps.PLANTED)
    assert len(names) == 31 and set(names) == set(corkboard.plans.EXPECTED)
    with ThreadPoolExecutor(min(4, os.cpu_count() or 1)) as pool:
        rows = list(pool.map(lambda name: corkboard.run_one(tmp_path, name, own_checks=True), names))
    assert {r["name"]: r["differences"] for r in rows if r["differences"]} == {}
    assert all(r["summary"]["broken"] >= 1 for r in rows)
    codes = {code for r in rows for found in r["broken"].values() for code in found}
    assert codes == set(behave.CODES) - {"stuck", "crashed"}      # those two are judged by hand above


def test_the_table_of_what_must_come_out_names_only_cases_the_plan_has(corkboard):
    plan = behave.check(corkboard.plans.plan())
    cases = {f"{c['check']}/{c['case']}" for c in behave.scene(plan)[1] if c["role"] != "control"}
    checks = {c["id"]: c["kind"] for c in plan["checks"]}
    for planted, table in corkboard.plans.EXPECTED.items():
        for case, codes in table.items():
            assert set(codes) <= set(behave.CODES), (planted, case)
            assert case in cases or checks.get(case.split("/")[0]) == "faults", (planted, case)
    for planted, undecided in corkboard.plans.INCONCLUSIVE.items():
        assert planted in corkboard.apps.PLANTED and set(undecided) <= cases
    assert corkboard.plans.differences(None, {"ran": False, "why_not": "x"}) == ["not run: x"]
