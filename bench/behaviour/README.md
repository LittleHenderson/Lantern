# Behaviour benchmark: does the runner catch what was planted, and nothing else?

Directive point 5 (2026-11-09): "Create disposable test applications and test actual outcomes and side effects …
A rejected request that already changed the database is a failure. Test the side effects, not just the response
code. Keep these tests away from production."

```bash
python bench/behaviour/run_behaviour.py WORKDIR                  # the whole plan against all 33 versions, about 4.5 minutes with 3 side by side (the default)
python bench/behaviour/run_behaviour.py WORKDIR --own-checks     # for a planted version only the checks written down for it (what the tests do)
python bench/behaviour/run_behaviour.py WORKDIR --only safe,refused-but-deleted --results FILE
python bench/behaviour/run_behaviour.py WORKDIR --first-plan     # no plan a person wrote: the plan Lantern writes itself for each version, about 2.5 minutes
```

| File | What it is |
|---|---|
| `apps.py` | Writes **Corkboard**, a small notes app for teams (FastAPI, SQLite, PyJWT): `build(folder, planted=None)`. The safe app, or the safe app with one of 32 problems (`PLANTED`) put in: each planted version differs from the safe one in the pieces its problem names and in nothing else (`tests/test_behaviour_apps.py`). The apps exist only in the folder a run writes them to |
| `plan.py` | The plan (`plan()`: 41 checks, 100 cases asked, 83 outcomes on the safe app) and, written down before the first run, which cases each planted problem must break and with which codes (`EXPECTED`), and which must come out undecided because the planted problem takes their control away (`INCONCLUSIVE`). `differences(planted, record)` says where a run differs from that |
| `run_behaviour.py` | Runs it: every version in Lantern's test sandbox (`lantern.behave`), isolated by `tools/netguard` (no network at all is needed, so anything tried fails the run) |
| `results.md` | The last whole run |
| `first_plan.py` | What the plan Lantern writes by itself (`lantern behave PATH --init`, `lantern/behave_init.py`) must show on Corkboard, written down before its first run: the cases that break for each of the 8 planted problems a first plan is to catch (`CAUGHT`), nothing broken anywhere else, and no undecided case that the plan itself did not name to look at first. `differences(planted, record, plan)` |
| `first_plan_results.md` | The last whole run of `--first-plan` |

## What is planted

Who may reach what: no login on the list of notes; a teammate reading a private note; another team's member
reading, listing and exporting a team's notes; any signed-in person changing and deleting another's note; a delete
that answers "no" after the note is gone; a member, and another team's admin, removing a user. Sign-ins: an expired
token, an altered or made-up token, a token for reading that can write, and (since 2026-11-15) the sign-in of a
removed person that goes on working on the copy of the app that let them in. What is sent: a role taken through the
profile form, a negative amount, a request of megabytes, an upload whose name leaves the folder, an uploaded page
served back as a page, a zip entry that leaves the folder, a zip that unpacks to megabytes. Where the app sends
people and goes itself: a redirect to any site, a redirect check that lets `//site` through, a preview that fetches
internal addresses, a preview check that misses other spellings of them. Limits and moments: no limit on wrong
passwords, a limit forgotten at a restart and not shared between copies, a coupon redeemed twice at once. Failures:
a transfer that keeps its first half after a database error, one that keeps it when cut off, one that is done
again when sent again, and one whose half is saved by the next person's request.

## Targets, set before the first run, and what came out

| # | Target | Came out |
|---|---|---|
| T1 | Every planted problem is caught on its version by the cases written down for it | 31 of 31 (first pass: 27 of 31 as written down, see below); 32 of 32 since 2026-11-15, the added one as written down on its first run |
| T2 | The safe app: 0 cases broken, the near-misses included | 0 of 80 broken, 80 held (0 of 83, 83 held, since 2026-11-15) |
| T3 | A refused request that changed something is its own kind of failure, told from "let in" | `refused-but-changed` on `refused-but-deleted`; `let-in` on `other-user-delete` |
| T4 | With the whole plan against every version, a planted version breaks only its own cases | 31 of 31: no other case broken (32 of 32 since 2026-11-15) |
| T5 | Nothing outside this computer is tried, and the runner starts no app without the sandbox's guard | 0 attempts (`tools/netguard`: "0 attempt(s) to reach anything else"); result 97 without the guard (`tests/test_behave.py`) |
| T6 | Apps that were not written for the runner start under it as they are | Lantern's gateway: 12 held, and the 1 case that must break did (15 held since 2026-11-15, when its plan got a check of the kind `ended`: a sign-in that was signed out is refused straight after, after a restart and on another copy). The shop sample: its planted command seen as a file written where the request said. Both are tests. Three faults of the runner showed and were fixed (below) |
| T7 | The whole plan on the safe app in under 60 seconds | About 25 seconds (58 starts of the app). The first measurement was 66.9 seconds: missed, until the app's copies were let keep compiled Python in their temp folder |

## The plan nobody wrote (roadmap stage 4, 2026-11-16)

`--first-plan` hands no plan over. For each of the 33 versions Lantern reads that version's own code, writes
`lantern-behaviour.json` (16 checks, 40 requests, 23 outcomes; 7 routes left out, each with the reason) and runs
it exactly as written.

| # | Target, written down before the first run | Came out |
|---|---|---|
| F1 | The safe app: no case broken | 0 broken; 16 held, 6 undecided, 1 not run |
| F2 | The planted problems of the three kinds a first plan asks about are caught by the cases written down for them: a visitor let in (`no-login-list`), somebody else's row (`other-team-read`, `other-user-change`, `other-user-delete`, `refused-but-deleted`, `other-team-list`), wrong passwords not counted (`no-login-limit`, `limit-in-memory`) | 8 of 8, with the cases and the codes as written down, on the first run |
| F3 | On the other 24 planted versions no case comes out broken (those problems take a plan a person wrote: `plan.py` catches all 32) | 0 broken on 24 of 24 |
| F4 | A case that is not decided belongs to a check the plan itself named to look at first, before anything ran | Missed on the first run for 2 checks, see below; holds on all 33 versions since |

What the first run showed that was wrong, each corrected after a test that failed first:

* One "held" was hollow. Two coupon requests at the same moment, with a coupon code Lantern made up: the app
  refuses the code, so nothing was ever done once, and "not done twice" read as held. The runner now says
  undecided for the kind `once` when the request does not work even when it is sent alone (`lantern/behave.py`;
  the plan a person wrote comes out as before, all 33 versions).
* Two undecided cases were on no list. The preview route is sent a made-up address, which the app's own list of
  hosts refuses: the plan now says so for every address it makes up. On `role-in-profile` nothing in the
  profile's body has to be sent, the plan sent it empty, and a request that changes nothing proves nothing
  beside a refusal: such a body now carries one field Lantern is sure of, and where it is sure of none the plan
  says so.

## What the first pass got wrong

The first run of all 31 planted versions, before anything was corrected: 27 came out as written down, 4 did not.

* `export-every-team`: a mistake in `EXPECTED`, the table written beforehand. The planted problem takes away the
  control of one case (`export-hides-private/amir`), which must then come out undecided (`INCONCLUSIVE`).
* `fetch-any-address` and `fetch-half-checked`: one fault of the runner. On a computer with no IPv6 (this one) an
  app's try for an IPv6 address ends when it asks for the socket, one step before the connection the sandbox
  refuses, and the runner saw nothing (`preview-loopback-v6` came out held).
* `unsigned-token`: its case "cut short" came out held. It was taken for a second mistake in the table, and the
  table was changed; a second run then gave the other answer. The fault was the runner's: it cut the token at a
  place where the token library read what was left as whole on one run and not on the next. A signed token is now
  cut inside its signature at a whole-text boundary, and the table is as it was written first.

While the IPv6 fault was being fixed, a test written for the safe twin showed one more fault: an app that only asked
where a name leads, saw that it leads inside and refused, was reported like one that went there, because the
question itself was counted. Since then the runner answers such questions itself and judges by the connection.

Two apps that were not written for the runner showed three more: an app made by a function (`create_app`) could
not be started (`"factory": true`); a word for a token variant that this version does not know came out as a case
that was not run (now the plan is refused before the run); an outcome did not name the file that was written
outside the app's folders (`saw.outside`).

## The thirty-second planted problem (2026-11-15)

The plan had no check of the kind `ended` (a request that works, the request that ends something, the first
request again: `lantern/behave.py`) and no version of Corkboard had a problem of that kind, so the code
`lived-on` came out of no benchmark run. Added: the version `sign-in-remembered` (`current_user` keeps whom this
copy of the app let in and does not look them up again) and the check `removed-user` (a person the team's admin
removed asks for a new token: straight after, after a restart, and on another copy of the app that answered them
once before).

Written down before the first run (`plan.EXPECTED`): on `sign-in-remembered` the check comes out broken with
`lived-on` straight after and on another worker and holds after a restart, because a copy started afresh
remembers nothing; on the safe app and on the other 31 versions it holds in all three cases.

The first run of the whole plan against all 33 versions (2026-11-16 UTC, `results.md`): 33 of 33 as written
down, 0 differing; the safe app 83 cases held, 0 broken; 0 attempts to reach anything outside this computer.
Nothing was corrected afterwards, neither in the table nor in the runner. Every code of `behave.CODES` but
`stuck` and `crashed` now comes out of a version of Corkboard (`tests/test_behave.py`).

Reading the code alone, measured the same day the way described below (`lantern analyze FOLDER --offline`, the
engine of this change): no finding on the safe app and none on `sign-in-remembered`, release decision Incomplete
for both. No rule reads that an answer a copy remembers outlives what it was about; the plan is what tells the
two apart. The tables below are of the dates they name and of the 31 versions there were then.

## What reading the code alone says about the same versions

Measured 2026-11-11: each version written to a folder (`apps.build(folder, planted)`) and read with
`lantern analyze FOLDER --offline`; its findings outside tests compared with the safe app's by rule, rank and count.
The reading engine is main's (c5cb7cd); this step does not change it.

| | Reading the code (`lantern analyze`) | Running it (`lantern behave`) |
|---|---|---|
| Planted versions told apart from the safe app | 6 of 31 | 31 of 31 |
| The safe app | 2 findings at high, both false alarms | 80 cases held, 0 broken |

The 6: `other-team-list` (`LT-AUTHZ-OWNER`), `unsigned-token` (`LW-AUTH-MISSING`, on another route), `open-redirect`
and `redirect-half-checked` (`LT-REDIRECT`), `upload-name-escapes` and `upload-served-as-page` (one more `LT-PATH`
each). For the other 25 the findings are the safe app's, one for one. The safe app's two findings are `LT-PATH` on
the zip import, where every name is checked against the folder before anything is written
(`if any(not t.startswith(inside) for t in targets): raise`): a check written over the whole list is not read as a
guard yet. The runner's outcomes change no finding, so those two stay until the reading engine is corrected.

Measured again 2026-11-12 (UTC) on the reading engine of point 6 (babe4e6), the same way. That engine reads a check
made over a whole list as a check on every item of the list (`flow.Engine.each_facts`, written after the result
above, against examples of its own: `tests/test_list_guard.py`):

| | Engine c5cb7cd | Engine babe4e6 |
|---|---|---|
| The safe app | 2 findings at high, both false alarms | no finding |
| Planted versions told apart from the safe app | 6 of 31 | 7 of 31 |

The seventh is `zip-entry-escapes`, the version whose check on the zip's names was taken out: the two `LT-PATH`
findings at high that were false alarms on the safe app now stand only there. The other six are told apart by the
same findings as before; for the other 24 the reading finds nothing, as on the safe app. The release decision
(`readiness.json` → `release`) reads Blocked for the three versions with an `LT-PATH` at high and Incomplete for the
other 28 and for the safe app (2 libraries have no exact version written down; the project has no tests): reading the
code alone refuses 3 of the 31 planted problems, which is why the plan is run.

## What this does not measure

One app, one framework (FastAPI), one database (SQLite), written by the same hand as the runner. The planted
problems are the ones the directive names; an app that hides a problem behind a shape the plan does not ask about
is not found, because only what a plan asks is tried. No JavaScript app is started, and on Windows no app at all (the benchmark says why and ends with 3). Limits of the runner itself:
`docs/behaviour.md`.
