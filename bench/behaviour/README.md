# Behaviour benchmark: does the runner catch what was planted, and nothing else?

Directive point 5 (2026-11-09): "Create disposable test applications and test actual outcomes and side effects …
A rejected request that already changed the database is a failure. Test the side effects, not just the response
code. Keep these tests away from production."

```bash
python bench/behaviour/run_behaviour.py WORKDIR                  # the whole plan against all 32 versions, about 3.5 minutes with 4 side by side
python bench/behaviour/run_behaviour.py WORKDIR --own-checks     # for a planted version only the checks written down for it (what the tests do)
python bench/behaviour/run_behaviour.py WORKDIR --only safe,refused-but-deleted --results FILE
```

| File | What it is |
|---|---|
| `apps.py` | Writes **Corkboard**, a small notes app for teams (FastAPI, SQLite, PyJWT): `build(folder, planted=None)`. The safe app, or the safe app with one of 31 problems (`PLANTED`) put in: each planted version differs from the safe one in the pieces its problem names and in nothing else (`tests/test_behaviour_apps.py`). The apps exist only in the folder a run writes them to |
| `plan.py` | The plan (`plan()`: 40 checks, 97 cases asked, 80 outcomes on the safe app) and, written down before the first run, which cases each planted problem must break and with which codes (`EXPECTED`), and which must come out undecided because the planted problem takes their control away (`INCONCLUSIVE`). `differences(planted, record)` says where a run differs from that |
| `run_behaviour.py` | Runs it: every version in Lantern's test sandbox (`lantern.behave`), isolated by `tools/netguard` (no network at all is needed, so anything tried fails the run) |
| `results.md` | The last whole run |

## What is planted

Who may reach what: no login on the list of notes; a teammate reading a private note; another team's member
reading, listing and exporting a team's notes; any signed-in person changing and deleting another's note; a delete
that answers "no" after the note is gone; a member, and another team's admin, removing a user. Sign-ins: an expired
token, an altered or made-up token, a token for reading that can write. What is sent: a role taken through the
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
| T1 | Every planted problem is caught on its version by the cases written down for it | 31 of 31 (first pass: 27 of 31 as written down, see below) |
| T2 | The safe app: 0 cases broken, the near-misses included | 0 of 80 broken, 80 held |
| T3 | A refused request that changed something is its own kind of failure, told from "let in" | `refused-but-changed` on `refused-but-deleted`; `let-in` on `other-user-delete` |
| T4 | With the whole plan against every version, a planted version breaks only its own cases | 31 of 31: no other case broken |
| T5 | Nothing outside this computer is tried, and the runner starts no app without the sandbox's guard | 0 attempts (`tools/netguard`: "0 attempt(s) to reach anything else"); result 97 without the guard (`tests/test_behave.py`) |
| T6 | Apps that were not written for the runner start under it as they are | Lantern's gateway: 12 held, and the 1 case that must break did. The shop sample: its planted command seen as a file written where the request said. Both are tests. Three faults of the runner showed and were fixed (below) |
| T7 | The whole plan on the safe app in under 60 seconds | About 25 seconds (58 starts of the app). The first measurement was 66.9 seconds: missed, until the app's copies were let keep compiled Python in their temp folder |

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

## What this does not measure

One app, one framework (FastAPI), one database (SQLite), written by the same hand as the runner. The planted
problems are the ones the directive names; an app that hides a problem behind a shape the plan does not ask about
is not found, because only what a plan asks is tried. No JavaScript app is started, and on Windows no app at all (the benchmark says why and ends with 3). Limits of the runner itself:
`docs/behaviour.md`.
