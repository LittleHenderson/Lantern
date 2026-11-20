# Who writes the proof, and does the sign-in still hold at the change (2026-11-19)

The side-by-side with another review tool (`bench/report_comparison_results.md`) left two of its points open. Both are
about the app's code: who may write the proof that something happened (its item 3), and whether the sign-in still
holds when the change is saved (its item 4). That tool found one problem of each kind on the project Lantern was
measured on (its findings 4 and 11 for item 3, finding 10 for item 4), and Lantern found none of them. This note is
what was built for them and what it measured. Nothing was copied from that project: every check was written from
examples of Lantern's own, beside safe twins, and the project is named only as "the project".

## What was built

| Check | What it names | Where |
|---|---|---|
| A | `LW-CALLER-SAYS-DONE`: something is marked paid, settled or confirmed, and the only proof is a value the caller sent whose name says it is the proof (a provider's transaction id, a receipt number); nothing hands that value to anything that could ask the provider | `lantern/selfproof.py`, Python and JS/TS |
| B | `LW-SELF-WRITTEN-PROOF`: a function named for checking asks for at least two kinds of record that a side the program trusts less (a runner, a worker, a client, an agent) may write itself, one of them a record that something happened; quiet where it also asks for a record that a list of the trusted side names | `lantern/selfproof.py`, Python |
| C | `LW-SIGN-IN-ENDED-MIDWAY`: a sign-in is checked under a lock of the object, the lock is let go, and a change follows; another method gives the checked field a new value under the same lock (a sign-out, a token rotated) | `lantern/staleauth.py`, Python |
| D | `lantern behave`, kind `ended-midway`: the change request is held at its first database write on one copy of the app, the sign-in is ended on a second copy, then the first goes on; the change must not be made. `--init` writes it where the app has a sign-out | `lantern/behave.py`, `lantern/behave_init.py` |

A, B and C are heuristics (`tool_confidence: LOW`, ranked medium) that say "check". D rests on what happened in a
running app.

## What had to hold, written down before the first run

From the design (a Claude Doc, 2026-11-18), before any check was run on the project:

| Step | What must hold | Result |
|---|---|---|
| Tests for each check | at least 5 dangerous examples, each beside safe twins; every twin stays quiet | A: 7 dangerous, 11 twins and look-alikes, and one in test code. B: 5 dangerous (4 of them added after the first count found only 1), each with a twin and a look-alike, and 6 more twins. C: 5 dangerous, 7 twins. All pass (`tests/test_self_proof.py`, `tests/test_ended_midway.py`) |
| The same 31 folders as #208, before and after | no finding gone; every new finding read by hand | 0 gone, 6 new, 0 ranked otherwise; all 6 read (below) |
| The project | A, B and C each name the other tool's findings 11, 4 and 10, or the reason is written | all three named (below) |
| Held-out benchmark | no new false alarm, or each is named | 626 findings before and 626 after, none new, none gone, none ranked otherwise |
| Behaviour test D | the benchmark app gets a planted version; the safe app holds and the planted one is caught | 34 versions, 34 as written down: the safe app holds all 84 cases, `note-after-removal` breaks `removed-midway` with `lived-on` and nothing else |
| Lantern's own check | 0 critical, high and medium; checks green; sealed box Passes | 0 / 0 / 0, 89 low, readiness 98 (A); the checks and the box are on the pull request |

One thing of the design was changed while it was built: the design called "the check also asks for a record the
trusted side writes" a safe twin of B, and the first version of B named it anyway. B now stays quiet where a list
whose name says it is the trusted side's (a controller, a supervisor, a server) names that record, and the twin
holds. It still cannot see who writes a record that no list names; it then names the record in the finding.

## Measured

31 folders: the 7 projects of `bench/run_bench.py`, 5 public web starters, the 15 sample apps, Lantern's gateway,
website and engine, and the project. Each was checked with main (6caf09f) and with this change, offline, with no kept
work (`LANTERN_CACHE=off`), with gitleaks 8.30.1 on PATH.

| | Before | After |
|---|---|---|
| Findings in all 31 folders | 16,481 | 16,487 |
| Findings gone | | 0 |
| Findings new | | 6 |
| Findings ranked otherwise | | 0 |

(The total is not #208's 16,366: Lantern's own engine folder grew with this change's tests, and its findings with it.)

The 6 new findings are all on the project. Read by hand:

- **A, 1 finding, real, the other tool's finding 11.** A withdrawal is set to settled from a provider's transaction
  id that the caller sends; nothing asks the provider.
- **C, 1 finding, real, the other tool's finding 10.** The check of the session's epoch holds the sign-in lock and
  returns; the request handler then makes one of five changes (a withdrawal confirmed among them) with the lock let
  go, and a method that rotates the token sets the same fields under that lock.
- **B, 4 findings, one root, the other tool's finding 4.** The list of record kinds the runner may append holds the
  records of a request sent, a response captured and a runtime observation, and four functions named for checking
  ask for two or more of them. One of them is the function the controller itself calls on the transport's records:
  that one is the other tool's finding 4. The other three are checks of the same records that call themselves
  independent; they share the root (fix the list, or have the controller write what it saw, and all four go), and
  where in the program they run was not settled by reading. Counted as 1 real problem named 4 times.

The first runs on the project showed three false alarms or misses, each fixed after a test that failed first:
a helper named for writing an audit line kept A quiet; `fetchone` was read as a look-up with the provider; and a flag
inside a dictionary of a document generator (`approved: True`) was read as a state set to done.

The held-out benchmark (apps no rule was tuned on, offline): 626 findings before and after, the same in every app.
No new false alarm. None of its apps holds these shapes, so it measures quiet, not catches.

Behaviour (`bench/behaviour/results.md`): 34 versions, 34 as written down. The first plan written from the code
(`bench/behaviour/first_plan_results.md`): 34 versions, 34 as written down; it catches 8 of the 33 planted problems, as before. The benchmark app has no sign-out, so `--init` writes no `ended-midway` case for it, and the new planted version needs the plan a person wrote.

## What is not claimed

- A precision. Three true cases in one project are too few; each check stays a heuristic until more are measured.
- That A sees a provider check made in a helper with a neutral name, or a proof sent under a name with no proof word
  (missed, quiet). A value handed to any call that is not a store's write counts as asked (quiet, possibly wrong).
- That B knows who writes a record. It reads list names and text constants; a writer list kept in another shape (a
  database table, a configuration file) is not read.
- That C sees a lock taken with `acquire()`, a check in a function of the module, or a check whose answer is kept
  under a name and asked later. It reads one class.
- That D runs anywhere `lantern behave` does not: a Python ASGI app with SQLite, on Linux or macOS. A change that
  writes nothing to the database cannot be held half-way and is "not run".
