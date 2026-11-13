# Held-out benchmark

Frozen on 2026-11-09 against Lantern `bc7cf10` (main), before any change of the "stronger full-stack release reviewer"
directive was written. Its job is to show whether Lantern is getting better at the things the directive names, on
code it was never tuned on, with the same definitions before and after.

```bash
python bench/heldout/run_heldout.py /tmp/heldout                 # fetch the pinned apps, analyze, score, write results
python bench/heldout/run_heldout.py /tmp/heldout --offline       # without dependency audits (no network)
python bench/heldout/run_heldout.py /tmp/heldout --only dvna --only express-unsafe
```

Every run is isolated (`tools/netguard/`): a temporary home folder, none of your keys or saved sign-ins, real model
providers off, and only the addresses the run needs can be reached: github.com, where the public apps are fetched
from, and, without `--offline`, the three the dependency audit asks. Anything else is refused, listed at the end, and
fails the run. Each analysis is its own Python program in isolated mode, started through the guard so the guard is in
it too.

`baseline.json` / `baseline.md` here are the frozen "before". A later run compares with them only when its
`definition_sha256` is the same (the hash covers `cases.json` and every file under `apps/`). Changing a case, an app or a
rule makes a new definition; the old baseline then no longer applies and must be re-run on the old engine.

## What is in the set

| App | Kind | Stack | Documented by | Expectations |
|---|---|---|---|---:|
| [Damn Vulnerable RESTaurant](https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game) `d32d099` | vulnerable | FastAPI | README, API Security Champion series, code | 7 |
| [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) `c5cb68a` | vulnerable | Express + MongoDB | tutorial; commented-out "Fix for A#" blocks in the code | 10 |
| [DVNA](https://github.com/appsecco/dvna) `9ba473a` | vulnerable | Express + Sequelize | `docs/solution/*.md`, one guide per category naming the file | 14 |
| [Goof](https://github.com/snyk-labs/nodejs-goof) `add14ba` | vulnerable | Express + MongoDB | README "Vulnerabilities in code", `exploits/` | 10 |
| [PyGoat](https://github.com/adeyosemanputra/pygoat) `2aa4cc1` | vulnerable | Django + Flask labs | lab names and docstrings | 20 |
| [full-stack-fastapi-template](https://github.com/fastapi/full-stack-fastapi-template) `aabb901` | clean | FastAPI + React | the official template | 0 (every medium+ finding is labelled in `labels.json`) |
| [node-express-boilerplate](https://github.com/hagopj13/node-express-boilerplate) `179ae84` | clean | Express + Mongoose | a widely used production boilerplate | 0 (labelled) |
| [taxonomy](https://github.com/shadcn-ui/taxonomy) `298a885` | clean | Next.js 13 + Prisma + Stripe | shadcn's reference app | 0 (labelled) |
| `apps/review-unsafe` / `review-safe` | pair | FastAPI | the five regression examples of the independent review of 2026-11-09 and their safe twins | 5 + 5 |
| `apps/flows-unsafe` / `flows-safe` | pair | FastAPI + React | the directive's section 4 flows (request → route → helper → service → query; address → helper → outgoing request; archive → extraction → write; signed-in user → another user's data; misleading `validate`; HTML escaping before SQL; a rate-limit library installed but unused; a guard after the action) and their guarded twins | 9 + 9 |
| `apps/express-unsafe` / `express-safe` | pair | Express | the same flows in Express form: `module.exports` handlers wired in a router, a route that forgot its sign-in | 9 + 7 |

Public apps are fetched at the pinned commit as untrusted data: nothing in them is ever run. Local apps are stored as
`*.tmpl` files (dot-files as `dot.<name>`), exactly like `lantern/starters/`, so Lantern's own audit never reads the
planted problems; the runner writes them out with their real names before analysis.

Nothing in the set was chosen or shaped by a fix: the public apps document their own problems; the local flows were
written from the directive's list before the engine changed; the review examples were copied from the independent
review. The set is not touched again except to add apps, which makes a new definition hash.

## Measurements (definitions, fixed)

* **Found** · a finding outside test code sits in the expectation's file within `window` lines (default 2) of the
  anchor's line, whatever its rule id. **Found at medium or above** · that finding is critical, high or medium (or at
  least `min_rank` when the expectation names one). **Found only as low** · found, but low: in a release decision that
  is as good as missed. An `authz` expectation counts only rule ids that look like an authorization rule
  (`LW-AUTH`, `AUTH`, `ACCESS`, `IDOR`, `BOLA`, `PERM`): a shell or SQL finding on the same lines is another problem.
* **False alarm** · a safe twin's anchor carries a medium-or-above finding. **False link** · a safe twin shows a call
  edge that does not exist in the code. On the clean public apps every medium-or-above finding outside tests is
  listed with its hand label from `labels.json` (`false alarm`, `real`, `intended`, or unlabelled).
* **Security path** · a found problem whose finding has a `reachable` entry (a route, page or command reaches the line).
  Two expectations (`fl-sql-chain-path`, `ex-sql-path`) ask for this explicitly, frontend fetch → route → query.
* **Call sites** · `Graph.call_sites()` from `graph.json`: resolved, likely (inferred), possible, name-only, external,
  built-in, unresolved, one denominator per app, plus unresolved reasons. A change in how calls are counted is a new
  definition, not an improvement; `call_sites()` is unchanged since Lantern 0.10 (#148, #150).
* **Release decision** · `readiness.json` → `release.decision` once the release gate exists (Blocked / Incomplete /
  Passed); until then the badge rule: Passed when no critical or high finding sits outside test code. **Vulnerable
  apps given a green release** · vulnerable apps whose decision is Passed.
* **Scanners** · each tool's recorded state per app, printed in every result, so a scanner that failed or did not run
  is never hidden behind the numbers.

Dependency expectations (`dvna-deps`, `goof-deps`) depend on the advisory databases of the day and on the network;
they are reported but compared with that in mind, and `--offline` runs skip them.

## Targets (set on 2026-11-09, before any new engine was evaluated)

Baseline numbers are in `baseline.md`. Targets for the end of the directive's stages 2–6, on this exact definition:

| Measure | Baseline (bc7cf10) | Target |
|---|---:|---:|
| Documented problems found at medium or above | 28 of 79 (21 of the 61 public, 7 of the 18 local); 2 more only as low; 49 missed | at least 60% of the 61 public expectations, and every `sql`, `shell`, `eval`, `deserialize`, `xxe` one |
| False alarms on safe-twin anchors | 3 of 17 (two review twins where an inner function sets a fixed string, one fixed ORDER BY clause passed between functions) | no more than at baseline, and none on `sql`/`shell` anchors whose value is a fixed string |
| Vulnerable apps given a green release | 2 of 8 (dvna, express-unsafe) | 0 of 8 (5 public + 3 local) |
| Clean apps not given a green release | 3 of 6 (taxonomy, review-safe, flows-safe), all through false alarms | 0 of 6, with every remaining medium+ finding labelled |
| Found problems with a mapped path | 21 of 30 | at least 70% |
| Resolution checks (`edge`, `linked`) | 1 of 3 (the `module.exports` handlers of both Express twins are not linked) | 4 of 4 |
| Protection checks | 2 of 3 (slowapi installed but unused is called "in place") | 3 of 3 |
| Unresolved share of call sites on the four Express apps | nodegoat 233/246, dvna 202/206, goof 154/160, express-boilerplate 397/506 | under 50% on each |

A target missed is reported as missed, with where, and the work continues; it is never met by changing a definition.

Correction (2026-11-11, no number of `baseline.json` changed): the first row's parenthesis read "27 of the 61
public, 1 of the 18 local" until this date. `baseline.json` holds 21 found of the 61 public and 7 found of the 18
local (28 in all, as the row always said); the split was written down wrong. The target is unchanged: 60% of 61 is
37 public problems.

## After point 4 of the directive (measured 2026-11-11)

Point 4 ("trace actual security problems across the whole app": a value followed across functions and files, a
check that counts for what its code proves, who may reach a record) was measured on this definition five times
while it was built, offline each time, as was the "before" of the same day. `after_point4.json` / `.md` is the fifth
and last of them; `after_point4_audits.json` / `.md` is the same engine with the dependency audits on, as the frozen
baseline ran. The third, the fourth and the fifth gave the same findings on every app of the set (with the audits
on: 55 of 79 each time); their result files differ in the engine's commit and the time only.

| Measure | Baseline, with audits (bc7cf10) | Before point 4 (eb3666e) | First (ae08c23) | Second (744b01a) | Third (d8a7980) | Fourth (1c7f819) and fifth (3e4687c) | Fourth and fifth, with audits | Target | Result |
|---|---|---|---|---|---|---|---|---|---|
| Documented problems found at medium or above, of 79 | 28 | 28 | 44 | 50 | 54 | 54 | 55 | | |
| of the 61 public | 21 | 20 | 32 | 37 | 39 | 39 | 40 | at least 37 | met |
| of the 18 local | 7 | 8 | 12 | 13 | 15 | 15 | 15 | | |
| of the 26 `sql`, `shell`, `eval`, `deserialize`, `xxe` ones | 19 | 20 | 25 | 25 | 25 | 25 | 25 | 26 | missed: one `eval` (`pg-ssti`) |
| Found only as low | 2 | 1 | 1 | 1 | 1 | 1 | 1 | | |
| Missed | 49 | 50 | 34 | 28 | 24 | 24 | 23 | | |
| False alarms on the 17 safe-twin anchors | 3 | 3 | 3 | 2 | 0 | 0 | 0 | no more than 3, none on a fixed `sql`/`shell` value | met |
| Vulnerable apps given a green release, of 8 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | met |
| Clean apps not given a green release, of 6 | 3 | 3 | 3 | 3 | 2 | 2 | 2 | 0 | missed: fastapi-template, taxonomy |
| Medium+ findings on clean apps (labelled false alarm) | 11 (9) | 11 (9) | 13 (6) | 12 (6) | 10 (7) | 10 (7) | 10 (7) | every one labelled | met: 7 false alarm, 3 intended, none unlabelled |
| Found problems with a mapped path | 21 of 30 | 25 of 29 | 40 of 45 | 43 of 51 | 46 of 55 | 46 of 55 | 46 of 56 | at least 70% | met |
| Resolution checks, of 3 | 1 | 3 | 3 | 3 | 3 | 3 | 3 | every one | met (the row above says "4 of 4": the definition holds 3) |
| Protection checks, of 3 | 2 | 2 | 3 | 3 | 3 | 3 | 3 | 3 | met |
| Unresolved call sites: nodegoat, dvna, goof, express-boilerplate | 233/246, 202/206, 154/160, 397/506 | 116/330, 66/240, 36/184, 72/956 | the same | the same | the same | the same | the same | under half on each | met (since point 3) |

By class, found at medium or above before point 4 and at the third measurement, of the expected: `auth` 3 and 3 of
5, `authz` 0 and 3 of 11, `config` 0 and 0 of 4 (1 only as low), `csrf` 1 and 1 of 2, `dependency` 0 and 0 of 2 (not
checked offline; 1 with the audits on), `deserialize` 3 and 4 of 4, `eval` 2 and 3 of 4, `exposure` 0 and 1 of 2,
`nosql` 0 and 1 of 2, `path` 0 and 2 of 4, `pollution` 0 and 1 of 1, `redirect` 0 and 3 of 4, `secret` 3 and 7 of 7,
`shell` 6 and 6 of 6, `sql` 8 and 10 of 10, `ssrf` 1 and 3 of 3, `xss` 0 and 4 of 6, `xxe` 1 and 2 of 2.

How the set was used. The code of the apps and the anchors in `cases.json` were not read while the engine was
written. After the first and after the second measurement the misses were read by expectation id, class, rule id,
rank and line number only, and every rule that followed was written against examples of its own (the tests named in
the changelog), none of them copied from the set. So the third number was preceded by two looks at which
expectations were missed, and it is not the number a first look at an unseen set would give; the first measurement
(44 of 79) is the one no look preceded. After the third measurement the two findings on clean apps that had no
label were read in the code and labelled (in fastapi-template the route and the helper that makes its page, in
express-safe the route, its handler, its login check and the twin's entry in `cases.json`).

The engine did change once more after that, and not from this set. The ten large public apps of
`tools/large_apps.py`, analysed before and after point 4 for time and memory, showed two false alarms of the new
rules (a browser script that sends the visitor to the page's own site, and a name like `SESSION_KEY` that only
names where something is kept); both were fixed against examples of their own (`bench/large_apps_results.md`,
the changelog). The fourth measurement is that engine. It was preceded by the two looks above and by the reading
for the two labels; nothing in the last change was written for an app of this set, and no number moved.

It changed a last time after the fourth, again not from this set. Small examples written for the stage report
showed that a record class a Python app loads with an import written from the top (`from app.models import Note`,
the commonest way) was read as a library's, so who may reach the record was not asked (the changelog: "How a
Python app loads its own files does not matter"). The fifth measurement is the engine with that corrected
(3e4687c). Every app of the set lists exactly the findings it listed at the fourth, offline (627 findings in all)
and with the audits on (1,197): the correction found nothing new here and raised no new false alarm.

Where it still misses (24, and 1 found only as low):

* `authz`, 8 of 11: `dvra-bola-order`, `dvra-bfla-role`, `ng-idor`, `ng-bfla`, `dvna-authz-admin`, `pg-admin-cookie`,
  `fl-authz-late-guard`, `ex-authz-delete`. Who may reach what is still the weakest class.
* `config`, 3 of 4 and the fourth only as low: `ng-cookie`, `dvna-cookie`, `ex-cookie`, `pg-django-debug`. Point 4
  added no rule for cookie and debug settings.
* `auth` 2 (`dvra-pin`, `dvna-reset-token`), `path` 2 (`goof-zipslip`, `goof-layout`), `xss` 2 (`ng-xss`, `pg-xss`),
  `csrf` 1 (`ng-csrf`), `exposure` 1 (`dvra-debug`), `nosql` 1 (`ng-nosql`), `redirect` 1 (`goof-redirect`).
* `eval` 1, `pg-ssti`: Lantern reports request text run as a template in the same file 13 lines above the documented
  line (`LT-EVAL`, medium, line 44, for a value the request brings at line 95) and nothing within two lines of the
  documented line 57. By the definition that is missed.
* `dependency` 2 offline. With the audits on `goof-deps` is found; `dvna-deps` is not (npm's audit is recorded as
  skipped for that app).

The two clean apps still refused a green release, both through a false alarm at high: fastapi-template through a
finding of the new engine (`LT-XSS` in `login.py`: the path it shows is real, a jinja2 `Template` that escapes
nothing, but only a superuser reaches the route and the page is made only when an account with exactly that e-mail
address exists, which Lantern does not see), taxonomy through `LA-WALLET-DRAIN` on a Stripe webhook, labelled at the
baseline. One finding is new on a safe twin: `LT-AUTHZ-OWNER` (medium, labelled intended) on the handler behind
express-safe's `DELETE /items/:id`, which asks for a login and compares no owner because the twin's items have none.
It stands in `core/handlers.js`; the safe-twin anchor is the route's line in `routes/index.js`, so by the definition
above it is not a false alarm on that anchor. Read strictly, as "a finding on a route this set calls safe", it would
be 1 of 17.

## Point 6 of the directive: targets (written down 2026-11-12 05:33 UTC, before the engine was run on the set)

Point 6 ("fix severity and make 100 mean the required work passed") adds a release decision per app (Blocked,
Incomplete, Passed) that does not depend on the score, and the runner now records it beside the score. Two targets
of point 4 were missed and carried into this stage: `pg-ssti`, and the clean apps that were not given a green
release. On the second the owner decided (2026-11-11) what counts: a clean app is refused only when it reads
Blocked; one that reads Incomplete (a required piece of evidence is missing: the tests were not run, a library
check could not be made) is not refused, and is listed with what is missing.

Written before the run, on this exact definition (e6b10d91686f):

| Measure | After point 4 (3e4687c): offline, with audits | Target |
|---|---|---|
| Documented problems found at medium or above, of 79 | 54, 55 | not below 54 offline and 55 with the audits |
| of the 26 `sql`, `shell`, `eval`, `deserialize`, `xxe` ones | 25, 25 | 26: `pg-ssti` found at medium or above where it is documented |
| Found only as low | 1, 1 | no more than 1 |
| False alarms on the 17 safe-twin anchors | 0, 0 | 0 |
| Vulnerable apps that read Passed or score 100, of 8 | (a green release: 0) | 0 |
| Clean apps that read Blocked, of 6 | (not green: 2, fastapi-template and taxonomy) | 0; each one that reads Incomplete listed with what is missing |
| Apps that score 100 while Blocked or Incomplete, of 14 | not recorded | 0 |
| Medium+ findings on clean apps | 10, of which 7 labelled false alarm | every one labelled, and no more than 10 |
| Found problems with a mapped path | 46 of 55, 46 of 56 | at least 70% |
| Resolution checks, protection checks | 3 of 3, 3 of 3 | every one |

What was known when these were written, so the numbers can be read for what they are. Three rules of this stage
were written after a result of this set, each against examples of its own (none copied from the set; the apps'
code was not read): a payment webhook that checks its sender before it spends (`tests/test_webhook_sender.py`,
after taxonomy's false alarm, which this set's labels explain in one sentence), text a request wrote into a file
that is read back and run as a template (`tests/test_stored_file.py`, after the `pg-ssti` miss, known by its line
numbers and its one-line note), and a check made on a whole list at once (`tests/test_list_guard.py`, after two
false alarms on the behaviour benchmark's own safe app, which is not part of this set). So taxonomy and `pg-ssti`
no longer measure those two rules blind. No rule was written for fastapi-template's finding: that a page is made
only when an account with exactly that address exists is not evidence Lantern can read from the code, and a rank
is lowered only on evidence.

## After point 6 of the directive (measured 2026-11-12 UTC)

`after_point6.json` / `.md` (offline) and `after_point6_audits.json` / `.md` (the dependency audits on) are the
engine of point 6 (babe4e6) on this definition, after the targets above were written down. The set was measured
three times: on 4caaeea, the run the targets were read against, and again after each of the two engine commits
that followed (bc571fd: text read back from a file is followed into a larger text and into a helper; babe4e6: a
check written as a loop of its own). Every finding of every app was the same in all three (626 offline, 1,196
with the audits on), so the numbers below are those of the first run and the files are the last run's.

| Measure | After point 4 (3e4687c): offline, with audits | After point 6 (babe4e6): offline, with audits | Target | Result |
|---|---|---|---|---|
| Documented problems found at medium or above, of 79 | 54, 55 | 55, 56 | not below 54 and 55 | met |
| of the 61 public | 39, 40 | 40, 41 | | |
| of the 18 local | 15, 15 | 15, 15 | | |
| of the 26 `sql`, `shell`, `eval`, `deserialize`, `xxe` ones | 25, 25 | 25, 25 | 26 | missed: `pg-ssti` |
| Found only as low | 1, 1 | 0, 0 | no more than 1 | met |
| Missed | 24, 23 | 24, 23 | | |
| False alarms on the 17 safe-twin anchors | 0, 0 | 0, 0 | 0 | met |
| Vulnerable apps that read Passed, of 8 | 0, 0 (a green release, by the rule of that time) | 0, 0 | 0 | met |
| Vulnerable apps that read Blocked, of 8 | not recorded | 8, 8 | | |
| Clean apps that read Blocked, of 6 | (not green: 2, 2) | 1, 1: fastapi-template | 0 | missed |
| Clean apps that read Incomplete, of 6 | not recorded | 5, 5 | each listed with what is missing | listed below |
| Apps that score 100 while Blocked or Incomplete, of 14 | not recorded | 0, 0 (the highest score is 63) | 0 | met |
| Medium+ findings on clean apps | 10: 7 false alarm, 3 intended | 9: 6 false alarm, 3 intended | every one labelled, no more than 10 | met |
| Found problems with a mapped path | 46 of 55, 46 of 56 | 46 of 55, 46 of 56 | at least 70% | met |
| Resolution checks, protection checks | 3 of 3, 3 of 3 | 3 of 3, 3 of 3 | every one | met |

What moved, finding by finding (the same in both runs; no app of the set lost or gained any other finding):

* Seven findings rose by one rank and none fell: four from low to medium (one in dvra, three in pygoat) and three
  from medium to high (one in nodegoat, two in pygoat). Each had been ranked under its tool's severity only
  because Lantern found no path to its line. One of them is a documented problem, `pg-django-debug` (`config`),
  which was found only as low and is now found at medium: **the one more problem found at medium or above is that
  rule, not a new detection.** `pg-django-secret` was found at medium and is found at high.
* One finding is gone: `LA-WALLET-DRAIN` (high) on taxonomy's Stripe webhook, which checks who sent the message
  before it spends. It was one of the two false alarms that kept a clean app from a green release.

By class, found at medium or above after point 4 and after point 6 (offline), of the expected: `auth` 3 and 3 of 5,
`authz` 3 and 3 of 11, `config` 0 and 1 of 4, `csrf` 1 and 1 of 2, `dependency` 0 and 0 of 2 (1 with the audits
on), `deserialize` 4 and 4 of 4, `eval` 3 and 3 of 4, `exposure` 1 and 1 of 2, `nosql` 1 and 1 of 2, `path` 2 and 2
of 4, `pollution` 1 and 1 of 1, `redirect` 3 and 3 of 4, `secret` 7 and 7 of 7, `shell` 6 and 6 of 6, `sql` 10 and
10 of 10, `ssrf` 3 and 3 of 3, `xss` 4 and 4 of 6, `xxe` 2 and 2 of 2. Point 6 added no detection rule for a class
of this set: the 24 misses are the same 24 as after point 4 (listed above), and `pg-django-debug`, found only as low
then, is found at medium.

The two targets missed, with where:

* **`pg-ssti` is still not found where the set documents it.** Lantern lists the problem in that file as `LT-EVAL`
  (medium, a heuristic) at line 44, where what the request sent is written into a file of the templates folder. The
  documented line is 57 with a window of 6 lines, where the saved files are read for a list of posts. By the
  definition that is missed, as after point 4. The rule written after that miss (text written into a file, read
  back and run as a template, `tests/test_stored_file.py`) does not fire in this app: Lantern's own record of that
  file (line numbers and the names of its rule tables only; the code was not read) shows the write at line 44, a
  read of files of the same place at line 56, and no line that runs text as a template; the one page rendered
  from a name the request sends is at line 111. So this app shows the saved file by its name and never reads it
  back to run it, which is what the finding at line 44 already says. A finding at line 57 would say that text is
  run where it is only read, and moving the documented line after the result would be changing the count, so
  neither was done.
* **One clean app reads Blocked: fastapi-template**, through `LT-XSS` (high) at
  `backend/app/api/routes/login.py:121`, labelled a false alarm after point 4: the value does reach the page the
  way Lantern says, but only a superuser reaches the route and the page is made only when an account with
  exactly that address exists. Neither is evidence Lantern reads from the code today, and a rank is lowered only
  on evidence, so the finding stays high and a high finding that is open blocks. A project can settle such a
  finding with `lantern accept ID --reason "..."`, which the decision then names as accepted.

The five clean apps that read Incomplete, each with what is missing (Lantern's own words, with the audits on):

| App | Libraries | Tests |
|---|---|---|
| express-boilerplate | not checked: its versions are in a pnpm, yarn or bun lock file, which Lantern does not read yet | not run in this check |
| taxonomy | not checked: its versions are in a pnpm, yarn or bun lock file, which Lantern does not read yet | the project has no tests |
| review-safe | 2 libraries have no exact version written down | the project has no tests |
| flows-safe | 5 libraries have no exact version written down; 2 are named in a `package.json` with no lock file | the project has no tests |
| express-safe | 3 libraries are named in a `package.json` with no lock file | the project has no tests |

This benchmark never runs an app's own tests, so no app of the set can read Passed here; what the table shows is
that none of the five is held back by a finding. fastapi-template would read Incomplete too without its one high
finding (two scanners could not read one file, its JavaScript libraries are in a lock file Lantern does not read,
and its tests were not run).

## After point 10 of the directive (measured 2026-11-12 23:46 UTC)

Point 10 is about speed and may change no result, so this measurement has no target but one: nothing moves.
`after_point10.json` / `.md` (offline) and `after_point10_audits.json` / `.md` (the dependency audits on, which
now run beside the reading of the code) are the engine of point 10 (3e38b7d) on this definition. Every app's
record in both files is the same as in the point 6 files, entry for entry: the same 626 findings offline and
1,196 with the audits on, 55 and 56 of the 79 expected problems found, 0 false alarms on the safe twins, 0 false
links, the same release decision for each of the 14 apps. Only the label, the engine's commit and the time of the
run differ. No file of the set was read to make the engine faster.

## Files

* `cases.json` · the frozen definition: apps, commits, expectations, rules.
* `apps/` · the local twins, as `.tmpl` files.
* `labels.json` · hand labels for findings on the clean public apps.
* `run_heldout.py` · fetch, analyze, score, write `<out>.json` and `<out>.md`.
* `baseline.json`, `baseline.md` · the frozen before.
* `after_point4.json`, `after_point4.md` · the fifth and last measurement after point 4 (offline, like the before
  of the same day); `after_point4_audits.json`, `.md` · the same engine with the dependency audits on.
* `after_point6.json`, `after_point6.md` · the measurement after point 6 (offline); `after_point6_audits.json`, `.md` · the same
  engine with the dependency audits on.
* `after_point10.json`, `after_point10.md` · the measurement after point 10 (offline); `after_point10_audits.json`,
  `.md` · the same engine with the dependency audits on. The same records as after point 6.
