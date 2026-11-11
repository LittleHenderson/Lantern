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
| Documented problems found at medium or above | 28 of 79 (27 of the 61 public, 1 of the 18 local); 2 more only as low; 49 missed | at least 60% of the 61 public expectations, and every `sql`, `shell`, `eval`, `deserialize`, `xxe` one |
| False alarms on safe-twin anchors | 3 of 17 (two review twins where an inner function sets a fixed string, one fixed ORDER BY clause passed between functions) | no more than at baseline, and none on `sql`/`shell` anchors whose value is a fixed string |
| Vulnerable apps given a green release | 2 of 8 (dvna, express-unsafe) | 0 of 8 (5 public + 3 local) |
| Clean apps not given a green release | 3 of 6 (taxonomy, review-safe, flows-safe), all through false alarms | 0 of 6, with every remaining medium+ finding labelled |
| Found problems with a mapped path | 21 of 30 | at least 70% |
| Resolution checks (`edge`, `linked`) | 1 of 3 (the `module.exports` handlers of both Express twins are not linked) | 4 of 4 |
| Protection checks | 2 of 3 (slowapi installed but unused is called "in place") | 3 of 3 |
| Unresolved share of call sites on the four Express apps | nodegoat 233/246, dvna 202/206, goof 154/160, express-boilerplate 397/506 | under 50% on each |

A target missed is reported as missed, with where, and the work continues; it is never met by changing a definition.

## Files

* `cases.json` · the frozen definition: apps, commits, expectations, rules.
* `apps/` · the local twins, as `.tmpl` files.
* `labels.json` · hand labels for findings on the clean public apps.
* `run_heldout.py` · fetch, analyze, score, write `<out>.json` and `<out>.md`.
* `baseline.json`, `baseline.md` · the frozen before.
