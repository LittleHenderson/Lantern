# Lantern

**See every path your code takes, from the button to the database.** Lantern maps a full-stack app
(Python and TypeScript/JavaScript), links the frontend's API calls to the backend routes that serve
them, explains each function three ways, and audits it with security checks ranked by whether a user
can actually reach the problem.

> Working title. Built from the product spec in [`docs/`](docs/Lantern_Product_Spec_v0.2.pdf). Status: Phase 0 spike plus the
> full-stack layer (v0.1). No PWA or cloud mode yet.

```
/admin page → BackupButton ─on click→ start → runBackup ─HTTP POST /backup→ backup() → subprocess(shell=True)   CRITICAL
```

That's a real path from the sample app in `tests/fixtures/shop`: a React button whose click ends up in a
shell command on the Python server. Lantern finds it with deterministic analysis and shows it as one chain.

## The core idea

**Facts come from tools; words come from models.** The call graph, the frontend-to-backend links, the
security findings, and the reachability paths are computed by parsers and scanners, so they're
repeatable. A model of your choosing only explains them, and every plain-English phrase it writes must
anchor to a real symbol, line, or term in your code, or the explanation is rejected.

## Quick start

```bash
pip install -e ".[scan,dev]"            # Python 3.11+

lantern analyze path/to/repo            # graph + bridge + security scan + report
open path/to/repo/.lantern/report.html  # self-contained, works offline and on a phone
```

Grade how ready it is to ship (0–100 across ten categories, every point with a reason), and get
starter files generated for what's missing:

```bash
lantern starter path/to/repo                     # preview Dockerfile, CI workflow, .env.example, SECURITY.md, /health
lantern starter path/to/repo --write Dockerfile  # write one (never overwrites)
lantern accept path/to/repo FINDING_ID --reason "why this risk is acceptable"   # recorded in lantern-accepted.json
lantern analyze path/to/repo --fail-on high      # exit 1 in CI if an open high or critical finding remains
```

Prove it to a reviewer: every `analyze` also writes `.lantern/evidence.html`, a short Evidence Report
pinned to the git commit, with the readiness scorecard, open/fixed/accepted findings, tool and model
provenance, a required Limits section, and a results digest anyone can check:

```bash
lantern verify path/to/repo --report evidence.html   # re-runs the analysis on this commit, compares digests
```

Attach your own walkthroughs of key flows by writing `lantern-narratives.md` at the repo root.
`.lantern/badge.svg` is a README badge with the score.

Record what actually runs (Python): `lantern analyze path/to/repo --trace -- python -m pytest -q`

Add Three-Lens explanations with your own key or a local model:

```bash
lantern explain path/to/repo --estimate                          # token estimate, no calls
export ANTHROPIC_API_KEY=...
lantern explain path/to/repo --model anthropic/<model-name>
lantern explain path/to/repo --model ollama/<model-name>          # local, nothing leaves your machine
```

Providers: `anthropic`, `openai`, `openrouter`, `mistral`, `gemini` (keys from `<NAME>_API_KEY`),
`ollama`, `lmstudio`, and any `openai-compatible` endpoint (`--base-url`). Explanations are cached by a
hash of each function's code.

Try it without a key: `python examples/make_demo.py demo-out` builds the report for the sample
full-stack app with hand-written explanations that pass the same validator.

## What it understands

| Layer | Coverage |
|---|---|
| **Python** | Scopes, imports (including `backend/app` subproject roots), classes and MRO, `self`/`super()`, overrides, type hints, return types, properties, `with`, decorator factories, pytest fixtures, FastAPI `Depends()`/`Annotated`, router prefixes. Entry points: FastAPI/Flask routes, Click/Typer commands, `__main__`, console scripts. |
| **TypeScript / JavaScript** | ES modules, `tsconfig` path aliases (`@/…`), barrel re-exports (`export *`), classes and `this`, React components and what they render, event handlers (`onClick`), callbacks passed as props. Entry points: Next.js pages and route handlers (app and pages router), TanStack Router and React Router routes, SPA mounts, Express/Hono/Fastify routes. |
| **The bridge** | `fetch`, axios, and generated API clients matched to backend routes by method and path, including global prefixes like `/api/v1` added elsewhere. External services and calls with no matching route are shown as such. |
| **Security** | Bandit, pip-audit, secret detection across Python and frontend files, plus full-stack checks: secrets in browser-exposed env vars (`NEXT_PUBLIC_`, `VITE_`, …), committed Supabase service-role keys, Supabase tables without row-level security, open Firebase rules, wildcard CORS, data-changing routes the UI calls with no login check, and JS code patterns (`eval`, raw HTML, shell/SQL built from strings, TLS off). Every finding is ranked by severity and reachability and shows the path from the page that triggers it. |

## Measured accuracy

`python bench/run_bench.py WORKDIR`. Full method and tables: [`bench/README.md`](bench/README.md).

**Python call graph** (each repo's test suite runs under the tracer and is compared to the static graph):

| Repo | Lines | Graph time | Confirmed edges correct* | Likely edges correct* | Recall |
|---|---:|---:|---:|---:|---:|
| click 8.1.8 | 17.9k | 0.4 s | 96.7% | 90.4% | 75.4% |
| flask (main) | 18.4k | 0.5 s | 95.5% | 97.0% | 57.0% |
| rich 13.9.4 | 39.5k | 1.2 s | 96.6% | 98.1% | 70.9% |

\*Lower bound: tests don't run every branch.

**Frontend → backend bridge:**

| Repo | Stack | Pages / routes found | Calls linked | Verified |
|---|---|---:|---:|---|
| full-stack-fastapi-template | React + FastAPI | 9 / 23 | 23 of 23 to its API | all 23 by name (`ItemsService.updateItem` → `update_item`) |
| taxonomy | Next.js | 14 / 8 | 5 of 5 to its API (+1 external) | all 5 by hand against every `fetch` in the repo |

## Privacy

Everything runs locally. `report.html` embeds function source by default; use
`lantern analyze --privacy structure` to leave it out. With a cloud model, the source of each explained
function is sent to that provider; use a local model to keep it on your machine.

## Status and limits

No PWA, cloud mode, or deployment-readiness score yet. Runtime tracing is Python-only. Very dynamic
code (`getattr`, plugin registries, framework dispatch) lowers recall; the report counts what it
couldn't resolve. Full-stack security checks are pattern- and graph-based; the "no login check" rule
is marked as a heuristic in the report. See [`CLAUDE.md`](CLAUDE.md) for architecture and the backlog.
