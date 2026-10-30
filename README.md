# Lantern

**See every path your code takes, from the button to the database.** Lantern maps a full-stack app
(Python and TypeScript/JavaScript), links the frontend's API calls to the backend routes that serve
them, explains each function three ways, and audits it with security checks ranked by whether a user
can actually reach the problem.

> Working title. Built from the product spec in [`docs/`](docs/Lantern_Product_Spec_v0.2.pdf). Status: v0.1, the local
> product: map, Three-Lens explanations with your own key, security audit, readiness grade, and Evidence Report, all in a
> local app. Cloud mode and device pairing are not built yet.

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

## Run it (one command)

You need Python 3.11 or newer. Then:

```bash
pip install "lantern[scan] @ git+https://github.com/LittleHenderson/Lantern"
lantern serve path/to/your/app          # any existing project, new or years old
lantern serve https://github.com/you/your-app   # or a GitHub link: cloned into ~/.lantern/repos, then analyzed
```

Your browser opens Lantern. The app is analyzed on first open (a few seconds), and from there you can:

* **Projects**: add more folders (type a path, browse, or paste a GitHub link), re-analyze, see each project's grade
  and open findings.
* **Atlas**: pick a page or API route and follow its path, through clicks and HTTP calls, down to the database.
  Click any function for what it does; "Explain with …" asks your model for the three lenses.
* **Findings**: security problems ranked by severity and by whether a user can reach them. "Accept risk…" records a
  written reason instead of hiding the finding.
* **Readiness**: a 0–100 grade across ten areas with what to fix first, a deployment recommendation, and starter files
  (Dockerfile, CI workflow, `.env.example`, SECURITY.md) you can write with one click. Lantern never overwrites a file.
* **Evidence Report**: a commit-pinned summary for a reviewer, with a "Save as PDF" button.
* **Settings**: choose a model (Anthropic, OpenAI, OpenRouter, Mistral, Gemini, DeepSeek, or a local Ollama / LM Studio model) and
  paste your key. Keys stay in memory unless you tick "remember". Lantern says plainly when code would leave your
  computer; local models keep everything on it.

Lantern only reads your code; it never runs it (unless you ask for `--trace` on the command line). The app listens on
127.0.0.1 only and needs the one-time link it prints. It installs as an app from the browser (PWA) and keeps
recently opened reports available offline.

No key yet? Try the full flow with the offline demo model: `python tools/fake_model.py 8799`, then in Settings pick
`openai-compatible`, model `demo`, base URL `http://127.0.0.1:8799/v1`, and open `tests/fixtures/shop`.

From a clone instead: `git clone https://github.com/LittleHenderson/Lantern && cd Lantern && pip install -e ".[scan,dev]"`.

## Learn by fixing a starter app

New to Lantern, or to security? Open the **Learn** tab in the app (or run `lantern learn`). Each starter is a small,
working app written the way an AI assistant often writes a first draft, with real problems in it. Lantern creates it
in a folder, analyzes it, and a **Guide** walks you through every feature, step by step. Each step has a "Show me"
button for the part of Lantern it teaches, a prompt you can paste into your AI assistant, and the fixed file if
you get stuck. **Check my progress** re-analyzes your copy and ticks a step off only when the problem is really gone.

| Starter | Stack | What you fix and learn |
|---|---|---|
| `notes-api` (start here) | Python, FastAPI, SQLite | MD5 passwords (critical: reachable + uses input), SQL injection, a shell call nobody reaches yet (reachability), hard-coded key, vulnerable pins (pip-audit), runtime tracing, explanations |
| `todo-next` | TypeScript, Next.js, Supabase | a DELETE route with no login, the service-role key in `NEXT_PUBLIC_`, a table without row-level security, token in localStorage, an old Next.js (npm audit), security headers |
| `recipe-box` | React + Vite and Python FastAPI | one map across two languages, `eval`, raw HTML (XSS), an OpenAI key in the browser, wildcard CORS, SSRF / upload / header protections, accepting a risk with a reason |
| `link-shortener` | Node.js, Express, Postgres | SQL and shell commands built from input, TLS checks off, owner-only delete, rate limiting and helmet, accepting a public route, an old Express (npm audit) |

```bash
lantern learn                         # list the starters
lantern learn notes-api ~/notes-api   # create one and analyze it (the "before" for the Evidence Report)
lantern serve ~/notes-api             # open the Guide tab
lantern learn --check ~/notes-api     # progress in the terminal
lantern learn --show-fix app/db.py    # the fixed version of a file (run inside the app's folder)
```

Every step ends with the Evidence Report listing what you fixed, which is what you hand to an engineer.

## Auditing Lantern

[`docs/audit/`](docs/audit/README.md) is a handoff package for an outside reviewer or another LLM: architecture,
every product claim with how to falsify it, a threat model, a test plan with adversarial cases, and a ready-to-paste
auditor prompt. `bash tools/audit.sh` runs every automated check in one go.

## Command line

Everything in the app also works from the terminal, for CI and scripts:

```bash
lantern analyze path/to/repo            # graph + bridge + security scan + readiness + report + evidence
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

Providers: `anthropic`, `openai`, `openrouter`, `mistral`, `gemini`, `deepseek` (keys from `<NAME>_API_KEY`),
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
| **Security** | Bandit, known-vulnerable dependencies (pip-audit from lock files, `==` pins and pyproject.toml; `npm audit` from package-lock.json), secret detection across Python and frontend files, plus full-stack checks: secrets in browser-exposed env vars (`NEXT_PUBLIC_`, `VITE_`, …), committed Supabase service-role keys, Supabase tables without row-level security, open Firebase rules, wildcard CORS, data-changing routes the UI calls with no login check, and JS code patterns (`eval`, raw HTML, shell/SQL built from strings, TLS off). Every finding is ranked by severity and reachability and shows the path from the page that triggers it; critical also needs the flagged line to use a parameter or request data. A "Protections to add" list (rate limiting, security headers, SSRF allow-lists, slow password hashing, login checks, upload limits) appears only where the code gives a reason, with the evidence. Dependency checks are the only network calls `analyze` makes; `--offline` skips them. |

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
