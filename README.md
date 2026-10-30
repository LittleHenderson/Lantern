# Lantern

**See every path your code takes, from the button to the database.** Lantern maps the call graph of a
Python and/or TypeScript/JavaScript repository, links frontend HTTP calls to the backend routes that
answer them, explains each function three ways, audits it with real security scanners, and ranks each
finding by whether an entry point (a page, a web route, a CLI command, `main`) can actually reach it.

> Working title. This is the Phase 0 spike from the product spec in [`docs/`](docs/). It proves the
> engine and the explanation format before the PWA, the cloud mode, and the Rust/C++ frontends are built.

## The core idea

**Facts come from tools; words come from models.** The call graph, the security findings, and the
reachability paths are computed by parsers and scanners, so they're repeatable. A model of your
choosing only explains them, and every plain-English phrase it writes must anchor to a real symbol,
line, or term in your code, or the explanation is rejected.

## Quick start

```bash
pip install -e ".[scan,dev]"            # Python 3.11+

lantern analyze path/to/repo            # graph + security scan + report
open path/to/repo/.lantern/report.html  # self-contained, works offline
```

Record what actually runs (marks edges as "seen running"):

```bash
lantern analyze path/to/repo --trace -- python -m pytest -q
# or after analyze:
lantern trace path/to/repo -- python app.py
```

Add Three-Lens explanations with your own key or a local model:

```bash
lantern explain path/to/repo --estimate                          # token estimate, no calls
export ANTHROPIC_API_KEY=...
lantern explain path/to/repo --model anthropic/<model-name>
lantern explain path/to/repo --model ollama/<model-name>          # local, nothing leaves your machine
lantern explain path/to/repo --model openai-compatible/<model> --base-url http://localhost:8000/v1
```

Providers: `anthropic`, `openai`, `openrouter`, `mistral`, `gemini` (keys from `<NAME>_API_KEY`),
`ollama`, `lmstudio`, and any `openai-compatible` endpoint. Explanations are cached by a hash of each
function's code, so unchanged functions are never paid for twice.

Try it without a key: `python examples/make_demo.py demo-out` builds a report for the small
`tests/fixtures/shop` app using hand-written explanations that pass the same validator.

## What you get

| | |
|---|---|
| **Map** | Every page, web route, CLI command, and program start, with the call path beneath it as an expandable tree (phone-friendly) or a flowchart. Line style shows confidence: seen running, confirmed, likely, possible. |
| **Three lenses** | 1 · Technical, 2 · Everyday (no jargon, one example, one analogy from a single metaphor world per repo), 3 · Mapped (each plain phrase paired 1:1 with the technical term, symbol, or line it stands for). |
| **Findings** | Bandit, pip-audit (requirements files), and secret detection (gitleaks if installed, built-in patterns otherwise). Ranked critical/high/medium/low by severity *and* reachability, with the exact path from the entry point. Test-code findings are counted separately. |

## Full stack: one path through the whole app

Most AI-built apps are a React/Next.js front end talking to an API. Lantern parses both halves and
joins them where they meet, so a path reads straight through:

```
ItemActionsMenu → EditItem → ItemsService.updateItem → [PUT /api/v1/items/{}] → update_item
  → get_current_user → Session.commit
```

* **TS/JS engine** (`lantern/ts_frontend.py`): functions, arrow functions, classes and methods, ES
  imports and re-exports, tsconfig `paths` and Vite `@` aliases, JSX `<Component />` renders,
  `this.method()`, `Class.static()`, and functions passed by name (`onClick={save}`, callbacks) as
  "possible" edges.
* **Entry points:** Next.js pages and route handlers (app and pages routers), TanStack/React Router
  file routes, Express-style `app.get("/path", handler)` servers, and app starts (`createRoot`, `.listen()`).
* **Bridge** (`lantern/bridge.py`): every `fetch`, axios-style, or generated-client call is matched to a
  backend route by method and path. Exact matches are "confirmed"; a match under a shared prefix the
  backend sets at runtime (like `/api/v1`) is "likely"; ties become "possible" links to each candidate.
  Calls to third-party APIs show up with their host.
* **Frontend secrets:** the secret scan reads JS/TS/HTML files and `.env` files, and flags server-only
  secrets referenced through browser-exposed prefixes (`VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, ...).

On the FastAPI full-stack template (2.9k lines Python, 10k lines TypeScript), all 23 frontend API calls
link to the right backend route.

## How the engine resolves Python calls

Tree-sitter parses every file; a resolver binds names through scopes, imports (including subproject
roots like `backend/app`), classes and their MRO. It understands `self`/`cls`, `super()`, overrides
(as "possible"), constructors, parameter type hints, function return types, `with` blocks, properties,
decorator factories (`@click.command()`), pytest fixtures, and FastAPI `Depends()` including
`Annotated` aliases. Calls it can't trace are counted as unresolved, never guessed silently.

## Measured accuracy (Phase 0)

Run with `python bench/run_bench.py WORKDIR`. Each repo's own test suite runs under the tracer, and the
static graph is compared to what actually executed. Full method and numbers: [`bench/README.md`](bench/README.md).

| Repo | Lines | Graph time | Confirmed edges correct* | Likely edges correct* | Possible edges correct* | Recall |
|---|---:|---:|---:|---:|---:|---:|
| click 8.1.8 | 17.9k | 0.33 s | 96.7% | 90.4% | 61.0% | 75.4% |
| flask (main) | 18.4k | 0.32 s | 95.5% | 97.0% | 48.7% | 57.0% |
| rich 13.9.4 | 39.5k | 0.75 s | 96.6% | 98.1% | 57.7% | 70.9% |

\*Lower bound: tests don't run every branch, so some correct edges are never observed.

## Privacy

Everything runs locally. `report.html` embeds function source by default; use
`lantern analyze --privacy structure` to leave source out. If you use a cloud model, the source of each
explained function is sent to that provider. Use a local model to keep it on your machine.

## Status and limits

Phase 0 spike. Python only; no PWA, cloud mode, or deployment-readiness score yet. Very dynamic code
(`getattr`, plugin registries, monkey-patching) lowers recall; the report says how many calls were
unresolved. See [`CLAUDE.md`](CLAUDE.md) for architecture and the Phase 1 backlog.
