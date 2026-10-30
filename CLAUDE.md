# CLAUDE.md

Context for working on Lantern in Claude Code. The product spec is `docs/Lantern_Product_Spec_v0.2.pdf`.
This repo is Phase 0 plus the full-stack layer: Python and TypeScript/JavaScript engines, the API bridge
between them, scanners, the Three-Lens explainer, and a static HTML report.

**Audience:** AI-assisted ("vibe") coders whose apps are usually full stack, often TypeScript. The
product's job is to make their code understandable and defensible to skeptical engineers.

## Non-negotiable principles (from the spec)

1. **Facts from tools, words from models.** Call edges, HTTP links, findings, and reachability come
   from deterministic code. Models only explain, and never create, dismiss, or close a finding.
2. **Show confidence, never fake certainty.** Every edge has `observed | resolved | inferred | possible`
   plus a `via` saying how it was resolved. A new rule gets a confidence level backed by `bench/`
   numbers: "inferred" (UI: "likely") needs about 90%+ measured precision across repos.
   Unresolvable calls are counted in `graph.unresolved`, not guessed.
3. **Every Lens 3 pair must anchor** to an allowed symbol, a line range inside the unit, or a term found
   in the source or `GLOSSARY`. `explain.validate()` enforces this; don't loosen it to make a model pass.
4. **Lantern must pass its own audit.** `lantern analyze .` should report no critical/high/medium. CI
   enforces it. (It caught two false positives in the web rules during development.)
5. **Heuristic checks say so.** Graph/pattern-based security rules that can misfire set
   `tool_confidence: LOW`; the viewer labels them "heuristic". Protections have three statuses: `add`, `check`
   (an app-wide mechanism exists but the code does not show it covers the routes in question), `in place`.
6. **Everything in the viewer is escaped.** Every value from the data goes through `esc()` (class names through
   `cls()`), and `render()` adds a hash-based Content-Security-Policy so a report opened from disk cannot run
   script planted in its data. CI opens a poisoned report (`tools/poison_report.py`) in Chromium to prove it.

## Commands

```bash
pip install -e ".[scan,dev]"
python -m pytest -q                                   # ~6 s
lantern serve tests/fixtures/shop                     # the app; prints a one-time link
lantern analyze tests/fixtures/shop --out /tmp/shop   # React + FastAPI sample, end to end
lantern analyze tests/fixtures/nextapp --out /tmp/nx  # Next.js + Supabase sample
python examples/make_demo.py /tmp/demo                # report with hand-written explanations, no key
python bench/run_bench.py /tmp/bench                  # clones 7 public repos; ~2 min with tracing
node tools/viewer_smoke.js /tmp/demo/report.html /tmp/shot   # screenshots + JS error check
                                                      # (needs Playwright + Chromium)
```

## Layout

| File | Role |
|---|---|
| `lantern/engine.py` | **Entry point for analysis**: Python frontend → JS/TS frontend → bridge. Use `engine.build_graph`, not the per-language builders. |
| `lantern/graph.py` | Unified Code Graph: `Node`, `Edge` (`via`, `detail`), confidence ranks, JSON round-trip, `stats()` |
| `lantern/python_frontend.py` | Python: discover → tree-sitter parse (`_visit_body`, `CallSite`s) → `Resolver` |
| `lantern/js_frontend.py` | TS/JS: `Walker` (defs, imports/exports, refs, HTTP calls, route/page registrations) → `SpecResolver` (relative, tsconfig paths, `@/`) → `JSResolver` (barrels, classes, `this`) → entries |
| `lantern/bridge.py` | Links `g.meta["http_calls"]` to route entry points by method + path segments; exact / suffix / unknown-prefix / ambiguous |
| `lantern/tracehook.py`, `trace.py` | Python runtime tracing (`sys.monitoring`), wrapper-hop collapse, upgrade edges to `observed` |
| `lantern/security.py` | Bandit, dependency audits, secrets → `websec.scan_web` → stable ids (line text, not number) → pin to nodes → reachability + `ui_path` → `input` on the flagged line → rank |
| `lantern/depaudit.py` | pip-audit (lock files, `==` pins, pyproject) and `npm audit --package-lock-only`; the only network calls in `analyze`; `--offline` / `LANTERN_OFFLINE` skips them; tests run offline (`tests/conftest.py`) |
| `lantern/protections.py` | Spec 9.4 "protections to add": rate limiting, headers, SSRF allow-list, password hashing, route auth, uploads; heuristic, never changes findings or score |
| `lantern/websec.py` | Full-stack rules: `LW-*` (public-env secrets, service-role JWT, CORS, Firebase, Supabase RLS, missing auth) and `LJ-*` JS patterns |
| `lantern/readiness.py` | Deployment Readiness Score (spec 10): ten weighted categories of deterministic checks (`pass/fail/partial/skip`, skip leaves the denominator), shape advisor, fan-in hotspots, starter files. Accepted risks: `lantern-accepted.json` via `lantern accept` |
| `lantern/evidence.py` | Evidence Report (spec 11): commit-pinned HTML/JSON, baseline → fixed findings, provenance, Limits, SHA-256 results digest checked by `lantern verify`, badge |
| `lantern/explain.py` | Prompt (language-aware, includes HTTP links), `validate()`, retry, bottom-up `select_nodes`, cache |
| `lantern/providers.py` | Anthropic, OpenAI-compatible (OpenAI, OpenRouter, Mistral, Gemini, DeepSeek, Ollama, LM Studio, vLLM), fixture stub |
| `lantern/report.py` + `viewer/report.html` | One self-contained HTML file (vanilla JS): pages/routes, path tree with HTTP and click hops, flowchart, lenses, findings with UI paths |
| `lantern/pipeline.py` | analyze / explain / rebuild as functions with a `log` callback; used by the CLI and the server |
| `lantern/server.py` + `viewer/app.html` | `lantern serve`: stdlib HTTP app (Home, Atlas iframe with live actions, Evidence, Explanations, Settings), jobs in threads, token + Host checks, keys in memory or `~/.lantern/keys.json` (0600); PWA manifest + service worker |
| `lantern/learn.py` + `lantern/starters/` | Starter apps for beginners (`lantern learn`, the app's Learn tab and Guide). Each starter: `starter.json.tmpl` (steps, each with a deterministic `check` read from analysis results), `files/` (planted problems), `solution/` (fixes). Everything is `*.tmpl` and dot-files are `dot.<name>`, so the self-audit never sees the planted problems. `tests/test_learn.py` proves each planted problem is found and each fix clears its step |
| `tools/fake_model.py` | Offline OpenAI-compatible server answering with the shop demo explanations, for end-to-end tests |
| `lantern/cli.py` | `analyze`, `trace`, `explain`, `report`; results in `PATH/.lantern/` |
| `tests/fixtures/shop` | Python backend (`shop/`) + React/Vite frontend (`web/`) with planted shell/SQL injection, MD5, XSS, public secret |
| `tests/fixtures/nextapp` | Next.js + Supabase with an unprotected DELETE route, a table without RLS, a public service-role var |
| `bench/` | Accuracy benchmark and write-up; `results.json` is the latest run |

Node ids: Python `py:pkg.mod.Class.method`; JS `js:<path-without-ext>::<Local.name>` (module: `js:<path>`);
external `ext:<pkg.member>` or `ext:HTTP <METHOD> <path-or-host>`.

## How Python resolution works

The walker emits `CallSite`s with a `kind`: `call`, `depends` (FastAPI `Depends(fn)`), `depends-alias`
(`Annotated` alias defined elsewhere), `decorator-result` (closure a decorator factory returns), `attr`
(kept only if it hits a `@property`), `with` / `with-obj`. Typing sources: `self`/`cls`; `self.x = Foo()`;
`x = Foo()` / `x = make()` (return type) / param hints / `with Foo() as x`; pytest fixtures by name.
Imports go through a suffix index (`from app import crud` → `backend.app.crud`); stdlib names never remap.

## How JS/TS resolution works

`Walker` records defs (functions, arrow functions assigned to names, `memo`/`forwardRef` wrappers,
classes and methods, inline route handlers), imports/exports (default, named, namespace, `export *`,
`export { a as b } from`), and refs with kinds `call`, `new`, `jsx` (rendering `<Comp/>`), `callback`
(function passed by name; `ui` set to `onClick` etc. when inside an event prop). Anonymous inline
functions are attributed to the enclosing named function. HTTP calls: `fetch`/`$fetch`/`useSWR`,
`x.get|post|...(url)`, `x.get({url})` (generated clients), `axios({url, method})`; URLs from strings,
template literals (`${id}` → `{}`), `+` concatenation, and module-level string constants.

Entries: Next.js (`app/**/page`, `app/**/route` exports, `pages/**`, `pages/api/**`, only when the
nearest `package.json` depends on `next`), `createFileRoute`, React Router `<Route>` and route objects,
`createRoot().render` (SPA start), Express-style `app.get('/x', handler)`, test files.

To add a rule (either language): write a failing test with a tiny repo via `_write()`
(`tests/test_frontend.py` for Python, `tests/test_fullstack.py` for JS/bridge/web security), give the
edge a distinct `via`, run `bench/run_bench.py`, and check the numbers before choosing its confidence.

## Backlog (priority order)

1. **Run real models through `lantern explain`** on the benchmark repos with two providers; record the
   first-try anchor pass rate (target 90%). Tune `SYSTEM` from failures, especially on JS components.
2. **More full-stack frameworks:** FastAPI `include_router(prefix=...)` (would turn the template's suffix
   matches into exact ones), Supabase client calls (`supabase.from('t')` as a data-layer edge with RLS
   status), tRPC and Next.js server actions (`"use server"`), Remix loaders/actions, SvelteKit, Django.
3. **Type-aware resolution:** Pyright for Python; the TypeScript compiler API (or `tsserver`) for JS,
   to resolve `useQuery`/`useMutation` results, hooks returning objects, and props typed by interface.
4. **JS runtime tracing** (V8 inspector or a Babel/esbuild transform) so frontend edges get the same
   precision measurement Python has.
5. **Cloud mode + local agent pairing** (spec sections 5 and 12): accounts, GitHub App, remote "analyze now",
   WebGL network view (Sigma.js) for very large graphs. The local app (`lantern serve`) is the base.
6. **Rust, then C++** frontends (spec 6.3), reusing the same graph, bridge, and viewer.
7. Scanner licensing for cloud mode: Opengrep with own or permissively licensed rules (spec 9.1).

## Known gaps

* JS: hook results (`const m = useMutation(...)`, `m.mutate()`) and destructured hook returns are
  unresolved; React Query `mutationFn`/`queryFn` callbacks are linked, which covers most real paths.
* Calls into libraries that call back into the repo (framework dispatch) only show when traced (Python).
* Dependency audits need exact versions: Python ranges without a lock file, and pnpm/yarn/bun lock files, are reported as not checked.
* "Uses input" follows assignments inside one function, in order (parameters, request data, and variables set
  from them), not across functions, branches, or loops. A value that arrives through another function's return
  value is missed; a parameter that is always a constant is over-ranked.
* The report embeds source by default; `--privacy structure` omits it.
* Explanations exist only for selected nodes (entry points + 3 levels, capped at 40 by default).

## Conventions

* Python 3.11+, standard library plus tree-sitter grammars; no network calls except model providers and the dependency
  audits (skippable with `--offline`).
* Always pass `encoding="utf-8"` to file reads/writes and `subprocess.run(text=True)`, and build repo-relative paths with
  `.as_posix()`: Windows CI runs with the system code page and backslash paths.
* Files in `.lantern/` live in the analyzed folder and may be planted: the server rebuilds every page from our templates,
  and anything rendered from them must be escaped.
* Keep `report.html` a single self-contained file that works offline and on a phone.
* Plain language in user-facing text; technical detail lives in Lens 1, `via`, and `detail`.
* Never commit real-looking secrets in fixtures (GitHub push protection); build them at test time.
