# CLAUDE.md

Context for working on Lantern in Claude Code. The product spec is `docs/Lantern_Product_Spec_v0.4.pdf`.
This repo is Phase 0 plus the full-stack layer: Python, TypeScript/JavaScript, Go, Rust and Java engines, the API bridge
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
| `lantern/engine.py` | **Entry point for analysis**: Python frontend → JS/TS frontend → Go frontend → Rust frontend → Java frontend → packs → bridge. Use `engine.build_graph`, not the per-language builders. |
| `lantern/graph.py` | Unified Code Graph: `Node`, `Edge` (`via`, `detail`), confidence ranks, JSON round-trip, `stats()` |
| `lantern/python_frontend.py` | Python: discover → tree-sitter parse (`_visit_body`, `CallSite`s) → `Resolver` |
| `lantern/js_frontend.py` | TS/JS: `Walker` (defs, imports/exports, refs, HTTP calls, route/page registrations) → `SpecResolver` (relative, tsconfig paths, `@/`) → `JSResolver` (barrels, classes, `this`) → entries |
| `lantern/go_frontend.py` | Go: packages from `go.mod`, functions/methods/structs/interfaces, calls resolved by `name`, `import`, `receiver-type` (written types and repo function results; types stored by import path so every file reads them alike), `embedded`, `interface` (one `possible` edge per repo type implementing the whole interface), `callback`; routes for net/http (Go 1.22 `"GET /p"` patterns), gin/echo/fiber/chi/gorilla with `Group`/`Route`/`PathPrefix().Subrouter()` prefixes; outgoing `http.Get`/`NewRequest`/client calls to `meta["http_calls"]`. Untyped receivers go to `graph.unresolved`. Sample: `tests/fixtures/goapp` (Go API + React, planted SQL/shell concatenation, unprotected DELETE) |
| `lantern/rust_frontend.py` | Rust: crates from every `Cargo.toml` `[package]` (workspaces), modules from file paths and inline `mod`, functions, `impl` blocks, traits; calls resolved by `name`, `use` (`crate::`/`self::`/`super::`/child modules/globs), `assoc` (`Type::f()`), `receiver-type` (params incl. `State(state): State<Arc<T>>` patterns, fields, `let`, return types; types canonicalised to `[crate, mod…, Name]`), `trait` (`dyn`/`impl`/`T: Trait` → one `possible` edge per `impl Trait for X`), `callback`; routes for axum (`.route("/p", get(h).post(h2))`, `.nest("/api", f())` and inline nests), actix (`#[get("/p")]`, `web::scope`, `.service`, `.route(p, web::get().to(h))`), rocket (`#[get]`, `.mount("/api", routes![…])`); outgoing `reqwest`/`ureq`/client calls with `format!` and consts folded. Untyped receivers go to `graph.unresolved`; chains on foreign calls are not counted. Sample: `tests/fixtures/rustapp` (axum + React, planted `format!` SQL/shell, unprotected DELETE) |
| `lantern/java_frontend.py` | Java: packages, classes (nested as `Outer.Inner`), interfaces, enums, records, methods (overloads share one node; constructor is `Class.Class`); calls resolved by `name`, `inherited` (`extends` chain, interface default methods), `static` (`Class.m()`), `receiver-type` (fields incl. `= new T()`, params, locals, try-resources, `var` from `new`/return types), `interface` (one `possible` edge per class that implements/extends the interface or abstract class), `constructor`, `callback` (`Class::m`); routes for Spring (`@RequestMapping` class prefix, `@GetMapping`…, `@RequestMapping(method=…)`), JAX-RS (`@Path` + `@GET`…), Micronaut, Javalin/Spark (`app.get("/p", Class::h)`); outgoing `RestTemplate`, `WebClient.get().uri()`, `HttpRequest.newBuilder().uri()`, OkHttp `Request.Builder().url()`. Imports: explicit, wildcard (repo packages), static. Sample: `tests/fixtures/javaapp` (Spring Boot + React, planted SQL/shell concatenation, unprotected DELETE) |
| `lantern/sandbox.py` + `lantern/_jail.py` | Test sandbox for "Watch my tests run": `detect` (pytest, Jest, Vitest, Mocha, npm/pnpm/yarn test, go test, cargo test, Maven, Gradle), `check_command` (test runners only), backends Docker (Linux + daemon; images pinned by digest in `IMAGES`, project ro at `/app`, `--network none`, 2 CPU/2 GB, uid 65534, host Python packages mounted ro) or restricted subprocess (read-only temp copy, env allow-list, `_jail`: rlimits, Landlock writes-only-in-temp + no TCP, uid 65534 if root; Python audit hook `SITECUSTOMIZE`; Windows Job Object), 10-min wall clock killing the tree; `blocked` reasons from `LANTERN-SANDBOX-BLOCKED:` markers. Python calls are traced and merged; other languages run untraced ("Tests run; your map upgrades for Python only for now"). `LANTERN_SANDBOX=subprocess\|docker` forces a backend. Tests: `tests/test_sandbox.py` |
| `lantern/lanes.py` | Stack lanes for the stack strip (design turn 11): `browser` → `frontend` → `server` → `data`, assigned from node id, file path and entry kind only (`assign(g)` sets `node.lane`, `meta["lanes"]`; `security.scan` sets `hot_lane` and `lanes` on each finding; `lane_for_file` for findings with no node). The viewer draws the strip on Finding/Fix/function panels, the Lanes view (Simple default on Paths), the four-dot glyph on list rows, hover definitions; it validates every lane value against the four stops. Rules and words: `docs/api.md` “Stack lanes” |
| `lantern/bridge.py` | Links `g.meta["http_calls"]` to route entry points by method + path segments; exact / suffix / unknown-prefix / ambiguous |
| `lantern/tracehook.py`, `trace.py` | Python runtime tracing (`sys.monitoring`), wrapper-hop collapse, upgrade edges to `observed` |
| `lantern/security.py` | Bandit, dependency audits, secrets → `websec.scan_web` → stable ids (line text, not number) → pin to nodes → reachability + `ui_path` → `input` on the flagged line → rank |
| `lantern/depaudit.py` | pip-audit (lock files, `==` pins, pyproject) and `npm audit --package-lock-only`; the only network calls in `analyze`; `--offline` / `LANTERN_OFFLINE` skips them; tests run offline (`tests/conftest.py`) |
| `lantern/protections.py` | Spec 9.4 "protections to add": rate limiting, headers, SSRF allow-list, password hashing, route auth, uploads; heuristic, never changes findings or score |
| `lantern/aiapp.py` | AI-app pack: `find_calls` pins model/embedding/image/speech/vector/payment/email/SMS calls to functions (`security["ai"]`: `calls`, `by_node`, `kinds`, `providers`, `notebooks`, `is_ai_app`; the viewer draws chips); `LA-WALLET-DRAIN` (route → paid call with no login and/or no rate limit; reuses `websec.login_check` and `protections.RATE_LIMIT_LIBS`), `LA-MODEL-OUTPUT-TO-TOOL` (model text → shell/SQL/eval/HTTP/file inside one function), `LA-PROMPT-FROM-INPUT` (informational), `LA-NOTEBOOK-SECRET` (keys in `.ipynb` cells and outputs). Sample: `tests/fixtures/aiapp`. Docs: `docs/ai-apps.md` |
| `lantern/websec.py` | Full-stack rules: `LW-*` (public-env secrets, service-role JWT, CORS, Firebase, Supabase RLS, missing auth), `LJ-*` JS, `LG-*` Go, `LR-*` Rust and `LV-*` Java patterns (`_pattern_rules`) |
| `lantern/readiness.py` | Deployment Readiness Score (spec 10): ten weighted categories of deterministic checks (`pass/fail/partial/skip`, skip leaves the denominator), shape advisor, fan-in hotspots, starter files. Accepted risks: `lantern-accepted.json` via `lantern accept` |
| `lantern/evidence.py` | Evidence Report (spec 11): commit-pinned HTML/JSON, baseline → fixed findings, provenance (including analysis packs), Limits, SHA-256 results digest; `verify()` re-runs and compares (used by the CLI and the connector; never replays a trace command); badge reads `Lantern · commit 1a2b3c · 0 critical · Oct 31`, never "verified" or "secure" |
| `lantern/explain.py` | Prompt (language-aware, includes HTTP links and the map's path to the unit as `REACHED FROM`), `validate()`, retry, bottom-up `select_nodes`, cache. Asks for a `scenario` per unit and per finding (`lens-v4`); `check_scenarios` removes one with code identifiers or a page/route the prompt did not show (`dropped_scenarios`), never failing the lenses |
| `lantern/scenarios.py` | Scenarios: a short story of one tester meeting each finding (`security.scan` attaches `scenario` to every finding), built only from `ui_path` clicks, `reachable`, `input` and a fixed story per kind (rule id → CWE → category; unknown rules get a generic story). The viewer's fourth lens tab (Scenario), the Fix page card and "See it happen" on finding cards show the model's story when it passed, else this one. Tests: `tests/test_scenarios.py` |
| `lantern/providers.py` | Default `anthropic/claude-haiku-5-5` (`DEFAULT_PROVIDER`/`DEFAULT_MODEL_NAME`); `resolve_default()` (--model > LANTERN_MODEL > ANTHROPIC_API_KEY > DEEPSEEK_API_KEY > allowance token); `LanternHostedProvider` (402 → `AllowanceExhausted`; run stops cleanly, cache shared with the user's own key via `cache_model`); `ensure_consent()` once per provider before code leaves the machine (local presets and localhost endpoints never ask); Anthropic and OpenAI-compatible adapters. `_post` returns the body; `_post_full` also returns headers |
| `gateway/` | Separate deployable (FastAPI, `create_app --factory`) hosting the free allowance. The owner's model keys live only here (Anthropic primary, DeepSeek fallback, `Settings.order()`); per-user lifetime and daily limits, global daily dollar cap, narrowed requests (one model, capped tokens and body), token hashes and counters only, never bodies. Owner dashboard at `/v1/admin` (`dashboard.py`, admin secret kept in the tab) over `/v1/admin/stats`; `/v1/usage` takes the app's opt-in counts. Sign in with GitHub/Google (`auth.py`): `/v1/login` → `/v1/auth/<p>/start` (HMAC-signed state carrying the client's `cli` code) → provider → `/v1/auth/<p>/callback` (server-side code exchange, `Store.sign_in`: one token per account, re-sign-in rotates and carries counters) → token shown once and parked for `/v1/auth/claim?cli=` (one claim, 10 min). Stores provider id + GitHub login, never email. Tests: `tests/test_signin.py` Tests: `tests/test_gateway.py`, `tests/test_allowance_flow.py` (live local gateway, end to end), `tests/test_usage.py` |
| `cloud/` | Cloud mode (spec 5, 12; plan `docs/cloud-mode-brief.md`): separate deployable (FastAPI, `lantern_cloud.app:create_app --factory`, Fly app `lantern-cloud`, `cloud/fly.toml`, `cloud/Dockerfile` built from the repo root with the engine). Milestone 1: `Settings` (env limits; owner decisions 2026-11-03: every known host, results kept until deleted, cloud runs may spend the allowance, share off until clicked), SQLite `Store` (accounts, runs, per-day counters; never tokens or emails), `Identity` (sign-in reused from the gateway via `GET /v1/whoami`, cached by token hash in memory), `/v1/health`, `/v1/me`, `/v1/admin/stats`, `IdleExit` (`idle.py`: stops itself after `LANTERN_CLOUD_IDLE_MINUTES` with no request and no run, so the Fly machine sleeps; `min_machines_running = 0`, restart `on-failure`). Milestone 2: `POST /v1/repos` (a `link`, or a `sample` starter id from `GET /v1/samples`: `lantern:sample/<id>`, written by `learn.scaffold` in `worker.get_source`, no clone); `POST /v1/uploads` (a .zip body, the website zips a folder in the browser; kept in `LANTERN_CLOUD_UPLOADS` until the run starts, then unpacked by `lantern/archive.py` (`python -m lantern.archive`, refuses escaping names, links, encryption, oversize while writing) jailed without network; link `lantern:upload/<label>`, no explain), `GET /v1/runs[/{id}[/stream]]` (SSE), `Worker` (`worker.py`: clone → `python -m lantern.depaudit` jailed with network → `lantern analyze --offline` jailed without network, audits passed through `LANTERN_AUDITS_FROM` (`depaudit.precomputed`) → results copied → temp folder removed in `finally`; `blocked` from the sandbox markers; limits → 429; restart requeues). Milestone 3: `POST /v1/runs/{id}/view` → links `/r/{id}/report.html|evidence.html|badge.svg|findings.json|graph.json|readiness.json?k=<exp>.<HMAC>` (owner only, 60 min, then an `lv` cookie scoped to `/r/{id}/`), pages rebuilt by `lantern.server.result_page` (shared with `lantern serve`; data only from stored files, nonce CSP, `live` null); the jailed analysis sets `LANTERN_CLOUD_RUN=1` → `run_meta["place"] = "cloud"` → an Evidence Limits line. Milestone 4: the website at `/` (`site.py` + `site/index.html`): built from `lantern/viewer/app.html` itself (stylesheet, fonts, brand mark, icons, ring, appearance, backdrop pulled in at start-up by anchors; `app_parts` fails loudly if the app changes shape), so it looks like the app; sign-in through the gateway (`/v1/signin/start|poll`, token only in an HttpOnly SameSite=Strict `lt` cookie; cookie-authenticated changes need `X-Lantern-Site: 1`), paste box + privacy choice, My runs (Simple cards / Advanced table), progress (steps + SSE log), the report in the app's frame; PWA manifest + service worker that never caches `/v1/` or `/r/`. The landing intro plays on every visit to `/` (not on `#/run/…`, `#/help`, `?intro=0`) from same-origin copies (`site/intro-runtime.js`, `site/intro.js`, vendored React; `test_the_intro_plays_on_the_website_from_this_origin` keeps them equal to `site/intro/`). Milestone 5: Share (`/v1/runs/{id}/share` on/off; `/s/<slug>/report.html|evidence.html|badge.svg`, a random `secrets.token_urlsafe(18)` slug, read-only, noindex, no data files; off makes a later share a new link), `DELETE /v1/runs/{id}` and `DELETE /v1/me` (409 while a run is going), retention sweep `app.sweep` when `LANTERN_CLOUD_RETENTION_DAYS` > 0. Milestone 6: words from a model through the person's own allowance, only after `POST /v1/ai/consent` (`users.ai_consent`; 412 `consent_needed` otherwise; notice = `DATA_NOTICES["lantern"]`): `POST /v1/runs/{id}/explain` (`Worker.explain`: re-clone, refuse a different commit, `lantern explain --model lantern/<default>` jailed with network, token via `LANTERN_TOKEN` env held in memory only, copy back `EXPLAINED_FILES` + cache, a restart marks waiting jobs `error`) and `POST /v1/ask` (`ask.ask(..., out=, name=)` on the run's results; `create_app(provider_for=)` swaps the model in tests and the demo); the website's Explain button, consent sheet and Ask Lantern pill (app's `#ask` styles, opacity slider, screenshot attach/paste/drop; `window.askAbout` for the report's button); `POST /v1/ask/screenshot` reads a screenshot's text with `ask.read_screenshot(max_pixels=40M)` in memory (Tesseract + Pillow `[ocr]` in `cloud/Dockerfile`), two at a time. Connect GitHub (`ghapp.py`, optional, `LANTERN_GITHUB_APP_ID|KEY|SLUG`): a github.com clone that git cannot open anonymously asks the GitHub App for a one-repository read-only token (installation looked up per repo, nothing stored), only after `collaborators/<login>/permission` says the signed-in GitHub id may read it; `remote.fetch(auth=)` passes it through `GIT_CONFIG_*` env; `run_view` `hint` (`upload`/`connect`, from `worker.HINTS`) drives the website's Upload / Connect GitHub buttons; tests `tests/test_cloud_github.py`. Smoke: `tools/cloud_site_demo.py --poison` + `tools/cloud_site_smoke.js` (in `audit.sh --browser`). Routes in `docs/api.md` “Cloud service”; deploy in `docs/deploy.md`. Tests: `tests/test_cloud.py`, `tests/test_cloud_runs.py`, `tests/test_cloud_view.py`, `tests/test_cloud_site.py`, `tests/test_cloud_share.py`, `tests/test_cloud_ai.py` |
| `lantern/ask.py` | Ask Lantern (the floating assistant on every screen): `facts()` gathers the project's results (readiness, open findings with ids, click paths and input, AI calls, routes, the selected function's everyday lens) and `ask()` has the configured model answer from those facts only; finding ids the model invents are replaced with "[unknown finding]" and counted. No project → answers about Lantern itself. `read_screenshot()` reads a dropped PNG/JPEG/WebP (≤ 8 MB) on this computer: Pillow decodes it, the Tesseract program reads it through a pipe (`ocr_image`: `tesseract stdin stdout`, never a temp file, so not pytesseract); without Tesseract it returns `text: null` + `how` (install line per OS). `[ocr]` extra = Pillow. Tests: `tests/test_ocr.py` (CI installs Tesseract on Linux). Routes `/api/ask`, `/api/ask/screenshot` |
| `lantern/report.py` + `viewer/report.html` | One self-contained HTML file (vanilla JS): pages/routes, path tree with HTTP and click hops, flowchart, lenses, findings with UI paths |
| `docs/api.md` | The local API (`lantern serve`) and every result file's shape, build sequence and acceptance checklist for anyone rebuilding the UI; keep it current when routes or file fields change |
| `lantern/pipeline.py` | analyze / explain / rebuild as functions with a `log` callback; used by the CLI and the server |
| `lantern/server.py` + `viewer/app.html` | `lantern serve`: stdlib HTTP app (Home, Atlas iframe with live actions, Evidence, Explanations, Settings), jobs in threads, token + Host checks, keys in memory or `~/.lantern/keys.json` (0600); `Store` writes under `FileLock` (`store.lock`, held across processes) with a unique temp file per write; PWA manifest + service worker |
| `lantern/remote.py` | A repository link instead of a folder (CLI `path`, `lantern serve`, the app's Add a project): `parse` (https only, public forges in `KNOWN_HOSTS` on 443 plus `LANTERN_GIT_HOSTS` (`host` any port, `host:port` that one; the port is kept in the clone URL), no credentials, `git@` form converted, `/tree/<branch>`), `clone` into `LANTERN_HOME/repos/<host>[_<port>]/<owner>/<name>` (`git clone --depth 1 --no-checkout`, prompts off, files measured against `LANTERN_CLONE_MAX_MB` before checkout, nothing left behind when any step fails, fast-forward if already there, an earlier checkout that failed or stopped part-way finished without touching edited files; `pipeline.analyze` refuses a Lantern clone (`is_clone`: `.git/lantern-clone` mark or under `LANTERN_HOME/repos`) with files still missing, or whose files git cannot list, via `check_complete`). Every git call goes through `run_bounded`, which kills the whole process tree at the timeout (Windows `subprocess.run` waited on pipes held by `git-remote-https`). The clone is as untrusted as any analyzed repo |
| `lantern/learn.py` + `lantern/starters/` | Starter apps for beginners (`lantern learn`, the app's Learn tab and Guide). Each starter: `starter.json.tmpl` (steps, each with a deterministic `check` read from analysis results), `files/` (planted problems), `solution/` (fixes). Everything is `*.tmpl` and dot-files are `dot.<name>`, so the self-audit never sees the planted problems. `tests/test_learn.py` proves each planted problem is found and each fix clears its step |
| `tools/fake_model.py` | Offline OpenAI-compatible server answering with the shop demo explanations, for end-to-end tests |
| `lantern/mcp_server.py` | Lantern as a connector: MCP over stdio (`lantern mcp`), standard library JSON-RPC. Tools: projects, findings (with click paths and fixes), paths (callers/callees/reachability), explain (stored only), readiness, analyze, recheck (fix-and-verify loop), verify. **No accept/close/dismiss tool exists**; `lantern_verify` refuses traced reports. Records each client's `clientInfo` in `LANTERN_HOME/connections.json` (names and times only) for Settings › Connections (`/api/connections`). `--setup` prints config snippets. Docs: `docs/connectors.md` |
| `lantern/packs.py` + `lantern/packs/*.json` | Analysis packs: JSON pattern files (rules `LP-*` matched per line; framework entry patterns whose handler names resolve to graph nodes, `via: pack:<name>`). Loaded from built-in, `<repo>/lantern-packs/`, `LANTERN_HOME/packs/`; `requires` gates by manifest text or files. Third-party pack findings are always `tool_confidence: LOW`. Applied in `engine.build_graph` (before the bridge) and `security.scan`. Per-pack off switch: `settings.json → packs.disabled` (`packs.disabled()`, `split_enabled`), `GET/POST /api/packs`, stale card "Re-check to apply"; provenance lists off packs. `lantern packs` lists and validates. Docs: `docs/packs.md` |
| `lantern/usage.py` | Opt-in usage counts (`share_usage` in settings, off by default): per-feature counts per day in `LANTERN_HOME/usage.json`, random `install_id`, sent at most daily to the gateway's `POST /v1/usage` (app: background thread every 6 h; CLI: at exit). `FEATURES` is the whole vocabulary; the gateway drops anything else. `lantern usage --on/--off/--show`; `/api/usage`. Turning it off discards unsent counts. Docs: `docs/analytics.md` |
| `lantern/exporters.py` | SARIF 2.1.0 export of findings (`lantern export --sarif`), with click paths in messages and accepted risks as suppressions |
| `lantern/cli.py` | `analyze`, `trace`, `explain`, `report`, `verify`, `accept`, `mcp`, `packs`, `export`; results in `PATH/.lantern/` |
| `tests/fixtures/shop` | Python backend (`shop/`) + React/Vite frontend (`web/`) with planted shell/SQL injection, MD5, XSS, public secret |
| `tests/fixtures/nextapp` | Next.js + Supabase with an unprotected DELETE route, a table without RLS, a public service-role var |
| `bench/` | Accuracy benchmark and write-up; `results.json` is the latest run |

Node ids: Python `py:pkg.mod.Class.method`; JS `js:<path-without-ext>::<Local.name>` (module: `js:<path>`);
Go `go:<import path>::<Func>` / `go:<import path>::<Type>.<Method>` (file module: `go:<path>.go`);
Rust `rs:<crate>::<mod path>::<fn>` / `rs:<crate>::<mod path>::<Type>::<method>` (file module: `rs:<path>.rs`);
Java `jv:<package>.<Class>.<method>` (class: `jv:<package>.<Class>`, file module: `jv:<path>.java`);
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

Script inside HTML pages (`.html`/`.htm`, `js_frontend.inline_script`): the JavaScript `<script>` bodies are laid over a
buffer of spaces at their original offsets (line numbers are the page's own) and parsed with the JS grammar; the module
keeps the `.html` in its name (`js:site/index.html::load`), the file node is a `page` entry (Browser lane; its functions
Frontend). JSON/importmap/`text/babel` blocks, `src=` tags and `.min.html` are skipped. `LJ-*` pattern rules do not run on
pages (a page that builds itself with `innerHTML` from escaped values would light up on every line).

Entries: Next.js (`app/**/page`, `app/**/route` exports, `pages/**`, `pages/api/**`, only when the
nearest `package.json` depends on `next`), `createFileRoute`, React Router `<Route>` and route objects,
`createRoot().render` (SPA start), Express-style `app.get('/x', handler)`, test files.

To add a rule (either language): write a failing test with a tiny repo via `_write()`
(`tests/test_frontend.py` for Python, `tests/test_fullstack.py` for JS/bridge/web security), give the
edge a distinct `via`, run `bench/run_bench.py`, and check the numbers before choosing its confidence.

## Default model and free allowance

Claude Haiku 5.5 is the default in the CLI and in `lantern serve` (`DEFAULT_MODEL = anthropic/claude-haiku-5-5`;
Settings defaults to the same). The gateway answers with Haiku first and DeepSeek when Anthropic fails
(`LANTERN_PRIMARY` swaps them); `DATA_NOTICES["lantern"]` names both. Spec section 8.5 still describes DeepSeek as
the default; the switch (2026-11-01) was a price and data-location decision: Haiku 5.5 is $0.10/$0.50 per MTok, US-hosted.
**Never put a provider key in the client or this repo**: the free allowance works only through `gateway/`.
Without an own key, `App.make_provider` uses the allowance when `lantern login` saved a token and a gateway URL
is configured (`DEFAULT_GATEWAY_URL` or `LANTERN_GATEWAY_URL`); otherwise it says how to get one. `lantern login --github`
/ `--google` opens the gateway's sign-in page and polls `/v1/auth/claim` (`providers.sign_in_start/claim`); the app's
Settings has the same buttons (`/api/login/start`, `/api/login/poll`). `/api/allowance`
reports what's left. Screen states and copy for Settings, consent, and errors are in spec section 8.5.

## Backlog (priority order)

0. **Ship the allowance:** the gateway is live at `https://lantern-gateway.fly.dev` (Fly.io, org Little Henderson, region sjc; `gateway/fly.toml`, `docs/deploy.md`; deploy with `fly deploy --depot=false` from behind a TLS-inspecting proxy) and `DEFAULT_GATEWAY_URL` points at it. Secrets are on Fly. Sign in with GitHub/Google issues one token per account (needs the OAuth app
   ids/secrets set on Fly, see `docs/deploy.md`). Then the spec chapter 19 order: wallet-drain check, "Prove it" live
   checks (domain verification and consent first), Ask Lantern with screenshots, What changed, data-flow map.
   Done: the MCP connector (`lantern mcp`) with the fix-and-verify loop (`lantern_recheck`), "Send to…",
   analysis packs (Django built in), SARIF export. Next for the connector: an HTTP transport with GitHub sign-in
   so ChatGPT and Claude on the web can use it without a bridge; more packs (Remix, tRPC, SvelteKit, Rails).

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
6. **Kotlin, C#, PHP, Ruby, then C++** frontends (spec 6.3), reusing the same graph, bridge, and viewer, the way
   `go_frontend.py`, `rust_frontend.py` and `java_frontend.py` do (all added 2026-11-01; their edge confidences are
   provisional until a benchmark per language exists).
7. Scanner licensing for cloud mode: Opengrep with own or permissively licensed rules (spec 9.1).

## Known gaps

* Go: no runtime tracing, no `go vet`/gosec/govulncheck yet (only the `LG-*` patterns); generics, function values
  stored in variables, and methods promoted through more than one embedding level are unresolved; a call on a
  `map`/`chan`/closure result is counted, not guessed. Confidence levels are not yet backed by a Go benchmark.
* Rust: no runtime tracing, no cargo-audit/clippy yet (only the `LR-*` patterns); macros other than `format!` and
  `routes!` are opaque (a route declared inside a macro is missed); closures stored in variables, trait objects
  built through generic constructors, and associated types are unresolved; `impl Trait for X` matching is by trait
  name, not path. Confidence levels are not yet backed by a Rust benchmark.
* Java: no runtime tracing, no SpotBugs/dependency-check yet (only the `LV-*` patterns); generics are looked through
  (a `List<Note>` receiver is `List`, external); overloads share a node so a call lands on the group, not the exact
  overload; Spring's `@Autowired` field injection is typed by the field's declared type (an interface → `possible`
  edges to every implementation); lambdas are attributed to the enclosing method. Confidence levels are not yet backed by a Java benchmark.
* JS: hook results (`const m = useMutation(...)`, `m.mutate()`) and destructured hook returns are
  unresolved; React Query `mutationFn`/`queryFn` callbacks are linked, which covers most real paths.
* Calls into libraries that call back into the repo (framework dispatch) only show when traced (Python).
* Dependency audits need exact versions: Python ranges without a lock file, and pnpm/yarn/bun lock files, are reported as not checked.
* "Uses input" follows assignments inside one function, in order (parameters, request data, and variables set
  from them), not across functions, branches, or loops. Parameters are read from the signature per language (Java/Kotlin/C#:
  the last identifier of each `Type name`; Go: without the receiver; Rust: the pattern before `:`, unwrapping
  `State(x)`/`Path(x)`/`Json(x)`); request data patterns cover Flask/Django/Express/Next, Go's net/http, gin, echo,
  fiber and chi, and Java servlets. A value that arrives through another function's return
  value is missed; a parameter that is always a constant is over-ranked. A plain `x = <safe value>` at the same
  block level clears `x`; a default inside an `if` (`if not x: x = "ls"`) does not, and neither does `x += ...`,
  so a value that is always replaced inside a branch stays ranked critical (the safe direction).
* The login check (`LW-AUTH-MISSING`, protection `route-auth`) reads names, not meaning: strings, comments, request
  data and the names that hold it are blanked first; an auth word must be a whole segment of a name (`get_token`,
  `has_permission`, `protectedProcedure`; not `tokenize`, `load_permissions`, `protect_zone`; `websec.auth_word`;
  `verify` only with the caller as its object: `verify_token`, `verify_session`, `verify_api_key`, not `verify_payment`) and
  counts only as a call or an attribute, a parameter
  only through a dependency, type, injected header or cookie, or caller name; a user lookup counts only when its
  argument identifies the caller (a token, session or request parameter, a `_by_token` lookup, or no argument at all,
  which is taken as "the session", deliberately) and is otherwise at most `check`, which includes a token read from
  the request body. Missed: a check hidden behind a helper with a neutral name (`load()`), or a bare local flag
  (`ok = role == "admin"`). Both land on `add`/`check`, the safe side.
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
* UI: the design is the Claude Design handoff (`Lantern_UI_mockups`: tokens, shared chrome, backdrop, Ask Lantern, ten
  screens in Simple/Advanced). The design tokens at the top of `app.html`, `report.html` and `evidence.py` are one set
  (accent teal `#0F7B74`/`#4FC3BA`, DM Sans / Lora / JetBrains Mono with system fallbacks; the report stays offline and
  never loads fonts from the network); change all three together. `app.html` has the backdrop (`#bg`, three drifting
  SVG layers, `settings.backdrop` off/subtle/bold, quiet on project screens; `report.html` draws the same geometry as
  `.backdrop` when opened on its own, `LANTERN_LIVE.backdrop`, and none inside a frame, where it is transparent), the Simple/Advanced toggle
  (`settings.view_mode`, phones Simple only) and the Ask Lantern pill/window (`#ask`).
  Status colors (good/warning/serious/critical) mean risk or results only and always sit beside a word or icon.
* Plain language in user-facing text; technical detail lives in Lens 1, `via`, and `detail`.
* Never commit real-looking secrets in fixtures (GitHub push protection); build them at test time.
* The connector and the plugin seams never get a way to create, dismiss, close or re-rank a finding. New MCP tools
  are read-only or re-run the analysis; new seams are data (patterns, endpoints, exports), not code.
