# Benchmark

```bash
python bench/run_bench.py WORKDIR            # clone, analyze, trace; writes WORKDIR/bench_results.json
python bench/run_bench.py WORKDIR --no-trace # speed only
python bench/run_bench.py WORKDIR --only flask
```

`results.json` in this folder is the last full run (October 2026, Python 3.13, one CPU core of a cloud
sandbox).

## Method

1. Build the static graph.
2. Run the project's own test suite under `lantern.tracehook`, which records every caller → callee pair
   between functions in the repo (PEP 669 `sys.monitoring`).
3. Collapse decorator wrapper hops: `a → wrapper → b` counts as `a → b` when the static graph has `a → b`
   and the wrapper is a function nested in another function (the `functools.wraps` pattern).
4. For every function that actually executed, compare.
   * **Recall** = observed calls the static graph also found.
   * **Precision (lower bound)** = static edges from executed callers that were observed, grouped by the
     edge's static confidence and by resolution method. Edges to classes with no Python `__init__`
     (named tuples, dataclasses) are excluded because constructing them runs nothing traceable.

Precision is a lower bound because test suites skip branches: an edge in an error path is correct but
may never run. Hand-labelled samples are the Phase 0 follow-up that tightens it.

## Results

| Repo | Lines | Functions | Graph | Scan | Trace | Internal edges | Unresolved sites |
|---|---:|---:|---:|---:|---:|---:|---:|
| click 8.1.8 | 17,899 | 1,238 | 0.43 s | 1.4 s | 1.5 s | 2,374 | 662 |
| flask (main) | 18,416 | 1,432 | 0.51 s | 1.5 s | 2.6 s | 1,591 | 1,273 |
| rich v13.9.4 | 39,533 | 1,816 | 1.23 s | 6.0 s | 6.7 s | 3,911 | 1,243 |
| requests v2.32.3 | 11,245 | 669 | 0.35 s | 1.7 s | – | 953 | 568 |
| httpie 3.2.4 | 19,135 | 1,073 | 0.50 s | 1.4 s | – | 1,350 | 971 |
| full-stack-fastapi-template (Py + TS) | 14,121 | 441 | 0.37 s | 1.0 s | – | 846 | 465 |
| taxonomy (Next.js) | 7,809 | 229 | 0.25 s | 0.5 s | – | 330 | 224 |

Graph time includes the TypeScript pass and the bridge (a directory walk for Python-only repos).

Spec target: structural analysis of a 50k-line Python repo in under 3 minutes. Measured: about 1 second
for 40k lines.

| Repo | Observed calls | Recall | Confirmed correct | Likely correct | Possible correct |
|---|---:|---:|---:|---:|---:|
| click | 2,519 | 75.4% | 96.7% (1,479) | 90.4% (436) | 61.0% (123) |
| flask | 2,159 | 57.0% | 95.5% (557) | 97.0% (625) | 48.7% (191) |
| rich | 3,688 | 70.9% | 96.6% (1,737) | 98.1% (911) | 57.7% (78) |

Spec target: at least 95% of resolved edges correct. Met on all three (lower bound).

### Precision by resolution method (confirmed / checked)

| Method | click | flask | rich |
|---|---:|---:|---:|
| plain name | 722/741 | 237/246 | 564/603 |
| constructor | 301/313 | 167/170 | 824/836 |
| decorator closure | 305/313 | 176/176 | 2/2 |
| local variable type | 80/89 | 176/176 | 564/566 |
| `self.method()` | 94/111 | 114/120 | 156/166 |
| unique method name | 79/88 | 241/255 | 161/171 |
| `with` block | 18/18 | 8/8 | 62/62 |
| property read | 7/8 | 18/28 | 157/159 |
| `super()` | 37/37 | 6/6 | 10/10 |
| pytest fixture type | 175/191 | – | 4/4 |
| override (possible) | 45/72 | 17/20 | 12/16 |
| 2–4 same-named methods (possible) | 30/51 | 75/170 | 33/62 |

This table drives confidence labels: a method earns "likely" only when it measures at 90%+ across repos.
Multi-candidate name matches don't, so they stay "possible" (dotted lines).

## Frontend → backend bridge

The bridge links each HTTP call in frontend code (`fetch`, axios, generated API clients) to the backend
route that serves it, by HTTP method and path segments. Results on the two full-stack repos:

| Repo | HTTP calls | Linked | Exact path | Prefix added elsewhere | Ambiguous | External | No route in repo |
|---|---:|---:|---:|---:|---:|---:|---:|
| full-stack-fastapi-template | 25 | 23 | 0 | 23 | 0 | 0 | 2 |
| taxonomy | 6 | 5 | 5 | 0 | 0 | 1 | 0 |

**Verification.** The FastAPI template's frontend uses a generated client, so each link can be checked
mechanically: `ItemsService.updateItem` must land on `update_item`. All 23 do (`name_verified` in
`results.json`). The 2 unlinked calls are a Playwright helper calling a local mail server, correctly
reported as having no route in the repo. The template's backend adds `/api/v1` through
`include_router` in another file, which is why every link is a suffix match ("likely").

For taxonomy, every `fetch(` in the repo was listed with grep and checked by hand: all 5 calls to its own
API link to the correct Next.js route handler (`POST /api/posts`, `PATCH /api/posts/[postId]`, …), the
landing page's call to the GitHub API is labeled external, and the two font loads in the OG-image route
pass a `URL` object rather than a path, so they're out of scope.

One bug the benchmark found and fixed: a call to `/users/${id}` tied between `GET /users/{user_id}` and
`GET /users/me`. Segment-shape matching (a variable matches a variable before it matches a literal)
resolved all 3 ties correctly.

**Entry points found:** FastAPI template: 9 pages (TanStack Router file routes, pathless `_layout`
segments removed), 23 API routes with router prefixes, 1 SPA mount. Taxonomy: 14 pages and 8 route
handlers across app-router route groups like `(marketing)`.

## What recall misses

Categorized on click before the last round of fixes (1,179 misses then, 620 now): decorator factories
(fixed), untyped receivers such as function return values and fixtures (mostly fixed), property reads
(fixed), `with` blocks (fixed). Remaining misses are mostly callbacks passed as values
(`ctx.invoke(f)`), attributes whose type is only known at runtime, and framework dispatch
(Flask's `current_app`, view functions called by the router). Flask's lower recall is mostly the
last category. Phase 1 adds Pyright for type-aware resolution and framework adapters for routing.

## Not yet measured

* Hand-labelled edge samples (tightens precision beyond the lower bound).
* Lens 3 anchor-validation pass rate on real models. The validator and retry loop are tested with stub
  providers; run `lantern explain --model ...` on the six repos above with two providers to complete
  this Phase 0 exit criterion.
* The 5 builders + 5 engineers review of explanations and reports.
* JavaScript call-graph precision against runtime traces (tracing is Python-only so far). The bridge
  is verified above; in-frontend edges are covered by fixture tests only.
* More full-stack repos, especially Express + React and Supabase-backed apps.
