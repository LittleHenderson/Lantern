# Phase 0 benchmark

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
| click 8.1.8 | 17,899 | 1,238 | 0.33 s | 1.4 s | 1.4 s | 2,374 | 662 |
| flask (main) | 18,416 | 1,432 | 0.32 s | 1.5 s | 2.4 s | 1,591 | 1,273 |
| rich v13.9.4 | 39,533 | 1,816 | 0.75 s | 6.0 s | 5.7 s | 3,911 | 1,243 |
| requests v2.32.3 | 11,245 | 669 | 0.21 s | 1.7 s | – | 953 | 568 |
| httpie 3.2.4 | 19,135 | 1,073 | 0.33 s | 1.4 s | – | 1,350 | 971 |
| full-stack-fastapi-template | 2,944 | 146 | 0.07 s | 0.6 s | – | 246 | 140 |

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

## Full stack (TypeScript frontend + bridge)

`run_bench.py` now builds the combined graph and records `languages` and `bridge` per repo.

| Repo | Python lines | TS/JS lines | Graph | Frontend HTTP calls | Linked to route | Ambiguous | Unmatched |
|---|---:|---:|---:|---:|---:|---:|---:|
| full-stack-fastapi-template | 2,944 | 10,001 | 0.27 s | 23 | 23 (all "prefix": backend mounts routers under `/api/v1` from a setting) | 0 | 0 |

All 23 links were checked by hand against the generated client and the FastAPI routers: 23/23 correct.
There is no JS runtime tracer yet, so TS edge precision isn't measured the way Python's is; the TS
confidence levels are provisional until it is (CLAUDE.md backlog item 7).
