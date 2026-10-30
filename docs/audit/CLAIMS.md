# Claims and how to test them

Each row is something Lantern's README, UI, or reports say. "Evidence" is what supports it today. "Try to break it"
is where an auditor is most likely to find the claim false. Mark each as **held**, **broken** (with a repro), or
**not tested**.

## Analysis

| # | Claim | Evidence | Try to break it |
|---|---|---|---|
| A1 | Python "confirmed" (resolved) edges are about 95–97% correct, "likely" (inferred) about 90–98%, on click, flask, and rich | `bench/README.md`, `bench/results.json`; runtime traces as ground truth (`python bench/run_bench.py /tmp/bench`, needs network for clones) | Re-run the bench. Hand-check 30 random resolved edges on a repo not in the bench. Dynamic dispatch, decorators, `functools.wraps`, metaclasses, re-exports through `__init__`. |
| A2 | The bridge links frontend calls to backend routes: 23/23 on full-stack-fastapi-template, 5/5 on taxonomy | `bench/README.md` | Routes mounted with `include_router(prefix=...)` (known gap: suffix match), same path on two methods, path params of different names, base URLs from env vars, `fetch` wrapped in a helper. |
| A3 | Unresolvable calls are counted, not guessed | `graph.unresolved`, About tab | Look for edges whose target is a different function with the same short name. |
| A4 | Lantern never runs the analyzed code unless `--trace` is given | `pipeline.analyze`: only `trace.run_trace` executes, gated on `trace_cmd`; bandit parses, doesn't import | Grep for `subprocess`, `exec`, `import_module`, `runpy` reached from `analyze`. Put a `setup.py` or `conftest.py` with a side effect in a repo and analyze it. |
| A5 | Entry points: Next.js pages and routes, React Router, TanStack Router, Express-style, FastAPI/Flask, Click/Typer, `__main__`, scripts | `tests/test_frontend.py`, `tests/test_fullstack.py` | Remix, SvelteKit, Django, tRPC, server actions (documented as not supported). Next.js route groups `(group)` and parallel routes `@slot`. |

## Security

| # | Claim | Evidence | Try to break it |
|---|---|---|---|
| S1 | Findings come only from tools; models never create or close one | `security.scan` has no provider input; `explain.run` writes only `explanations.json` | Find any code path where explanation output changes `security.json` or a count. |
| S2 | Findings are ranked by severity and reachability; the UI shows the path from the page that triggers them | `security.rank`, `reachability`, `ui_path`; `tests/test_security.py`, shop fixture | A finding inside a function reached only through an unresolved call (should not claim reachable). A route reachable only from tests. |
| S3 | Heuristic rules are labeled | `tool_confidence: LOW` → "heuristic" chip | Any `LW-*`/`LJ-*` rule that can misfire but isn't LOW. |
| S4 | Accepted risks need a written reason and remain visible | `lantern accept` (≥10 chars), Evidence Report "Accepted risks" | Accept via a hand-edited `lantern-accepted.json` with an empty reason (should be ignored: `load_accepted`). See THREAT_MODEL T6. |
| S5 | Lantern passes its own audit | CI step `lantern analyze . --fail-on medium` | Run it. Check whether a real issue is being hidden as "low". |

## Readiness

| # | Claim | Evidence | Try to break it |
|---|---|---|---|
| R1 | Score is 0–100 across ten weighted categories (weights from spec 10.1) | `readiness.CATEGORIES`, `tests/test_readiness.py::test_weights_sum_to_100` | |
| R2 | Every point has a visible reason; checks that don't apply are skipped, not counted | `_check` always sets `evidence`; skip leaves the denominator | A check that's skipped when it should apply (or the reverse) for some project shape. |
| R3 | The score is hard to game | Mostly file/pattern checks | It *can* be gamed: an empty `SECURITY.md`, a `Dockerfile` never used, a CI file that never runs. The Evidence Report Limits say "a check passing means the thing exists, not that it is configured well". Judge whether that is honest enough. |
| R4 | Starter files are never written over existing files or outside the project | `cmd_starter`, server `starter` route; tests | Names with `..`, absolute paths, symlinked directories inside the repo pointing out. |

## Explanations

| # | Claim | Evidence | Try to break it |
|---|---|---|---|
| E1 | Every Lens 3 phrase must anchor to a real symbol, a line range inside the unit, or a term in the source/glossary; otherwise the explanation is rejected | `explain.validate`, `tests/test_explain.py` | Anchors to symbols outside the allowed set, line ranges outside the function, terms that only appear in comments a hostile repo planted. |
| E2 | The UI says plainly when code goes to a cloud model, and offers local models | Settings and Explanations screens, Atlas button note | Any path that sends code without that notice (e.g. `openai-compatible` pointed at a remote host is treated as cloud unless the URL is localhost). |
| E3 | Explanations are cached by a hash of each function's code | `explain.Cache` | Change only a callee; check whether a stale explanation is reused. |

## Evidence Report

| # | Claim | Evidence | Try to break it |
|---|---|---|---|
| V1 | Pinned to a commit, and flags uncommitted changes | `evidence.git_info`; `tests/test_evidence.py` | Analyze a subfolder of a repo; analyze with untracked files (not counted as dirty: only tracked changes are). |
| V2 | `lantern verify` re-runs and compares a digest of the deterministic results | `digest_payload`, `cmd_verify`; test shows match then mismatch after a code change | Nondeterminism: run twice and compare; different machines; different bandit versions (expected to differ, and Provenance lists versions). |
| V3 | The digest is not a signature, and the report says so | Section 7 text | |
| V4 | The Limits section states what the report does not prove | `evidence.limits` | Missing limits for situations you can construct. |

## Local app

| # | Claim | Evidence | Try to break it |
|---|---|---|---|
| L1 | One command runs it: `lantern serve PATH` | README; `tests/test_server.py` | Fresh machine, fresh venv, Windows, Python 3.11. |
| L2 | Only this computer can use it, and other websites can't drive it | 127.0.0.1 bind, token link + SameSite=Strict cookie, `X-Lantern-Token` on writes, Host check | See THREAT_MODEL T2. |
| L3 | Keys stay in memory unless "remember" is ticked, then 0600; the API never returns them | `Store.set_key`, `test_keys_stay_private` | Logs, job errors, tracebacks, or reports that echo a key. |
| L4 | Works offline for recently opened reports (PWA) | `viewer/sw.js` | Stop the server and reload an opened report. |
