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
| S5 | Lantern passes its own audit, on Linux and Windows | CI steps `lantern analyze . --fail-on medium` (ubuntu and windows jobs) | Run it. Check whether a real issue is being hidden as "low". |
| S6 | Critical means high severity, reachable from a route/command, and the flagged line uses a parameter, request data, or a variable set from either earlier in the same function (spec 9.3). A plain reassignment to a safe value at the same block level clears the variable; a default inside an `if` block, `x += ...`, or a reassignment that still uses the variable keeps it | `security._input_on_line`, `rank`; `test_critical_needs_input_on_the_flagged_line`, `test_input_through_a_local_variable_is_still_critical`, `test_input_follows_assignments_in_js_handlers`, `test_reassigning_a_safe_value_clears_the_input` | Input that arrives through another function's return value, a loop, or a branch (missed: assignments are followed in order inside one function only). A parameter that is always a constant, or a variable always replaced inside a branch (over-ranked). |
| S7 | Known-vulnerable dependencies are checked for Python (lock files, `==` pins, pyproject) and npm (package-lock.json); what can't be checked is said | `depaudit.py`, `tests/test_depaudit.py`; Limits section | Ranges without a lock file, pnpm/yarn/bun lock files, a hostile `.npmrc` or `--index-url` in the repo. |
| S8 | "Protections to add" appear only with evidence from the code, and are labeled heuristic. The login check has three statuses: `add` (no sign in the handler, what it calls, or app-wide middleware), `check` (an app-wide mechanism exists but the code does not show it covers these routes, or the handler only looks up a user by a request value and tests the result), `in place` (every data-changing route shows its own check). Strings, comments, request data and the names that hold it are blanked before the handler is read; an auth word must be a whole segment of a name (`get_token`, `has_permission`, `OAuth2PasswordBearer`; never `tokenize`, `load_permissions`, `protect_zone`, `author`) and counts only as a call or an attribute (`authorize(...)`, `user.is_admin`), never as a bare name, parameter or assignment target (`permissions = payload.get("permissions")`); a parameter counts through a dependency, type or caller name (`Depends(get_current_user)`, `CurrentUser`, `current_user`), not through its name alone (`permissions: list[str]`); `get_user(token)` counts, `get_user(payload["owner"])` never does. `LW-AUTH-MISSING` uses the same reading and both name the same sign | `websec.login_check`, `body_auth_sign`, `signature_sign`, `auth_word`, `segments`, `code_only`; `protections._global_auth_signs`; `tests/test_protections.py`, `test_missing_auth_reads_the_handler_not_its_comments` | A protection reported missing when a library you use provides it; a check hidden in a bare local flag or a neutrally named helper (reported as add/check, the safe side); `get_user()` with no argument is taken as a session read, deliberately. |

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
| E1 | Every Lens 3 phrase must anchor to a real symbol, a line range inside the unit, or a term that is a whole word or name in the code (3+ characters, with a letter; line numbers excluded) or in the glossary; otherwise the explanation is rejected | `explain.validate`, `tests/test_explain.py` | Anchors to symbols outside the allowed set, line ranges outside the function, terms that only appear in comments a hostile repo planted. |
| E2 | The UI says plainly when code goes to a cloud model, and offers local models | Settings and Explanations screens, Atlas button note | Any path that sends code without that notice (e.g. `openai-compatible` pointed at a remote host is treated as cloud unless the URL is localhost). |
| E3 | Explanations are cached by a hash of each function's code | `explain.Cache` | Change only a callee; check whether a stale explanation is reused. |

## Evidence Report

| # | Claim | Evidence | Try to break it |
|---|---|---|---|
| V1 | Pinned to a commit, and flags uncommitted changes | `evidence.git_info`; `tests/test_evidence.py` | Analyze a subfolder of a repo; analyze with untracked files (not counted as dirty: only tracked changes are). |
| V2 | `lantern verify` re-runs the analysis the same way (scan on/off, trace, offline) and compares a digest of the deterministic results | `digest_payload` (`run`), `cmd_verify`; `test_verify_replays_no_scan`, `test_verify_replays_a_trace_only_when_the_verifier_types_it` | Nondeterminism: run twice and compare; different machines; different bandit versions; dependency advisories published between runs (stated in Limits and in verify's output). |
| V5 | "Fixed" means the flagged code is gone: moving it is not a fix, and editing it shows "changed, still open" | `security.stable_ids`, `evidence.compare_baseline`; `test_moving_a_line_is_not_a_fix`, `test_editing_the_flagged_line_is_changed_not_fixed` | Rename the file; split the line in two; change the rule's wording. |
| V3 | The digest is not a signature, and the report says so | Section 7 text | |
| V4 | The Limits section states what the report does not prove | `evidence.limits` | Missing limits for situations you can construct. |

## Local app

| # | Claim | Evidence | Try to break it |
|---|---|---|---|
| L1 | One command runs it: `lantern serve PATH` | README; `tests/test_server.py` | Fresh machine, fresh venv, Windows, Python 3.11. |
| L2 | Only this computer can use it, and other websites can't drive it | 127.0.0.1 bind, token link + SameSite=Strict cookie, `X-Lantern-Token` on writes, Host check | See THREAT_MODEL T2. |
| L3 | Keys stay in memory unless "remember" is ticked, then 0600; the API never returns them | `Store.set_key`, `test_keys_stay_private` | Logs, job errors, tracebacks, or reports that echo a key. |
| L4 | Works offline for recently opened reports (PWA) | `viewer/sw.js` | Stop the server and reload an opened report. |
