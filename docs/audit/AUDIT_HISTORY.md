# Audit history

## 2026-10-30 · DeepSeek, commit 39d7b4c

An outside LLM audit, done on Windows 11 and Linux (WSL2). The full report is kept outside the repository; this table
records each finding and what changed. Fixed in PR #7 (Windows and the local app), PR #8 (verification integrity),
and PR #9 (security coverage).

| Audit § | Finding | Severity | Status |
|---|---|---|---|
| 2.1 | Files read/written in the system code page: `analyze` crashed before writing the report on Windows, `serve` returned nothing | critical | Fixed (#7): UTF-8 everywhere, Windows CI job with `PYTHONUTF8=0` |
| 2.2 | Backslash paths: no Next.js entry points (so no `LW-AUTH-MISSING`), test files not recognized, self-audit 44/F, `js:` ids with `\` | critical | Fixed (#7): `.as_posix()` at every boundary; CI checks the Next.js sample on Windows |
| 3.1 | A repo could plant `.lantern/security.json` and run script in the app (unescaped counts) | high | Fixed (#7): pages rebuilt from templates, values type-checked and escaped, nonce CSP |
| 3.2 | Session token injected into a repo-supplied `report.html` | medium | Fixed (#7): the token goes only into pages the server builds |
| 3.3 | `<!--<script>` in a docstring blanked the report | medium | Fixed (#7): data in a JSON block with `<`, `>`, `&` escaped; browser check in CI |
| 3.4 | Non-ASCII `?token=` dropped the connection | low | Fixed (#7) |
| 4.1 | Moving a line faked a "fixed" finding | high | Fixed (#8): ids from line text; "changed, still open" |
| 4.2 | `verify` couldn't verify `--trace` / `--no-scan` reports | high | Fixed (#8): run options in the digest and replayed; a trace command is typed by the verifier, never taken from the report |
| 4.3 | Lens 3 term anchors accepted `1`, `|`, `a` | medium | Fixed (#8) |
| 4.4 | Method-name guesses not disclosed; unresolved list truncated at 200 | medium | Fixed (#8): true totals kept; Limits counts name-guessed edges (they were already only "likely"/"possible") |
| 4.5 | `fetch(url, opts)` with opts in a variable linked to GET at "confirmed" | medium | Fixed (#8): unknown verb is `ANY`, never confirmed |
| 4.6 | `"reason": "x"` silenced `--fail-on` | medium | Fixed (#7): the loader requires a real reason |
| 4.7 | Readiness evidence strings that were false (unreadable package.json "pinned") | medium | Fixed (#8). Gaming the score with placeholder files remains possible and is stated in Limits |
| 4.8 | `super()` uses BFS, not C3 MRO; parameter shadowing | low | Open (backlog: type-aware resolution) |
| 5.1–5.2 | No npm audit; pip-audit only for requirements*.txt | gap | Added (#9) |
| 5.3 | No data flow for "critical" | gap | Partly (#9): critical now needs the flagged line to use a parameter or request data; cross-function taint is still open |
| 5.4 | Spec 9.4 "protections to add" not built | gap | Added (#9) |
| 5.5–5.9 | JS runtime tracing, permission model, git-history secrets, container/CI review, more frameworks | gap | Open (backlog) |
| 5.10 | Digest doesn't cover explanations | gap | Stated in Limits (#8) |
| 5.13, 5.15 | No Windows CI; browser test not in CI | gap | Added (#7) |

Not tested by that audit, and still worth trying: flask and rich benchmarks, cross-machine digests, real cross-origin
CSRF, concurrency in the server, regex/CPU exhaustion on adversarial repos, `--host 0.0.0.0`.

## 2026-10-30 · re-audit of commit a78e7d8

The same auditor retested every finding above and confirmed all ten fixed, then found three new problems and one
wording bug. Fixed in the pull request after #9 (see the git history for its number).

| # | Finding | Severity | Status |
|---|---|---|---|
| N1 | The viewer still put some fields into HTML raw (`f.rank`, `k.status`, `R.score`, `R.grade`, line numbers, counts): editing only the data block of a report ran script in whoever opened it. A report opened from disk had no Content-Security-Policy at all | high | Fixed: every value from the data goes through `esc()`; values used as class names go through `cls()` (known words only) and lookups keyed by data through `pick()`. `render()` now writes a `<meta http-equiv="Content-Security-Policy">` that allows only scripts whose SHA-256 it lists, so inline handlers and `javascript:` URLs planted in the data are refused even without a server (verified in Chromium: the old viewer plus the policy shows the markup but runs nothing). CI opens a report whose every string and number carries an HTML payload (`tools/poison_report.py`) at desktop and phone size and fails if anything lands as markup or the title changes. The old viewer fails that check 22 ways; the new one passes |
| N2 | "Login check on routes that change data: in place" on an app with no login check: the status only came from `LW-AUTH-MISSING`, which needs a frontend call it could link | medium | Fixed: the protection checks every data-changing route itself (decorator, parameters, functions it calls within 3 hops, and what the handler body mentions), and has a third status. `add`: no sign anywhere. `check`: an app-wide mechanism exists (middleware, router dependency, auth library) but the code does not show it covers these routes. `in place`: every such route shows its own check. Sign-in, sign-up and webhook routes are expected to be public; `/authors` no longer counts as "auth" |
| N3 | `cmd = request.args.get("cmd")` then `subprocess.run(cmd, shell=True)` was ranked high, not critical, and the report printed a false sentence ("this line uses no parameter or request data") | medium | Fixed: `_input_on_line` follows assignments inside the function in order (parameters, request data, loop and `with` targets, destructuring, multi-line statements) and names the chain: "`cmd`, which line 9 sets from request data `request.args`". Still local to one function, and the sentence now says so. Same for Express handlers |
| N4 | `deps-pinned` skipped with "no dependency manifest" on a library whose `pyproject.toml` declares dependencies | minor | Fixed: `pyproject.toml` (`[project]`, optional groups, PEP 735 groups, Poetry), `Pipfile` and `requirements*.txt` are read in every project shape; the fix text for a library says bounds, not exact pins; a manifest with no dependency list is reported as such |
| – | Found while building the starter apps: `VITE_OPENAI_API_KEY` was not flagged as a public secret (`API_KEY` was not a secret word); pip-audit listed the same advisory twice and the same CVE under two ids | low | Fixed: `*_API_KEY` behind a public prefix is flagged unless the key is meant for the browser (Firebase, Maps, reCAPTCHA, analytics, ...); advisories are merged by id and alias, lowest id first |
| – | `tools/viewer_smoke.js` tripped Lantern's own `LJ-EVAL` rule on Playwright's `$$eval` | – | Rule fixed (`$eval`/`$$eval` are not `eval`); the self-audit stays clean |

Process notes from this round: the refreshed audit packet is now written as `LANTERN_AUDIT_PACKET-<commit>.md` so a
download never shadows the previous one. Still untested: flask and rich benchmarks, cross-machine digests, real
cross-origin CSRF, server concurrency, regex exhaustion, `--host 0.0.0.0`, and an npm scoped-registry override
through a repo `.npmrc`.
