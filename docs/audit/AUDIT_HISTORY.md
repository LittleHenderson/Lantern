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
