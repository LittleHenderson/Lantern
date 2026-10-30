# Test plan

## 1. Automated checks (run these first)

```bash
bash tools/audit.sh              # everything below except the browser step; about 1 minute
bash tools/audit.sh --browser    # adds the Chromium viewer and app checks
```

| Step in `tools/audit.sh` | Command | Pass when |
|---|---|---|
| Unit and integration tests | `python -m pytest -q` | all pass (88 at the time of writing) |
| Self-audit | `lantern analyze . --out $W/self --fail-on medium` | exit 0 |
| Sample: React + FastAPI | `lantern analyze tests/fixtures/shop` | 2 critical, 2 high; shell injection path from `/admin` |
| Sample: Next.js + Supabase | `lantern analyze tests/fixtures/nextapp` | finds `LW-AUTH-MISSING`, `LW-NO-RLS`, public service-role var |
| Determinism | `lantern verify` on a temp git repo against its own report | MATCH, then DIFFERENT after a code change |
| CLI surface | `lantern --help`, `starter`, `accept`, `evidence` | exit codes as documented |
| Offline model end to end | `tools/fake_model.py` + `lantern explain --model openai-compatible/demo` | explanations validated for the demo units |
| Browser (optional) | `node tools/viewer_smoke.js` | "no JS errors" at desktop and phone sizes; also on a report whose every field carries an HTML payload (`tools/poison_report.py`): nothing lands as markup, the title never changes |

CI runs the tests and the self-audit on Python 3.11, 3.12, and 3.13 for every push (`.github/workflows/ci.yml`).

## 2. What the test files cover

| File | Covers |
|---|---|
| `tests/test_frontend.py` | Python resolution: imports, classes/MRO, `self`/`super`, type hints, properties, decorators, FastAPI `Depends`, pytest fixtures, entry points |
| `tests/test_fullstack.py` | JS/TS walker and resolver, Next.js/React Router/TanStack/Express entries, HTTP call extraction, bridge matching, web security rules |
| `tests/test_security.py` | Scanner orchestration, pinning, reachability, ranking, `.env` scanning, symlink containment |
| `tests/test_trace.py` | Runtime tracing and merge into the graph |
| `tests/test_explain.py` | Anchor validator: invented symbols, out-of-range lines, unknown terms, code identifiers in Lens 2, required finding explanations |
| `tests/test_providers.py` | Provider presets (including DeepSeek), key requirements, URL scheme checks |
| `tests/test_readiness.py` | Weights, failing and fixed projects, skip logic for libraries, fixtures ignored, accept + `--fail-on`, starter files never overwrite |
| `tests/test_evidence.py` | Commit pinning, verify match/mismatch, fixed-vs-baseline, narrative escaping, no-git message, remote credential stripping |
| `tests/test_server.py` | Access control (token, cookie, write header, Host), project lifecycle over HTTP, key privacy and file mode, explain end to end with the fake model |

## 3. Manual walkthrough (15 minutes)

1. `lantern serve tests/fixtures/shop`. A browser opens on Projects; the shop project shows grade F and 2 critical.
2. Open it. In Atlas, choose `/admin`, expand, and follow `BackupButton → on click → start → runBackup → HTTP POST
   /backup → backup`. The Flowchart view shows the same path.
3. Findings: the top item is `subprocess … shell=True` with the path from `/admin`. Press "Accept risk…", give a
   reason; after the re-run it shows "accepted risk" with your reason, and the counts drop.
4. Readiness: score and ten categories; each failed check has evidence and a fix. Press "Write file" on SECURITY.md;
   it appears in the folder; pressing again is refused.
5. Settings: pick `openai-compatible`, model `demo`, base URL `http://127.0.0.1:8799/v1` (after
   `python tools/fake_model.py 8799`). The screen says the model is local. Pick `anthropic` and confirm the warning
   that code will be sent to Anthropic.
6. Atlas → click `BackupButton` → "Explain with openai-compatible/demo". The three lenses appear. Lens 3 phrases
   highlight their technical twins.
7. Explanations tab → "Explain N functions"; the log shows ok and "rejected by the anchor check" lines (the fake
   model only knows some functions; rejections are expected and prove the validator runs).
8. Evidence Report: commit, scorecard, open/accepted findings, provenance listing the demo model, Limits, digest.
   Run the `lantern verify` command it shows.
9. Phone width (browser dev tools, 390 px): Projects, Atlas list, detail sheet, Findings, and Evidence are usable.
10. Stop the server, reload an opened report: the service worker serves the cached copy.

3b. **An existing repository from a link.** On Projects, paste `https://github.com/fastapi/full-stack-fastapi-template`
and press Add and analyze: the card appears at once with the clone log, then the analysis, then grade and findings.
`lantern analyze https://github.com/pallets/flask --offline` does the same from a terminal (the clone lands in
`~/.lantern/repos/github.com/pallets/flask`). A link with a token in it, an `http://` link, a link to a user
page, or a link to any host other than the public forges (`https://127.0.0.1/o/r`, `https://10.0.0.8/o/r`, your own
server unless it is in `LANTERN_GIT_HOSTS`) must be refused with a message that says why. With
`LANTERN_CLONE_MAX_MB=1`, a repository with a 2 MB file must be refused before any file is written. Measured 2026-10-30 on a 2-core container: the template clones
and analyzes in 3 s; Django (2,984 files, 33,000 functions) in about 90 s plus the clone (graph 24 s, scanners
56 s, readiness 2 s). Its report embeds every function's source and is 74 MB, so for a repository that size set
privacy to "structure" (Settings, or `--privacy structure`).

## 4. Adversarial cases to try

4.1 **XSS through the analyzed repo.** Create files and functions named `<img src=x onerror=alert(1)>` (valid as a
string in routes and JSX text, a filename on Linux), a route path containing `"><script>`, and a docstring with
`</script>`. Analyze, open `report.html` and `evidence.html`, and check nothing executes.

4.2 **XSS through model output.** Make `tools/fake_model.py` return `<script>` in `lens1.summary`, a string instead
of a list in `lens1.inputs`, and `{"type":"lines","start":"<b>1</b>"}` as an anchor. Explain and view.

Last run 2026-10-30 (Chromium, both report.html and evidence.html, every lens opened): no script executed for 4.1
or 4.2. Re-run after any viewer change.

4.3 **Local server from another origin.** From a page on `http://localhost:9999`, `fetch('http://127.0.0.1:8765/api/
state', {credentials:'include'})` and a form POST to `/api/projects/<id>/analyze`. Both must fail. Repeat with a
rebinding-style Host header: `curl -H 'Host: attacker.test:8765' …` must get 403.

4.4 **Path tricks.** Starter `name` values `../x`, `/etc/x`, `a/../../x`; a project path given as `~/../..`; a symlinked
directory inside the repo pointing at `$HOME`.

4.5 **Accepted-risk abuse.** Hand-write `lantern-accepted.json` with an empty reason, an unknown id, a non-list, and
invalid JSON. Lantern must ignore bad rows and keep working.

4.6 **Resource exhaustion.** A 50 MB minified JS file, a 10,000-level nested expression, a line of 1 MB of `(`, a
repo with 100,000 empty files, deeply nested directories. Note time and memory for `lantern analyze`.

4.7 **Honesty checks.** Pick five edges labeled "confirmed" and five "likely" in a real repo you know, and check each
by hand. Pick three readiness passes and confirm the evidence text is literally true.

4.8 **Determinism.** Run `lantern analyze` twice on the same commit and diff `evidence.json` `payload`. Only
`generated_at` and timings should differ, and they are outside the digest.

4.9 **Key leakage.** Set a fake key, trigger a provider error (wrong base URL, a server returning 401 with the request
echoed), and search `~/.lantern`, `.lantern/`, job logs (`/api/jobs/<id>`), and the terminal for the key.

4.10 **Heuristics that must not say "in place".** A data-changing route whose only login word is in a comment
(`# TODO: add auth here later`) or a docstring; one whose body does `who = get_user(payload["owner"])` with or
without `if not who:`; a route path `/authors`; `permissions = payload.get("permissions")` followed by a test on
`permissions`; `settings.protected = payload["protected"]`; a parameter `permissions: list[str] = Body()`; a route
whose only dependency is `Depends(get_session)`; `token = payload.get("token")` followed by a tested `get_user(token)`.
Expect `add`, `check` (lookup with a test), `add` (lookup without), `add` for the next five and `check` for the last.
Then `if not current_user.is_admin:`, `authorize(user, item)`, `get_user(token)` with `token: str = Header()`, and
`get_user_by_token(token)` must still give `in place`. A helper named with an auth word inside another word, called
from the handler and defined in the repo (`tokenize(payload.get("text"))`, `load_permissions(...)`,
`protect_zone(...)`), gives `add` with no "calls" evidence; renamed `get_token`, `has_permission`, `protect` it gives
`in place`. So do `verify_payment(...)`, `verify_signature(...)` and `verify_age(...)` (`add`) against `verify_token`,
`verify_session` and `verify_password` (`in place`). A 100 KB handler built to make the regexes backtrack (unbalanced brackets, a 3,000-step attribute chain,
5,000 escaped quotes, 1,500 chained names) is read in under five seconds. Then `cmd = request.args.get("cmd")` followed by `cmd = "ls -la"` (expect high, no input sentence) and
by `if not cmd: cmd = "ls"` (expect critical, naming the request line).

## 5. Pass criteria for a release

* All of section 1 passes on Linux with Python 3.11–3.13 and on Windows with Python 3.12 under stock settings
  (`PYTHONUTF8=0`, the system code page). CI runs both, plus `tools/audit.sh --browser` in Chromium. macOS is not in
  CI. (Before PR #7, Windows failed 24 of 88 tests; see `AUDIT_HISTORY.md`.)
* No critical or high issue open from sections 4.1–4.5 and 4.9.
* Section 4.6: analysis of a 100k-line repo finishes in under 60 s and under 2 GB.
* Every claim in `CLAIMS.md` is held or its text is corrected.
