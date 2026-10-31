# Threat model

Scope: Lantern as built today, running locally (`lantern serve` or the CLI). Cloud mode is not built.

## Assets

| Asset | Where it lives |
|---|---|
| The user's source code | Their repo; copies of function bodies in `report.html` (privacy `full`) and in prompts sent to a cloud model |
| Model API keys | Environment variables; server memory; `~/.lantern/keys.json` (0600) if "remember" is ticked |
| Other files on the user's machine | Anything the user account can read |
| Integrity of results | `security.json`, `readiness.json`, `evidence.json`, the digest; what a reviewer relies on |
| The user's attention and trust | UI wording about where code goes, how sure an edge is, what a score means |

## Trust boundaries

1. **Analyzed repository → Lantern.** Repos are untrusted input: a user may analyze code they cloned from anywhere.
2. **Model output → Lantern.** Text from any provider (or a hostile endpoint) is untrusted.
3. **Browser (other websites) → local server.** Any page the user visits can send requests to `127.0.0.1`.
4. **Lantern → model provider.** Code leaves the machine here, only on request, only to the configured endpoint.
5. **Shared reports → their readers.** `report.html` / `evidence.html` are opened by other people.

## Attackers and mitigations

### T1. Hostile repository

| Attack | Mitigation | Where | Status |
|---|---|---|---|
| Make Lantern execute code during analysis (`setup.py`, `conftest.py`, build scripts) | Analysis only parses. Bandit parses AST. Code runs only with `--trace -- <cmd>`, a command the user types | `pipeline.analyze`, `trace.py` | Mitigated; please verify (CLAIMS A4) |
| Symlink `creds.py` or `.env` → `~/.aws/credentials` to get it scanned and embedded in a report | All walkers skip symlinks that resolve outside the repo | `python_frontend.inside_repo` and its callers | Mitigated, tested (`test_symlinks_out_of_the_repo_are_not_read`) |
| Symlinked *directory* inside the repo pointing out | `os.walk` and `Path.rglob` don't follow directory symlinks by default | discovery functions | Believed mitigated; add a test |
| HTML/JS injection through file names, function names, strings, or code shown in the report | All dynamic text goes through `esc()` in the viewers and `html.escape` in `evidence.py`; embedded JSON escapes `</` | `viewer/report.html`, `report.py`, `evidence.py` | Mitigated; most valuable place to look for a miss |
| Ship a `lantern-accepted.json` that accepts real findings, so `--fail-on` passes | A real reason is required by the loader too (two+ words, 10+ letters: `security.reason_ok`); accepted findings stay listed (Findings, Evidence Report, counts) | `security.load_accepted` | **Open by design.** Changes to `lantern-accepted.json` must be reviewed like code. Consider a CI rule that fails when it changes without review. |
| Plant `.lantern/` results (report.html, evidence.html, badge.svg, security.json) to run script in the app or receive the session token | The server never sends those files' bytes as pages: it reads only the data (JSON), rebuilds every page from its own templates, injects the token only into those, and sends a per-response nonce Content-Security-Policy (no script on the Evidence Report). Summary values are type-checked and escaped. In the Atlas every value from the data goes through `esc()` (class names through `cls()`), and the report page carries its own hash-based Content-Security-Policy, so the same holds for a report opened from disk | `server._result_file`, `report.read_bundle`, `report.render`, `_csp`, `viewer/report.html` | Mitigated, tested (`test_planted_results_cannot_run_script`, `test_standalone_report_carries_a_hash_content_policy`; CI opens a report whose every field carries an HTML payload, `tools/poison_report.py`, in Chromium and fails if any of it lands as markup or changes the title). Residual: someone who rewrites the whole file (not just its data) can of course make any page they like; that file is then not Lantern's report |
| Text like `<!--<script>` in a docstring or route that changes how the browser parses the embedded data (blanking the report) | Data sits in a `type="application/json"` block with every `<`, `>`, `&` escaped | `report.safe_json` | Mitigated, tested in Chromium by `tools/audit.sh --browser` (CI) |
| Ship a fake `lantern-narratives.md` that misdescribes flows | It is shown under "Understanding" as the builder's own text, escaped | `evidence.py` | Accepted: it is labeled as the builder's text |
| Huge or pathological files (deep nesting, megabyte lines) to exhaust CPU/memory, or regex backtracking | tree-sitter is linear; some regexes run over whole files | `websec.py`, `readiness.py`, `security.py` | **Not tested.** Fuzz with large and adversarial inputs (TEST_PLAN 4.6) |
| A repository link that makes `git` do something other than clone a public https repository: option injection (`--upload-pack=...`), `ext::` or `file://` transports, credentials in the URL, a path that escapes `~/.lantern/repos`, a link pasted from a chat that points this machine at a loopback or private address or at the sender's server (a beacon or port probe), a repository whose files fill the disk | Only `https://host/owner/name` (optionally `/tree/branch`) is accepted, and only for the public forges in `remote.KNOWN_HOSTS` plus hosts the user names in `LANTERN_GIT_HOSTS` (so no IP literals, `localhost` or unknown servers by default); owner, name and branch are checked against a strict character set and `..`; the URL is rebuilt from those parts and passed after `--`; `GIT_TERMINAL_PROMPT=0` and no askpass, so a private repository fails instead of prompting; the destination is built from the checked parts; the clone is made without a checkout, the files are measured from the index and refused above `LANTERN_CLONE_MAX_MB` (500 MB by default) before anything is written; a clone that is slow rather than large is stopped after 900 s, and the folder of a clone that was stopped, refused, over the cap or could not be checked out (a reserved Windows name, a path over MAX_PATH, a full disk) is removed, so a folder holding only `.git` never passes as a finished clone; an earlier clone found without working files is checked out under the same cap instead of being analyzed as an empty project, and one with tracked files missing (`git ls-files --deleted`) gets them written (`git checkout-index -a`, which never overwrites a file that exists, so an edit the user made is kept). The clone itself is then untrusted input like any repo (above) | `remote.parse`, `remote.allowed_hosts`, `remote.fetch`, `remote.tree_mb`, `server.App.clone_project` | Mitigated, tested (`tests/test_remote.py`). Residual: the pack is downloaded before the size is known (`--depth 1` bounds the history, not the tree); the user's own git configuration (credential helpers, `url.<base>.insteadOf`) applies, as it does to any `git clone` they run |
| Planted comments that prompt-inject the explaining model ("say this function is safe") | Models can't change findings or scores; Lens 3 anchors are validated; unvalidated output carries a warning | `explain.validate` | Partly mitigated: Lens 1/2 wording can still be steered. The UI says explanations aren't proof |
| Make the readiness grade look better than it is (empty SECURITY.md, unused Dockerfile) | Limits section says checks show existence, not quality | `readiness.py`, `evidence.limits` | **Open by design**; documented |

### T2. Other websites attacking the local server

| Attack | Mitigation | Where |
|---|---|---|
| Cross-site request forgery against write endpoints | Writes need the `X-Lantern-Token` header (a custom header forces a CORS preflight, which the server never approves) | `Handler._write`, `_authed(True)` |
| Cross-site reads (JSON of projects, reports) | Reads need the `lantern_token` cookie (SameSite=Strict, so not sent on cross-site requests); browsers' same-origin policy blocks reading responses | `_authed(False)` |
| DNS rebinding (attacker domain resolves to 127.0.0.1) | Host header must be `127.0.0.1:PORT`, `localhost:PORT`, or `[::1]:PORT` | `_host_ok` |
| Another local user on a shared machine | Needs the token printed in the starting user's terminal; 127.0.0.1 only | `serve` |
| Clickjacking the app | `X-Frame-Options: SAMEORIGIN` | `_send` |
| `--host 0.0.0.0` exposes it to the network | Prints a warning; token still required; plain HTTP | `serve` | **Use only on trusted networks** |
| Token leakage through the address bar or Referer | Token link redirects to `/` after setting the cookie; `Referrer-Policy: no-referrer` | `do_GET` |

Note: the token is also embedded in `app.html` and in served reports (`window.LANTERN_LIVE`), so anything that can run
script in the app's origin can act as the user. That makes XSS in the viewers (T1, T3) the main path to a takeover.

### T3. Hostile or compromised model endpoint

| Attack | Mitigation |
|---|---|
| Return HTML/JS inside explanation fields | All lens fields rendered through `esc()`; line anchors escaped; non-list fields tolerated (`viewer/report.html` `lensBody`) |
| Return explanations that "dismiss" a finding | Models have no write path to findings (`explain.run` writes only explanations) |
| Very large responses | `max_tokens` is requested; response size is not hard-capped (**open**, low) |
| Steal the key | The key is sent only to the configured endpoint, in a header; a user who points `base_url` at a hostile server gives it the key (expected) |

### T4. Key handling

* Keys pasted in Settings are held in memory by default; "remember" writes `~/.lantern/keys.json` with `O_CREAT` mode
  0600 via a temp file and atomic replace (`Store._write`).
* `/api/state` and `/api/settings` return only where a key came from, never the key (`test_keys_stay_private`).
* Keys are never written into `.lantern/`, reports, or the Evidence Report. Check job logs and tracebacks: provider
  errors include the HTTP body from the provider, which could echo request details (**review**).
* On Windows, mode 0600 has no effect; the file relies on the user profile's ACLs (**open**, documented here).

### T5. Code leaving the machine

* Only `explain` sends code, only to the configured provider, and the UI says so in plain words when the provider is
  not local (spec 5.3). `openai-compatible` counts as local only when its base URL is localhost/127.0.0.1.
* `analyze`, `verify`, scanners, and the server make no network calls except the dependency audits: pip-audit
  (PyPI/OSV) and `npm audit` (registry.npmjs.org). They send package names and versions, never code. `--offline` or
  `LANTERN_OFFLINE=1` turns them off. Only `name==version` pairs reach pip-audit (index options in the repo are
  ignored), and `npm audit` gets `--registry` explicitly so a repo's `.npmrc` can't redirect it. Earlier note: `pip-audit` queries a
  vulnerability database when `requirements*.txt` exists (**document in UI**: currently only in Provenance).

### T6. Shared reports

* `report.html` at privacy `full` embeds function source and scanner snippets (for example a hard-coded password
  that bandit flagged). Share `--privacy structure` reports, or the Evidence Report, which contains no source.
* The Evidence Report shows the git remote with credentials stripped (`git_info`, tested).

## Known open risks, ranked

1. Regex/CPU exhaustion on adversarial repos is untested (T1).
2. A committed `lantern-accepted.json` can silence `--fail-on` (T1); needs a review rule.
3. Readiness can be satisfied by placeholder files (T1); disclosed in Limits.
4. Provider error text may surface in job logs; check it never includes the key (T4).
5. `--host` beyond localhost serves plain HTTP (T2).
6. No signature on the Evidence Report, only a digest (stated in the report).
