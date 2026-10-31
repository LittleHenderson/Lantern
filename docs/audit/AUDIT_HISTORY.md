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
wording bug. Fixed in PR #11.

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

## 2026-10-30 · re-audit of commit 17d8704

The same auditor confirmed all four findings above fixed and could not break the fixes or the two extras, then
found one medium and one low problem plus two notes. Fixed in PR #12.

| # | Finding | Severity | Status |
|---|---|---|---|
| R1 | A comment still counted as a login check: `# TODO: add auth here later` made `route-auth` "in place" with the evidence "handler mentions `auth`". `who = get_user(payload.get("owner"))` did too, although fetching the target user (the IDOR shape) says nothing about who is calling | medium | Fixed: strings and comments (including docstrings and `/* */`) are blanked before a handler is read. A user lookup (`get_user`, `getUser`, `find_user_by_...`) is a sign only when its argument identifies the caller (token, session, request, headers, cookies, or nothing); given a request value it is at most a weak sign (the result is tested), which makes the status `check` with the lookup named, and with no test it is no sign at all. `LW-AUTH-MISSING` now uses the same reading (`websec.login_check`) and names the lookup in its text, so the finding and the protection tell one story. When unsure the answer is `check`, never `in place` |
| R2 | Input taint survived reassignment: `cmd = request.args.get(...)` then `cmd = "ls -la"` stayed critical, and this was not in the known gaps | low | Fixed: a plain `=` whose right side has no request data or tainted name clears the name when the statement sits at the same block level as the one that tainted it (the function body for a parameter). `if not cmd: cmd = "ls"` is deeper, so it keeps the taint; so do `cmd += "x"` and `cmd = "nice " + cmd`. Documented in `CLAUDE.md` known gaps and CLAIMS S6 |
| – | Learn said "1 of 10 steps done" while listing 11 steps (the read-only step was outside the denominator) | note | Fixed: the counter reads "1 of 10 checked steps done · 1 to explore on your own", in the app and in `lantern learn --check`; `progress()` returns `explore` and a test checks that `total + explore` equals the number of listed steps |
| – | The project card's `shape` label was unvalidated text from `readiness.json` (escaped, so no script, but spoofable) | note | Fixed: the server passes a shape only when it is one of Lantern's six shape names (`readiness.SHAPES`); anything else becomes null, like a bad grade |

Still untested after this round: Firefox and Safari handling of the report's Content-Security-Policy meta, cross-machine
digests, flask and rich benchmarks, real cross-origin CSRF, server concurrency, regex exhaustion, `--host 0.0.0.0`,
and the `.npmrc` scoped-registry override.

## 2026-10-30 · re-audit of commit ca3fcb6

The same auditor confirmed all four round-three fixes on Windows and Linux (148 tests, self-audit clean, `tools/audit.sh`
ALL PASS), then found one medium and one low problem in the login check and reviewed the draft of PR #13. Fixed in PR #14.

| # | Finding | Severity | Status |
|---|---|---|---|
| Q1 | A payload field named like an auth word was read as a login check: `permissions = payload.get("permissions")` gave "in place" with the evidence "handler mentions `permission`", and so did `protected` and `auth_enabled`. Worse than the comment case, because it is the real data path: the handler reads what the caller claims | medium | Fixed: request data and everything reached from it (`payload.get(...)`, `req.body.x`, `params["y"]`) are blanked before a handler is read, then plain parameters and every local name assigned from either, followed in order. An auth word now counts only as a call or an attribute (`authorize(...)`, `current_user.is_admin`), never as a bare name or an assignment target (`settings.protected = ...`, `user.is_admin = True`). A parameter counts through a dependency, type or caller name (`Depends(get_current_user)`, `CurrentUser`, `Security(...)`, `current_user`), not through its name alone (`permissions: list[str]`, `is_admin: bool`); parameters injected by the framework (`Header()`, `Cookie()`, `Depends()`) or named for a credential (`token`, `authorization`) are never treated as data. A user lookup given a value that came from the request body (`token = payload.get("token")`) is now a weak sign like any other request value, unless the lookup is by token (`get_user_by_token(...)`). A bare `session` is no longer an auth word anywhere (`Depends(get_session)`, `db.session` are database sessions); `req.session`, `session.user` and `"x" in session` still are |
| Q2 | Finding and protection disagreed on a route the app calls whose only sign is a tested `get_user(payload.get("owner"))`: the finding named the lookup, the protection said `add` with "no sign of a login check". Also the finding's sentence "The handler only has `get_user(…)` looks up a user by…" read badly | low | Fixed: the protection's text is built from what was found, so a weak sign is named in its evidence and its sentence ("only look up a user by a value from the request… finds the record's owner, not who is calling") whether or not the finding fired, and "no sign" is said only of routes with none. The finding now reads "The only sign in the handler is that `get_user(…)` looks up a user by `…`, not by who is calling: that finds a record, not the caller" |
| – | `get_user()` with no argument counts as a strong sign (taken as a session read) | note | Kept, now listed under known gaps in `CLAUDE.md` and CLAIMS S8 |
| – | PR #13 (links): any https host was accepted, so a link pasted from a chat could point the user's machine at a loopback or private address or at the sender's host (a beacon or port probe); and `--depth 1` bounds the history, not the working tree, so there was no size cap | medium | Fixed: only the public forges (`remote.KNOWN_HOSTS`: GitHub, GitLab, Bitbucket, Codeberg, Gitea, sourcehut, Azure DevOps, Hugging Face, Gitee) plus hosts named in `LANTERN_GIT_HOSTS` are cloned, so IP literals, `localhost` and unknown servers are refused by default; the clone is made with `--no-checkout`, the files are measured from the index (`git ls-tree -r -l`) and refused above `LANTERN_CLONE_MAX_MB` (500 MB by default) before anything is written. The pack download itself is still bounded only by `--depth 1` |

Still untested: Firefox and Safari handling of the report's Content-Security-Policy meta, cross-machine digests, flask
and rich benchmarks, real cross-origin CSRF, server concurrency, regex exhaustion, `--host 0.0.0.0`, and the `.npmrc`
scoped-registry override.

## 2026-10-30 · re-audit of commit 23877e6

The same auditor confirmed both round-four fixes (request data is data; finding and protection name the same sign) on
Windows and Linux (185 tests, self-audit 0/0/0, `tools/audit.sh` ALL PASS) and audited the repository-link feature as new
code: 18 of 18 links behaved (loopback, private addresses, look-alike hosts, `http://`, `git://`, credentials, `..`,
`..%2f` and an option-shaped branch refused; GitHub, GitLab, Codeberg and `git@host:owner/name` accepted;
`LANTERN_GIT_HOSTS` only while set), the size cap refused a 1.25 MB repository at `LANTERN_CLONE_MAX_MB=1` and the folder
was gone afterwards, the server answered 400/403/202 as designed, and the CLI analyzed a public repository end to end.
Two things remained. Fixed in PR #15.

| # | Finding | Severity | Status |
|---|---|---|---|
| R1 | A helper whose name merely contains an auth word turned the login tick green: `words = tokenize(payload.get("text"))` gave "in place" with the evidence "calls `tokenize`" (the substring `token`); so did `load_permissions(...)` and `protect_zone(...)`. The unsafe mirror image of the documented "a check hidden behind `load()` is missed" | low/medium | Fixed: auth words match whole name segments. A name is split on `_`, `.`, `$` and camelCase (`websec.segments`: `getServerSession` → "get server session", `OAuth2PasswordBearer` → "o auth 2 password bearer") and a word must match between word boundaries (`websec.auth_word`), in decorators, parameter types and defaults, called functions and the handler's own lines alike. `get_token`, `has_permission`, `protectedProcedure`, `AuthGuard` and `jwt.decode` count; `tokenize`, `load_permissions` (plural: a list, not a check), `protect_zone`, `count_tokens`, `generate_csrf_token`, `guard_rail` and `author` do not. `protect` and `requires` count only as a whole name (`protect()`, Starlette's `@requires(...)`); `getSession`/`useSession`/`getServerSession` count only in JavaScript, where they read the login, since a Python `get_session` is a database session |
| R2 | The size-cap message rounded both numbers to whole megabytes: "files add up to 1 MB, above Lantern's 1 MB limit" for a 1.25 MB repository at a 1 MB cap | low | Fixed: one decimal ("1.3 MB, above Lantern's 1 MB limit") |
| – | From the untested list: a clone that is slow rather than large | note | `git` is stopped after 900 s with a plain message; the partial folder it leaves is now removed, as is the folder of a clone git itself refused (`tests/test_remote.py`). The name-blanking pass was made linear in the number of names and a 100 KB hostile handler (unbalanced brackets, long chains, escaped quotes, 1,500 chained names) is read in bounded time (`tests/test_fullstack.py`). Cross-site writes were already covered: a write needs the token in the `X-Lantern-Token` header, which a page on another origin cannot add, and the cookie alone is refused (`tests/test_server.py`); `npm audit` was already pinned to the public registry so a repository's `.npmrc` cannot redirect it (`tests/test_depaudit.py`). With `--host 0.0.0.0` the Host check still admits only `127.0.0.1`, `localhost`, `[::1]` and `LANTERN_ALLOWED_HOST`, so a request from another machine is refused until that variable names the address used |

Still untested: Firefox and Safari handling of the report's Content-Security-Policy meta, cross-machine digests, flask
and rich benchmarks, real cross-origin CSRF in a browser, server concurrency.

## 2026-10-30 · re-audit of commit 124fb98

The same auditor confirmed both round-five fixes (whole-segment matching, with `Depends(get_session)` staying `add`; the
one-decimal size message) and tried the three newly covered areas: timing stayed bounded on 800 hostile handler lines, a
50,000-quote string and a 100,000-character unterminated string; clone cleanup held for a timeout, a real git refusal
(nonexistent branch) and the size cap; `--host 0.0.0.0` stayed closed without `LANTERN_ALLOWED_HOST` set at startup
(189 tests on Windows and Linux, self-audit 0/0/0, `tools/audit.sh` ALL PASS). Two things remained. Fixed in PR #16.

| # | Finding | Severity | Status |
|---|---|---|---|
| S1 | A failed checkout left an empty clone, and the retry silently analyzed nothing. `fetch()` cleaned up after a timeout, a refusal and an over-size tree, but not when `git reset --hard` failed (reproduced with a repository holding `aux.txt`, a reserved Windows name; also a path over MAX_PATH or a full disk). The folder kept only `.git`, so the next attempt took it for an existing clone, ran `git pull --ff-only` (exit 0) and returned it without a checkout and without the size cap; `lantern analyze` then reported 0 files, 0 functions as a successful run | low/medium | Fixed: the checkout failure removes the folder like the other three paths (`remote._checkout`), and an earlier clone found without working files is checked out, under the same cap, before it is returned (`remote.has_files`). The app forgets a project whose clone left nothing behind (`server.App.clone_project`). Tests: `tests/test_remote.py`, `tests/test_server.py` |
| S2 | Bare `verify` still counted: `verify_signature`, `verify_payment`, `verify_age` gave "in place", so a checkout route that verifies a payment was told it already had a login check | low | Fixed: `verify` counts only with the caller as its object (`verify_token`, `verify_jwt`, `verify_session`, `verify_user`, `verify_password`, `verify_otp`, `verify_credentials`); `verify_payment`, `verify_signature` and `verify_age` are nothing. The finding's list of example words no longer names `verify` or `session` |
| – | Process: the refreshed packet for 124fb98 did not reach the auditor's Downloads folder | note | The packet and source files are attached to the reply as downloadable files and kept in the project Library under `lantern/audit/` |

Still untested: Firefox and Safari handling of the report's Content-Security-Policy meta, cross-machine digests, flask
and rich benchmarks, real cross-origin CSRF in a browser, server concurrency.

## 2026-10-30 · re-audit of commit 6f9ffeb

A clean pass. The same auditor re-tested every change in PR #16 and found nothing to report: a failed checkout left
nothing behind (the reserved-name fixture, plus one with a writable file and a reserved one in a subfolder); a
`.git`-only folder was completed through the same checkout, so the size cap applied; the running app forgot a project
whose clone failed; `verify_payment`/`verify_signature`/`verify_age` gave `add` and `verify_token`/`verify_session`/
`verify_password`/`verify_credentials`/`verify_jwt`/`authenticate_user` gave `in place`, with no regression on
`tokenize`/`get_token` (192 tests on Windows and Linux, self-audit 0/0/0, `tools/audit.sh` ALL PASS, CI green). Two notes,
neither a defect, applied in PR #17.

| # | Note | Severity | Status |
|---|---|---|---|
| T1 | API-key checks were missed, in the safe direction: `verify_api_key(...)` and `check_api_key(...)` gave `add`, a false alarm rather than a false pass | note | Applied: `verify`, `check`, `validate` and `require(s/d)` followed by `api key` count (`verify_api_key`, `check_api_key`, `require_api_key`); `get_api_key` and `create_api_key` still do not |
| T2 | The `.git`-only repair tested `has_files()`, which is true as soon as anything but `.git` exists, so a checkout that stopped part-way (not reproducible with current git, code reading only) would have passed as complete. `git diff --quiet HEAD` was suggested | note | Applied with a narrower test than suggested: `git ls-files --deleted` lists tracked files missing from the working tree, and `git checkout-index -a` writes exactly those (it never overwrites a file that exists), so a file the user edited in the clone is kept. `git diff --quiet HEAD` would also flag edited files, and completing the checkout with `reset --hard` would have discarded them. A clone that still has files missing afterwards is refused with a message naming the first |
| – | Process: the packets for 124fb98 and 6f9ffeb were attached to the thread but the auditor runs in WSL and reads only the Downloads folder | note | The reply names the three attached files to download; the project Library keeps the same files |

Still untested: Firefox and Safari handling of the report's Content-Security-Policy meta, cross-machine digests, flask
and rich benchmarks, real cross-origin CSRF in a browser, server concurrency.

## 2026-10-31 · re-audit of commit 402a1c0

The same auditor confirmed both round-seven changes: `verify_api_key`, `check_api_key`, `require_api_key` and
`validate_api_key` give `in place`, `get_api_key` and `create_api_key` give `add`, and all twelve words fixed in rounds
four to six still behave. A real part-way checkout (index populated, two of four files present, one edited by hand) was
repaired with only the missing files written and the edited one kept, and a repair that cannot write a file (a file
standing where its folder belongs) was refused with the file named (194 tests on Windows and Linux, self-audit 97/100 A,
`tools/audit.sh` ALL PASS, CI green on all five jobs). One low finding. Fixed in PR #18.

| # | Finding | Severity | Status |
|---|---|---|---|
| U1 | A clone whose repair was refused stays on disk, and the app keeps its card, because `clone_project` forgets a project only when `has_files()` is false. Re-analyze, or `lantern analyze <folder>`, then analyzed the incomplete tree with no warning and exit 0 (`graph 1 files`, `sub/c.py` still missing): a missing file is a place a finding could have been. Related: `missing_files()` returned `[]` when `git ls-files` itself failed, which reads as "nothing missing" | low | Fixed: `pipeline.analyze` starts by refusing a folder Lantern cloned whose files are not all there ("this clone has 1 missing file(s), starting with sub/c.py. Remove … and try again, or clone it yourself and add the folder"), which covers the CLI, Re-analyze and every other analysis path; the CLI prints it and exits 2. `missing_files()` returns `None` when git cannot list the files, and both the repair and `analyze` refuse in that case. Only Lantern's clones are checked (`remote.is_clone`: a `.git/lantern-clone` mark written at clone time, or a folder under `LANTERN_HOME/repos` for clones made before the mark), because in a git folder of your own a deleted file is your change and is analyzed as it is. Tests: `tests/test_remote.py` |
| – | Process: the 402a1c0 packet still did not reach the auditor's Downloads folder | note | The reply names the three attached files to save into `C:\Users\wakil\Downloads` |

Still untested: Firefox and Safari handling of the report's Content-Security-Policy meta, cross-machine digests, flask
and rich benchmarks, real cross-origin CSRF in a browser, server concurrency, a clone that is genuinely slow.

## 2026-10-31 · re-audit of commit 45a3c86

The same auditor confirmed PR #18 on five cases: a marked clone with a file deleted, an older clone under
`LANTERN_HOME/repos` without the mark, and a corrupted `.git/index` are each refused with exit 2; a git folder of your own
and a complete clone are analyzed. Then it covered five of the areas listed as untested. The report's
Content-Security-Policy meta holds in Chromium, Firefox and WebKit (poisoned reports inert, an injected `<script>` and
`onerror` blocked). The results digest is identical on Windows and Linux for the same clean commit (analyzing a `C:` tree
through WSL makes git see mode changes, so the tree counts as dirty and the digest differs; a native clone matches). The
flask benchmark reproduces the published figures exactly (95.5% resolved over 554, 97.0% inferred over 625, recall
57.0%). Cross-origin requests from a real browser on another origin get 403 or are blocked by CORS. Concurrency and a
slow clone each gave a finding (197 tests on Windows and Linux, self-audit 97/100 A, `tools/audit.sh` ALL PASS). Fixed in PR #19.

| # | Finding | Severity | Status |
|---|---|---|---|
| V1 | The clone timeout did not bound the call. Against a server that accepts the connection and never answers, `remote.fetch(..., timeout=2)` returned after 300 s on Windows: `subprocess.run` killed `git.exe`, then (on Windows only) waited in `communicate()` for the output pipes, which `git-remote-https.exe` still held. The app's clone job showed "running" for those 300 s | medium/low | Fixed: every git call goes through `remote.run_bounded`, which starts the command in its own process group (a new session on POSIX, `CREATE_NEW_PROCESS_GROUP` on Windows), kills the whole tree at the timeout (`killpg`, `taskkill /F /T`), and stops waiting for a pipe that something outside the tree still holds. Tests: a command whose child keeps the pipes open returns within the timeout, and a clone from a silent server on a local port stops after 2 s with nothing left behind (`tests/test_remote.py`) |
| V2 | Two app instances sharing `~/.lantern` lost projects: of six simultaneous adds across two servers, one returned 500 and four were kept. `Store.lock` was a thread lock, so each process read, changed and wrote `projects.json` over the other's change, and every write went through the same `projects.tmp` | low | Fixed: `Store` writes under `server.FileLock`, an OS lock on `store.lock` (`flock` on POSIX, `msvcrt.locking` on Windows) held around each read-modify-write, and each write uses a temporary file of its own before an atomic replace (retried briefly when Windows refuses to replace a file being read). Test: four processes adding 15 projects each at the same moment keep all 60, and no temporary file is left (`tests/test_server.py`) |
| V3 | A port in a link was dropped: `https://git.example:8443/o/r` was cloned from port 443, so a self-hosted forge on another port failed with a confusing error even when allow-listed | low | Fixed: the port is kept in the clone URL (443 is dropped as the default). In `LANTERN_GIT_HOSTS`, `host` allows any port on that server and `host:port` only that port; the public forges are accepted only on 443, since `github.com:8443` is not GitHub's service. A port above 65535 is refused. Test: `tests/test_remote.py` |

Still untested: rich in the benchmark, a clone that stalls mid-transfer (after the handshake), concurrency beyond the
cases above, and Safari on macOS (Playwright's WebKit was used).
