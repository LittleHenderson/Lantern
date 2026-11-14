# Architecture

Lantern is one Python package (`lantern/`, standard library plus tree-sitter grammars) with two front doors that call
the same functions: the command line (`lantern/cli.py`) and the local app (`lantern/server.py`). There is no hosted
service. The only network calls are to the model provider the user configures, the dependency audits
(PyPI/OSV via pip-audit, the npm registry via `npm audit`) and, since 2026-11-13, where the person has a project's
own tests run in the sandbox, the fetch of the libraries that project names (`lantern/libraries.py`: pip and npm
through Lantern's doorkeeper `lantern/_stores.py`, to PyPI and the npm registry or to the stores the person set).
`--offline` turns the audits and the fetch off.

## Pipeline

```
repo folder
  │
  ├─ engine.build_graph ─┬─ python_frontend   discover → tree-sitter parse → CallSites → Resolver
  │                      ├─ js_frontend       Walker (defs, imports, refs, HTTP calls, routes) → SpecResolver → JSResolver
  │                      └─ bridge.link       frontend HTTP calls ↔ backend routes (method + path segments)
  │        = Unified Code Graph (graph.py)
  │
  ├─ (optional) trace     run the user's command under sys.monitoring; edges seen running → "observed"
  ├─ security.scan        bandit, pip-audit, secret patterns/gitleaks, websec (LW-*/LJ-*), then flowscan.run
  │                       (request data followed across functions and files, LT-*; Python and JS/TS) → pin to
  │                       nodes → reachability from entry points → rank → accepted risks (lantern-accepted.json)
  ├─ readiness.assess     ten weighted categories of file/pattern/graph checks → score, advisor, starter files
  ├─ report.write_report  one self-contained report.html (viewer/report.html + embedded JSON)
  └─ evidence.build       commit-pinned evidence.html/.json, digest, badge.svg
                          (baseline.json from the first run gives "before" counts and "fixed" findings)

explain (on request)      select_nodes (entry points + N levels, bottom-up) → prompt → provider → parse →
                          validate anchors → retry once → cache by code hash → explanations.json → re-render
```

`lantern/pipeline.py` holds `analyze`, `explain`, `plan_explain`, and `rebuild_outputs`; the CLI prints their log
lines and the server streams them to the browser.

## Modules

| Module | Responsibility | Key functions |
|---|---|---|
| `graph.py` | Node/Edge dataclasses, confidence ranks, JSON round-trip, stats | `Graph.add_edge` keeps the strongest confidence |
| `calls.py` | Call-site inventory (Python and JS/TS): one record per call written in the code, keyed `file:line:col`, one outcome each, a reason for every unresolved one, groups written / handed / implicit, test code apart. The frontends call `record`; `engine.build_graph` ends with `finish` | `record`, `classify`, `why`, `finish`, `summarize`, `write` |
| `python_frontend.py` | Python discovery, parsing, name and type resolution | `discover`, `inside_repo`, `build_graph`, `Resolver` |
| `js_frontend.py` | TS/JS discovery, ES module resolution, React/Next/Express entry points | `add_js`, `Walker`, `SpecResolver`, `JSResolver` |
| `java_frontend.py`, `kotlin_frontend.py` | Java and Kotlin parsing, packages/classes/methods, call resolution (`name`, `import`, `receiver-type`, `interface`, …), Spring routes | `add_java`, `add_kotlin`, `Linker` |
| `swift_frontend.py`, `ios.py` | Swift parsing and call resolution (types, extensions, protocols, SwiftUI `body`); iOS apps from the Xcode project / Info.plist, screens and link handlers as entries, `LI-*` rules, the `security.mobile` summary | `add_swift`, `ios.add_entries`, `ios.scan` |
| `dart_frontend.py`, `flutter.py` | Dart parsing and call resolution (classes, mixins, extensions, widget `build`); Flutter projects from `pubspec.yaml`, screens and link listeners as entries, `LF-*` rules | `add_dart`, `flutter.add_entries`, `flutter.scan` |
| `csharp_frontend.py`, `dotnet.py` | C# parsing and call resolution (namespaces, partial classes, interfaces, ASP.NET controller and minimal-API routes, `HttpClient` calls); .NET MAUI / Xamarin projects from `.csproj`, pages, `[RelayCommand]`s and app-link handlers as entries, `LC-*` rules | `add_csharp`, `Linker`, `dotnet.add_entries`, `dotnet.scan` |
| `php_frontend.py` | PHP parsing and call resolution (namespaces, traits, typed properties, includes); Laravel/Symfony/Slim/WordPress routes and plain pages as entries; outgoing Guzzle/`Http::`/curl calls. `LH-*` rules live in `websec.php_rules`; the Composer audit in `depaudit.run_composer_audit` | `add_php`, `Linker`, `php_rules`, `run_composer_audit` |
| `ruby_frontend.py` | Ruby parsing and call resolution (lexical constant lookup, mixins, `@ivar` types, Active Record models); Rails routes and Sinatra blocks as entries, auth `before_action` filters as `middleware` edges, jobs as `main`; outgoing HTTParty/Faraday/Net::HTTP calls. `LB-*` rules live in `websec.ruby_rules`; the Gemfile.lock audit in `depaudit.run_gem_audit` | `add_ruby`, `Linker`, `ruby_rules`, `run_gem_audit` |
| `cpp_frontend.py` | C and C++ parsing (tree-sitter-c for `.c`, and for `.h` when the repo has no C++; tree-sitter-cpp otherwise) and call resolution; cpp-httplib/Crow/Drogon/Pistache routes, `main`, gtest/Catch2 tests as entries; libcurl and `httplib::Client` calls. `LX-*` rules live in `websec.cpp_rules`; C/C++ input reading in `security._c_line`/`C_REQUEST_DATA` | `add_cpp`, `Collector`, `Linker`, `cpp_rules` |
| `rn.py` | React Native / Expo projects from `package.json` + `app.json`; React Navigation and Expo Router screens, `Linking` handlers as entries (on the JS/TS map), `LN-*` code and `app.json` rules, the `security.mobile` summary | `rn.add_entries`, `rn.scan` |
| `bridge.py` | Match `g.meta["http_calls"]` to route entries | `link`, `match` |
| `trace.py`, `tracehook.py` | Runtime tracing (Python only), merge into graph | `run_trace`, `merge_trace` |
| `behave.py`, `_behave_inside.py` | Behaviour checks (`lantern behave`; `docs/behaviour.md`): the project's app (Python ASGI, SQLite) is started in the test sandbox from the project's plan `lantern-behaviour.json` and asked as the people who must be refused and as those who may; the rows and files are compared before and after every step. `behave.py` checks the plan (paths only, never an address), judges from what was recorded and writes `behaviour.json`; `_behave_inside.py` runs inside the sandbox (app copies over pipes, no socket; database failures made at each write; names answered inside). A record of its own: no finding reads it. Since 2026-11-11 it names the code it is of (`of.code_sha256`) and carries this computer's seal, and the release decision (`release.py`) counts it only when the seal holds and the plan and the code are the project's now | `load`, `check`, `scene`, `judge`, `run`; `Recorder`, `worker`, `token_variant` |
| `security.py` | Scanner orchestration, node pinning, reachability, ranking, accepted risks. A rank starts at the tool's own severity and who reaches the line can only raise it; it goes lower only on evidence written on the finding, for test code, or where a rule fixes it (`rank_basis`, `reachability` on every finding). Bandit is started with `--ignore-nosec` and Lantern reads a `# nosec` comment itself: with a written reason, on a line no request data was followed to, it is an accepted risk; otherwise the finding stays open and says so | `scan`, `reachability`, `rank`, `reach_state`, `nosec_says`, `load_accepted` |
| `android.py` | Android apps: manifest/network-config/Gradle reading (expat, entities refused), manifest entry points, `LM-*` rules, the `security.mobile` summary (permissions, components) | `find_modules`, `add_entries`, `scan` |
| `websec.py` | Full-stack rules (public env secrets, Supabase, Firebase, CORS, missing auth, JS patterns) | `scan_web` |
| `flow.py`, `flow_py.py`, `flow_js.py`, `flow_rules.py`, `flowscan.py` | Follow the data (Python and JS/TS; nothing of the project is run): both readers put a file into one small language, the engine follows a request's values through functions and files with a summary per function (what reaches its return value, what reaches a sensitive action, what its checks prove, what it asks about who is signed in: a login counts where the code shows that a request without one is turned away, whatever the function is called, and a record read into an object and later removed or saved through it counts as changed; a value carries the text it starts with, so an address that begins with written text, with a value of the server's own or with a path names its host itself and the request does not; what a library call the tables do not name gave back for the request's text is marked, `Val.lost`, and is not such a value), the tables name sources, sanitizers and what each is safe for, sinks and library calls that pass a value on; `flowscan` turns flows into findings (`LT-*`, or the steps on another tool's finding of the same problem), the four who-may-reach-what heuristics (`LT-AUTHZ-*`), `LW-AUTH-MISSING` for an open route that changes a record picked by an id, and the rank of a raw place in a page template (`LW-XSS-RAW`) | `flow.analyze`, `flowscan.run`, `fixed_evidence`, `raised_severity` |
| `templates.py` | Page templates, read as text with patterns: the places that print a value without escaping it (EJS, Handlebars and Mustache, Pug, Jinja, Django, Nunjucks, Twig) and the names of the page's values printed there; `websec.template_rules` makes the finding, the flow engine asks what the route handed the page under that name | `read`, `index`, `named` |
| `ratelimit.py` | Is a request limit on this route: where a limiter is put to work, route by route (`yes`, `own`, `maybe`, `no`), read by the "Rate limiting" protection and by `LA-WALLET-DRAIN`; a library that is only installed is no limit | `view`, `View.of` |
| `readiness.py` | Readiness checks, shape classifier, advisor, hotspots, starter files. `checklist` is the weighted average; `score` is that number as the release decision lets it stand. A check the release needs that was skipped because the work was not done keeps its points in the sum and earns none | `assess`, `counts`, `Repo`, `check_*` |
| `release.py`, `seal.py` | The release decision, apart from the score (2026-11-11): `Blocked` (a required criterion failed), `Incomplete` (nothing failed and required evidence is missing) or `Passed` (every required criterion that applies passed). Five criteria (`findings`, `scanners`, `tests`, `dependencies`, `behaviour`), each `passed`, `failed`, `missing` or `not-applicable` with its reason. The score is held at 59 while Blocked and under 100 until Passed. `bind` ties the decision to the commit, one SHA-256 over every file of the project, the files that list libraries, the settings of the run and every tool with its version. `shown` is the one way a decision read back from a file is taken (one of three words, bounded text, the rest worked out anew). `seal.py`: an HMAC-SHA256 under a key of this computer (`LANTERN_HOME/seal.key`) on a behaviour record | `decide`, `bind`, `score`, `shown`, `code_digest`; `seal.sign`, `seal.holds` |
| `evidence.py` | Evidence Report, digest, badge, git facts (through `gitfacts.py`). The digest takes the release decision, each criterion's state and the SHA-256s it is tied to; the badge is green only for a release that Passed | `build`, `digest_payload`, `render_html`, `git_info` |
| `gitfacts.py` | What git knows about an analyzed folder (commit, branch, uncommitted changes, address, missing files), read without obeying the folder's own git settings: `.git` read by hand, never through a link or a pointer that does not name the folder back; git started only from a git folder Lantern makes, with a fixed list of harmless settings. What of a repository lies outside the folder asked about is read only when it is the current user's or the person's `safe.directory` list names it (`_yours`; on Windows the owner is asked through `winowner.py`) | `info`, `deleted`, `head_commit`, `find`, `head`, `settings` |
| `explain.py` | Prompt, JSON parsing, anchor validation, scenario checks, selection, cache | `validate`, `check_scenarios`, `select_nodes`, `run` |
| `scenarios.py` | A short story per finding (who, steps, what goes wrong, after the fix, basis) and a plain heading, both from the finding's own facts; no model | `for_finding`, `headline`, `kind_of`, `attach` |
| `providers.py` | Anthropic, OpenAI-compatible presets, fixture stub | `make_provider` |
| `report.py` | Bundle data into `viewer/report.html`; inside the page the map is written column by column and read back as the same rows (`columns.py`) | `write_report`, `collect_sources`, `render`, `read_bundle` |
| `columns.py` | The map as a report holds it (2026-11-12): `nodes` and `edges` column by column, a value written once where every row has it, a node's id as its place in the list of nodes. What comes back is exactly what went in (rows, order of fields, kind of every value); a packed map of another shape is refused. Only a report is written this way; `graph.json` is as it was. The page's `unpackGraph` is the same reading in JavaScript | `pack_graph`, `unpack_graph` |
| `kept.py` | Work kept between runs, in `LANTERN_HOME/cache` (2026-11-12): how one Python file reads and what Bandit said about a set of files, each under one SHA-256 of the whole question (the file's bytes and name, the code that does the work: this Lantern, the Python that runs it, the parser libraries). Never in the project, data and never code, the current user's files only, never a finding, a rank, a score or a link between files. Off for `lantern verify`, cloud runs and `LANTERN_CACHE=off` | `Shelf.key`, `Shelf.get`, `Shelf.put`, `on`, `without`, `tally`, `tidy`, `clear` |
| `listing.py` | The project's files, looked up once for a whole run and shared by every reader (which files there are, never what they hold; outside a run every call walks the folder as before) | `one_run`, `files`, `once`, `fresh` |
| `quick.py` | Which line patterns can find anything in a file at all: pieces of plain text every match must hold, read from the pattern's own structure; a file with none of them is passed over for that pattern, and whenever it cannot tell the answer is "may match" | `needs`, `may_match`, `Text` |
| `server.py` | Local HTTP app, jobs, settings and keys store | `serve`, `Handler`, `Store`, `Jobs` |
| `viewer/app.html` | App shell: Projects, project tabs, Explanations, Learn and Guide, Settings (with Appearance), Help | vanilla JS |
| `viewer/report.html` | Atlas: map (path tree + flowchart), Findings (with severity filter), Readiness, About, node detail with lenses. Drops its own brand row when framed by the app | vanilla JS |

## Output files (in `PATH/.lantern/`, git-ignored by default)

| File | Contents |
|---|---|
| `graph.json` | `schema`, `repo_root`, `meta` (languages, files, lines, `http_calls`, `bridge` stats), `nodes[]` (`id`, `kind`, `qualname`, `file`, `start_line`, `end_line`, `fingerprint`, `signature`, `entry`), `edges[]` (`src`, `dst`, `kind`, `confidence`, `lines`, `via`, `detail`), `unresolved` |
| `calls.json` | `summary` (for `written`, `handed`, `implicit`, `in_tests`: `total`, `outcomes`, `reasons`, `by_via`, `with_several_targets`, `lines_with_several_calls`; `languages`, `not_inventoried`), `outcomes` and `reasons` (the words for each code), `sites[]` (`at`, `file`, `line`, `col`, `callee`, `caller`, `lang`, `group`, `outcome`, `to`, `via`, `confidence`, `reason`, `why`, `test`; at most 250,000, `truncated` says when) |
| `security.json` | `findings[]` (`id`, `tool`, `rule`, `title`, `tool_severity`, `tool_confidence`, `file`, `line`, `category`, `node`, `reachable`, `reachability` (`state`, `kind`, `why`), `ui_path`, `rank`, `rank_basis[]` (`step`, `rank`, `why`), `status`, `accepted` (with `how: "nosec"` for a comment in the code), `nosec` (`state`, `reason`)), `tools[]`, `counts` (open only, plus `in_tests`, `accepted`) |
| `readiness.json` | `version` (2), `score`, `checklist`, `grade`, `release` (`decision`, `words`, `profile`, `criteria[]`, `blocking`, `missing`, `bound_to`), `categories[]` → `checks[]` (`id`, `status` pass/fail/partial/skip, `required`, `points`, `earned`, `evidence`, `fix`, `how`), `shape`, `stack`, `advice`, `hotspots`, `next_steps`, `starter` |
| `explanations.json` | `metaphor`, `explanations{node_id → record}` (`lens1`, `lens2`, `lens3.pairs[]` with `anchor`, `scenario`, `findings` (each may carry `scenario`), `dropped_scenarios`, `validated`, `validation_errors`, `model`, `prompt_version`, `code_hash`), `stats` |
| `run.json`, `baseline.json` | timings, privacy, trace exit code; first-run counts and finding ids |
| `behaviour.json` | Written only by `lantern behave`: `of` (plan SHA-256, commit, `dirty`, Lantern, Python, system), `ran`, `why_not`, `summary` (`held`, `broken`, `inconclusive`, `not-run`), `outcomes[]` (`check`, `case`, `kind`, `outcome`, `codes`, `said`, `saw`), `of.code_sha256`, `seal`. Not in the report; the release decision reads it, and through the decision's `behaviour` criterion its outcome is in the digest |
| `report.html` | Self-contained viewer with all of the above embedded (source included only at privacy `full`) |
| `evidence.html`, `evidence.json`, `badge.svg` | Evidence Report, its data including `payload` and `digest`, README badge |

Files the user commits in their repo: `lantern-accepted.json` (accepted risks with reasons) and
`lantern-narratives.md` (their own walkthroughs, shown in the Evidence Report).

Local app state in `~/.lantern/` (or `$LANTERN_HOME`): `projects.json`, `settings.json`, `keys.json` (mode 0600).

## Identifiers

* Python node: `py:pkg.mod.Class.method`. JS node: `js:<path-without-ext>::<Local.name>`, module `js:<path>`.
  External: `ext:<pkg.member>` or `ext:HTTP <METHOD> <path-or-host>`.
* Finding id: first 12 hex of SHA-1 over tool, rule, file, line. Stable across runs while the line doesn't move.
* Project id (server): first 10 hex of SHA-256 of the absolute path.

## Invariants (break one and it is a bug)

1. Models never create, dismiss, or change a finding, an edge, or a score. They only fill `explanations.json`.
2. Every edge carries a confidence (`observed`, `resolved`, `inferred`, `possible`) and a `via`. Unresolvable calls are
   counted in `graph.unresolved`, not guessed.
3. An explanation is `validated` only if every Lens 3 pair anchors to an allowed symbol, a line range inside the
   unit, or a term in the source or glossary (`explain.validate`). Unvalidated ones are shown with a warning.
4. Pattern-based security rules that can misfire set `tool_confidence: LOW` and are labeled "heuristic".
5. A readiness check that does not apply is `skip` and leaves the denominator; one the release needs that was skipped
   because the work was not done (the tests were not run, listed libraries were not looked up) stays in it and earns
   nothing. Every scored check has evidence.
6. Starter files are never written over an existing file or outside the project.
7. The digest covers only deterministic results, so the same commit and tool versions give the same digest.
8. `lantern analyze .` on Lantern itself has no open critical, high, or medium findings (CI enforces this).
9. A release decision is `Passed` only when every required criterion that applies has passed, and a score of 100
   only stands beside `Passed`. What was not run, not finished or not checked is `missing`, never passed.
10. No rank is under the tool's own severity without the reason written on the finding. A path Lantern did not find
    is not such a reason.
11. Being faster changes no result. Work kept from an earlier run is used only for a question that is the same in
    every part (the bytes read, the name, the code that reads), so a run with kept work, a run without it
    (`LANTERN_CACHE=off`) and the engine before 2026-11-12 write the same result files but for what a clock put
    into them; a report holds the same data however the page holds it. `bench/speed.py` fails on any difference, and
    `tests/test_kept.py` checks it on every sample. No check is switched off and no file is read less to save time.

## Request flow in the local app

Browser → `GET /?token=…` sets an HttpOnly SameSite=Strict cookie → `GET /` serves `app.html` with the token in
the page → reads use the cookie, writes also send `X-Lantern-Token`. Long work (`analyze`, `explain`, `accept`)
starts a thread job (one per project at a time) and returns `202 {id}`; the page polls `/api/jobs/{id}`.
`/p/{id}/report.html` is the saved report with `window.LANTERN_LIVE` injected, which turns on the live buttons.

## Look and feel

`app.html`, `report.html` and `evidence.py` each carry the same design tokens (CSS custom properties), since every
page must stand alone. Ink for text and primary buttons, one blue accent for selection and links, and the status
colors good / warning / serious / critical only for risk and results, always next to a word or icon. Light and dark
both exist: `prefers-color-scheme` by default, or a choice saved as `lantern.theme` in `localStorage`. The app sets
`data-theme` on the documents of its same-origin frames (report, Evidence Report), so the Evidence Report follows it
without running any script. Icons are inline SVG from fixed strings in the templates; no fonts or images load from
the network.
