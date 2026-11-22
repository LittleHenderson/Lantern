# Lantern local API and result files

For anyone building a front end for Lantern, including the UI handoff from the design package. **The backend
already exists** (`lantern serve`, `lantern/server.py`); a new UI is built against this API and reads these
files. Do not invent a schema from the spec's chapter 13: that chapter describes the future cloud service.

The UI lives in `lantern/viewer/`: `app.html` (the app shell: Home, Projects, Explanations, Learn, Settings),
`report.html` (the Atlas, Findings and Readiness, one self-contained file, also served inside the app), and the
Evidence Report rendered by `lantern/evidence.py`. A redesign replaces those files; the server stays as it is.

## Build sequence

1. **Home → Projects → Atlas** (`/api/state`, `POST /api/projects`, `/analyze`, jobs, `/p/<id>/report.html`).
2. **Findings → Finding → Fix** (`security.json` via the report bundle; Accept risk; Send to…).
3. **Readiness and Protections** (`readiness.json`), **Explanations** (`/plan`, `/explain`, `/explanation`).
4. **Evidence Report** and the badge (`/p/<id>/evidence.html`, `badge.svg`, `evidence.json`).
5. **Settings**: model and key, privacy, appearance, **Connections** (`/api/connections`, `/api/allowance`).
6. **Learn** (starters) last; it is self-contained.

## Rules the UI must keep

* Every value from a result file goes through an escaper before it reaches the page. Result files sit inside
  the analyzed folder, which may be a stranger's repository, so they can be planted. The server already
  rebuilds every page from our templates and sends a hash-based Content-Security-Policy; a new UI keeps both
  (`tools/poison_report.py` and the browser tests in CI prove it).
* Facts come from the files; words come from models. The UI never computes a finding, a rank or a path, and
  never offers a way to close a finding without a written reason.
* `report.html` must stay one self-contained file that works offline, from disk, and on a phone.
* No external requests from any page (no CDN fonts or scripts).
* Status colors (good / warning / serious / critical) mean risk or results only and always sit beside a word.

## Authentication

`lantern serve` prints `http://127.0.0.1:8765/#token=...`. The part after `#` stays in the browser: the app's page
(`GET /`, the same for everybody, with no key and no data in it) reads it, keeps it in its own storage
(`localStorage` `lantern.k`, which a browser keeps apart for each port) and takes it out of the address bar. Every
request for data, reads and writes alike, needs the key in the `X-Lantern-Token` header; the report gets it from
`window.LANTERN_LIVE.token`. No cookie is set and none counts. A result file the browser opens by its address (a
frame, a new tab) takes a pass: `POST /api/view {"path": "/p/<id>/report.html"}` answers
`{"url": "/p/<id>/report.html?k=<pass>"}`, good once, for a minute, for that file. Wrong or missing key → 403. The
`Host` header must name the server, and `GET /` under the name `localhost` is sent on to the address Lantern
listens on. The link's older form (`/?token=...`) is sent on to `/#token=...`.

## Endpoints

All JSON. Errors are `{"error": "message"}` with 4xx/5xx. Long work returns a **job** (HTTP 202) to poll.

### State

| Route | Returns |
|---|---|
| `GET /api/state` | `{"version", "projects": [project summary…], "settings": {provider, model, base_url, privacy}, "providers": [provider row…]}` |
| `GET /api/jobs/<id>` | `{"id", "project", "kind": "analyze"\|"explain"\|"clone"\|"trace"…, "status": "running"\|"done"\|"error", "log": [lines], "result", "error", "started", "finished", "can_stop", "stopping"?}`. `can_stop`: this kind of job can be ended part-way with `POST /api/jobs/<id>/stop` (a test run; true also after it has ended). `stopping`: a stop was asked for and the job has not ended yet |
| `GET /api/fs?path=` | Folder listing for the Browse dialog: `{"path", "parent", "dirs": [names]}` |

**Project summary** (one per project): `id`, `path`, `name`, `added`, `exists`, `has_report`, `score` (0–100 or null),
`grade` (A–F or null), `release` (`"Blocked"`, `"Incomplete"`, `"Passed"` or null: the release decision of
`readiness.json`, taken only as one of those three words; null for results an older Lantern wrote),
`shape` (deployment shape string), `counts` `{critical, high, medium, low, accepted}` or null,
`finished_at`, `explained` (number of explained functions), `job` (running job id or null), `starter` (starter id
when the project came from Learn).

**Provider row**: `name`, `local` (true for Ollama/LM Studio, false for cloud, null for openai-compatible),
`needs_key`, `env` (environment variable name), `default_url`, `key` (where a key is set: "this session",
"remembered on this computer", "environment variable X", or null), `notice` (data-location text to show before
code is sent). The `anthropic` row (the default, `providers.DEFAULT_PROVIDER`; Haiku 5.5) adds `default: true`, and `allowance: true` when the free allowance is usable.

### Projects

| Route | Body | Returns |
|---|---|---|
| `POST /api/projects` | `{"path": "/folder or https://github.com/owner/repo"}` | A folder: the project summary (200). A link: `{"job", "project"}` (202) while it clones and analyzes |
| `POST /api/projects` | `{"paths": ["/folder", "https://github.com/owner/repo", "name=/folder", …], "name"?: "notes"}` | Several projects as one map (`lantern workspace`, `docs/workspaces.md`): `{"job", "project"}` (202), the job's `kind` is `workspace`; the project is the workspace's folder (`LANTERN_HOME/workspaces/<name>`), listed at once under the name it will have, made (links cloned, each project copied) and analyzed in the job, and forgotten again when no workspace of that name was made. 400 before anything is listed for what cannot be one (`workspace.plan`): not a list of two to 12 texts, a project's name that is not lowercase letters, digits and dashes or one Lantern's folder rules give a meaning, a link that is none, a folder that is not there, a workspace's name that cannot be one, or a folder or record under that name that Lantern did not make |
| `DELETE /api/projects/<id>` | | `{"ok": true, "note"}`; files are never deleted |
| `POST /api/projects/<id>/analyze` | | job (202). Builds the map, scans, scores readiness, writes report and Evidence Report |
| `GET /api/projects/<id>/plan?depth=3&limit=40` | | `{"nodes": N, "input_tokens", "output_tokens", "note"}`: what an explain run would cover (an estimate, no model call) |
| `POST /api/projects/<id>/explain` | `{"nodes": [ids]}` for some, or `{"depth", "limit"}` for the plan | job (202). Log lines include `free explanations left: N` and `stopped early: …` when the allowance runs out |
| `GET /api/projects/<id>/explanation?node=<id>` | | `{"record": explanation record or null, "metaphor": {"world", "roles"}}` |
| `POST /api/projects/<id>/accept` | `{"finding": id, "reason": "≥10 letters, two words", "by": name}` or `{"finding", "remove": true}` | job (202): writes `lantern-accepted.json` in the repo and re-analyzes. A weak reason → 400 |
| `POST /api/projects/<id>/cmd` | `{"argv": ["analyze", "--offline"]}` | The terminal drawer. job (202) whose log the drawer prints. `argv` is a list of strings (never a shell line; at most 64 items). Allowed: `analyze [--offline] [--no-scan] [--privacy]`, `trace [--anyway] [--] TEST COMMAND` (through the test sandbox; typing it counts as the confirmation of the command; since 2026-11-15, where this system's sandbox does not hold every program of the tests, the first try is refused with the sentence that says what they can reach, and `--anyway` is the person's word for it, remembered like the sheet's tick), `explain [--node ID…] [--depth N] [--max-nodes N]`, `report [--privacy]`, `verify [--report FILE]`, `accept ID --reason "…" [--by]` / `accept ID --remove` (same reason check as the UI), `packs`, `export [--sarif FILE]` (default `.lantern/findings.sarif`), `learn [--check]`, `diff [BASE..HEAD] [--offline]` (the job of `/change` below; the two versions must be written as commit names, and no other option of `lantern diff` is taken); a leading `lantern` is dropped. `--out` is always the project's `.lantern/`; path arguments must resolve inside the project. Anything else → 400 `{"error", "allowed": [...], "help"}`. Token and Host checks as on every write |
| `POST /api/projects/<id>/change` | `{}` or `{"range": "main..my-branch"}` | "What changed" (since stage 2 of the 2026-11-14 roadmap). job (202), kind `change`: two versions of the project are checked and what the two checks found is compared (`lantern/diff.py`, see `change/` under Result files). With no `range`: the last commit and the files as they are now. `range` is what `lantern diff` takes: `BASE`, `BASE..HEAD` or `BASE...HEAD` (from the commit where the two parted), one line of at most 300 characters, each side written as a commit's name (a branch, a tag, `HEAD`, a commit's number, with `~1` or `^`); anything else → 400 with a sentence. A commit is copied out of the repository into a folder of Lantern's own and checked there; the project's folder is not touched and no test is run. Everything is written to `.lantern/change/`, so the project's own report and results stay as they were. The job always ends `done`; `result` is `{"compared": true, "line", "same", "counts", "release": "Passed → Blocked"}` or `{"compared": false, "why": "<Lantern's sentence>"}` (the folder is in no git repository, no such commit, git is not installed). The person's `privacy` setting holds for the two checks' own reports. 409 while another job of the project runs |
| `POST /api/projects/<id>/behaviourplan` | `{}` or `{"force": true}` | "Behaviour plan" (since stage 4 of the 2026-11-14 roadmap). job (202), kind `plan`: a first `lantern-behaviour.json` is written into the project from its code (`lantern/behave_init.py`, as `lantern behave --init` does; nothing of the project is run and no model is asked). Result `{"written": true, "exists", "file", "line", "next", "checks", "requests", "counts": {"read_first", "look_at", "left_out"}, "read_first": […], "look_at": […], "left_out": […]}` (each list holds at most 12 sentences; the file's own `notes` hold all of them), or `{"written": false, "exists", "why"}`: a plan that is there is left as it is (`exists: true`) unless `force` is `true` (a `force` that is neither `true` nor `false` → 400), and `why` says so, or says that the code holds no FastAPI app, or no sign-up and sign-in Lantern can read. Every sentence is made by the server; the page prints none of its own about the plan. |
| `GET /api/projects/<id>/testcmd` | | The command the "Watch my tests run" sheet shows first: `{"command", "how", "language": "python\|node\|go\|rust\|java", "supported", "traced", "note", "cwd"?, "sandbox": {"name": "docker\|subprocess", "label", "image", "details": [lines]}, "minutes", "minutes_range": [1, 240], "memory_mb", "memory_range": [128, 1048576], "leaves", "reach": {"network", "files", "ask", "accepted"}, "confirmed"}`. `details` lists the walls this computer's sandbox has (fewer on macOS and on a Linux kernel without Landlock; since 2026-11-13 they say whether the tests get a network of their own, in which they may start a server and call it, and how long and how much memory they get); its last line says that the tests are not run when any of them cannot be set up. `leaves` (the sheet's last line) and `reach` (since 2026-11-15) are what this run keeps the tests from on this computer, for this kind of tests (`sandbox.reach`): `network` and `files` are each `all` (every program of the tests is held), `python` (Python code only) or `none`; `ask` is the sentence the person agrees to before the tests start, empty where everything is held, and `accepted` says whether they already did for this command. The page prints `leaves` as it is and adds no words of its own (until then the line said on every system that nothing leaves the computer). `minutes` and `memory_mb` (since 2026-11-13) are what a run started now would get: what the person last set in the sheet, else what the installation says (`LANTERN_TEST_MINUTES`, `LANTERN_TEST_MEMORY_MB`), else 10 minutes and 2048 MB; the two ranges are what the sheet's fields (`#testmin`, `#testmem`) may hold. `traced` is true for Python only ("Tests run; your map upgrades for Python only for now") |
| `POST /api/projects/<id>/trace` | `{"command": "python -m pytest -q", "confirm": true, "minutes"?: 1…240, "memory_mb"?: 128…1048576, "reach"?: "<the sheet's sentence>"}` | job (202). `minutes` and `memory_mb` (since 2026-11-13) are how long the tests may take and how much memory they and everything they start may have in use; a value that is no whole number in its range → 400 (never quietly another number); one that is given is remembered for the next run (settings `test_minutes`, `test_memory_mb`), one left out means the last one set, else the installation's, else 10 minutes and 2048 MB. Only test runners (`sandbox.check_command`; anything else → 400). The first run of a command for a project needs `confirm: true` (409 otherwise); later runs of the same command do not. Where `testcmd`'s `reach.ask` is not empty (since 2026-11-15) the tests start only when `reach` is that sentence, letter for letter, or the person agreed to it for this command before: 409 `{"error", "reach": {"ask", "words"}}` otherwise, with the sentence for the kind of tests the command is (the sheet shows it with its tick box); an agreement is kept per project, command and sentence, so a system whose sandbox holds less than before asks again. Runs in `lantern/sandbox.py` and re-analyzes; the job result is `{"returncode", "observed", "recall", "backend", "language", "traced", "timed_out", "time_limit", "over_memory", "memory_limit", "blocked": [{"kind": "write\|network\|read\|device", "what"}], "ran", "unavailable", "not_run_for", "libraries", "off_network", "cancelled", "not_ended", "note", "score_before", "score_after", "summary"}`. `blocked[].kind` (since 2026-11-13 also `read`: the tests reached for one of the person's own folders, which the sandbox closes to a Python or JavaScript run on Linux; since 2026-11-20 also `device`: on Windows the tests reached for a device of the computer by its name, which the sandbox refuses but for `NUL` and the console). `libraries` (since 2026-11-13): what the tests ran on, `{"state": "fetched\|installed\|none", "store", "count", "exact"}` (fetched for this run from the store named, with how many libraries and whether every version was the project's own choice; the ones installed on this computer, when the check was offline; or none, when the project names none), null when there is no such record; the libraries themselves are in `run.json`. `off_network` (since 2026-11-14): true when this run's own walls kept the tests from the network, false when they did not (tests that are not Python on macOS and Windows, where Lantern's guard is inside Python only; the run's log says why), null for a run that does not say (one before that date, or one that did not run); the page says "with the network off" only for true, and for false that the tests were not kept from the network by this run. `ran` false + `unavailable` (a sentence, always Lantern's own words): the sandbox could not be set up on this computer, or (`not_run_for: "libraries"`, since 2026-11-13) the libraries the project names could not be had for the tests, so the tests were **not run**; the job still ends `done`, because everything that only reads the code was checked: `returncode` is null and `observed` 0, the score's "Tests pass" check is `skip` (not `fail`), and the Evidence Report names no test command. `cancelled`: the person stopped the tests (below); the job ended there, **no result file was written** (the project shows what its last finished check found, `score_after` equals `score_before`, `summary` is null). `returncode` null with `timed_out`: stopped at the time limit (`time_limit`, the seconds the tests had); `returncode` null with `over_memory`: stopped because the tests, with what they started, had more memory in use than `memory_limit` megabytes. Either way the tests did not finish, which is no pass and no failure: the check goes on, "Tests pass" is `skip` with `required: true` (its points stay in the sum and earn none; until 2026-11-13 a run stopped by the clock read `fail` there) and the release decision is Incomplete, with the way to give the tests more time or memory. Whatever way a test run ends, every process it started is ended too; `not_ended` lists, in Lantern's own words, anything that could not be (normally `[]`; the page then says so and never says beside it that everything was ended) |
| `POST /api/jobs/<id>/stop` | `{}` | Ends a running test run: the tests and every process they started. Returns the job (`stopping: true`); the job then ends `done` with `result.cancelled` true and no result file changed (`pipeline.Stopped`). 404 for an unknown job, 400 for a job that cannot be stopped part-way (`can_stop` false), 403 without the app's token. Asking again, or after the job has ended, changes nothing |
| `GET /api/agents` | | `{"agents": [{"id": "claude"\|"codex"\|"aider", "name", "found": bool}], "chosen": id or ""}`: the coding agents Lantern can run for "Fix this for me", and whether each one's program is on this computer |
| `POST /api/projects/<id>/agentfix` | `{"finding": id}` | job (202), only when an installed agent is chosen in Settings (400 otherwise, and for a finding that is not open). Copies the project to `LANTERN_HOME/fixes/`, runs the agent there as a fixed argument list (never a shell line) with no `LANTERN*` variables, analyzes the copy offline and compares it with the project's results. Result: `{"fix": id or null, "status": "fixed"\|"fixed_with_new"\|"not_fixed"\|"no_change", "verdict", "agent", "returncode", "files": [{"path", "change": "added"\|"changed"\|"deleted", "diff"}], "new": [{"rank", "title", "file", "line"}], "fixed": N, "contract": {"verdict", "words", "broken", "not_shown", "items": [{"id", "state", "facts"}]}}`. The verdict is the fix contract's (below, "The fix contract"; since 2026-11-16): `not_fixed` also for a change after which the finding no longer shows and was only hidden, or whose scanner read less; the tests are not run here, so `contract.not_shown` holds `tests`. The project is not touched |
| `POST /api/projects/<id>/agentapply` | `{"fix": id}` | job (202): copies only the fix's changed files into the project, refusing if any of them changed since the copy was made, deletes the copy, and analyzes the project again |
| `POST /api/projects/<id>/agentdiscard` | `{"fix": id}` | `{"ok": true}`: deletes the copy. An id that is not a fix → 400 |
| `POST /api/projects/<id>/starter` | `{"name": "Dockerfile"}` | `{"ok", "wrote"}`; never overwrites. Since stage 5 of a firm pass or fail (2026-11-21) the names include `tests/test_first.py` for a project with no tests that is a FastAPI app Lantern can import (`lantern/firsttests.py`) |
| `GET /api/projects/<id>/browser/pictures` | | Since stage 5 of a firm pass or fail (2026-11-21): `{"pictures": [{"page", "name"}]}`, the pictures of the pages the last `lantern browse` kept on this computer (`docs/browser.md`, "Pictures of the pages"), only when `browser.json` carries this computer's seal (else `[]`); `page` is the site's own text, escape it. 404 for an unknown project. Token as on every `/api/` route |
| `GET /api/projects/<id>/browser/pictures/<name>` | | One of those pictures: `image/png` with `Content-Security-Policy: default-src 'none'`, `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`; 404 `"no such picture"` for a name that record does not list, one that is not 64 hex digits and `.png`, or a file that is not this user's plain file holding a picture whose SHA-256 is its name (`pictures.read`). The report fetches each with the token and shows it from a `data:` address (its policy allows no other) |
| `GET /api/projects/<id>/learn` | | Starter progress: `{"steps": [{"title", "done", …}]}` |

### Pages and files per project

| Route | Content |
|---|---|
| `GET /p/<id>/report.html` | The Atlas page, rebuilt from the data with live actions enabled (`window.LANTERN_LIVE = {api, token, model, local, view_mode, backdrop, agent}`; `agent` is `{id, name}` when an installed coding agent is chosen, else null). `backdrop` (`off`/`subtle`/`bold`) sets the moving shapes when the page is opened in its own tab; inside the app's frame the report draws none and the app's own show through. `view_mode` (`simple`/`advanced`) is the saved setting and wins over the browser's `localStorage`; switching inside the Atlas saves it with `POST /api/settings` and calls the app's `window.lanternViewMode(settings)` so its toggle agrees |
| `GET /p/<id>/evidence.html` | The Evidence Report |
| `GET /p/<id>/evidence.json` | Its data (schema below) |
| `GET /p/<id>/badge.svg` | `Lantern · commit 1a2b3c · 0 critical · Oct 31` |
| `GET /p/<id>/change.html` | What changed: the change receipt as a page, built from `.lantern/change/change.json` by Lantern's own template (the `change.html` that lies beside it is never sent: a results folder may come with a project). The page holds no script at all, and its header says so: `Content-Security-Policy: default-src 'none'; style-src 'sha256-…'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'`. 404 "No change was compared yet" with no receipt, 409 for data that is no receipt this Lantern writes. The app shows it in the project's frame after the button "What changed" or the terminal's `diff`, and sets the theme on it from outside |
| `POST /api/view` | `{path}` → `{url}`: a pass for one of the five result files above, so that the page can open it by its address (a frame, a new tab), where it cannot send the key. Good once and for a minute; 400 for any other path, 404 for an unknown project |

### Settings and connections

| Route | Body / returns |
|---|---|
| `POST /api/settings` | `{"provider", "model", "base_url", "privacy": "full"\|"structure", "view_mode"?: "simple"\|"advanced", "backdrop"?: "off"\|"subtle"\|"bold", "share_usage"?: bool, "agent"?: ""\|"claude"\|"codex"\|"aider", "key"?, "remember"?: bool, "forget_key"?: true}` (fields left out keep their saved values; an unknown `view_mode` is saved as `simple`; the saved settings also hold `test_minutes` and `test_memory_mb`, written by `POST …/trace` and kept only as whole numbers in their ranges) → `{"settings", "providers"}` |
| `GET /api/allowance` | `{"available": bool, "used_requests", "limit_requests", "remaining_requests", "remaining_today", "used_tokens", "limit_tokens"}` |
| `GET /api/usage` | `{"enabled": bool, "gateway": bool, "where", "why", "pending": [the pings that would be sent now], "features": [the whole vocabulary], "text"}`. `gateway`: the counts can be sent now. `where`: the address they are posted to, or null. `why`: null, or one fixed sentence saying why none is sent (the gateway address is not https, holds a name or a password, …, or real providers are switched off); it never repeats the address. `text`: what `lantern usage --show` prints, with how the last try ended |
| `GET /api/packs?project=<id>` or `?all=1` | `{"packs": [{"name", "version", "source": "builtin"\|"project"\|"user", "rules": n, "entry_patterns": n, "path", "enabled": bool, "active": bool\|null, "about"}]}`. Built-in and user packs always; the project's own `lantern-packs/*.json` when `project` is given, or every listed project's with `all=1` (what Settings → Analysis packs shows; a name is listed once). `active`: its `requires` match that project (null without a project). Python web and TypeScript web are the engine, not packs, and are not listed |
| `POST /api/packs` | `{"name", "enabled": bool, "project"?: id}` → `{"ok", "packs"}`. Writes `settings.json → "packs": {"disabled": [names], "changed_at"}` for every project; an unknown name or a non-boolean `enabled` → 400. Nothing is re-analyzed: projects whose report is older than the change get `"stale": "packs"` in `/api/state` and the card shows "Re-check to apply". The next analysis skips disabled packs, lists them in `graph.json` `meta.packs.disabled`, and the Evidence Report's provenance names each pack with its status (`ok (…)` or `off (turned off in Settings)`) |
| `GET /api/connections` | `{"connections": [{"name", "version", "last_used" (unix s), "calls", "last_tool"}], "now", "setup": {"claude_code": "claude mcp add lantern -- … mcp", "json": {mcpServers…}}}` |
| `POST /api/ask` | `{"project"?: id, "question", "focus"?: {"node"}}` → `{"answer", "cited": [finding ids]}` (or `{"answer", "no_model": true}`) |
| `POST /api/ask/screenshot` | multipart form, one file: PNG, JPEG or WebP up to 8 MB (larger, or another type → 400). Read on this computer: `{"width", "height", "format", "lines", "text"}`; without the Tesseract program `{"width", "height", "format", "text": null, "reason": "tesseract not installed", "how": "<one-line install for this OS>"}`. The image goes to Tesseract through a pipe, is never written to disk or sent anywhere, and is not kept after the response; the app quotes the text into the next question and then drops it |
| `GET /api/starters`, `/api/starters/<id>`, `/api/starters/<id>/fix?file=` | Learn catalog, one starter, the fixed version of a file |
| `POST /api/starters` | `{"id", "parent"}` → `{"project", "job"}` (201): scaffolds a starter app and analyzes it |

## Result files (`<project>/.lantern/`)

The Atlas page gets all of these in one bundle (`DATA` in `report.html`: `graph`, `security`, `readiness`,
`explanations`, `sources`, `stats`, `browser`). The CLI writes the same files, so a UI can also be built on them directly.
`browser` (since stage 5 of a firm pass or fail, 2026-11-21) is what the report shows of `browser.json`
(`browse.view`): null unless that record carries this computer's seal and is of the code `readiness.json`'s release
decision is tied to; `{ran: false, why, browser}` for a run that opened nothing; else `{ran: true, why, browser,
pages, seconds, pictures, checks}`, `pictures` a count only, each check `{id, title, outcome, codes, why, blocks, saw}` (`blocks`: one of the checks that block a release; `saw`: at most three
rows with at most eight fields each, every text cut to 300 characters, and no `saw` at all in a report made with
`--privacy structure`, because the rows hold the site's own text). Escape every value.

**How a report holds the map (since 2026-11-12).** Inside `report.html`, and only there, `graph.nodes` and
`graph.edges` are written column by column (`lantern/columns.py`), because most of the time a phone needs to open a
large report is the time it needs to take the file in (Django's report: 73,896,338 bytes before, 38,050,642 after,
the same data). `graph.json` is unchanged. The page's first lines (`unpackGraph`) and `lantern.report.read_bundle`
turn the map back into the rows described under `graph.json`, with the fields in the same order and every value of
the same kind, before anything else looks at it; anything that reads a report's data block by itself must do the same
or, simpler, read `graph.json`:

| In the data block | Meaning |
|---|---|
| `graph.packed` = `1` | the map's last entry: `nodes` and `edges` are written as below. No such entry: they are lists of rows, as every earlier Lantern wrote them (still read) |
| `nodes`, `edges` = `{"keys": [...], "n": N, "cols": [...]}` | `keys`: the fields in the rows' own order; `n`: how many rows; `cols`: one column for each field. A list that could not be written this way (rows that are not all tables with the same fields in the same order) stays a list of rows |
| a column `["v", [values]]` | the value of every row, as it is |
| `["c", value]` | every row has this one value (text, a number, yes/no or nothing; never a list or a table) |
| `["t", [values], [places]]` | few different values, each written once; `places[i]` is the place of row `i`'s value in `values` |
| `["r", [places]]` | for `parent`, `src` and `dst`: the id of a node, written as that node's place in `nodes` (counted from 0). A value that is no such id stands in a list of its own: `["ext:os.path"]`, `[null]` |
| `{"as_it_was": {...}, "packed": 1}` | a map that came with an entry `packed` of its own (none Lantern writes has one) is not packed and stands whole under this name |

A packed map of any other shape is refused, by the page (it draws nothing) and by `read_bundle` (`ValueError`, "this
report's map is not written the way this Lantern writes it; analyze again"): another value of `packed`, a count of
rows that no column's list has, a place outside its list, a field named `__proto__`.

### `graph.json`

`{"schema", "repo_root", "meta", "nodes": [...], "edges": [...], "unresolved": {text: count}}`

`repo_root` is where the run that wrote the file found the project. Nothing reads the project there afterwards:
`lantern report`, `evidence`, `explain`, `trace`, the app and the connector read the functions' lines in the folder
they were asked about (`Graph.load(path, repo)`), and a node's `file` is opened only when it is a file of that folder
(`python_frontend.project_text`: not through `..`, not from the top of the disk, not through a link that leads out).

* Node: `id`, `kind` (`module`|`class`|`callable`|`external`), `name`, `qualname`, `file`, `start_line`, `end_line`,
  `parent`, `signature`, `docstring`, `decorators`, `entry` (null or `{"kind": "page"|"route"|"main"|"cli"|"script"|"test",
  "detail": "/admin" or "POST /backup", "via"?: "pack:django", "registered_at"?, "middleware"?: [node ids],
  "use"?: [{"id", "file", "line"}]}`
  (`middleware`: an Express route's own middleware, in order, e.g. `router.delete('/x', requireLogin, h)`: node ids,
  or the `ext:` name of a library's function or of one imported from a file that is not in the repo
  (`ext:./mw/guards.requireLogin`, for which no node exists); the login check reads each one's own name, what
  follows the last `.` and `/`. `use`: the middleware Express runs before the route because it was put on the app or
  on a router with `use` (`app.use(requireLogin)`, `app.use('/admin', requireAdmin)`, `router.use(mw)`,
  `app.use('/api', mw, router)`), outermost first, each with the place it was put on; only what the code shows comes
  first is listed: written on an earlier line of the same file and function as the route or as the router's mount, on
  a path that covers the route's, and in front of every mount of a router that is mounted more than once. A router, an
  error handler (four parameters), a class and Passport's reading of the session are no such middleware. A function
  written in place has the id `inline:<file>:<line>` (`app.use((req, res, next) => { ... })`: it is no node of the
  map), and a function put on every verb counts the same way (`app.all('*', check)`, `app.all('/api/*', check)`). No edge and
  no call site is added for it; the login check and the flow step read it. An entry is only ever on a function of the repo: a route whose handler is a
  library's function, or comes from a file that is not there, marks no node); an HTML page with script inside it is
  a `page` entry whose `detail` is the file path, and its functions are `js:<path>.html::<name>` with the page's own
  line numbers), `lane` (the stack strip stop the
  node lives on: `browser`|`frontend`|`server`|`data`, or null for an external that is not a data hop — see
  **Stack lanes** below).
* Edge: `src`, `dst`, `kind` (`calls`|`may_call`|`contains`|`implements`), `confidence`
  (`observed` > `resolved` > `inferred` > `possible`; the UI words are seen running / certain / likely / possible),
  `lines`, `via` (how it was resolved; `http-*` for a frontend→backend hop), `detail` (`PUT /api/items/{id}` on an
  HTTP edge, `onClick` on a UI edge).
* Node ids: Python `py:pkg.mod.Class.method`; JS `js:<path-without-ext>::<Local.name>`; external `ext:<pkg.member>`
  or `ext:HTTP <METHOD> <path>`. A database table is `db:<table>`, or `db:<schema>.<table>` for a schema other than
  `public` (since 2026-11-14, roadmap stage 1): `kind` `external`, `lane` `data`, `name` the table's name. One edge
  runs from each function to each table it touches: `kind` `calls`, `detail` what the function does there in a
  fixed order (`select, update cards`), `lines` every line it does so on, and `via` `supabase-from` (`inferred`:
  the client is one by where its value came from) or `supabase-name` (`possible`: it is only named like one); a
  function with a call of each kind gets the likely link. A table is never an entry point, and its name is no
  called function's name for a rule that reads those (the login check). `graph.outside(id)` is true for `ext:` and
  `db:` alike.
* `meta`: `files`, `lines`, `languages`, `bridge` (link counts; with table calls also `db_calls` and `tables`),
  `http_calls`, `db_calls` and `js_directives` (both below), `packs` (`{added, ambiguous, unresolved, packs}`),
  `lanes` (`{browser, frontend, server, data}` node counts), `calls` (the summary of `calls.json`, below),
  `too_deep` (since 2026-11-13, only when a reader left something: `{pieces: n, files: [path, …],
  where: [{file, line, reader}, …], readers: [reader, …]}`. A reader goes through code by calling itself once per
  level and leaves a piece that is nested deeper than Python follows: `pieces` counts them, `files` names every
  file that holds one, `where` gives the line each of the first 40 begins at and the reader that left it
  (`python`, `javascript`, `go`, `rust`, `java`, `kotlin`, `swift`, `dart`, `csharp`, `php`, `ruby`, `cpp`), and
  `readers` names a reader that stopped before it was through with the project, with what it had read by then
  still on the map. The calls written in such a piece are not on the map. The run's log has a line
  `deep    <n> pieces of code nested deeper than Lantern follows were not read to the end (<files>)`, the Evidence
  Report's Limits name the files and the readers; `lantern/deep.py`. Until then such a piece ended the run with
  `maximum recursion depth exceeded` and no result file. `too_deep.slow`, only when there is one =
  `{count: n, files: [path, …], readers: [reader, …], seconds: 20}`: the files a parser was not through with in the
  seconds it gets for one file (`deep.PARSE_SECONDS`; the first 40 by name). Such a file is on the map as a file and
  nothing written in it is; the log's `deep` line and the Limits say so. Only the Dart reader's parser has such a
  limit so far).
* `meta.workspace` (since 2026-11-17, roadmap stage 6; only on the map of a workspace, `lantern/workspace.py`):
  `{"name", "made", "members": [{"name", "from": "folder"|"link", "source", "commit", "dirty", "branch", "remote",
  "files", "links", "left_out", "accepted"}], "across": {"requests", "code", "rows": [{"from", "to", "kind":
  "request"|"code", "via", "confidence", "src", "dst", "call"?, "route"?}], "more"}, "shared": {"names", "examples"}}`.
  `source` is a link as it was given, or a folder's own name (the whole path stays in the record beside the
  workspace). `files`, `links` count what was copied of the member, `left_out` `{why: count}` what was not (`folder`,
  `link-out`, `kind`, `large`, `name`, `unreadable`); `accepted` says the member has a `lantern-accepted.json`, which is
  not read in the workspace. `across.rows`: a request one member makes that another answers (`kind` `request`, the
  bridge's own `via` and confidence, `call` what was asked, `route` the route that answers) and code of one member
  linked into another (`code`, always `possible`); at most 200, `more` counts the rest. `shared.names`: names on the
  map that more than one member writes (found when the workspace was made, each member read alone); every link that
  touches one is `possible`, and `examples` names the first 20 with the members that write them. The call-site
  inventory's records of such links say `possible` too. A reader whose rule is about the project's own top reckons
  from the member's folder (`workspace.below`: a plain PHP page's address). The log's line is `across  …`.
* `meta.db_calls` (since 2026-11-14, roadmap stage 1; only when the project has one): the calls into database tables
  the JS/TS reader wrote down, one row per call written `<client>.from("<table>").<op>(…)` with `<op>` one of
  `select`, `insert`, `update`, `upsert`, `delete`: `{"src"` (the function the call is written in), `"table",
  "schema"` (null for `public`, also when written `.schema("public")`), `"op", "id"` (`db:<table>`), `"confidence"`
  (`inferred`|`possible`), `"via"` (`supabase-from`|`supabase-name`), `"file", "line", "ui"}`. The client is one by
  where its value came from (`supabase-from`: what `createClient` and its like of an `@supabase/…` package gave back,
  a `useSupabaseClient()` result or a value typed `SupabaseClient`, followed through the names of the file, a value
  another file of the project exports and a function of the project whose every `return` is a client) or by its name
  alone (`supabase-name`: a receiver called `supabase`, `supabaseClient` or `supabaseAdmin`, or, since 2026-11-15, a
  longer name that begins with the library's (`supabaseServiceRole`; none that names its storage or a bucket), also as
  `this.<name>`, whose value Lantern cannot follow; not a name that is given another value, is a function or is an
  import of something else, and not a value Lantern knows to be another thing). The table's name is the text written
  in the call or a constant of the file that holds one; any other name makes no row. `bridge.link_tables` turns the
  rows into the `db:` nodes and their edges.
* `meta.js_directives` (the same date; only when a file has one): `{file: ["use client"]}`, `["use server"]` or
  both, the directives a JS/TS file begins with. `lantern/clientside.py` reads them where it says which functions
  run on the visitor's side (`where(g)` → `{node id: {"on": "the browser"|"the phone", "why"}}`: the file begins
  with `"use client"`, it is part of a phone app, the project has no framework that renders pages on a server, it
  is a page of Next.js's `pages/` folder, or such code calls it; never a route, a file in a server folder or a
  file that begins with `"use server"`). It is worked out when a rule asks and is in no result file.
* Server Actions (since 2026-11-14, roadmap stage 1). Where the nearest `package.json` depends on a framework that
  runs them (`next`, `waku`, a `react-server-dom-*` package), every function a file that begins with `"use server"`
  exports, and every function whose own body begins with `"use server"`, is an entry point `{"kind": "route",
  "detail": "ACTION <name>"}`. It has no verb and no path: the framework gives it an address of its own, and anyone
  who has that address can send to it, with or without the project's pages. A class, a method and a function the file
  does not export are none, and with no such framework the words do nothing. Its `lane` is `server`: a `"use server"`
  file is the server's as a whole; an action written inside a page puts itself there, and the page stays where it was.
  `<form action={fn}>` and `<button formAction={fn}>` make an edge from the component to the action with `via`
  `callback`, `confidence` `inferred` and `detail` `action` or `formAction` (in the report: "on submit"); a client
  component that calls the action by name is linked as any call (`resolved`). The data flow reads every argument of an
  action as request data (a `FormData` as its fields; a `number` carries no text). `ACTION <name>` is the map's own
  word: a sentence a reader gets says "the Server Action <name>" (`graph.route_words`), in a finding's title, story
  (through a page: "send the form on it"; with no page that uses it, a request sent straight to the action) and case,
  and in the lists of `readiness.json`; the report's rows and chips show `Server Action <name>`. A finding's `routes`
  list keeps the detail as the map writes it. An action made by a helper (since 2026-11-15): `export const save =
  checked(schema, async (data) => …)` in a `"use server"` file is an entry on the function written in the call,
  wherever it stands among the arguments; the helper is in the entry's `middleware` list, and the action has an edge
  to it with `via` `action-helper` (`inferred`). The data flow reads the helper as a step before the action: a login
  it asks for counts for the action; one it asks after the action has run, or asks and does not enforce, does not;
  what it hands the action from the form is request data, and a user it read from the session is not. A choice between
  two actions handed to a call (`useActionState(first ? signIn : signUp, null)`) is a `callback` edge to each. Not
  looked through: a chain of helpers with a call in it, a named function handed to the helper.
* tRPC procedures (since 2026-11-15, roadmap stage 1). Where the nearest `package.json` depends on `@trpc/server`,
  each procedure of a router is an entry point on its handler: `{"kind": "route", "detail": "POST
  /api/trpc/post.create", "trpc": {"path": "post.create", "type": "mutation"|"query"|"subscription", "procedures":
  ["protectedProcedure", …], "mount": "/api/trpc"|null}}`. A mutation is `POST`, a query or a subscription `GET`. The
  path is the keys through the routers (a router inside a router, `mergeRouters(a, b)`, a router spread into another,
  one written out as an object: `{ … } satisfies TRPCRouterRecord`). `mount` is where the adapter serves them
  (`endpoint`, `basePath` or `prefix` of the adapter call, the path of the Express `use` it stands in, or the Next.js
  route file that calls it) and `null` where the code does not say: the detail is then the path alone (`POST
  /post.create`). `procedures` are the names the procedure is built on, nearest first (`adminProcedure`,
  `publicProcedure`), and the functions put before it with `.use(fn)` are in the entry's `middleware` list (node ids).
  A handler written in place is a node of its own, `js:<file>::<router>.<key>` (a `.use(fn)` written in place:
  `js:<file>::<name>.use`); a handler handed by name keeps its node. The route whose function calls the adapter keeps
  its entry and gets `"serves": "trpc"`: the login rule and the readiness page ask its procedures, not it. A call
  through a tRPC client (`api.post.create.useMutation()`, `client.post.hello.query()`,
  `trpc.post.hello.queryOptions()`) adds an edge from the calling function to the procedure with `via` `http-trpc` and
  the route's detail, beside the call's own record in `calls.json`: `resolved` where the client is what a function of
  an `@trpc/…` package returned, `inferred` where the client's value is not followed and the path names one procedure,
  `possible` where it names several. `graph.json` `meta.trpc` counts them: `{"procedures", "routers", "client_calls",
  "linked"}` (absent where the project has none). The data flow reads `input` (and `rawInput`) of the handler's one
  argument as request data and `ctx` as the server's own (`ctx.session`, `ctx.user`: who is signed in). Measured on
  one public project: procedures 6 of 6, client links 12 of 12 right (`bench/modern_stack_results.md`).
* SvelteKit (since 2026-11-15, roadmap stage 1). Where the nearest `package.json` depends on `@sveltejs/kit`, the
  files with fixed names are entry points: `{"kind": "route", "detail": "POST /notes?/remove", "sveltekit":
  "action"}`. `sveltekit` says which door it is: `"endpoint"` (a verb a `+server.ts` exports: `GET /api/notes/[id]`;
  `fallback` is `ANY`), `"load"` (`load` of a `+page.server.ts`: `GET <the page's address>`), `"action"` (each of its
  `actions`: `POST <address>` for `default`, `POST <address>?/<name>` for a named one), `"layout load"` (`load` of a
  `+layout.server.ts`: `GET <folder>/*`, where a group's folder keeps its round brackets, `GET /(app)/*`: it runs for
  that group's pages) and `"handle"` (`handle` of `src/hooks.server.ts`, or each named part of `sequence(a, b)`: `ANY
  /*`, with `"serves": "sveltekit"`; the login rule and the readiness page ask the routes behind it, not it). In a
  page's or an action's address a folder in round brackets is left out and `[id=integer]` is `[id]`. Every route's
  `middleware` list (node ids) begins with the hook's parts in their order, followed by a helper the action or verb is
  wrapped in (`save: withAuth(fn)`). A `+page.svelte` is `{"kind": "page", "detail": "/notes/[id]"}` on its component.
  A `.svelte` file's module keeps its ending (`js:src/routes/notes/+page.svelte`), the component is a node named after
  the file (`js:src/routes/notes/+page.svelte::+page`, `js:src/lib/Card.svelte::Card`; lines 1 to the file's end) and
  a function of its script is `…::+page.wipe`; a `.svelte.ts` file keeps its whole name too. Edges the framework's
  wiring gives, `resolved`: `http-sveltekit` from a page to the `load` beside it, to the `load` of each layout above
  it and to the action a form on it posts to (detail = the route; `possible` where several actions fit; in the report
  "sends it to POST /notes?/remove"); `sveltekit-load` from a page to the `load` of its `+page.ts` and of the
  `+layout.ts` files above it (they also run in the browser and are no entries); `sveltekit-layout` from a page to the
  layout components it is drawn in. An event on a tag of the markup (`on:click={save}`, `onclick={save}`) is a
  `callback` edge with `detail` `onClick`, as in JSX. `graph.json` `meta.sveltekit` counts them: `{"routes", "pages",
  "forms", "linked", "handed"}` (absent where the project has none; `routes` leaves the hook out, `forms` are the
  forms that post, `linked` those that found their action, and `handed`, since 2026-11-15, the links a page makes
  through a form in a shared part: the part's `<form method="POST" action={sendTo}>` posts where the page that draws
  it writes the address, `<Panel sendTo="/account?/rename">`, an edge from the page on that line with `via`
  `http-sveltekit-prop`, `inferred`, `possible` where several actions fit). In `calls.json` Svelte's own words
  (`$state`, `$derived`, `$effect`, `$props`, `$bindable`, `$inspect`, `$host`) are `builtin` with `via`
  `svelte-rune`. The data flow reads what a route is handed (`request`, `url`, `params`, `cookies`, whole as `event`
  or taken apart) as request data and `locals` as the server's own (`locals.user`, `locals.session`: who is signed
  in). A function taken out of `locals` first (`({ locals: { safeGetSession } })`, `const { auth } = event.locals`) is
  the same function. Measured on one public SvelteKit project (`bench/modern_stack_results.md`).
* Remix (since 2026-11-15, roadmap stage 1; also React Router's framework mode where `app/routes.ts` says
  `flatRoutes()`). Where the nearest `package.json` depends on one of Remix's own packages, a file of `app/routes` is
  a route by its name: `_index` is `/`, `concerts.trending` is `/concerts/trending`, `concerts.$city` is
  `/concerts/:city`, `files.$` is `/files/*`, `($lang).categories` is `/:lang?/categories`, `admin_.reports` is
  `/admin/reports`, `_auth.enter` is `/enter`, `sitemap[.]xml` is `/sitemap.xml`, and a folder's `route` file (its
  `index` file where no route file is there) is the folder's route. Entries: `{"kind": "route", "detail": "GET
  /notes/:noteId", "remix": "loader"}` on the `loader` a route file exports; `"remix": "action"` on its `action`
  (`POST <address>`, with `?index` on an index route; the bridge matches a request of any verb but GET to it);
  `"remix": "layout loader"` on a layout's loader (`GET <address>/*`); and `{"kind": "page", "detail":
  "/notes/:noteId"}` on what the file exports by default. A door made by a helper (`export const action =
  guarded(async (…) => …)`) is an entry too: the helper is in its `middleware` list, with an `action-helper` edge.
  Edges the framework's wiring gives: `http-remix` (`resolved`, detail = the route) from a page to its own loader, to
  the loaders of the layouts it is drawn in and to the action a posting form on it names (`<Form method="post">`,
  `<form>`; the address is read from where the form stands; `possible` where several fit), and `remix-layout` from a
  page to the layouts' own components. `graph.json` `meta.remix` counts them: `{"routes", "pages", "forms", "linked"}`
  (absent where the project has no such app), and carries `"not_read"` for an app whose routes Lantern does not read:
  `"Remix 1 route folders"` (every Remix version the `package.json` names is a 1.x and `v2_routeConvention` is not
  switched on), `"React Router routes listed in app/routes.ts"` (a list written by hand, or `flatRoutes` with a folder
  of its own), or both joined by `"; "`. None of that app's files is then an entry by its name, and the Evidence
  Report's `limits` carry one fixed sentence for each (any other text in `not_read` names no sentence). A route file
  that shows something holds both sides: its loader and action, and the functions of that file only they call, have
  lane `server`; what it shows keeps a component's lane. The data flow reads a route's one argument as the request
  (`request`, `params`; `context` is the server's own), and what `getSession` of the framework's own session storage
  hands back for the request's cookie shows who is signed in, only when the cookie is signed. Measured on one small
  public Remix project (`bench/modern_stack_results.md`).
* The type-aware pass (since 2026-11-15, roadmap stage 1; opt-in). `lantern analyze --typecheck`, or
  `LANTERN_TYPECHECK=1` (`true`, `yes`, `on`) in the person's own environment, asks the type checkers installed on
  this computer where the calls go that Lantern's own reading left unresolved: the TypeScript compiler for JavaScript
  and TypeScript, pyright for Python. Nothing in a project switches it on, and without it every result file is what it
  was. A checker is found outside the analyzed folder only: `LANTERN_NODE` (the `node` program), `LANTERN_TYPESCRIPT`
  (the `typescript` package folder), `LANTERN_PYRIGHT` (pyright's `langserver.index.js`), else the folders PATH
  names in full (never the current folder);
  `LANTERN_TYPECHECK_SECONDS` is each checker's time (120; at most 1800). The project's own `tsconfig.json`, pyright
  settings, plug-ins and Python are never used, and nothing of the project is run. What an answer adds: an edge into
  the project with `via` `typecheck`, `resolved` where the name written at the call names the function itself and
  `inferred` where it was reached through a value's type; in Python, where that type's method only declares
  (`@abstractmethod`, `@overload`, a body of `...` or `raise NotImplementedError`) or a class beneath it writes the
  method anew, an edge with `via` `override` and confidence `possible` to each method that may run (at most 24; a
  method that only declares gets no edge); a built-in call (counted in `builtin_calls`); a library edge (`ext:…`),
  never where the site's reason was `library-or-repo`; or nothing. In `calls.json` the site's `outcome` changes with
  it (`resolved`, `likely`, `possible`, `builtin`, `external`), its `via` is `typecheck`, and no total moves: a call
  is one call before and after. `graph.json` `meta.typecheck` (the same table is `run.json` `typecheck`): `{"asked":
  true, "typescript": {…}, "python": {…}, "passed_by"?: [names]}`. Each part is `{"ran": true, "version", "asked",
  "linked", "likely", "possible", "builtin", "library", "declared", "left", "not_asked", "stopped", "seconds"}`, where
  the seven counts from `linked` to `left` add up to `asked` (`linked`: confirmed; `declared`: only a declaration with
  no code was named; `left`: no answer; `not_asked`: calls over the 50,000 asked about per language; `stopped`: the
  checker's time ran out first), or `{"ran": false, "why", "asked": 0, "unresolved"?}` when the checker is missing,
  too old (TypeScript before 5) or could not be started, or when no call of its language was unresolved. `passed_by`
  names a `node`, a compiler or a pyright that lies inside the analyzed folder and was not started. The log has a
  `types` line. `evidence.json`: the checkers are in `provenance.tools` (`{"tool": "typescript"|"pyright", "version",
  "role": "type checker, asked for with --typecheck"}`, with `"status": "not asked"` for one that did not run while
  calls of its language were unresolved), the run's options carry `typecheck` (the versions of the checkers that ran),
  and `limits` has one line per checker. `lantern verify` on a report made with the pass answers `{"match": false,
  "typecheck": true, "refused": …}` unless it is given `--typecheck` too; the connector's `lantern_verify` passes the
  refusal on and starts no checker. Measured on twelve public projects (`bench/modern_stack_results.md`): no link was
  confirmed by a checker; the links are "likely" or "possible".
* JavaScript `via` values added in stage 3 (2026-11-09): `require-call` (`require('./x')(...)`), `route-handler` and
  `middleware` (a function handed to an Express router by name: resolved when it is named straight from a module,
  inferred when it is reached through a value or a type Lantern worked out, such as `const notes = new Notes()`),
  `wrapped-function` (`const f = wrap(async ...)`
  handed to a router; inferred), `library-value` (a variable or module export holding what a library call returned:
  `const app = express()`; since 2026-11-14 also a value an ES module exports and another file imports,
  `export const db = new PrismaClient()` and `db.note.delete()` elsewhere; `local-type` now also stands for a
  variable's written type, `let prisma: PrismaClient`, and for `kept ?? new T()`), `library-result` (a call on a library call's result: `Joi.string().min()`),
  `express-param` (`req`/`res`/`next` by position in a handler of a package that depends on express; inferred),
  `param-type` (a written TypeScript parameter type), `builtin-value` (DOM lists and elements, events, fetch
  responses), `module-value`, `member`. Python: `inherited-library` / `inherited-builtin` (a method or attribute the
  repo class does not define, from its first base outside the repo: `ext:django.Model.objects.filter`,
  `ext:unittest.TestCase.assertEqual`; inferred; not given when the class also has a base Lantern cannot identify:
  a library's star import, a computed base, or a class from a project file it did not read) and `library-result`
  (`ext:requests.get().json`).
  A library label is not given where the function may be the project's own. Python: `self.<attr>.<m>()` through a
  library base's attribute, and `<lib call>().<m>()`, are library calls only when no class of the repo has a method
  `<m>` (for a call's result, everyday names such as `get` or `items` do not count, and `str(x).title()` stays a
  built-in); otherwise the older reading stands (a name-only guess, or unresolved `library-or-repo`), and a method a
  sibling mixin gives a subclass is not the library's. JavaScript: a member of what a library call returned, or of a
  property of `req`/`res`, is not labelled when the repo puts a function of that name on an object that is not its
  own (`schema.statics.find = function`, `schema.methods = {…}`, `{ methods: {…} }`, `schema.method('x', fn)`,
  `Object.assign(obj, {…})`), when a class of the repo with that method was handed to the library calls the value
  came from (`getRepository(User).findOne()`), or, for what hangs on `req`/`res`, when any class of the repo has
  that method (names JavaScript's own objects have aside); a direct member of Express's `req`, `res`, app or router,
  of a written TypeScript type, of `new LibraryClass()` or of a built-in value only when the repo puts a function of
  that name on that kind of object (`res.fail = function`, `String.prototype.shout = …`). A route's `middleware`
  list keeps such a function's name; no record calls it a library function. `window.<name>…`, when `<name>` is not
  one of the browser's or Node's own names, is unresolved `global-property`, not a built-in.
  JavaScript imports: a bare name is looked up through the nearest tsconfig/jsconfig `paths`, then under a written
  `baseUrl` (`components/Button` → `<baseUrl>/components/Button`), as the compiler does. An import that finds no
  file names a file of the project, never a library, when it is a relative, `@/`, `~/` or `#` path or a `paths`
  alias that points at a project folder (`"contentlayer/generated": ["./.contentlayer/generated"]`, generated code
  that is not committed; not a catch-all `*`, not a target in `node_modules`, and not an alias that covers a
  package the nearest `package.json` depends on): the record is unresolved `missing-module`, nothing is built on
  the value, and the map keeps the `ext:` edge older versions drew.
  Route paths include the prefixes of `app.use('/p', router)` (Express; the router may be a variable, a required
  module, or what a factory returns: `require('./routes')()` whose function ends `return router`),
  `include_router(r, prefix=…)` (FastAPI) and `register_blueprint(bp, url_prefix=…)` (Flask, which replaces the
  blueprint's own); a router mounted in two places, or under a prefix that is not a written string, keeps the
  paths written on it. Express verbs hung on `router.route('/p')` (`.get(h).post(mw, h)`) are routes on that path.

### `calls.json`

The call-site inventory (`lantern/calls.py`): every call written in Python or JavaScript/TypeScript, once.
`{"version": 1, "summary", "outcomes": {outcome: words}, "reasons": {code: sentence}, "sites": [...], "truncated"?}`

* Site: `at` (`file:line:col`, the identity: line and byte column, from 1, of the call's `(`, or of the callee for a
  call written without one, such as a decorator or a JSX element), `file`, `line`, `col`, `callee` (as written, at most
  120 characters), `caller` (node id), `lang`, `group`, `outcome`, `to` (target ids; several for one call with several
  possible targets), `via`, `confidence`, `reason` and `why` (only when unresolved), `test` (inside a test file).
* `group`: `written` (calls written in the code: the main count), `handed` (functions handed to code that calls them:
  FastAPI `Depends(fn)`, Express route handlers and middleware, callbacks by name; counted only where they are
  functions), `implicit` (context managers, properties, decorator closures; only when they reach repo code).
* `outcome` (exactly one): `resolved`, `likely`, `possible`, `name-only`, `external`, `builtin`, `unresolved`.
* `reason` codes: `parameter`, `callback-parameter`, `local-unknown`, `call-result`, `self-attribute`,
  `not-in-class`, `unknown-base` (the class has a base class Lantern cannot look into: a library class, a star
  import, a computed base, or a file it cannot find), `this-outside-class`, `repo-variable`, `missing-member`,
  `missing-export`, `missing-module` (the name comes from a project file Lantern did not read: a relative import or
  require, or in JavaScript a tsconfig `paths` alias to a project folder, that finds no file; the graph keeps the
  older `ext:` edge for such a call, the inventory does not call it a library), `not-defined`, `computed`, `dynamic-require`, `function-member`, `library-or-repo` (the value comes from
  a library or the language, but the project has a function of that name it may carry, so Lantern does not say
  which one runs), `global-property` (reached through `window`/`globalThis`/`self`/`global` under a name that is
  not the browser's or Node's own), `not-read` (a call the JavaScript reader skipped: counted so the total stays
  complete).
* `summary` (also `graph.json` `meta.calls`): `version`, `languages` (inventoried), `not_inventoried` (languages that
  have only the edge-line count of `Graph.call_sites()`), and for each of `written`, `handed`, `implicit` and
  `in_tests` (written calls in test files): `total`, `outcomes` (adds up to `total`), `reasons`, `by_via`,
  `with_several_targets`, `lines_with_several_calls`.
* `Graph.call_sites()` (in `stats()`) is the older edge-line count and is kept unchanged so results compare across
  versions: an edge with three call lines counts three, and two calls on one line to the same function count once.

#### Stack lanes (the stack strip)

Four fixed stops, always in this order: **Browser → Frontend → Server → Data**. The UI draws them as the strip at the
top of every finding, function and path ("You are here: Server"), as swimlanes in the Path view (Simple default), and
as a four-dot glyph on list rows. `lantern/lanes.py` assigns them from the node id, file path and entry kind only — no
model, no extra analysis — so the UI never guesses:

| Lane | Rule | Hover definition |
|---|---|---|
| `browser` | a `page` entry point, or an `app start` main (the client bundle's root) | What the visitor sees and clicks. |
| `frontend` | any other JS/TS node in a client-side module | Your pages and screens: the code that builds what the browser shows. |
| `server` | every Python/Go/Rust/Java node; a JS/TS module that holds a route handler or a server start, or lives under `app/**/route.*`, `pages/api/`, `api/`, `server/`, `backend/`, `functions/`, `netlify/`, `supabase/functions/`, `workers/`, `middleware.*`; an `ext:HTTP` call whose target starts with `/` (the app's own API) | Code that runs on a machine you pay for, not the visitor's. |
| `data` | an external node that reaches a database, a file, the shell or an outside service (`sqlite3`, `psycopg`, `prisma`, `supabase`, `fs`, `subprocess`, `child_process`, `fetch`/`axios`/`requests` to another host, `stripe`, `openai`, `boto3`, …; the full list is `lanes.DATA_RE`); an `ext:HTTP` call to a host | Where things are kept or sent: the database, files, shell commands, outside services. |
| null | any other external (`json.dumps`, `hashlib.md5`) — not part of the stack picture | — |

The UI must keep the four stops in that order and use the same four words everywhere; a lane with no nodes in the
project is still drawn, dimmed.

In an Android app (`graph.meta.platform == "android"`, `meta.android.roots` lists the app module folders) the app's own
Java/Kotlin code runs on the phone: a screen (a `page` entry, or a `route` entry whose detail says ` screen `) is
`browser` and every other node under an app module is `frontend`; findings in the manifest or build file are
`frontend`. The UI then shows the first two stops as **Screen** and **App** (hover: "what the person sees and taps on
their phone" / "the rest of your app's code, running on the person's phone"); the order and the four lane values do
not change.

An iOS app (`graph.meta.platform == "ios"`, `meta.ios.roots` lists the folders of each Xcode app, `meta.ios.apps` gives
`root`, `plist`, `project`, `bundle_id`, `min_ios`) gets the same two stops: its Swift screens are `browser`, the rest of its
code `frontend`. When a repository holds both, `platform` is `"android"` and both sets of roots count.

A Flutter app (`meta.flutter.roots`: each folder whose `pubspec.yaml` depends on the Flutter SDK) and a React Native or
Expo app (`meta.rn.roots`, `meta.rn.apps` with `root`, `expo`, `router`, `config` (the `app.json` path or null)) get the
same two stops for their Dart or JavaScript code. `platform` is `"flutter"` or `"react-native"` unless an `android/` or
`ios/` app in the same repository set it first.

A .NET MAUI or Xamarin app (`meta.maui.roots`: each folder whose `.csproj` sets `UseMaui`, targets `net…-android`/
`net…-ios`, or uses Xamarin.Forms) gets the same two stops for its C# code; `platform` is `"maui"` (also when its own
`Platforms/Android` manifest was read, since that folder is part of the MAUI project). Entry details: `<Page> screen ·
<method>` (a page's constructor, lifecycle method or event handler; a view model's `[RelayCommand]` uses its page's name),
`LINK <Class> handles links (other apps and web pages can open it) · <method>` (route). ASP.NET routes: `GET /api/notes/{id}`
(controller or minimal API; an inline minimal-API lambda is its own node, id `cs:<file>::GET /path`). C# findings (`LC-*`)
inside a MAUI project carry `platform: "maui"`; Readiness `shape` is `".NET MAUI app"`.

A PHP project's routes use the same `route` entries: `GET /api/notes` (Laravel, Symfony, Slim; an inline closure is its
own node `php:<file>::GET /path`), `POST /wp-admin/admin-ajax.php?action=<name> (anyone can call it)` or `(signed-in
users)` (WordPress ajax), `GET /wp-json/<ns>/<route>` (WordPress REST), `ANY /<page>.php` (a page a browser opens,
path from the web root: `public/`, `public_html/`, `htdocs/`, `www/`, `web/` dropped). A route inside an `auth`/`sanctum`/
`can:` middleware (and a signed-in-only WordPress action) has a `middleware` edge to `ext:middleware.auth`.

A Ruby project's routes: `GET /api/notes/:id` (Rails `config/routes.rb`, on the controller action `rb:Api.NotesController.show`;
Sinatra blocks are their own node `rb:<file>::GET /path`); a job's `perform` is `main` (`background job (PruneJob)`). An
action covered by a `before_action` named with an auth word (`authenticate_user!`, `require_login`; inherited, `only:`/
`except:`, not removed by `skip_before_action`) has a `middleware` edge to `ext:middleware.auth`.

A C/C++ program's start is `main` (`program start (<file>)`, id `cc:main@<file>`: each program keeps its own); its web routes
(cpp-httplib `svr.Get`, Crow `CROW_ROUTE`, Drogon `ADD_METHOD_TO`/`registerHandler`, Pistache `Routes::Get`) are `route`
entries, a lambda handler being its own node `cc:<file>::GET /path`; gtest/Catch2 blocks are `test` (`cc:<file>::TEST Suite.Name`).

### `security.json`

`{"findings": [...], "tools": [scanner records], "incomplete": [the scanner records that apply and are not ok],
"counts": {critical, high, medium, low, in_tests, accepted}, "id_version", "reachable_nodes", "total_callables",
"logins_shown", "route_logins", "not_read", "ai", "mobile"}`

`route_logins` (since stage 2 of the 2026-11-14 roadmap; absent from results written before it): what every route
shows about asking who is calling, one record a route, so that two checks of one project can be compared route by
route (`lantern diff`): `[{"node", "detail": "POST /api/admin/export", "file", "line", "login": "shown" | "lookup" |
"none", "why": the sign that was read or null, "public": the path is one made to be open (a sign-in, a webhook),
"changes": its verb changes data, or it is a Server Action whose code does}]`. It is the reading the missing-login
rule and the protections card make (`websec.login_check`), one story with the findings: a route in `logins_shown`
is `shown` whatever its names, and a route an open `LW-AUTH-MISSING` finding stands on is `none`. `lookup`: the
handler only looks a user up by a value of the request, which finds a record and not the caller. Not listed: routes
in test code, the one door other routes stand behind (tRPC's), what a phone app is started with. A heuristic, like
the two rules it is shared with.

`logins_shown`: the node ids of the routes whose own code turns away whoever is not signed in, as the flow step read
it (a check under any name, one written in place, a hook, a dependency); `null` when that step did not run, and
absent from results written before 2026-11-11. The protection `route-auth` in `readiness.json` counts such a route
as checked (found: "the code on the way to this route turns away whoever is not signed in"), and names a route an
`LW-AUTH-MISSING` finding calls open among the open ones, whatever the names around it say. A Server Action that
changes data (read as for the finding, below) counts among the "routes that change data" of `route-auth` and
`rate-limit`, and their `evidence` and `found` name it `the Server Action <name> (<file>:<line>)`. A tRPC
procedure is counted under its own address (a mutation changes data); the one route that serves them all
(`serves: "trpc"`) is not counted, and neither is SvelteKit's `handle` (`serves: "sveltekit"`): its routes are. The
upload line (`upload-checks`) is given for a form read with `formData()` only where the same file takes a file out
of it (`File`, `Blob`, `arrayBuffer()`, `stream()`; since 2026-11-15): reading a form's fields is no upload.

`not_read` (`lantern/unread.py`, since 2026-11-12; `{}` when the project holds neither kind, absent from older
results): what the project holds that Lantern takes for code or software and did not read. `renamed`: code kept under
another name, `<name>.<code ending>.<txt|tmpl|template|bak|orig|old>` (`engine.py.txt`, `main.py.tmpl`):
`{files, lines, endings: {".py.txt": n}, examples, scanned, as_text_unscanned, as_text_unscanned_examples}`. No reader
opens such a file, so the map, the paths and Lantern's own checks do not cover it. Python kept as text (`.py.txt`,
`.pyw.txt`) is handed to Bandit by name (`scanned` counts the files it read without an error; its findings carry the
file's own name, and a command there that is handed literals only is ranked `low` with the reason, as in a `.py`
file). Code kept as text that no scanner read (`as_text_unscanned`: text is kept that way to be loaded) leaves the
release decision's `scanners` criterion `missing`; a template or a left-over copy is named in the Evidence Limits
only. `copied`: software copied into a folder named `vendor` (which every reader leaves out):
`{folders, copies, named: ["<name> <version> (<folder>)"], unnamed, unnamed_examples, cut_short}` (`cut_short`: a folder there lay deeper than Lantern looks, or held more names than it reads, so part of it was not looked at). A copy that brings a
`package.json` with a published name and one exact version is looked up by that name and version (`copied-audit`
below); code files under `vendor` with no such file above them are `unnamed` and cannot be looked up. A package
manager's own `vendor` folder (Composer's, Go's, Bundler's) is not a copy: its lock file says what is in it. A
`vendor` folder under `tests/`, `fixtures/` or `examples/` is not one either (the dependency audits leave such
folders out the same way). The Evidence Limits name both kinds.

A scanner record (`lantern/scanresult.py`, one per tool run: bandit, gitleaks, lantern-secrets, pip-audit, npm-audit,
maven-audit, composer-audit, gem-audit, copied-audit, lantern-web, lantern-ai, lantern-flow, packs): `tool`, `state` (`ok` | `partial` | `failed` |
`timeout` | `unavailable` | `skipped`), `status` (the same as one sentence: `ok`, `ok (…)`, `partial: …`, `error: …`,
`error: timed out …`, `skipped: not installed (…)`, `skipped: …`; records from before 0.11 have only this), `why`,
`applicable` (false when the tool had nothing to do here: no Python dependency files, gitleaks absent but the built-in
patterns ran), and when known `version`, `exit_code`, `scope` (`{files, packages}`; for `lantern-secrets` also
`placeholders` when the built-in patterns passed over that many keys' places kept by filler, such as `sk_live_` and
nothing but `x`, which are no findings), `exclusions` (folders a tool was
told to skip, and for bandit the Python files it was told to leave out because they are not files of the project: a
link that leads out of it, a pipe), `errors` (one line per file or package left out of a `partial` run), `findings`, `duration_ms`, `role`,
`fallback_for` (the built-in secret scan when gitleaks did not finish), and for gitleaks `way` when it was started on
the project: `linked` (the project was handed over under a name of Lantern's own) or `plain` (by its own path).
`partial` keeps the findings the tool did
produce. Bandit's `scope` has `under_another_name` when Python kept as text was handed to it (how many such files, a
part of `files`), and the record then names them in `read_as_text`. Bandit's record has `way: "copies"` when it was started on copies of the project's own Python files, in a folder of Lantern's own, and not on the project's folder: that is done where something in the project that is not the project's own (a link that leads out, a pipe) cannot be written as an exclusion (a comma in its path, or more of them than fit a command line). Findings name the project's files as always; a file that could not be copied is in `errors` and makes the run `partial`; where no folder for the copies can be made the record is `failed` and Bandit is not started; nothing of such a run is kept between runs. `copied-audit` (`depaudit.run_copied_audit`: the
copies under `vendor` that say what they are, asked of OSV as npm packages by the name and version their own
`package.json` gives, which nothing proves) adds `copied` and `copied_examples` (the copies with a name and a
version), `unnamed` and `unnamed_examples` (code files that belong to no such copy: the record is then `partial`),
`checked`, `files`; `skipped` with `applicable: false` where the project has no such folder, `skipped` and applicable
when offline. The dependency audits (pip-audit, maven-audit, composer-audit, gem-audit) add, when they apply: `files` (the
dependency files read), `checked` (how many name-and-version pairs were asked about), `unpinned` (how many entries
have no exact released version to look up: a range, a branch, a link or a folder, no version, a variable) with
`unpinned_examples` (the first five, as text), `unlocked` (npm-audit, composer-audit, gem-audit: how many libraries
a `package.json`, `composer.json` or `Gemfile` names for the shipped app where no lock file beside it says which
version is installed, so none of them could be looked up) with `unlocked_examples` (the first five, as
`<file>: <name>`), `other_locks` (npm-audit: up to ten folders whose versions are in a pnpm, yarn or bun lock file,
which Lantern does not read yet; written also on a record that ends `ok` for the folders it did check), for pip-audit `tries` and `asked_again` where it was started more than once (`tries`: how many times; `asked_again`: for each try after the first, what failed before it, in the words of the status: `pypi.org did not answer in time`, `the connection to pypi.org failed`, `pypi.org answered with an error`; `exit_code` is the last try's, `duration_ms` the time of all of them), and `not_read` (how many parts of the dependency files are no package
name and version, or no dependency file at all: a list where a table belongs, a number where a name belongs, a file
that is not valid TOML or JSON, a pipe, a file over 32 MB). With `not_read` the state is `partial` and `errors` names
the first 20, each as `<file>: <what>` on one line of printable ASCII of at most 200 characters (of a path over
100 characters the end is kept, after `...`; `files` has every path whole); the rest of the file is still checked. An
audit that is skipped (`--offline`, tool not installed) carries `not_read` only when nothing in the files could be
used. `incomplete` is read by readiness (`sec-scanners`), the Evidence Report, the badge (`scan incomplete`), the
command line (`--fail-on` exits 1 for any state but `skipped`) and the app's project cards; a run with `--offline`
lists its skipped audits there without failing the gate. Libraries that were not looked up are not "none found":
`unpinned`, `unlocked`, `other_locks` and a skipped or failed audit each make the release decision's `dependencies`
criterion `missing` (`readiness.json`), and the readiness check of the same name earns nothing for them.

Bandit is started with `--ignore-nosec` (since 2026-11-11): a `# nosec` comment in the project's code no longer takes
a line out of the results. Lantern reads the comment itself and writes what it found on the finding (`nosec`, below).

`lantern-flow` (`lantern/flowscan.py`, Python and JS/TS; `applicable` false for a project with neither) is the step
that follows request data across functions and files. Its record has `version` and `scope` `{files, functions,
flows` (request values followed to a sensitive action), `on_other_findings` (flows attached to a finding another
tool made on the same line), `not_followed_further` (calls where a value that still carried request data was handed
to code Lantern does not read), `login_read_from_code` (findings "no login check was found" that were not kept
because the route's own code turns away whoever is not signed in), `token_check_lets_on` (routes that change data
on whose way a login token is read and nothing turns away a request whose token does not hold), `sender_checked`
(`LA-WALLET-DRAIN` findings that were not kept because the route goes on only with a message its provider signed
and pays for nothing before that check), `webhook_routes` (only when there is one: the routes taken for a
provider's webhook that write stored data, which is what `LW-UNSIGNED-WEBHOOK` read), `webhook_for_no_login` (only
when there is one: the routes whose finding "no login check was found" was not kept because an `LW-UNSIGNED-WEBHOOK`
finding names the same route: a provider cannot sign in, so that finding points to the wrong fix), `model_text` (only
when there is one, since stage 5 of the roadmap of 2026-11-14: text a model wrote followed to an action, `{flows,
findings` (new `LA-MODEL-OUTPUT-TO-TOOL` findings), `on_older_findings` (lines written on a finding of the older
reading of that rule, inside one function), `checked_by_code` (findings of the older reading not kept because the
model's text arrives on that line checked on every way)`}`), `tool_text` (only when a tool is found, since the same
stage: what a model puts into a function of the project it is handed as a tool, followed to an action, `{tools`
(functions a library is told are tools a model may call), `flows`, `findings` (new `LA-UNSAFE-MCP-TOOL` findings),
`approval_asked` (flows not kept because a person is asked first: the library's approval flag, or a question in the
function before the action), `reads_only` (flows to a file that is only read), `on_model_findings` (flows to a line
an `LA-MODEL-OUTPUT-TO-TOOL` finding already names)`}`), `agent_loops` (only when a paid model call or a
finding is there, since the same stage: loops and functions that call themselves with a paid model call in each
round, `{paid_calls` (model calls paid for each time, known by the library's own name for them), `loops` (rounds
that make a paid call and that the model's answer can end), `capped` (of those, the ones where a count the loop
changes, a clock or a budget is read where it decides to go on), `asked` (a person says yes to each round),
`ends_otherwise` (something else can end them too: a queue that runs out, a flag the code sets, a limit a helper
checks), `settings_off` (a library's own agent loop with its limit switched off), `findings`
(`LA-UNBOUNDED-AGENT-LOOP` findings, the loops and the settings)`}`)`}`; `partial` when a file could not be read, a function could not be followed or the
time limit was reached, with `errors` naming the first 20. Its own findings have `tool: "lantern-flow"` and a rule
`LT-<KIND>`: `LT-SQL` (CWE-89), `LT-SHELL` (78), `LT-EVAL` (94), `LT-DESERIALIZE` (502), `LT-XXE` (611), `LT-PATH`
(22), `LT-SSRF` (918), `LT-XSS` (79), `LT-REDIRECT` (601), `LT-NOSQL` (943), `LT-POLLUTION` (1321), and four about
who may reach what, always `tool_confidence: LOW` and rank `medium`: `LT-AUTHZ-OWNER` (639: a route with a login
reaches a record by an id from the request, and nothing compares the record's owner with who is signed in; for a
record that is changed or removed only what was asked before the change counts, also when the change is made by a
helper or through the object the record was read into (`db.session.delete(note)`, `order.deleteOne()`: the line of
the change is then the flow's last step); `line` is the line the record is reached on, one finding for that line
with `routes`, the routes that get there, and `late` when every one of them does ask whose the record is, but only
after it), `LT-AUTHZ-ROLE` (285: an admin route with a login
where nothing asks for an admin; no `flow`), `LT-AUTHZ-MASS-ASSIGN` (915: everything the request sent is written
onto a stored record) and `LT-AUTHZ-CLIENT-ROLE` (807: a route decides what the caller may do on a value the caller
writes, a cookie, a header, a word in the address or the body named like a role or an admin flag, and nothing on the
route asks for a role the server keeps; one finding per place the value is read, `line` is that line, `claim` names
the value and the routes; no `flow`; made with or without a login on the route). A route with no sign of a login
gets none of the first three. `LW-AUTH-MISSING` says so instead: `lantern-web` makes it for a route the project's
own frontend calls, and the flow step makes it (`tool: "lantern-flow"`, with a `flow` to the record) for any other
route that changes or removes a record picked by an id from the request; a route made to be open (sign-in, a
webhook) gets none, and a route gets the finding once. Whether a route shows a login is read from its code where
the code says so (a condition on who is signed in whose other branch refuses, a token a library checked, a record
found by the request's own credential: `lantern/flow.py`), and from names otherwise. Where the code shows a login,
the finding by names is not kept. Where a login token is read on the way and nothing turns away a request whose
token does not hold (the failure is caught and the request goes on, the token is read without being checked, the
answer is not waited for), the name of that check is no sign, and a route that changes data gets the finding with
the title "... changes data, and Lantern found nothing that turns away a request whose login token does not hold".
`more_info` names what looked like a login on the route and was not taken for one, in sentences that begin "Not
taken for a login check:" (a library's login made optional with `optional=True`; a FastAPI security scheme whose
token the handler never looks at). Two things that are named like a login ask nobody who is calling and are no
sign by names (since 2026-11-16): a call into the management side of a sign-in service, which makes, changes or
removes whichever account it is handed with the server's own key (`websec.MANAGES_ACCOUNTS`: Supabase's
`auth.admin.*`, Clerk's `clerkClient.users.*` and its like, Firebase's `getAuth().setCustomUserClaims(…)` and its
like; the calls that do ask, `getUser()`, `auth()`, `verifyIdToken()`, count as before), and a secret setting of
the server that is read and handed on (`websec.SETTING_READ`: `process.env.NOTES_API_TOKEN`, `settings.API_TOKEN`),
which stands in a login's place only where the statement it is in compares something or calls a function named for
checking, or a later statement does so with the name it was kept under (a comparison with nothing, `=== undefined`,
only asks whether it is set). A Server Action has no verb and no request to read, so it is asked in a way of
its own (since 2026-11-14, `websec._actions_unasked`): an action that code of the project outside its tests uses,
that is not open by its name (sign-in, a webhook), that changes data and in which no strong sign of a login is
found gets `LW-AUTH-MISSING` with the title "The Server Action <name> changes data, the app uses it, and no login
check was found" (`MEDIUM`, `tool_confidence: LOW`; `line` is the action's first line, `snippet` the line read as
the change, and `more_info` says what was read as the change). "Changes data" is, in this order: a table call of
the map that adds, changes or removes rows (`meta.db_calls`); an SQL text inside a string of its lines that
changes rows (`insert into`, `update … set`, `delete from`, …; not in a comment); a member call named like a
database library's change (`create`, `update`, `delete`, `upsert`, `save`, `$executeRaw`, …), unless its chain
begins at something that is no database (the form's data, cookies, headers, a `Set` or `Map` of the function's
own, `crypto`) or the map followed the call into a library that keeps none of the app's data (a model provider's
`create`, a payment provider's `update`; `websec.ACTION_DATA_LIBS` names the libraries that do); Firestore's
`setDoc`, `addDoc`, `updateDoc`, `deleteDoc`. The action's own lines are read first, then the project's JS/TS
functions it calls, two calls deep. On the two public sample projects that have Server Actions the rule raised no
finding, so its precision is not known: it stays a heuristic (`tool_confidence: LOW`). `LA-WALLET-DRAIN` on an action
is titled "The Server Action <name> spends money …", and its `snippet` is the action's first line (a route's is its
verb and path). Since 2026-11-15 every `LA-WALLET-DRAIN` finding carries `paid`: `{"login": true|false, "limit":
true|false}`, what the rule found on the way to the paid call; the finding's story and heading are written from it (a
result written before has none, and its story is read from the title's fixed ending). A tRPC procedure is asked as a
route (a mutation is a
`POST`), with two signs of its own (since 2026-11-15): a name it is built on that holds a login word ("the
procedure `protectedProcedure` it is built on"), and, under any name, what the functions put before it and its
own lines do: `new TRPCError({ code: "UNAUTHORIZED" })` or `FORBIDDEN` written as code ("`adminProcedure` turns a
caller away (TRPCError FORBIDDEN, server/api/trpc.ts:17)", "it turns a caller away itself (TRPCError
UNAUTHORIZED, line 22)"). A comment, a text and another code (`TOO_MANY_REQUESTS`) are none. `more_info` of the
finding names what the procedure is built on. On a finding in a procedure, `input.via` names the handler's
`input` ("parameter `input`"), never the `.input(…)` step that says what the procedure accepts. On a SvelteKit
route (since 2026-11-15) `locals.user` and `locals.session` asked in the route's lines or in a helper's are signs.
The hook that runs before every route is not read by its name; the flow step reads its code. A part of it that
turns away every request with nobody signed in puts every route behind it in `logins_shown`; a part that names
the addresses it guards (`event.url.pathname.startsWith("/app")`, "every address but `/login`", `event.route.id`)
puts there the routes whose own address is certainly among them, and no other. A word of the address read by
its name (`url.searchParams.get("id")`, `request.nextUrl.searchParams.get("id")`, also off `new URL(request.url)`)
has `input.via` "`id` in `url.searchParams` is what the request sent", and the rules that ask who may reach what
read it as they read `req.query.id` on Express (before, it carried no name and they did not see it).

Two rules of `lantern-web` rest on the same step. `LW-XSS-RAW` (79, `tool_confidence: LOW`): a place in a page
template that prints a value without escaping it (EJS `<%- x %>`, Handlebars and Mustache `{{{x}}}` / `{{& x}}`, Pug
`!{x}` / `!=`, Jinja, Django, Nunjucks and Twig `|safe`, `|raw`, `{% autoescape off %}`; `lantern/templates.py`).
Its rank is what Lantern knows of the value: request data followed from a route into that place has the `flow` and
ranks like any flow into a page (`medium` when a step of the flow is only a likely link); when every place Lantern found that shows the page hands it fixed text, a number or
a value made safe for a page, the rank is `low`; anything else is `medium`; `fixed_why` says which in a sentence.
`LW-SECRET-INLINE` (798): a secret written in JS/TS, Python or a JSON settings file, one finding per line, rank
`medium`, `secret_kind` `signing` (the text that signs sessions or login tokens), `default` (a signing secret that
falls back to text in the code when the setting is missing), `password` (the password of an account the app
connects with) or `address` (a database address that carries its password); the `snippet` has `[redacted]` in the
secret's place and no field repeats the text.
`LW-TOKEN-PICKUP` (639): a Python or JS/TS route that hands back, under a credential's name, something it looks
up with one plain value of the request, with no second proof and no sign of who is calling in the handler; rank
`medium`, `tool_confidence` `LOW`. The finding stands on the line that fetches; the title names the route, the
word (`token`) and the value (`code`); `more_info` names the call that fetches and what to check (who can know
the value). Its `scenario` is the story kind `pickup`.
`LW-LOOPBACK-COOKIE` (287): a server the code starts on this computer's own address (`127.0.0.1`, `localhost`,
`::1`) that puts a login into a cookie: a cookie set under a name that says so, a `Set-Cookie` header, or the
framework's own session given a key that says who is signed in. A browser keeps cookies by host name and not by
port, so it sends this one to every other program that serves pages on the computer. Rank `medium`,
`tool_confidence` `LOW`. The finding stands on the line that sets the cookie; the title names the cookie;
`more_info` names the file and line of the start and says what to check (what the cookie opens) and what to do
for a server that stays on this computer (the key in a header the page adds itself). Its `scenario` is the story
kind `local-cookie`.
`LW-SW-KEEPS-PAGES` (525): a service worker whose `fetch` handler puts aside every answer it fetched under the
request's own address (`put` or `add` on a cache, in the handler or in a function of the file the handler hands
the request to) with nothing that narrows what is kept (the kind of file, its ending, a folder of static files, a
list), in a project where some other code file shows that people sign in. Rank `medium`, `tool_confidence` `LOW`.
The finding stands on the line that stores; `more_info` names the file that shows the login and says that the
copies stay in the browser after the person has signed out. Its `scenario` is the story kind `kept-pages`.
`LW-LIMIT-COUNTED-LATER` (367; `lantern/countlater.py`): a Python or JS/TS function that turns a request away with
402 or 429 where a condition says a limit is reached, then waits for its work (an awaited call, a call to a model or
another service), and writes the use down only after that (a call named for counting, a number stepped in place,
`increment:` / `decrement:`, SQL that sets a column to itself plus or minus). Requests sent at the same moment all
read the number before any is counted. Rank `medium`, `tool_confidence` `LOW`. Quiet where the use is counted or
held between the look and the work (the look's own condition included), where a limiter takes one in the look, where
the function names a lock or a transaction, and where the count shares no name with the look or with the line that
gave the look its value. The finding stands on the look's line; `more_info` names the lines of the work and of the
count and the name the two share. The work's own statement is one step, to where its brackets close: a take written
in it (an update that takes from the field under its own condition, written over several lines) holds, and a count
is looked for only after it. Its `scenario` is the story kind `counted-later`.
`LW-SHARED-CONNECTION` (567; `lantern/sharedconn.py`): a Python file that opens one SQLite connection with the
library's own guard switched off (`sqlite3.connect(..., check_same_thread=False)`), keeps it on `self`, on its
class or under a name at the top of the file, and uses it in a function with no lock held. Two requests that
are answered on two threads at the same moment can then be on the one connection together. Rank `medium`,
`tool_confidence` `LOW`. Quiet where a use stands under a lock (`with <lock>:`, a decorator with a lock's name,
an `acquire()` in the function), in the function that opens the connection and at the top of the file, for a
bare `close()`, in a function the file only calls from such places, and where every use that is left is in
`async def` functions or in functions only they call (the event loop's one thread). One finding for each
connection, on the first such line; `more_info` names the line that opens the connection, the other functions
with their lines, and how many uses stand under a lock. Its `scenario` is the story kind `shared-connection`.
`LW-CLIENT-ENV-SECRET` (200; `lantern/publicvalues.py`, roadmap stage 5): a setting whose name starts with
`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `GATSBY_`, `PUBLIC_` or `VUE_APP_` is copied
into what every visitor downloads, and `LW-PUBLIC-SECRET` reads its name. This rule reads what the setting is
given, where the name says nothing, on one line of a settings file (`.env*`, a shell file), a compose file or a
workflow, a `.toml` or `.json` settings file, a Dockerfile, or JavaScript (an entry `NAME: value`, a bundler's
`define`, `process.env.NAME = value`). Three reasons, on the finding as `public.why`: `address-with-password` (an
address `scheme://user:password@host` that is not this computer's and whose password is no placeholder; with
`public.from` when the password is another setting) and `key` (a key of a shape only servers hold, `public.kind`),
both rank `high`; `from-secret` (the value is exactly another setting whose name is a secret's, `public.from`),
rank `medium`. `tool_confidence` `LOW`: whether the file feeds the build people get, and whether the value is a
secret after all, cannot be read from a line. The value is never repeated; `snippet` is the setting's name. Quiet
for an address with no password, a password that is the user name or a placeholder, a key made for pages, a
type, a comparison, a comment, a build argument with no value, and a name `LW-PUBLIC-SECRET` already names in that
file. A key the secret scan lists on the same line is one finding, the secret scan's, which then carries `public`
and one more sentence in `more_info`. Its `scenario` is the story kind `secret`.
`LW-SERVER-IMPORT-IN-CLIENT` (200; `lantern/clientpull.py`, roadmap stage 5): a file that begins with `"use client"`
is handed to every visitor's browser with every file it imports and every file those import (`Graph.js_pulls`,
written by the JS/TS reader: value imports, imports for what a file does when loaded, re-exports; an import of types
loads nothing). One finding for each file reached that way whose code reads a secret setting by its name
(`process.env.NAME`, `process.env["NAME"]`, `import.meta.env.NAME`, `Bun.env.NAME`, `Deno.env.get("NAME")`,
`const { NAME } = process.env`; a name that says a secret, or a database's address; never a public-prefixed name),
on the line of its first such read. The server's code is then in what visitors download: rank `medium`. Where `env`
in the `next.config.*` file nearest above the page's file names that setting, its value is in the page too: rank
`high`, and `pulled.handed` says where. `tool_confidence` `LOW`: a bundler leaves out code that nothing calls, which
import lines do not show. The way stops at a file that begins with `"use server"` and at a file that imports
`server-only`. A remark, a text, a pattern and the words of a page that name a setting are no read. A settings file of
t3's env libraries (`@t3-oss/env-nextjs`, `-core`, `-nuxt`) is made to be imported by pages, and the library keeps the
server's settings out of them: a read inside a call of its `createEnv` is no read, unless the build hands the setting
over (`env` in `next.config.*`), where every read counts. Not read: a project with no `"use client"` file, `import()`
and `require`, a file that only loads a server library and reads no secret setting. Its `scenario` is the story kind
`server-code`, or `server-key` where the build hands the setting on.
`LW-SENSITIVE-COLUMN-RETURNED` (200; `lantern/wholerecord.py`, roadmap stage 5): a record sent back whole, with a
secret field in it. Which fields a record has, and which of them hold a secret by their names (a password's hash, a
reset token, a key), is read from the project's own model files (`lantern/datamodel.py`: a Prisma schema,
SQLAlchemy, SQLModel and Django classes, Drizzle tables). JS/TS, one function at a time: a Prisma query
(`<client>.<model>.findUnique|findFirst|findMany|create|update|upsert|delete`) that names no fields, selects a secret
one, leaves one in beside an `omit`, or brings a record that has one with `include`; a Drizzle query that names no
columns (`.select().from(<table>)`, `.query.<table>.findMany()`, `.insert|update|delete(<table>)….returning()`). It
is a finding where what the query found goes out as it came: the query, or the name it was given, stands in an
answer (`res.json(x)`, `NextResponse.json({ user })`, `new Response(JSON.stringify(x))`, `json(x)`), also inside an
object or a list written there, or is returned by a function whose result goes to the caller (a file or a function
that begins with `"use server"`, a tRPC procedure, `getServerSideProps`, a route's `loader`). Python: a FastAPI
route that returns the table's own object (a parameter written with the model's class, what a query for it gave, a
function of the project written to return one) with no `response_model` and no return type that names another
class, or whose `response_model` is the table's own class; a Django REST framework `ModelSerializer` whose `fields`
are `"__all__"` or list the secret field, or whose `exclude` leaves it in, and that does not mark it `write_only`.
Rank `medium`, `tool_confidence` `LOW`: a name says a secret or it does not, and code in another function that takes
the field out first is not followed. The finding stands on the query's line (a route: where it has the object; a
serializer: where it says which fields) and carries `columns`; `snippet` is the first field's name, never a value.
Quiet for a query that names its fields and none of them a secret, a field taken out in the same function (`delete
user.passwordHash`, `user.passwordHash = undefined`), a record handed to a function of the project, an answer with a
class of its own (`response_model=UserOut`). Not read: NestJS controllers, GraphQL resolvers, Koa, Flask and Django
views, Drizzle relations (`with:`), and whether a FastAPI object's fields are still loaded when it is returned. Its
`scenario` is the story kind `whole-record`.
`LW-UNSIGNED-WEBHOOK` (345; `lantern/webhooks.py`, roadmap stage 5; made by the flow step, so `tool` is
`lantern-flow`): a route a payment or message provider calls that writes stored data with no check of who sent the
message. A route is taken for a provider's when it takes a POST, shows no login, and its address has the word
`webhook` or `hook` or its own lines name a header or an event a provider sends (`stripe-signature`,
`x-hub-signature-256`, `svix-id`, `checkout.session.completed`). What it writes is read by the flow step, in the
route and in the functions it calls: a row made, changed or removed through a database library or by SQL text, and
an account made, changed or removed through the management side of a sign-in service (Supabase's admin API, Clerk's
backend client, Firebase's admin library). Three answers, `webhook.check`: `none` (no check was found), `lets-on`
(the provider's own check is called and a message that fails it, or never gets to it, still goes on: its failure is
caught and passed over, it is made for some requests only, its secret is missing or empty) and `late` (data was
written before the check). Quiet where every write stands behind the provider's own check of the signature (Stripe's
`constructEvent`, svix, Standard Webhooks), and where a check is written that Lantern cannot follow as code: a
comparison that takes the same time whatever the text (`timingSafeEqual`, `compare_digest`), a call named for
checking a signature, a webhook or a sender, a value compared with a secret setting or with something named like a
signature or a secret. It then cannot tell, and says nothing. Rank `medium`, `tool_confidence` `LOW`. The finding
stands on the route's first line and carries `webhook`; such a route is not listed a second time as one with no
login. Not seen: a check that is written and whose answer is thrown away, a check made by a gateway in front of the
app, and what a check by a provider's name does on a client Lantern cannot place (it keeps the rule quiet). Only
Stripe's, svix's and Standard Webhooks' own checks are followed as code; every other provider's is known by the
written signs above. Its `scenario` is the story kind `unsigned-webhook`.
`LW-NONATOMIC-BALANCE` (362; `lantern/balance.py`, roadmap stage 5): a Python or JS/TS function that checks a
balance (an `if` that compares it, negates it or looks for zero; a balance is a name with one of the words balance,
credits, coins, points, quota, funds, wallet, allowance, stock, inventory, also through the line that gave a name of
the condition its value) and after the check writes it down taken away as a step of its own: a store's update call
that writes the field with a decrement or a minus sign, SQL that sets the column to a value with a minus sign and
names no condition on it, or the object's field set lower and the object then saved or committed. Requests sent at
the same moment all read the same balance before any has written. Rank `medium`, `tool_confidence` `LOW`. The
finding stands on the check's line and carries `balance`: `{field, check, write, how}`, the lines of the check and
of the write, and `how`: `update`, `sql`, `saved`, or `bounded` (an update that writes back a value worked out from
the balance that was read, under a condition that only bounds the field: both requests pass the bound and write the
same value). Quiet where the write carries the check: a condition that holds the field to the value that was read
(`where: { credits: user.credits }`, `.eq('coins', profile.coins)`, `filter(points=profile.points)`), or a condition
that bounds it (`gte`, `__gte`, `>=`, `$gte`) beside a take from the value the database holds (`decrement`,
`F("credits") - cost`, `Model.credits - cost`, `SET credits = credits - $1`); where a lock or a transaction is named
before the check or on the lines that decorate the function; in JavaScript where the function waits for nothing; and
where `LW-LIMIT-COUNTED-LATER` names the same check. A chain written over several lines is one statement. Not read:
counters kept by Redis or another store's own commands, a field named `quantity`, a check and a take in two
functions; that the check and the take are about the same record is not checked (they share the field's name).
Inside a transaction it is quiet, which is quiet the wrong way at the usual isolation level of PostgreSQL and MySQL.
Its `scenario` is the story kind `balance-race`.

`mobile` is null unless the project is an Android app: `{"platform": "android", "modules": [{"root", "manifest",
"package", "min_sdk", "target_sdk", "permissions": [{"name", "line", "sensitive", "words", "used"}], "components":
[{"kind", "name", "exported", "launcher", "permission", "line"}]}]}`. `words` is the permission in plain words
("exact location"); `used` is true/false when Lantern knows what code would use it (a heuristic) and null otherwise.
The Findings screen shows it as "On the phone". Android findings (`rule` `LM-*`, `tool` `lantern-web`) carry
`platform: "android"`. Android entry details: `<Class> screen[ (app start)] · <method>` (page),
`INTENT <Class> screen (other apps and links can open it) · <method>` or `INTENT <Class> <kind> (other apps can start
it) · <method>` (route), `Android starts <Class> (<kind>) · <method>` / `app start (<Class>) · <method>` (main).

For an iOS app `mobile` is `{"platform": "ios", "modules": [{"root", "manifest" (Info.plist or the Xcode project),
"package" (bundle id), "min_ios", "permissions" (one per usage description: `name` is the Info.plist key, `sensitive` is
always true), "components" (one `{"kind": "link", "name": "journal://", "exported": true, …}` per URL scheme)}]}`; with
both platforms in one repository the iOS modules are added to Android's list with `"platform": "ios"`. iOS findings
(`LI-*`) carry `platform: "ios"`. iOS entry details: `<Type> screen · <method>` (page, a UIKit view controller method or
a SwiftUI `body`), `LINK <Type> handles links (other apps and web pages can open it) · <method>` (route),
`app start (<Type>) · body` (main).

Flutter and React Native findings (`LF-*`, `LN-*`) carry `platform: "flutter"` / `"react-native"`. For a React Native app
with an `app.json`, `mobile` (when no Android/iOS module claimed it) is `{"platform": "react-native", "modules": [{"root",
"manifest" (app.json), "package" (`android.package` or the slug), "permissions" (from `android.permissions`, words and
`used` as for Android), "components" (one `link` per `scheme`)}]}`. Entry details: `<Widget> screen · build` (Flutter
page), `<Component> screen · <Component>` or `· /<expo router path>` (React Native page), `LINK <Component> screen
(other apps and web pages can open it) · …` and `LINK <name> handles links (other apps and web pages can open it) ·
<fn>` (route). Readiness `shape` is `"Flutter app"` or `"React Native app"` for these.

Finding: `id` (stable across moves: tool, rule, file and the flagged line's text), `tool` (`bandit`, `pip-audit`,
`lantern-flow`, `npm-audit`, `maven-audit` (Gradle/Maven libraries through OSV; `line` is where the library is written), `composer-audit` (PHP libraries from `composer.lock` through OSV; `line` is where `composer.json` asks for it, else its `composer.lock` entry), `gem-audit` (Ruby gems from `Gemfile.lock` through OSV; `line` is the Gemfile's `gem` line, else the lock entry), `copied-audit` (software copied into a `vendor` folder, looked up through OSV by what its `package.json` says it is; `line` is that file's `version` line), `secrets`, `lantern-web`, `lantern-pack:<name>`), `rule`, `title`, `tool_severity`, `tool_confidence`
(`LOW` = show "heuristic"), `file`, `line`, `cwe`, `more_info`, `snippet`, `category`, `in_tests`, `node`,
`reachable` (null or `{"entry", "kind", "path": [node ids]}`), `reachable_from_tests_only`,
`reachability` (`{"state", "kind"?, "why"}`: what is known about who runs the flagged code, as a fact of its own
beside the rank. `reached` (with the `kind` of entry point), `tests-only`, `unknown` (no path was found, or the
line is in no function of the map: never to be shown as "nothing runs it") or `not-code` (a library in a list). A
path that was not found lowers no rank),
`test_file_in_use` (true on a finding in a file named like a test that a page, route or command outside the test
files runs through links Lantern worked out: it is then the app's code, `in_tests` is false and it is ranked like
any other), `test_file_guessed` (true where only a guess by method name leads from the app into the test file: it
stays test code and the reason says so), `test_file_stood_in` (true where only the recording of the project's own
test run leads from the app into the test file, a call to a stand-in, a callback or a double that a test handed
the app: it stays test code, as it is with no test run, and the reason says so), `ui_path` (node ids from a
page, or null), `input` (null, `false`, or `{"via": "parameter `name`"}`; when a flow was followed to the line,
`{"via": <the words of the flow's first step>, "flow": true}`; not for a flow of text a model wrote, nor of what a
model puts into a tool), `flow` (optional,
`flowscan.py`: request data, or text a model wrote, followed to this line across functions and files, on a
`lantern-flow` finding or attached to another tool's finding for the same kind of problem on the same line; a flow of
text a model wrote is on an `LA-MODEL-OUTPUT-TO-TOOL` finding only, and one of what a model puts into a tool on an
`LA-UNSAFE-MCP-TOOL` finding only: `{"class"` (`sql`, `shell`, `eval`, `deserialize`, `xxe`, `path`, `ssrf`, `xss`,
`redirect`, `nosql`, `pollution`, `record`, `assign`), `"confidence"` (`HIGH`, or `LOW` when a step is a likely link),
`"severity"`, `"origin"` (`server`: what a request sent; `dom`: the page's own address in the browser; `model`: text a
model wrote, from the call that gave it back; `tool`: what a model puts into a function of the project it is handed
as a tool, from the function's parameter), `"writes"` (optional, `true` where the action writes, changes or removes
the file it names; a file that is only read has none), `"source": {file, line, what}`, `"sink": {file, line, what}`, `"steps": [{file, line, what}]` (from the
request to the sensitive action, in order; `what` is a sentence with code names between backticks), `"others"` (up to
five other starting points that reach the same line), `"count"}`; the viewer's box "How the value gets there" lists
the steps, every value escaped), `claim` (`LT-AUTHZ-CLIENT-ROLE` only: `{"name"` (the cookie, header or field as
the code reads it), `"sent_as"` (`a cookie`, `a header`, `the address`, `the request's body`), `"what"` (a sentence:
where the value arrives), `"routes"` (the routes that decide on it)`}`), `secret_kind` (`LW-SECRET-INLINE` only),
`routes` (`LT-AUTHZ-OWNER` only: the routes that reach the record on this line, e.g. `["GET /orders/:id"]`),
`late` (`LT-AUTHZ-OWNER` only, optional: `"change"`, `"shell"`, `"remove"` or `"send"` when the route does ask whose
the record is, but only after it changed the record, ran a command, removed a file or told another service to
change something for it; the scenario's `kind` is then `owner-late`),
`owned` (`LT-AUTHZ-OWNER` only, optional, since 2026-11-16, `lantern/tenantscope.py`: what the project's model files
say of whose the record reached on this line is: `{"model"` (as the file writes it), `"kind"` (`prisma`,
`sqlalchemy`, `sqlmodel`, `django`, `drizzle` or `sql`), `"file"`, `"line"` (where the model is written), `"fields"`
(the fields that name its owner, `["orgId"]`; may be empty)`}` and, where `fields` is empty, at most one of
`"itself": true` (it is what other records belong to: an org, a user), `"through"` (the name of the record it
belongs to) or `"maybe"` (fields that may say whose it is under another name: `["customerId"]`). With none of them
the data gives the record no owner: a finding about a read of it then has `rank` `low` with the model file's place
in `fixed_why`, a finding about a change or a removal keeps its rank. Absent where the line names no model of the
project; the case's `evidence` then has no entry `from: "data model"`),
`fixed_why` (optional, on a rule Lantern gives one rank whatever reaches it: the sentence shown as the reason for
the rank, `case.severity.why`), `rank` (`critical`|`high`|`medium`|`low`),
`rank_basis` (how the rank came about, in order: `[{"step", "rank", "why"}]` with `step` one of `severity` (the
tool's own severity, where every rank starts), `raised` (request data was followed to the line; an entry point from
outside reaches it), `lowered` (evidence from the code around the line, the `rank_note`), `fixed` (a rank the rule or
the kind of finding fixes) and `test-code`; the last step's `rank` is the finding's; also in `case.severity.basis`),
`context` (optional, `context.py`, read from names around the line: `{"hash": {"purpose": "security"|"non-security"|"unknown", "why", "password", "reads"}}`
for weak-hash rules, `{"sql": {"fixed_only", "spliced": [{"expr", "fixed", "why"}], "driver_params", "reads"}}` for Python SQL,
`{"fixed": {"class": "sql"|"shell", "function", "calls": [{"from", "file", "line"}], "count"}}` when a tool flagged a query or a command, no flow
reaches it, and every call Lantern found hands that function fixed text (only when the flow step read everything; rank `low` with the reason); in Python kept as text, which the flow step does not read, the same table with no calls and `"reads": "the call on this line"` when every call that starts on the flagged line is handed literals only (`context.fixed_command`); never for the scanner's wildcard finding (B609: the shell fills a `*` in with the names of the files it finds, which the command's text says nothing about)), `rank_note` and
`rank_before_context` (only when `context` lowered the rank: why, and the rank it would have had; the viewer shows both; a
non-security hash or SQL splicing only fixed text → `low`, a hash of unknown purpose → at most `medium`),
`trust` (LW-PUBLIC-SECRET only, `context.public_secret_trust`: `browser` `{exposed, where, sent_as}`, `server_trusts`
(`server-checks-it`|`server-reads-it`|`not-seen-on-server`|`no-server-code`), `server_checks`, `server_reads`, `routes`,
`other_controls` `[{route, login_check, why}]`, `conditions` (settings the checking code branches on), `stranger_access`
(always `not determined`), `unknown` [plain sentences]; never changes the rank),
`public` (`LW-CLIENT-ENV-SECRET`, and a secret-scan finding on a line that gives its key to a public setting:
`{"name"` (the setting), `"why"`: `address-with-password`|`key`|`from-secret`, `"from"` (the other setting, where
there is one), `"kind"` (which key, for `key`)`}`; never the value),
`pulled` (`LW-SERVER-IMPORT-IN-CLIENT`: `{"settings"` [the secret settings the file reads by name, at most 12, the
one the build hands on first], `"path"` [the files from the page's file to this one; a way of more than 12 files is
listed by its two ends], `"not_shown"` (how many files of the way are not listed), `"clients"` (how many files that
begin with `"use client"` reach it, null when that was not counted), `"handed"` (null, or `{"file", "line"}`: where a
`next.config` file's `env` names the setting)`}`),
`columns` (`LW-SENSITIVE-COLUMN-RETURNED`: `{"model"`, `"fields"` [the secret fields that go back, at most 12; one
that a record brought with it is written `author.passwordHash`], `"via"`: `prisma`|`drizzle`|`sqlalchemy`|`sqlmodel`|
`django`, `"defined"`: `{"file", "line"}` (where the model is written), `"sent"` (the line it goes back on)`}`),
`webhook` (`LW-UNSIGNED-WEBHOOK`: `{"route"` (`POST /api/webhooks/stripe`), `"why"` (what made Lantern take the route
for a provider's: the word of its address, or the header or event name in its lines), `"check"`: `none`|`lets-on`|
`late`, `"changes"` [`{"file", "line"}`: where stored data is written with no check before it, at most 6], `"more"`
(how many such places are not listed, only when there are more), `"at"` (the line of the check that lets a failed
message on, or that comes after the write; absent for `none`), `"at_file"` (the file that line is in, only when it
is not the route's own)`}`),
`agent_loop` (`LA-UNBOUNDED-AGENT-LOOP`, since stage 5: `{"kind"`: `loop`|`itself`|`setting`, `"paid"` [the
paid calls made in each round, at most 4: `{"file", "line", "what"` (the call as written), `"through"` (only
where the call is made in a function the round calls: the place of the model call itself, `file:line`)`}`],
`"ends"` [the conditions on the model's answer that end the rounds, at most 4: `{"line", "what"}`], `"setting"`
(only for `setting`: the words of the limit that is switched off)`}`),
`row_rules` (`LW-NO-RLS` only, since 2026-11-14, `websec.row_rules`: what the project's SQL files, replayed in the
order they are applied (`lantern/rowrules.py`), leave open on one table: `{"table"` (`<schema>.<name>`), `"state"`:
`off` (the files create the table and never switch row-level security on), `off-in-the-files` (the same, and code
that runs in the database names row-level security, which Lantern does not run: a guess, `tool_confidence: LOW`),
`open-write` or `open-read` (row-level security is on and a policy lets every one of its roles through with a
condition that is always true); for the last two `"policy"`, `"lets"` (`insert`, `update`, `delete`, or `select`)
and `"for"` (`everyone`|`signed-in`); `"client"`: the functions on the visitor's side that reach the table through
the map's `db:` links, `[{"node", "does": [ops], "file", "line", "on", "why"}]`, empty when Lantern found none,
which is not proof that none does}`. The rank is the rule's own (`fixed_rank`, with `fixed_why`): a table with
row-level security off is `high`, and `critical` where `client` is not empty; `off-in-the-files` `medium`; a
policy that lets everyone change or remove any row `high`, `critical` where `client` is not empty; one that lets
any signed-in user do so `high`; one that only lets rows be added, or lets every row be read, `medium`. A policy
for the server's own roles (`service_role` and its like), one that asks who is calling, one a restrictive policy
narrows, and a table the files do not create make no finding. `pin` is the table's `db:` node when the map has
it; the finding's id is the one the older rule gave the same line. The heading, the story and the case are worded
from it (`scenarios.row_words`): what is open (every row to read and change, rows to change or remove, rows to
add, every row to read) and for whom (anyone, or anyone who signs up), where the key is taken from (the page, or
the phone app), and in `case` an `evidence` entry `from: "SQL files"` and three conditions: what the files leave
open (`met` true, or null for `off-in-the-files`), "The database is as the project's SQL files leave it" (always
null: a change made in the dashboard is in no file), and "A visitor has the table's name and the public key"
(true where `client` is not empty, else null, never false). A finding without `row_rules` (Firebase's rules,
results an older Lantern wrote) is told as before),
`case` (every finding outside test code, `case.py`, version 1: `where` `{file, line, function, revision, revision_note?}` (revision = the analyzed folder's git commit, `null` outside git; `revision_note` when the folder has uncommitted changes, or the header's `note` when git could not compare the files), `claim` (the tool's words, never stronger than the evidence), `evidence` `[{fact, from}]` (`from`: the tool, `map`, `input check`, `context (names)`/`context (code)`, `SQL files`, `data model`, `data flow`, `code`), `conditions` `[{need, met, why}]` (what has to be true for harm; `met` true = Lantern saw it, false = saw it is not, null = cannot check), `impact` (the scenario's harm), `severity` `{rank, tool_severity, why, before_context?, context_note?}`, `confidence` `{level: high|medium|low|unknown, why, about}` (the tool's own confidence, one step lower when the path has a `likely`/`possible` link; about the pattern being there and reached, never about exploitability), `unknown` [plain sentences], `status` `[{word, done, why}]` for `reported`, `reproduced` (the id was in this folder's previous `security.json` or `baseline.json`; null on a first run), `fixed` (false while listed), `tested` and `independently reviewed` (always null: Lantern keeps no such record; an accepted risk is a review by the builder, not an independent one)),
`status` (`open`|`accepted`), `accepted` (`{"reason", "by", "date"}` when accepted; with `"how": "nosec"`, and `by`
and `date` null, when the acceptance is a `# nosec` comment with a written reason on the line),
`nosec` (Bandit findings only, when the line carries a `# nosec` comment about this finding: `{"state", "reason"}`.
`accepted`: a reason is written and Lantern followed no request data to the line, so the finding counts as a risk
the project accepted, shown and counted like one accepted with `lantern accept`, its rank as it was. `bare`: no
reason that reads as one, `reason` null, the finding stays open. `overruled`: a reason is written and Lantern
followed request data to the line, so the finding stays open. The reason is the project's own text, on one line,
at most 300 characters: escape it like any other value), `hot_lane` (the lane the problem
lives on: the pinned node's `lane`, or from the file for a finding with no node, e.g. a secret in `settings.py` →
`server`), `lanes` (every lane the finding's path crosses, in strip order, de-duplicated: the `ui_path` (or `reachable`
path) nodes' lanes, plus `hot_lane`, plus `data` when the pinned node calls a data-lane external — the glyph fills these
dots and colours the `hot_lane` dot by rank), `headline` (optional: the finding's heading in plain words for Simple
view, from a fixed sentence per kind in `scenarios.HEADLINES`/`FIXED_HEADLINES`, filled only with the clicked thing, page or
route from the map, and only when input reaches the line; absent for rules with no sentence, so show `title`; when
shown, also show `title` as "<tool> says: …"), `scenario` (`{"kind", "who", "steps": [str], "harm", "after_fix",
"basis"}`: a short story of one person meeting the finding, built by `scenarios.py` from this finding's own facts; show
`steps` as a numbered list, then "What goes wrong" and "After the fix", and `basis` small underneath; prefer the model's
`findings[].scenario` from `explanations.json` when there is one).

### `readiness.json`

`version` (2 since 2026-11-11), `score`, `grade`, `checklist`, `release`, `shape`, `stack` (`{frameworks, …}`),
`categories` (`[{key, title, weight, score, percent, checks: [{id, title, points, earned, status:
pass|fail|partial|skip, evidence, fix, how, required?}]}]`; a skipped check leaves the sum, except one with
`required: true`: the release needs it and the work was not done (the tests were not run, or, since 2026-11-13, were
stopped at their time or memory limit: `tests-pass` then says "not finished: …" where it said `fail` for the clock
before; listed libraries were not looked up), so its points stay in the sum and it earns none), `next_steps` (the
highest-gain failed checks, with `gain` and `category`), `protections` (`[{id, title, status: add|check|in place, why,
evidence, found, how}]`; for `rate-limit` (`lantern/ratelimit.py`) `in place` means every route in question shows a
limit that covers it (on the route, or put on the app before the route in the same file), `check` that a limit exists
and the code does not show that for each of them (a default limit for the whole app, a limiter in another file, the
project's own limiter in which nothing visibly counts), `add` that nothing puts a limit to work, whatever is
installed; `evidence` lists the routes without one first, `found` what covers the others; for `security-headers`
(`lantern/headers.py`, since 2026-11-12) `in place` means the code or a hosting file shows a header set for every
response (a hosting rule for every path, a library put on the app, the project's own function that runs for every
request) of every app of the project that has pages or routes of its own, `check` that a header is set and the code
does not show every response gets it (a `<meta>` tag in one page, one route's own answer, a rule or a library for one
path, a table of headers nothing visibly sends, a setting for one app of several: `why` names the folders left out), `add` that
nothing sets one, whatever words stand in the code; `found` lists the places as `<file>:<line> (<what>)`), `incomplete` (the scanner records from `security.json` that apply and are not `ok`; the
`sec-scanners` check in Security findings fails when one `failed` or timed out, is partial for a gap the run knew
about, and passes only when every applicable scanner finished), `advice` (deployment advice strings for the shape),
`hotspots`, `env_vars`, `starter` (`{filename: {content, snippet?}}`).

`checklist` is the weighted average of the categories (what `score` was in version 1). `score` is that number held
down by the release decision: never above 59 while the decision is Blocked, never 100 unless it is Passed. A
version 1 file has neither `checklist` nor `release`; show its `score` as before and no decision.

`release` (`lantern/release.py`) is the answer to "can this ship", made from required criteria and never from the
average (the shop sample, shortened):

```json
{"decision": "Blocked",
 "words": "Blocked: 3 critical and 1 high findings open outside test code: B602 at shop/app.py:16, …",
 "profile": {"name": "full-stack web app", "required": ["findings", "scanners", "dependencies", "tests"],
             "not_required": [{"id": "behaviour", "why": "The project has no behaviour plan …"}]},
 "criteria": [{"id": "findings", "title": "No critical or high finding is open", "required": true,
               "state": "failed", "why": "3 critical and 1 high findings open outside test code: …",
               "fix": "Fix each one …", "ids": ["57fa455f7b3b", "…"]},
              {"id": "tests", "title": "The project's tests were run and passed", "required": true,
               "state": "missing", "why": "The tests were not run in this check. …", "fix": "Run them under Lantern: …"},
              {"id": "behaviour", "title": "The behaviour checks held when the app was started", "required": false,
               "state": "not-applicable", "why": "The project has no behaviour plan …", "fix": ""}],
 "blocking": ["findings"], "missing": ["dependencies", "tests"],
 "bound_to": {"commit": "1a2b3c…", "uncommitted_changes": false,
              "code": {"files": 15, "sha256": "40c2…", "not_read": 0, "left_out": "the folders no reader …"},
              "dependencies": {"files": {"pyproject.toml": "0ca7…", "web/package.json": "9de9…"}, "count": 2,
                               "sha256": "ad5c…"},
              "settings": {"scan": true, "trace": null, "offline": false, "place": "local", "packs_off": [],
                           "accepted_sha256": null, "plan_sha256": null, "plan_unusable": null},
              "tools": [{"tool": "bandit", "version": "1.9.4", "role": "…", "state": "ok"}, …],
              "lantern": "0.11.0", "python": "3.13.1", "system": "Linux"}}
```

`decision`: `Blocked` (a required criterion `failed`), `Incomplete` (none failed and one is `missing`) or `Passed`
(every required criterion passed). Six criteria, each with `state` `passed`, `failed`, `missing` or
`not-applicable`, a `why` and, when it is not passed, a `fix`: `findings` (failed while a critical or high finding is
open outside test code; an accepted one does not block and is named in `why`), `scanners` (missing while a scanner
that applies did not finish or did not cover everything, or while the project keeps code as text that no scanner
read: `security.json` `not_read`), `dependencies` (missing while a listed library was not
looked up, or the project lists libraries of a kind Lantern has no check for yet: Go, Rust, Dart and Flutter, .NET,
Swift, C and C++, or software copied into a `vendor` folder was not looked up (`copied-audit`: offline, or files with
no name and version); `not-applicable` and not required where the project lists none and holds no such copy), `tests` (passed only when the
project's tests ran in this check and ended with 0; failed when they ended with anything else; missing when the
project has none, they were not run, the sandbox could not be set up or stopped them, it refused something they
tried, or they ended with an error in a run where the libraries the project names as optional could not be had and
were left out, `trace.libraries.optional.fetched: false`; for a project with none, since 2026-11-21, `write` lists the
tests to write first, read from the code, at most 50, as `{kind, where, file, line}` (`where` names the route as
the readiness page's other lists do: `POST /api/notes`, and a Server Action as `the Server Action save`; `file` and
`line` may be null) with `kind` one of `sign-in`, `signed-in-change`, `open-change`, `paid`, `read`, `page`, `write_count` counts all
of them, and `fix` names at most three of each kind and, where Lantern offers one, how to write the first test file
(`lantern starter PATH --write tests/test_first.py`, or the app's starter files); where a browser opened the site on
this code, `why` says that this does not count in place of tests), `behaviour` (not required where the project has no `lantern-behaviour.json`; else passed only when
`behaviour.json` carries this computer's seal, is of this plan and this code, and every case held; failed when a
case came out broken), `browser` (since 2026-11-21; not required where `lantern browse` would find nothing to open,
no app Lantern can start and no folder of plain pages; else passed only when `browser.json` carries this computer's
seal, is of this code (`of.code_sha256` = `bound_to.code.sha256`), opened at least one page, and each of `opens`,
`script`, `forms`, `visitor` and `protections` held or had nothing to check, with `opens` held (`protections`
`not-run` for `hosting-unknown` on plain pages is allowed and said); failed when one of those five came out
`broken`; missing for any other record, one of those five `inconclusive` or `not-run`, or no record; `leads`,
`outside` and `keyboard` block nothing and are said in `why`; `docs/browser.md`, "In the release decision"). `blocking` and `missing` name the required criteria in those states. `bound_to` is what the
decision is about: `code.sha256` is one SHA-256 over every file of the project by path and content (the folders no
reader looks into, and this run's results folder, are not in it), `dependencies.files` has one SHA-256 for each of
the first 200 files that list libraries and `dependencies.sha256` one over all of them, `settings` holds the run's
options with the SHA-256 of `lantern-accepted.json` and of the behaviour plan (`plan_unusable`: why a plan that is
there cannot be used), `tools` every tool with its version and how its run ended. The file lies in the results
folder, which may come with a project: a page, a card or the connector shows the decision only when it is one of
the three words, takes the texts beside it as plain text of a bounded length, and works out `blocking` and
`missing` anew from the criteria (`release.shown`). `lantern analyze PATH --require not-blocked|passed` ends with 1
unless the decision of that very run is good enough (`not-blocked` stops on Blocked, `passed` on Incomplete too);
the run's log has a line `release <decision>: <first reason>`.

### `explanations.json`

`{"metaphor": {"world", "why", "roles"}, "explanations": {node id: record}, "stats": {...}}`

Record: `lens1` `{summary, inputs, outputs, side_effects, errors, role}`, `lens2` `{text, example, analogy}`,
`lens3` `{text, pairs: [{plain, technical, anchor: {type: symbol|lines|term, …}}]}`, `scenario` `{who, story}` (optional:
a short story of someone using the app so this function runs), `findings` `[{id, lens1, lens2, fix, scenario?}]`,
`dropped_scenarios` (scenarios that broke the rules: removed, never shown), `model`, `prompt_version` (`lens-v4`),
`validated`, `validation_errors`, `attempts`, or `{"error", "validated": false}` when the model failed. Show Lens 3
pairs as hover/tap links from the plain phrase to the anchored code. The Scenario tab shows `scenario.story`; with none,
the scenario of the function's finding, else a one-line sketch from the map.

### `evidence.json`

`header` (`repo`, `name`, `commit`, `branch`, `dirty`, `remote`, `committed_at`, `generated_at`, `mode`, `privacy`;
`note?`: a sentence, present when there is no commit (`not a git repository`, `git not installed`, or why the folder's
git folder was not read: it is a link, it is kept in a place that does not name the folder back, or it lies outside
the folder and is not the current user's) or when git could not compare the files with the commit, in which case
`dirty` is `true` (also where the git folder takes part of its history from another place, a list of other folders of objects, which `git clone --shared` and `--reference` write too, or a link among its own objects: git is not started on it and `committed_at` is null): `lantern/gitfacts.py`),
`scorecard` (`readiness` (with `checklist` beside `score`), `now` counts, `before` counts, `baseline_date`,
`baseline_commit`), `release` (the whole `release` of `readiness.json`, or null for a readiness file an older Lantern
wrote; the Scorecard section shows the decision, every criterion, the profile and what the decision is tied to; the
digest takes in the decision, each criterion's state and the SHA-256s of the code, the dependency files, the plan
and the accepted risks, so `lantern verify` fails when one of them differs; the badge is green only for `Passed`
and otherwise ends in `blocked` or `incomplete`), `architecture`,
`security` (`open`, `accepted`, `fixed`, `changed`, `in_tests`, `protections`, `incomplete`: `[{tool, state, status,
why, role, version}]`, the scanners that did not finish or did not cover everything; while it is not empty the memo, a
notice under the tiles and the badge say `scan incomplete`, and the badge is never green), `understanding`,
`provenance` (`workspace`, only for the map of a workspace: `{"name", "made", "members": [{"name", "from",
"source", "commit", "dirty", "branch", "remote"}]}`, which the page shows as "Projects in this map", and which the
digest takes in through `payload.workspace` = `{"members": ["<name>:<commit>[+changes]", …], "shared": <count>}`, so
a project of its own has no such part and its digest is as before; the Limits then say the map is a workspace of
those projects, which of them is in no git repository or had changes not committed, how many links of code cross
between them and how many names two of them write, and whose accepted risks are not read there;
`tools` with each scanner's `state` and `status`, `models`, `rules`, including analysis packs, and
since 2026-11-13 `libraries`: the libraries the project's tests ran on, taken from `run.json` by shape,
`{state: "fetched"|"installed", store, exact, checked, left_out, above, packages: [{name, version, exact, checked,
fingerprint, built_from?}], optional_left?, built?}`, or null when no test run is in the results or the tests ran on no library; the page lists them
under "Libraries the tests ran on"; `optional_left` is there only when optional libraries were left out of the fetch,
`{groups: [<name>, …], more}` with names of the form a tool writes only, and the Limits then carry a line for it;
`built_from` is the fingerprint of the source a package was built from for the run (taken only when it has the shape
`sha256:<64 hex>`), `built` counts such packages, and the Limits then name them and say that the package was made on
that computer for that run), `limits`
(strings: what the report does not prove; one line per incomplete scanner; one line per kind of project for the
dependency entries that were not checked because they have no exact version, whatever state that audit ended in; one
line when the baseline in the results folder could not be used, in which case `scorecard.before`, `baseline_date` and
`baseline_commit` are null and `security.fixed` and `changed` are empty; one line per kind of project for libraries
named where no lock file says which version is installed, one for folders whose versions are in a pnpm, yarn or bun
lock file, one saying that the release decision is about exactly the files, libraries, settings and tools it names,
and one saying that no app was started where the project has no behaviour plan), `digest` (`sha256:…`), `payload`.
An accepted finding whose `accepted.how` is `nosec` is shown as "Accepted in the code (a # nosec comment on the
line)" with its reason, and has no name and no date.

### `behaviour.json`

Written by `lantern behave PATH` (`lantern/behave.py`), which starts the project's app in the test sandbox and runs
the project's own plan, `lantern-behaviour.json` (its shape, the kinds of check and the limits: `docs/behaviour.md`).
No finding changes with it. Since 2026-11-11 the release decision reads it (`readiness.json`, criterion
`behaviour`), and counts it only when it carries this computer's seal and is of the plan and the code that are in
the project now.

A plan that `lantern behave --init` wrote (or the app's "Behaviour plan" button) carries one more table, `notes`,
which the runner does not read: `made_by`, `read_first` (sentences to read before the first run), `review`
(`[{check, why}]`: the cases to look at first) and `left_out` (`[{route, where, why}]`: routes with no case).

```json
{"version": 1,
 "from": "running the project's code in Lantern's test sandbox, with no network",
 "of": {"plan_sha256": "9f2c…", "code_sha256": "c41e…", "commit": "1a2b3c…", "dirty": false, "lantern": "0.11.0",
        "python": "3.13.1", "system": "Linux"},
 "seal": "…",
 "ran": true, "why_not": null,
 "summary": {"held": 3, "broken": 1, "inconclusive": 0, "not-run": 0},
 "outcomes": [
   {"check": "delete-note", "case": "amir", "kind": "refuse", "about": "Only its owner deletes a note",
    "outcome": "broken", "codes": ["refused-but-changed"],
    "said": "was refused, and something had changed all the same",
    "saw": {"status": 403, "changed": {"notes": [0, 1, 0]}}}],
 "seconds": 1.2, "app_starts": 3}
```

`ran` false with `why_not` means nothing was judged: the project has no plan (`no_plan: true`, the only case that
key is written in), the sandbox could not be set up or starts no app on this system (`sandbox.NO_APPS`; no system
since 2026-11-20, when Windows started apps too; the app was then not started), the plan's set-up failed at a
step, or the run left no record. A plan that cannot be used writes no file at all. The command ends with 0 only when
`ran` is true, at least one case held and none is broken, inconclusive or not run; 1 when a case is; 2 for no plan,
a plan that cannot be used or a path that is no folder; 3 when the app was not started or the run left nothing to
judge. `outcome` is `held`, `broken` (with `codes` and `said`), `inconclusive` or `not-run` (each with `why`).
`saw`: `status` of the last answer, `changed` (per table `[rows added, removed, changed]`, `(files)` for the app's
folders), `tried` (what the sandbox refused, or what the app began where this computer has no IPv6), `asked`
(`[name, address]` the app asked about and the runner answered), `outside` (files outside the app's folders that
were made, removed or changed, as paths from the sandbox's temp folder; at most five), `died`. `tried` and `outside`
hold text a request may have chosen: escape them like any other value. `of` says what was run: the plan's SHA-256,
the SHA-256 over every file of the project as the release decision counts it (`code_sha256`, taken before the app
is started), the commit and whether files differed from it (`gitfacts.info`), Lantern's version, Python and the
system. `seal` (`lantern/seal.py`) is an HMAC-SHA256 of the record under a key this computer's Lantern made on
first use and keeps in `LANTERN_HOME/seal.key`; it is absent when that folder cannot be written. The results folder
usually lies in the project, so a project can bring a `behaviour.json` of its own: without a seal that holds, the
record counts for nothing. The seal says which Lantern made the record, not that the record is right.

### `browser.json`

Written by `lantern browse PATH` (`lantern/browse.py`, `docs/browser.md`, a firm pass or fail, stage 5): the project's
own site opened in a real browser, and what each check saw there. It is written whatever came out, through
`results.write`. The release decision's `browser` criterion and the report's card read it (since step 3, the same
day), each only when `seal` holds and `of.code_sha256` is this code's.

| Field | Meaning |
|---|---|
| `of` | which code: `commit`, `dirty` (`gitfacts.info`), `lantern`, the version that made it, and `code_sha256` (since step 3), the SHA-256 over every file of the project as the release decision counts it (`release.code_digest`, the results folder left out), taken before anything is opened |
| `ran` | `true` when the pages were opened; `false` with `why_not` (one of `browse.WHY_NOT`'s keys: `not-built`, `no-browser`, `no-browser-sandbox`, `browser-failed`, `no-site`, `not-started`, `no-sandbox`) and `why`, Lantern's own sentence for it |
| `browser` | `{name, version, own_sandbox, how, keyboard_end}`: the browser as it names itself, whether it kept its own sandbox (always `true` in a record with `ran: true`: without it no page is opened) and how that was told, and what it does when Tab is pressed on the last control of a page, looked at once a run on a page of Lantern's own (`leaves` the page, `wraps` to the first control, `stays`, or `unknown`; the keyboard check reads a trap with it); `null` where no browser was started |
| `site` | `{how, address, pages}`: `pages` (a folder of plain pages served by Lantern's own code) or `app` (the app started in the sealed box), the address it was opened at (`http://localhost:<port>`, where nothing listens) and how many pages the site says it has |
| `opened` | each page opened: `{path, status, seconds}` (`status` is the answer's status, `null` where none came) |
| `checks` | one row a check, in the order of `browse.CHECKS`: `{id, outcome, codes, saw, why}`; `outcome` is one of `held`, `broken`, `inconclusive`, `nothing-to-check`, `not-run` (only `held` counts as held), `codes` the codes of `docs/browser.md` of the decided rows only, `saw` what the browser saw (at most a few rows a check; a row with `undecided: true` came on a page where a script from another computer was refused while it loaded, and may come from that script being missing; a check whose every row is undecided is `inconclusive`) |
| `asked_outside` | every request a page made for another computer, once for each address and page: `{address, host, kind, page, refused}` (`kind` as the browser names it: `script`, `image`, `fetch`, …; `refused` is always `true`: it was refused inside the browser) |
| `browser_own` | what the browser asked for itself, not its pages (method and host), refused at Lantern's door; not counted for the site |
| `seconds`, `notes` | how long the run took; at most ten notes about the site (pages left out, a part not read) |
| `pictures` | since step 3: `{set, shots, not_kept}` (and `why`, Lantern's own words, when the pictures' folder could not be made): `set` the run's folder under `LANTERN_HOME/pictures/` (32 hex digits) or `null`, `shots` each page with a picture, in the order opened, `{page, name, bytes}` (`name` the picture's SHA-256 and `.png`; at most ten), `not_kept` how many were not kept (not a PNG, over 8 MB, past ten, or not written). The pictures themselves are never in the results folder (`docs/browser.md`, "Pictures of the pages") |
| `seal` | since step 3: this computer's seal over the record (`lantern/seal.py`, as on `behaviour.json`); absent where `LANTERN_HOME` cannot be written. Without a seal that holds the record counts for nothing |

Everything in `opened`, `checks[].saw`, `asked_outside` and `browser_own` comes from the site or the browser: escape
it like any other value. The command ends with 0 only when a check held and every other check held or had nothing to
check, 1 when a check is broken, undecided or was not run, or none held, 2 when there is nothing to open, 3 when the
site was not started or no browser could be used.

### `change/` (the change receipt, `lantern diff`)

Written by `lantern diff [PATH] [BASE..HEAD]`, by the app's "What changed" (`POST /api/projects/<id>/change`) and by
the GitHub Action on a pull request (`docs/github.md`), into `change/` of the results folder: `change.json` (the
data), `change.md` (the text for a pull request, begins with `<!-- lantern-change -->`), `change.html` (one page with
no script), and the two checks' own results in `before/` and `after/` (each a results folder like any other; a side
that was handed over with `--base-results` / `--head-results` is not written again). The receipt is a pure function
of the two checks' `graph.json`, `security.json` and `readiness.json` (`diff.compare`): no model writes or ranks any
line, and two versions that differ only in comments and spacing give `same: true`. `diff.read(path)` reads a receipt
back the strict way (a plain file, `schema` 1, every part there; `diff.NotResults` otherwise).

The check before each push (`lantern hook install`, `lantern/hook.py`) writes the same files for each branch or tag it
checks into `.lantern/push/<branch>/` of the project (a name made of the ref's own letters, `hook._slug`), beside a
`.gitignore` of that folder that leaves it all out of git. What stops a push is `diff.blockers(receipt)`: rows
`{kind: "finding" | "link" | "criterion", part, words, finding | link | criterion}` read from the receipt only;
`lantern diff --require not-blocked` ends with 1 when that list is not empty.

`change.json`:

| Field | Meaning |
|---|---|
| `schema` | `1` |
| `lantern` | the version that compared |
| `base`, `head` | each side: `{"label": what the person called it ("main", "the files as they are now", "this pull request"), "commit", "lantern": the version of the Lantern that made this check, as its `run.json` says it, or null (results written before 2026-11-16, or text there that is no version), "code_sha256", "files", "uncommitted_changes"}` |
| `same` | true when nothing below differs |
| `counts` | `doors_added`, `doors_removed`, `doors_moved`, `logins_changed`, `logins_weaker`, `doors_added_open`, `links_broken`, `links_unanswered`, `findings_new`, `findings_fixed`, `findings_now_reached`, `findings_raised` (ranked higher than before), `findings_accepted`, `findings_reopened`, `paid_new`, `functions_changed`, `functions_added`, `functions_removed` |
| `release` | `{"before", "after"}`: each `{"decision", "words", "criteria": {findings, scanners, dependencies, tests, behaviour, browser}, "score", "grade", "counts"}` as `readiness.json` has them; `"changed"`; `"criteria"`: `[{"id", "before", "after"}]` for each criterion that moved; `"why"`: sentences; `"words"`: `"Passed → Blocked"` |
| `doors` | pages, routes and commands (identity: kind + detail). `added`, `removed`: `[{"kind", "detail", "words", "node", "file", "line", "login": the route's `route_logins` record or null, "login_recorded"}]`; `moved`: the same handler under another address (`before`, `after`); `login_changed`: a route on both sides whose `login` differs (`before`, `after`, `weaker`) |
| `links` | requests the page makes: `broken` (still made, and no route answers it any more), `unanswered` (new, and no route of the project answers it), `mended` (unanswered before, answered now), `unasked` (a route that is still there and that no page asks any more) |
| `findings` | by finding id: `new`, `fixed`, `still_open` (on code this change touched, and open as before), `now_reached` (in the code before, and a page or route reaches it only now; `rank_before`), `rank_changed` (`rank_before`, `raised`), `accepted` (`how`: `nosec` for a comment on the line with a written reason, `accepted` for `lantern accept`; `reason`; `came`: true when the finding came with this change, accepted from its first day), `reopened` (accepted before, open now). A finding's id is made from its line's text, so an edited line has its finding under another id: one that is gone while its rule shows again in the same file is listed as `still_open`, `accepted` (a `# nosec` comment is an edit of the line) or `reopened`, and `fixed` is said only where the rule no longer shows in that file |
| `paid` | calls that cost money (a model, an embedding, an image, speech, a payment, an email, an SMS: the kinds of `aiapp.PAID_KINDS`; a vector store is none, and a call is one only where the code makes it, never where a remark or a text names a provider) that a route reaches now and did not before (the route is new, the call is new, or the way from one to the other is): `[{"kind", "detail", "words", "node", "file", "line" (the route), "calls": [{"kind", "provider", "file", "line", "what"}], "in": {"node", "file", "line"} (the function that makes the call), "login": the route's login record as in `doors`, or null}]`. A paid call no route reaches is not listed |
| `touches` | the functions whose text changed (`changed`, `added`, `removed`: `[{"node", "name", "file", "line"}]`, by each function's `fingerprint`), their `files`, how many are `in_tests`, the `doors` that lead to them, what they lead to (`reaches`: `table`, `shell` (what starts a program; not what a started program gave back or raised, `diff.NOT_THE_SHELL`), `service`, `outside`), `paid`, `cut_short` (the walk over the map stopped at its limit), `by_text` (changed files Lantern maps no function of) |
| `more` | counts of rows left out of a list that was cut |
| `limits` | sentences: what this comparison cannot say (a scanner that did not finish on one side, libraries not looked up because both checks were made offline, a part of the release decision only one side was checked for, files of a commit that were not copied, results of an older Lantern without `route_logins`, two checks made by different versions of Lantern or a check that does not say which made it: a difference may then be the Lantern's and not the change's; two checks whose `security.json` `id_version` differ: their findings are not compared at all, every list under `findings` is empty) |

Everything in `change.md` that comes from a project is written so that it stays text on GitHub (`onrepo.md`,
`onrepo.code`: no HTML, link, picture, heading or table of its own, and no `@name`, `#12` or address that GitHub
would turn into a notice to a person or a link). Everything in `change.html` is escaped.

### The fix contract (`lantern fix`, the connector's recheck, "Fix this for me")

Not a result file of a check: the answer of `fixcheck.judge` about two checks, the one made before a fix and the
one made after it (`docs/fix.md`; since stage 3 of the 2026-11-14 roadmap).

`{"schema": 1, "verdict": "passed" | "refused" | "incomplete", "words": one sentence, "finding": {id, rule, title,
file, line, rank, …}, "items": [{"id", "state": "held" | "broken" | "not-shown", "need": what this part needs, as a
sentence, "facts": [what Lantern read there, as sentences]}], "broken": [ids], "not_shown": [ids]}`

`items` always holds the seven parts in this order: `gone`, `no-suppression`, `still-read`, `links`, `calls`,
`nothing-new`, `tests`. `passed` only when every part held; `refused` when one is broken; `incomplete` when none is
broken and one is not shown. A part's `facts` are at most 12 sentences (the rest counted in the last one), each
printable, with everything that came from the project cut to a length; a UI shows them as text.

Where it comes back:

* `lantern fix check … --format json`: `{"finding": id, "verdict", "contract": the answer above, "compared_with":
  {"what": "brief" | "first-check" | null, "kept_at", "words"}, "candidate": bool, "files": [paths the candidate
  changes] or null, "tests_ran": bool, "suggestion": {"written": FILE or null, "why": sentence or null} or null}`.
  The command ends with 0 (passed), 1 (refused), 3 (incomplete) or 2 (nothing could be checked).
* `lantern fix brief … --format json` and the connector's `lantern_fix_brief`: `{"project", "finding": the finding
  as `lantern_findings` gives it, "path": the steps from the page or route to the line, "flow": {"steps", "class"}
  or null, "contract": [{"id", "need"}], "kept_at"}`; the connector adds `"then": {"tool": "lantern_recheck",
  "finding"}`, `"tests"` (a sentence: the connector runs none) and `"cannot_close": true`.
* The connector's `lantern_recheck`: `{"project", "finding", "status": "fixed" | "refused" | "not-shown" | "open" |
  "changed", "verdict", "was", "now", "contract", "compared_with": {"what", "kept_at"}, "fixed": [...], "new":
  [...], "changed_still_open": [...]}`; with `refused` the finding is listed under `"refused"` and with `not-shown`
  under `"not_shown"`, never under `"fixed"`.
* `POST /api/projects/<id>/agentfix` (above): `contract` without `schema`, `finding` and each part's `need`.

The check a fix is compared with is kept in `LANTERN_HOME/fix-briefs/<project>/<finding>/`: copies of that check's
result files and `brief.json` `{"schema", "finding", "kept_at", "how": "brief" | "first-check", "files"}`.

A pack's record in `security.json` `tools` carries `rules` (how many) and `rules_sha256` (16 hex characters of what
the pack said: its name, version, requirements, rules and entry patterns) since the same date; a record without
them was written by an older Lantern.

### Other files

`calls.json` (above), `run.json` (`lantern`: the version that made this check, since 2026-11-16, read by `lantern diff`; timings, privacy, offline, trace, `incomplete` `[{tool, state, status, why, role}]`,
finished_at; `kept`, since 2026-11-12 and only when the run asked for kept work = `{"<kind>": {"reused": n, "anew": n}}`
for the kinds `python-file` (how a Python file reads) and `bandit` (what Bandit said about a set of files): how much
of the work this run took from `LANTERN_HOME/cache` and how much it worked out anew, also said in the log as
`kept    bandit: 1 from kept work, 0 anew; python-file: 2788 from kept work, 0 anew`; it is about the run, like its
timings, and in no other result file, and a run with `LANTERN_CACHE=off`, a `lantern verify` and a cloud run have
none; `trace`, when a test command was asked for = `{command, returncode, observed_edges, recall, stderr_tail,
backend, language, traced, timed_out, blocked, not_ended, ran}` and, since 2026-11-13, `time_limit` (the seconds the
tests had: in the sandbox what was set, else 600; on the command line without `--sandbox` what `--test-minutes`
says, else 900), `over_memory` (true when the sandbox stopped the tests for their memory), `memory_limit` (the
megabytes they had in the sandbox) and `own_network` (true when the tests ran in a network of their own, which
holds this computer's own address and nothing else: there a test may start its app's server and call it), and,
since stage 2 of "a firm pass or fail" (the same day), `own_sockets` (true when every connection of the tests'
programs was made for them by the sandbox's doorman, so that a program that is not Python reached no socket file
outside the run's own folders), since 2026-11-14 `off_network` (true when the run's own walls kept the tests from
the network: a container, a network of the run's own, Python's tests through the guard, or any other program
where something below Python holds it, `sandbox.held_below_python`; false for tests that are not Python where
nothing does, which is macOS and Windows, and a run inside another sandbox whose doorman makes the connections;
a run before that date has no such entry, which says nothing either way) and `libraries`, what the tests ran on: `{state: "none"}` when the project names no
library, `{state: "installed"}` when the check was offline and every library named is on this computer, else
`{state: "fetched", language, store, packages: [{name, version, fingerprint, file, asked, exact, checked, built?}], added,
notes, exact, checked, reached, refused, walls, locked?, above?, optional?, built?}`: `store` is the host the libraries were fetched
from, each package has the fingerprint of the file that was fetched (`sha256:<hex>` for Python, npm's
`sha512-<base64>` for JavaScript), `asked` says the project names it itself, `exact` that its version was the
project's own choice (an `==` pin or a lock file, named in `locked`) and `checked` that the fingerprint is one the
project names; at the top `exact` is true when every version was, `checked` counts the fingerprints the project
names, `added` is what Lantern asked for itself (the test runner), `notes` are Lantern's own sentences about what it
passed over or did not do (an option of pip's it does not take, the libraries the project names as optional and
whether they were fetched too or left out, install scripts that were not run, a `package.json` with no lock file and the workspaces that were then not handed to npm), `reached` and `refused` are the places the
fetch reached and how many it was refused, `walls` says what held the fetch to its doorkeeper (`own-network`, `port-rule` or `told`: `lantern/libraries.py`;
`told` also inside a sandbox whose doorman makes every connection for what runs in it, where no rule of the run's own decides),
`built` (Python on Linux, since 2026-11-14) is on a package that the store did not have ready-built for this system and that Lantern
built from its source for this run, in the sandbox with the network off: `{from: <the source package's file name>,
source_fingerprint: "sha256:<hex>", with: ["<tool> <version>", …]}`; such a package's `fingerprint` is the built file's, which
nobody names, its `checked` says that the source's fingerprint is one the project names, and `built` at the top counts them (it is
left out when none was built),
`optional` (Python, since 2026-11-14, only where the project names libraries under an extra or a group that is not one for tests)
is `{groups: [<name>, …], more: <how many names are not of the form a tool writes>, fetched: true|false, why?}`: `true` when they
were fetched beside the rest, `false` when they were left out and the tests ran on what the project always needs: the fetch with
them did not go through, or they were not asked for (the project writes fingerprints beside its libraries, or one of them names
another store, a link or a folder); `why` is Lantern's sentence for it,
and `above` counts the `node_modules` folders above the run's own folder, which Node looks in too; or `{command,
ran: false, unavailable: "<why>", returncode: null, observed_edges: 0, …}` when the sandbox could not be set up
and the tests were not run, with `not_run_for: "libraries"` when the sandbox was there and the libraries the
project names could not be had (`<why>` then says which library or file; nothing is fetched from a store, a link
or a folder that the project names itself);
`lantern.trace.counted` says whether anything of the run is in the results; tests the person stopped leave no record,
because a stopped run writes no file), `baseline.json` (first-run findings for "fixed since"),
`cache/` (explanation cache).

With no lock file npm is handed a `package.json` Lantern wrote, never the project's own (`libraries._for_npm`): the four tables of libraries, each library by a package name and by a version, a range, a tag or the store's own name for it (`npm:<name>@<versions>`); the `optional` marks of `peerDependenciesMeta`; `overrides` of the same form. A library or an override that names a folder, a file, a link, a repository or an address means npm is not started and the tests are not run (`trace.unavailable`, `not_run_for: "libraries"`), and so does a package in npm's own record of the fetch that did not come from the store (`libraries.not_from_the_store`). With a lock file nothing changed: a library kept in a folder of the project is fetched as the lock file names it.

What `lantern analyze` reads back from an earlier run of the same folder (`lantern/results.py`, `earlier`):
`security.json` (which findings were there before), `baseline.json` and `explanations.json` (for the report). Each is
read only when it is a plain file (not a link, a folder, a pipe or a device) of at most 256 MB that holds a JSON
table whose parts this run uses have the shape above. One that is cut off, empty, not text or of another shape is
passed over, and the run's log says `earlier <name> from an earlier run was not used: <why>.` with a reason in fixed
words (never text from the file); the run then finishes without what that file would have given. A `baseline.json`
that cannot be used is neither compared with nor replaced, and the Evidence Report's Limits say so;
`lantern evidence PATH --reset-baseline` starts a new one. The commands about a finished run (`report`, `evidence`,
`explain`, `verify`, `export`, the connector's tools) read its files strictly: one that cannot be read is an error
there, never "no findings".

Every reader of a result file reads it only as a plain file (`results.plain`): not through a link, and not a pipe,
which would hold the reader up for good. The strict readers end with `error: <path> was not read: it is a link, and
Lantern does not read its results through a link. Remove it and analyze the project again.` (or `it is not a plain
file`, `it is larger than 256 MB`, `it is not text`) and 2; `lantern verify --report FILE` says the same of a report
that is a link, a pipe or not there. In `lantern serve` the project cards, Ask Lantern and the Learn steps go on as if
such a file were not there, a report page answers 409 (`This result file can't be read`), and a JSON result answers
`null`. The record of calls a project's tests leave ("Watch my tests run", `lantern trace`) is read the same way, and
only rows of the recorder's own shape are kept (`trace.well_formed`).

How result files are written (`lantern/results.py`, `write` and `folder`): each file goes into a new file beside its
place and is moved there in one step, so a reader sees the file of the run before or the new one, never a part. A link
or a pipe under a result file's name is replaced by Lantern's own file (what a link pointed at is left alone) and the
run's log says `note    <name> in the results folder was a link; …`; a folder there, or a file this user may not
change (marked read-only), ends the run before it starts, with the reason. A results folder that is a link inside the
project, or is reached through one, is refused: the command line prints `error: <path> is a link, and Lantern does not
write its results through a link that came with the project. Remove the link, or name a results folder of your own
with --out.` and ends with 2; in `lantern serve` a check's job ends with the error `Refused: <that sentence>`, a route
that needs the folder at once answers 409 (a change) or 500 (a page) with the sentence, and `/api/projects` shows the
project as not checked (`has_report` false, no score). A results folder named with `--out` outside the project may be
a link.

In the repo itself: `lantern-accepted.json` (accepted risks with reasons, committed; written the same way),
`lantern-packs/*.json` (project analysis packs), `lantern-narratives.md` (the builder's own notes for the Evidence Report).
Each is read only as a file of the project (`python_frontend.project_text`, which asks `inside_repo`), like every
other file Lantern opens in a project: one that is a link leading out of the project, or lies behind a folder that is
such a link, counts as not there, and a pipe under its name is not waited on. A dependency file that is such a link is
named in its audit's record (`<file>: a link that does not lead to a file of the project, so it was not read`, the same
words whatever the link leads to), and a `package-lock.json` that is one counts as no lock file.

## Cloud service (`cloud/`, cloud mode)

A separate server from `lantern serve`: Lantern's own Fly app (`https://lantern-cloud.fly.dev`), for people who
analyse a repository from the website without installing anything. Plan and later routes: `docs/cloud-mode-brief.md`
§4. This section lists only what is built; a route appears here before any UI is built against it.

**Sign-in.** Two ways, same accounts:

* *The website* (`/`, same origin as the API, so no CORS is offered): `POST /v1/signin/start {provider}` makes a
  secret and a mark, keeps both in an HttpOnly cookie `lsi` (path `/v1/signin`, 10 min, SameSite=Lax: the browser
  must send it when the gateway sends it back here) and answers the gateway page to open
  (`<gateway>/v1/auth/<provider>/start?challenge=<SHA-256 of the secret>&return=<this site>/v1/signin/return&nonce=<mark>`,
  which goes straight to GitHub or Google). The gateway sends the browser that finished the sign-in to
  `GET /v1/signin/return?code=<one-time code>&state=<mark>`; when the mark is this browser's own, the server
  collects the token from the gateway's `POST /v1/auth/redeem` with the code and the secret and puts it in an
  HttpOnly cookie `lt` (path `/`, 30 days, SameSite=Strict, Secure on https); a code with any other mark signs
  nobody in and is used up. The tab the person started in asks `POST /v1/signin/poll` every 1.5 s, which only says
  whether this browser is signed in yet.
  The page's script never sees the token. A request authenticated by the cookie that changes something (anything
  but GET) must also carry `X-Lantern-Site: 1`, which another site's page cannot send here; without it: 403.
* *Apps and scripts*: sign in at the gateway (`lantern login`) and send `Authorization: Bearer lt_...`.

Either way the cloud service asks the gateway `GET /v1/whoami` → `{account, label}` on every request, so a sign-in
that was ended anywhere is refused at the next one (since 2026-11-15; before, a "yes" was remembered for 5 minutes).
With `LANTERN_CLOUD_IDENTITY_TTL` above 0 a "yes" is used again for that many seconds, keyed by the token's SHA-256
in memory, for a read (`GET`) only: a request that changes something or makes a link always asks. Runs belong to the
account (`github:<id>`, `google:<sub>`), so they survive a new sign-in. Each sign-in gets its own token and earlier
ones keep working (up to 8 places per account, sharing one allowance). Nothing about the token is stored on disk. A
sign-in that was signed out on the website while the gateway could not be reached is refused by the website from
then on (its SHA-256 in memory, at most 5,000 of them; the token itself is held in memory only for the few minutes
the website tries again to end it at the gateway: after 5, 15, 45, 120 and 300 seconds).

**Errors** are `{"error": {"type", "message"}}`; `message` is a plain sentence the UI may show as is. Types:
`signed_out` (401: no token, or an expired/replaced one: sign in again), `forbidden` (403), `not_found` (404),
`limit` (429), `unavailable` (503: the gateway did not answer; the person is **not** signed out).

| Route | Auth | Returns |
|---|---|---|
| `GET /v1/health` | none | `{ok, service: "lantern-cloud", version, engine, limits, hosts, cleanup, steps, service_user}`; `engine` is the analysis engine's version, `hosts` is `"all"` or a list. `cleanup` is one word about the service's own clean-up: `"ok"`, `"behind"` (files it should have removed have been waiting for 24 hours or more, or runs more than a day past the retention time are still there) or `"unknown"` (it could not find out). `tools/uptime.py` fails on any word here other than `"ok"` (a service from before 2026-11-10, which says nothing about clean-up, passes). `steps` (2026-11-18) says whether each check's steps run as a user of that check's own: `"apart"` (the last proof, when the service started or before a check, found that the check's user could read none of the service's files), `"open"` (it could, so where checks must be kept apart no check starts), `"unchecked"` (not asked yet) or `"shared"` (the service is not root and no switcher started it, so its steps run as its own user); `tools/uptime.py` fails on `"open"`, `"shared"` and any other word (a service that says nothing about it passes). `service_user` (2026-11-20) says which user the service itself runs as: `"own"` (an ordinary user: in the website's image its switcher, `cloud/lantern_cloud/switcher.py`, starts it so and starts each check's steps as that check's user) or `"root"`; `tools/uptime.py` fails on `"root"` and any other word (a service from before the field, which says nothing, passes). No counters |
| `GET /` | none | The website (`cloud/lantern_cloud/site/index.html`, filled by `site.py` with the app's own stylesheet, typefaces, brand mark, icons, readiness ring, appearance switch and backdrop from `lantern/viewer/app.html`). Per-response nonce, the app's CSP (`lantern.server._csp`), `no-store`. Screens: signed out (paste box, sign-in sheet), My runs (Simple: cards; Advanced: the app's table), a run in progress (steps from `step`, log from `/stream`), a finished run (the report in the app's frame, tabs Paths / What to fix / What protects you / Ready to ship? / Report), Help |
| `GET /guide` | none | How to use Lantern (`lantern/viewer/guide.html` via `lantern.guide.page`, the app's stylesheet and appearance switch): animated demos from fixed data, no account or project data. Nonce CSP, `no-store`. `lantern serve` sends the same page at `/guide` without the sign-in link |
| `GET /manifest.webmanifest` · `/sw.js` · `/icon.svg` | none | Installable like the app. The service worker caches only the icon and manifest, never `/v1/` or `/r/` |
| `GET /react.production.min.js` · `/react-dom.production.min.js` · `/intro-runtime.js` · `/intro.js` | none | The home page's intro: React 18.3.1 (vendored) and the landing page's intro files (copies of `site/intro/`, a test keeps them equal), loaded under the page's nonce |
| `GET /v1/signin/providers` | none | `{providers: ["github", "google"]}` as switched on at the gateway; 503 when it does not answer |
| `POST /v1/signin/start` `{provider}` | `X-Lantern-Site` | `{url}` to open; sets `lsi`. 400 for a provider that is not switched on |
| `GET /v1/signin/return?code=&state=` | `lsi` | The page the gateway sends the browser back to. With this browser's own mark: collects the token (gateway `POST /v1/auth/redeem`), sets `lt`, clears `lsi`, and shows "You're signed in" (200). Any other mark, or no `lsi`: the code is used up, nobody is signed in (400). The gateway not answering: 503 |
| `POST /v1/signin/poll` | `X-Lantern-Site` | `{signed_in: false}` while a sign-in of this browser is going (`lsi`); `{signed_in: true, label}` once `lt` is a sign-in; 400 with neither |
| `POST /v1/signout` | `X-Lantern-Site` | Ends this browser's sign-in at the gateway (`POST /v1/auth/signout`) and clears `lt`; `{"everywhere": true}` ends every sign-in of the account (website, app, CLI) → `{signed_in: false, ended, confirmed: true}`. The links to results made for the account (`/view`) open nothing from then on. When the gateway cannot be reached: with `everywhere`, 503, nothing is signed out and `lt` stays; without it, `lt` is cleared, the website itself takes that sign-in no more and tries again for a few minutes to end it at the gateway, and the answer is `{signed_in: false, ended: 0, confirmed: false, message}`: the sign-in is not ended at the gateway yet, and `message` is the sentence for the person (the page shows it). `Cache-Control: no-store` |
| `GET /v1/me` | Bearer or `lt` | `{account: "github"\|"google"\|"token", label, runs_today, runs_active, limits, connect_url}` (`connect_url`: the GitHub App's install page when Connect GitHub is on, else null) |
| `GET /v1/github/repos[?fresh=1]` | Bearer or `lt` | `{repos: [{name: "owner/repo", private, description, language, pushed}], github, connected, connect_url}`: the GitHub repositories the signed-in person owns, most recently pushed first (at most 300). Public ones are asked of GitHub's public API; private ones only where the GitHub App is installed on the person's own account (a one-off token with `metadata: read`, never kept). A row whose owner is not the signed-in GitHub id, or whose name is not of GitHub's form, is passed over. Kept in memory 120 s per account (`fresh=1` asks again). A Google sign-in gets `github: false` and no repos. 503 when GitHub does not answer. The website's GitHub screen draws the list; a click starts a run on `https://github.com/<name>` |
| `GET /v1/samples` | none | `{samples: [{id, title, stack, level, summary}]}`: Lantern's built-in starter apps (`lantern.learn.catalog`), each with planted problems, for people with no repository to hand |
| `POST /v1/repos` `{link \| sample, privacy?, stored_snippets_ok?}` | Bearer or `lt` | 202 + a **run** (status `queued`). `link`: https link to a public repository on a host `lantern.remote` accepts (and `LANTERN_CLOUD_HOSTS`, when set). `sample`: a starter id from `/v1/samples` instead of a link; the run's `link` is then `lantern:sample/<id>` and its `host` is `sample`, and the worker writes the starter from the package (`learn.scaffold`) instead of cloning (400 "Choose one of the sample apps…" for any other value). `privacy`: `"structure"` (default, no code kept) or `"full"` (short snippets kept; needs `stored_snippets_ok: true`, else 400 with the sentence to show). 400 for a bad link or privacy, 429 over a limit (one active run per person, runs per day, runs for everyone per day) |
| `POST /v1/uploads?name=&privacy=&snippets_ok=` (body: the .zip, `Content-Type: application/zip`) | Bearer or `lt` (+ `X-Lantern-Site: 1` with the cookie) | 202 + a **run**, as `/v1/repos`, with `link` `lantern:upload/<name>` (`name` cut to letters, digits, `._-`, at most 80; a label only) and `host` `upload`. The website zips a chosen or dropped folder in the browser (leaving out `node_modules`, `.git`, virtual environments, build output) or sends a chosen .zip. The body must start with `PK` (400 otherwise) and stay under `LANTERN_CLONE_MAX_MB` (413, checked on `Content-Length` and while receiving). It waits in the uploads folder (`LANTERN_CLOUD_UPLOADS`) until the run starts, is then moved into the run's temp folder and unpacked by `python -m lantern.archive` in the restricted process with no network (relative names only, no links or special files, no passwords, unpacked size capped while writing; a refusal ends the run with the unpacker's sentence), and is gone when the run ends. `snippets_ok=1` plays the part of `stored_snippets_ok`. Same limits as `/v1/repos`. `POST /v1/runs/{id}/explain` on an upload run is 409: the code is no longer there to read again |
| `GET /v1/runs` | Bearer or `lt` | `{runs: [run]}`, the person's runs, newest first (at most 100) |
| `GET /v1/runs/{id}` | Bearer or `lt` | the run; 404 when it is not the caller's (same answer as a missing id) |
| `GET /v1/runs/{id}/stream` | Bearer or `lt` | `text/event-stream`: `event: log` with one JSON string per line, then one `event: end` with the run, then the stream closes. A finished run sends its saved tail and `end` at once. While it is open the stream looks again, at every round, at whether its reader may still read the run and the same layers of it, and asks the gateway about the sign-in every 15 seconds: when something was taken away it closes with no `end` (ask for the run again to learn why); a gateway that cannot be reached ends nothing |
| `POST /v1/runs/{id}/view` | Bearer or `lt` | `{expires_in, report, evidence, badge, findings, graph, readiness}`: absolute links that open the run's results in a browser for the next `LANTERN_CLOUD_VIEW_MINUTES` (60). Each carries `?k=<expiry>.<layers>.<who>.<HMAC>` for this run only: `layers` is `all` or the code of the layers the caller may see, `who` a keyed fingerprint of the caller's account (it says nobody's name), and the signature covers those, the run and the account's round of links. A link opens what the person it was made for may read at the moment it is used: nothing once they are taken out of the workspace, the run leaves it, or they may see fewer layers than the link names (more layers later change nothing: it opens what it was made for), and nothing after they sign out on the website (since 2026-11-15; before, a link kept the run and the layers of the moment it was made, for the hour). 404 when not the caller's run, 409 when it has no report (not `done`). Open the link at once; never store or share it (until one of those ends it, anyone holding it can open it; to show someone, use Share) |
| `GET /r/{id}/report.html` · `evidence.html` · `badge.svg` · `findings.json` (= `security.json`) · `graph.json` · `readiness.json` | `?k=` from `/view`, or the `lv` cookie the first page sets for `/r/{id}/` | Rebuilt from Lantern's templates (`lantern.server.result_page`, the same code as `lantern serve`): the stored files are read for data only, pages get a per-response nonce CSP plus the report's own hash CSP, `live` is null (no actions), privacy as chosen before the run. Headers: `Cache-Control: private, no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`. 401 with a sentence for a missing, wrong, expired or ended key (one page for all of them: it does not say which); 404 for other names |
| `GET /v1/runs/{id}/share` | Bearer or `lt` | `{shared, url}` while sharing is off (the default; `url` null); while it is on also `check`, `badge` and `markdown` (below) |
| `POST /v1/runs/{id}/share` | Bearer, or `lt` + `X-Lantern-Site` | Turns sharing on: `{shared: true, url, check, badge, markdown}`, `url` = `<public url>/s/<slug>/report.html`, the slug 24 random characters, not the run id; `check` = `…/s/<slug>/check.html` and `badge` = `…/s/<slug>/badge.svg`; `markdown` = `[![Lantern check](<badge>)](<check>)`, the badge for a README, linking to its check page (2026-11-17). Asking again returns the same links. 404 when not the caller's run, 409 when the run is not `done` |
| `DELETE /v1/runs/{id}/share` | Bearer, or `lt` + `X-Lantern-Site` | Turns sharing off: `{shared: false, url: null}`. The old link stops working at once and never comes back; sharing again makes a new one |
| `GET /s/{slug}/report.html` · `evidence.html` · `badge.svg` | none (the link is the key) | The shared run's pages, read-only, built exactly as `/r/{id}/…` (same templates, nonce CSP, `live` null, privacy as chosen before the run) plus `X-Robots-Tag: noindex`. The raw data files (`findings.json`, `graph.json`, `readiness.json`) are not shared. 404 "This link is off" for a slug that is not (or no longer) shared. The badge follows the release decision, as the one written beside the report does: grey for Incomplete, the colour of a high finding for Blocked, green only for Passed (`evidence.badge_record`; until 2026-11-17 the badge served here and by `lantern serve` was drawn without the decision and was green for an Incomplete release) |
| `GET /s/{slug}/check.html` | none (the link is the key) | The page the badge links to (roadmap stage 6, 2026-11-17; `evidence.check_html`, rebuilt from `evidence.json` by `server.check_page`, no script, CSP `evidence.CHECK_POLICY`, `noindex`, `no-referrer`; its logo opens `/`, its guide button `/guide`): the commit, the code fingerprint (`release.bound_to.code.sha256`: SHA-256 of every file by its path and what it holds; the first 12 letters shown), the release decision and what it is made of, how many of the scanners that apply finished (`N of M … (P%)`, with the ones that did not), when and with which Lantern, the results fingerprint (`digest`), and the line that repeats the check: `git clone <link> lantern-check && cd lantern-check && git checkout <commit> && pip install "lantern[scan] @ git+…@<engine>" && lantern verify . --digest <digest>` (`--offline` when the run was). What the page says the check found is read from the part of the record the digest is made of (`payload`) and only when the digest is that part's own (`check_facts`: otherwise the page says the record does not hold together and gives no line), so the line, which makes the digest again, checks it: a scanner the payload names as partial or not finished counts as one that did not finish whatever the record's list says (`LEFT_AS`), and the open critical and high counts, which the payload does not hold apart from test code, are not shown (the decision's `findings` part says whether one is open). From the rest of the record come only whether a skipped scanner had work to do (`security.incomplete`) and the time and the Lantern the line installs (`header`, which the website writes itself: another Lantern of that repository ends with MATCH only where it makes the same results; a fork's commit, which GitHub also hands out through that repository's address, could say anything, so the line is as good as the website that wrote the record). The link is the one the run was asked for, read by `remote.parse` and put together again from its parts in plain letters (`evidence.CLONE_LINK`); an upload, a sample app or a link of other letters gives a line without the clone (or none where no commit holds the files: `check_line`). A run that ran tests or type checkers, or read several projects, gets no line, with the reason. 404 "This link is off" when sharing is off, like the other pages |
| `DELETE /v1/runs/{id}` | Bearer, or `lt` + `X-Lantern-Site` | `{deleted: id, files: "removed" \| "waiting"}`: the run's row and its share link are gone at once (nobody can open the run any more). `files` says whether its result files are off the server's disk: `"waiting"` when the server could not remove them yet (it has written that down and tries again, see "Clean-up" below; the website tells the person). 404 when not the caller's run; 409 while it is `queued` or `running` |
| `DELETE /v1/me` | Bearer, or `lt` + `X-Lantern-Site` | `{deleted: true, runs: n, files: "removed" \| "waiting"}`: every run, share link, daily counter and the account row are deleted, and the `lt` cookie is cleared; `files` is `"waiting"` when one of the result folders could not be removed from the disk yet (as for one run). Signing in again starts a fresh, empty account. 409 while one of the person's runs is still going. The gateway account (and its allowance counters) is not touched |
| `GET /v1/ai` | Bearer or `lt` | `{consent, notice, allowance}`: whether the person has agreed to send work to a model, the sentence they agree to (`providers.DATA_NOTICES["lantern"]`), and `{remaining_requests, limit_requests, remaining_today}` from the gateway's `/v1/allowance` (null when it does not answer) |
| `POST /v1/ai/consent` `{agree}` | Bearer, or `lt` + `X-Lantern-Site` | Records (`true`) or withdraws (`false`) the agreement: `{consent, notice}`. Off by default; deleting the account forgets it |
| `POST /v1/runs/{id}/explain` | Bearer, or `lt` + `X-Lantern-Site` | 202 + the run, `explain.status` `queued`. Writes plain-words explanations (entry points and three levels down, up to 40 functions) with the caller's free allowance: the worker copies the repository again, refuses if its commit differs from the run's (the words must match the map), runs `lantern explain` in the restricted process with the network on and the token in its environment (held in memory only while the job waits), copies back `explanations.json` and the rebuilt report (each written beside its old one first, and put in its place only when all are written, so a save that fails changes none of them), keeps the explain cache (explaining again never pays twice; also when the job was stopped at the time limit, whose message says "The ones already written are kept" only when they were), and deletes the copy. Like a run's result files, what the step wrote is taken as plain files only: a link or a file with a second name among it ends the job with `explain.error` "Lantern's own step left something that is not a plain file where a result belongs, so nothing was changed. …". 412 `consent_needed` without agreement, 409 when not `done` or already being written, 503 when the server has no worker |
| `POST /v1/ask` `{question, run?, focus?: {node?, finding?}}` | Bearer, or `lt` + `X-Lantern-Site` | `{answer, cited, invented}`. Ask Lantern (`lantern.ask`): the model answers from the run's results (`ask.facts`, never source code) or, with no `run`, from what Lantern is. Finding ids the model made up are replaced with "[unknown finding]" and counted in `invented`. 412 without agreement, 402 `allowance` when the free allowance is used up, 401 `signed_out` when the gateway no longer accepts the token (the person signed in somewhere else; the remembered sign-in is dropped), 413 when the question and facts are too big, 503 when the gateway or the model company fails, with the true reason in plain words (`providers.why_failed`: a refused key, no credit, an outage, no key set up, gateway unreachable), 502 when the answer cannot be read, 404 for a run that is not the caller's |
| `POST /v1/ask/screenshot` (multipart, one PNG/JPEG/WebP ≤ 8 MB, ≤ 40 M pixels) | Bearer, or `lt` + `X-Lantern-Site` | `{width, height, format, lines, text}` like the app's `/api/ask/screenshot` (`ask.read_screenshot`: Pillow, then Tesseract through a pipe). The image stays in the request's memory: never written to disk, kept, or sent to a model; the text reaches a model only inside a question the person sends. `text: null` + `reason` when this server cannot read text in images (`how` is always null here). 400 not an image or too many pixels, 413 too large, 429 when two are already being read. Needs no consent (no model is involved) |
| `GET /v1/admin/stats` | Bearer = cloud admin secret | `{users, runs, runs_by_status, runs_today, shared, workspaces, cleanup}`; 403 when no admin secret is set. `cleanup` = `{waiting, by_kind: {results?, work?, upload?}, oldest, reasons, left_alone: {work, uploads, results}, last_pass: {at, ok, error, removed}, behind, refused}`: how many things the service still has to remove and since when, the reasons the system gave (five at most, no names), how many things in its three folders are not its own and were left alone, how the last hourly pass ended, and how many deletes were refused because the name was not one the service gives or the thing was in use. Never a run id, a file name or a path |
| `GET /v1/workspaces` | Bearer or `lt` | `{workspaces: [{id, name, role, created, people, runs}]}`: the team workspaces the caller is in; `role` is `owner` or `member` |
| `POST /v1/workspaces` | Bearer, or `lt` + `X-Lantern-Site` | `{name}` (1 to 60 characters) → 201 and the workspace (below), with the caller as its owner. 429 past `LANTERN_CLOUD_WORKSPACES_PER_OWNER` (10) |
| `GET /v1/workspaces/{id}` | Bearer or `lt` | `{id, name, role, people: [{id, name, role, joined, you, lanes}], runs: [run + {mine, by}], invites_open, lanes, limits}`. A person's `id` is an opaque per-workspace handle, never their account; `invites_open` is null for members. `lanes` (on a person, and on the workspace for the caller) is null for every layer, else the layers they may see in other people's runs; for such a caller each run has `summary: null`, an empty `log_tail` and `lanes`. 404 when the caller is not in it |
| `PATCH /v1/workspaces/{id}` | owner | `{name}`: renames it |
| `DELETE /v1/workspaces/{id}` | owner | `{closed: id}`: everyone leaves, open invites stop working, and every run in it goes back to being its owner's alone. No run is deleted |
| `POST /v1/workspaces/{id}/invites` | owner | 201 `{url, expires, one_time: true}`: `url` = `<public url>/#/join/<secret>`. The link works once (whoever accepts it first joins as a member) and for 7 days; only a SHA-256 of the secret is kept, so it is shown this once. No email is asked for or kept. 429 past `LANTERN_CLOUD_OPEN_INVITES` (10) unused links |
| `DELETE /v1/workspaces/{id}/invites` | owner | `{cancelled: n}`: every unused invite link stops working |
| `POST /v1/invites/peek` | none | `{code}` → `{name, expires}`: which workspace an invite opens, so the join page can say so before sign-in. 404 when used, expired or cancelled |
| `POST /v1/invites/accept` | Bearer, or `lt` + `X-Lantern-Site` | `{code}` → the workspace, with the caller as a member; the link stops working. 404 when used, expired or cancelled; 429 past `LANTERN_CLOUD_WORKSPACE_PEOPLE` (25) people |
| `GET /v1/runs/{id}/notes` | Bearer or `lt` (the run's owner, or a member of its workspace) | `{notes: [{id, node, body, by, mine, created, can_delete}]}`: notes people left on functions in this run's map, oldest first. A member who sees only some layers gets only the notes on functions in those layers |
| `POST /v1/runs/{id}/notes` | the same, + `X-Lantern-Site` with `lt` | `{node, body}` → 201 `{id}`. `node` must be a function on this run's map (and in a layer the caller can see), else 404; `body` is 1 to 1000 characters of text, else 400; 409 before the run is done; 429 past `LANTERN_CLOUD_NOTES_PER_RUN` (300). A note is words only: it never changes the analysis and is never sent to a model |
| `DELETE /v1/notes/{id}` | the note's author or the run's owner | `{deleted: id}`; 403 for anyone else who can open the run, 404 for people who can't. Deleting a run or an account deletes its notes |
| `PUT /v1/workspaces/{id}/people/{person}` | owner | `{lanes: ["browser", "frontend", "server", "data"] (any of them) or null}` → the workspace: per-layer permissions. That member's `/view` links open a report built without the other layers (`lantern/scope.py`): calls into them end at a sealed node; the report's data has `readiness` null (the score with its checks, the release decision and the protections are worked out from every layer, so the Readiness and Protections pages say they are not shown in this view) and of each scanner in `security.tools` only `tool`, `version`, `state` and `status` (= the state's word); the evidence report, the badge (it shows the whole app's score and its critical and high counts; since 2026-11-15, before it was served and the report kept the readiness data with the hidden names taken out) and raw JSON answer 403; `GET /v1/runs/{id}` has no summary or log and lists `lanes`; the stream sends no log lines; Ask Lantern with that run answers 403. Choosing all four is the same as null. 400 for anything else; 409 for the owner, who always sees everything |
| `DELETE /v1/workspaces/{id}/people/{person}` | owner, or the person themselves | `{removed, left}`: the owner takes someone out, or a member leaves. Their runs in it go back to being theirs alone. 409 for the owner (close the workspace instead) |
| `PUT /v1/runs/{id}/workspace` | the run's owner | `{workspace: id \| null}` → the run: puts a finished run in a workspace the caller is in, or takes it out. Members of that workspace can then read it (`GET /v1/runs/{id}`, its stream, `/view` links, Ask Lantern), never share, explain, move or delete it |

A **run** = `{id, link, host, privacy, status, stage, error, created, started, finished, commit, summary, shared,
log_tail, step, explain, workspace}`. `workspace` is null, or the id of the team workspace its owner put it in. `status`: `queued` → `running` → `done` | `error` | `blocked` (the sandbox stopped the analysis from
reaching the network or writing outside its folder). `stage` is a plain sentence for the current step. `error` is a
plain sentence (never a traceback or a server path). `summary` (when done) = `{score, grade, shape, counts:
{critical, high, medium, low}, files, lanes: {browser|frontend|server|data: {critical, high, medium, low}}, phone,
release}`, read from the
result files (`lanes`: open findings outside tests by `hot_lane`; a finding with no lane is left out; `phone`: the
platform is a phone app, so the website says Screen and App; `release`: `"Blocked"`, `"Incomplete"`, `"Passed"` or
null, the run's release decision. The cloud service never runs a project's tests, so a run there reads Incomplete
at best; a run saved before `lanes` existed gets them on the next
`GET /v1/runs`). `shared` is false until the person clicks Share
(`POST /v1/runs/{id}/share`). `log_tail`: the last 40 log lines, server paths removed. `explain`: `{status: null|queued|running|done|error, error, summary: {functions, validated, failed, stopped}, log}` (`log`: the explain job's last lines while it runs). `step`: `clone` | `audit` | `analyze` |
`save` while running (the key of `stage`), else null. `hint`: `"upload"` when the repository could not be opened (private, or no such repository; git asked for a password, or Connect GitHub refused: the person cannot read it, or signed in with Google), so the website offers "Upload your code instead"; `"connect"` when Connect GitHub is on and the app is not installed on that repository, so it offers "Connect GitHub" (`/v1/me` `connect_url`) and Upload; else null. `summary` values are checked when read (score and files whole
numbers or null, grade A–F or null, counts whole numbers), since a stranger's repository wrote the files.

Retention: with `LANTERN_CLOUD_RETENTION_DAYS` = 0 (the default, the owner's decision) results are kept until the
person deletes them. With a number N, the hourly pass below deletes finished runs older than N days (`app.sweep`),
their result folders and share links, exactly as `DELETE /v1/runs/{id}` does.

Clean-up (`cloud/lantern_cloud/cleanup.py`, the one place the service removes result folders, work folders and
uploads from its disk). The service removes only
what it made itself, by name inside its three folders, never by a path it was given: a run's result folder
(`<results>/<run id>`, 16 characters as `Store.create_run` gives them), a run's work folder (`run-…`/`explain-…` with
the mark file `.lantern-work` that `Cleanup.fresh` puts in each one it makes), a half-received upload
(`.part-<16 hex>`) and the upload of a run that is over (`<run id>.zip`). A link, a file where a folder belongs, a
thing of another user, a name of another shape, the results of a run that still exists and the upload of a run that
is waiting are never removed; what is in the three folders and is not the service's is left alone and counted
(`left_alone`). Before a removal starts it is written down (table `leftovers`: kind, name, since when, tries, the
last reason; the row of a deleted run's results is written in the same transaction that deletes the run), and the row
goes when nothing is left, so a service cut off in the middle finishes later. A removal that fails keeps its row with
the system's reason. One pass (`Cleanup.upkeep`) runs at start-up and then every hour, or five minutes after a pass
that failed: retention when N > 0, then everything still written down, then the counts. Nothing in it can stop the
service from starting, and a failed pass is logged and shown in `last_pass`. Removal itself is `lantern.removal`
(shared with the app and the CLI): never through a link, any depth of folders, nothing outside the thing is changed.

What a run does (`cloud/lantern_cloud/worker.py`): clone into a temp folder (size cap before checkout) → dependency
audits on lock files in the restricted process with the network on → analysis (`lantern analyze --offline`, the
audit results passed in through `LANTERN_AUDITS_FROM`) in the restricted process with **no network** and writes only
in its temp folder → result files copied to the run's folder (plain files of the step's own folder only: the
service follows no link there and reads no file that has a second name elsewhere; anything else ends the run with
`error` "Lantern's own step left something that is not a plain file where a result belongs, so nothing of it was
kept. …") → the temp folder, clone included, removed in every
case (when the system refuses, the run's log says so, the folder is written down and the hourly pass tries again;
the run's own result is not changed by that). Nothing from the repository is built, installed or run. A restart
marks a running run `error` ("start it again"), requeues waiting ones and removes the work folders cut-off runs left.

`limits` = `{runs_per_day, concurrent_jobs, clone_max_mb, job_seconds, retention_days (null = kept until
deleted), default_privacy: "structure"}`.

Gateway side: `GET <gateway>/v1/whoami` (Bearer = the person's token) → `{account, label}`; 401 for an unknown or
disabled token. A hand-minted token has `account: "token:<16 hex>"`. Never returns an email.

## Acceptance checklist per screen

* **Projects**: add by folder and by GitHub link; job log streams while analyzing; score, grade and counts update
  without reload; remove never deletes files.
* **Atlas**: pick a page or route, follow the path through click and HTTP hops to the backend; every edge shows its
  confidence word; unresolved count visible; works in the app iframe and opened from disk; phone layout.
* **Stack strip** (every screen that shows a finding, function or path): the four stops in order, "You are here"
  lit, the stops the path crosses filled, hover definitions in plain words; Path view has a Lanes mode (Simple default)
  where each node sits in its lane and the bad hop is red; list rows carry the four-dot glyph and "On the Server" in words,
  with the legend once above the list.
* **Findings / Finding**: ranked list with filters; click path from the page; "uses outside input"; heuristic tag;
  Open function; Accept risk asks for a reason and shows it afterwards; **Send to…** with Claude, ChatGPT, Copy.
* **Readiness / Protections**: the release decision above the score (one of three words with its tone and beside a
  word, why, each criterion with its state in words, what it is tied to; nothing when the file has none), score
  ring, categories, "do first" list, protections with add / check / in place,
  starter files written with one click and never overwriting.
* **Explanations**: plan (count and cost) before running; consent text with the provider's data notice; three
  lenses with anchored pairs; validation failures shown as such; allowance remaining and the clean stop.
* **Evidence**: before/after counts, fixed findings, provenance, Limits, digest and the verify command; badge
  wording exactly `Lantern · commit · N critical · date`.
* **Settings**: provider list with local/cloud marking and data notices; key remembered or session-only; privacy;
  theme; **Connections** rows by assistant name with last use, setup snippets, no connect/disconnect control.
* **Cloud website**: the same look as the app (it is built from it); sign in with GitHub or Google in a new tab and
  the page notices by itself; paste a link with the privacy choice (snippets need the box ticked); the run page shows
  the four steps and the live log, then the report; My runs in Simple (cards) and Advanced (table); phone layout;
  `tools/cloud_site_smoke.js` with `tools/cloud_site_demo.py --poison` passes (no JS errors, run data stays text).
* **Everything**: no JS errors in Chromium at desktop and phone widths (`tools/viewer_smoke.js`); the poisoned
  report (`tools/poison_report.py`) renders as text; `python -m pytest -q` and `bash tools/audit.sh --browser` green.
