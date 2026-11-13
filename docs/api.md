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

`lantern serve` prints `http://127.0.0.1:8765/?token=...`. The first visit sets a `lantern_token` cookie
(SameSite=Strict, HttpOnly). Every write (`POST`, `DELETE`) also needs the token in the `X-Lantern-Token`
header; the app gets it from `window.LANTERN_TOKEN` (injected into `app.html`) and the report from
`window.LANTERN_LIVE.token`. Wrong or missing token → 401. The `Host` header must name the server.

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
| `DELETE /api/projects/<id>` | | `{"ok": true, "note"}`; files are never deleted |
| `POST /api/projects/<id>/analyze` | | job (202). Builds the map, scans, scores readiness, writes report and Evidence Report |
| `GET /api/projects/<id>/plan?depth=3&limit=40` | | `{"nodes": N, "input_tokens", "output_tokens", "note"}`: what an explain run would cover (an estimate, no model call) |
| `POST /api/projects/<id>/explain` | `{"nodes": [ids]}` for some, or `{"depth", "limit"}` for the plan | job (202). Log lines include `free explanations left: N` and `stopped early: …` when the allowance runs out |
| `GET /api/projects/<id>/explanation?node=<id>` | | `{"record": explanation record or null, "metaphor": {"world", "roles"}}` |
| `POST /api/projects/<id>/accept` | `{"finding": id, "reason": "≥10 letters, two words", "by": name}` or `{"finding", "remove": true}` | job (202): writes `lantern-accepted.json` in the repo and re-analyzes. A weak reason → 400 |
| `POST /api/projects/<id>/cmd` | `{"argv": ["analyze", "--offline"]}` | The terminal drawer. job (202) whose log the drawer prints. `argv` is a list of strings (never a shell line; at most 64 items). Allowed: `analyze [--offline] [--no-scan] [--privacy]`, `trace [--] TEST COMMAND` (through the test sandbox; typing it counts as the confirmation), `explain [--node ID…] [--depth N] [--max-nodes N]`, `report [--privacy]`, `verify [--report FILE]`, `accept ID --reason "…" [--by]` / `accept ID --remove` (same reason check as the UI), `packs`, `export [--sarif FILE]` (default `.lantern/findings.sarif`), `learn [--check]`; a leading `lantern` is dropped. `--out` is always the project's `.lantern/`; path arguments must resolve inside the project. Anything else → 400 `{"error", "allowed": [...], "help"}`. Token and Host checks as on every write |
| `GET /api/projects/<id>/testcmd` | | The command the "Watch my tests run" sheet shows first: `{"command", "how", "language": "python\|node\|go\|rust\|java", "supported", "traced", "note", "cwd"?, "sandbox": {"name": "docker\|subprocess", "label", "image", "details": [lines]}, "leaves", "confirmed"}`. `details` lists the walls this computer's sandbox has (fewer on macOS and on a Linux kernel without Landlock); its last line says that the tests are not run when any of them cannot be set up. `traced` is true for Python only ("Tests run; your map upgrades for Python only for now") |
| `POST /api/projects/<id>/trace` | `{"command": "python -m pytest -q", "confirm": true}` | job (202). Only test runners (`sandbox.check_command`; anything else → 400). The first run of a command for a project needs `confirm: true` (409 otherwise); later runs of the same command do not. Runs in `lantern/sandbox.py` and re-analyzes; the job result is `{"returncode", "observed", "recall", "backend", "language", "traced", "timed_out", "blocked": [{"kind": "write\|network", "what"}], "ran", "unavailable", "cancelled", "not_ended", "note", "score_before", "score_after", "summary"}`. `ran` false + `unavailable` (a sentence, always Lantern's own words): the sandbox could not be set up on this computer, so the tests were **not run**; the job still ends `done`, because everything that only reads the code was checked: `returncode` is null and `observed` 0, the score's "Tests pass" check is `skip` (not `fail`), and the Evidence Report names no test command. `cancelled`: the person stopped the tests (below); the job ended there, **no result file was written** (the project shows what its last finished check found, `score_after` equals `score_before`, `summary` is null). `returncode` null with `timed_out`: stopped at the 10-minute wall clock (the check goes on and "Tests pass" is `fail`). Whatever way a test run ends, every process it started is ended too; `not_ended` lists, in Lantern's own words, anything that could not be (normally `[]`; the page then says so and never says beside it that everything was ended) |
| `POST /api/jobs/<id>/stop` | `{}` | Ends a running test run: the tests and every process they started. Returns the job (`stopping: true`); the job then ends `done` with `result.cancelled` true and no result file changed (`pipeline.Stopped`). 404 for an unknown job, 400 for a job that cannot be stopped part-way (`can_stop` false), 403 without the app's token. Asking again, or after the job has ended, changes nothing |
| `POST /api/projects/<id>/starter` | `{"name": "Dockerfile"}` | `{"ok", "wrote"}`; never overwrites |
| `GET /api/projects/<id>/learn` | | Starter progress: `{"steps": [{"title", "done", …}]}` |

### Pages and files per project

| Route | Content |
|---|---|
| `GET /p/<id>/report.html` | The Atlas page, rebuilt from the data with live actions enabled (`window.LANTERN_LIVE = {api, token, model, local, view_mode, backdrop}`). `backdrop` (`off`/`subtle`/`bold`) sets the moving shapes when the page is opened in its own tab; inside the app's frame the report draws none and the app's own show through. `view_mode` (`simple`/`advanced`) is the saved setting and wins over the browser's `localStorage`; switching inside the Atlas saves it with `POST /api/settings` and calls the app's `window.lanternViewMode(settings)` so its toggle agrees |
| `GET /p/<id>/evidence.html` | The Evidence Report |
| `GET /p/<id>/evidence.json` | Its data (schema below) |
| `GET /p/<id>/badge.svg` | `Lantern · commit 1a2b3c · 0 critical · Oct 31` |

### Settings and connections

| Route | Body / returns |
|---|---|
| `POST /api/settings` | `{"provider", "model", "base_url", "privacy": "full"\|"structure", "view_mode"?: "simple"\|"advanced", "backdrop"?: "off"\|"subtle"\|"bold", "share_usage"?: bool, "key"?, "remember"?: bool, "forget_key"?: true}` (fields left out keep their saved values; an unknown `view_mode` is saved as `simple`) → `{"settings", "providers"}` |
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
`explanations`, `sources`, `stats`). The CLI writes the same files, so a UI can also be built on them directly.

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
  or `ext:HTTP <METHOD> <path>`.
* `meta`: `files`, `lines`, `languages`, `bridge` (link counts), `http_calls`, `packs` (`{added, ambiguous, unresolved, packs}`),
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
  `maximum recursion depth exceeded` and no result file).
* JavaScript `via` values added in stage 3 (2026-11-09): `require-call` (`require('./x')(...)`), `route-handler` and
  `middleware` (a function handed to an Express router by name: resolved when it is named straight from a module,
  inferred when it is reached through a value or a type Lantern worked out, such as `const notes = new Notes()`),
  `wrapped-function` (`const f = wrap(async ...)`
  handed to a router; inferred), `library-value` (a variable or module export holding what a library call returned:
  `const app = express()`), `library-result` (a call on a library call's result: `Joi.string().min()`),
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
"logins_shown", "not_read", "ai", "mobile"}`

`logins_shown`: the node ids of the routes whose own code turns away whoever is not signed in, as the flow step read
it (a check under any name, one written in place, a hook, a dependency); `null` when that step did not run, and
absent from results written before 2026-11-11. The protection `route-auth` in `readiness.json` counts such a route
as checked (found: "the code on the way to this route turns away whoever is not signed in"), and names a route an
`LW-AUTH-MISSING` finding calls open among the open ones, whatever the names around it say.

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
patterns ran), and when known `version`, `exit_code`, `scope` (`{files, packages}`), `exclusions` (folders a tool was
told to skip, and for bandit the Python files it was told to leave out because they are not files of the project: a
link that leads out of it, a pipe), `errors` (one line per file or package left out of a `partial` run), `findings`, `duration_ms`, `role`,
`fallback_for` (the built-in secret scan when gitleaks did not finish). `partial` keeps the findings the tool did
produce. Bandit's `scope` has `under_another_name` when Python kept as text was handed to it (how many such files, a
part of `files`), and the record then names them in `read_as_text`. `copied-audit` (`depaudit.run_copied_audit`: the
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
which Lantern does not read yet; written also on a record that ends `ok` for the folders it did check), and `not_read` (how many parts of the dependency files are no package
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
and pays for nothing before that check)`}`; `partial` when a file could not be read, a function could not be followed or the
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
token the handler never looks at).

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
stays test code and the reason says so), `ui_path` (node ids from a
page, or null), `input` (null, `false`, or `{"via": "parameter `name`"}`; when a flow was followed to the line,
`{"via": <the words of the flow's first step>, "flow": true}`), `flow` (optional, `flowscan.py`: request data followed
to this line across functions and files, on a `lantern-flow` finding or attached to another tool's finding for the same
kind of problem on the same line: `{"class"` (`sql`, `shell`, `eval`, `deserialize`, `xxe`, `path`, `ssrf`, `xss`,
`redirect`, `nosql`, `pollution`, `record`, `assign`), `"confidence"` (`HIGH`, or `LOW` when a step is a likely link),
`"severity"`, `"source": {file, line, what}`, `"sink": {file, line, what}`, `"steps": [{file, line, what}]` (from the
request to the sensitive action, in order; `what` is a sentence with code names between backticks), `"others"` (up to
five other starting points that reach the same line), `"count"}`; the viewer's box "How the value gets there" lists
the steps, every value escaped), `claim` (`LT-AUTHZ-CLIENT-ROLE` only: `{"name"` (the cookie, header or field as
the code reads it), `"sent_as"` (`a cookie`, `a header`, `the address`, `the request's body`), `"what"` (a sentence:
where the value arrives), `"routes"` (the routes that decide on it)`}`), `secret_kind` (`LW-SECRET-INLINE` only),
`routes` (`LT-AUTHZ-OWNER` only: the routes that reach the record on this line, e.g. `["GET /orders/:id"]`),
`late` (`LT-AUTHZ-OWNER` only, optional: `"change"`, `"shell"`, `"remove"` or `"send"` when the route does ask whose
the record is, but only after it changed the record, ran a command, removed a file or told another service to
change something for it; the scenario's `kind` is then `owner-late`),
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
`case` (every finding outside test code, `case.py`, version 1: `where` `{file, line, function, revision, revision_note?}` (revision = the analyzed folder's git commit, `null` outside git; `revision_note` when the folder has uncommitted changes, or the header's `note` when git could not compare the files), `claim` (the tool's words, never stronger than the evidence), `evidence` `[{fact, from}]` (`from`: the tool, `map`, `input check`, `context (names)`/`context (code)`), `conditions` `[{need, met, why}]` (what has to be true for harm; `met` true = Lantern saw it, false = saw it is not, null = cannot check), `impact` (the scenario's harm), `severity` `{rank, tool_severity, why, before_context?, context_note?}`, `confidence` `{level: high|medium|low|unknown, why, about}` (the tool's own confidence, one step lower when the path has a `likely`/`possible` link; about the pattern being there and reached, never about exploitability), `unknown` [plain sentences], `status` `[{word, done, why}]` for `reported`, `reproduced` (the id was in this folder's previous `security.json` or `baseline.json`; null on a first run), `fixed` (false while listed), `tested` and `independently reviewed` (always null: Lantern keeps no such record; an accepted risk is a review by the builder, not an independent one)),
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
`required: true`: the release needs it and the work was not done (the tests were not run, listed libraries were not
looked up), so its points stay in the sum and it earns none), `next_steps` (the
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
(every required criterion passed). Five criteria, each with `state` `passed`, `failed`, `missing` or
`not-applicable`, a `why` and, when it is not passed, a `fix`: `findings` (failed while a critical or high finding is
open outside test code; an accepted one does not block and is named in `why`), `scanners` (missing while a scanner
that applies did not finish or did not cover everything, or while the project keeps code as text that no scanner
read: `security.json` `not_read`), `dependencies` (missing while a listed library was not
looked up, or the project lists libraries of a kind Lantern has no check for yet: Go, Rust, Dart and Flutter, .NET,
Swift, C and C++, or software copied into a `vendor` folder was not looked up (`copied-audit`: offline, or files with
no name and version); `not-applicable` and not required where the project lists none and holds no such copy), `tests` (passed only when the
project's tests ran in this check and ended with 0; failed when they ended with anything else; missing when the
project has none, they were not run, the sandbox could not be set up or stopped them, or it refused something they
tried), `behaviour` (not required where the project has no `lantern-behaviour.json`; else passed only when
`behaviour.json` carries this computer's seal, is of this plan and this code, and every case held; failed when a
case came out broken). `blocking` and `missing` name the required criteria in those states. `bound_to` is what the
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
`dirty` is `true`: `lantern/gitfacts.py`),
`scorecard` (`readiness` (with `checklist` beside `score`), `now` counts, `before` counts, `baseline_date`,
`baseline_commit`), `release` (the whole `release` of `readiness.json`, or null for a readiness file an older Lantern
wrote; the Scorecard section shows the decision, every criterion, the profile and what the decision is tied to; the
digest takes in the decision, each criterion's state and the SHA-256s of the code, the dependency files, the plan
and the accepted risks, so `lantern verify` fails when one of them differs; the badge is green only for `Passed`
and otherwise ends in `blocked` or `incomplete`), `architecture`,
`security` (`open`, `accepted`, `fixed`, `changed`, `in_tests`, `protections`, `incomplete`: `[{tool, state, status,
why, role, version}]`, the scanners that did not finish or did not cover everything; while it is not empty the memo, a
notice under the tiles and the badge say `scan incomplete`, and the badge is never green), `understanding`,
`provenance` (`tools` with each scanner's `state` and `status`, `models`, `rules`, including analysis packs), `limits`
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
key is written in), the sandbox could not be set up or starts no app on this system (Windows, for now; the app was
then not started), the plan's set-up failed at a
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

### Other files

`calls.json` (above), `run.json` (timings, privacy, offline, trace, `incomplete` `[{tool, state, status, why, role}]`,
finished_at; `kept`, since 2026-11-12 and only when the run asked for kept work = `{"<kind>": {"reused": n, "anew": n}}`
for the kinds `python-file` (how a Python file reads) and `bandit` (what Bandit said about a set of files): how much
of the work this run took from `LANTERN_HOME/cache` and how much it worked out anew, also said in the log as
`kept    bandit: 1 from kept work, 0 anew; python-file: 2788 from kept work, 0 anew`; it is about the run, like its
timings, and in no other result file, and a run with `LANTERN_CACHE=off`, a `lantern verify` and a cloud run have
none; `trace`, when a test command was asked for = `{command, returncode, observed_edges, recall, stderr_tail,
backend, language, traced, timed_out, blocked, not_ended, ran}`, or `{command, ran: false, unavailable: "<why>",
returncode: null, observed_edges: 0, …}` when the sandbox could not be set up and the tests were not run;
`lantern.trace.counted` says whether anything of the run is in the results; tests the person stopped leave no record,
because a stopped run writes no file), `baseline.json` (first-run findings for "fixed since"),
`cache/` (explanation cache).

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
  one-time code, keeps it in an HttpOnly cookie `lsi` (path `/v1/signin`, 10 min, SameSite=Strict) and answers the
  gateway page to open (`<gateway>/v1/auth/<provider>/start?cli=<code>`, which goes straight to GitHub or Google).
  The page then calls `POST /v1/signin/poll` every 1.5 s; the server collects the token from the gateway's
  `/v1/auth/claim` and puts it in an HttpOnly cookie `lt` (path `/`, 30 days, SameSite=Strict, Secure on https).
  The page's script never sees the token. A request authenticated by the cookie that changes something (anything
  but GET) must also carry `X-Lantern-Site: 1`, which another site's page cannot send here; without it: 403.
* *Apps and scripts*: sign in at the gateway (`lantern login`) and send `Authorization: Bearer lt_...`.

Either way the cloud service asks the gateway `GET /v1/whoami` → `{account, label}` and remembers the answer for 5
minutes, keyed by the token's SHA-256 in memory. Runs belong to the account (`github:<id>`, `google:<sub>`), so they
survive a new sign-in. Each sign-in gets its own token and earlier ones keep working (up to 8 places per
account, sharing one allowance). Nothing about the token is stored on disk.

**Errors** are `{"error": {"type", "message"}}`; `message` is a plain sentence the UI may show as is. Types:
`signed_out` (401: no token, or an expired/replaced one: sign in again), `forbidden` (403), `not_found` (404),
`limit` (429), `unavailable` (503: the gateway did not answer; the person is **not** signed out).

| Route | Auth | Returns |
|---|---|---|
| `GET /v1/health` | none | `{ok, service: "lantern-cloud", version, engine, limits, hosts, cleanup}`; `engine` is the analysis engine's version, `hosts` is `"all"` or a list. `cleanup` is one word about the service's own clean-up: `"ok"`, `"behind"` (files it should have removed have been waiting for 24 hours or more, or runs more than a day past the retention time are still there) or `"unknown"` (it could not find out). `tools/uptime.py` fails on any word here other than `"ok"` (a service from before 2026-11-10, which says nothing about clean-up, passes). No counters |
| `GET /` | none | The website (`cloud/lantern_cloud/site/index.html`, filled by `site.py` with the app's own stylesheet, typefaces, brand mark, icons, readiness ring, appearance switch and backdrop from `lantern/viewer/app.html`). Per-response nonce, the app's CSP (`lantern.server._csp`), `no-store`. Screens: signed out (paste box, sign-in sheet), My runs (Simple: cards; Advanced: the app's table), a run in progress (steps from `step`, log from `/stream`), a finished run (the report in the app's frame, tabs Paths / What to fix / What protects you / Ready to ship? / Report), Help |
| `GET /guide` | none | How to use Lantern (`lantern/viewer/guide.html` via `lantern.guide.page`, the app's stylesheet and appearance switch): animated demos from fixed data, no account or project data. Nonce CSP, `no-store`. `lantern serve` sends the same page at `/guide` without the sign-in link |
| `GET /manifest.webmanifest` · `/sw.js` · `/icon.svg` | none | Installable like the app. The service worker caches only the icon and manifest, never `/v1/` or `/r/` |
| `GET /react.production.min.js` · `/react-dom.production.min.js` · `/intro-runtime.js` · `/intro.js` | none | The home page's intro: React 18.3.1 (vendored) and the landing page's intro files (copies of `site/intro/`, a test keeps them equal), loaded under the page's nonce |
| `GET /v1/signin/providers` | none | `{providers: ["github", "google"]}` as switched on at the gateway; 503 when it does not answer |
| `POST /v1/signin/start` `{provider}` | `X-Lantern-Site` | `{url}` to open; sets `lsi`. 400 for a provider that is not switched on |
| `POST /v1/signin/poll` | `X-Lantern-Site` + `lsi` | `{signed_in: false}` while waiting; `{signed_in: true, label}` + `lt` cookie once; 400 with no sign-in in progress |
| `POST /v1/signout` | `X-Lantern-Site` | Ends this browser's sign-in at the gateway (`POST /v1/auth/signout`) and clears `lt`; `{"everywhere": true}` ends every sign-in of the account (website, app, CLI) → `{signed_in: false, ended}`; 503 when the gateway is unreachable and `everywhere` was asked |
| `GET /v1/me` | Bearer or `lt` | `{account: "github"\|"google"\|"token", label, runs_today, runs_active, limits, connect_url}` (`connect_url`: the GitHub App's install page when Connect GitHub is on, else null) |
| `GET /v1/samples` | none | `{samples: [{id, title, stack, level, summary}]}`: Lantern's built-in starter apps (`lantern.learn.catalog`), each with planted problems, for people with no repository to hand |
| `POST /v1/repos` `{link \| sample, privacy?, stored_snippets_ok?}` | Bearer or `lt` | 202 + a **run** (status `queued`). `link`: https link to a public repository on a host `lantern.remote` accepts (and `LANTERN_CLOUD_HOSTS`, when set). `sample`: a starter id from `/v1/samples` instead of a link; the run's `link` is then `lantern:sample/<id>` and its `host` is `sample`, and the worker writes the starter from the package (`learn.scaffold`) instead of cloning (400 "Choose one of the sample apps…" for any other value). `privacy`: `"structure"` (default, no code kept) or `"full"` (short snippets kept; needs `stored_snippets_ok: true`, else 400 with the sentence to show). 400 for a bad link or privacy, 429 over a limit (one active run per person, runs per day, runs for everyone per day) |
| `POST /v1/uploads?name=&privacy=&snippets_ok=` (body: the .zip, `Content-Type: application/zip`) | Bearer or `lt` (+ `X-Lantern-Site: 1` with the cookie) | 202 + a **run**, as `/v1/repos`, with `link` `lantern:upload/<name>` (`name` cut to letters, digits, `._-`, at most 80; a label only) and `host` `upload`. The website zips a chosen or dropped folder in the browser (leaving out `node_modules`, `.git`, virtual environments, build output) or sends a chosen .zip. The body must start with `PK` (400 otherwise) and stay under `LANTERN_CLONE_MAX_MB` (413, checked on `Content-Length` and while receiving). It waits in the uploads folder (`LANTERN_CLOUD_UPLOADS`) until the run starts, is then moved into the run's temp folder and unpacked by `python -m lantern.archive` in the restricted process with no network (relative names only, no links or special files, no passwords, unpacked size capped while writing; a refusal ends the run with the unpacker's sentence), and is gone when the run ends. `snippets_ok=1` plays the part of `stored_snippets_ok`. Same limits as `/v1/repos`. `POST /v1/runs/{id}/explain` on an upload run is 409: the code is no longer there to read again |
| `GET /v1/runs` | Bearer or `lt` | `{runs: [run]}`, the person's runs, newest first (at most 100) |
| `GET /v1/runs/{id}` | Bearer or `lt` | the run; 404 when it is not the caller's (same answer as a missing id) |
| `GET /v1/runs/{id}/stream` | Bearer or `lt` | `text/event-stream`: `event: log` with one JSON string per line, then one `event: end` with the run, then the stream closes. A finished run sends its saved tail and `end` at once |
| `POST /v1/runs/{id}/view` | Bearer or `lt` | `{expires_in, report, evidence, badge, findings, graph, readiness}`: absolute links that open the run's results in a browser for the next `LANTERN_CLOUD_VIEW_MINUTES` (60). Each carries `?k=<expiry>.<HMAC>` for this run only. 404 when not the caller's run, 409 when it has no report (not `done`). Open the link at once; never store or share it (anyone holding it can open it until it expires; to show someone, use Share) |
| `GET /r/{id}/report.html` · `evidence.html` · `badge.svg` · `findings.json` (= `security.json`) · `graph.json` · `readiness.json` | `?k=` from `/view`, or the `lv` cookie the first page sets for `/r/{id}/` | Rebuilt from Lantern's templates (`lantern.server.result_page`, the same code as `lantern serve`): the stored files are read for data only, pages get a per-response nonce CSP plus the report's own hash CSP, `live` is null (no actions), privacy as chosen before the run. Headers: `Cache-Control: private, no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`. 401 with a sentence for a missing, wrong or expired key; 404 for other names |
| `GET /v1/runs/{id}/share` | Bearer or `lt` | `{shared, url}`; `url` is null while sharing is off (the default) |
| `POST /v1/runs/{id}/share` | Bearer, or `lt` + `X-Lantern-Site` | Turns sharing on: `{shared: true, url}`, `url` = `<public url>/s/<slug>/report.html`, the slug 24 random characters, not the run id. Asking again returns the same link. 404 when not the caller's run, 409 when the run is not `done` |
| `DELETE /v1/runs/{id}/share` | Bearer, or `lt` + `X-Lantern-Site` | Turns sharing off: `{shared: false, url: null}`. The old link stops working at once and never comes back; sharing again makes a new one |
| `GET /s/{slug}/report.html` · `evidence.html` · `badge.svg` | none (the link is the key) | The shared run's pages, read-only, built exactly as `/r/{id}/…` (same templates, nonce CSP, `live` null, privacy as chosen before the run) plus `X-Robots-Tag: noindex`. The raw data files (`findings.json`, `graph.json`, `readiness.json`) are not shared. 404 "This link is off" for a slug that is not (or no longer) shared |
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
| `PUT /v1/workspaces/{id}/people/{person}` | owner | `{lanes: ["browser", "frontend", "server", "data"] (any of them) or null}` → the workspace: per-layer permissions. That member's `/view` links open a report built without the other layers (`lantern/scope.py`): calls into them end at a sealed node; the evidence report and raw JSON answer 403; `GET /v1/runs/{id}` has no summary or log and lists `lanes`; the stream sends no log lines; Ask Lantern with that run answers 403. Choosing all four is the same as null. 400 for anything else; 409 for the owner, who always sees everything |
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
