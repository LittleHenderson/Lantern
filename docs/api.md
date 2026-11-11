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
| `GET /api/jobs/<id>` | `{"id", "project", "kind": "analyze"\|"explain"\|"clone", "status": "running"\|"done"\|"error", "log": [lines], "result", "error", "started", "finished"}` |
| `GET /api/fs?path=` | Folder listing for the Browse dialog: `{"path", "parent", "dirs": [names]}` |

**Project summary** (one per project): `id`, `path`, `name`, `added`, `exists`, `has_report`, `score` (0–100 or null),
`grade` (A–F or null), `shape` (deployment shape string), `counts` `{critical, high, medium, low, accepted}` or null,
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
| `GET /api/projects/<id>/testcmd` | | The command the "Watch my tests run" sheet shows first: `{"command", "how", "language": "python\|node\|go\|rust\|java", "supported", "traced", "note", "cwd"?, "sandbox": {"name": "docker\|subprocess", "label", "image", "details": [lines]}, "leaves", "confirmed"}`. `traced` is true for Python only ("Tests run; your map upgrades for Python only for now") |
| `POST /api/projects/<id>/trace` | `{"command": "python -m pytest -q", "confirm": true}` | job (202). Only test runners (`sandbox.check_command`; anything else → 400). The first run of a command for a project needs `confirm: true` (409 otherwise); later runs of the same command do not. Runs in `lantern/sandbox.py` and re-analyzes; the job result is `{"returncode", "observed", "recall", "backend", "language", "traced", "timed_out", "blocked": [{"kind": "write\|network", "what"}], "note", "score_before", "score_after", "summary"}` |
| `GET /api/agents` | | `{"agents": [{"id": "claude"\|"codex"\|"aider", "name", "found": bool}], "chosen": id or ""}`: the coding agents Lantern can run for "Fix this for me", and whether each one's program is on this computer |
| `POST /api/projects/<id>/agentfix` | `{"finding": id}` | job (202), only when an installed agent is chosen in Settings (400 otherwise, and for a finding that is not open). Copies the project to `LANTERN_HOME/fixes/`, runs the agent there as a fixed argument list (never a shell line) with no `LANTERN*` variables, analyzes the copy offline and compares it with the project's results. Result: `{"fix": id or null, "status": "fixed"\|"fixed_with_new"\|"not_fixed"\|"no_change", "verdict", "agent", "returncode", "files": [{"path", "change": "added"\|"changed"\|"deleted", "diff"}], "new": [{"rank", "title", "file", "line"}], "fixed": N}`. The project is not touched |
| `POST /api/projects/<id>/agentapply` | `{"fix": id}` | job (202): copies only the fix's changed files into the project, refusing if any of them changed since the copy was made, deletes the copy, and analyzes the project again |
| `POST /api/projects/<id>/agentdiscard` | `{"fix": id}` | `{"ok": true}`: deletes the copy. An id that is not a fix → 400 |
| `POST /api/projects/<id>/starter` | `{"name": "Dockerfile"}` | `{"ok", "wrote"}`; never overwrites |
| `GET /api/projects/<id>/learn` | | Starter progress: `{"steps": [{"title", "done", …}]}` |

### Pages and files per project

| Route | Content |
|---|---|
| `GET /p/<id>/report.html` | The Atlas page, rebuilt from the data with live actions enabled (`window.LANTERN_LIVE = {api, token, model, local, view_mode, backdrop, agent}`; `agent` is `{id, name}` when an installed coding agent is chosen, else null). `backdrop` (`off`/`subtle`/`bold`) sets the moving shapes when the page is opened in its own tab; inside the app's frame the report draws none and the app's own show through. `view_mode` (`simple`/`advanced`) is the saved setting and wins over the browser's `localStorage`; switching inside the Atlas saves it with `POST /api/settings` and calls the app's `window.lanternViewMode(settings)` so its toggle agrees |
| `GET /p/<id>/evidence.html` | The Evidence Report |
| `GET /p/<id>/evidence.json` | Its data (schema below) |
| `GET /p/<id>/badge.svg` | `Lantern · commit 1a2b3c · 0 critical · Oct 31` |

### Settings and connections

| Route | Body / returns |
|---|---|
| `POST /api/settings` | `{"provider", "model", "base_url", "privacy": "full"\|"structure", "view_mode"?: "simple"\|"advanced", "backdrop"?: "off"\|"subtle"\|"bold", "share_usage"?: bool, "agent"?: ""\|"claude"\|"codex"\|"aider", "key"?, "remember"?: bool, "forget_key"?: true}` (fields left out keep their saved values; an unknown `view_mode` is saved as `simple`) → `{"settings", "providers"}` |
| `GET /api/allowance` | `{"available": bool, "used_requests", "limit_requests", "remaining_requests", "remaining_today", "used_tokens", "limit_tokens"}` |
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

### `graph.json`

`{"schema", "repo_root", "meta", "nodes": [...], "edges": [...], "unresolved": {text: count}}`

* Node: `id`, `kind` (`module`|`class`|`callable`|`external`), `name`, `qualname`, `file`, `start_line`, `end_line`,
  `parent`, `signature`, `docstring`, `decorators`, `entry` (null or `{"kind": "page"|"route"|"main"|"cli"|"script"|"test",
  "detail": "/admin" or "POST /backup", "via"?: "pack:django", "registered_at"?, "middleware"?: [node ids]}`
  (`middleware`: an Express route's own middleware, in order, e.g. `router.delete('/x', requireLogin, h)`: node ids,
  or the `ext:` name of a library's function or of one imported from a file that is not in the repo
  (`ext:./mw/guards.requireLogin`, for which no node exists); the login check reads each one's own name, what
  follows the last `.` and `/`. An entry is only ever on a function of the repo: a route whose handler is a
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
  `lanes` (`{browser, frontend, server, data}` node counts), `calls` (the summary of `calls.json`, below).
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
"counts": {critical, high, medium, low, in_tests, accepted}, "id_version", "reachable_nodes", "total_callables", "ai",
"mobile"}`

A scanner record (`lantern/scanresult.py`, one per tool run: bandit, gitleaks, lantern-secrets, pip-audit, npm-audit,
maven-audit, composer-audit, gem-audit, lantern-web, lantern-ai, packs): `tool`, `state` (`ok` | `partial` | `failed` |
`timeout` | `unavailable` | `skipped`), `status` (the same as one sentence: `ok`, `ok (…)`, `partial: …`, `error: …`,
`error: timed out …`, `skipped: not installed (…)`, `skipped: …`; records from before 0.11 have only this), `why`,
`applicable` (false when the tool had nothing to do here: no Python dependency files, gitleaks absent but the built-in
patterns ran), and when known `version`, `exit_code`, `scope` (`{files, packages}`), `exclusions` (folders a tool was
told to skip, and for bandit the Python files it was told to leave out because they are not files of the project: a
link that leads out of it, a pipe), `errors` (one line per file or package left out of a `partial` run), `findings`, `duration_ms`, `role`,
`fallback_for` (the built-in secret scan when gitleaks did not finish). `partial` keeps the findings the tool did
produce. `incomplete` is read by readiness (`sec-scanners`), the Evidence Report, the badge (`scan incomplete`), the
command line (`--fail-on` exits 1 for any state but `skipped`) and the app's project cards; a run with `--offline`
lists its skipped audits there without failing the gate.

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
`npm-audit`, `maven-audit` (Gradle/Maven libraries through OSV; `line` is where the library is written), `composer-audit` (PHP libraries from `composer.lock` through OSV; `line` is where `composer.json` asks for it, else its `composer.lock` entry), `gem-audit` (Ruby gems from `Gemfile.lock` through OSV; `line` is the Gemfile's `gem` line, else the lock entry), `secrets`, `lantern-web`, `lantern-pack:<name>`), `rule`, `title`, `tool_severity`, `tool_confidence`
(`LOW` = show "heuristic"), `file`, `line`, `cwe`, `more_info`, `snippet`, `category`, `in_tests`, `node`,
`reachable` (null or `{"entry", "kind", "path": [node ids]}`), `reachable_from_tests_only`, `ui_path` (node ids from a
page, or null), `input` (null, `false`, or `{"via": "parameter `name`"}`), `rank` (`critical`|`high`|`medium`|`low`),
`context` (optional, `context.py`, read from names around the line: `{"hash": {"purpose": "security"|"non-security"|"unknown", "why", "password", "reads"}}`
for weak-hash rules, `{"sql": {"fixed_only", "spliced": [{"expr", "fixed", "why"}], "driver_params", "reads"}}` for Python SQL), `rank_note` and
`rank_before_context` (only when `context` lowered the rank: why, and the rank it would have had; the viewer shows both; a
non-security hash or SQL splicing only fixed text → `low`, a hash of unknown purpose → at most `medium`),
`trust` (LW-PUBLIC-SECRET only, `context.public_secret_trust`: `browser` `{exposed, where, sent_as}`, `server_trusts`
(`server-checks-it`|`server-reads-it`|`not-seen-on-server`|`no-server-code`), `server_checks`, `server_reads`, `routes`,
`other_controls` `[{route, login_check, why}]`, `conditions` (settings the checking code branches on), `stranger_access`
(always `not determined`), `unknown` [plain sentences]; never changes the rank),
`case` (every finding outside test code, `case.py`, version 1: `where` `{file, line, function, revision, revision_note?}` (revision = the analyzed folder's git commit, `null` outside git; `revision_note` when the folder has uncommitted changes, or the header's `note` when git could not compare the files), `claim` (the tool's words, never stronger than the evidence), `evidence` `[{fact, from}]` (`from`: the tool, `map`, `input check`, `context (names)`/`context (code)`), `conditions` `[{need, met, why}]` (what has to be true for harm; `met` true = Lantern saw it, false = saw it is not, null = cannot check), `impact` (the scenario's harm), `severity` `{rank, tool_severity, why, before_context?, context_note?}`, `confidence` `{level: high|medium|low|unknown, why, about}` (the tool's own confidence, one step lower when the path has a `likely`/`possible` link; about the pattern being there and reached, never about exploitability), `unknown` [plain sentences], `status` `[{word, done, why}]` for `reported`, `reproduced` (the id was in this folder's previous `security.json` or `baseline.json`; null on a first run), `fixed` (false while listed), `tested` and `independently reviewed` (always null: Lantern keeps no such record; an accepted risk is a review by the builder, not an independent one)),
`status` (`open`|`accepted`), `accepted` (`{"reason", "by", "date"}` when accepted), `hot_lane` (the lane the problem
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

`version`, `score`, `grade`, `shape`, `stack` (`{frameworks, …}`), `categories` (`[{key, title, weight, score, percent,
checks: [{id, title, points, earned, status: pass|fail|partial|skip, evidence, fix, how}]}]`), `next_steps` (the
highest-gain failed checks, with `gain` and `category`), `protections` (`[{id, title, status: add|check|in place, why,
evidence, found, how}]`), `incomplete` (the scanner records from `security.json` that apply and are not `ok`; the
`sec-scanners` check in Security findings fails when one `failed` or timed out, is partial for a gap the run knew
about, and passes only when every applicable scanner finished), `advice` (deployment advice strings for the shape),
`hotspots`, `env_vars`, `starter` (`{filename: {content, snippet?}}`).

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
git folder was not read) or when git could not compare the files with the commit, in which case `dirty` is `true`:
`lantern/gitfacts.py`),
`scorecard` (`readiness`, `now` counts, `before` counts, `baseline_date`, `baseline_commit`), `architecture`,
`security` (`open`, `accepted`, `fixed`, `changed`, `in_tests`, `protections`, `incomplete`: `[{tool, state, status,
why, role, version}]`, the scanners that did not finish or did not cover everything; while it is not empty the memo, a
notice under the tiles and the badge say `scan incomplete`, and the badge is never green), `understanding`,
`provenance` (`tools` with each scanner's `state` and `status`, `models`, `rules`, including analysis packs), `limits`
(strings: what the report does not prove; one line per incomplete scanner), `digest` (`sha256:…`), `payload`.

### Other files

`calls.json` (above), `run.json` (timings, privacy, offline, trace, `incomplete` `[{tool, state, status, why, role}]`,
finished_at), `baseline.json` (first-run findings for "fixed since"),
`cache/` (explanation cache). In the repo itself: `lantern-accepted.json` (accepted risks with reasons, committed),
`lantern-packs/*.json` (project analysis packs), `lantern-narratives.md` (the builder's own notes for the Evidence Report).
Each is read only as a file of the project (`python_frontend.inside_repo`): a notes file or a packs folder that is a link
leading out of the project counts as not there.

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
| `GET /v1/health` | none | `{ok, service: "lantern-cloud", version, engine, limits, hosts}`; `engine` is the analysis engine's version, `hosts` is `"all"` or a list. No counters |
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
| `DELETE /v1/runs/{id}` | Bearer, or `lt` + `X-Lantern-Site` | `{deleted: id}`: the run's row, its result files and its share link are gone. 404 when not the caller's run; 409 while it is `queued` or `running` |
| `DELETE /v1/me` | Bearer, or `lt` + `X-Lantern-Site` | `{deleted: true, runs: n}`: every run, result folder, share link, daily counter and the account row are deleted, and the `lt` cookie is cleared. Signing in again starts a fresh, empty account. 409 while one of the person's runs is still going. The gateway account (and its allowance counters) is not touched |
| `GET /v1/ai` | Bearer or `lt` | `{consent, notice, allowance}`: whether the person has agreed to send work to a model, the sentence they agree to (`providers.DATA_NOTICES["lantern"]`), and `{remaining_requests, limit_requests, remaining_today}` from the gateway's `/v1/allowance` (null when it does not answer) |
| `POST /v1/ai/consent` `{agree}` | Bearer, or `lt` + `X-Lantern-Site` | Records (`true`) or withdraws (`false`) the agreement: `{consent, notice}`. Off by default; deleting the account forgets it |
| `POST /v1/runs/{id}/explain` | Bearer, or `lt` + `X-Lantern-Site` | 202 + the run, `explain.status` `queued`. Writes plain-words explanations (entry points and three levels down, up to 40 functions) with the caller's free allowance: the worker copies the repository again, refuses if its commit differs from the run's (the words must match the map), runs `lantern explain` in the restricted process with the network on and the token in its environment (held in memory only while the job waits), copies back `explanations.json` and the rebuilt report, keeps the explain cache (explaining again never pays twice), and deletes the copy. 412 `consent_needed` without agreement, 409 when not `done` or already being written, 503 when the server has no worker |
| `POST /v1/ask` `{question, run?, focus?: {node?, finding?}}` | Bearer, or `lt` + `X-Lantern-Site` | `{answer, cited, invented}`. Ask Lantern (`lantern.ask`): the model answers from the run's results (`ask.facts`, never source code) or, with no `run`, from what Lantern is. Finding ids the model made up are replaced with "[unknown finding]" and counted in `invented`. 412 without agreement, 402 `allowance` when the free allowance is used up, 401 `signed_out` when the gateway no longer accepts the token (the person signed in somewhere else; the remembered sign-in is dropped), 413 when the question and facts are too big, 503 when the gateway or the model company fails, with the true reason in plain words (`providers.why_failed`: a refused key, no credit, an outage, no key set up, gateway unreachable), 502 when the answer cannot be read, 404 for a run that is not the caller's |
| `POST /v1/ask/screenshot` (multipart, one PNG/JPEG/WebP ≤ 8 MB, ≤ 40 M pixels) | Bearer, or `lt` + `X-Lantern-Site` | `{width, height, format, lines, text}` like the app's `/api/ask/screenshot` (`ask.read_screenshot`: Pillow, then Tesseract through a pipe). The image stays in the request's memory: never written to disk, kept, or sent to a model; the text reaches a model only inside a question the person sends. `text: null` + `reason` when this server cannot read text in images (`how` is always null here). 400 not an image or too many pixels, 413 too large, 429 when two are already being read. Needs no consent (no model is involved) |
| `GET /v1/admin/stats` | Bearer = cloud admin secret | `{users, runs, runs_by_status, runs_today, shared, workspaces}`; 403 when no admin secret is set |
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
{critical, high, medium, low}, files, lanes: {browser|frontend|server|data: {critical, high, medium, low}}, phone}`, read from the
result files (`lanes`: open findings outside tests by `hot_lane`; a finding with no lane is left out; `phone`: the
platform is a phone app, so the website says Screen and App; a run saved before `lanes` existed gets them on the next
`GET /v1/runs`). `shared` is false until the person clicks Share
(`POST /v1/runs/{id}/share`). `log_tail`: the last 40 log lines, server paths removed. `explain`: `{status: null|queued|running|done|error, error, summary: {functions, validated, failed, stopped}, log}` (`log`: the explain job's last lines while it runs). `step`: `clone` | `audit` | `analyze` |
`save` while running (the key of `stage`), else null. `hint`: `"upload"` when the repository could not be opened (private, or no such repository; git asked for a password, or Connect GitHub refused: the person cannot read it, or signed in with Google), so the website offers "Upload your code instead"; `"connect"` when Connect GitHub is on and the app is not installed on that repository, so it offers "Connect GitHub" (`/v1/me` `connect_url`) and Upload; else null. `summary` values are checked when read (score and files whole
numbers or null, grade A–F or null, counts whole numbers), since a stranger's repository wrote the files.

Retention: with `LANTERN_CLOUD_RETENTION_DAYS` = 0 (the default, the owner's decision) results are kept until the
person deletes them. A number N starts an hourly sweep (`app.sweep`) that deletes finished runs older than N days, their
result folders and share links, exactly as `DELETE /v1/runs/{id}` does.

What a run does (`cloud/lantern_cloud/worker.py`): clone into a temp folder (size cap before checkout) → dependency
audits on lock files in the restricted process with the network on → analysis (`lantern analyze --offline`, the
audit results passed in through `LANTERN_AUDITS_FROM`) in the restricted process with **no network** and writes only
in its temp folder → result files copied to the run's folder → the temp folder, clone included, removed in every
case. Nothing from the repository is built, installed or run. A restart marks a running run `error` ("start it
again") and requeues waiting ones.

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
* **Readiness / Protections**: score ring, categories, "do first" list, protections with add / check / in place,
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
