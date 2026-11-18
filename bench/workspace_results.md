# Workspace check: results (2026-11-17)

`python bench/workspace.py` (module docstring: what it compares and what it had to show, written down before its
first run). Offline, nothing kept between runs (`LANTERN_CACHE=off`), isolated (`tools/netguard`, no address tried).
Roadmap of 2026-11-14, stage 6, part 1 (`lantern workspace`, `docs/workspaces.md`).

## What it had to show (written before the first run)

* **Alone and inside:** every sample the same in all five (functions by file and lines; links with `via` and
  confidence; entry points; call-site records; findings by rule, file, line and rank), every path taken from the
  member's top, and no link from a sample to the partner project or back.
* **Split and joined:** every request the whole sample links from its web folder to the rest is linked across the two
  projects, by the same rule (`via`) and with the same confidence, and nothing else.

## First run (2 samples, before any fix)

`--only shop,goapp`, 2 s:

| | Differences | What it was |
|---|---|---|
| shop, alone and inside | 4 entry points | 🔧 the measurement's own: an entry's words name its file from the top of the map (`python shop/shop/cli.py`); the comparison now reads them from the member's top. Nothing in Lantern changed for it |
| shop, split and joined | 1 request only in the whole sample | 🔧 the measurement's own: a call to an outside address (`api.weather.example.com`) was counted as a request between the two halves; it now counts only requests answered by a route of the project |
| goapp, alone and inside | 8 links, 8 entry points, 2 findings | 🟥 **a real fault in the Go reader**: only a `go.mod` at the top of the repository was read, so a Go server in a folder of its own linked none of its own imports (`handlers.go` → `internal/store` became library calls, `ext:store.Repo.Save`), and `LG-SQL-CONCAT` in `internal/store/store.go:27` read **high** instead of **critical** (the 8 entry differences were the measurement's own, as for shop) |
| goapp, split and joined | none | 2 of 2 requests |

The Go fault is not only a workspace's: a monorepo with a Go service in a folder of its own (`backend/` beside
`frontend/`) read the same way before. Fixed (`go_frontend._Modules`: the nearest `go.mod` at or above a folder, as the
go tool reads it) after two failing tests and a safe twin (`tests/test_go.py`).

## After the fix (all 15 samples)

Run again after every later change of the stage; the last run (4:13 PM PST) is the same as the first full one:

| Sample | Functions | Links | Entries | Call sites | Findings | Differences |
|---|---|---|---|---|---|---|
| aiapp | 16 | 27 | 4 | 32 | 11 | 0 |
| androidapp | 40 | 50 | 16 | 0 | 26 | 0 |
| cppapp | 22 | 50 | 8 | 14 | 6 | 0 |
| csharpapp | 55 | 75 | 14 | 0 | 10 | 0 |
| flutterapp | 30 | 47 | 5 | 0 | 5 | 0 |
| goapp | 31 | 61 | 8 | 11 | 3 | 0 |
| iosapp | 36 | 41 | 8 | 0 | 12 | 0 |
| javaapp | 43 | 56 | 7 | 11 | 3 | 0 |
| kotlinapp | 41 | 52 | 8 | 0 | 3 | 0 |
| nextapp | 19 | 26 | 6 | 26 | 3 | 0 |
| phpapp | 34 | 57 | 11 | 16 | 8 | 0 |
| rnapp | 22 | 32 | 4 | 49 | 8 | 0 |
| rubyapp | 46 | 65 | 12 | 14 | 7 | 0 |
| rustapp | 31 | 59 | 8 | 11 | 3 | 0 |
| shop | 45 | 73 | 8 | 54 | 9 | 0 |

(Call sites are inventoried for Python and JS/TS only, so the samples in other languages have none.) No link from a
sample to the partner or back in any of the 15.

Split and joined, 7 samples (aiapp, cppapp, goapp, javaapp, rubyapp, rustapp, shop): each 2 requests linked in the
whole sample, 2 linked across the two projects with the same `via` and confidence, nothing else, no link of code
across. 11 s for all of it.

## Names (what a member may be called)

A member's name is the folder its copy is in. On the 15 samples, 66 everyday names were tried as the member's name
(`alone and inside` as above, the name being the only change; the rule refusing names switched off for the trial):

* **39 change nothing**: web, api, server, client, frontend, backend, mobile, admin, worker, site, shared, common,
  core, ios, android, public, www, htdocs, contest, latest, production, settings, default, demo, static, assets,
  components, services, utils, db, node, go, python, java, data, models, auth, payments, notes.
* **27 change what is read**: test, tests, e2e, build, dist, vendor (all 15 samples); bin (4); example, out, target
  (3); spec (2); docs, mocks (shop); lib, app, src, config, templates, views, routes, database, migrations (the PHP
  sample); pages (the Next.js sample); scripts, tools (the Ruby sample); packages (the C# sample).

The names a member is never given are then taken from Lantern's own rules, not from the trial
(`tests/test_workspace.py::test_no_project_is_given_a_name_a_folder_rule_of_lantern_gives_a_meaning`): every pattern
of Lantern's about a whole folder's name (87: in a call of `re` anywhere in the package, or kept at a module's top) is
asked about a file under a name and under a name no rule knows, for every word in the rules, the same word with
something before or after it, and the name Lantern makes in its place; Lantern's own lists of folder names (8) are
added. Result: 95 names and 2 beginnings (`cmake-build-`, `bazel-`), `workspace.RESERVED` and `RESERVED_STARTS`. All
27 of the trial are among them; none of the 22 everyday names the test keeps (web, api, server, client, admin, …) is.
Four rules leave their names usable, each with its reason in the test (`LEFT_USABLE`): where a file is drawn on the
lanes, a route's address, a protection card's count of the browser's requests, and a SvelteKit project's rule for its
own `server/` folder (a project called `server` beside a SvelteKit project reads as it does alone,
`test_a_project_called_server_beside_a_sveltekit_project_reads_as_alone`). While the names were checked a second fault
was found, not in a workspace only: 🟥 the Dart reader skipped every Dart file under any folder called `web`, `ios`,
`android`, `macos`, `windows` or `linux`, also a repository's own `web/` server, and not only a Flutter project's
platform folders; fixed after a failing test and a twin (`tests/test_flutter.py`).

## The map benchmark before and after this stage (2026-11-17, 7:15 PM PST)

`python bench/run_bench.py WORK --no-trace`, offline, on the 7 public projects of the map benchmark, with stage 5's
last code (before this stage) and with this stage's code, in two pairs of runs. Every value the benchmark writes but
its two times (functions, files, lines, languages, links inside the project, entry points and their kinds, links
between page and server, confidence levels, unresolved calls, findings): **0 different**, in both pairs. Time
(reading and scanners, all 7 projects): 24.09 and 25.30 s before, 25.76 and 24.92 s after, each with the files
already read once (the very first run, 28.68 s, read them from the disk). The two runs of one side differ by as
much as the two sides do, so the measurement tells no difference in time.

## Readiness

The shop sample split into its web page and its server and joined as a workspace grades as the whole sample does:
F 26, "full-stack web app", decision Blocked (alone: F 26, the same). Its halves alone: the server F 37 "web API",
the page F 20 "frontend web app". A workspace is graded as the one repository it reads as.

## Found while checking, not by the measurement

🟥 Making a workspace under the name of a folder a person keeps in the workspaces folder would have replaced (and
removed) that folder. Lantern now marks the folders it makes (`.lantern-workspace`) and never replaces or removes one
without the mark, nor a record it did not write (`test_a_folder_of_that_name_that_lantern_did_not_make_is_never_replaced`).
Found while checking where Lantern's readers reckon a project's top: a plain PHP page in a member answered at the
member's path (`/legacy/index.php`) instead of its own (`/index.php`), which the measurement did not show because the
PHP sample's pages lie below a web root; fixed (`workspace.below`), `test_a_page_answers_at_the_address_it_has_alone`
with its twin under a web root.
