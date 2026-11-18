# Several projects as one map: `lantern workspace`

A web app, a phone app and the API they call often live in repositories of their own. Checked one at a time, the
map of the web app ends where a request leaves it: `fetch("/api/notes")` is a call to somewhere the map does not
know, and a finding in the API cannot say which page of the web app leads to it. A **workspace** puts the projects
side by side and checks them as one map.

```bash
lantern workspace ~/code/web ~/code/api                 # two folders; the workspace is called web-api
lantern workspace web=~/code/site https://github.com/acme/notes-api --name notes   # names of your choosing, a link
lantern workspace --name notes                          # the same projects copied anew from where they came from
lantern workspace --list                                # the workspaces and their projects, with each commit
lantern workspace --remove notes                        # the copies and the record; the projects are not touched
lantern serve ~/.lantern/workspaces/notes               # the app, on the workspace like on any project
```

In the app, `POST /api/projects` with `{"paths": [...], "name"?: "..."}` does the same in a job (`docs/api.md`).

## What it does

Each project is copied into a folder under its own name, `~/.lantern/workspaces/<name>/<project>/`, and that folder
is checked like any other project. A workspace reads as one repository that holds the projects in folders, and
Lantern reads it exactly as it reads such a repository: the bridge links a page of one project to the route of
another by the rule it uses inside one repository (method and path), every link keeps the `via` that says how it was
made, and what a finding is reached from crosses from one project to the other as it crosses from a page to a server.

What crosses is listed on the map (`meta.workspace.across`) and in the log:

```
across  2 requests from one project answered by another; 0 links of code across projects (possible); 0 names written in more than one project (links to them possible)
```

The Evidence Report names each project, where it came from and the commit it was copied at, and the digest takes in
those commits, so `lantern verify` fails when one of them differs.

## What it does not make up

* **A name two projects share.** Two projects made from one template write the same Java package and class; two
  Rails apps each have a `UsersController`. Lantern reads such a name as one, so the map would hold one node for code
  of two projects and their calls would mix. When the workspace is made each project is read alone to find such
  names; every link that touches one is only `possible`, and the names are listed with the projects that write them.
* **Code of one project that names code of another** (`from textutil import clean`, where only another project has
  a `textutil.py`) would be linked as inside one repository. Whether a project installs the other is not read, so
  such a link is only `possible`, and it is listed.
* **A request answered across projects** keeps the bridge's own confidence and `via`.

## What is copied

A project's plain files and folders, byte for byte; a link only where it stays inside the project. Never version
control, Lantern's own results (`.lantern`, which may have come with the project), installed libraries and tools'
caches, and nothing that is no file. What was left out is counted per project. A repository link is cloned first, by
the same rules as `lantern analyze LINK`.

Only your own command makes a workspace: the record of what a workspace holds is kept beside it
(`~/.lantern/workspaces/<name>.json`), never inside a project, and a list of projects a project brings is never read.
A folder under the workspaces folder that Lantern did not make is never replaced or removed.

## Names

A project's name is the folder its copy is in, so it is part of every path on the map (`api/main.py`). It is made of
lowercase letters, digits and dashes. A name that one of Lantern's own folder rules gives a meaning is never given to
a project, because it would change how the project's files are read: `tests`, `docs`, `examples`, `build`, `dist`,
`vendor`, `src`, `app`, `lib`, `tools`, `public`, `templates` and the rest of `workspace.RESERVED`, and names that
begin `cmake-build-` or `bazel-`. A folder of such a name gets `-project` after it (`docs-project`); a name you give
that way is refused with the reason. Everyday names (`web`, `api`, `server`, `client`, `admin`, `mobile`, `shared`,
`core`, …) are free.

Where a rule of a reader is about where a project begins (the address of a PHP page below its web root), the reader
reckons from the project's own folder (`workspace.below`), so the page answers at the address it has alone.

## Not yet

* Contracts the projects share (OpenAPI files, `.proto` files, a tRPC router used as a package) are not read as
  links: only requests one project makes and another answers are.
* A project's accepted risks (`lantern-accepted.json`) are not read in the workspace, so its accepted findings show as
  open there; the Evidence Report says so.
* Settings that a reader takes as true for the whole repository are true for every project of the workspace, as they
  would be in one repository: a SvelteKit project's rule for files in a `server/` folder is one (measured: a project
  called `server` beside a SvelteKit project reads as it does alone, `tests/test_workspace.py`).
* A folder name is read by more than Lantern's folder rules where a reader decides by what a folder holds; the
  measurement below tried 66 names on the 15 sample projects.

## How it was checked

`python bench/workspace.py` (`bench/workspace_results.md`): every sample project read alone and as a member of a
workspace, compared on its functions, links, entry points, call sites and findings; and every sample that holds a web
page and its server split in two and joined again as a workspace. Tests: `tests/test_workspace.py`.
