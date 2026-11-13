# Changelog

Each release has a section headed `## <version>`. The release workflow (`.github/workflows/release.yml`) puts the
section matching the pushed tag into the GitHub Release body (`v0.9.0-rc1` uses `## 0.9.0-rc1` if present, else `## 0.9.0`).
GitHub takes 125,000 characters there and no more, and `tools/changelog_section.py` stops a release before anything
is built when a section is longer. So a release with a long list has two sections: a summary under `## <version>`,
which is what the release page shows, and the whole list under `## <version>: every change`, which stays in this
file. New entries go under `## Unreleased`, on top.

## Unreleased

## 0.11.0

Lantern as a release reviewer: a release decision the score cannot speak over, problems followed across the whole
app, an app's behaviour tested by running it, a safer and a faster engine, seven more languages and phone apps.

This is the summary. Every change in full, with the names in the code, each measurement and what was found and not
fixed, is the section "0.11.0: every change" of
[CHANGELOG.md](https://github.com/LittleHenderson/Lantern/blob/v0.11.0/CHANGELOG.md).

**If you used 0.10.0: results change, on purpose.** A project now gets a release decision beside its score: Blocked,
Incomplete or Passed. Scores go down where required work was skipped (tests that were not run, libraries that were
not looked up). The score is held at 59 while the decision is Blocked and at 99 until it is Passed, so 100 means the
required work passed. A badge that was green may now say "blocked" or "incomplete". Some findings rise by one rank,
because a finding is no longer ranked lower when Lantern found no path to its line. Lines that carry a `# nosec`
comment appear in the results for the first time.

### Finds more, and tells you how sure it is

- **The release decision.** Blocked: a critical or high finding is open, the project's tests failed, or a behaviour
  check came out broken. Incomplete: nothing failed and something required is missing (a scanner did not finish,
  libraries were not checked, the tests were not run). Passed: everything required for this kind of project passed.
  It is on the report, the Evidence page, the badge, the app, the website, the connector and
  `lantern analyze --require not-blocked|passed` for CI.
- **Follow the data** (Python and JavaScript/TypeScript). A value that arrives with a request is followed across
  functions and files to where it does something sensitive: a query, a command, a file path, a page, a redirect, an
  outgoing request. A check counts for what its code proves, whatever the function is called. The finding shows
  every step of the way with file and line.
- **Who may reach what** (heuristic, and marked as such). A record reached by an id from the request with nobody
  asking whose it is, an admin path that asks for no role, a whole request body written onto a stored record, a role
  read from a cookie or header the caller writes. A login is read from what the code does, not from a name.
- **Behaviour checks.** `lantern behave PATH` starts the project's app in the test sandbox, with no network, and
  tests what really happened: twelve kinds of check from a plan the project carries (`lantern-behaviour.json`,
  guide `docs/behaviour.md`). A refused request that changed something all the same is a failure of its own kind.
- **Every call is counted once** (`calls.json`, Python and JavaScript/TypeScript): one record per call, with one
  outcome and, where Lantern cannot follow it, the reason in plain words. Far more calls are followed: `require()`
  and `module.exports`, Express routers and middleware, star imports, library base classes.
- **A scanner that fails can no longer read as a clean result.** Every scanner writes down how its run ended, and a
  failed or partial run is said on the report, on the Evidence page and in the release decision.
- **Fewer false alarms, nothing hidden.** A weak hash is ranked by what it is for. SQL that splices only fixed text
  is ranked low, with the reason. A webhook whose sender is checked is not "a route anyone can call". A request
  limit counts only where it is put to work on the route. Every finding outside test code carries its case: the
  claim, the evidence, the conditions and what is not known.
- **A report says no more than Lantern saw.** "Security headers: in place" is said only when a header is set for
  every response; a header set for a part of the app reads "check", with the place. Python kept as text
  (`engine.py.txt`) is handed to the Python scanner. Software copied into a `vendor` folder is named and, where
  it brings a name and a version, looked up for known security holes.

Measured on the held-out benchmark (`bench/heldout/`: 14 apps, 79 known problems, 17 safe examples that must stay
clean; no rule was written from their code), before this work and now:

| | before | now |
|---|---:|---:|
| Known problems found at medium or higher, of 79 | 28 | 55 (56 with the library checks on) |
| False alarms on the 17 safe examples | 3 | 0 |
| Vulnerable apps given a green result, of 8 | 2 | 0 (all 8 read Blocked) |
| Clean apps refused a green result, of 6 | 3 | 1 |

Not reached: 24 of the 79 known problems are still missed (23 with the library checks on), and one of the six clean
apps reads Blocked through one false alarm. The other five read Incomplete, because the benchmark does not run
their tests, and none reads Passed. `bench/heldout/README.md` has every number and how to run it.

### Safer to run on a stranger's project

- A link in a project that leads out of the project is not read and not shown, and Lantern's results are written
  into the results folder and nowhere else.
- Lantern starts only the person's own programs, never one that lies in the folder it reads. The git settings of
  that folder are not obeyed, npm takes no settings from the project it audits, and a settings file in a project
  does not steer the Python scanner.
- What a project's dependency files say is checked before it is used, and a project file of the wrong shape no
  longer stops the analysis.
- A project's tests are not run without their sandbox, nothing they start is left running, and the app has a
  "Stop the tests" button.
- A git folder that is not yours no longer puts its commit on your report.
- The cloud service deletes only what it made, and a delete that fails is written down, said and tried again.
- The gateway (0.2.6) bounds what anybody can send it without signing in.
- The opt-in usage counts go to the gateway's own address and nowhere else, and Lantern says where they go.
- No line of a project keeps a check busy: a quote mark followed by many backslashes, or one long chain of calls
  in C# or Ruby, could hold a check for hours or days.
- Code nested about a thousand levels deep no longer stops the whole check with an error and no report. The piece
  is left, named in the report as not read, and everything around it is read.

### Faster, with every result as it was

Measured with `bench/speed.py` on six projects, the engine before the change and after it back to back on one
machine, every result file compared and the same:

| | before | now |
|---|---:|---:|
| Django (481,021 lines), first check | 115.72 s | 52.05 s |
| Django, a second check with nothing changed | 113.84 s | 41.03 s |
| Laravel's framework (415,998 lines), first check | 37.83 s | 19.38 s |
| Django's report | 73,896,338 bytes | 38,050,642 bytes |
| The 12-file sample, first check | 0.63 s | 0.74 s |

The last row is slower, and stays in the record as that. Work is kept between runs only for Python files and for
the Python scanner (`lantern cache [--clear]`, `LANTERN_CACHE=off`), never in the project, and never a finding, a
rank, a score or a release decision. The hosted service keeps nothing.

### More languages, and phone apps

- Kotlin, Swift, Dart, C#, PHP, Ruby and C/C++ are read and mapped: functions, calls, routes and line rules, each
  with a sample app.
- Android, iOS, Flutter, React Native and .NET MAUI apps are read as phone apps: the screens, the parts other apps
  can start, links into the app, permissions, and rules for each platform (the "On the phone" card).
- The libraries of Android and Java (Gradle, Maven), PHP (Composer) and Ruby (Bundler) projects are checked for
  known security holes.
- Script written inside HTML pages is read.

### The app and the website

- A terminal you pull up from the bottom of every screen, in the app and on the website. It runs Lantern's own
  commands and never a shell or anybody's code.
- "How to use Lantern": a guide with a tour and a section for each task, reachable from every page.
- The map: the Graph and the Flowchart fill the whole panel as an endless canvas, with a breadcrumb that says where
  you are and a minimap (100%, 60%, 30% or hidden). The Graph says what its lines mean.
- Every function has its three lenses from the moment a check ends.
- Website: upload an app from your computer, Connect GitHub for private repositories, a Settings page, the intro on
  every visit, and a check in progress always shows that it is working.
- Signing in somewhere new no longer signs you out everywhere else (up to 8 places per account), and there is a
  "Sign out everywhere" button.
- Big projects' reports open again, and a repository over the size limit is checked without its pictures, video
  and other bulk files.
- The cloud service allows 300 runs per person per day and 1000 for everyone together.

### For people who work on Lantern

- Tests and benchmarks cannot reach a real AI provider or the internet and never see the developer's keys
  (`tools/netguard/`). CI runs every test, and its log names each test it skips.
- New commands: `lantern behave`, `lantern cache`, `lantern analyze --require`.
- New result files `calls.json` and `behaviour.json`; `readiness.json` is version 2 (`release`, `checklist`); a
  finding carries `reachability`, `rank_basis`, its `case` and, where one was followed, its `flow`. Results that
  0.9.0 and 0.10.0 wrote still open. `docs/api.md` has every shape.
- The release itself can be rehearsed: the release workflow, started by hand, builds the package and runs every
  test against it, and publishes nothing. Release notes longer than GitHub takes stop a release before anything is
  built. Tests that read Lantern's own files read the installed package (`tests/lantern_files.py`): twelve failed
  against the built package in a trial of this release. Five release tests that were dropped by mistake on
  2026-11-12 are back (`tests/test_release_plumbing.py`).

### Known limits

- On Windows a test that starts an event loop (an async test, a FastAPI test client) fails in the test sandbox, and
  `lantern behave` starts no app there. Found and not fixed.
- Follow the data, who may reach what and the call inventory cover Python and JavaScript/TypeScript. The other
  languages keep the reading inside one function, and their confidence levels are not yet backed by a benchmark
  for each language.
- A computer with one processor, Windows and macOS were not measured for speed.
- A Dart type written inside itself thousands of levels deep takes the Dart grammar's own parser very long (10,000
  levels: 66.33 seconds). Found and not fixed.
- `CLAUDE.md`, "Known gaps", lists the rest.

## 0.11.0: every change

- The release is tried before the tag, and its own tests are whole again (2026-11-12; found while preparing 0.11.0).
  Three things would each have ended a pushed tag in a failed release, or let a wrong one out:
  - **The text of the Release was too long.** GitHub takes 125,000 characters as the text of a Release and refuses
    more at the workflow's last step, after the build and the tests. The section waiting to be released was 193,835
    characters. `tools/changelog_section.py` now ends with 1 and says the length when a section is over `LIMIT`
    (the workflow's second step, before anything is built), and a release with a long list keeps a summary under
    `## <version>` and the whole list under `## <version>: every change`, which the tool leaves out.
  - **Twelve tests failed against the built package.** The release's `test-wheel` job moves the checkout's
    `lantern/` folder away and runs every test against the installed package. Twelve tests read a page of
    `lantern/viewer/` or a module's source through the checkout's path and found no file (a trial run on 84d5c1e:
    4,276 passed, 27 skipped, 12 failed), and three more walked a `lantern/` folder that was gone and passed having
    read none of Lantern's modules (`test_no_program_is_started_any_other_way`,
    `test_no_name_is_given_twice_at_the_top_of_a_module`,
    `test_every_loader_of_a_saved_map_says_which_folder_it_means`). Lantern itself was not at fault: every file is
    in the package. The same happened to one test at 0.10.0, after the tag (#88). Such a test now asks
    `tests/lantern_files.py` where the package is (`PACKAGE`, `VIEWER`, `page`, `named`, and `modules`, which
    fails on a walk that finds no file), and `test_no_test_looks_for_lanterns_own_files_in_the_checkout` reads
    every test file.
  - **Five release tests were gone.** `tests/test_release.py` was written anew on 2026-11-12 for the release
    decision, and the five tests it held went with the old text by mistake: one version in `pyproject.toml` and
    `lantern/__init__.py`, a CHANGELOG section per tag, `serve --check`, Bandit missing said, the testers' guide and
    its one pinned install command. They are back unchanged as `tests/test_release_plumbing.py` and pass.

  `.github/workflows/release.yml` can now be started by hand (`workflow_dispatch`, "Run workflow" on the Actions
  tab). Such a rehearsal builds the package, runs every test against it and looks at the live gateway exactly as a
  tag does, and ends before the one job that publishes (`if: github.event_name == 'push'`, the only job that may
  write to the repository). `docs/deploy.md` has the order: merge, rehearsal, deploy lantern-cloud, tag.

  `tests/fixtures/old_results/v0.11.0/` holds what this version writes for the shop sample (0.11.0 is the first to
  write a release decision into `readiness.json` and a call inventory, `calls.json`), so the next versions are
  tested on opening it. `tests/test_old_results.py` also holds that a result from 0.9.0 or 0.10.0, which has no
  release decision, is shown with none: this version does not make one up for work an older version did.
- Three things a report said that were not so, found on a real static site (2026-11-12). The site keeps 17 Python
  files (12,518 lines) as `<name>.py.txt`, runs them in the browser beside a copy of their runtime in `vendor/`, and
  is served with no security header. Its report said "Security headers: in place", "bandit: ok" (on 0 files), that
  every scanner had covered everything, and that the project lists no libraries.
  - **Security headers** (`lantern/headers.py`): the card reads `in place` only when the code or a hosting file shows
    a header set for every response (a hosting rule for every path, a library put on the app, the project's own
    function that runs for every request), `check` with the place when a header is set for a part (a `<meta>` tag in
    one page, one route's answer, a rule or a library for one path), and `add` when nothing sets one. Until now one
    of a few words anywhere in the code read "in place": there, a `<meta>` tag in one exported document and the word
    "helmet" as an HTML tag's name in a search pattern. On that site the card now reads `check` and names the four
    places. Projects that set a header for part of the app, or only name one, will see `in place` become `check` or
    `add`: Lantern's own two services read `check` (each page sets its own headers; no one place does for all).
    A setting counts for the app it is in, not for the one in the folder beside it: helmet on the API sends nothing
    with the pages of the site, so a project with a site and an API reads `in place` only when each has its own
    (an app begins at the nearest folder with a `package.json`, a `pyproject.toml` or the like; a rule at the top of
    the project is for all of it; the card names the folders that are left out). A copy or a template of a hosting
    file (`next.config.js.tmpl`) is not the settings in force: Lantern's own card read "in place" for the sample of
    a starter app while this was written. Comments are found in one pass over the text (`headers._not_code`), which
    no line can keep busy and which no longer takes the closing quotes of a text kept under a name for the start
    of a docstring.
  - **Code kept under another name** (`lantern/unread.py`): Python kept as text (`engine.py.txt`) is handed to Bandit
    by name; on that site it now reads 17 files and reports 8 lines it could not see before. A command there that is
    handed literals only is ranked `low` with the reason beside it (one of the 8: a line that clears the screen), as
    in a `.py` file; a command that takes a value keeps its rank. Code kept as text that no scanner reads
    (`helper.js.txt`) leaves the release decision's `scanners` criterion `missing` and is named. Templates and
    left-over copies (`.tmpl`, `.bak`) are named in the Evidence Limits, which also say that the map and Lantern's
    own checks read none of these files. `security.json` has the counts in `not_read`.
  - **Software copied into the project** (`depaudit.run_copied_audit`, tool `copied-audit`): what lies under a folder
    named `vendor` is named. A copy that brings a `package.json` with a name and one exact version is looked up
    through OSV by that name and version, and a known problem is a finding at that file's `version` line; files with
    no name and version are counted and cannot be looked up; offline the lookup is skipped. In each case the release
    decision's `dependencies` criterion is `missing` where it used to say the project lists no libraries, and the
    Evidence Limits name the copies. Only the name and the version leave Lantern. A package manager's own `vendor`
    folder (Composer, Go modules, Bundler) is not a copy, and neither is one kept for the tests or inside a sample
    app, nor what a Python environment named `env` holds. Where a `vendor` folder is deeper or larger than Lantern
    looks into, the record and the Limits say that part of it was not looked at.
  - Found while checking the new lines one by one: a wildcard in a command (`tar cf out.tar *`, Bandit B609, high) was
    ranked `low` with the words "only fixed text reaches this line … nothing that comes from outside is put into
    it", in any Python file. The shell fills the `*` in with the names of the files it finds, and a file's name can
    be an option. Fixed text no longer lowers that finding (`flow_rules.FILLED_BY_THE_SHELL`); the same command
    with no wildcard is still lowered (`tests/test_flow.py`, two cases).
  - The Evidence Limits said "Python built-in calls" about a project with no Python on the map; they say "built-in
    calls (the language's own functions)".
  - Tests: `tests/test_headers.py` (45 cases) and `tests/test_unread.py` (38), every wrong answer beside a twin that
    must read as before. Run against the code before, 17 of the first 30 header cases and 30 of the first 30 of the
    other file fail. Not done: the map
    still does not read renamed code, a copy outside a folder named `vendor` is not found, and nothing here runs the
    site (see Known gaps in `CLAUDE.md`).
- A terminal you pull up from the bottom of every screen, in the app and on the website (2026-11-12; design 5a/5b,
  which until now was a drawer reached only from a button on an open project's bar or the ` key, and was missing
  from the website). A "Terminal" tab sits at the bottom middle of every screen: a click or a drag up pulls the
  drawer up, its top edge sets the height (drag, or the arrow keys; kept in the browser as `lantern.termh`;
  half the screen on a phone), a drag down or Esc closes it, and ` (Ctrl+` from inside a text box) opens and closes
  it from anywhere. The drawer is the app's own code; `lantern_cloud/site.py` takes it into the website whole. In
  the app it now works before a project is open (`projects`, `open NAME|NUMBER`). On the website each command does
  what a button does, through the same request: `runs`, `open`, `check LINK` (map and findings only; snippets need
  `--snippets --agree`, the tick box's words), `samples`, `sample ID`, `status`, `findings [rank]` (ids are links to
  the finding in the report), `explain`, `share` and `delete` (both open the same window the button opens, which
  asks first), `ask QUESTION`; `clear`, `history` and `exit` on both. It never runs a shell or anybody's code, the
  server gets no new route, and every line printed goes through `esc()`. `tools/viewer_smoke.js` drags the tab up on
  the home screen and opens a project from it; `tools/cloud_site_smoke.js` runs the website's commands on the
  poisoned demo and follows a finding's link.
- How to use Lantern from every page (2026-11-12). Until now only screens with the main menu linked to the guide. A
  project's screens in the app and a run's screens on the website hide that menu, so the guide button now sits in
  their top bar beside Simple/Advanced. A report or an Evidence Report open on its own (a new tab, a shared link, a
  file on disk) has the link in its top bar too: `/guide` when Lantern serves the page, the website's guide
  otherwise (a plain link, so a report from disk still fetches nothing); inside the app or the website it stays
  hidden, because the bar around it has the button. The website's notice pages (expired link, sharing off), the
  local app's "open the link from your terminal" page, every sign-in page of the free allowance and the public
  landing page (menu and footer; "Guide" on phones and tablets so the menu fits) link to it as well.
  `tests/test_guide.py::test_every_page_reaches_the_guide` fails if one of them loses it.
- Code nested very deep no longer stops the check (2026-11-13). The readers go through code by calling themselves
  once per level of nesting, and Python ends a program about a thousand levels deep. One such piece anywhere in a
  project, a chain of some hundred calls, a sum of a thousand pieces, an `else if` ladder, brackets inside brackets,
  functions or classes written inside each other, ended `lantern analyze` with `maximum recursion depth exceeded`
  and no result at all. Measured with eleven such shapes in each of the thirteen kinds of source file, every case a
  project of its own: 69 of the 136 cases stopped the check, in 12 of the 13 kinds (Dart was the one that read them
  all). Now 0 stop. A reader leaves the piece it cannot follow, one statement or one place, reads everything around
  it, and the piece is written down: `graph.json` `meta.too_deep` (how many, in which files, the line each of the
  first 40 begins at), a `deep` line in the log and a line in the Evidence Report's Limits. In the 136 cases, 68
  deep files are named as not read to the end, with the functions before and after the piece and the calls around
  it on the map, and 68 are read whole; a route that hands the request to a shell in the same project is reported
  as critical in every one. What a reader knew about a name is not used after an unread piece that writes that
  name, so no link below it is a guess shown as a fact. Where a reader has no single piece to leave, the file is
  named (`deep.whole`), and where it has no net of its own the reader is named as stopped and the other readers go
  on (`engine._part`). It is said, not judged: no finding, rank, score or release decision changes for it. New
  `lantern/deep.py`. The recursion limit is not raised, which would trade the stop for a crash of Python itself.
  Three readers were also slow on long lines and are not any more: **Ruby** asked tree-sitter for the parent of
  every name, which costs a walk from the top of the file each time (one line of 20,000 chained calls 40.39
  seconds, now 1.09; 100,000 calls were not read after four minutes and take 1.3 seconds); **PHP** worked out every
  call of a chain anew for each call above it (400 links 2.12 seconds, now 0.04; forty functions with a chain of
  300 links each 37.6 seconds, now 0.85), with the links and the counts of unplaced calls of 16 written shapes of
  chain exactly as they were; **C and C++** asked for a parent the same way. Tests first: `tests/test_nested.py`
  (111 tests) and two new ones in `tests/test_chains.py`; on the code before, 104 of the 133 fail. Nothing changes
  for ordinary code: the map built before and after is the same, byte for byte, for the 15 sample projects and for
  five public apps at a fixed commit (Django, Laravel's framework, Hugo, Excalidraw, ripgrep: 89,201 nodes and
  241,697 links together), and nothing is written down as too deep in any of them. Found with the
  same measurements and not fixed (`CLAUDE.md`, Known gaps): the Dart grammar's own parser takes far longer than
  the file grows on a type written inside itself several thousand levels deep (10,000 levels 66.33 seconds, spent
  before Lantern's reader sees the file, and the same before this change), and most readers follow a method only a
  few classes up a family of classes.
- No line of a project keeps the check busy (2026-11-13). Three faults of one kind, all in Lantern for some time,
  found while checking the fixes for a report on a real static site. **C#:** a line that chains calls, each on what
  the one before gave (`sb.Append(a).Append(b)…`, a query, a builder), doubled the reading time with every call
  after a library call: 20 chained calls 5.21 seconds, 30 still being read after 150 seconds. Real C# code holds
  such lines, so a real app could keep the check busy for hours. Each link is now worked out once (200 chained
  calls: the whole check in 0.45 seconds). **Ruby:** every call of a chain went down the whole chain again; twice the
  links took eight times the time (800 links 26.42 seconds, now 0.43), and at 1,500 links the check stopped with
  an error where it now ends. Short chains of every shape the two readers tell apart give the links and the counts
  they gave before (`tests/test_chains.py`, 20 tests; every one of the twelve readers is also given a chain of sixty
  calls; 5 of the 20 fail on the code before, each at its time limit). **Strings:** one line, a quote mark followed by about thirty pairs of
  backslashes and no closing quote, in a comment or anywhere else of a Python, JavaScript, PHP or other source file,
  kept `lantern analyze` running for days: four places found string literals with one pattern that had two ways
  through a backslash, and it tried every way of pairing them (measured: 18 pairs 2.706 seconds, 20 pairs 18.861
  seconds, about 2.6 times the time for each pair more). A small project with such a line was still being checked
  after three minutes; it now ends in under a second and reports the same finding below the line. Two patterns
  beside it took four times the time for twice the text (60,000 characters of `/* ` that nothing closes 5.28 seconds;
  a JavaScript template of 40,001 characters that does not end 4.87 seconds). New `lantern/strings.py` finds the same
  strings, templates and comments, match for match, in time that grows with the text (a million pairs of backslashes
  0.3957 seconds); `websec.code_only`, `security._statements`, `security._php_line` and `aiapp` use it. No result
  changes: `tests/test_strings.py` keeps the old patterns and compares them with the new functions on 1,716,498
  short texts, on longer ones made at random, on Lantern's own code and on written cases; each place is run on such
  text in a child process with a time limit (8 of these tests fail on the code before, 6 of them at their 30-second
  limit), and a test fails if a module finds strings the old way again. Found while checking the fixes for a report
  on a real static site; the fault was in Lantern before them. Other patterns that read strings were measured and
  left as they are (they are slow only on megabytes of text made for it): `CLAUDE.md`, Known gaps. Found by the same
  look: one expression nested several hundred levels deep (a chain of 400 to 1,500 calls, a sum of 1,200 pieces)
  stopped the whole check with `maximum recursion depth exceeded` in most readers; that is the entry above.
- Faster, with every check and every result as it was (2026-11-12; point 10 of the 2026-11-09 directive, "Increase
  performance without dropping checks"). Measured first, then changed: `bench/speed.py` analyzes the sample shop and
  five public apps at a fixed commit each, three first runs and three repeat runs a side, the unchanged engine and
  this one back to back on one machine. On Django (481,021 lines) a first run takes 52.05 s where it took
  115.72 s and a repeat run 41.03 s where it took 113.84 s; on Laravel's framework (415,998 lines)
  19.38 s where it took 37.83 s and 18.50 s where it took 37.53 s. Django's report is
  38,050,642 bytes where it was 73,896,338 and opens on a slowed phone in 3548 ms where it took
  4951 ms. **No result changes.** For all six projects every result file both engines write
  (`graph.json`, `calls.json`, `security.json`, `readiness.json`, `baseline.json`, the badge) is the same, the
  times aside, and so is everything the report holds; no file is read less and no check is left out. Every number,
  what was tried and dropped, and what is still slow: `bench/speed_results.md`.
  - **One look at the folder for a run** (`lantern/listing.py`). The web rules walked the whole project once per
    language, the packs once per rule and per manifest name, the dependency audits twelve times, the secret
    patterns once more. Inside a run the folder is now walked once and the list is shared (`listing.files`,
    `listing.once`); every reader still opens a file through `project_text`, which asks again at that moment
    whether the file is the project's own. After the project's own tests have run in its folder the list is
    looked up anew (`listing.fresh`). Outside a run nothing is kept.
  - **Scanners beside the map** (`security.Early`). Bandit, the dependency audits and gitleaks read the project's
    files and nothing of the map, and were started only when the map was finished. They now start with the run
    and work beside the reading of the code, up to two at a time and none where the computer has one processor
    (`LANTERN_JOBS`: 0 runs one after another as before, 8 at most); `scan` takes what each gave at the place and
    in the order it always did, so findings and records are the same either way. A run that fails or is stopped
    ends every helper program with everything it started (`remote.end_for`).
  - **Work kept between runs** (`lantern/kept.py`; `lantern cache`, `lantern cache --clear`). How a Python file
    read, and what Bandit printed for a set of files, is kept in `LANTERN_HOME/cache`: never in the project or its
    results, folders 0700 and files 0600, 1 GB at most (`LANTERN_CACHE_MB`), an entry nobody asked for in 30 days
    removed. An entry is found only under one SHA-256 of the whole question: the bytes of the file and the name it
    is read under, and one digest of every file of Lantern's own code, the Python that runs it and the libraries
    that do the work (for Bandit also the folder, the exclusions and the installed plug-ins). Change any of them
    and the work is done anew. An entry that is cut short, another question's, another user's, a link, or of a
    shape Lantern does not write is no entry. `LANTERN_CACHE=off` runs without it; `lantern verify` and the hosted
    service never use it. What Lantern makes of the kept readings (links, findings, ranks, the score) is worked
    out in every run. `run.json` says how much was reused (`kept`), and the run's log has a `kept` line.
  - **A quick look before line patterns** (`lantern/quick.py`). The paid-API patterns, the secret patterns and the
    rules of a pack were tried on every line of every file: 14 million searches for Django by the paid-API
    patterns alone. `quick.needs(rx)` reads a pattern with Python's own pattern parser and names pieces of plain
    text of which every match holds at least one; a file that holds none of them has no line the pattern can
    match, and that pattern is left out for that file. Where it cannot tell, the pattern is tried as before.
  - **Tables where a list was gone through for every question**: the functions a pack's registration line names
    (`packs._handlers`; every such line went through every node of the map, 446 times on Django), the methods of a
    PHP class and the functions of a PHP file, the classes below a class
    (`Resolver.subclasses`), the readiness searches (one reading of a file's name and words, not one per search),
    the words of a name (`websec.segments`). The saved map is written field by field (`graph.node_dict`,
    `edge_dict`) where `dataclasses.asdict` copied every text: 2.2 million calls for Laravel, twice a run. While a
    map is built the full passes of Python's memory collector wait (`engine.building`): 6 of the 26 seconds of
    Django's map, with the same peak memory.
  - **The map column by column inside the report** (`lantern/columns.py`). Most of a large report was the map,
    every node and link written as a table with the name of every field in it. The report now holds the same map
    by columns, with each repeated value written once and each link naming its two functions by their place in
    the list; the page turns it back into the same rows before anything looks at it (`unpackGraph`), and so does
    `report.read_bundle`, so nothing else knows. `graph.json` and every other result file are written as before.
    A packed map of any other shape is refused by the page and by Python (39 hand-made ones in the tests). A
    report written by an older Lantern is still read.
  - **`bench/speed.py`**: the measurement and the proof. Three first runs and three repeat runs of each project,
    one repeat run with kept work off, one first run on kept work; one SHA-256 per result file with only what a
    clock put into it taken out; `--engine` measures another checkout, `--compare … --must-match` fails when a
    result differs from that engine's; `--browser` opens each report on a slowed phone.
  - Not gained, said plainly: a first run of the 12-file sample is slower, 0.74 s where it took 0.63 s (a run now pays
    about a tenth of a second for the digests kept work is found under). Work is kept only for the Python reader
    and Bandit, so a repeat run of a project without Python takes what its first run takes (Laravel 18.50 s and
    19.38 s), and one edited Python file has Bandit read every file again (Django 45.40 s, against 39.52 s with
    nothing changed). The taps inside an open report are as fast as before, not faster (Django's findings tab
    1819 ms on a slowed phone, 1841 ms before). Memory counted with every program a run starts is 2 to 8 MB
    higher on the four smaller projects, because the scanners now work beside the reader. The hosted service
    keeps nothing, so every run there is a first run. A computer with one processor, Windows and macOS were not
    measured.

- The Atlas says where you are, and the Graph and the Flowchart have a minimap (2026-11-12). Above the map a
  breadcrumb runs from the project to the view, the starting point and, along the shortest path of calls, the
  function you chose; each step is a button that brings that function to the middle of the map, a path of more than
  five steps folds its middle into "N more", and a function the starting point does not reach stands after a gap.
  The minimap is a copy of the map's own boxes and lines with a box for what the screen shows; a click or a drag on
  it moves there. It can be shown at 100%, 60% or 30% or hidden (the M key too), and the choice is kept in the
  browser (`lantern.minimap`). Its drawing is copied attribute by attribute from the map Lantern drew, never from
  the data as text. `tools/viewer_smoke.js` checks the breadcrumb, the three settings, hiding and a click.

- The release decision: Blocked, Incomplete or Passed, and a score that cannot speak over it (2026-11-11; point 6
  of the 2026-11-09 directive, "Fix severity and make 100 mean the required work passed"). Three things were wrong
  until now. A finding was ranked lower when Lantern found no path to its line. A check that was skipped left the
  sum, so tests that were never run cost nothing. And the one number, an average over ten categories, was all there
  was to say whether a project can ship. **This changes what an existing project sees, on purpose: scores go down
  where required work was skipped, a badge that was green may now say "blocked" or "incomplete", some findings
  rise by one rank, and lines that carry a `# nosec` comment appear in the results for the first time.**
  - **A path Lantern did not find lowers nothing.** `security._steps`: the rank starts at the tool's own severity
    (`FLOOR`) and who reaches the line can only raise it. Until now a high with no path was ranked medium and a
    medium low, "because nothing in the map reaches it"; a scheduler, another program, a framework that calls by
    name or a call Lantern could not follow would not show on the map. A rank goes under the tool's severity only
    on evidence written on the finding (`rank_note` with `rank_before_context`: a weak hash used as an identifier,
    SQL that splices only fixed text, a function every caller hands fixed text), for test code, or where a rule
    fixes its rank. Every finding now carries the facts apart: `tool_severity` and `tool_confidence` as before,
    `reachability` (`{state, kind?, why}`; `reached`, `tests-only`, `unknown`, `not-code`; `unknown` is never read
    as "nothing runs it") and `rank_basis` (the steps to the rank, each `{step, rank, why}`: `severity`, `raised`,
    `lowered`, `fixed`, `test-code`). The case, the scenario, the connector's note and the SARIF message say "no
    path was found, which is not proof that nothing runs it" where they said "nothing reaches it" or "nobody can
    do this yet", and the case's condition "Someone outside can reach this code" is not known (`null`) where it
    was `false`. On Lantern's 15 sample apps five findings rise from low to medium for this reason (two on the
    Android sample, one on the PHP sample, two on the Ruby sample); no finding fell.
  - **Test code by what runs it, not by its name alone.** A file named like a test, one function of which a page,
    route or command outside the test files runs through links Lantern worked out, is the app's own code
    (`test_file_in_use`): its findings are ranked and counted like any other. A guess by method name, or one of
    several classes that have the method, is no evidence of who runs a file (a test double has the methods of what
    it stands in for): such a file stays test code and the finding says a guess leads there (`test_file_guessed`).
  - **A `# nosec` comment hides nothing.** `# nosec` is Bandit's own switch: a comment that tells it to skip a
    line, and it comes with the project like the code. Lantern ran Bandit as it comes, so such a line was listed
    nowhere: no finding, no count, no word on the Evidence page. Bandit is now started with `--ignore-nosec` and
    Lantern reads the comment itself (`security.nosec_says`, comments taken from Python's own reading of the file,
    so the words inside a text are none). A comment with a written reason, on a line Lantern followed no request
    data to, counts as a risk the project accepted, exactly like `lantern accept`: listed, counted apart, its rank
    as it was, the reason beside it (`status: accepted`, `accepted.how: "nosec"`, `nosec.state: "accepted"`; the
    Evidence page says "Accepted in the code (a # nosec comment on the line)", SARIF says `inSource`). A comment
    with no reason accepts nothing (`bare`), and neither does one on a line Lantern followed request data to
    (`overruled`): both stay open at their rank and the finding says so. A comment that names other checks only
    is not about the finding. Lantern's own code had 28 such lines; each now carries its reason.
  - **The release decision** (`lantern/release.py`, in `readiness.json` as `release`). `Blocked`: a required
    criterion failed (a critical or high finding is open outside test code, the project's tests failed, a
    behaviour check came out broken). `Incomplete`: nothing failed and something required is missing (a scanner
    did not finish or did not cover everything, libraries were not checked, the tests were not run, the behaviour
    plan was not run on this code). `Passed`: every required criterion that applies to this kind of project has
    passed. Five criteria, each `passed`, `failed`, `missing` or `not-applicable` with its reason and what to do:
    `findings`, `scanners` and `tests` for every project, `dependencies` where the project lists libraries,
    `behaviour` where it brings a plan (`lantern-behaviour.json`). What the profile does not ask for is named with
    the reason (`profile.not_required`), so Passed does not read as more than it is. Tests that were not run, that
    the sandbox could not run, or that the project does not have are `missing`, never passed; tests that ended
    with an error are `failed`, except where the sandbox refused something they tried (that may be the sandbox,
    so it is `missing`).
  - **The score cannot speak over the decision.** `checklist` is the weighted average as before; `score` is that
    number held at 59 (the top of grade F) while the release is Blocked and under 100 until it is Passed
    (`release.score`), so a critical issue is not averaged away by unrelated points and 100 is for a passed
    release with complete evidence. A check the release needs that was skipped because the work was not done
    (`required: true` on the check: the tests were not run, listed libraries were not looked up) keeps its points
    in the sum and earns none (`readiness.counts`); any other skipped check leaves the sum as before.
    `readiness.json` is `version` 2. On the 15 sample apps the score falls by between 0 and 6 points for this
    reason (the Kotlin sample 46 to 40), and every one of them reads Blocked.
  - **Tied to what was tested** (`release.bind` → `release.bound_to`): the commit and whether files differ from
    it; one SHA-256 over every file of the project, by path and content (`code`: `files`, `sha256`, `not_read`,
    and in words which folders no reader looks into); one for each file that lists libraries and one over all of
    them (`dependencies`); the settings of the run (scan on or off, the test command, offline, where it was made,
    packs switched off, the SHA-256 of `lantern-accepted.json` and of the behaviour plan); every tool with its
    version and how its run ended; Lantern, Python and the system. The Evidence digest takes the decision, each
    criterion's state and those SHA-256s in (`evidence._release_part`), so `lantern verify` fails when any of
    them differs. A report an older Lantern made has no decision and its digest is what it was.
  - **A behaviour record counts only when it is of this code** (`lantern/seal.py`). `behaviour.json` lies in the
    results folder, which usually lies in the project, so a project could bring one that says every check held.
    `lantern behave` now writes the SHA-256 of the code it started the app from (`of.code_sha256`) and this
    computer's seal (`seal`: an HMAC-SHA256 under a key made on first use, `LANTERN_HOME/seal.key`, readable by
    its owner only). The release decision counts a record only when the seal holds and the plan and the code are
    the ones in the project now; otherwise `behaviour` is `missing` with the reason. The seal says which Lantern
    made the record, not that the record is right, and whoever can read `LANTERN_HOME` can make one.
  - **Libraries that could not be looked up are said.** A `package.json`, `composer.json` or `Gemfile` with no
    lock file beside it names libraries whose versions nobody knows: the audit's record counts them (`unlocked`,
    the first five in `unlocked_examples`) and names the folders whose versions are in a pnpm, yarn or bun lock
    file Lantern does not read yet (`other_locks`); a `package.json` that names nothing that ships is "skipped:
    no package.json names a library that ships" and no gap. The readiness check `dependencies` earns nothing for
    them, the Evidence Limits say how many, and `dependencies` is `missing`. So is it for the kinds of project
    Lantern has no library check for yet (`release.NO_AUDIT`: Go, Rust, Dart and Flutter, .NET, Swift, C and C++).
  - **Where it shows.** The report's readiness page (a box above the score: the word, why, each criterion with
    its state in words, what the decision is tied to); the app's project cards, list and CSV, and the website's
    run cards (`release` in a run's summary); the Evidence page's Scorecard (the decision, the criteria, the
    profile, "What this decision is tied to") and its Limits; `evidence.json` (`release`, `scorecard.checklist`);
    the badge, which is green only for a release that Passed and otherwise ends in "blocked" or "incomplete";
    `lantern analyze` (a `release` line in the log, and `--require not-blocked|passed` for CI: exit 1 unless this
    run's own decision is good enough, never one read back from the results folder); the connector
    (`lantern_readiness` returns `release` and `checklist`, `lantern_projects` names the decision); Ask Lantern's
    facts. A decision read back from a file is taken as one of the three words with bounded plain text beside it,
    and what blocks and what is missing is worked out anew from the criteria (`release.shown`); the one-command
    audit poisons the box (`tools/audit.sh`).
  - **Lantern's check of itself** (`tools/self_readiness.py`, CI) now fails on a release decision of Blocked, on
    Incomplete for anything but the tests (that step reads the code and never runs the tests, which CI's test
    jobs do: `ALLOWED_MISSING`, by name), and on a required check that was skipped and is not in `ALLOWED_SKIP`.
  - **Three checks the code makes are now read as checks** (`lantern/flow.py`; each written after a false alarm
    or a miss on a benchmark, against examples of its own). A payment webhook that checks who sent the message
    before it spends is not "a route anyone can call" (`Engine.sender_checked`, `flow_rules.SENDER_VERIFIES`;
    `flowscan._senders` drops `LA-WALLET-DRAIN` there only when nothing is paid for before the check; record
    `scope.sender_checked`). Text a request wrote into a file that is read back and run as a template is one flow
    from the request to the line that runs it, by way of the write and the read (`Engine.stored`, `read_back`,
    `read_back_flows`, `same_place`: that the two files are one is read from the paths' fixed words, so the flow
    is a guess, `LOW`, ranked medium; the text read back is followed into a larger text, `"<main>" + text`, an
    f-string or template literal, `%`, `format` (`flow.read_of`, `flow_rules.READ_INTO`), and into a helper that
    runs what it is handed, on the helper's line (`Engine.ran`), not through a `replace`, which may be the code
    taking a template's own marks out). A check made on a whole list at once narrows every item of the list
    (`Engine.each_facts`: Python `any(...)` / `all(...)` over a generator, JavaScript `some` / `every` with a
    function written in the call; `zip(a, b)` pairs keep each list's own items; a JavaScript `map` gives what its
    function gave back; the same check written as a loop of its own before the loop that uses the items,
    `Engine.loop_facts`, only where every item gets to the check and none gets past a failed one; the safe app of
    `bench/behaviour/` had two `LT-PATH` findings at high for want of it and has no finding now; the six planted
    versions the reading told apart from it are still told apart, and a seventh with them, `zip-entry-escapes`,
    where those two findings now stand alone). Tests: `tests/test_webhook_sender.py`, `tests/test_stored_file.py`,
    `tests/test_list_guard.py`, each dangerous shape beside safe twins and look-alikes.
  - **Measured on the held-out benchmark** (`bench/heldout/`, same definition, targets written down before the
    run): 55 of 79 documented problems found at medium or above offline (54 before), none found only as low (1
    before), no false alarm on the 17 safe twins, no vulnerable app reads Passed (8 of 8 read Blocked) and no app
    scores 100. **Two targets were missed and are kept as missed:** one of the six clean apps reads Blocked
    (fastapi-template, through one false alarm ranked high that Lantern has no evidence to lower), and `pg-ssti`
    is still not found where the benchmark documents it (Lantern lists the problem 13 lines above, where the text
    is saved; the app shows the saved file by its name and never reads it back to run it, so the new stored-file
    rule does not fire there). The other five clean apps read Incomplete, each for the same two reasons: their
    libraries were not all checked and their tests were not run by the benchmark.
  - Tests: `tests/test_severity.py`, `tests/test_nosec.py`, `tests/test_release.py` (each downgrade and each
    decision beside its deceptive near-miss: a comment that says the command is fixed on a line the request
    reaches; a behaviour record with the right words and no seal, of another plan, of other code; a results folder
    that brings its own `readiness.json`; a skipped required test; 100 points of checklist with a failed test).
  - Not done here, and said where it matters: the cloud service never runs a project's tests, so a run on the
    website reads Incomplete at best; a project in Go, Rust, Dart, .NET, Swift or C/C++ that lists libraries
    reads Incomplete until Lantern can check them; "fixed" on the Evidence page still means only that a finding
    of the baseline is no longer reported, not that anybody showed it fixed.
- Behaviour checks: `lantern behave PATH` starts the project's app in the test sandbox and tests what really
  happens (2026-11-11; point 5 of the 2026-11-09 directive, "Test full-stack behavior, not just source patterns").
  Until now everything Lantern said about a project came from reading it. A project can now carry a plan,
  `lantern-behaviour.json`: how the app is loaded and set up, who the people are, and checks of twelve kinds
  (`refuse`, `hide`, `tokens`, `input`, `keeps`, `contain`, `redirect`, `address`, `limit`, `once`, `retry`,
  `faults`). The runner (`lantern/behave.py` outside, `lantern/_behave_inside.py` inside the sandbox) starts the app
  on a read-only copy with no network, hands it each request inside one process over a pipe (the app is served at
  no address), and compares the database's rows and the app's files before and after every step.
  **A refused request that changed something all the same is a failure of its own kind** (`refused-but-changed`),
  whatever the answer said. A refusal counts only beside the same request from somebody who may make it, which must
  work and, for a request that changes things, must change something: otherwise the case is `inconclusive`, never
  `held`; a case that could not be run is `not-run`, never `held`. Sign-in tokens are tried missing, empty,
  garbage, cut short, altered, unsigned, signed with another key and expired. A request is made to fail at each of
  its database writes and commits and is cut off before each of them and before the answer leaves; afterwards all
  of its work must be there or none, and the next person's request must work and save only its own. A limit on
  tries is asked straight after, after a restart and on a second copy of the app; two requests at the same moment
  must end as one after the other does; the same request sent again must not be done twice. Where a name leads is
  answered by the runner itself, so no question leaves the sandbox, and an app that looks a name up and refuses is
  told from one that sets out for the address. **A plan cannot be pointed at a live site**: it holds paths only (an
  address or a `Host` header in a request is refused before anything starts), the app's database files and folders
  must lie in the folder the sandbox gives it, and SQL of the plan's own is run only on a database the plan names
  there. The record is `behaviour.json` (`docs/api.md`), with `of`: the plan's SHA-256, the commit and whether files
  differed from it, Lantern's version, Python and the system. The command ends with 0 only when every case held.
  Nothing else reads the record yet: no finding, score or page changes with it (point 6 is where it is bound).
  Guide: `docs/behaviour.md`.
  Measured on throw-away apps only (`bench/behaviour/`, `python bench/behaviour/run_behaviour.py WORKDIR`;
  `bench/behaviour/results.md` is the last run). Corkboard is a small notes app for teams (FastAPI, SQLite, PyJWT)
  written by a generator as the safe app or with one of 31 problems planted, each differing from the safe app in
  the pieces its problem names and in nothing else (`tests/test_behaviour_apps.py`): no login; another person's
  and another team's notes read, changed, deleted, listed and exported; a member and another team's admin removing
  a user; a delete that is refused after the note is gone; an expired, an unsigned and a wrongly scoped token; a
  role taken through the profile form; a negative amount; a request of megabytes; an upload's and a zip entry's
  name leaving the folder; an uploaded page served as a page; a zip that unpacks to megabytes; a redirect to any
  site and a half-checked one; a preview that fetches internal addresses and one whose check misses other
  spellings; no limit on wrong passwords and a limit kept in memory; a coupon redeemed twice at once; a transfer
  that keeps its first half after a database error, after being cut off, when sent again, and whose half is saved
  by the next person's request. The plan (40 checks, 97 cases asked, 80 outcomes on the safe app) and the cases
  each planted problem must break (`plan.EXPECTED`) were written down before the first run. First pass: 27 of 31
  planted versions came out as written down. The 4 that differed: one mistake in the table (`export-every-team`
  takes away the control of one case, which then comes out undecided); two versions (`fetch-any-address`,
  `fetch-half-checked`) that met one fault of the runner (on a computer with no IPv6 an app's try for an IPv6
  address ends one step before the connection the sandbox refuses, and the runner saw nothing); and
  `unsigned-token`, whose case "cut short" came out held and was taken for a second mistake in the table until a
  second run gave the other answer: the runner cut the token at a place where the token library read the rest as
  whole on one run and not on the next. While the first fault was being fixed a test for the safe twin showed one
  more: an app that only asked where a name leads, and refused, was reported like one that went there. After the fixes, with the whole plan run
  against every version: 32 of 32 as written down (each planted problem broken in its own cases and in no other;
  the safe app 80 held, 0 broken), 0 attempts to reach anything outside this computer (`tools/netguard`). The safe
  app's whole plan takes about 25 seconds (58 starts of the app); the first measurement was 66.9 seconds, over the
  60 set beforehand, until the app's copies were let keep compiled Python in their temp folder.
  Two apps that were not written for it (`tests/test_behave.py`): Lantern's own gateway, copied as it is (an app
  made by a function, set up from the environment): 12 cases held, and the one that must come out broken did (a
  chat request with no site listed: the gateway asked for `api.anthropic.com`, was answered inside the sandbox and
  refused at the connection). Tried by hand and not kept as a test, because the gateway counts by the minute
  of the real clock: after five wrong owner secrets the sixth is not looked at, and the count is forgotten at a
  restart and on a second copy (it is kept in memory, as `gateway/README.md` says). The shop sample
  (`tests/fixtures/shop`), whose backup route `lantern analyze` reports as a command built from the request: the
  request was sent and the file it named was found where it said (`outside-file`, `saw.outside`). These two showed
  three more faults, fixed with tests first: an app made by a function could not be started (`"factory": true`), a
  word for a token variant that this version does not know came out as a case that was not run (now refused before
  the run), and an outcome did not name the file that was written outside the app's folders.
  Not in this step: only Python ASGI apps with SQLite as the database are started; a JavaScript app is not; the
  report, the Evidence Report and the readiness score do not read the record; no app is started on Windows (two
  entries down); macOS has fewer walls around the app than Linux; an app that sets out for an address through code
  below Python (a client or an event loop written in C) is stopped by the kernel on Linux but not seen, so that
  case can come out held (`docs/behaviour.md`, Limits).
- Fixed, test sandbox ("Watch my tests run"): three defects of the Python guard that the behaviour runner's first
  runs showed (2026-11-11; all three in every release so far; each fixed after a test that failed). **A name given
  beside an open folder** (`os.unlink(name, dir_fd=fd)`, the way `shutil.rmtree` and `tempfile.TemporaryDirectory`
  remove a tree) was read as a name in the current folder, the project's read-only copy: every test that removes a
  folder tree in its own temp folder failed in the sandbox and was listed as a refused write. Such a name is now
  read in the folder it was given beside (`_at`, `_full`, `_PATHS` in `sandbox.SITECUSTOMIZE`), and an open folder
  the guard cannot place is refused. **A question about a name asked the older ways** (`socket.gethostbyname`,
  `gethostbyname_ex`, `gethostbyaddr`) went to the real resolver, while `getaddrinfo` was refused; all four are
  refused and reported now, and this computer under its own names is answered. **A database file**: SQLite opens
  and writes its files itself, below Python, so the guard never saw them, and where no kernel layer stands behind
  it (macOS, Windows, a Linux kernel without Landlock) a test could change a database file outside its temp
  folder; `sqlite3.connect` on a file outside the temp folder is now refused and reported unless the file is there
  and cannot be changed (a fixture database in the project's copy is still read), and a database in memory is no
  file. Not covered: `os.open(name, flags, dir_fd=fd)` for writing (its event carries no folder), and code inside
  the process that is not Python (a C extension other than SQLite, `ctypes`), which the guard cannot see and only
  Landlock holds. Tests: `tests/test_sandbox.py` (each refusal beside the ordinary use that must keep working).
- Found and not fixed, test sandbox on Windows (2026-11-11): a test that starts an event loop (an async test, a
  test of a FastAPI or Starlette app through its test client) fails in the sandbox there. Windows has no call that
  makes a pair of connected sockets, so Python builds the pair every event loop wakes itself with from a listener
  on this computer and a connection to it, and the guard refuses the listener (seen on Linux by handing Python the
  Windows way of making the pair; `tests/test_sandbox.py` says it on Windows itself, in CI's Windows job). A change
  that let a program reach a listener of its own was written, tested and taken out again before it was pushed: the
  event loop Windows uses by default makes its connections with a call for which Python reports no
  `socket.connect` event (ConnectEx; Python's table of audit events), so a loop that could start could connect to
  an address written as numbers with the guard seeing nothing. Until the guard covers those connections, such
  tests fail on Windows as before, and `lantern behave` starts no app there (`sandbox.NO_APPS`: the command says
  why and ends with 3).
- Security: a value that arrives with a request is followed across functions and files to where it does something
  sensitive, a check counts for what its code proves, and who may reach a record is asked (2026-11-11; point 4 of the
  2026-11-09 directive, "Trace actual security problems across the whole app"; Python and JavaScript/TypeScript, the
  other languages keep the one-function reading). Until now "uses input" was read inside one function, in the order
  the lines are written. A route that hands the request's text to a helper, which hands it to a service, which
  builds the query, was listed (when a pattern matched the query) with no sign that a visitor chooses the text; a
  function called `validate`, or `html.escape` in front of a query, was not told from a real check; and a
  rate-limiting library that was only installed read as a protection "in place".
  Follow the data (`lantern/flow.py`, `flow_py.py`, `flow_js.py`, `flow_rules.py`, `flowscan.py`): both readers put
  a file into one small language, so the engine is written once, and nothing of the project is run. A value carries
  where it came from, for each kind of action whether it was made safe for that action (`html.escape` is safe for a
  page and for nothing else, `int()` for everything), its leading fixed text (`"https://api.example.com/" + name`
  does not choose the host) and whether the text reads like SQL. Every function gets a summary (which parameters
  reach its return value, which reach a sensitive action in it or below it, what its checks prove), callees before
  callers. A check narrows a value only in the branch that passed it and only before the action; what it proves is
  read from its code (a look-up in a list the request did not write, a pattern that bounds the whole value, a
  resolved path that starts with the folder, a host on a list), so a function is a validator for what its body
  proves, whatever it is called. What a constructor keeps is on the object and read back out of it, field by field;
  a request body that FastAPI hands over as an object of a class of the project is the request's, field by field.
  Flows become findings `LT-SQL`, `LT-SHELL`, `LT-EVAL`, `LT-DESERIALIZE`, `LT-XXE`, `LT-PATH`, `LT-SSRF`, `LT-XSS`,
  `LT-REDIRECT`, `LT-NOSQL` and `LT-POLLUTION`, each with every step (file, line, a sentence); a flow that ends on a
  line another tool flagged for the same kind of problem is attached to that finding instead, so one problem is one
  finding. The report shows the steps in a box "How the value gets there", every value escaped. A query or a command
  no flow reaches, where every call Lantern found hands the function fixed text, is ranked low with that reason, and
  only when the engine read every file.
  Pages and templates (`lantern/templates.py`): a place in a page template that prints a value without escaping it
  is a finding of its own, `LW-XSS-RAW`, at the template's line (EJS `<%- x %>`, Handlebars and Mustache `{{{x}}}`,
  Pug `!{x}`, Jinja, Django, Nunjucks and Twig `|safe`), ranked by what Lantern knows of the value: request data
  followed from a route into that place ranks like any flow into a page, fixed text or an escaped value wherever the
  page is shown ranks low, anything else is medium, and the reason is said in a sentence. Text of the request that
  is run as a template (`Template(text)`, `from_string(text)`, or written into a file of the templates folder that
  is then shown) is `LT-EVAL`: escaping it for a page changes nothing about that. A page escaped by hand, a page
  sent as plain text and a redirect built on the request's own address (`new URL('/login', req.url)`) are not
  reported.
  Who may reach what, heuristics that say so (`tool_confidence: LOW`, ranked medium): a record reached by an id from
  the request on a route with a login where nothing compares the record with who is signed in (`LT-AUTHZ-OWNER`;
  for a record that is changed or removed only what was asked before the change counts, also when a helper makes
  the change and checks afterwards); an admin path that never asks for an admin (`LT-AUTHZ-ROLE`); everything the
  request sent written onto a stored record (`LT-AUTHZ-MASS-ASSIGN`); and a route that decides what the caller may
  do on a value the caller writes, a cookie, a header or a word in the address or the body named like a role or an
  admin flag (`LT-AUTHZ-CLIENT-ROLE`, new: `Cookie: is_admin=1` makes anybody an admin). A route with no login that
  changes or removes a record picked by an id from the request gets `LW-AUTH-MISSING` with the way to the record,
  also when nothing in the project's own frontend calls it (before, only routes the frontend calls were asked).
  Express middleware put on with `use` (`app.use(requireLogin)`, `app.use('/admin', requireAdmin)`,
  `router.use(mw)`, `app.use('/api', mw, router)`) now counts for the routes written after it and only for those
  (`entry["use"]`); the login check and the flow step read it. A page that signs a person in is not reported for
  looking them up by the name they typed, and a function that makes a token is not a sign that somebody is signed
  in. Neither is one that makes random text (Python's `secrets.token_urlsafe`, `token_hex`, `token_bytes`): for the
  check by names the word `token` in it said "login" until now, so a route that made a nonce or a new key read as
  one with a login check.
  A secret written in the code (`LW-SECRET-INLINE`): the text that signs sessions or login tokens, such a secret's
  fallback for when the setting is missing (`process.env.SESSION_SECRET || 'keyboard cat'`), the password of an
  account the app connects with, a database address that carries its password; in JS/TS, Python and JSON settings
  files, ranked medium, and the finding never repeats the text. Keys of a known format stay with the key patterns
  and gitleaks; a line they list is not listed twice.
  A library being installed is not a protection (`lantern/ratelimit.py`): "Rate limiting" reads "in place" only
  when the code shows a limit that covers the routes in question, "check" for an app-wide limit the code does not
  show covers them or for the project's own limiter in which nothing counts, else "add", naming the library that is
  installed and put to work nowhere. `LA-WALLET-DRAIN` reads the same way.
  A login is read from what the code does, whatever the function that asks is called: it counts where the route's
  code turns away whoever is not signed in. That is a check under a plain name (`restrict`), a function written in
  place (`app.use((req, res, next) => { if (!req.session.userId) return res.status(401).end(); next() })`, named
  `inline:<file>:<line>` in the route's `entry["use"]`; it adds no function, call or link to the map),
  `app.all('*', check)` and `app.all('/api/*', check)`, a Flask `before_request` hook, a FastAPI dependency,
  Passport's `req.isAuthenticated()`, and a library that is a login check and nothing else (`express-jwt`,
  `express-basic-auth` and their like, by the package; not one made with `credentialsRequired: false`, which turns
  nobody away). A caller that has to send a secret the server keeps (`req.headers['x-api-key'] !==
  process.env.API_KEY`) is the server's own caller. A login asked of some requests only is no login for the rest: a
  check in a branch other requests go round does not count, one that only leaves the sign-in page open does, and one
  that lets some verbs through (`if (req.method === 'GET') return next()`) counts for the routes of the verbs it
  asks and for no other. Where the code shows such a login, "no login check was found" (`LW-AUTH-MISSING`, said by
  the names around a route) is not said any more, counted in the record as `login_read_from_code`: before, a route
  the page calls behind a check with a plain name, one written in place or a Flask hook was listed as open to
  everybody.
  A login token is a login only where the code shows that a token which does not hold turns the request away: a
  library checks it and fails when it does not hold (`flow_rules.VERIFIES`: `jsonwebtoken.verify`, `jose.jwtVerify`
  where the answer is waited for, PyJWT's and python-jose's `decode` with a key and the check left on, Firebase's and
  Google's own), the request's own credential (a token, a key or a session id in a header or a cookie) is looked up
  among stored records, or a function every request passes through hands on only the requests that passed. The
  other way round: a failed check that is caught and after which the request goes on (`try { req.user =
  jwt.verify(t, KEY) } catch (e) {} next()`, `except JWTError: return None` in a dependency) is no login, also
  under a telling name (`authenticate`) and also for the names check, which until now took the name; a library that
  only reads a token (`jsonwebtoken.decode`, `jwt-decode`: `READS_TOKEN`; PyJWT's `decode` with no key or with the
  check switched off) is none; what a token library hands back is the caller's word about who they are, not a secret the
  server keeps, so a check that only asks whether it is there is not a role check; a library's login made optional
  (`@jwt_required(optional=True)`, `verify_jwt_in_request(optional=True)`, `@auth.login_required(optional=True)`)
  is none, unless the handler itself turns away whoever the library names nobody for (`if get_jwt_identity() is
  None: abort(401)`); and a FastAPI security scheme whose token the handler takes in and never looks at (`token:
  str = Depends(oauth2_scheme)`) only carries the token in. A route of that kind that changes data is listed
  (`LW-AUTH-MISSING`, "... and Lantern found nothing that turns away a request whose login token does not hold",
  counted in the record as `token_check_lets_on`), and the finding names what looked like a login and was not taken
  for one ("Not taken for a login check: ..."). A record reached through who is signed in counts for the route
  only where every request gets there, not after `if not token: return None`.
  A record changed through its own object: a record read by its id into an object that is then removed or saved
  (`db.session.delete(note)`, `note.delete()`, `order.deleteOne()`, `row.destroy()`, `repo.remove(order)`, a field
  set and `save()` or the session's `commit()`) is a record that is changed, with the line of the change as a step
  of the finding. Before, only the read was noted: an owner asked for after the removal was not reported as too
  late, and a route with no login that removes a record this way was not listed.
  Where an ownership finding stands: `LT-AUTHZ-OWNER` is on the line the record is reached, one finding for that
  line with the routes that get there (`routes`), because that line is where the owner has to be asked for and one
  service function five routes use is one place to fix (before: one finding per route, on the route's first
  line). A route that does ask whose the record is, but only after it changed the record, ran a command, removed a
  file or told another service to change something for it, is reported as that (`late`): "not allowed" after the
  thing was done is no check.
  How a Python app loads its own files does not matter. The engine told the project's own names from a library's
  by the dot a relative import starts with (`from .models import Note`). A record class loaded any other way was
  read as a library's value, "a library that is no database", and nothing about who may reach the record was
  asked: `from app.models import Note` (the commonest way), a flat project's `from models import Note` and
  `import models`, an app in a folder below the repository's, the file beside by its bare name in a folder that
  is a package (an app started from inside its folder), a star import (`from .models import *`), and an import
  from the top written inside the function that uses the class. Each of these is now read as the relative import
  it stands for (`flow.own_imports`, `own_dotted`, `own_module`). A star import of a file of the project brings
  what Python would bring: the names in `__all__` when it is written once as a list of text, else every name
  without a leading underscore, also through a second file that passes them on with a star (`star_names`). A name
  stays a library's where it may be one: a single name the standard library has; a longer path that starts with
  one, unless that file is there in full; the file beside in a package that does not write the name asked of it
  (`from celery import shared_task` beside `proj/celery.py`); a path two files of the project end with; and every
  name of a star import once a later star import is one Lantern cannot read. Found on 2026-11-11 with the stage
  report's own examples, not from the held-out set: every Flask example of the tests until then said
  `from .models import ...`. Of 68 new examples (the same four routes in eleven layouts; star imports and imports
  inside a function, each beside safe twins; three library look-alikes; ten on which file an import names) 43
  failed on the code before. Data that is followed to a query, a command or an outbound call was already followed
  through such imports (the map resolves the calls), and the 117 findings of the 15 sample apps are unchanged.
  Pages made in the code: a template written in the code is read like a template file
  (`render_template_string('<p>{{ bio|safe }}</p>', bio=bio)`; jinja2's own `Template(text)`, which escapes nothing
  unless it is told to), and text a helper builds is a page where a route returns it (a library's answer, `jsonify`,
  a rendered template file, a redirect, is not). An escape of the project's own counts for what its code does with
  `<`: `x.replace('<', '&lt;')`, `x.split('<').join('&lt;')`, a pattern of single characters with a function or a
  table that says what each becomes, Python's `translate` with a table that takes `<` away; one that misses it does
  not (`/<script|</g` hands the function `<script`, for which its table has nothing), and what `html.unescape`,
  `decodeURIComponent` and their like give back is as it was before the escape.
  Uploads and archives: an upload saved under a path is what that path holds, and whatever opens the file later gets
  it back; an archive library handed the upload, or the path it was saved under, gives entries whose names are the
  archive maker's, so an entry's name joined to a folder and written is `LT-PATH` (zip slip), also when the
  unpacking is a helper in another file. A path compared with the folder it must stay in counts as checked only
  where the request does not choose that folder too.
  An address that starts with a value of the server's own: a setting (`API_URL + '/items/' + id`,
  `f"http://{HOST}:{PORT}/api/{id}"`), a field an object was built with (`self.base + path`), an address out of a
  table in the code (`PROVIDERS[name]["authorize"] + "?" + query`). The host is then the server's to name, so the
  request chooses a path or a query on it and not where the server connects: no `LT-SSRF` and no `LT-REDIRECT` once
  written text has closed the host (one slash, a `?` or a `#`), also when a helper puts the start in front of a
  path the route hands it. Still reported: the request's text straight after such a value (`API_URL + x`, where
  `x` may be `.evil.example/`), a dot or an at sign after it, a start of which only the scheme is the server's,
  `urljoin(API_URL, x)`, a helper handed the request's text as it came, and for a redirect one slash with nothing
  written after it (`PREFIX + '/' + next`: where the prefix is empty that is `//evil.example`).
  An address that names no host: written text of a path at its start (`'/items/' + id`, `'items/' + id`,
  `'?q=' + q`) lets nothing after it name one, so an outbound call with it goes to the base its client was made
  with (`axios.create({ baseURL })`, `httpx.Client(base_url=...)`) or fails: no `LT-SSRF`. `urljoin(base, page)` is
  read like `new URL(page, base)`, and the parts of `x.concat(a, b)` and of a list written in a `join` call stand in
  the order written. Still reported: one slash and then the request's text (`'/' + x` is `//host`), the request's
  text as it came, parts joined with nothing or with a dot. Flask's `request.host_url`, `root_url` and `origin` are
  what the request sent (the caller writes the Host and Origin headers), so an outbound call to an address that
  starts with one of them is reported, and a redirect to the Origin header is. What a library call Lantern does
  not know gave back after the request's text went into it is nobody's for sure, so it is not taken for a value of
  the server's own either (`'https://' + normalize(host) + '/api/' + id` stays reported), whether it gets into the
  address through a field or an item of it, a call on it, `str()`, a branch, a second library call or a helper of
  the project that hands it back.
  In the browser the page's own address is this site's. The scheme, the host and the port a page was loaded from
  (`location.protocol`, `host`, `hostname`, `port`, `origin`) are not text whoever made the link wrote, and an
  address that starts with them goes to this site once the host is closed (`location.origin + '/login'`;
  `location.protocol + '//' + location.host + location.pathname`, which is read as the origin spelt out). Going to
  the page's own address again leaves the site nowhere: `location.href` as it is, with text after it, with a
  parameter set through `new URL(location.href)`, with fixed text swapped for fixed text, and without what follows
  the `#` (`location.href.split('#')[0]`: the first piece still begins as the address did). Still reported: a
  part read out of the address (the query, what follows the `#`, a later piece of a split, a parameter), the
  address's text straight after the origin, the path alone as the next page (`location.pathname` may begin with
  two slashes), the page that linked here, and the address put into the page as HTML. A swap that takes the site
  off the front of an address (`url.replace(/^https?:\/\/[^/]+/, '')`) leaves a part of it, on the server too;
  that read as the same address before and was missed. The leading text of `a + b + c + d` is read from all the
  parts in the order written, as a template's is: pair by pair the start of `proto + '//' + host + path` was lost.
  A secret under a plain name is followed from the call that signs with it (`session({ secret: config.phrase })`,
  `jwt.sign(data, PHRASE)`, `app.secret_key = config.PHRASE`) to the line that gives the name its text, in that file
  or in the file of the project it was loaded from (at most 4 lines for one name). In Python a text given to a
  name that says it signs is listed, as an assignment or as a keyword argument (`SECRET_KEY = "..."`,
  `JWT_SECRET`, `client_secret="..."`); for the names Flask and Django themselves read (`SECRET_KEY`,
  `JWT_SECRET_KEY`) a phrase counts as the secret too. A password's name is left to Bandit. A line `LW-SECRET-INLINE`
  lists is not listed again as Bandit's "possible hardcoded password" (B105, B106, B107), which ranked it low and
  repeated the text in its title; the Learn step "Take the secret key out of the code" counts either rule.
  A name like `SESSION_KEY`, `COOKIE_KEY` or `TOKEN_KEY` says "signs" and "is kept under" alike, so its text
  decides: one that reads like a name (`SESSION_KEY = "_auth_user_id"`, `TOKEN_KEY = 'auth_token'`,
  `cookieKey: 'sid'`) is the key something is kept under and is not listed. The text that signs under such a name
  is still found from the call that signs with it, and the name counts as before where its file hands it over as a
  secret, a password or one of the keys that sign (`keys: [COOKIE_KEY]`). A search pattern under a name that ends
  in `secret` (`LOOKS_FOR_SECRET = '(?P<name>secret|token)='`) is no secret either; Lantern's audit of itself
  found that one, on a line of this change.
  A folder named `env` is left out only where it is a Python environment (`pyvenv.cfg`, conda's records, the
  programs that switch it on, its library folder: `python_frontend.is_environment`). Until now the name alone was
  enough: a project's own `config/env/` or `src/env/` was read by no reader of any language, its functions were not
  on the map and nothing in it was checked.
  Changed for the person: findings of a project that was analyzed before can differ. New findings `LT-*`,
  `LW-XSS-RAW`, `LW-SECRET-INLINE`, and `LW-AUTH-MISSING` on routes the frontend does not call. A finding request
  data was followed to starts from the graver of the tool's severity and the flow's kind, so a query built from
  request data can rank higher than before; a query or command only fixed text reaches ranks low. A route behind
  `app.use(requireLogin)` no longer gets `LW-AUTH-MISSING` and no longer counts under "route auth" as open. A
  router loaded with `require` into a name and mounted by that name now has its prefix in its routes' addresses
  (`/api/notes`, before `/notes`), so links between frontend and backend that matched by the end of the path can
  now match exactly. "Rate limiting" turns from "in place" to "add" or "check" where the library is only
  installed, and `LA-WALLET-DRAIN` can appear there. `LW-AUTH-MISSING` goes from a route whose code shows a login,
  and an ownership finding can appear there instead; it appears on a route whose only sign of a login was a token
  check that lets a failed token on, a login made optional or a token nobody looks at, and on a route with no login
  that removes or saves a record through its object. The card "Login check on routes that change data" tells the
  story the findings tell: a route whose code shows a login under a plain name is counted as checked (before: "add"
  or "check", with the route listed as open), and a route a finding calls open is listed as open by its name and no
  longer among the routes that show a login. A route whose only sign of a login was a call that makes random text
  (`secrets.token_urlsafe`) now counts as open there. Code in a project's own folder named `env` is read for the
  first time, with whatever is found in it. A Python line with a signing secret is listed once, as
  `LW-SECRET-INLINE` (medium), where Bandit's B105 (low) stood; a risk accepted under the Bandit finding does not
  carry over to the new one. The reason beside a rank that a rule fixes is now the rule's
  own sentence where it has one (`fixed_why`). Result files: `security.json` findings may carry `flow`, `claim`,
  `secret_kind`, `fixed_why`, and an ownership finding `routes` and `late`; `security.json` itself has
  `logins_shown` (the routes whose code shows a login); a route's `entry` in `graph.json` may carry `use`; the
  scanner list has a `lantern-flow` record (`docs/api.md`). Nothing was removed, and older result files open as
  before.
  Tests, each dangerous example beside safe twins and look-alikes, none copied from the held-out apps:
  `tests/test_flow.py` (391), `tests/test_flow_js.py` (319), `tests/test_flow_authz.py` (648),
  `tests/test_templates.py` (6), `tests/test_secret_inline.py` (110), `tests/test_ratelimit.py` (24),
  `tests/test_env_folder.py` (11), and new tests in `tests/test_express.py` and `tests/test_fullstack.py` for
  Express `use`. The examples a rule was written for came before its code and failed first; examples added
  afterwards to pin down what already read right say so beside them. Older expectations that changed
  are rewritten with the reason beside each (`tests/test_security.py`, `test_context.py`, `test_case.py`,
  `test_scenarios.py`, `test_readiness.py`, `test_mcp.py`, `test_protections.py`; in the last round five more: a
  route's `use` list names the function written in place in front of it (`tests/test_express.py`), a page made with
  jinja2's own `Template` that prints the request's text is a finding where it read clean (`tests/test_flow.py`),
  two ownership findings stand on the line of the record, not on the route's first line
  (`tests/test_flow_authz.py`), and `jwt.decode(token)` with no key no longer makes the login card read "in place"
  (`tests/test_protections.py`; the whole suite showed that the card and the new findings told two stories, and 14
  examples were added there, 8 of which failed before the card was changed)). A name given twice at the top of a
  test file now fails the suite, as it does for the product's own files (`tests/test_project_files.py`): a new
  constant in a test file had been replaced by an
  older one further down, and the new test read the wrong text. Lantern's audit of itself: 0
  critical, 0 high, 0 medium, grade A. After the last round of rules it had failed with four findings at medium,
  and three of them were Lantern's mistakes, which real projects would have met too: its cloud client
  (`self.base + path`) and its sign-in redirect (an address out of a table in the code) were listed as "the request
  chooses where the server connects", and its share page, which makes a nonce with `secrets.token_urlsafe`, was
  asked whose record it shows. The rules above (the address that starts with a value of the server's own or
  names no host, a library call's result that is not the server's own, random text is no login) came from that:
  133 examples in the four test files, 72 of which failed before. Looked at apart, of 22 everyday safe shapes of an
  outbound call (a setting and a path in their many spellings, a client with a base address) the code before this
  round reported 20 and it now reports 1
  (`os.path.join` used for an address). The fourth finding was right, a demo tool's made-up client secrets written
  in the code, which are now made when it runs. Of the 117 findings of the 15 sample apps under `tests/fixtures`, the last
  round of rules changes one: the signing secret in the shop sample (`shop/auth.py`, line 5) is listed as
  `LW-SECRET-INLINE` (medium) where Bandit's B105 (low) stood. Against the code before point 4 the 15 samples
  list the same 117 findings but for two of the shop sample: that one, and the planted SQL injection
  (`shop/repo.py`, line 15), which is critical where it was high, because the request's value is now followed to
  it from the route through three files. `tools/audit.sh` expects 3 critical findings there and checks that path;
  it had expected 2, was not run here while the stage was built, and failed on GitHub for the first commits of
  this change.
  Measured on the held-out set (`bench/heldout/`: 14 apps the engine was not written on, definition
  `e6b10d91686f`, offline): documented problems found at medium or above went from 28 of 79 before this change to
  54 (44 at the first measurement, 50 at the second, 54 at the third, the fourth and the fifth and last; 55 with the
  dependency audits on),
  and on the five public apps from 20 of 61 to 39 (target: 37). False alarms on the 17 safe-twin anchors went from 3
  to 0, a mapped path is on 46 of the 55 problems found, and no vulnerable app is given a green release (0 of 8, as
  before). Two targets are missed. One of the 26 `sql`, `shell`, `eval`, `deserialize` and `xxe` problems is still
  not found (`pg-ssti`: a finding stands 13 lines above the documented line and nothing at it). And 2 of the 6 clean
  apps are still refused a green release, each through one false alarm at high; one of the two is a finding of this
  engine, on a value that has to equal a stored e-mail address before it reaches the page. Who may reach what is
  the weakest class (3 of 11 found). The third number was preceded by two looks at which expectations were missed,
  by class, rule and line number only; the apps were not read. After it two findings on clean apps were read in
  the code to label them. The rules for the browser's own address and for key names came after that, from the
  large apps below and not from this set; the fourth measurement is the engine with them, and no number moved.
  The fifth is the engine after the imports written from the top were read as the project's own (found with the
  report's examples, not from this set): every app lists exactly what it listed at the fourth.
  Every miss by name, the labels and all five measurements are in `bench/heldout/README.md`.
  Time and memory, on the ten large public apps of `tools/large_apps.py` with the code before this change and
  with it (two runs a side, each alone, the same container, offline; `bench/large_apps_results.md`): 183.8 s and
  173.4 s for the ten before, 190.3 s and 198.9 s after, so between 6.5 s and 25.5 s longer (3.54% to 14.71%);
  Django, the largest, 99.0 s and 91.3 s before with 759 MB, 103.9 s and 107.5 s after with 790 and 786 MB. The
  same code run twice differs by about ten seconds on the ten, so the cost is known only as that range; the
  first write-up, made from one run a side, called a second or two noise, which was wrong. No file and no check
  was left out. An earlier run of these apps is also where the two false alarms above came from (the browser script of Hugo, the
  key names of Django); on the final code Hugo lists what it listed before, and Django lists 20 new heuristic
  findings at medium on its own templates, 4 of them false alarms on a plain-text e-mail (see Not covered).
  Not covered (the whole list is in `CLAUDE.md` under Known gaps and in `docs/audit/CLAIMS.md`, S18 to S24): only
  Python and JavaScript/TypeScript are followed. The values of a plain-text e-mail template inside
  `{% autoescape off %}` are listed as page output that is not escaped (4 such lines in Django's own
  `password_reset_email.html`): an e-mail's text is not told from a page. A value an object's own method reads back, or one kept in a
  database, a session or a file and read back later (stored XSS, second-order SQL), is not followed. A library call
  passes a value on only when `flow_rules.PROPAGATORS` names it. The who-may-reach-what rules, the template rule and
  the secret rule read names and shapes and say so (heuristic): a shared record read by its id is reported like a
  personal one, a guard on a class and Express `use` in another file than the routes are not applied, a secret under
  a neutral name is not listed. A check made outside the code (a proxy, the database's own row rules) is not seen.
  An address that starts with a value nobody outside chose is taken to have the server's host: one that starts with
  an address a visitor saved earlier, with a part of the request the engine does not know as request data
  (`request.remote_addr`), or with a library call's result for the request's text that was kept on an object and
  is read in a method, is not reported; a helper that takes the host as a parameter is reported whoever fills it,
  a setting too. In the browser a helper that is handed the page's address and cuts it (`head(location.href)`
  around `u.split('#')[0]`), a piece cut from its start with `slice` or `substring`, and the path alone as the
  next page are reported; a `replace` whose pattern is built when the page runs (`new RegExp(...)`) is taken to
  leave the site in place. A signing secret under a name like `SESSION_KEY` whose text reads like a name
  (letters only), which no call Lantern knows is handed and which its file hands to nothing named for a secret,
  is not listed.
  A login is taken on trust from a short list of token libraries; a value kept on the request and tested later
  (`req.user = jwt.decode(t)`, then `if (!req.user)`) still reads as a login, and a login made optional is seen
  only on the route itself. A record handed to a helper that removes it, one read with SQLAlchemy 2's
  `session.execute(select(...))`, and a field saved by a `commit()` in another function are not counted as changed.
  In a folder that is a package, the file beside used as a module by its bare name (`import models`, then
  `models.Note`), a star import of it by its bare name (`from models import *`) and a name it only passes on are
  still read as a library's, and so is what a star import brings when `__all__` is built or added to, or when an
  import of the same name is written before the star: the who-may-reach rules ask nothing there. Another tool's
  finding on a query (Bandit's B608) whose request value passed a real check (a fixed list, asked in the route or
  in a helper) keeps that tool's rank and still says the request sets the value: the engine reports nothing of its
  own there, and does not lower the other finding (kept for point 6).

- lantern-cloud: 300 runs per person per day is now what `cloud/fly.toml` says (the owner's choice of 2026-11-11;
  the file said 50, his choice of 2026-11-04). The live service already ran with 300 through a setting kept on
  Fly, which wins over the file, so nothing changes for anybody; the file, `docs/deploy.md` and the testing
  checklist now say what is live. The limit for everyone together stays 1,000 a day.

- Security: a link in a project that leads out of the project is no longer read or shown (2026-11-10; found during
  stage 7 of the 2026-11-09 directive, while measuring what Lantern does with each file of 16 sample projects when
  that file is a link). A project comes from anywhere, and a git repository can hold symbolic links to any path of the
  computer it is cloned on. Lantern's readers of source files refused a file that was itself such a link
  (`python_frontend.inside_repo`). Measured on the code before:
  the notes file (`lantern-narratives.md`) was read without asking, and the Evidence Report shows it as it is. A
  project that brought that name as a link had the first 20,000 characters of the file it led to in `evidence.html`
  and `evidence.json`; a pipe under that name held the run up for good.
  `inside_repo` looked at the last name of a path only, so a file reached through a folder that is a link out of the
  project counted as the project's: `lantern-packs -> /somewhere` had the packs of rules in that folder loaded.
  Bandit finds its files itself. It opened a `.py` link wherever it led, and its findings quote the lines; a pipe
  under a `.py` name held it up until Lantern's time limit ended the whole Python check, so a project could switch
  that check off by bringing one.
  Now `inside_repo` answers for the whole path: a plain file, or a link to one, that lies inside the project by
  whatever folders it is reached. A link that leads out, a file behind a folder that is such a link (on Windows a
  junction too), a pipe, a device, a folder under a file's name and a name nothing answers to are not files of the
  project. A link that stays inside the project is read as before, and so is a project that is itself reached through
  the person's own shortcut. The notes file asks it. `security.run_bandit` hands Bandit an exclusion for each Python
  file that is not the project's (`_not_the_projects`, `_only`: a pattern that fits that one file, since Bandit's own
  matching would take `a.pyw` along with `a.py`), names those files in the record's `exclusions`, and takes no
  finding, no count and no error from such a file whatever Bandit did. And a repository Lantern clones is written with
  no link at all (`remote.NO_LINKS`, git's `core.symlinks=false`): git writes a small file that holds the link's own
  text, as it does on a Windows without links, the clone does not count as changed for it, and a clone an earlier
  Lantern made gets the setting the next time it is updated.
  Changed for the person: in a repository Lantern clones from a link, a file that is a link to another file of the
  same repository is now that small text file, not a second copy of the other file (a folder the person cloned
  themselves and added is read as before, links inside it included). A file Bandit is told to leave out is named in
  its record; before, a link to nothing made the Python check "partial".
  Tests: `tests/test_links_out.py` (19 tests, each refusal beside a safe twin: the project's own notes file, a link
  that stays inside, the person's shortcut, the project's own pack, real files whose names begin like a link's, a
  project file Bandit cannot read). On the code before, 17 fail, 1 passes (the safe twin of the notes file) and 1
  needs Windows; with this change 18 pass and 1 needs Windows (a junction), where CI's Windows job runs it.
  Not covered: a clone an earlier Lantern made keeps the links it already has until it is cloned again (the readers
  above refuse them all the same); a Python file that is not the project's and has a comma in its path, or is one of
  more than fit a command line (24,000 characters of exclusions), is not handed to Bandit as an exclusion, so nothing
  is taken from it but a pipe there still holds Bandit up to its time limit, which the record then says; an exclusion
  is found, letter for letter, in no path but its own unless a folder was named for that purpose (`tool.p[y]z/`), and
  a file in such a folder is then left out of Bandit as one in `build/` or `vendor/` already is; a link put in place
  while an analysis runs (that takes another program of the same computer writing in the project at that moment).
- Security: what anybody can send the gateway without signing in is bounded (2026-11-10; stage 7 of the 2026-11-09
  directive, part 4: "verify abuse controls on sign-in and telemetry without breaking endpoints that are
  intentionally anonymous"; gateway 0.2.6, which applies once that version is deployed). The gateway answers some
  addresses for people who have not signed in: the health check, the sign-in pages, the owner's page (it asks for
  the secret) and the app's opt-in usage reports.
  **What was wrong** (the gateway's code before, 97c1677; its own app with stand-ins for the model and for GitHub,
  nothing left the computer, the live gateway was not asked):
  - a usage report whose body was a list, a number, a text, `null` or `true` was answered with an internal error
    (HTTP 500, 5 of 5); so was a request for the model that was a list, a number, `null` or nested 3,000 deep (4 of
    4) or whose `max_tokens` was a word, a list or `1e400` (3 of 3), and an admin secret with a letter outside ASCII;
  - 32 MB sent by nobody to `/v1/usage`, `/v1/tokens` and `/v1/auth/signout` were taken whole (33,554,432 bytes
    each) before the refusal: the size was looked at after the body had been read;
  - 3,000 usage reports from one sender, each with a new install id, were all answered 200 and 3,001 installs were
    kept, with whatever text was sent as the version and the operating system (`<b>hello</b> you`,
    `see evil.example`), which the owner's page lists;
  - 500 wrong admin secrets from one sender were each answered 403 at once: nothing slowed guessing;
  - the token of a new sign-in waited for the app in the database file in clear, where the gateway's promise is
    hashes only;
  - one sign-in link used 200 more times made the gateway ask GitHub 200 times, and GitHub out of reach was
    answered with an internal error (HTTP 500).
  **What changed** (`gateway/lantern_gateway/limits.py` new, `app.py`, `auth.py`, `dashboard.py`):
  - no request's body is read past the limit of its address (`LANTERN_MAX_BODY` for `/v1/chat/completions`, 4,000
    bytes for every other address): one that says it is larger is refused before any of it is read, one that does
    not say is cut off at the piece that crosses the limit (413 `too_large`);
  - a body that is not a JSON object is answered 400 in the gateway's own words, and a `max_tokens` that is no
    number counts as not given;
  - usage reports: 300 an hour from one sender (`LANTERN_SENDER_PINGS_PER_HOUR`), 50 new installs a day from one
    sender (`LANTERN_SENDER_INSTALLS_PER_DAY`), 1,000 new installs per UTC day for everyone together
    (`LANTERN_INSTALLS_PER_DAY`); past a limit the answer is 429 with `Retry-After`, the app keeps its counts for
    its next try, and an install the gateway already knows keeps being counted. A version is kept only when it is
    shaped like one and an operating system only when it is Linux, Darwin or Windows (else nothing, or `other`);
  - the owner's secret: after five wrong secrets in a minute from one sender, or 30 from everyone together, no
    secret is looked at until that minute ends (429), and the owner's page says so in words ("Too many wrong secrets
    in the last minute. Wait a minute, then try again."); a secret outside ASCII is a wrong secret (403);
  - signing in: a link that comes back from GitHub or Google works once (a second use gets a page and the provider
    is not asked), the provider is asked at most 10 times a minute for one sender and 120 for everyone together, two
    links made in the same second differ, and a provider that cannot be reached or answers oddly gets a page (502);
  - the token that waits for the app is stored sealed with the app's own code, of which the gateway keeps only a
    hash; a row an earlier version left in clear is deleted at start-up and never handed out, so a person who is in
    the middle of signing in at the moment of the deploy signs in again;
  - who a sender is: the address the gateway's proxy wrote in the header named by `LANTERN_ADDRESS_HEADER` (Fly's
    `Fly-Client-IP`), else the connection's address, IPv6 by its /64 network; kept in memory only, as a keyed hash
    whose key exists only while the process runs. No address is written anywhere.
  **Evidence.** The same probe after: 400 for the 9 shapes and the cap for the 3 sizes, 65,536 bytes taken of each
  32 MB, 49 of the 3,000 reports answered 200 and 2,951 answered 429 with 50 installs kept and no text, 5 wrong
  secrets answered 403 and 495 answered 429, a secret outside ASCII 403, no token in clear in the database file, 200
  more uses of a link answered 400 with 0 requests to GitHub, GitHub out of reach a 502 page. In a real browser
  (Chromium, a gateway on 127.0.0.1): five wrong secrets show "That secret was not accepted.", the sixth and then
  the right one show the new sentence. `tests/test_gateway_limits.py`: 116 tests, each refusal beside the ordinary
  use that must keep working; on the code before 81 fail (60 on what the gateway did, 21 because the setting, the
  limiter, the document or the page's sentence they ask about was not there) and 35 pass. One test of
  `tests/test_signin.py` changed (a link now carries a random part) and fails on the code before. Mistakes planted
  in the changed lines of `limits.py`, `app.py` and `auth.py`, one at a time: on the tests as first written (99 of
  them) 93 of 133 failed a test and 40 failed none; tests were added for 28 of the 40; on the tests as they stand
  **121 of 133 fail a test and 12 fail none**. The 12: the length of the limiter's key and of the name it keeps of
  a sender (2); a full table that clears ended minutes one sender earlier (1); a stand-in for a port that is never
  read (1); two checks that two lengths are equal, which they are by construction (2); the housekeeping of the
  table of used links at 50,000 entries, which 120 sign-ins a minute never reach (3); a comparison at the exact
  same instant and a default far below any time (2); the length of a link's random part (1).
  Also: CI's Linux test job prints the line `programs these tests started` (which npm the tests met) right after
  the tests; it stood far up in the log, and the red run of 616b7dd came from a newer npm.
  **Limits.** A caller with many addresses is many senders, which is why each limit that matters has a count for
  everyone together beside it; such a caller can use those up, a minute at a time: the owner waits for their page
  (nobody gets in), and people signing in see "Too many sign-ins in the last minute". The per-sender counts are as
  good as the proxy's header: whether a caller can write its own `Fly-Client-IP` through Fly's proxy was not tried,
  and Fly's documentation as read on 2026-11-10 does not say. `/v1/auth/<provider>/start` and `/v1/auth/claim` are
  not limited. The counts are in memory and start empty when the gateway restarts (the cap on new installs for
  everyone is read from the database). The server's log lines hold an app's sign-in code for the ten minutes it is
  good. The owner's page was checked in Chromium only.
- Lantern starts only the person's own programs, and a settings file in a project does not steer the Python scanner
  (2026-11-10; stage 7 of the 2026-11-09 directive, execution safety: reading a project must not run it). Lantern
  is often started inside the folder of the project it was asked to read (`cd project`, then `lantern analyze .`).
  **What was wrong** (the code before, ce65f49; Bandit 1.9.4, Python 3.13.18; each shown by a failing test, offline,
  on this computer). Bandit was started as `python -m bandit` in the person's current folder, and Python looks
  there first for every module such a program loads: a project file named `bandit.py`, `logging.py`,
  `argparse.py`, `tokenize.py` or `yaml.py` ran as a program, twice (the scan, and the question for the version),
  and Lantern said only "incomplete bandit: error: empty output". Of 12 module names tried one at a time, 10 were
  loaded; with `-P`, 0. That is claim A4 ("Lantern never runs the analyzed code") not holding for that way of
  starting it. A `.bandit` file in the project (Bandit looks for one in the folder it scans when it is handed
  none): with its checks switched off, every file left out, only another check asked for, a second settings file
  named, or the file in a folder further down, the scan found nothing where there is a finding and Lantern's record
  of it said `ok`; two such files, or one naming a file for the report, made the scan fail. And programs started by
  their bare name (`git`, `gitleaks`, `pip-audit`, `docker`, `taskkill`) or found with `shutil.which` (`git`,
  `npm`, `gitleaks`, `pip-audit`, `docker`, `tesseract`, `lantern`): on any system a PATH entry that is empty, `.`
  or another relative path means the current folder (27 failing tests: nine ways Lantern starts a program, three
  such entries), and Windows looks in the current folder before PATH, as `shutil.which` does there. A test run in
  Docker ("Watch my tests run") started `docker` by its bare name and its clean-up (`docker rm`) in the person's
  current folder; in the restricted process the runner of the tests (`npm`) could be a file of the project named
  like it; and Docker asked for (`LANTERN_SANDBOX=docker`) and not installed ended in a Python error.
  **Now.** `lantern/programs.py` is the one place a program is found and worded. `programs.find(name)` gives the
  full path from the folders PATH names in full (on Windows with the endings Windows can start), or nothing;
  `programs.python(module, ...)` starts a Python tool with `-P`, Python's own switch for "not the current folder";
  `programs.env()` is the environment every helper is started with (`remote.run_bounded`): PATH and PYTHONPATH
  without their relative entries, and on Windows the system's own switch (`NoDefaultCurrentDirectoryInExePath`),
  which its shell obeys when `npm.cmd` starts `node`. Bandit is handed a settings file of Lantern's own (`--ini`,
  with nothing in it; `programs.settings`), so it looks for none in the project; when that file cannot be written
  the scanner is not started and the record says why, and a temp folder that cannot be cleared away afterwards
  does not cost the scan.
  The cloud worker's steps (`lantern.depaudit`, `lantern.archive`, `lantern.cli`) are started with `-P` as well;
  they already ran in a folder whose names the service chose. In the sandbox the runner of a project's tests and
  Docker are started by their full paths, Docker with the same environment; Docker asked for and not installed
  means the tests are not run, said in Lantern's words (`Unavailable`).
  Changed for the person: a `.bandit` file of their own no longer changes what Lantern's scan reports (to set a
  finding aside, `lantern accept` keeps it listed with its reason), and a program that can be reached only through
  a relative PATH entry counts as not installed.
  Tests: `tests/test_programs.py` (72 tests; 3 need Windows and run in CI's Windows job) and one more in
  `tests/test_server.py`. On the code before 56 of the 73 fail, 14 pass and 3 are skipped: 46 on what the code does
  and 10 because a function of this change is not there yet. `test_no_program_is_started_any_other_way` reads every
  module of `lantern/`, `cloud/lantern_cloud/` and `gateway/` and fails on `shutil.which`, on a program started by
  its bare name and on `[sys.executable, "-m", …]` outside the two lines that start the project's own tests on
  purpose. Mistakes planted in the changed lines, one at a time (the tool can plant none in the changed lines of
  `cloud/lantern_cloud/worker.py`). First pass, with the tests and the test files as first chosen: 51 planted in
  nine files, 32 failed a test at once and 19 failed none. Of the 19, 8 cannot fail a test (five change a time limit
  by one second, three change `text=True` on a line that also names an encoding, which already means text), 2 fail
  older tests in files that had not been named (`tests/test_links_out.py`, `tests/test_sandbox_safety.py`), 8 led to
  tests (a settings folder that cannot be cleared away, the Windows branch that ends a process tree, the runner of a
  test run in the sandbox) and 1 to a change of the code (Docker asked for and not installed). Final pass, on the
  final code and tests: 53 planted in ten files, 44 fail a test, and the 9 that fail none are of those two kinds
  (six time limits, three `text=True`).
  Not covered: a folder PATH names in full is used as the person wrote it, also when it lies inside a project (a
  project's virtual environment that the person switched on); Lantern started as `python -m lantern.cli` inside a
  project, or with a relative entry in PYTHONPATH, has handed its own Python the current folder before any line of
  Lantern runs (the `lantern` command does not); what gitleaks does with settings files in the folder it scans was
  not measured (it is installed neither here nor in CI); the Windows rules are tried against Windows itself only by
  the three tests of CI's Windows job; the project's own tests ("Watch my tests run", `lantern trace`) are the
  project's code on purpose and run in the sandbox.
- npm takes no settings from the project it audits, and reads nothing outside a folder of Lantern's own (2026-11-10;
  stage 7 of the 2026-11-09 directive: path boundaries, lock files). `npm audit` takes settings from the folder it
  is started in (`.npmrc`), and from a folder above whose `package.json` names that folder as a workspace. Lantern
  started it in the project.
  **What was wrong** (the code before, 033e30a; npm 10.9.9, node 22; the real npm against stand-in registries on
  127.0.0.1, offline). Lantern named the registry itself (`--registry`), and that held: a `registry=` line in the
  project was passed over. But with `offline=true` in the project's `.npmrc` npm asked nobody and found nothing, and
  Lantern's record of the audit said `ok`. With `proxy=` and `https-proxy=` both of npm's requests went to the
  address the project named (where nothing says "not through a proxy", as on a person's computer), and the record
  said `ok`. With `strict-ssl=false`, or `cafile=` naming a file of the project, npm talked to a registry whose
  certificate nobody vouches for. With `cache=` and `logs-dir=` npm wrote 21 files where the project said. A token
  line (`//host/:_authToken=`) and `user-agent=` were sent as the project wrote them. `global=true`,
  `location=global` and `workspace=<a name>` made the audit fail, and `fetch-timeout=1` did in 3 of 8 runs (each
  said in the record). 16 other settings tried changed nothing (`node-options` and `script-shell` among them:
  nothing of the project ran). And npm reads the `package.json` of every folder a lock file names on the computer:
  with a lock file that names `../next-door`, the version written in that folder's `package.json`, outside the
  project, was in the question npm sent to the registry; a workspace pattern such as `../*` in `package.json` made
  it read the `package.json` of every folder beside the project, and so did the same pattern in the lock file's own
  first entry, which npm takes in place of a `package.json` it cannot use.
  **Now.** npm is started in a new folder of Lantern's own (`programs.folder`), on copies (`depaudit._npm_stage`):
  `package.json`, `package-lock.json` and `npm-shrinkwrap.json` (npm up to 11 takes it before the lock file), and the
  `package.json` of each folder the lock file names inside the project, at the place it has in the project. Each is
  read as any dependency file is (a plain file of the project, 32 MB at most) and handed to npm as what Lantern read
  in it, written out anew, never as the file's own text (`_npm_json`): two readers of one text can disagree (a name
  that stands twice; JSON nested 200,000 deep, which Node reads and Python does not follow), and npm would then
  follow what Lantern never saw. A file Lantern cannot read as JSON means npm is not started on that lock file. The
  folders matter: npm finds a workspace package by its folder, and a copy of the two files alone asked about nothing
  and said that nothing is known (measured before the fix was written). A folder named outside the project is not
  copied, and the copy lies as many folders deep in Lantern's folder as any entry of the lock file holds `..`, so
  nothing is where such an entry points. An entry counts as a link however it is marked (npm takes `1`, `"yes"` and
  `[]` for the mark as it takes `true`), and what it points at counts as a path whatever it looks like (to npm
  `https://x/../../../next-door` is the folder beside the project). What cannot be kept from npm that way means npm
  is not started on that lock file, and the record names the file and the reason: a folder named by its full path;
  one written in words a path and an address read differently (`%`, a control character, `~`: an older lock file's
  `file:` version is read as an address); more than 16 levels up; more than 5,000 folders, or 64 MB of their
  `package.json` files; a workspace pattern that leaves its folder (`..`, a full path, a backslash, braces that can
  put either together), in `package.json` or in a lock file's own first entry. A folder's `package.json` that is no
  file of the project (a link out of it, a pipe), that Lantern cannot read as JSON, or that asks for workspace
  folders outside, is not copied and is named, and the audit's state is `partial`.
  Changed for the person: a project's own `.npmrc` no longer counts for Lantern's audit (a private registry, a proxy
  or a certificate set there); their own npm settings (`~/.npmrc`, `NPM_CONFIG_*`) count as before. A folder a lock
  file names outside the analyzed folder is no longer read. A lock file in a folder that a `package.json` one folder
  up names as a workspace is audited as that lock file (before, npm went up to that folder and the audit failed
  there for want of a lock file). A project whose `package.json` or lock file is not valid JSON is not handed to
  npm, and the record says which file (before, npm audited a project with a broken `package.json` from its lock file
  alone, and said itself what was wrong with a broken lock file).
  Tests: `tests/test_npm_settings.py` (145 tests; 23 start the real npm against stand-in registries on this computer
  and are skipped where npm is not installed; 122 put a stand-in in npm's place and run everywhere, but for 6 that
  need links and pipes or a path longer than Windows takes). On the code before 138 fail and 7 pass: 135 on what the
  code does, 3 because a name of this change is not there yet. The 7 are twins (what must keep working) and the
  `fetch-timeout=1` case, which the code before fails in 3 of 8 runs. Mistakes planted in the changed lines, one
  at a time, on the final code and tests: 60 in two files (59 in `lantern/depaudit.py`, 1 in
  `lantern/programs.py`), 58 fail a test and 2 fail none: the 64 MB limit written as 65 MB (the tests set a small
  limit instead of writing 64 MB of files) and the longest line of the record written as 301 characters in place
  of 300 (no line Lantern writes about npm gets that long). The first pass, on the fix and the tests as first
  written: 55 planted, 38 failed a test at once, 17 failed none.
  Kept in the record: the fix as first written (101 tests, all passing; the whole suite passing under Python 3.13
  and 3.11, 1893 passed and 22 skipped each) still let the real npm read outside Lantern's folder in two crafted
  cases. They were found while reading the planted mistakes that failed no test, and npm's own code. A lock file
  nested deeper than Python follows was handed over as it was, unread, and npm followed it two folders up; and with
  a `package.json` that is not JSON npm took the lock file's first entry with its workspace patterns. 48 tests were
  written first (32 failed, two of them with the real npm), then the fix was changed. Nothing of the first form was
  pushed.
  Not covered: npm also looks in the folders above the one it is started in for a `package.json` that names it as a
  workspace; above Lantern's folder those are the temp folder and the folders it lies in, which are the computer's
  and not the project's. A name JavaScript
  treats specially (`__proto__` as a key of the lock file, three ways) was tried in place: npm 10.9.9 follows none,
  and Lantern has no rule for it. What gitleaks does with settings files in the folder it scans is still not
  measured. A project with only an `npm-shrinkwrap.json` is not audited (Lantern looks for `package-lock.json`).
  Where the lock file npm reads is left over from another `package.json` (it names libraries this one does not
  ask for), npm asks about nothing and the record says `ok`, as npm itself does in the project.
  Kept in the record: the first run of these tests on GitHub failed (616b7dd; under Python 3.11 on Linux, in both
  of its runs: 4 failed, 1933 passed, 22 skipped). The fix was first measured with npm 10.9.9 alone, and four
  tests said what that npm asks about; GitHub's Linux machines have a newer npm. Repeated here with npm 11.21.2
  and 12.2.2: the same four fail, and under 12.2.2 a fifth; npm 10.8.2 behaves as 10.9.9. What changed is npm:
  11 and 12 no longer ask about a project's own folders (a workspace package, a library that is a folder), and
  12 no longer reads `npm-shrinkwrap.json`. In all four versions Lantern's copy is asked exactly what npm asks
  when it is started in the project itself with the same words (7 projects each; the eighth is the project with
  only an `npm-shrinkwrap.json`), so the code did not change. The five tests now compare with what the installed
  npm asks in the project itself (`itself`) and allow only the answers measured; the last lines of a test run
  name the npm it started (`programs these tests started: npm …`). All 145 pass against each of the four.
- The opt-in usage counts go to the gateway's own address and nowhere else, and Lantern says where they go
  (2026-11-10; stage 7 of the 2026-11-09 directive, "validate ... the address used for optional usage reporting").
  Sharing is off until the person turns it on; this is about what happened after they did.
  **What was wrong** (the code before, 62fe781; found by reading the sender, then shown by tests against the
  gateway's own code started on this computer; the live gateway was not asked). The sender posted to
  `<gateway address>/v1/usage`, and the gateway address Lantern is set up with already ends in `/v1`
  (`providers.gateway_url()`, `https://lantern-gateway.fly.dev/v1`): the counts went to `/v1/v1/usage`, a route the
  gateway does not have, the answer was passed over, and nothing told the person. That line is in the 0.10.0 release
  commit (072a1c5) and in every commit since, so with the address Lantern ships with no count arrived. The one test
  of the sender put a stand-in in place of `urlopen` and handed over an address written without `/v1`, a form the
  app and the command line never use, so it passed. Five more, each shown by a failing test. `send`, which says it
  never raises, raised for a gateway address with a name and a password, a port that is not a number, a blank, a
  line break or a control character (`http.client.InvalidURL`) and for an answer that is no web answer
  (`http.client.BadStatusLine`); in the app that ends the thread that sends every six hours until the app is started
  again, and at the command line it is a Python error when the command ends. A redirect (301, 302, 303) was followed
  with a GET, and a 200 from the place it pointed at marked the day as sent. `LANTERN_NO_REAL_PROVIDERS`, the
  person's switch for "nothing leaves this computer", was not asked: 13 of the new tests tried to reach another
  computer on the code before (the tests' guard refused each). An `http://` address of another computer was taken,
  so the install id would have crossed the network in clear. And no failure was ever said.
  **Now.** `usage.destination(base)` gives the one address the counts are posted to for a gateway address, or the
  reason none is sent, in fixed words that never repeat the address (it may hold a password): `https`, or `http` for
  this computer only; a computer's name or number; no name or password; no `?` or `#` part; a port that is a number;
  printable characters without blanks or a backslash, 2,000 at most. An address that ends in `/v1` gets `/usage`;
  one written without it gets `/v1/usage`, as before. `usage.where(base)` adds the switch. `send` asks `where`,
  follows no redirect (the place a redirect points at is never asked), never raises, stops at the first day the
  gateway does not take, keeps what was not taken for the next try, and writes down how the last try ended
  (`usage_last.json` in `LANTERN_HOME`: a day, a number and one of Lantern's own words, never text a server sent; a
  note of another shape says nothing; turning sharing off removes it). `lantern usage --show` and `/api/usage`
  (`where`, `why`, `text`) say `Sent to: <address>`, or `Not sent: <why>. The counts stay on this computer.`, and
  `Last try 2026-11-10: not taken (the gateway answered 404). The counts stay on this computer and are tried again.`
  Changed for the person: with sharing on, the counts now arrive. What is sent is unchanged (a random install id,
  the version, the operating system's name and a count per feature; `lantern usage --show` prints it), and the days
  that still wait on this computer go with the next try (days older than a week are dropped, as before). An
  `http://` gateway address of another computer in `LANTERN_GATEWAY_URL` is no longer used for the counts.
  Tests: `tests/test_usage_address.py` (63 tests against the gateway's own app and stand-in servers on 127.0.0.1;
  23 addresses that are sent nothing beside 12 that are taken). On the code before 61 fail and 2 pass (an address
  written without `/v1` arrives; nothing is tried while sharing is off): 44 on what the code does or says, in 6 of
  them the sender raising, and 17 because `usage.destination` is not there yet. The older test of the sender
  (`tests/test_usage.py`) now goes through a real address on 127.0.0.1 and fails on the code before too. Mistakes
  planted in the changed lines of `lantern/usage.py`, one at a time (61; the tool can plant none in the 3 changed
  lines of `lantern/server.py`): 59 failed the tests at once and 2 failed none (the text a sent day is remembered
  by; the answer when there is no address at all). Two tests were added, and all 61 now fail a test.
  Kept in the record: on GitHub's Windows machines one of the two runs of 616b7dd failed in one of these tests
  (1 failed, 1567 passed, 287 skipped; the other run passed, as every run before): a try against something that
  answers, but not as a web server does, was described with another sentence than the test expects. The test's
  stand-in read once, answered and closed; when part of the request is still on its way then, the system cuts
  the connection and the caller may never see the answer. That is the cause as read from the test, not shown:
  on Linux 300 tries of each of three ways of closing all gave the expected word. The stand-in now reads the
  whole request and closes after the caller has, and the test's message says which word was noted.
  Not covered: that no count arrived is read from the code and shown against the gateway's code on this computer,
  not against the live gateway (its owner's page would show it); the app's Settings page says only that nothing is
  sent, the reason is in `lantern usage --show` and in the route; an `https` address is taken as written (the name
  is not looked up, and `LANTERN_GATEWAY_URL` is the person's own setting); the system's proxy settings are used as
  before; what the gateway does with what it is sent (how much one sender may send, how large a request may be) is
  the next part of this stage.
- Security: a file of a project is opened only as a file of that project, a result file is read back only as a
  plain file, and a saved map is used for the folder the person named (2026-11-10; stage 7 of the 2026-11-09
  directive, "test path, link and ownership boundaries"; it goes on from the link fix above with the same
  measurement). Three rules. What the code before did is measured on the stage with the link fix merged in.
  **1. Files Lantern looks for by their name.** The link fix closed the source files, the notes file, the packs and
  Bandit. Every other reader still opened its file with a plain read, wherever a link led. `bench/links.py` (new)
  puts every file of the 15 sample projects, and of one more project made of the other files Lantern looks for by
  name, in six states, one at a time (taken away; a link out of the project; the same link with an empty file at its
  end; the same link with nothing at its end; a pipe; a link to itself), and runs the whole analysis on each: 232
  files, 1424 runs. On the code before: 17 files were read through the link (`package.json`, `app.json`,
  `go.mod`, `Cargo.toml`, `pubspec.yaml`, a `.csproj`, `build.gradle` and `build.gradle.kts`, `Info.plist`, the
  entitlements file, `project.pbxproj`, the network security settings, a notebook: what they hold went into the map,
  the findings and the readiness score), the results for 3 told whether the path a link named exists outside
  the project (two Gradle files and `package-lock.json`), and a pipe held 29 runs up for good, at 10 lines of
  the code in 8 modules. Under Python 3.11 and 3.12 a link to itself in the way of an import stopped the whole
  analysis with a Python error (`RuntimeError: Symlink loop` from `Path.resolve()`): 28 of the 264 runs of that
  state under Python 3.12.3, none under 3.13, which does not raise there. (On main, before the link fix, 230 of
  those 264 runs stopped, in `inside_repo` itself; the link fix took those away.) With this change: 0 read
  through, 0 tells, 0 held up, 0 stopped in 1424 runs under Python 3.13.18, and 0 stopped in the 264 under 3.12.3.
  (Under Python 3.11.18 the whole sweep was run only after GitHub's run under 3.11 had failed: see "Found by
  GitHub's run" below. There too it is now 0, 0, 0, 0 in 1424 runs.)
  Reading the code found one more of the second kind, which no sample could show: the Android signing-key finding
  (`LM-SIGNING-SECRET`) ranks higher when the key file is in the repository too, and a key file that was a link
  counted when something was at its other end. It asks `inside_repo` now, and a test holds it. And a test written
  for a planted mistake (below) showed one more of the first kind: a `setup.cfg` that was a link out of the project
  was read, and the function it named as a script became an entry point. The samples' `setup.cfg` names none, so
  the sweep could not show it; `project_text` had closed it already.
  `python_frontend.project_text(p, repo[, limit])` and `project_bytes` are now the one way a file of a project is
  opened. They ask `inside_repo` and raise FileNotFoundError for whatever it refuses, so every reader that passes a
  missing file over passes these over too; the readers of 28 other modules of `lantern/` go through them (38
  modules changed in all). Where a reader only asks whether a
  file is there, it asks `inside_repo` in place of `exists()` or `is_file()` (`android.py`, and `sandbox.detect`,
  which proposes the test command: ten names, the Gradle wrapper, the package manager's lock file, a linked `tests/`
  folder). A path that cannot be followed is an import of nothing (`js_frontend._reached`). And an import of a file
  that is a link to a project file with another kind of name (`helper.ts` → `kept.txt`) now leads to the link, which
  is the module; before, on main too, the path was followed to its end first, no module was found there, and the
  import was read as a library's.
  **2. Result files read back.** `results.write` (below) made writing safe; reading back was still a plain
  `read_text` in the commands about a finished run (`lantern report`, `evidence`, `verify`, `export`, the
  connector's tools), the app's cards and pages, Ask Lantern and the Learn steps: a `.lantern/security.json` that a
  project brought as a link was read wherever it led and shown as the project's findings, and a pipe there held the
  command or the page up for good. `results.plain(p)` is now the one opener for a result file (never through a link,
  never a pipe or a folder, at most 256 MB). `results.text` / `results.table` are the strict forms for the commands,
  which end with result 2 and one sentence (`… security.json was not read: it is a link, and Lantern does not read
  its results through a link. Remove it and analyze the project again.`); the app, Ask Lantern and the Learn steps go
  on without the file. The record of calls that "Watch my tests run" reads is written inside the program under
  test: it is read the same way, and only rows of the recorder's own shape are kept (`trace.well_formed`; before, a
  row such as `{"pairs": [1]}` ended the run with a Python error). The note a clone keeps of what it left out
  (`remote.skipped`) is read the same way.
  **3. Which folder a saved map is about.** `graph.json` names the project folder it was made for (`repo_root`),
  and `lantern report`, `lantern evidence` and `lantern explain` read each function's lines, and the notes file,
  in the folder that file named. A project that brought its own `.lantern/graph.json` naming another folder had,
  measured on the code before: a line of that folder's file in `report.html`; that folder's notes file in
  `evidence.json`; and that line, not the project's own, in each of the 3 requests `lantern explain` sent to the
  model. Now `Graph.load(path, repo)` takes the folder from its caller, every caller in `lantern/` hands over the
  folder the person named, and each function's lines are opened with `project_text`, so a saved `file` that leads
  out of the project has no lines. With this change: none of the three, and the project's own line is what is sent.
  Changed for the person: a project file that is a link to a file outside the analyzed folder (a `tsconfig.json`
  or `package.json` kept one folder up and linked into the folder that is analyzed) is no longer read; analyze the
  folder that holds both. A results folder made for one place and used from another (the project was moved, or
  `--out` names results of another copy) now reads the lines of the folder named on the command line, where before
  it read the place the results were made for. For code that calls Lantern's functions:
  `pipeline.rebuild_outputs(out, repo)`, `plan_explain(out, repo, …)` and `explain(out, repo, provider, …)` take the
  project folder as their second argument.
  Tests: `tests/test_project_files.py` (138 tests, each refusal beside a twin that must still be read: the
  project's own file, a link that stays inside the project, the person's shortcut to the project, a plain result
  file). `test_no_file_is_opened_any_other_way` reads every module of `lantern/` and fails on an `open`, `os.open`,
  `read_text` or `read_bytes` outside the openers and a list of the places that open a file of Lantern's own, so a
  reader added later is caught before any sweep is run. On the code before, 89 fail and 49 pass. Of the 89, 76 fail
  on what the code does (33 a reader still waiting on a pipe when the test's limit ran out, 1 a refusal that did
  not come, 1 stopped with `RuntimeError: Symlink loop`, 41 a compared result) and 13 because a function or an
  argument of this change is not there yet. The 49 that pass: 33 of the 68 files looked for by name, whose reader
  asked `inside_repo` already; 11 tests of the checking tools themselves; 5 tests of what was right before. With
  this change 138 pass. (133 of the 138 were written and counted with the change; 5 came with what GitHub's run
  found, below, and all 5 fail on the code before.)
  Mistakes planted in the changed lines, one at a time (84, in 18 of the 38 modules): 45 failed the new tests at
  once, 18 failed the older tests of their module, and 21 failed neither. For those 21, eight tests were added and
  three sharpened (the app's Explain button and its command drawer, `lantern explain --node`, the plan's three
  levels and forty functions, the Supabase check, a setup file's scripts, the Android signing key, an Android file
  over the size limit, the test command, the words of a refused report); all 84 now fail a test. Thirteen of the
  21 sat in older logic on a line that only gained the folder argument or moved, which no test had tried (which
  functions the app's Explain plans, a setup file's scripts, the Supabase check); eight in lines this change
  rewrote. The older tests tried were each module's own test file, not the whole suite.
  Found while doing this, in the measuring script itself: its time limit was an ordinary error raised once, and a
  reader that passes over whatever goes wrong with a file passed over the limit too. A sweep of main's code then
  waited on a second pipe for good and had to be stopped. The limit can no longer be passed over
  (`links.limited`; a test plants the mistake three ways). The numbers above are from the corrected script; for
  the stage's own code it gave the same 49 lines as the first run.
  Found by GitHub's run of this change under Python 3.11 (1 failed, 1653 passed, 19 skipped, twice; the
  measurements above were made under 3.13, and under 3.12 for one state only): `ios.find_apps` looked for
  `Info.plist` by its exact name and gave the app whatever it found as its settings file, read or not. Before
  Python 3.12 such a look finds a link only when something is at its end, so under 3.11 the map and the findings
  named `Journal/Info.plist` as the app's settings file when the outside path existed and the Xcode project when it
  did not; under 3.12 and 3.13 the link was named in both cases, unread. The whole sweep, then run under Python
  3.11.18 on that commit: that 1 tell and nothing else (0 read through, 0 held up, 0 stopped in 1424 runs). Now a
  file `inside_repo` refuses is no settings file of an app (`Info.plist`, the entitlements files), on any Python,
  and the Learn step that asks whether a file is there (`SECURITY.md`, `Dockerfile`) asks `inside_repo` as well:
  it took a link with nothing at its end for the file from Python 3.12 on, and a link to any file outside the
  project on every Python. Five tests; on the code before 5 fail under 3.13 and 3.12, and 4 under 3.11. With the
  fix the sweep under 3.11.18 gives 0, 0, 0, 0, and the whole suite passes under 3.11.18 as it does under 3.13.18.
  Not covered: the sweep sees a read only when what the file holds changes a result file (the look for openers
  covers the rest by the way they open: it knows `open`, `os.open`, `read_text`, `read_bytes` and `.open`, not a
  library that is handed a path); gitleaks, which finds its files itself, was not measured (not installed where the
  sweep ran); a link put in place between Lantern's question and its open is read; whether a name is a folder is
  still asked the plain way in places, and no file is read through it; every field of a result file other than the
  project folder is still taken as Lantern's own when the file is a plain file of the right shape; rows of the right
  shape in a test run's record are believed, so a test program can have a call between two functions of the map
  marked as seen running, or added, that never happened; the sweep is POSIX only.
- Security: Lantern's results are written into the results folder and nowhere else (2026-11-10; stage 7 of the
  2026-11-09 directive, part 3). The results folder lies inside the analysed project by default
  (`PATH/.lantern`), and a project comes from anywhere: a link somebody sent, a zip, a clone. Every result file
  was written with a plain write, which follows a link and waits on a pipe. Measured on the code before: a
  project that brought `.lantern/security.json` as a link to a file of the person's own had that file overwritten
  with Lantern's results (the same for each of the nine files `lantern analyze` writes, for a record in the cache
  of explanations and for `lantern-accepted.json`); one that brought `.lantern` itself as a link to a folder had
  Lantern's files made in that folder, by the command line, the app and the connector alike; a pipe under a
  result file's name held the run up for good; a folder there ended it with a Python error, after the whole
  analysis. Now a result file is written into a new file beside its place and moved there in one step
  (`results.write`, the one way every result file is written): a link at that place is replaced by Lantern's own
  file and what it pointed at is left alone, a pipe is replaced the same way, and the run says what it met
  (`note    security.json in the results folder was a link; Lantern put its own file in its place and left what
  the link pointed at alone`). A results folder that is a link inside the project, or is reached through one
  (`--out PROJECT/build/out` where `build` is a link), is refused in plain words before anything is analysed
  (`results.folder`; the command ends with 2, the connector answers with the sentence, the app gives it as the
  reason the check did not run and shows the project as not checked yet instead of reading results through the
  link). A link outside the project is the person's own (results kept on another disk) and is followed as
  before. A folder under a result file's name is said before the run starts. Two things that come with writing
  this way: a result file is now whole or as it was (a write that stops half-way leaves the file of the run
  before; before, the file was emptied first and filled afterwards), and a result file the person closed to
  other users stays closed. A result file this user may not change (marked read-only) is not replaced: the run
  says so before it starts (the older way stopped at such a file as well, with a Python error after the whole
  analysis). The cache of explanations is not kept through a link, and reads only plain files.
  `lantern export --sarif FILE` still writes a name outside the project as the person wrote it (a link of their
  own, `/dev/stdout`); a link inside the project is replaced by the file. Changed for a person who made
  `.lantern` a link themselves: that is refused too, and `--out FOLDER` names the other place instead.
  `tests/test_results_folder.py` (49 tests, each refusal beside a safe twin; 3 of the 49 need Windows: a junction
  as the results folder, a junction and a symbolic link under a result file's name; 1 needs a user who is not
  root). On the code before, with the new names answering the older way, 38 of them fail (2 of the 38 only meet
  a name that did not exist yet) and 7 pass: the six safe twins and the file that stays closed, which the older
  way of writing did rightly. Not covered: a link put in place between Lantern's look at the folder and its
  write (that takes another program of the same computer writing in the project at that moment); a run that is
  killed in the middle of a write leaves a file named `.<name>.<16 letters and digits>.part` beside the result
  file, which nothing reads.
- Security: what a project's dependency files say is checked before it is used (2026-11-10; stage 7 of the
  2026-11-09 directive, part 3). A lock file comes with the project, so it is as untrusted as the code. Until now
  the names and versions in uv.lock, poetry.lock, pdm.lock and Pipfile.lock went unchecked into the file Lantern
  hands to pip-audit. Measured on the code before: a "version" that goes on after a line end put lines of its own
  into that file (`-r /etc/hostname`, `-e /etc`, another index address), Lantern's record said `ok`, and the real
  pip-audit took the file with such a line and went on to its questions. One entry pip-audit cannot read (a version
  such as `1.0-SNAPSHOT.final`) made it give up on every package, the vulnerable ones included. Entries Lantern
  could not use were left out without a word: of a composer.lock with 4 entries 1 was checked and the other 3 were
  named nowhere, of 4 gems in a Gemfile.lock 2 were checked. And a dependency file of an unexpected shape (a list
  where a table belongs, a number where a name belongs) ended the whole analysis with a Python error, `--offline`
  or not: 14 of the 14 shapes tried.
  Now only a package name and a version of the form the ecosystem defines leave Lantern (`depaudit.PY_NAME`,
  `PY_VERSION`, `MAVEN_NAME`, `MAVEN_VERSION`, `COMPOSER_NAME`, `COMPOSER_VERSION`, `GEM_LINE`; plain ASCII, with a
  length limit). Whatever else an entry holds is counted and named in that audit's record (`not_read`, and
  `errors` with the first 20, each one line of printable characters; the audit's state is then `partial`, so the
  report, the badge and `--fail-on` treat the scan as incomplete), and the rest is still checked. What has no
  released version to look up is counted as not checked (`unpinned`, with examples), as ranges already were: a
  Composer library installed from a branch, a Pipfile.lock entry from a link or a folder, a lock entry with no
  version, a Gradle catalog library with no version, a range or a variable. The Evidence Report's Limits say how
  many, whatever state the audit ended in, and the readiness check for pinned versions names a part of a manifest
  it could not check first. A dependency file is read only when it is a plain file of at most 32 MB (a pipe under
  such a name, also under the composer.json or Gemfile beside a lock file, held the audit up for good), a
  byte-order mark at its start is passed over (such a file was unreadable before), and an audit that raises
  anything nobody foresaw becomes that audit's `failed` record (`depaudit.guarded`), in `lantern analyze` and in
  the cloud's audit step alike.
  Files as people have them change nothing: on 32 real lock files of public projects all 6,002 names and versions
  are the same before and after. 33 entries in six of those files have no exact version (branches, catalog
  libraries with no single version); they were dropped without a word before and are now counted as not checked.
  The version pattern agrees with pip's own parser on 300,000 random strings. `tests/test_lockfiles.py` (55 tests;
  with the real pip-audit only as its dry run, which asks nobody). Not changed: `npm audit` still reads
  package-lock.json itself. An audit that is skipped (`--offline`, or its tool is not installed) names odd entries
  only when nothing in those files could be used; where some entries are usable its record says that it was
  skipped, and the odd ones are named by the next run that asks.
- A project file of the wrong shape no longer stops the analysis (2026-11-10; the same stage). A manifest comes
  with the project too. `"dependencies": "x"`, `paths = 5`, a list where a table belongs: each is valid JSON or
  TOML, and each ended `lantern analyze` with a Python error, so one odd line in a project could keep it from
  being checked at all. Measured with a new sweep (`bench/manifests.py`: every value in 21 kinds of project file
  replaced, one at a time, by 21 other values, and the whole analysis run offline on each): on the code before,
  839 of 11,652 variants stopped the analysis, at 50 lines of Lantern's code in 11 files (package.json 40 of 965,
  tsconfig.json 113 of 502, app.json 19 of 730, pyproject.toml 98 of 1,861, Pipfile 24 of 344, a notebook 102 of
  752, lantern-accepted.json 13 of 168, a project pack 69 of 672, uv.lock 56 of 385, Pipfile.lock 43 of 419,
  composer.lock 19 of 522, the Gradle catalog 45 of 465, an earlier security.json 55 of 354, baseline.json 84 of
  584, explanations.json 59 of 459; six kinds that are read as text, 0 of 2,470). Now: 0 of 11,652. An odd value
  costs the one fact it would have given and nothing else (`lantern/manifest.py`): the other dependency section
  of that package.json is still read, the other aliases of that tsconfig still lead to their files, the other
  rows of `lantern-accepted.json` still count, the other cells of that notebook are still read. A project pack
  with an odd part is skipped whole and named with the reason, as a pack with any other problem already was. An
  odd dependency section of a manifest is named by the readiness check for pinned versions ("package.json: its
  devDependencies are not a table, so the versions there were not checked"); any other odd part of a manifest (an
  alias, a script, a notebook cell) is passed over without a line in the report.
  The same for what an earlier run left in the results folder. A `security.json`, `baseline.json` or
  `explanations.json` that was cut off (the computer was switched off while it was written), emptied, or changed
  by hand ended every later `lantern analyze` of that folder, until somebody deleted the file. Now such a file is
  passed over and the log says so in one sentence of fixed words, never text from the file
  (`lantern/results.py`): without the earlier `security.json` the run does not say which findings were there
  before; without `explanations.json` the report is written without a model's explanations; a `baseline.json`
  that cannot be used is neither compared with nor replaced (it may be the only record of the first analysis: a
  merge can leave it with conflict marks), the Evidence Report says in its Limits that it does not know what was
  fixed, and `lantern evidence PATH --reset-baseline` starts a new one. Only a plain file is read back: not a
  link, a folder, a pipe (which held the run up for good) or a file over 256 MB. The commands that are about a
  finished run (`lantern report`, `evidence`, `explain`, `verify`, `export`, the connector's tools) still read
  its files strictly: passing a damaged scan result over there would turn it into "no findings". The app, Ask
  Lantern and the Learn tab read them with readers of their own, which are not changed here.
  Also fixed on the way: a project pack whose route entry leaves `detail` out, a tsconfig alias that points at
  the root folder, and a JSON manifest saved with a byte-order mark each stopped or blinded a reader.
  `tests/test_manifests.py` (117 tests: the cases the sweep found, the top level of every file in four other
  shapes, projects as they should be, which give every fact they gave before, and 47 that hand the reader of
  earlier results one value of the wrong kind at a time). On the code before, 166 of the 172 new tests of both
  entries fail (111 show the fault; 55 only meet a name that did not exist yet, the 47 just named among them)
  and 6 pass: the three of projects and results as they should be, the top level of two files that stopped
  nothing before either, and one that holds on to what "seen in the run before" already said rightly (a mistake
  planted in those two lines went unnoticed by every older test). The sweep is not part of CI (about two
  minutes); run it after changing how any of these files is read.
- Security: a git folder that is not yours no longer puts its commit on your report (2026-11-10; stage 7 of the
  2026-11-09 directive, part 3). Since the git-settings fix of the same day (further down) nothing in a git folder
  is obeyed, but a git folder was still read whoever it belonged to, also when it was found in a folder above the
  one analyzed. On a shared computer anybody can make one there: `/tmp/.git`, `C:\.git`, a `.git` in a shared
  projects folder. Every project beneath it that has no git folder of its own was then reported with that user's
  commit, branch and address, and with "no uncommitted changes": an Evidence Report that seemed to pin the code to
  a commit somebody else chose. git itself refuses such a repository.
  Measured on the code before (as root, git 2.43.0), with a real other owner: a project folder inside a repository
  whose `.git` belonged to another user was reported with that repository's commit, its branch, its `origin`
  address and no uncommitted changes, where git answers `fatal: detected dubious ownership`. A second fault was
  found on the way, in the cloud service: where the folder the service works in lies inside a repository (a
  developer's checkout, a demo started from one), an upload with no git folder of its own got that repository's
  commit in the run's record and on its evidence page.
  Now Lantern keeps git's own rule for everything of a repository that lies outside the folder you asked about: a
  `.git` in a folder above and that folder, the place a `.git` file names, the folder a linked worktree shares.
  Each must be yours (for root also the user `sudo` came from; on Windows also the Administrators' when you are one
  of them, `lantern/winowner.py`), or you must have named the repository in git's `safe.directory` list. git itself
  is asked for that list, in a git folder Lantern makes, so your own settings answer and never the project's. An
  owner the system does not tell (an error, a network name on Windows, a disk that keeps none) counts as nobody's.
  Otherwise the report says "not pinned: no git commit", and why. The folder you name yourself is read whoever owns
  it, as before: you named it, and nothing in it is obeyed. The cloud service reads a run's commit only from a git
  folder inside the run's own code, without starting a program, and tells every step to look no higher.
  What changes for a repository of your own: nothing. What can change: a repository in a folder above the one you
  analyze that is not yours (a shared checkout, one made by another account or through `sudo`, a folder mounted
  into a container under another user) gives no commit until you name it
  (`git config --global --add safe.directory <its folder>`), which is what git asks for there too. In one place
  Lantern is stricter than git: on Windows git takes your home folder for yours even when the system owns it;
  Lantern does not, so a repository kept in the home folder itself gives no commit to a folder beneath it for a
  person who is not an administrator, until it is named the same way. In one place it follows your own word
  further than git for Windows does: an entry of that list stands for the folder it names however the folder is
  spelled (a link, a Windows short name such as `C:/Users/RUNNER~1/...`); git for Windows 2.56 takes it so for a
  whole path and not for an entry that ends in `/*`.
  Tests: 22 new ones in `tests/test_gitfacts.py` (66 in all) and 1 in `tests/test_cloud_runs.py`; one existing test
  in each file was extended. On the code before, 20 of the 22 fail (10 show the older answer, 10 try functions that
  code does not have) and 2 need Windows; the new cloud test and both extended tests fail as well. With the change,
  here: 62 pass and 4 need Windows (2 a junction, 2 Windows itself), and all 34 of `tests/test_cloud_runs.py` pass.
  Not covered by CI, and said in `docs/audit/CLAIMS.md` (A4f): the test with real other owners needs root; on
  Windows the calls are tried against Windows itself by two tests only, and the path for an administrator who is
  not elevated against a stand-in only.
  GitHub's first run of this change on Windows failed: 1 failed, 1124 passed, 68 skipped. Both Windows-only tests
  passed in it (the calls work against Windows itself, and a `.git` given to another owner with `icacls` got git's
  own answer). The one failure was a line of a test that compared with git for a `safe.directory` entry spelled
  with a short name, the difference described above; the test now writes its entries with the folder's real name
  and keeps the other spelling as lines of its own.
- The cloud service deletes only what it made, and a delete that fails is written down, said and tried again
  (2026-11-10; stage 7 of the 2026-11-09 directive, part 2). Measured first, on the code as it was, in nine
  situations, as root and as an ordinary user, on the Python the live image runs (3.12); both users gave the same
  results. When the service started, it deleted everything it found in its work folder and its uploads folder: a
  folder and a file that were not Lantern's, a person's folder that was only named like a run's, a `.zip` that was
  no run's. A link in the work folder, named like a run's folder, had the folder it pointed at (read-only before)
  set to owner-only, and the link stayed. A person who deleted a run while the disk refused deletes was answered
  `{"deleted": "<id>"}`: the run's 8 result files stayed on the server, nothing was recorded, and neither a healthy
  disk nor a restart removed them. The same 8 files stayed for good when the service was cut off between deleting
  a run's record and its files. A retention pass that failed every hour told nobody: nothing in the owner's
  statistics, nothing on the health page. A repository whose folders are nested 1,100 deep left its run "running"
  for good, its owner was refused every new check ("You already have a run going"), and after a restart the service
  did not start at all (RecursionError). On a person's computer, copying a repository into a folder that already
  held files failed in git, and the folder was then deleted with the files in it; removing a clone whose path was a
  link set the folder it pointed at, and the folder around it (shared by all users, in the test), to owner-only and
  left the link.
  Now there is one way to delete (`lantern/removal.py`): never through a link, nothing changed outside the thing,
  any depth of folders with one folder held open at a time, and an answer that says what stayed and the system's
  reason, with no name from inside. The cloud service has one place that deletes (`cloud/lantern_cloud/cleanup.py`).
  It removes by name, never by a path it was handed, and only what the service made: a run's result folder, a work
  folder that carries the mark file the service writes into each one it makes, a half-received upload, the upload
  of a run that is over. Everything else in its three folders is left alone and counted for the owner. Each removal
  is written down before it starts (table `leftovers`; for a deleted run, in the same transaction as the delete)
  and the record goes when nothing is left, so a service cut off in the middle finishes at its next start. A
  removal the system refuses keeps its record with the reason and is tried again at each start and every hour. The
  person is told: deleting a run or an account answers `files: "removed"` or `"waiting"`, and the website says
  "Deleted, with one thing still to do" when files wait. The owner is told: `/v1/admin/stats` has `cleanup` (how
  many things wait and since when, the reasons, how the last pass ended, how many things in the folders are not
  the service's; never a run id or a name), `/v1/health` says one word (`ok`; `behind` after 24 hours; `unknown`),
  and the uptime check fails on any word but `ok`, which is a mail. A run is recorded as ended whatever its
  tidy-up does, and nothing in the start-up sweeps or the hourly pass can keep the service from starting.
  Explanations are saved so that "Nothing was changed" is true when a save fails: each rewritten page is written
  beside its old one and put in its place only when all are written (before, with the disk refusing the third of
  the four pages, the explanations and the report were already replaced while the message said that nothing was).
  Three more defects were found on the way and fixed, each with a test written first. (1) The service took a run's
  result files, and the explanations and their cache, out of the finished step's folder with copies that follow
  links (`shutil.copyfile` after `is_file()`, `shutil.copytree`). The step runs with fewer rights than the service,
  so a step that was taken over could leave a link and have the service read the link's target for it: in the
  tests a file from outside the run landed in the run's results (as `graph.json`, as `report.html`, as
  `explanations.json`, in the cache), where the run's owner can download it. Now only plain files are taken, each
  reached from the step's folder held open, never by a path (`worker._take`, `_take_tree`, `_there`): a link, a
  file that has a second name somewhere else (a hard link), a folder, a pipe, or the folder itself being a link
  ends the run or the explanations with "Lantern's own step left something that is not a plain file where a result
  belongs", and nothing of that step is kept. (2) Explanations stopped at the time limit said "The ones already
  written are kept; click Explain again to go on" and threw them away with the work folder, so every new try paid
  for the same explanations again from the person's allowance (in the test: 25 paid for, 0 kept). Now they are
  kept with the run, and the next try asks for none of them again; when they cannot be kept the message no longer
  says so. (3) One saved explanation that was cut short while it was written (the program was stopped, the disk
  was full) stopped every later explain of that project with an error, in the cloud and in the app, until somebody
  deleted the cache folder by hand. Now that one is asked for again and written anew (`explain.Cache.get`), and
  the cloud keeps each cache file whole or not at all.
  The same nine situations on the new code (root and an ordinary user, Python 3.12, the same results for both):
  nothing that is not Lantern's was deleted or changed (situations 1, 2, 3, 7 and 8); the delete that could not
  remove its files answered `files: "waiting"`, the statistics said "8 things in it could not be removed; the first
  reason: no permission (PermissionError 13)", and after the restart 0 files were left (4); the failing retention
  pass is in the statistics (`last_pass`: `ok` false, `RuntimeError`) (5); the repository nested 1,100 deep ended
  `done` and left nothing, its owner's next check was accepted, and the service started again (6); the cut-off
  delete was finished at the next start, 0 files left (9).
  On a person's computer: `remote.fetch` refuses a folder that is not new or empty before anything is copied; a
  failed checkout removes the folder only when Lantern cloned it (that very call, Lantern's mark, or Lantern's own
  repos folder), so a repository folder of the person's with no files checked out stays; the error after a failed
  clone ends with what could not be removed; a sandbox temp folder that could not be deleted is written down
  (`LANTERN_HOME/leftovers.json`) and deleted when the next test run starts, only if it is still the same folder.
  Changed answers (`docs/api.md`): `DELETE /v1/runs/{id}` and `DELETE /v1/me` gain `files`, `/v1/health` gains
  `cleanup`, `/v1/admin/stats` gains `cleanup`. `docs/terms.md` gains one sentence saying the same to the person.
  At the first deploy of this version: a work folder that a cut-off run of the older version left is no longer
  deleted at start-up (it has no mark); `docs/deploy.md` ("Clean-up") says how to see and remove it, and what the
  count `left_alone` means.
  Tests: 89 new ones, each dangerous case with a safe twin: `tests/test_removal.py` (37),
  `tests/test_cloud_cleanup.py` (39), 8 more in `tests/test_cloud_ai.py`, 3 in `tests/test_explain.py`, 2 in
  `tests/test_uptime.py`. Run on the code from before this change: 70 failed and 3 passed (the 3 are checks of
  ordinary cases that must keep working: a plain folder is removed, a failed copy into a new folder leaves
  nothing, a service that says nothing about clean-up passes the uptime check). The other 16 were not run there:
  14 try the new copying functions directly, which the older code does not have (the same defects are shown on
  the older code by 11 tests that go through the service), 1 reads the website's new note, 1 is the safe twin of
  the link tests. One older test was moved to where an older Lantern kept its clones
  (`test_an_earlier_clone_without_files_is_checked_out`: its folder lay outside Lantern's repos folder with no
  mark, which is now a folder of the person's and is kept). The browser check deletes a run whose files cannot be
  removed and reads the note. Found and not fixed: the restricted step can still read whatever its user can read
  (its second wall, Landlock, limits writing and the network, not reading), and the cloud image runs the service
  and its steps as one user, so a step that was taken over could read another run's results and write them into
  its own report (`docs/audit/THREAT_MODEL.md`, open risk 0). Taking only plain files closes the way through a
  link, not this one. Also found, at the end of this part: a folder's own git settings were obeyed when Lantern
  asked git about that folder. That has its own entry below ("Security: the git settings of a folder Lantern
  reads are no longer obeyed"). Known limits:
  `docs/audit/CLAIMS.md` (C2, C5, C8 to C13, L7) and CLAUDE.md's Known gaps.
- A project's tests are not run without their sandbox, and nothing they start is left running (2026-11-10; stage 7
  of the 2026-11-09 directive, part 1). Measured first, on the code as it was, with a planted test that starts
  three programs (a plain child, one that moves to its own session, a daemon): all three were still running after
  the tests had ended; two of the three after the time limit, while the log said "every process it started was
  ended"; and all three, with the test command itself, after Lantern was killed. When the kernel refused the rules
  that keep writes inside the sandbox's temp folder, the launcher printed "Landlock restrict error 7" and ran the
  tests all the same. They also ran when the guard that refuses writes and network connections was not in their
  Python, which is what happened for root with new files made owner-only (`umask 077`): a planted test sent a
  network packet and nothing was refused. On Windows no answer of the calls that build the Job Object was looked
  at (tried against a stand-in for Windows' own library: when Windows refuses to put the tests in the job they run
  outside it without a word, and the job's handle stays open). Deleting the sandbox's folder changed the mode of a
  folder outside it that the project's copy held a link to, and when the folder could not be deleted it set the
  folder around it to owner-only (the system's temp folder, for every user, when Lantern is root). As an ordinary
  user, a test that left a folder with every right taken off stopped the run with a `TypeError` and left the copy
  of the project on disk.
  Now the tests are not started when a restriction the sandbox counts on cannot be put in place (the kernel
  refuses the Landlock rules, the no-new-privileges switch or the change to the unprivileged user; the guard is not
  in the tests' Python; a Windows call that builds or fills the Job Object fails, each one checked and named with
  its error number in the new `lantern/winjob.py`; the project cannot be copied; Docker could not start its
  container). The check of the code goes on, and the results say that the tests were not run and why, in Lantern's
  own words: `run.json` (`trace.ran` false, `trace.unavailable`), the score ("Tests pass" is left out, not failed),
  the Evidence Report's Limits, and the app ("Your tests were not run."). A system that has fewer walls by design
  (a Linux kernel with no Landlock, macOS, Windows) still runs tests with the walls it has, listed on the sheet.
  Nothing a test run starts outlives it: on Linux the launcher stays as the command's supervisor and ends every
  process beneath it (also one that moved to another session or became a daemon) when the tests end, at the time
  limit, on a stop, when the app closes and when Lantern is killed; on Windows the Job Object does; with Docker
  the container is removed and the answer read. The app has a **Stop the tests** button
  (`POST /api/jobs/<id>/stop`); a stop changes no result (in the browser check the tests were ended 0.8 seconds
  after the click). What could not be ended is said (`not_ended`, the log, the app's message), and nothing says
  beside it that everything was. A test run stopped at the time limit reads "stopped at the time limit" in the
  score, not "exited None". Deleting the sandbox's folder changes nothing outside it and the log names a folder
  that is still there.
  The cloud service's steps go through the same launcher: a step is ended with everything it started when the
  service shuts down (the run then fails with "Lantern was shut down while this run was going. Start it again.")
  and when the service's process is gone. One silent case was found there and fixed: as root with owner-only files
  the analysis step ran without its guard (tried with a stand-in for that step which sends a packet to this
  computer: the packet went out; now it is refused and the run ends `blocked`). These steps read a project and
  never run it, so without Landlock or the guard they say so in the run's log and carry on.
  Found by CI on this change itself, and fixed (same day): when the app was closed while a project's tests ran,
  Lantern ended the tests and then left before the run had tidied up. Measured on that code: the copy of the
  project stayed in the temp folder in 20 of 20 tries, without a word; on a busy computer the run's last log line
  was lost in 4 of 25 (and the copy stayed in 25 of 25); and on CI a small program that prints its log was taken down as it left, in two of the
  four Linux test jobs that finished ("Fatal Python error ... at interpreter shutdown"). Closing the app now waits until each run has logged
  its last line and deleted its temp folder (0 of 20 left, 0 of 20 with a slow log, 0 of 25 on a busy computer),
  and a run that was still copying the project when the app closed starts no test at all (before, such a run
  was told nothing: it went on, and could start the tests while the program was leaving).
  Tests: `tests/test_sandbox_safety.py` (new), six more in `tests/test_cloud_runs.py`, and the browser check now
  presses the button. Not proven here: Windows itself (four tests that only CI's Windows job runs). Known limits
  are in `docs/audit/CLAIMS.md` (A4d, A4e) and CLAUDE.md's Known gaps.
- Security: the git settings of a folder Lantern reads are no longer obeyed (2026-11-10; found during stage 7 of
  the 2026-11-09 directive). `lantern analyze` asked git about the folder it was given: `git status` for
  uncommitted changes (`evidence.git_info`) and, for a folder that carries the mark of a Lantern clone,
  `git ls-files --deleted` (`remote.missing_files`). git obeys the folder's own settings file, `.git/config`, and
  that file can name commands: `core.fsmonitor` is run whenever git reads the index, a clean filter when a file's
  content has to be compared, and `git status` starts itself inside every submodule under that submodule's
  settings. `git clone` never copies such settings, but a folder that arrives another way brings its `.git` as it
  is: an unpacked archive, a download, an upload to the cloud service.
  Measured on the code before, with commands that only write a marker: a planted `core.fsmonitor` was run by
  `lantern analyze` (through `git status`, and through `git ls-files` once the folder carried the clone mark,
  which anyone can write); a planted filter was run; a command in a submodule's settings was run. In the cloud
  service the command of an uploaded zip ran inside the analysis step, where the service runs as root (the step
  is then the user `nobody`) and where it runs as an ordinary user. The step has no network and may write only in
  its temp folder, but it may read what its user may read, and the cloud image runs the service and its steps as
  one ordinary user: in a local set-up of that kind, with a stand-in file, text from another person's stored
  result ended up in the uploader's own stored result, in a run that ended "done". The same code also followed a
  `.git` file, a `commondir` file or a link to another repository of the computer and reported that repository's
  commit and `origin` address as the folder's; obeyed `GIT_DIR` and its like when they were set in the shell (as
  inside a git hook); said "no uncommitted changes" when git could not compare the files at all; and let git
  rewrite the folder's index.
  Now (`lantern/gitfacts.py`) the folder's `.git` is read like any other file of the project: where the
  repository is, the commit, the branch and the address of `origin` are read by hand, never through a link and
  never through a `.git` file that names a place which does not name the folder back. git itself is started only
  on a git folder Lantern makes for the occasion, whose settings file holds nothing but a short list of yes/no and
  fixed-word settings copied from the project (how line ends and file modes were written to this disk); it reads
  the project's index, objects and files from there and none of the project's settings. Submodules are looked into
  one by one in the same way, never by git, and only where they are real folders inside the project. The cloud
  service reads an upload's commit without starting any program, and its steps are no longer told to trust every
  folder's git settings (`safe.directory=*`). When the files cannot be compared, they count as changed and the
  Evidence Report and each finding's case say why (`header.note`, `where.revision_note`); a git folder that is not
  read is named on the report too.
  What changes for a repository of your own: nothing, unless its `.git` is a link or was made with
  `git init --separate-git-dir` (no commit is reported, with the reason), it keeps its refs in the reftable form
  (the same), or it relies on a filter or a submodule-ignore rule that only its own settings define (a file can
  then count as changed). In the other direction: a repository that belongs to another user of the computer,
  which git itself refuses unless the person listed it (`safe.directory`), is now read, also from a folder above
  the one analyzed (before, no commit was reported for it). Nothing in it is obeyed; a rule of Lantern's own for
  whose git folder may be read is not part of this change (it followed the same day: the first entry of this
  section). The person's own git settings, in the home folder or
  the computer's, still apply.
  Tests: `tests/test_gitfacts.py`, 44 tests kept apart by kind: planted settings, pointers and variables that
  must not be obeyed (24); what cannot be told, which must be said (3); repositories as people have them, which
  must get the answers git itself gives (13: plain, packed refs, detached, linked worktree, shallow, sha256,
  sparse checkout, submodules, line endings); the settings reader against git's own (1); and the limits (3). The
  reader keeps a tab written inside a value as a tab, which is git's own reading since 2.45; older git made it a
  space, so that one value is asked of git only as one of the two (GitHub's first run of these tests, on git
  2.56, failed on it: written beside git 2.43, the reader made it a space, and the test said so). On
  the code before, 28 of them fail (17 show a defect, 11 test the new reading, its words and its limits), 14 pass
  and 2 need Windows; with the fix 42 pass and 2 need Windows. `tests/test_cloud_runs.py` has
  2 more (an upload with planted git settings; the service starts no program to read a commit): both failed
  before. One existing test of `tests/test_remote.py` now makes git fail for real instead of through a stand-in.
- CI runs every test, and its log names each test it skips (2026-11-10). CI's test jobs installed neither PyJWT nor
  cryptography, so `tests/test_cloud_github.py` was skipped while it was imported: its 14 tests (a private
  repository is opened only for a person GitHub says may read it) counted as one skipped test, `pytest -q` named no
  skipped test, and the runs were green. Found while counting the skipped tests of the entry below: 1,052 tests on a
  developer's computer, 1,039 in CI. Now the `dev` extra holds what the tests need (`PyJWT[crypto]`, pinned in
  `requirements-lock.txt` with what it brings: cryptography, cffi, pycparser), and CI and the release build run
  pytest with `-rs` and with `LANTERN_TESTS_COMPLETE=required`: there a test file or a test that is skipped because a
  library is not installed fails the run and is named with the library. The one-command audit prints its skipped
  tests also when the run passed. A developer's own run without those libraries still skips and says so, and a test
  skipped for another reason (another operating system, a program that is not installed) is not touched.
  The first log that named its skipped tests showed four more that CI's test pass does not run, all four tests of
  the isolation itself (`tests/test_netguard.py`): two need root, one starts the no-network runner (which cannot be
  started inside itself without root) and one needs a way out for the refusal to show, while CI's tests run as the
  ordinary user inside the no-network runner. Three of them ran nowhere in CI, the fourth only in the one-command
  audit of the Python 3.13 job. CI's Linux jobs now run that file a second time, as root and with the
  computer's ordinary network (the guard refuses and records as everywhere), with
  `LANTERN_TESTS_COMPLETE=no-skips`: there a test that is skipped, whatever the reason, fails the run and is named.
  One of the four failed when the session itself was started through sudo (the runner went back to the user who
  called sudo, who cannot write where root's test keeps its files); the tests no longer hand sudo's variables on
  (`_bare_env`). And a test file that is skipped while it is imported is now named by every run ("test files skipped
  whole"): pytest counts such a file as one skipped test whatever it holds and names the line that skipped, which is
  in another file when the skip came with an import. On Windows that is four files with 53 tests (the cloud worker
  runs on Linux), two of them named nowhere in the log before; `20 skipped` there means 69 tests that do not run.
  That second pass failed on its first run in CI, and what it found is fixed. One: a program that root starts under
  another user started with no network guard in it where that user cannot read the folder the guard is in. Python
  leaves a folder it cannot read out of its path without a word, CI's checkout is under a home folder that others
  may not enter, and the test's program tried its address and carried on (a documentation address: nothing was
  reached). For root, where that folder is closed to others, the programs of a run now load the guard from a copy
  that every user can read and only root can change (`guard_folder`), so such a program is refused and stops like
  any other. The copy is one folder with two files, in `/run` (or `/tmp`), named after its content. It stays when
  the run ends: a program still going would otherwise start its next one from a path whose first folder is gone,
  and Python passes over that as quietly as over a folder it cannot read. The next run uses it again, and only if
  it is root's own, closed to everyone else and the same byte for byte. Two folders that hold the guard on the path
  used to start each other until Python gave up, and the next start-up file never ran; the path now holds one, and
  the start-up file passes any other by. Two: both of CI's Linux passes start through sudo, and the sudo of
  GitHub's machines (sudo-rs) hands a command none of the caller's variables: "preserving the entire environment
  is not supported, '-E' is ignored". So where that sudo ran, neither `LANTERN_TESTS_NETLESS=required` nor
  `LANTERN_TESTS_COMPLETE=required` reached the tests of the Linux jobs, from the commit that set each: in both
  runs whose logs were read for this (commits 1a2bc59 and eaf4045) sudo printed that line before each pass. Those
  runs were inside the no-network runner all the same (its last line and the recorded addresses say so: 0 outside),
  but a test skipped there for a missing library would not have failed that pass; the Windows job, the audit pass
  and the release build, which do not start through sudo, were held to the rule. Each rule is now written on the
  sudo line itself, a run under a rule names it in its last lines ("rules of this run: ..."), and each of the two
  steps looks for its rules there and fails without them. CI also waits for Docker before the tests: in one of the
  six Linux jobs of that run `docker info` did not answer and the four Docker sandbox tests were skipped (the log
  named them).
- Tests and benchmarks can no longer reach a real AI provider or the internet, and never see the keys of the person
  running them (2026-11-09). Before, a full test run made 11 connections to the outside (6 by a `pip-audit` program one
  test started, 5 to the OSV vulnerability database from the set-up of five test files), a test could read 13 of 19
  keys planted in the shell and the saved sign-in, and code that hid a connection error let the attempt pass unseen.
  Now every run starts in an empty temporary home folder with every key, token and saved sign-in taken out of the
  environment, real model providers switched off (`LANTERN_NO_REAL_PROVIDERS`: only a model on this computer may
  answer, anything else is refused with a plain error), and every connection or name lookup that is not for this
  computer refused and written down, in the tests and in the programs they start (`tools/netguard/`). A test that
  tries the network fails, also when the code under test swallowed the error, when the attempt was made by a program
  it started, or in a set-up step; so does the run when something tries outside any test. On Linux, CI also runs the
  tests in a network that holds nothing but the computer's own address and has the operating system write down every
  address any program tries (`tools/netless.py --watch`); the measured count after the change is 0. The benchmarks
  (`bench/run_bench.py`, `bench/mobile/run_mobile.py`, `bench/heldout/run_heldout.py`, `bench/fuzz.py`,
  `tools/large_apps.py`, `tools/mutation.py`, `tools/load_test.py`) and `tools/audit.sh` start the same way and may
  only reach the hosts they name (the repositories they clone, the three addresses the dependency audit asks); the
  load test refuses any website that is not on this computer. The held-out benchmark starts each analysis as a Python
  program in isolated mode (`-I`), which reads nothing from the variable the guard uses to get into a program, so the
  plain way left the guard out of it; it now starts through the guard (`python_isolated`). The two scripts that measure a real model (`bench/explain_eval.py`, `bench/ask_eval.py`,
  the `model-eval` workflow) are now a separate live suite that starts only with `--live --model PROVIDER/MODEL
  --destination HOST --max-requests N` (and `--send-this-code` for code that is not a Lantern sample): there is no
  default model and no falling back to whatever key the shell holds, the model must be served from the approved host,
  and the run stops at the request cap and keeps what it has. Also fixed on the way: the CI step that runs the tests
  piped its output into `tee` without `pipefail`, so on Python 3.11 and 3.12 a failing test run could not fail the
  step (the same in the weekly large-apps job's phone and load checks).
  The browser checks keep their pages off the internet too (`tools/outside.js`): the app and the website ask the
  outside for one thing, their font stylesheet, which the one-command audit fetched from Google 26 times in one run
  with one browser (measured: 26 refused connections to fonts.googleapis.com). It is now answered inside the
  browser, so nothing is sent; anything else a page asks of the outside fails the check with the address, and a
  report may ask for nothing at all. A browser has more ways out than the requests its pages make (a connection it
  opens ahead of time because a page hinted at an address, a page nobody watched, its own housekeeping), so every
  browser a check starts, the report speed check included, now has a proxy on this computer as its only way out; the
  proxy forwards nothing, and a try for anything but the pages' font host, or an address the browser itself is known
  to ask of its maker (listed in `tools/outside.js`), fails the check with the address.
  Found by the new tests in their first CI run: the step that fetches the code left that run's own GitHub sign-in in
  the checkout's git settings, where every test and every program a test starts there could read it (all 13 checkout
  steps in the 7 workflows). No workflow leaves it now (`persist-credentials: false`); one test reads every workflow
  for it and another looks in the checkout the tests run in. A test about git's settings now names only the kind of
  setting it met, never the setting's name or value.
  Found in their second CI run: an older test started a check on the cloud service and returned; its stand-in for the
  download was taken away with the test, and the check, still going, asked github.com for the repository while the
  next test ran (refused, and that test failed for it). Every test now finishes the checks and explanations it asked
  the cloud service for before its stand-ins are taken away; measured on the whole suite that day, 3 of the 1,046
  tests that ran had left one going. The browser proxy also showed three things in its first run in CI. CI's
  Playwright (1.48.2; a developer's computer here has 1.63.0) sent Chromium's requests for this computer's own pages
  to the proxy as well, so the app under test got the proxy's refusal; the list of addresses that go round the proxy
  is now written so that both versions keep them out of it. On the website check WebKit and Firefox made 39 and 17
  tries for the font host that the first layer never saw, WebKit told the page about 17 refusals in its console, and
  Firefox asked its maker for a newer Firefox twice. All of these were stopped at this computer; they are now counted
  and shown instead of failing the check, and any other address, any other console line and anything at all in a
  report still fail. The one-command audit prints, for each browser, what the helper's own check found and what the
  first report and the website asked and tried, also when the check passed: Firefox and WebKit run only in CI, so
  CI's log is where their counts can be read.
- Every call is counted once, and Lantern follows far more of them (2026-11-09, directive stage 3). A new call-site
  inventory (`calls.json`, `graph.json` `meta.calls`) gives each call written in Python or JavaScript/TypeScript one
  record, by file, line and column, with one outcome (into the repo, likely, one of several, guessed by name only,
  library, built-in, or not followed) and, when Lantern cannot follow it, a reason in plain words ("`svc` is a
  parameter whose type Lantern cannot follow"). Functions handed to a framework (FastAPI `Depends`, Express route
  handlers and middleware) and test code are counted apart. The older edge-line count is kept unchanged beside it. The
  JavaScript reader now understands `require()`, `module.exports`/`exports.x`, constructor functions (`this.x =
  function`, `X.prototype.y`), handlers wrapped by a helper (`catchAsync(async (req, res) => ...)`), Express routers
  mounted with `app.use('/api', router)` (routes get their full paths, also when the router comes from a factory that
  ends `return router`), routes written `router.route('/x').get(h).post(h)`, route middleware (listed on the route,
  and the login check reads it), `req`/`res`/`next`, TypeScript parameter types, values a library call returned
  (`const app = express()`), chains on library results, and DOM lists, events and fetch responses. A route line whose
  handler is made by a call (`router.post('/login', passport.authenticate('local'))`) is no longer taken for an
  outgoing web request. Python follows methods a class inherits from a library (`self.assertEqual`,
  `Note.objects.filter`, `n.save()` on a model), calls on a library call's result (`pandas.read_csv(p).head()`), names
  that arrive through `from x import *` of a project file (a package `__init__` that re-exports its modules included),
  and router prefixes from `include_router` (FastAPI) and `register_blueprint` (Flask). Lantern does not call
  something a library when it cannot know: a class with a parent class it cannot look into, and a name imported from a
  project file that is not there (a relative import, or a path the project's `tsconfig.json` maps to a folder that is
  not in the repo, such as generated code), stay "not followed" and say so. Nor does it when the function may be the
  project's own: a function the project puts on a library's object (`schema.statics.paginate = function`, `res.fail =
  function`), a method of a project class the library hands back (`getRepository(User).findOne()`, Django's
  `get_user_model().objects.create_member()`, `req.user.can()`), a method a mixin gives a subclass, and
  `window.App.init()` are "not followed" with the reason, or keep the older name-only guess, instead of being counted
  as library or built-in calls. A route whose handler is a library's function is not marked as one of the app's entry
  points, and a middleware Lantern cannot read is judged by its own name, never by the folders it lives in
  (`./auth/rate-limit` is not a login check). An import that the project's `tsconfig.json` finds through `baseUrl`
  alone (`import { load } from 'lib/data'` with `"baseUrl": "src"`) is read as the project's own file; the old version
  took it for a package. Each rule has a test that failed before it and a twin that must stay unresolved. On the
  frozen held-out benchmark (14 apps, 9,532 calls written outside tests), calls not followed fell from 3,051 to 1,255
  (1,807 newly followed; 11 that the old version called "library" although they come from a generated file that is not
  in the repo now say so): from 244 of 288 to 74 on dvna, 276 of 441 to 140 on NodeGoat, 183 of 271 to 42 on goof, 441
  of 653 to 82 on express-boilerplate, 946 of 3,614 to 299 on pygoat and 121 of 791 to 103 on dvra. The command and
  code injections of NodeGoat, dvna, goof and the local Express app are now reached from their routes and ranked
  critical, so none of the vulnerable apps gets a green release, while the safe twins' false alarms stay at 3 of 17.
  The rules were written after reading these same apps' untraced calls, so a fresh set of apps would show a smaller
  gain.
- A scanner that fails can no longer read as a clean result (2026-11-09, directive "Engineer Lantern into a stronger
  full-stack release reviewer", stage 2). Bandit was run with `--exit-zero` and empty output was read as "no
  findings"; gitleaks wrote its report to the terminal and any trouble silently fell back to Lantern's small built-in
  pattern list while the record still said "ok"; pip-audit's and npm's empty or broken output counted as a clean
  audit, and a package pip-audit could not look up was dropped without a word; one OSV detail lookup failing dropped
  every finding of that audit. Every scanner now writes one record (`lantern/scanresult.py`): a state (ok, partial,
  failed, timed out, not installed, skipped), the reason, the tool's version, exit code, what it covered, the folders it
  was told to skip, and the files or packages it could not read; findings a tool did produce are kept when the rest of
  its run failed. Each tool's real exit codes are read (Bandit and pip-audit exit 1 when they find something; npm
  reports an error as JSON). The scanners that apply to a project and did not finish are listed in `security.json`,
  `readiness.json` and `run.json` as `incomplete`, fail the new readiness check "Every security scanner finished"
  (partial for a gap the run knew about, such as `--offline`), are named in the Evidence Report's memo, Provenance and
  Limits, make the badge say "scan incomplete" (never green), show on the app's project cards and above the findings
  in the report, and make `lantern analyze --fail-on` exit 1 (a deliberate `--offline` skip is listed, not failed).
  Scanners run through one bounded runner that kills the whole process tree at the time limit. Tests:
  `tests/test_scanners.py` (48) feed each adapter empty, broken and wrong-shaped output, a missing program, a timeout,
  an unreadable file and a partial failure, and follow the states to the command line, the app, the stored files and
  the readiness score.
- The rest of what Lantern's report on itself got wrong (2026-11-09). "Allow-list for outgoing requests" counted a
  list of the host names a server answers to (`ALLOWED_HOSTS`, lantern-cloud's settings) as a list of the places it
  may call; only an allow-list in a file that makes the requests counts now. An app-wide login check was read into a
  request hook that only counts visits (the 20 lines after it, which belonged to the next function); only the hook's
  own body is read now, and a word in Lantern's own pattern lists no longer counts as an auth library. Sign-out
  routes (`/signout`, `/sign-out`, `/log-out`) need no login. The Evidence Report's "verify it yourself" command
  installed the newest Lantern, which can give another digest once the analysis changes; it now installs the exact
  Lantern that made the report (the commit, written into the lantern-cloud image at deploy time, or the release tag).
  The scorecard says that low findings don't lower the score, so 100/100 beside open low findings reads as intended.

- Lantern's report on its own code told four things wrong (2026-11-09, found by checking the Evidence Report of run
  b51NcYcvaZzhuElb). Reports made on the website were titled "repo" for every project, because the code was read
  from a folder called `repo`; it is now read from a folder named after the repository (`Lantern`, `shop`), so the
  Evidence Report and "what keeps … safe" use the project's name. The "Protections" list marked rate limiting and
  upload checks "in place" because it found the words in Lantern's own advice text and pattern lists; strings and
  comments no longer count (the same line was also listed three times), and an item that is in place now says what
  was found instead of repeating the warning. Routes in test code (Lantern's sample apps under `tests/fixtures`) are
  no longer listed as "anyone on the internet can call them". A lock file no longer names frameworks the app does
  not use (Starlette and Click came from `requirements-lock.txt`), and the "N findings are heuristic" line counts
  only the findings the report lists.

- Sign out everywhere (2026-11-09; gateway 0.2.5). The website's account box and Settings have a "Sign out everywhere" button: after
  one confirmation it signs the account out on every computer and phone, in the Lantern app and in the terminal
  (gateway `POST /v1/auth/signout` with `{"everywhere": true}`, which needs a working sign-in, so nobody can sign
  someone else out). Results and the free allowance stay. A plain Sign out now also ends that browser's sign-in at the
  gateway instead of only forgetting it.
- Signing in somewhere new no longer signs you out everywhere else (2026-11-09; gateway 0.2.5). Each account had one
  token, and every sign-in (the app, the CLI, the gateway's own page, the website on another computer) replaced it, so
  the website's sign-in stopped working and asked again. Each sign-in now gets its own token and the earlier ones keep
  working, up to 8 places per account (the one used least recently is signed out first, and a place unused for 90 days
  is forgotten). All of an account's sign-ins share one allowance and one daily count, so signing in again never adds
  free use, and switching an account off still signs it out everywhere. Accounts from before keep their current
  token. The website also picks up a sign-in finished in the GitHub or Google tab after the page was reloaded or its
  sign-in box closed, instead of asking again.
- The intro's Sound and Skip intro buttons go away when the film ends (2026-11-09). They stayed in the corner of the
  end card, where there was nothing left to skip or hear; now the end card shows only its two buttons, Escape leaves it,
  and both come back when the intro plays again. Same on the website and the landing page; the intro still plays on
  every visit.
- Ask Lantern on the website says why it could not answer (2026-11-09). It used to say "The model did not
  answer" for every problem. Now it names the real one in plain words: your sign-in is no longer accepted (and the
  sign-in box opens), the model company refused Lantern's key or its account is out of
  credit, the model company is down or busy, the question is too big, or Lantern's model server cannot be reached.
  The server log records which one.
- The gateway's "You're in" page no longer prints your Lantern token (gateway 0.2.4, 2026-11-09). When nothing comes
  to pick the token up by itself, the page shows one Lantern button, "Copy my Lantern token", that puts it on the
  clipboard and then says "Copied. Now paste it into Lantern". A token on screen ends up in screenshots. The token is
  printed only if copying fails or the browser runs no scripts. The page's one script is allowed by its hash in the
  Content-Security-Policy, so nothing else can run.
- The Graph view says what its lines mean and lights up the chosen step's own lines (2026-11-09). A line with an arrow
  from A to B means A can call B, read from the code; only teal lines were seen running under tests. Clicking a box now
  makes its lines glow with a slow pulse, with dots moving the way the call goes: teal for what it calls, light for what
  calls it, while every other line fades back. The legend and "What am I looking at" say this in plain words, and each
  line's hover text reads "X can call Y · read from the code". With reduced motion the glow stays lit and nothing moves.
- A big project's report no longer leaves the website's run page empty (2026-11-09). Noetic Compass's report is one
  54,909,481-byte page; the cloud sent it uncompressed, and the frame stayed blank while it arrived (28 s on a 20 Mbit/s
  line in a test, longer on slower ones). Result pages and data files now go out gzip-compressed to browsers that ask
  (3,247,600 bytes for that page; 7 s on the same line), each still rebuilt with its own nonce, and at most two are
  built at once so reloading cannot pile up builds. The run page shows "Opening the report" with a counting clock
  until the report has loaded, and says big projects take longer after 12 seconds.
- Fixed two problems an independent review found (2026-11-09). (1) SQL built from text that was first fixed and then
  replaced with input through a `match` capture, `except … as`, or an inner function's `nonlocal`/`global` was called
  "only fixed text" and lowered from high to low; any of those bindings now means "not followed", so the finding keeps
  its rank. (2) `out = list()` was taken as Python's list even when the repo defines its own `list()`, takes a
  parameter named `list`, imports or assigns one; that erased a real link (`out.append` → the repo's `Box.append`).
  A rebound built-in name is now never counted as the built-in (an annotation such as `x: str` does not rebind it).
  On Noetic Compass b574170: no finding changed rank, no link changed, 28 calls move from "built-in" back to "not
  traced" (27,824 → 27,796; 28,519 → 28,547).
- Tests can no longer reach a real model or the network: provider keys and tokens from the developer's shell are
  removed, `LANTERN_HOME` is an empty folder per test, and connecting to any non-local address fails
  (`tests/conftest.py`). The review's full run had called a real model through an inherited key.
- Python built-in calls (`len`, `print`, a list's `append`) are now counted in the call-site total as their own group
  instead of being dropped without a count; they are still not drawn on the map. A method call on a local that is
  always a built-in literal in its function (`out = []` … `out.append(x)`; every binding of the name must be a literal
  of that one type, the name must not be a parameter, and the type must have the method) is counted as a built-in
  call instead of untraced. On one large app: untraced 33,318 → 28,519 call sites, and 23,025 built-in calls that were
  never counted now are; one wrong link (a list's `append` taken for a library call's result) is gone; no link to the
  app's own code changed on 15 other apps.
- How to use Lantern: a guide page at `/guide` (website and `lantern serve`), in the main menu as "How to use Lantern".
  A 60-second tour and 12 tasks, each with a short animated demo (one shared player, each demo is data: a simplified
  copy of Lantern's screens, a moving cursor, gold-glowing instructions), numbered steps and a Good to know box, plus
  keyboard shortcuts and a note on what is simulated. Demos play only while on screen, start paused with less motion,
  and are labelled "Animated demo · not a screen recording".
- Every finding outside test code now carries its case ("The case for this finding" on the finding card and panel, and
  `case` in `security.json`): where, at which revision; the claim in the tool's words; the evidence and where each fact
  came from; what has to be true for it to hurt, each marked yes / no / cannot check; the impact; why it has its rank;
  how sure Lantern is (lower when the path depends on a likely link); what is not known; and the status words reported,
  reproduced (same id as the previous run), fixed, tested and independently reviewed. Lantern never marks the last two
  itself. Ids are unchanged.
- A setting the browser can see (`VITE_…SECRET`, `NEXT_PUBLIC_…`) now says four things apart on its finding: that it is
  visible (and the header it travels in), whether server code checks it (where, and on which routes), that whether a
  stranger can get in is not determined from code alone, and what else guards those routes (other login checks, the
  settings the checking code branches on). It is never called a confirmed bypass, and its rank does not change.
- Two login-check mistakes fixed: a route decorator's `response_model=TokenResponse` and a request body typed
  `TokenRequest` (or `OAuth2PasswordRequestForm`) no longer count as checking who is calling.
- Every call site Lantern read is now sorted on one denominator (About page and Evidence report): linked for certain,
  likely, one of several targets, guessed by method name, known library call, not traced. Untraced calls in test files
  are counted and said apart, and untraced app calls are grouped by shape. The "guessed by method name" figure the map
  showed before counts links between functions (2,100 on one app), not call sites (2,739), and is now labelled as such.
- Fewer false alarms, nothing hidden. A weak hash (MD5/SHA-1) is ranked by what it is for, read from the names around
  it (the value hashed, where the result goes, the function and class, and the callers of a small wrapper): an id,
  a seed, a cache key or S3's `ContentMD5` checksum is `low`; a password, token or signature keeps its rank; when
  Lantern cannot tell, it is at most `medium`. Python SQL that splices only fixed text (a literal, a choice between
  literals, a module constant) while the values go to the driver as parameters is `low`. Every lowered finding keeps
  its id and shows the rank it would have had and why. "Slow password hashing" now needs a password-named value to be
  hashed (a word in a string or a regex list no longer counts, and `\bcrypto` in a regex is no longer read as
  bcrypt); a password value with no hashing in sight is `check`, not `add`. Found on a real app: 3 critical → 0, with
  paired safe/unsafe tests (`tests/test_context.py`).
- Zoomed in, every page stays usable: when a project's top bar does not fit, its tabs move to a second row that
  scrolls sideways (website and app); Readiness and Protections scroll again after the map was opened (the map's
  full-panel layout stayed on and cut them off); the Findings and Readiness tables scroll sideways instead of cutting
  columns; the map fits a short window; the report no longer drifts 9px sideways on a phone.
- Big projects' reports open again. Files a build tool wrote (a Vite/webpack bundle or minified script, whatever
  its name: a few very long lines) are no longer mapped as code, and the report cuts lines over 2,000 characters and
  caps how much source it carries. One 1.3 MB bundle had made a 360 MB report that took 2.3 GB to open and crashed
  lantern-cloud; the same project's report is now 72 MB and opens with about 500 MB.
- Checks on big projects are about three times faster: finding which functions call which now uses an index
  instead of reading every link each time (a 1,300-file project went from 6 minutes to under 2, with identical
  results). lantern-cloud also allows 20 minutes per run (was 10).
- A repository over the size limit is checked without the pictures, video, sound, fonts, archives, compiled
  programs, model weights and datasets Lantern never reads, so only code counts toward the limit; the Evidence report
  says how many files were left out and names the biggest. lantern-cloud's limit is now 500 MB (was 200), with a 3 GB
  data volume and 2 GB of memory; a run that would not fit in the free space says so instead of failing part-way.
- The website has a Settings page (a button in the header, and in the account sheet): theme, Simple or Advanced, what a
  new check keeps by default, plain-words explanations on or off, sign out, delete the account, play the welcome again.
  The Lantern logo now always does something: from any screen it goes to My runs, and on My runs it plays the welcome.
- My runs shows where each run's open findings are in the stack: Browser, Frontend, Server and Data (Screen and App
  for phone apps), with the count and the worst one in each. Runs checked earlier get it from their stored results.
- The Graph and Flowchart views fill the whole panel and are an endless canvas: drag anywhere, zoom with the wheel or
  a pinch toward the pointer, far past the old 35% to 250% (0.01% to 1,000,000%), and they stay sharp because they are
  still vector. The dots behind move and scale with the map. "fit" shows all of it however large, and a new button (or F)
  takes the map full screen; Esc leaves. On the canvas the arrow keys move, plus and minus zoom and 0 fits; a sideways
  trackpad swipe or shift with the wheel moves the map. On a phone the zoom buttons sit at the top, clear of the legend
  and the Ask Lantern button. Reports made before this keep the old view until the project is analysed again.
- C and C++ are read: programs, libraries and C++ web servers (cpp-httplib, Crow, Drogon, Pistache). Namespaces,
  classes, methods (in the class or `Class::m`), free and `static` functions are on the map with their calls (typed
  locals and members through `const&`, pointers and `std::unique_ptr`, `auto p = std::make_unique<T>()`, `this->`,
  `Class::f()`, `ns::f()`, `new T`); the C library's `system`, `sqlite3_exec`, `fopen` show in the Data lane. Each
  program's `main` is a start point, route lambdas are their own steps, gtest/Catch2 blocks are tests, and copied-in
  single-file libraries (`httplib.h`, `json.hpp`, `sqlite3.c`) and `third_party/` are left out. A React page whose
  search box reaches `snprintf(sql, …, "… LIKE '%%%s%%'", q)` is critical, and so is a command-line tool that runs
  `system()` or `printf(argv[1])` with its argument. 12 new `LX-*` checks: SQL built with `sprintf`/`+`, shell
  commands, `gets`, unbounded `strcpy`/`sprintf`, `scanf("%s")`, format strings, TLS checks off, `rand()` for
  secrets, MD5/SHA-1 passwords, `tmpnam`, files named by the request or `argv`, plain `http://`. Readiness reads
  `CMakeLists.txt`/Conan/vcpkg/Meson and `ctest`. New sample: `tests/fixtures/cppapp`.
- Ruby is read: Rails and Sinatra apps. Classes, modules, methods and top-level methods are on the map with their
  calls (`@svc = NoteService.new` then `@svc.all`, `note = Note.find(id)` then `note.destroy`, included modules,
  `self.`, class methods, `X.new` → `initialize`; Active Record queries and Kernel's `system`/backticks show in the
  Data lane). Routes come from `config/routes.rb` (`resources`, `namespace`, `scope`, `member`/`collection`,
  `get "p", to: "c#a"`, `root`) and Sinatra `get '/p' do`; jobs' `perform` is a start point. A controller's
  `before_action :authenticate_user!` (inherited, `only:`/`except:`, `skip_before_action`) passes the login check, so
  a skipped `destroy` is reported. A React page whose search box reaches `Note.where("… #{q} …")` is critical. 17 new
  `LB-*` checks: SQL built with `#{}`, `order(params[:x])`, shell commands, `eval`/`constantize`, `Marshal.load`,
  `html_safe`/`raw`/`<%==`, mass assignment, redirects and files from `params`, TLS checks off, MD5/SHA-1 passwords
  and tokens, CSRF protection off, CORS `*`, full error pages in production, a written `secret_key_base`, plain
  `http://`. Gems in `Gemfile.lock` are checked against the OSV vulnerability database (`gem-audit`). Readiness reads
  the Gemfile/Gemfile.lock, Rails/Sinatra and `rspec`/`rails test`. New sample: `tests/fixtures/rubyapp`.
  On OWASP RailsGoat: 7 critical findings (SQL, shell, `Marshal.load` of `params`, three `constantize` of `params`).
- The AI-call scan skips lines over 2,000 characters (minified bundles such as `jquery.min.js`): one such line took
  minutes to read, so a Rails app with vendored JavaScript never finished.
- PHP is read: Laravel, Symfony, Slim, WordPress plugins and plain PHP pages. Namespaces, classes, interfaces, traits,
  functions and the top-level code of a page are on the map with their calls (`$this->repo->find()` through typed and
  promoted properties, `new Repo()`, `self::`/`static::`/`parent::`, static calls, interfaces fanning out as
  `possible` edges, `[Controller::class, 'show']`, `'Controller@show'`, `require 'db.php'`). Routes come from Laravel
  (`Route::get`, `resource`, `prefix()->group()`, `routes/api.php` adds `/api`; a route inside an `auth` middleware
  passes the login check), Symfony `#[Route]`/`@Route`, Slim/Lumen `$app->get` and `group`, WordPress
  `wp_ajax_nopriv_*` (anyone can call it) and `register_rest_route`, and plain pages a browser opens directly
  (`ANY /legacy/login.php`). A React page whose search box reaches a Laravel `DB::select("…'%$q%'")` is critical, and
  so is an old login page that builds SQL from `$_POST`. 18 new `LH-*` checks: SQL built from variables (also in
  `whereRaw`/`DB::raw`), shell commands, `eval`, `include` of a visitor-chosen file, `unserialize`, echoing `$_GET`,
  Blade `{!! !!}`, MD5/SHA-1 passwords and tokens, TLS checks off, `extract($_POST)`, CORS `*`, `display_errors`,
  uploads saved under the visitor's name, plain `http://`. PHP libraries in `composer.lock` are checked against the
  OSV vulnerability database (`composer-audit`). Readiness reads `composer.json`/`composer.lock`, Laravel/Symfony/Slim
  and `phpunit`/`artisan test`. New sample: `tests/fixtures/phpapp`.
- C# is read, for ASP.NET servers and .NET MAUI / Xamarin phone apps. Namespaces (block and file-scoped), classes,
  structs, records, interfaces, `partial` classes written across files, constructors and top-level statements are on
  the map with their calls (own class, typed fields, properties and locals, `var x = new T()`, static calls, `this`,
  interfaces and abstract classes fan out as `possible` edges, `button.Clicked += OnSave`, method groups). Routes come
  from controllers (`[Route("api/[controller]")]` + `[HttpGet("{id}")]`) and minimal APIs (`app.MapGet`, `MapGroup`
  prefixes, inline lambdas and `Class.Method` handlers); `HttpClient` calls (`GetStringAsync`, `PostAsJsonAsync`,
  `new HttpRequestMessage(HttpMethod.Put, …)`, paths relative to `BaseAddress`, `const` URLs) link the phone app to the
  server. A MAUI app's pages (`ContentPage`, `Shell`, …: constructor, `OnAppearing`, event handlers), its view models'
  `[RelayCommand]`s and its link handlers (`OnAppLinkRequestReceived` and what it hands the link to) are entry points,
  so a search box whose text reaches server SQL built with `$"…{q}…"` is critical, and so is a shared link whose id
  reaches a local SQLite query. 11 new `LC-*` checks: SQL and shell commands built from variables, trusting any
  certificate, MD5/SHA-1, `BinaryFormatter`/`TypeNameHandling`, CORS for any site, `Html.Raw`, plain `http://`,
  passwords in connection strings (code and `appsettings.json`), and on the phone: tokens in `Preferences` or the log.
  Readiness grades a `.NET MAUI app` (crash reporting, `Console.WriteLine` in release, `packages.lock.json`,
  `HttpClient.Timeout`, Polly retries). The viewer no longer calls Kotlin, Swift, Dart or C# server code "library".
  New sample: `tests/fixtures/csharpapp`.
- Flutter and React Native apps are read as phone apps. Lantern now reads Dart: classes, mixins, extensions and
  functions are on the map with their calls (to their own class, typed fields and locals, `final db = NoteDb();`,
  static methods, interfaces, `onPressed: _load`), and a widget built inside another (`HomeScreen()`) leads to its
  `build` (a StatefulWidget's State `build`). Screens are the widgets a route opens (`MaterialPageRoute`, `routes:`,
  `home:`, `GoRoute`, `Navigator.push…`) and widgets named `…Screen`/`…Page`; the code a `uriLinkStream` /
  `getInitialLink` listener calls is where links start. React Native and Expo apps get their screens from React
  Navigation (`<Stack.Screen component={NoteScreen} />`, the `linking` config) and Expo Router files (`app/**`), and
  their link handlers from `Linking.addEventListener("url", …)` / `getInitialURL()`. In both, a link whose id reaches a
  database query built from text is critical. New checks: 8 `LF-*` for Dart (passwords in the log or in
  SharedPreferences, trusting any certificate, SQL built from variables, web view JavaScript and bridges, plain
  `http://`, weak hashes) and 10 `LN-*` for React Native (tokens in AsyncStorage or the log, SQL built from
  variables, web views open to any site or to files, plain `http://`, and Expo's `app.json`: URL schemes, backups on,
  App Transport Security off, permissions the code never uses). Readiness grades them as a Flutter app or a React
  Native app when there is no `android/` or `ios/` folder to read (crash reporting, logs in release, timeouts and
  retries, ATS and backups in `app.json`, `pubspec.lock`). New samples: `tests/fixtures/flutterapp`,
  `tests/fixtures/rnapp`.
- iOS apps are read as iPhone apps. Lantern now reads Swift: types, extensions, protocols and SwiftUI views are on the map
  with their calls, and the app's screens (UIKit view controllers, SwiftUI views the app or a navigation link opens) and
  the code that handles incoming links (`.onOpenURL`, the app and scene delegates) are where paths start. A link whose
  id reaches a database query built with `\(id)` is critical, with an iPhone story ("Sam sends a link to your app…").
  16 new `LI-*` checks cover Info.plist (App Transport Security off, URL schemes any app can send, file sharing, keys
  written in it, permissions the code never uses), entitlements (`get-task-allow`), the Xcode project (old minimum iOS)
  and Swift code (passwords in the log or in UserDefaults, Keychain items readable while locked, trusting any
  certificate, SQL built from variables, weak hashes, web view file access and bridges, UIWebView, plain `http://`,
  secrets on the clipboard). The "On the phone" card lists what the app asks to use, and Readiness grades it as an iOS
  app (crash reporting, print kept out of release, ATS, debugger, minimum iOS, timeouts, signing files not committed).
  Vapor routes in Swift servers are entry points too. New sample: `tests/fixtures/iosapp`.
- Kotlin is read and mapped, not just checked line by line. Kotlin classes, `object`s, companions and functions are on
  the map with their calls (to their own class, objects, companions, typed properties and locals, interfaces, `::f`
  references), so an Android app written in Kotlin gets the same paths as one in Java: a link that opens a screen and
  whose id reaches a database query is critical. Screens drawn with Jetpack Compose (`@Composable fun HomeScreen`) are screens on the map. Spring routes in Kotlin are
  entry points, Java's server checks (SQL and
  shell commands built from variables, weak hashes, trust-all certificates) run on Kotlin too, and a value put into a
  Kotlin string (`"… '$id'"`) counts as used. New sample: `tests/fixtures/kotlinapp`.
- Android and Java libraries are checked for known security holes. Lantern reads the libraries written in
  `build.gradle`, `build.gradle.kts`, `gradle/libs.versions.toml` and `pom.xml` (test libraries left out, `$version`
  variables and Maven properties filled in) and asks the public OSV database about each exact version. Each finding
  points at the line the library is written on and names the version that fixes it. `--offline` skips it, and the
  Evidence Report says that libraries pulled in by other libraries were not checked.
- Android apps are read as phone apps. Lantern finds the app's screens and the parts other apps can start from
  `AndroidManifest.xml`, so findings get a real path ("a link opens NoteActivity and the id it carries reaches a
  database query" is critical), and the map says Screen and App instead of Browser and Server. 26 new `LM-*` checks
  cover the manifest (debuggable, backups, plain http, components open to other apps, permissions the code never
  uses, Google keys), the network security config (plain http, user certificates), the Gradle build (release
  debuggable or signed with the debug key, no R8, old target SDK, `+` versions, signing passwords) and Java/Kotlin code
  (location or tokens in the log, WebView JavaScript, bridges and file access, ignored SSL errors, shared storage,
  plain-text logins in SharedPreferences, SQLite queries built from text, trust-all certificates, `http://` links,
  broadcasts any app can hear). Findings has an "On the phone" card listing what the app asks to use and what is open
  to other apps. Readiness grades an Android app as one: crash reporting, logs stripped from release, R8, signing key,
  target SDK, network timeouts and retries, and Android Studio's sample tests no longer count as real tests. Each
  Android problem has its own story (another app on the phone, a USB cable, a café Wi-Fi). On devr22/HerSheild: 13
  findings where there were none, readiness 55 instead of 28.
- Cloud: 50 runs per person per day (was 10) and 1000 for everyone together (was 300), the owner's choices of 2026-11-04; `docs/deploy.md` says how to change it with one command.
- Every function has its three lenses from the moment a check ends. Where no model has explained a function yet, the
  Technical, Everyday and Mapped lenses are built from the map alone (file, lines, signature, entry point, calls, HTTP
  links, findings), with a byline that says no model wrote them and every phrase anchored to a real symbol. The
  Explain button still asks a model for the fuller wording and an analogy. The Explanations list now reads "Explained
  by a model" and "From the map so far". `tools/viewer_smoke.js` checks the map-built lenses render.
- Fixed: the analysis crashed outright (a segmentation fault, shown on the website as a bare "stopped with an error")
  on repositories with a function past line 256 of a file, for example devr22/HerSheild. The cause was the
  `tree-sitter` Python package 0.26.0, which frees a node's line number while it is still in use; Lantern now refuses
  that version (`tree-sitter>=0.23,!=0.26.0`) and a test parses past row 256 in a child process so a bad build fails
  the suite instead of killing it. The Java and Rust readers also keep each parse tree alive for as long as its nodes
  are used. The cloud now says when the analysis died before writing anything ("crashed (signal 11) … a bug on
  Lantern's side") instead of a sentence with no cause.
- Website: Connect GitHub, for private repositories. When the owner sets up Lantern's GitHub App (`docs/deploy.md`), a
  private repository's check offers "Connect GitHub": the person picks repositories on GitHub, clicks Try again, and
  Lantern reads them with a one-repository, read-only token that lasts an hour at most, only for someone GitHub says
  may read that repository. The token reaches git through its environment, never a link, file or log. "Connect private
  repositories" also sits beside "Explore GitHub". Off (Upload only) until the app is configured.
- Findings page: its counts now match the summary, the grade and Ask Lantern. Findings in test code (test files and
  fixtures, often planted on purpose) were counted in the page's "open" number and severity tiles but nowhere else; they
  are now listed at the end under "In test code: N, not counted" (Advanced: an "In test code" filter).
- Script written inside HTML pages is now read (an app's own `index.html`, Jinja/Django templates, the pages of a
  server-rendered app): its functions appear on the map with the page's line numbers, its `fetch` calls link to the
  backend routes, and the page sits in the Browser lane with its functions in Frontend. JSON blocks, `src=` tags,
  `text/babel` and `.min.html` are left alone. Lantern's own map now shows its four pages and 389 of their functions,
  and its shape reads "full-stack web app". The pattern rules (`LJ-*`) still read only `.js`/`.ts` files.
- Website: a private repository (or a wrong link) no longer stops with git's "could not read Username… clone it yourself"
  message. The check says in plain words that Lantern could not open it, and offers "Upload your code instead", which
  opens the upload window; git's own words stay in the log.
- Website home: the warm light behind the headline, as in the mock-ups (the app's home has it too); "Your repositories"
  (GitHub sign-ins) and "Explore GitHub" buttons under the link box, to find a repository to paste; and "Try a sample app":
  Lantern's four built-in starter apps, each with planted problems, checked with one click (written from the package,
  nothing cloned), so a beginner sees a real report without a repository of their own.
- Website: upload an app from your computer. "Upload…" next to the link box (or drop a folder or a .zip on it) sends a
  folder, zipped in the browser without `node_modules`, `.git`, virtual environments and build output, or a .zip
  (`POST /v1/uploads`). The new `lantern.archive` unpacks it inside the sealed box with no network and refuses names
  that leave the folder, links, password-protected files and archives that grow past the size cap; the upload is
  deleted when its check ends. Messages under the link box no longer vanish when the page refreshes its runs.
- Website: a check in progress always shows that it is working. The button you clicked spins while the check starts
  ("Starting your check…"), and each running check shows a timer that counts every second ("running for 0:42") on its
  card and its progress page. With animations turned off in Windows or macOS (reduced motion), the progress bar and dots
  now fade in and out instead of standing still. The app (`lantern serve`) shares the bar and dot change.
- Landing page: the intro plays on every visit to `/` (deep links and `?intro=0` skip it) with no flash of the page first,
  and ends on a card with "Add your app" (lands on the install card with an accent ring) and "See a finished report
  first"; Skip and Escape jump to that card. The hero's first button is now "Add your app". The React scripts carry SRI
  hashes, and the page opens even if they do not load. On phones the page is no longer wider than the screen.
- Website (lantern-cloud): the same 20-second intro plays on every visit to the home page, ends on "Add your app" (lands
  on the link box with an accent ring) and "Try a sample app first", and Skip or Escape jump to that card. Links to a
  run or to Help (`#/run/…`, `#/help`) and `?intro=0` skip it. Its scripts and React are served from the website itself
  under the page's nonce, never from another host; if they fail to load, the page shows as before.

## 0.10.0

Lantern on the web, and the app redrawn to match the design mock-ups screen by screen.

- Cloud mode (a separate service, `lantern-cloud` 0.1.0, deployed on its own): paste a repository link on the
  website, sign in with GitHub or Google, and Lantern analyzes it in a locked-down sandbox (no network during the
  analysis, limits per person and per day) with a live log. Reports open only for their owner; Share makes a
  read-only link and turning it off retires it. Delete a run or your whole account at any time; results are kept
  until you do. Explanations and Ask Lantern use your free allowance, only after you agree once to the data notice.
  The website is built from the app's own stylesheet, so it looks like the app.
- Ready to ship? (Simple) leads with the grade as designed: a large letter inside the score ring, the score and a
  plain answer beside it, the biggest moves as cards with their gain in green, smaller moves in a row underneath, and
  a right-hand column with what's already good, how the score works, and the starter-files note.
- The Evidence Report reads as a printed document, as designed: paper sheets with a serif heading and opening
  paragraph, the four numbers as a ruled row (fixed in green, open in red), section labels in small capitals, and
  inside the app the moving shapes drift around the sheets. "Save as PDF" works inside the app again: it used an
  inline click handler, which the page's script policy refused.
- What protects you (Simple) is laid out as designed: the protections Lantern found fill the page under an uppercase
  count and a large heading, and what it looked for and didn't find is a full-height column down the right edge, each
  card with its "How do I add one?" under the text instead of squeezing it. On phones the column follows below.
- The moving shapes behind the app now show behind the Atlas too (the report inside the app is see-through, and its
  lanes sit on the page instead of a grey box), and a report opened on its own draws the same shapes: full behind
  About and the other pages, quieter behind the map, findings and fix pages. Settings › Backdrop (off, subtle, bold)
  reaches a report opened in its own tab; with reduced motion turned on the shapes stay still. Dark mode's glow
  matches the design token.
- Paths, as designed: Advanced opens on the whole-app Graph with the riskiest route already selected; Simple opens
  on Lanes, full width, starting on the path that reaches the worst finding, with a line naming where it goes wrong.
  The lanes now fit the screen instead of running off the right edge, and the page title is no longer cut short.
  Flowchart and Graph sit on a dotted canvas, as in the mock-ups.
- Findings in Simple view read as an audit memo, as designed: serif headings, the severity in the margin, entries split by
  thin rules. Each heading is a plain sentence ("The backup button can run shell commands on your server") chosen from a
  fixed list by the rule and filled only with names from the map; the scanner's own words stay right underneath.
- Project screens have one header row, as designed: logo, "My apps" (Simple) or "Projects /" (Advanced), the app's
  name and grade, the tabs (a segmented control in Simple), then the actions and the Simple/Advanced switch. The
  global header and the report's own stats strip no longer stack above it, so at 1200px nothing is cut off. The cloud
  website's run pages get the same single row.
- Phones always show the Simple view, as the design says, even when Advanced was picked on a computer; the
  Simple/Advanced switch is hidden below 760px. Protections no longer says "Lantern found each one in your code" when
  it found none.
- Design drop 01: the Atlas lanes use straight 2px connectors in a staircase, report tabs and stat chips no longer wrap,
  the phone tab row scrolls, finding cards lose the coloured left bar (critical cards get a tinted border), code chips
  don't break mid-word, and Advanced tables drop less important columns on narrower screens.
- Scenarios: every finding now comes with a short story of one tester meeting it ("Priya opens the /admin page, clicks
  the backup button, types `report; whoami`…"), then what goes wrong and what the fix changes. Lantern builds it from
  its own facts (the page, the clicks, the route, whether typed input reaches the line), so it is there with no model.
  Explanations gain a fourth part, Scenario, next to Technical, Everyday and Mapped; a model's story that names code or
  a page the map does not show is removed, never shown. Prompt version `lens-v4`: explanations made before this are
  asked again on the next `lantern explain`.

## 0.9.0

First build for outside testers.

- One-command install: `pip install "git+https://github.com/LittleHenderson/Lantern@v0.9.0"`. Works with no extras;
  `lantern analyze` runs Lantern's own rules and says which optional scanners (Bandit, pip-audit) are off.
  `pip install "lantern[scan] @ git+https://github.com/LittleHenderson/Lantern@v0.9.0"` adds them.
- `lantern serve --check`: starts the app, prints the one-time link, loads the app once and stops (exit 0 if it answered).
- Release workflow: a pushed `v*` tag builds the sdist and wheel, runs the tests against the built wheel in a clean
  environment, and attaches both files to a GitHub Release.
- Clean-install test in CI on Linux, macOS and Windows.
- **Watch my tests run** (Paths): runs the project's test command in a sandbox (Docker with a pinned image, no
  network, read-only project; or a restricted subprocess with Landlock, rlimits and a job object on Windows), stopped
  after 10 minutes. Python tests upgrade the map's links to "seen running"; other languages run untraced for now.
- **Terminal drawer**: runs Lantern's own commands only (`analyze`, `trace`, `explain`, `report`, `verify`, `accept`,
  `packs`, `export`, `learn`); anything else is refused.
- **Screenshots in Ask Lantern**: Tesseract reads a dropped PNG/JPEG/WebP through a pipe on your computer; the image is
  never saved or uploaded. `[ocr]` extra.
- **Analysis packs on/off**: per-pack switches in Settings for every project's packs, with a "Re-check to apply" card.
- **Simple / Advanced** is saved by the app and followed by the Atlas, including after a restart.
- Free allowance gateway: `/v1/health` reports its version and model; CI checks it. Token hashes are deleted after 90
  days without use and per-day counters after 90 days (`LANTERN_RETENTION_DAYS`). The limits are listed in
  `docs/deploy.md`.
- Tester guide `docs/try-lantern.md` and a "Tester report" issue form.
- Live-app browser smoke in CI: the test sheet, the terminal, a screenshot upload and a pack switch, with no JS errors.
