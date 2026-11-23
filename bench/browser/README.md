# Browser benchmark

Written on 2026-11-22, before the benchmark's first run (a firm pass or fail, stage 5, step 5). Its job is to count,
exactly, how many planted problems the eight checks of `lantern browse` (`docs/browser.md`) find on sites made for the
purpose, and how many safe sites and look-alikes they leave as they are. Some of the sites are built against; the
others are held back and are not opened in a browser while the checks are built.

```bash
python bench/browser/run_browser.py /tmp/bb                                  # the open part, every version
python bench/browser/run_browser.py /tmp/bb --only garden,g-empty-page       # some versions
python bench/browser/run_browser.py /tmp/bb --runs 2 --results bench/browser/open/results.md --json /tmp/bb/open.json
python bench/browser/run_browser.py /tmp/bb --part held-back --results bench/browser/held-back/results.md
                                                                             # the held-back part: see "The two parts"
sudo python tools/netless.py --watch /tmp/net.json -- python bench/browser/run_browser.py /tmp/bb
                                                                             # Linux: every address any program tried
```

`--browser FULL PATH` names the browser; without it the runner takes the one `lantern browse` finds. Every run is
isolated (`tools/netguard/`): a temporary home folder, none of your keys, and no address outside this computer may be
reached at all; what was tried is listed at the end and fails the run. The browser is not Python, so the guard does not
see inside it: inside the run it reaches the site only through Lantern's own door, which forwards nothing, and on Linux
`tools/netless.py --watch` runs the whole benchmark in a network that holds only this computer and writes down every
address any program tried. The record of each run of each version is kept in `WORKDIR/<part>/records/`.

## The two parts

| Part | Families | Versions | Planted | Look-alikes | Safe | What it is for |
|---|---|---:|---:|---:|---:|---|
| `open` | `garden`, `tasks`, `library` | 67 | 46 | 18 | 3 | Built against: a version that does not come out as written down is looked at, a fault of the checks is fixed in the checks, test first, and the part is run again |
| `held-back` | `bikes`, `clinic` | 54 | 42 | 10 | 2 | Not opened in a browser until the end of stage 5; run once then, and again on the code of the release (stage 6) |

* `garden`: a community garden's five plain pages, served as they are, with folders of their own for its style, script
  and pictures.
* `tasks`: a list of tasks built into `dist/` the way a single-page app is: one page that its script draws whole.
* `library`: a library's FastAPI app with a sign-in, a stylesheet, a script and a logo.
* `bikes`: a bike shop's plain pages built into `public/`: a map drawn on a canvas, routes in a folder of their own, a
  price list, a booking form.
* `clinic`: a clinic's FastAPI app whose pages fill themselves from its own API: a sign-in, booking, a help page and a
  question form.

Each part holds every one of the 24 codes of `docs/browser.md` as a planted problem at least once.

**What "held back" means here, honestly.** The held-back sites were written by the same author as the checks (Claude),
on 2026-11-22, after the checks were built and before this benchmark was first run. They were designed before a line
of them was written, and checked only without a browser: every version builds and every edit stands exactly once where
it is made; their scripts read as JavaScript and their Python as Python (`node --check`, `py_compile`); the clinic's
pages and forms were asked through the app itself, with no server and no browser, and each answered as written down;
Lantern's reading of the code, run on the safe clinic and three of its versions, names the page that asks for a
sign-in and the header said to be set for every response, as the `visitor` and `protections` checks need. The checks
have not been changed since. But their author knows how the checks work, and while the expectations were written down
the checks' own code was read in two places where `docs/browser.md` does not settle a case: which answers are looked
at for the headers, and whether a link to an address that a route of the code answers can be a dead link (it cannot:
"no route of the code"). The first is a reading listed below. So the held-back part is a weaker test than sites
written by somebody else would be, and its results say so.

**The checks were changed after that (a dated note, 2026-11-22).** "The checks have not been changed since" was true
when it was written. Later the same day the open part's first trial (its three safe sites only, 3:04 PM PST, before
any planted version or look-alike was opened) found a fault of the checks: the task list keeps its tasks in the
browser, and its working "Done" button was reported as a button that does nothing (`dead-button` on `/index.html`),
because every step of a run was made in one tab and a click went to the control at the same place on the page opened
anew, whatever it was. It was fixed in the checks, test first (`docs/browser.md`, "Each step is a first visit", and
three look-alikes in `tests/browse_sites.py`), and with it the same fault in how a form is found again, which was seen
by reading the code (three more look-alikes); no definition of either part was changed for it. The held-back part has
still not been opened in a browser; the fix was made by the author of its sites, who knows them, which is one more
reason its results are a weaker test.

**And again after the open part's first whole run (a dated note, 2026-11-22).** The open part was run whole at 4:00 PM
PST (Lantern 000bb39, definition `693d745feb7e932c`, every version opened twice, no way to the network; its results
are kept as `open/results-first-whole-run.md`, and stand): 60 of 67 versions as written down; planted problems found
45 of 46; safe sites and look-alikes as written down 18 of 21. Each of the 7 differences was looked at in the browser
by hand, and each was a fault of the checks, none a version written down wrong. Two went against readings listed below
before the first run (`gl-disabled-button`: a switched-off button was clicked and read as dead; `ll-csp-blocks-widget`:
a script the page's own policy keeps out was counted as asked of another computer), and one against the words of
`docs/browser.md` (`t-no-focus-ring`: an outline set to 0 shows nothing, and it read as a ring because a number of it
changed). The others: a print button read as dead, because the check did not see the browser's print dialog
(`gl-print-button`); the keyboard check said held on two task lists whose page stays empty, with no control at all
(`t-chunk-missing`, `t-blank-render`; nothing to check is written down); and after a trap the button the keyboard never
got to read as out of its reach (`l-trapped`). They were fixed in the checks, test first (`docs/browser.md`, the
`leads`, `outside` and `keyboard` sections, and eight versions of `tests/browse_sites.py`); no definition of either
part was changed for them, and the open part was run again on the fixed code (Results). The held-back part has still
not been opened.

**One line of the open part's definitions written in two parts (a dated note, 2026-11-22).** Before the open part was
run again, Lantern's check of itself (`lantern analyze .`, then `tools/self_readiness.py`) failed on the benchmark: the
line that `l-let-in` plants stood whole in `open/cases.py` (`DEBUG = True`, the text the version writes into its
`app/data.py`), and Lantern's readiness check, which reads every code file of Lantern as Lantern's own, read it as
Lantern's debug switch left on ("Debug mode is off" failed; readiness 93 of 100, where it is 96 without that line).
The line is now written in two parts there, test first (`tests/test_browser_bench.py`: no Python file of the
benchmark reads as a debug switch or a bare `except:`, and the version still plants the line). Nothing a part builds
or must give changed: each of the 121 versions was built from the files before and after, and each came out byte for
byte the same. The open part's fingerprint is taken over the bytes of its files, so it changed from `693d745feb7e932c`
to `8e257c494883877d`; the held-back part's, `348593e68cbe85b8`, did not.

## What each version is

A family is one site, written safe, in `<part>/sites/<family>/`: every file a `.tmpl` and dot-files as `dot.<name>`
(the runner writes them out with their real names), so Lantern's own audit never reads the planted problems. A version
is that site with a few exact edits (`define.files`: each text to replace must stand exactly once). There are three
kinds:

* **safe**: the site itself.
* **planted**: one problem a check must find, with the code it must give and the page it must be seen on.
* **look-alike**: something a careless check would take for a problem (a ring drawn as a shadow, a link to a place on
  the same page, a cookie named for a colour theme, a dialog a button opens), or where the run itself can only say it
  cannot tell (a script from another computer that the run refuses).

For every version, `cases.py` writes down what all eight checks must give: the family's safe outcomes, changed where the
version's `gives` says, with every code. Side effects are written down too: a script that stops at a missing element
also leaves the buttons after it dead, and a renamed script leaves its page empty. `seen` names rows that must be
there: a code on a page, not undecided. `define.faults` refuses definitions that do not hold together (an unknown
check, outcome or code, a planted version that gives no broken check with its code, a row of a code the version does
not give).

## Measurements (definitions, fixed)

For one run of one version (`define.compare`):

* **As written down**: every check has the outcome and the codes written down, and every row written down is there.
* **Found** (a planted version): the check of the planted problem is broken with its code, and the row written down
  for that code is there.
* **False alarm**: a code a check gave that was not written down for the version.
* **Missed**: a code written down that the check did not give.
* **Another outcome**: a check's outcome differs where no code is involved (held where nothing to check was written
  down, inconclusive, not run).
* **A row not seen**: a row written down that is not there, or is there only as undecided.

A version is as written down only when every run of it is; a version whose runs gave different outcomes says so. The
results give: the versions as written down; the planted problems found, of all planted; the safe sites and look-alikes
as written down, of all of them; every false alarm, miss, other outcome and row not seen, each named; for each of the
24 codes, in how many versions it is planted and in how many it was found; the runs that could not be made; what the
browser itself tried to reach, refused at Lantern's door; what the sites' pages asked of another computer, refused
inside the browser; and what the run's guard refused. The definition's fingerprint (`run_browser.definition_sha256`:
`define.py`, the part's `cases.py` and every file of its sites) stands at the top of every results file; two results
are compared only when they name the same one. A change to any of those files is a new definition.

## Targets

* **Open part**: every planted problem found, and every safe site and look-alike as written down. A version that does
  not come out so is a fault of the checks unless the version itself is wrong (a site that does not do what its
  description says); each such case is said in the results with what was found and what was done, a fault of the
  checks is fixed test first, and the part is run again.
* **Held-back part**: opened once at the end of stage 5 and reported exactly as it came out. The aim is the same; a
  miss there is reported as a miss, and a fix made after it does not change its first numbers. It is run again on the
  code of the release, and both results stand.

A target missed is reported as missed; it is never met by changing a definition. A definition that turns out to be
wrong is corrected with a dated note here, saying what was wrong and what the first numbers were, and those numbers
are kept. The finish check of stage 5 takes the counts of both parts: the planted problems found and the safe twins
left clean, counted and reported exactly, with no run reaching the network.

## Readings beyond the words of `docs/browser.md`

Where what is written down goes further than the words of `docs/browser.md`, the version says so in its `beyond` and
why. They are:

* A page that answers with a server error comes without the headers the code sets for every response (its middleware
  never ran for it); `docs/browser.md` does not say whether that is `said-not-sent`. Written down: it is not; the fault
  is the `opens` check's alone (`l-server-error`, `c-server-error`), or the `forms` check's when it is the answer to a
  sent form (`l-form-error`), as a page that does not open is the `opens` check's and not the `leads` check's.
* An error raised while the page that answers a sent form loads is raised while the form is sent, which
  `docs/browser.md` gives to the `forms` check (`g-script-raises`).
* A form the page's script sends with `fetch` is sent to the address the script asks, and is judged by that answer
  (`c-form-error`, `c-form-nowhere`).
* An error in a promise that nothing catches is an error the page's script raises (`c-raised`), or the click raises
  when a click started it (`c-button-raises`).
* A disabled button is not offered to be clicked, so it is no dead button (`gl-disabled-button`).
* A canvas on which nothing was drawn shows nothing, so the page is `empty` (`b-blank-map`).
* `javascript:void(0)` is one of the links like `href="#"` that lead nowhere (`b-void-link`); a link to a place the page
  has is none (`bl-skip-link`, `bl-section-link`).
* A link to a file of the folder that is not a page leads somewhere, and the file is not one of the pages
  (`bl-download-link`); a `tel:` link, like a `mailto:` link, is not an address of the site and is not counted
  (`bl-phone-link`).
* A data file the page's script asks for is not a script the page names, and the browser's own line about a load that
  failed is not the site's `console.error` (`bl-missing-data`).
* A ring drawn as a shadow shows where the keyboard is (`bl-ring-shadow`).
* The browser does not ask another computer for a script the page's own Content-Security-Policy refuses, so `outside`
  holds (`ll-csp-blocks-widget`).
* A cookie named for a colour theme is not named like a sign-in (`cl-theme-cookie`).
* Two readings that `docs/browser.md` says in so many words, written down where a version leans on them: an animation
  that goes on for ever does not hold the page up (`cl-live-dot`), and a dialog is something a click did
  (`cl-confirm-button`).

## Results

`open/results.md` and `held-back/results.md`, written by `--results`, with the date, the commit of Lantern, the
definition's fingerprint, the browser and the system. A file of an earlier run is kept beside it under a name of its
own, and its numbers stand.

* **Open part, first trial** (its three safe sites only, 2026-11-22 3:04 PM PST, Lantern 564eb35, no way to the
  network): 2 of 3 as written down; the task list's working "Done" button read as `dead-button`. A fault of the
  checks, fixed in 000bb39 (the first dated note above). Not a whole run, so no results file.
* **Open part, first whole start** (3:56 PM PST): void, no results. Two minutes in, the recorder of the network that
  holds only this computer (`tools/netless.py --watch`, with this computer's strace 6.8) stopped with a fault of its
  own that its makers have since fixed, and the run with it. It was started again with strace 7.3, built as GitHub's
  checks build it.
* **Open part, first whole run** (`open/results-first-whole-run.md`: 2026-11-23 00:16 UTC, Lantern 000bb39, definition
  `693d745feb7e932c`, Chrome 153.0.8010.12, Python 3.13.18 on Linux, every version opened twice, 944 s; tried outside
  this computer: 0 by the run's guard, 0 by the recorder): 60 of 67 versions as written down, 7 not. Planted problems
  found: 45 of 46 (missed: `t-no-focus-ring`). Safe sites and look-alikes as written down: 18 of 21
  (`gl-disabled-button` and `gl-print-button` gave `dead-button`; `ll-csp-blocks-widget` gave `outside-script`). The
  other differences: `t-chunk-missing` and `t-blank-render` gave `keyboard` held where nothing-to-check is written
  down, and `l-trapped` gave `not-reached` beside its `trapped`. The two runs of every version agreed. Each was a fault
  of the checks (the second dated note above).
