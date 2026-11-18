# What a change does (`lantern diff`)

A change to an app is read line by line, and what matters about it is often not in the lines: a new route that
nobody has to sign in for, a page that still calls a route the change removed, an old problem that a page reaches
only now. `lantern diff` checks two versions of a project and says what is different between the two checks. The
result is a **change receipt**.

## Three ways to get one

* **In the app** (`lantern serve`): open a project and click **What changed**. Lantern compares your last commit
  with your files as they are now and opens the receipt. Nothing of your project is changed and no test is run.
* **In a terminal**:

  ```bash
  lantern diff                      # the last commit, compared with the files as they are now
  lantern diff main                 # main, compared with the files as they are now
  lantern diff main..my-branch      # two versions
  lantern diff main...my-branch     # from where the two parted: what a pull request would show
  lantern diff path/to/repo v1.2.0..HEAD --format md     # another folder; print the text for a pull request
  ```

  The receipt is written to `PATH/.lantern/change/` as `change.html` (a page), `change.md` (text for a pull
  request) and `change.json` (the data); the two checks' own results are beside them in `before/` and `after/`.
  The command ends with 0 when it compared, whatever it found, and with 2 (and a sentence) when it could not.
  The app's terminal takes `diff [BASE..HEAD]` too.
* **On every pull request**: Lantern's GitHub Action puts the receipt at the top of its comment
  (`docs/github.md`).

Any other CI system uses the same command: `lantern diff origin/main...HEAD --format md` prints the text to post,
and `change.json` holds what a pipeline can decide on (`counts`, `release.after.decision`). `lantern diff` itself
posts nothing anywhere. `--require not-blocked` makes the command end with 1 when the change itself brings what
blocks a release (the list is under "Before each push" below), and with 0 otherwise.

## Before each push (`lantern hook install`)

```bash
lantern hook install        # in the repository: from now on every `git push` is checked first
lantern hook status         # is the check on?
lantern hook remove         # take it away again
git push --no-verify        # push once without the check
```

`lantern hook install` writes git's `pre-push` hook. Before git sends anything, Lantern compares each commit being
pushed with what the other side already has, by the same two checks as `lantern diff` (offline: no library is
looked up), and **stops the push when the change itself brings what blocks a release**:

* a critical or high finding that is new, that a page or route reaches only now, that is ranked critical or high
  only now, or that is open again; a secret written into a file is such a finding;
* a request the page still makes that a route answered before and none answers now (a broken link between page
  and server);
* a required part of the release decision that failed only with this change.

What blocked the project before the push and still does is the project's, not the push's, and does not stop it: a
project that was Blocked before can still push a change that adds nothing that blocks, and the hook says so. A
finding accepted in the change with a written reason (`lantern accept`, a `# nosec` comment with a reason) does not
stop it either, and neither does a new request that no route of this project answers (the server that answers it
may be another project: `lantern workspace`).

```
lantern  checking the push of fault: 3f689e9a37ea after 20fd64a36696 (where it parted from origin/main)
lantern  stopped: this push brings what blocks a release (0.8 s)
lantern    - new critical finding B602 at shop/app.py:30 (subprocess call with shell=True identified, security issue.)
lantern    - a request the page still makes that no route answers now: POST /backup (web/src/api.ts:11)
lantern  read from the code (the tests are not run); the receipt, with what such a check cannot see: .lantern/push/fault/change.html
lantern  To push once without this check: git push --no-verify
```

What a push is compared with: the commit the other side has, where this repository holds it. A new branch, or a
commit this repository does not hold, is compared with the commit where it parted from the remote's main branch
(`origin/HEAD`, else `origin/main`, else `origin/master`, as this repository last fetched them). The first push to an
empty remote is compared with nothing, so a critical or high finding anywhere in it stops the push. Taking a branch
away sends no code and is not checked. When Lantern cannot check a push (a commit it cannot copy, a results folder
it will not write to), the push is stopped too, with the reason and the way round it.

The receipt of each check is written to `.lantern/push/<branch>/` (`change.html`, `change.md`, `change.json`, and
the two checks in `before/` and `after/`); that folder carries a `.gitignore` of its own, so git never offers it for
a commit. On the sample projects a push is answered in under 1.5 seconds, a planted fault included
(`bench/push_check_results.md`). A larger project takes two longer checks: on Lantern's own repository (793 files)
a push took about 100 seconds. What each file reads as is kept between runs (`lantern cache`), so a file that did not
change is not read again, but the scanners and the data-flow step look at the whole project on each side, and on a
large project they are most of the time.

The hook is yours. Lantern writes one only where no pre-push hook is (or where the one there is Lantern's own), and
never replaces, changes or removes a hook it did not write, a link included: it prints the one line to add to yours
instead. The hook it writes can be run and changed by you only, not by other users of the computer. Where git runs hooks from another folder (the setting `core.hooksPath`, which tools such as husky set),
Lantern writes nothing and says so, with that line. The hook runs the Lantern that wrote it, with the Python that
wrote it, and never a copy of Lantern in the project being pushed (the project's folder is not on its path). Nothing
of the project is run, its tests included; the two checks read the code, as `lantern diff` does.

## What a receipt lists

Only differences between the two checks:

* **Doors** (pages, routes, commands): added, removed, moved to another address, and a login check that got weaker
  or was taken off a route that is still there. A new route says what it shows about a login: "Added
  `POST /api/admin/export`: no login check found, and it changes data".
* **Links between page and server**: a request the page still makes that no route answers any more (with what
  became of the route: removed, another verb, another path), and a new request that no route of the project answers.
* **Findings**: new, fixed, in the code before and reached by a page or route only now, ranked higher or lower,
  accepted in this change (by `lantern accept`, or by a `# nosec` comment with a written reason: the receipt quotes
  the reason, and says so when the finding came with the change), open again after an acceptance was taken away.
  A finding that was only excused is never listed as fixed.
* **Calls that cost money** (a model, a payment, a message) that a route reaches now and did not before. A call
  counts where the code makes it: a remark or a text that only names a provider is none, and a vector store is not
  counted as one that costs money.
* **What the change touches**: the functions whose code changed, the pages and routes that lead to them, and what
  they lead to (database tables, the shell, other services). "The shell" lists what starts a program
  (`subprocess.run`, `child_process.exec`); what a started program gave back or raised (`subprocess.CompletedProcess`,
  `subprocess.TimeoutExpired`) is not listed.
* **The release decision before and after**, for example `Passed → Blocked`, with what moved it.

Two versions that differ only in comments and spacing give a receipt that says nothing changed.

## What it does not say

No model writes or ranks any line of a receipt, and a receipt never creates, closes or re-ranks a finding. It says
what Lantern's map and scanners show on two checks, so the limits of those checks are its limits, and they are
listed at its end: a scanner that did not finish on one side, libraries not looked up (a check made offline, as
each check before a push is: a library with a known problem that came with the change is not listed), a part of the
release decision that only one side was checked for (the tests are not run on an earlier version), files of a commit
that could not be copied, a submodule's code (which is not part of a commit). Two checks made by different versions of Lantern (a check
handed over with `--base-results` may be an older one) can differ for that alone: the receipt names both versions,
or says that a check does not name its own, and where the two name their findings in different ways it compares no
finding at all. What a route shows about a login is read from names and shapes
(`websec.login_check`), as on the report: "no login check found" means look, not proof that there is none.

## For engineers

* `lantern/diff.py`: `compare(base, head)` is a function of two results folders (`graph.json`, `security.json`,
  `readiness.json`) and reads nothing of the project. A door is its kind and its words, a finding its id (made from
  the flagged line's text), a function its id on the map with a fingerprint of its code without comments and
  spacing, a page's request the function that makes it and its words. The receipt's shape is in `docs/api.md`.
* An earlier version is never checked out in the project's folder. `gitfacts.resolve` reads the name (a branch, a
  tag, `HEAD`, a commit's number, with `~1` or `^`) from the repository's own files, and `gitfacts.copy` has git
  write that commit out in a git folder of Lantern's own, under settings and an attributes file of Lantern's own,
  into a folder of Lantern's own: the settings, hooks, filters and attributes that come with a repository decide
  nothing about the copy, a link that leads out of the project is not made, and a copy that holds fewer files than
  the commit is not used. That folder is checked like any folder (`lantern analyze`, tests not run) and removed.
* `--base-results DIR` / `--head-results DIR` hand over the results of a check already made of a side, which is
  then not made again (the GitHub Action does this for the pull request's own check); `--base-label` /
  `--head-label` say what the receipt calls a side; `--privacy structure` keeps source out of the two checks' own
  reports (the receipt never holds source); `--offline` skips the look-up of libraries on both sides.
* A comparison costs two whole checks. What Lantern keeps between runs (`lantern cache`) makes the second check's
  reading of unchanged files cheap; the scanners and the data-flow step look at the whole project on each side.
* In the app the receipt's page is built again from `change.json` by Lantern's template each time it is shown
  (`/p/<id>/change.html`); it holds no script, and the `change.html` in the results folder is never sent.
