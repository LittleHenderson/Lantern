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
posts nothing anywhere.

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
listed at its end: a scanner that did not finish on one side, a part of the release decision that only one side
was checked for (the tests are not run on an earlier version), files of a commit that could not be copied, a
submodule's code (which is not part of a commit). Two checks made by different versions of Lantern (a check
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
