# Leave Lantern's report on your GitHub repository

Lantern can leave its report on the repository it checked, in three ways that work together:

1. **A comment on every pull request.** Each time someone proposes a change, Lantern checks it and posts one comment
   with the result: 🟢 **Passed**, 🔴 **Blocked** or 🟡 **Incomplete**, then **what this pull request changes**
   (see below), the open problems by how serious they are, why the result is what it is, and the most serious
   problems by file and line. On the next push it edits the same comment instead of adding another. The check itself
   fails when the result is Blocked, so a pull request shows a red cross until the problem is fixed or accepted with
   a written reason.
2. **The report saved in the repository.** On your main branch Lantern opens one pull request, "Lantern report",
   that puts the report in `.lantern/report/`. It brings that pull request up to date on every push. Merge it when
   you want the report kept with the code: `README.md` there is the report in words (GitHub shows it when you open
   the folder), `evidence.html` is the full Evidence Report, and `evidence.json` holds what an engineer needs to check
   it again.
3. **A badge on your front page.** `.lantern/report/badge.svg` reads like
   `Lantern · commit 1a2b3c4 · 0 critical · Nov 15` and is green only for a release that Passed. The line in your
   README links it to the saved report, so it needs no website to show and it changes when you merge a new report.

Lantern writes only to a repository whose owner put its workflow there, and only with the token GitHub gives that
workflow. It never pushes to your main branch: the report arrives as a pull request that you merge.

## What a pull request changes

On a pull request Lantern checks the code twice, as it was before the pull request and as it is with it, and the
comment begins with the difference. It lists only what the two checks show:

* **Doors**: pages, routes and commands that were added or removed, with what a new route shows about a login
  ("Added `POST /api/admin/export`: no login check is shown, and it changes data"), and a login check that got
  weaker or was taken off a route that is still there.
* **Links between page and server**: a request the page still makes that no route answers any more (the route was
  removed, renamed or answers another verb now), and a new request that no route of the project answers.
* **Findings**: new ones, fixed ones, ones that were in the code before and that a page or route reaches only now,
  and ones accepted in this pull request.
* **Calls that cost money** (a model, a payment, a text message) that a route reaches now and did not before.
* **What the change touches**: how many functions changed, which pages and routes lead to them, and what they lead
  to (database tables, the shell, other services).
* **The release decision before and after**, for example `Passed → Blocked (1 new high finding)`.

Two versions that differ only in comments and spacing give a comment that says nothing changed. No model writes or
ranks any line of it. What the comparison cannot say is listed at its end (for example: a scanner that did not finish
on one side, or tests that were run on neither). The same report is on the run's page in its long form, and the full
report that is kept with each run holds it as `change/change.html`, `change/change.md` and `change/change.json`.

You get the same report on your own computer, for any two versions, with `lantern diff` (`lantern diff` alone
compares your last commit with the files as they are now; `lantern diff main...my-branch` shows what a pull request
would show).

## Set it up (one command)

In your project's folder:

```
lantern github setup
```

It writes:

* `.github/workflows/lantern.yml`, the workflow that runs Lantern on every push and pull request;
* `.lantern/report/README.md` and `badge.svg`, which say "no analysis yet" until the first report is merged;
* the badge line at the top of `README.md` (`--no-readme` leaves it alone; with no README it prints the line);
* where `.gitignore` leaves all of `.lantern/` out, the lines `.lantern/*` and `!.lantern/report/`, so the report can
  be committed while Lantern's other results stay out of git.

Then, on GitHub:

1. Commit and push these files.
2. Open **Settings → Actions → General**. Under **Workflow permissions**, tick **Allow GitHub Actions to create and
   approve pull requests** and press **Save**. Without it the comments still work, but GitHub refuses the pull request
   that saves the report (the run's page says so, and the report waits on the branch `lantern/report`).
3. Wait for the first check (the **Actions** tab shows it), then merge the pull request **Lantern report**.

A workflow file of that name that does not run Lantern is left alone unless you add `--force`.

## The workflow by hand

```yaml
name: Lantern
on:
  push:
    paths-ignore: [".lantern/report/**"]   # merging the report does not start a new one
  pull_request:
  workflow_dispatch:
permissions:
  contents: write
  pull-requests: write
jobs:
  lantern:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: LittleHenderson/Lantern@main   # `lantern github setup` names an exact commit or release
        with:
          require: not-blocked
```

### Settings of the Action

| Setting | Default | What it does |
|---|---|---|
| `path` | `.` | The folder to check, inside the repository. |
| `comment` | `true` | Post the result on each pull request, as one comment that is edited on every push. |
| `change` | `true` | On a pull request, also check the code as it was before it and say what the pull request changes. `false` checks once and leaves that part out. |
| `code-scanning` | `false` | Also hand the findings to GitHub's code scanning (see below). |
| `save-report` | `pull-request` | On the default branch, open or update the pull request that saves the report; `off` does not. |
| `require` | `not-blocked` | When the check fails: on Blocked (`not-blocked`), on anything but Passed (`passed`), or never (`none`). |
| `offline` | `false` | Skip the look-up of the project's libraries in the advisory databases (the result is then Incomplete at best). |
| `python-version` | `3.12` | The Python that runs Lantern. |
| `token` | the workflow's token | The token that comments and opens the pull request. |

Outputs: `decision` (Passed, Blocked, Incomplete or none) and `report-folder` (the results on the runner). The full
report (`report.html`, `evidence.html`, the map, every result file, the findings as `lantern.sarif`, and on a pull
request the `change` folder) is kept with each run as the download **lantern-report**, and the run's page shows the
same words as the comment.

### GitHub's code scanning (off unless you turn it on)

GitHub can show findings in the repository's **Security** tab and on the changed lines of a pull request. To hand
Lantern's findings to it, set `code-scanning: "true"` and add one line to the workflow's permissions:

```yaml
permissions:
  contents: write
  pull-requests: write
  security-events: write   # to hand the findings to code scanning
```

It is off by default because it changes what GitHub does: once it has findings, GitHub adds a check of its own,
"Code scanning results", to every pull request, and that check follows GitHub's rules and not the `require` setting
above. GitHub offers code scanning for public repositories, and for private ones with GitHub Code Security; where
it is not available, or the permission is missing, the run's page says so in one sentence and the check goes on.

## For engineers

* Facts come from the analysis, never from a model: the comment, the saved README and the badge are written from
  `evidence.json` by `lantern github summary` (`lantern/onrepo.py`). Every value from the results is written as text:
  a finding's title cannot make a link, an image, HTML, a mention or an issue reference.
* The Action installs Lantern from its own commit and writes that commit into the report, so the report names the
  exact Lantern that made it. To check a saved report:

  ```
  cp .lantern/report/evidence.json ../lantern-evidence.json
  git checkout <the commit the report names>
  pip install "lantern[scan] @ git+https://github.com/LittleHenderson/Lantern@<the Lantern it names>"
  lantern verify . --report ../lantern-evidence.json
  ```

  `.lantern/` is a folder Lantern never reads as code, so a merged report does not change the next result.
  `MATCH` says this Lantern finds the same results on that commit; a library warning published since can change the
  dependency part, and `lantern verify` names what differs.
* On a pull request GitHub checks out a merge of the change into the main branch; the commit the comment names is
  that merge (`git fetch origin pull/<number>/merge`).
* What a pull request changes is `lantern diff` (`lantern/diff.py`) between that merge commit's first parent, which
  is the main branch as it was merged into, and the files that were checked out. The Action fetches that one commit
  (`git fetch --depth=1`), Lantern copies it out of git into a folder of its own (git's attributes and filters that
  come with the repository decide nothing about the copy, and a link that leads out of the project is not made) and
  checks it as it checks any folder; the check of the pull request itself is not made a second time. A workflow that
  checks out something else (`ref:` on the checkout step) is compared with the commit where its branch began, which
  needs `fetch-depth: 0`; without that history the run's page says so and no comparison is made, because a
  comparison with the main branch as it is now would call everything main gained since "removed by this pull
  request". The results of the earlier commit's check are in the full report under `change/before/`.
* Findings reach code scanning through GitHub's own API (`POST /repos/{owner}/{repo}/code-scanning/sarifs`) with the
  workflow's token, as the file `lantern.sarif` that `lantern export --sarif` writes; no other service is involved.
* The project's tests are not run by the Action (Lantern runs a project's code only when asked), so the decision there
  is Incomplete at best. Run them in a step before it with `lantern analyze . --trace --sandbox -- <test command>` on a
  runner you trust if you want Passed.
* A pull request from a fork gets a read-only token from GitHub: Lantern then cannot comment, says so on the run's
  page, and the check still passes or fails on the result. Lantern uses `pull_request`, never `pull_request_target`,
  so a fork's code never runs with a token that can write.
* The Action needs GitHub's `gh` program, which GitHub's own runners have; on a runner without it the comment and the
  pull request are skipped with a warning.
