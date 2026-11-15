# Leave Lantern's report on your GitHub repository

Lantern can leave its report on the repository it checked, in three ways that work together:

1. **A comment on every pull request.** Each time someone proposes a change, Lantern checks it and posts one comment
   with the result: 🟢 **Passed**, 🔴 **Blocked** or 🟡 **Incomplete**, the open problems by how serious they are,
   why the result is what it is, and the most serious problems by file and line. On the next push it edits the same
   comment instead of adding another. The check itself fails when the result is Blocked, so a pull request shows a
   red cross until the problem is fixed or accepted with a written reason.
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
| `save-report` | `pull-request` | On the default branch, open or update the pull request that saves the report; `off` does not. |
| `require` | `not-blocked` | When the check fails: on Blocked (`not-blocked`), on anything but Passed (`passed`), or never (`none`). |
| `offline` | `false` | Skip the look-up of the project's libraries in the advisory databases (the result is then Incomplete at best). |
| `python-version` | `3.12` | The Python that runs Lantern. |
| `token` | the workflow's token | The token that comments and opens the pull request. |

Outputs: `decision` (Passed, Blocked, Incomplete or none) and `report-folder` (the results on the runner). The full
report (`report.html`, the map, every result file) is kept with each run as the download **lantern-report**, and
the run's page shows the same words as the comment.

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
* The project's tests are not run by the Action (Lantern runs a project's code only when asked), so the decision there
  is Incomplete at best. Run them in a step before it with `lantern analyze . --trace --sandbox -- <test command>` on a
  runner you trust if you want Passed.
* A pull request from a fork gets a read-only token from GitHub: Lantern then cannot comment, says so on the run's
  page, and the check still passes or fails on the result. Lantern uses `pull_request`, never `pull_request_target`,
  so a fork's code never runs with a token that can write.
* The Action needs GitHub's `gh` program, which GitHub's own runners have; on a runner without it the comment and the
  pull request are skipped with a warning.
