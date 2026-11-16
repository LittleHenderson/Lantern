# A fix that is a fix (`lantern fix`, the fix contract)

A finding stops showing for many reasons that are no fix. A comment excuses it. The code is moved to a file
Lantern reads differently, or to a folder it does not read at all. The call is put together at run time, so the
scanner no longer recognises it. The route that led to it is taken away, or the test that would have failed is
deleted. A coding assistant that is asked to "make the finding go away" finds these ways quickly, and until
2026-11-16 Lantern's own recheck called several of them "fixed", because it looked only for the finding's id.

Now a fix is held to a **contract**: Lantern compares the check made before the fix with the check made after
it, part by part, and calls the finding fixed only when no part is broken.

## The seven parts

| Part | What the fix has to show |
|---|---|
| `gone` | The finding is gone: its rule is no longer found on that code, in that file or at a place the code was moved to |
| `no-suppression` | Nothing was hushed: no new `# nosec` comment and no new entry in the list of accepted risks came with the fix |
| `still-read` | Lantern still reads what it read before: every scanner that finished before finished again, and no code was put where Lantern does not read it |
| `links` | Every door of the app is still there under its address, and every request of a page still finds the route that answered it |
| `calls` | Every call Lantern could follow before can still be followed: none was put together at run time or sent into code Lantern does not read |
| `nothing-new` | Nothing got worse elsewhere: no new finding ranked medium or higher, no finding reached or ranked higher than before, no login check weaker |
| `tests` | The project's tests are all still there, and they were run on the fixed code and passed |

Each part comes back as `held`, `broken` or `not-shown`, with what Lantern read there as sentences. The verdict:

* **passed**: every part held. This needs the tests to have run on the fixed code.
* **refused**: at least one part is broken. The answer names the part and the place.
* **incomplete**: nothing is broken and something is not shown. Most often the tests were not run; Lantern runs
  a project's code only when asked, and tests that were not run prove nothing.

Everything is read from the two checks' result files. Nothing here accepts, closes or re-ranks a finding: the
contract only refuses to call one fixed. A risk that is meant to stay is accepted by a person, with
`lantern accept` and a written reason.

## In a terminal

```bash
lantern fix brief PATH FINDING            # before the fix: where it is, how it is reached, the contract
lantern fix check PATH FINDING -- python -m pytest -q      # after the fix, with the tests run in the sandbox
lantern fix check PATH FINDING            # without the tests: "incomplete" at best
```

`FINDING` is the id from the Findings page (or the beginning of one). `PATH` may be left out for the folder you
are in. Options come after the two names, the test command after `--`.

`fix brief` prints the file and line, the path a user takes to the line, how outside input gets there step by
step, and the seven parts. It also **keeps the check as it is now** in Lantern's own folder
(`LANTERN_HOME/fix-briefs/`, outside the project), as the one the fix is compared with.

`fix check` analyzes the project again, runs the test command in the test sandbox when one is given, and prints
the verdict part by part. It ends with **0** when the fix passed, **1** when it is refused, **3** when it is
incomplete and **2** when nothing could be checked. `--format json` prints the data.

Which check the fix is compared with is always said in the first line. It is the check kept for that finding:
by `fix brief`, or else by the first `fix check`, which keeps the project's last check before it analyzes again.
So a fix made in several steps is compared with the code as it was before the first step, and **a "fix" that was
refused cannot be made to pass by checking it a second time**. A kept check is let go when a fix made in the
project passed; `fix brief` asked again starts from the code as it is then.

## A fix in another folder, and a change to apply

When the fix was made in a copy of the project (by an assistant in its own working folder, or by you):

```bash
lantern fix check PATH FINDING --candidate COPY --suggest fix.patch -- python -m pytest -q
```

Lantern makes a throw-away copy of the project, puts the candidate's change onto it, and analyzes and tests that
copy. Your project and its results are left exactly as they are. **Only when the fix passed** is the change
written to `fix.patch`, in the form `git apply fix.patch` and `patch -p1 < fix.patch` take. What was analyzed,
what the tests ran on and what is written out are one and the same change. The file is written byte for byte on
every system: its lines end as the lines of the files it changes end, also where those end the Windows way.
Lantern applies nothing and sends nothing anywhere: applying the change is yours to do.

## For an assistant (the connector)

`lantern_fix_brief` gives an assistant the same brief as data, and `lantern_recheck` holds its fix to the same
contract (`docs/connectors.md`). The connector starts no code of a project, so after a true fix it answers
`fixed` with the verdict `incomplete`: the tests have still to be run, in a terminal. "Fix this for me" in the
app is held to the contract too: a change that only hides the finding reads "Don't apply this one", with the
reason.

## What it does not show

* **What the tests ask.** A test that is still there under its name, with its checks taken out or switched off
  with a skip mark, counts as there. The contract sees a test that is gone, and that the run passed.
* **Code hidden from the JavaScript reader.** Whether a call that is newly read as a library's names a file of
  the project in a folder Lantern leaves out is looked up for Python imports only.
* **The code before the first check.** The fix is compared with the check that stood when the brief was asked for
  or the fix was first checked. What was done to the project before that is not held against the fix.
* **A change text cannot carry.** No suggested change is written for a file that is not UTF-8 text or is over
  2 MB, for a file name outside plain ASCII or with a quote or a backslash in it, or for more than 8 MB in all;
  the command says so and ends with 2. A candidate's change inside a folder Lantern leaves out (`node_modules`,
  `build`, `vendor`) or to a link is in neither the check nor the written change.
* **Rules that were changed with the fix.** A finding made by an analysis pack that stops showing after the pack
  itself was changed, or taken away, is "not shown" to be gone: change a pack in a change of its own.
* **A suggestion on GitHub.** The checked change is a file for a person to apply. Posting it on a pull request
  as a suggested change is not built yet.
