# Changelog

Each release has a section headed `## <version>`. The release workflow (`.github/workflows/release.yml`) puts the
section matching the pushed tag into the GitHub Release body (`v0.9.0-rc1` uses `## 0.9.0-rc1` if present, else `## 0.9.0`).

## Unreleased

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
  person who is not an administrator, until it is named the same way.
  Tests: 22 new ones in `tests/test_gitfacts.py` (66 in all) and 1 in `tests/test_cloud_runs.py`; one existing test
  in each file was extended. On the code before, 20 of the 22 fail (10 show the older answer, 10 try functions that
  code does not have) and 2 need Windows; the new cloud test and both extended tests fail as well. With the change,
  here: 62 pass and 4 need Windows (2 a junction, 2 Windows itself), and all 34 of `tests/test_cloud_runs.py` pass.
  Not covered by CI, and said in `docs/audit/CLAIMS.md` (A4f): the test with real other owners needs root; on
  Windows the calls are tried against Windows itself by two tests only, and the path for an administrator who is
  not elevated against a stand-in only.
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
