# Link sweep: a file of a project that is a link out of it, a pipe, or a link to itself

Last run: 2026-11-10, `bench/links.py` as it is in this commit, on one machine (Linux, 4 CPUs, as root), offline
(`tools/netguard`: 0 attempts to reach anything). What the script does and what counts as a find is in its first
lines.

232 files: every file of the 15 sample projects under `tests/fixtures` (190 files) and the 42 files of `EXTRA`, the
files Lantern looks for by name that no sample holds. Each file in six states (taken away; a link out of the
project; the same link with an empty file at its end; the same link with nothing at its end; a pipe; a link to
itself), and each untouched project twice: 1424 runs of the whole analysis. `--jobs 2 --seconds 20`.

## All six states, Python 3.13.18

| Code | Read through | Tells | Held up | Stopped | Unstable | Time |
|---|---:|---:|---:|---:|---:|---:|
| main, the live code, before the link fix and before this stage (efa233a) | 25 | 15 | 129 | 2 | 0 | 1588 s |
| The stage with the link fix merged in (004e573) | 17 | 3 | 29 | 0 | 0 | 657 s |
| This change | 0 | 0 | 0 | 0 | 0 | 369 s |

## The state "a link to itself" under Python 3.12.3 (`--states loop`, 264 runs)

`Path.resolve()` raises `RuntimeError: Symlink loop` there and in 3.11; Python 3.13 does not, so the table above
cannot show this one.

| Code | Stopped | Where |
|---|---:|---|
| main before the link fix (efa233a) | 230 | `python_frontend.py`, `inside_repo` |
| The stage with the link fix merged in (004e573) | 28 | `js_frontend.py`, `_try` (an import that leads to the link) |
| This change | 0 | |

## What the code before did (004e573)

Read through a link (the results depend on what the outside file holds), 17 files:

`aiapp/notebooks/experiments.ipynb`, `androidapp/app/build.gradle`,
`androidapp/app/src/main/res/xml/network_security_config.xml`, `csharpapp/NotesApp/NotesApp.csproj`,
`extras/Cargo.toml`, `extras/go.mod`, `extras/notebooks/demo.ipynb`, `flutterapp/pubspec.yaml`, `goapp/go.mod`,
`iosapp/Journal.xcodeproj/project.pbxproj`, `iosapp/Journal/Info.plist`, `iosapp/Journal/Journal.entitlements`,
`kotlinapp/app/build.gradle.kts`, `nextapp/package.json`, `rnapp/app.json`, `rnapp/package.json`,
`rustapp/Cargo.toml`.

Tells (the results differ between a link to an empty file and a link to nothing), 3 files:
`androidapp/app/build.gradle`, `extras/package-lock.json`, `kotlinapp/app/build.gradle.kts`.

Held up by a pipe, 29 runs, by the innermost line of Lantern's code:

| Where | Runs | Files |
|---|---:|---|
| `js_frontend.py` `_nearest_package` | 11 | `package.json` |
| `js_frontend.py` `_load_jsonc` | 3 | `tsconfig.json` |
| `android.py` `_read` | 3 | `Info.plist`, the entitlements file, `project.pbxproj` |
| `python_frontend.py` `_scripts_from_config` (two lines) | 3 | `pyproject.toml`, `setup.cfg` |
| `aiapp.py` `notebooks` | 2 | a notebook |
| `dotnet.py` `find_projects` | 2 | a `.csproj` |
| `go_frontend.py` `module_path` | 2 | `go.mod` |
| `rust_frontend.py` `crates` | 2 | `Cargo.toml` |
| `flutter.py` `find_projects` | 1 | `pubspec.yaml` |

## What main did (efa233a)

Read through, 25 files: the 17 above, the notes file (`lantern-narratives.md`) and 7 Python source files, whose
lines Bandit quoted in its findings. Tells, 15 files: the 3 above, the notes file and 11 Python files. Held up, 129
runs: a pipe under the name of any file a reader opens, source files included (43 at `js_frontend.py` `add_js`, 17
at `java_frontend.py` `add_java`, 11 at `python_frontend.py` `parse_module`, 11 at `_nearest_package`, and 47 at 21
other lines). Stopped, 2 runs: a `requirements.txt` that is a link to itself (`OSError` in `depaudit.py`
`python_pins`). The link fix closed the source files, the notes file and Bandit; the dependency files were closed
earlier in this stage ("what a dependency file says is checked before it is used").

## What the sweep does not see

* A read that changes no result file. The file's content has to matter to the map, the findings, the readiness
  score or the Evidence Report, in the sample it sits in. `tests/test_project_files.py` adds, for files whose
  reading shows only when they hold something that matters, one test each with a file that does (the accepted-risks
  file, a project's own pack, a lock file, the Android signing key, a `setup.cfg` that names a script), and a test
  that reads every module of `lantern/` for a plain `open`, `read_text` or `read_bytes`. The `setup.cfg` test is the
  proof of this limit: on the code before, a `setup.cfg` that was a link out of the project made the function it
  named an entry point, and the sweep showed `setup.cfg` only as held up by a pipe, because the samples' file names
  no script.
* A tool that does not run in the sweep. Bandit was installed and ran; gitleaks was not installed; the dependency
  audits themselves (pip-audit, `npm audit`, the OSV lookups) do not run offline, only what Lantern reads of the
  dependency files before them does.
* Results that are read back, and which folder a saved map is about. Those were found by reading the code and are
  measured by a probe and by tests, not by this sweep.
* Windows. The sweep needs symbolic links and pipes as any POSIX user may make them.

## Kept in the record

* The first version of this script raised its time limit as an ordinary error, once. A reader that passes over
  whatever goes wrong with a file passed over the limit too. On the stage's own code that changed nothing: the
  corrected script gave the same 49 lines as the first run (17, 3 and 29). On main's code it did: a run waited on a
  second pipe for good and had to be stopped by hand. The limit is now raised as an error no reader catches by
  accident, and again every second until the analysis is left (`limited`), and
  `tests/test_project_files.py::test_the_sweeps_time_limit_is_not_passed_over_by_a_reader` plants the mistake three
  ways.
* The first measurements were made with five states under Python 3.13 only. The sixth state (a link to itself) and
  the run under Python 3.12 were added later the same day; under 3.13 alone the stop would not have shown.
