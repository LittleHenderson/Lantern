"""CI's network recorder is strace 7.3 with its makers' fix of 2026-11-10, built from its source.

`tools/netless.py --watch` has strace write down every address any program of a run tries. Every released strace
(7.3, of 2026-10-22, and older) can stop at random when a program it follows ends right after a signal: a failed
PTRACE_GETSIGINFO is taken for a group-stop, PTRACE_LISTEN is asked of a program that is in none, the kernel answers
with an input/output error and strace ends the record (strace's issue 433). In CI's Linux test jobs that cut the
record of the tests off on 2026-11-14, 2026-11-17 and 2026-11-18 (since 2026-11-18 the runner says so: result 6). Its
makers fixed it after that release (commit 3a4f0c7c3969ec6e25e729ed6b36a0391764a375), so no packaged strace has the
fix yet, and on 2026-11-20 the owner chose to have CI build the release with that commit as it is. These tests keep
it so:

- the commit is kept in `tools/strace/` byte for byte as `git format-patch` writes it from its makers' repository;
- every job that records a run builds its recorder before it records, from the release checked against its
  fingerprint first, and shows the makers' own test of this fault failing on the release as it is, with the error CI
  saw, and passing once the fix is in;
- no workflow installs a packaged strace beside it, and the step ends by checking that the strace found the way the
  recorder finds it (the PATH handed to it under sudo) is the one built, at version 7.3.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
RELEASE = "https://github.com/strace/strace/releases/download/v7.3/strace-7.3.tar.xz"
RELEASE_SHA256 = "529634c40910895a9a1f3c5c1e65da2ca9ed72fb158dfc4bcc89efdf05e39b72"
FIX = "3a4f0c7c3969ec6e25e729ed6b36a0391764a375"
PATCH = "tools/strace/3a4f0c7.patch"
PATCH_SHA256 = "886a939b9b051831bbe6e11edb8e4f24a0c63e4630e51d00b4e912d251530323"
FILES = ["NEWS", "src/.gitignore", "src/Makefile.am", "src/disable_ptrace_getsiginfo.c", "src/strace.c",
         "tests/Makefile.am", "tests/gen_tests.in", "tests/getsiginfo-esrch.sh"]
# Not applied to the release: the list of news (written for the next release), git's list of files to ignore (not
# in a release), and the build list the release's build files were made from (the helper it adds is built with the
# rule of its twin). Everything else of the commit is applied as it is.
NOT_APPLIED = ["NEWS", "src/.gitignore", "src/Makefile.am"]
MAKERS_TESTS = ["getsiginfo-esrch.gen.test", "getsiginfo-esrch--seccomp-bpf.gen.test"]
THE_FAULT = r"ptrace\(PTRACE_LISTEN,[^)]*\): Input/output error"      # strace 7.3's words for it (src/strace.c)
BUILT = "/usr/local/bin/strace"


def _jobs():
    for path in WORKFLOWS:
        for name, job in (yaml.safe_load(path.read_text(encoding="utf-8")).get("jobs") or {}).items():
            yield path.name, name, job


def _recording_jobs():
    """Each job that runs the no-network runner with its recorder: (workflow, job, its steps, the index of that step)."""
    for wf, name, job in _jobs():
        steps = job.get("steps") or []
        records = [i for i, step in enumerate(steps) if re.search(r"tools/netless\.py\s+--watch\b", str(step.get("run")))]
        if records:
            yield wf, name, steps, records[0]


def _build_step(steps: list, recorded: int) -> tuple[dict, str]:
    built = [i for i, step in enumerate(steps) if RELEASE in str(step.get("run"))]
    assert len(built) == 1 and built[0] < recorded, (built, recorded)          # built once, before it records
    return steps[built[0]], steps[built[0]]["run"]


def _at(run: str, text: str) -> int:
    assert run.count(text) == 1, (text, run.count(text))
    return run.index(text)


def test_the_fix_is_its_makers_commit_byte_for_byte():
    data = (ROOT / PATCH).read_bytes().replace(b"\r\n", b"\n")    # a checkout on Windows may write line ends of its own
    assert hashlib.sha256(data).hexdigest() == PATCH_SHA256       # changed in any way, it is no longer their code as it is
    text = data.decode("utf-8")
    assert text.startswith(f"From {FIX} Mon Sep 17 00:00:00 2001\n"), text[:80]
    assert "\nSubject: [PATCH] strace: handle ESRCH from PTRACE_GETSIGINFO during\n termination\n" in text
    assert re.findall(r"^diff --git a/(\S+) b/\1$", text, re.M) == FILES
    assert "Resolves: https://github.com/strace/strace/issues/433" in text


def test_no_workflow_installs_a_packaged_strace():
    """A packaged strace has the fault. Installed beside the one CI builds, the order of PATH would decide which one
    records, and nothing would say so."""
    installs = 0
    for path in WORKFLOWS:
        for line in path.read_text(encoding="utf-8").splitlines():
            if re.search(r"\b(?:apt-get|apt|brew|choco|dnf|yum|snap|pip|npm)\s+install\b", line):
                installs += 1
                assert not re.search(r"\bstrace\b", line), (path.name, line.strip())
    assert installs                                               # the pattern still finds the lines it is about


def test_every_job_that_records_a_run_builds_its_recorder_first_from_the_release_checked_against_its_fingerprint():
    jobs = list(_recording_jobs())
    assert [(wf, name) for wf, name, *_ in jobs] == [("ci.yml", "test")], jobs     # the jobs it is about are found
    for wf, name, steps, recorded in jobs:
        step, run = _build_step(steps, recorded)
        assert step.get("shell") == "bash", (wf, name)
        assert type(step.get("timeout-minutes")) is int and 0 < step["timeout-minutes"] <= 15, (wf, name)
        fetched = _at(run, f"--output strace-7.3.tar.xz {RELEASE}")
        checked = _at(run, f'echo "{RELEASE_SHA256}  strace-7.3.tar.xz" | sha256sum --check --strict')
        unpacked = _at(run, "tar -xJf strace-7.3.tar.xz")
        assert fetched < checked < unpacked, (wf, name)              # nothing of it is read before its fingerprint holds


def test_the_step_shows_the_makers_test_failing_on_the_release_and_passing_with_their_fix():
    for wf, name, steps, recorded in _recording_jobs():
        _, run = _build_step(steps, recorded)
        fix = _at(run, f'fix="$GITHUB_WORKSPACE/{PATCH}"')
        # first everything of the commit but the fix itself and the three files the release does not use: the
        # helper and the test the commit adds
        first = _at(run, "git apply " + " ".join(f"--exclude={f}" for f in [*NOT_APPLIED, "src/strace.c"]) + ' "$fix"')
        configured = _at(run, "./configure ")
        assert "--enable-gcc-Werror" not in run                   # a newer compiler's new warning is no failure here
        made = run.index('make -j"$(nproc)"', configured)
        helper = _at(run, "make -C src -f Makefile -f - disable_ptrace_getsiginfo <<'RULE'")
        assert ("disable_ptrace_getsiginfo$(EXEEXT): disable_ptrace_getsiginfo.$(OBJEXT) "
                "$(disable_ptrace_getregset_DEPENDENCIES) ; $(LINK) disable_ptrace_getsiginfo.$(OBJEXT) "
                "$(disable_ptrace_getregset_LDADD) $(LIBS)\nRULE\n") in run              # the twin helper's own rule
        assert _at(run, f'tests="{" ".join(MAKERS_TESTS)}"') < _at(
            run, 'for t in $tests; do tests/gen_tests.sh tests/gen_tests.in "tests/$t"; done')
        harness = _at(run, 'STRACE="$1" TIMEOUT_DURATION=120 make -C tests check TESTS="$tests" '
                           'check_PROGRAMS="run_expect_termsig unblock_reset_raise"')
        assert f"fault='{THE_FAULT}'" in run
        # on the release as it is: the test must fail, both ways, and with the fault CI saw
        release = _at(run, 'if makers_test "$PWD/src/strace"; then')
        failed = _at(run, """grep -qx ':test-result: FAIL' "$b.trs" && grep -E "$fault" "$b.log" """)
        # then the fix itself, built and installed, and the same test must pass on what was installed
        fixed = _at(run, 'git apply --include=src/strace.c "$fix"')
        remade = run.index('make -j"$(nproc)"', fixed)
        installed = _at(run, "quietly sudo make install")
        again = _at(run, f"makers_test {BUILT} ||")
        passed = _at(run, """grep -qx ':test-result: PASS' "$b.trs" ||""")
        assert (fix < first < configured < made < helper < harness < release < failed < fixed < remade < installed
                < again < passed), (wf, name)


def test_the_step_ends_by_checking_that_the_recorder_finds_the_strace_it_built():
    """tools/netless.py looks strace up on the PATH sudo hands it (`shutil.which`), as the tests step starts it: the
    same lookup, under the same sudo line, must give the one built, and that one must say it is 7.3."""
    for wf, name, steps, recorded in _recording_jobs():
        _, run = _build_step(steps, recorded)
        found = _at(run, """found=$(sudo env "PATH=$PATH" sh -c 'command -v strace')""")
        same = _at(run, f'test "$found" = {BUILT} ||')
        version = _at(run, """first=$(sudo env "PATH=$PATH" strace -V | sed -n 1p)""")
        said = _at(run, """test "$first" = "strace -- version 7.3" ||""")
        assert _at(run, "quietly sudo make install") < found < same < version < said, (wf, name)
        assert 'sudo env "PATH=$PATH" "HOME=$HOME"' in steps[recorded]["run"]    # the PATH the recorder is handed
        assert steps[recorded]["run"].count("tools/netless.py --watch") == 1
