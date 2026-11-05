# 2026-11-04: lantern-cloud crashed on every real repository

**Noticed by / how:** Wakil, trying the first real Android app (HerSheild) on lantern-cloud the evening the mobile
checks shipped; every run ended with "the analysis crashed" and no report.

**For how long, who was affected:** a few hours on 2026-11-04, between the redeploy that pulled in the new parser
version and the fix. Everyone who started a run on lantern-cloud in that window; the local app (`lantern serve`) was
affected too for anyone who had installed that day.

**What happened:** the parser library Lantern uses for every language (tree-sitter) published version 0.26.0 with a
memory bug: parsing a file longer than about 256 lines corrupted memory and the process died with a signal, before
Lantern could write anything. Lantern's dependency said "tree-sitter 0.25 or newer", so a fresh install picked up the
new version. The cloud service showed a bare "crashed" label with no clue.

**What fixed it:** PR #101 pinned the dependency away from 0.26.0 and made the cloud service say plainly "Lantern's
analysis crashed (signal N) before it could write anything. This is a bug on Lantern's side, not in your code."

**What stops it next time:**

* a regression test fails if that version is ever allowed again (`tests/test_frontend.py`);
* Lantern's own libraries are pinned to exact versions in `requirements-lock.txt` and the cloud image installs from
  it, so a new library version can only arrive through a Dependabot pull request that runs the full test suite first
  (test checklist 2.6, 9.2);
* a 30-minute uptime check (`.github/workflows/uptime.yml`) emails when lantern-cloud stops answering or runs an
  engine older than the latest release, so the first sign is a mail, not a tester (9.3, 9.5).

**Open:** nothing.
