# Current state (read this first)

Written 2026-11-14 for an outside auditor, a person or an AI agent. It says where Lantern stands at one commit: what
is released, what is live, what changed since the last outside audit, what was measured, and what failed or was
missed. The other five files of this folder say how Lantern works and how to test it; this one says what to look at
now. Every number here is copied from a measured run; nothing is rounded.

## The commit to audit

| | |
|---|---|
| Repository | https://github.com/LittleHenderson/Lantern (public, default branch `main`) |
| Commit | `1f20c94d7f030b00f525a3a7145812186a7dfc61` (2026-11-14, PR #187, "a firm pass or fail", stage 2) |
| Latest release | v0.11.0, tag on `95c68e9` (2026-11-13), https://github.com/LittleHenderson/Lantern/releases/tag/v0.11.0: wheel, source package and a CycloneDX SBOM |
| Since the release | #186 (`be6a3c5`, tests get an answer in the sandbox) and #187 (`1f20c94`, a project's tests run on the libraries it names). Both are in `CHANGELOG.md` under "Unreleased" |

```bash
git clone https://github.com/LittleHenderson/Lantern && cd Lantern
git checkout 1f20c94d7f030b00f525a3a7145812186a7dfc61
```

## What Lantern is, and what it promises

Lantern reads a full-stack app and makes it understandable and defensible to a skeptical engineer. It is built for
people who build with AI help and do not read code ("vibe coders"), and for the engineers who have to check their
work. Two goals: a person who does not code can bring an app to the standard a senior full-stack engineer would ask
for; an engineer can check every claim the report makes. Security is the first area.

What it does: maps every function and call with a confidence level on each link (13 languages: Python,
TypeScript/JavaScript, Go, Rust, Java, Kotlin, Swift, Dart, C#, PHP, Ruby, C/C++; phone apps for Android, iOS,
Flutter, React Native, .NET MAUI), links frontend HTTP calls to backend routes, runs security scanners and its own
rules, follows request data across functions (Python and JS/TS), ranks each finding by who can reach it, grades
readiness 0-100, makes a release decision (Blocked / Incomplete / Passed) apart from the score, can run the project's
tests and its app in a sandbox, and writes a commit-pinned Evidence Report with a digest anyone can re-check. A
model only writes plain-language explanations; it never creates, closes or re-ranks a finding.

The six principles any change must keep are at the top of `CLAUDE.md` (facts from tools, words from models; show
confidence; Lens 3 anchoring; Lantern passes its own audit; heuristic checks say so; everything in the viewer is
escaped behind a hash-based Content-Security-Policy).

## The four things that run, and where

| Part | Where it runs | Version / state today | In scope |
|---|---|---|---|
| Command line and local app (`lantern analyze`, `lantern serve`, `lantern behave`, `lantern mcp`) | The person's computer | `main` at the commit above; v0.11.0 released | Yes, all of it |
| lantern-cloud (`cloud/`), the website | Fly.io, https://lantern-cloud.fly.dev/ | Deployed from `be6a3c5` on 2026-11-13 (reports version 0.11.0). #187 is merged and **not deployed**. The website reads code only: it never runs a project's tests, so its best decision is Incomplete | Yes (THREAT_MODEL T7, CLAIMS C1-C13). Do not attack the live service; run it locally (`tools/cloud_site_demo.py`) |
| Gateway (`gateway/`), the free model allowance and sign-in | Fly.io, https://lantern-gateway.fly.dev | 0.2.6, deployed from `95c68e9` on 2026-11-13 | Yes (THREAT_MODEL T8, CLAIMS G1). Same rule: test it locally |
| GitHub Actions (`.github/workflows/`) | GitHub | `ci.yml` runs 22 checks on every pull request | Yes |

The live services hold other people's data and the owner's provider keys. Hostile tests go against a local copy only.

## How to build and check it

```bash
python3 -m venv .venv && . .venv/bin/activate        # Python 3.11, 3.12 or 3.13
pip install -e ".[scan,dev]"
python -m pytest -q                                   # about 5 minutes on a fast machine; no network, no keys
ruff check lantern gateway cloud tests tools bench examples
lantern analyze . --out /tmp/self --offline           # Lantern's audit of itself
python tools/self_readiness.py /tmp/self/readiness.json
bash tools/audit.sh                                   # tests, self-audit, samples, digests, CLI (add --browser for Chromium)
lantern analyze . --trace --sandbox -- python -m pytest -q   # Linux: Lantern's own tests run by Lantern in its sandbox (about an hour)
```

`TEST_PLAN.md` has the full list, `CLAUDE.md` "Commands" has every benchmark.

Results on this commit (2026-11-14):

| Check | Result |
|---|---|
| GitHub CI, 22 checks on the head that became `1f20c94` | ✅ 22 of 22 green. Six Linux test jobs: 5,004 passed, 0 failed, 40 skipped each; coverage 87.93% / 87.94%. Both Windows jobs: 4,486 passed, 454 skipped. Both browser jobs: all PASS in Chromium, Firefox and WebKit |
| Lantern's own tests, run by Lantern inside its own sandbox | ✅ Release decision "Passed", 4,968 passed, 0 failed, 76 not run, 56 min 51 s, score 100, grade A |
| Lantern's audit of its own code, `lantern analyze . --offline`, run again on `1f20c94` on 2026-11-14 | ✅ 0 critical, 0 high, 0 medium, 82 low outside test code; 419 files, 7,143 functions, 39,956 call sites (11,850 not followed); readiness 92/100, grade A; decision Incomplete, because offline the library audit is skipped and this command runs no tests (the sandbox run above is the one with tests) |

## What changed since the last outside audit

The last outside audit (round 10, of `db01e52`, 2026-10-31) was a clean pass; `AUDIT_HISTORY.md` has every round.
Since then the code base roughly doubled. Nothing below has had an outside audit:

1. **v0.9.0 and v0.10.0 (2026-11-03):** the local app's redesign, starter apps, scenarios on findings, the cloud
   service (accounts through the gateway's GitHub/Google sign-in, uploads, share links, delete, explanations through
   the allowance, Ask Lantern with screenshots, Connect GitHub).
2. **Seven more languages and phone apps (2026-11-05):** Kotlin, Swift, Dart, C#, PHP, Ruby, C/C++; Android, iOS,
   Flutter, React Native, MAUI. Their link confidences are not yet backed by a benchmark per language.
3. **The release-reviewer directive (11 points, 2026-11-09 to 11-13, released as v0.11.0):** a held-out benchmark;
   every scanner writes how its run ended; every call counted once (`calls.json`); data followed across functions;
   behaviour checks (`lantern behave`); the release decision; hardening against hostile projects (links out,
   project files of the wrong shape, the project's git settings, programs started from the project's folder, npm
   settings, results written only where they belong, deletes only of what Lantern made, gateway limits for callers
   who have not signed in); tests and benchmarks cut off from the network and from the developer's keys; speed.
4. **"A firm pass or fail", stages 1 and 2 (2026-11-13/14, after the release):** the sandbox gives a project's tests a
   network of the run's own (this computer only), a copy they may change, time and memory limits; the libraries a
   project names are fetched for one run through a doorkeeper that reaches only the stores, and the tests then run
   on exactly those libraries with a read wall, a memory folder of the run's own and a "doorman" (a seccomp filter
   that decides every connection of a program that is not Python). This is the newest and least-reviewed code:
   `lantern/sandbox.py`, `lantern/_jail.py`, `lantern/libraries.py`, `lantern/_stores.py`, `lantern/winjob.py`.

## Measured results, with what was missed

Held-out benchmark (`bench/heldout/`: 14 apps, 79 known problems, 17 safe examples that must stay clean; no rule
was written from their code). Before the directive (`bc7cf10`) and at the release:

| | Before | Now |
|---|---:|---:|
| Known problems found at medium or higher, of 79 | 28 | ✅ 55 offline, 56 with the library checks |
| False alarms on the 17 safe examples | 3 | ✅ 0 |
| Vulnerable apps given a green result, of 8 | 2 | ✅ 0 (all 8 read Blocked) |
| Clean apps refused a green result, of 6 | 3 | 🟥 1 (one read Blocked through one false alarm, `LT-XSS` high; target was 0, recorded as missed) |
| One planted template-injection problem found at its documented line | not found | 🟥 still not found (recorded as missed) |
| Known problems missed (not even at low) | 49 | 🟨 24 (23 with the library checks) |

Other recorded misses and failures, kept on purpose:

* 🟥 Speed: the 12-file sample's first check got slower, 0.63 s → 0.74 s (Django 115.72 s → 52.05 s, Laravel 37.83 s
  → 19.38 s). Recorded as missed.
* 🟥 The first two versions of #187 failed: the first, 21 of 4,982 tests on GitHub and "Incomplete" with 334 failed
  tests in the sandbox; the second, 3 tests on GitHub. Twelve causes, each fixed after a failing test; one of them
  is a real limit on Linux kernels before 5.19 (below).
* 🟥 The first version of #186 failed 2 tests in the sandbox run ("Blocked"); a later run failed 1 test whose own
  setup was at fault (`tests/test_kept.py`), fixed before the merge.
* 🟨 Stage 2's finish check (three public projects from a link to Passed or Blocked): met for a Python project, a
  JavaScript project and the JavaScript half of a third; the third's Python half needs a library that is published
  only as source for this system, and Lantern builds nothing yet. Work in progress, not in this commit.
* ⬜ The tester round with real people has not been run.
* ⬜ The runtime-trace precision benchmark (`bench/run_bench.py`) was not re-run after the call-resolution changes.

## Known open problems a reviewer should know

Full lists: `THREAT_MODEL.md` "Known open risks, ranked" and `CLAUDE.md` "Known gaps". The ones that matter most:

1. **Windows:** in the sandbox no event loop starts under the Python guard, so async tests fail and `lantern behave`
   starts no app. A program the tests start that is not Python (JavaScript tests included) is kept from nothing by
   Lantern on Windows and macOS, the network included; the sheet and the log say so. A bare `python` started by a
   test inside an environment the test made is the computer's own Python, with no guard. Found, not fixed.
2. **Linux kernels before 5.19:** a program interrupted by its own signals faster than the doorman answers gets its
   connections late or not at all; after 1,000 unanswered requests in a row the run says so and failing tests read
   "missing", fewer than that and they read "failed".
3. **A sandbox inside a sandbox** (Lantern's own tests run by Lantern) has no doorman of its own: the outer run's
   decides its connections.
4. **The cloud service's steps** may read what the service's own user may read (open risk 0); their walls stop writes
   and the network, not reads.
5. **Release decision:** Blocked is decided by rank alone, so one false alarm at high blocks; the website can never
   say Passed (it does not run tests); projects in Go, Rust, Dart, .NET, Swift or C/C++ that list libraries read
   Incomplete because no library check exists for them.
6. **Analysis:** data flow, authorization rules and the call inventory cover Python and JS/TS only; authorization
   rules are heuristics (`tool_confidence: LOW`) and read evidence per route, not per record.
7. **Readiness can be gamed** with placeholder files (disclosed in the report's Limits).

## Where to look hardest

1. The sandbox and the library fetch (`sandbox.py`, `_jail.py`, `libraries.py`, `_stores.py`): can a test, a library
   or a project file reach the network, another program's socket, the person's files, or outlive the run? Can a
   hostile test make a run read Passed? (CLAIMS A4b, A4d, A4e, A4j; THREAT_MODEL T1.)
2. The release decision (`release.py`, `seal.py`, `readiness.py`, `evidence.py`): can planted results, a planted
   `lantern-accepted.json`, a `# nosec` comment or a behaviour record make a project read better than it is? (R5-R9.)
3. The cloud service and the gateway (`cloud/lantern_cloud/`, `gateway/lantern_gateway/`): sign-in, session tokens
   (one token per sign-in, up to 8 per account, "sign out everywhere"), the HttpOnly SameSite=Strict cookie and
   `X-Lantern-Site` header, share links, delete, run limits (300 runs per person a day, 1,000 for everyone), clean-up
   of other people's results, the limits for callers who have not signed in. (C1-C13, G1, T7, T8.)
4. The viewer's escaping and CSP (`viewer/report.html`, `viewer/app.html`, `evidence.py`, `cloud/.../site.py`):
   `tools/poison_report.py` and `tools/audit.sh --browser` are the starting points. (Principle 6.)
5. Honesty: any sentence in the UI, a report, the badge or the docs that claims more than the code shows.
6. Findings: false negatives on real apps in any of the 13 languages, false positives that block a clean app, and
   ranks that move without evidence written on the finding (S25).

## Open pull requests at this commit

None of Lantern's own work is open for review. Open on GitHub: Dependabot updates (#121-#126, #169, #176, #177, not
merged, not reviewed) and older drafts that are not part of the product (#40, #96, #130-#136). Their branches are out
of scope. Issue #58 (recording JavaScript and other languages' test calls) is open.

## How to report

As in `README.md`, "How to report a finding". Security problems in Lantern itself go through `SECURITY.md`. Say what
you ran and what you only read. A finding is most useful with the smallest repository that shows it.
