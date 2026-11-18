# Check before each push: results (2026-11-17)

`python bench/push_check.py` (module docstring: what it does and what it had to show, written down before its first
run). Each sample is copied into a repository of its own, its first commit pushed to a remote on this computer, the
hook written with `lantern hook install`, and every push made with a real `git push`. Offline, isolated
(`tools/netguard`, no address tried), a home folder of its own, so the first check of each sample finds nothing kept
for its files. Roadmap of 2026-11-14, stage 6, part 2 (`lantern hook install`, `docs/diff.md`, "Before each push").

## What it had to show (written before the first run)

* **The shop sample:** each of the three planted faults stopped (the push fails and the other side does not get the
  branch), each twin let through, and every push answered in under 3 seconds, the first one included.
* **Every sample:** both harmless pushes let through. Their times are written down, with no claim beyond the shop
  sample (a larger project takes two longer checks).

## First run (the shop sample, before any fix)

`--only shop`: 🟥 **a real fault in the hook.** The two harmless pushes went through, and the run then ended with an
error before the first planted fault: the check had written its receipt into the repository (`.lantern/push/main/`),
the next commit, made with `git add -A` as the measurement makes each commit (and as a person does who commits
everything), took the receipt into the project, and the checkout for the first planted fault then refused ("Your local
changes to the following files would be overwritten by checkout: .lantern/push/main/after/evidence.html …"). A person
would have pushed Lantern's receipts with their code. Fixed: `.lantern/push/` carries a `.gitignore` of its own that
leaves the whole folder out (`hook._receipts`, `IGNORED`). The test of a real push
(`test_a_push_that_brings_a_serious_finding_is_stopped_and_its_harmless_twin_goes_through`) now asks git whether
anything under `.lantern/push` is offered for a commit; on the code without the fix it fails (git lists the receipt's
files), with the fix it passes.

## After the fix

The shop sample alone first (`--only shop`): every result as written down; the harmless pushes 1.26 and 1.25 s, the six
planted changes 1.21 to 1.30 s. Then all 15 samples, 42 s for all of it, **0 results not as written down, 0 tries to
reach the network**:

| Planted in a new branch of the shop sample | Must be | Result | Seconds (whole `git push`) |
|---|---|---|---|
| a route that runs the command it is sent (`shell=True`) | stopped | stopped: "new critical finding B602 at shop/app.py:30" | 1.15 |
| its twin: the route runs a fixed command (a list, no shell) | let through | let through | 1.25 |
| a payment key written into a file of the page | stopped | stopped: "a secret written into a file: new critical finding stripe-live-key at web/src/payments.ts:1" | 1.28 |
| its twin: the key's place kept by filler | let through | let through | 1.22 |
| the route the page asks for renamed under it | stopped | stopped: "a request the page still makes that no route answers now: POST /backup (web/src/api.ts:11)" | 1.09 |
| its twin: the route and the page's request renamed together | let through | let through | 1.12 |

Each stopped push left the other side without the branch, and each twin's push gave it the branch. The hook's own
count of its two checks was 0.9 to 1.0 seconds of each; the rest is git and the start of the hook. The shop sample was
Blocked before every one of these pushes (its planted problems are on its first commit), and the three twins were let
through all the same, with the words "the release decision was Blocked before this push, for what was there already":
the check is about what a push brings.

Harmless pushes (a new notes file, then a line more in it), seconds for the whole `git push`:

| Sample | First push after the hook was written | Second push | Let through |
|---|---:|---:|---|
| aiapp | 1.25 | 1.22 | both |
| androidapp | 1.26 | 1.16 | both |
| cppapp | 1.14 | 1.06 | both |
| csharpapp | 1.01 | 1.08 | both |
| flutterapp | 1.00 | 1.07 | both |
| goapp | 1.14 | 1.17 | both |
| iosapp | 1.20 | 1.16 | both |
| javaapp | 1.15 | 1.12 | both |
| kotlinapp | 1.11 | 1.13 | both |
| nextapp | 1.13 | 1.19 | both |
| phpapp | 1.12 | 1.25 | both |
| rnapp | 1.05 | 1.07 | both |
| rubyapp | 1.15 | 1.06 | both |
| rustapp | 1.21 | 1.05 | both |
| shop | 1.11 | 1.12 | both |

On projects this small what the first check kept makes no difference the measurement can tell: the second push was
from 0.16 s faster (rustapp) to 0.13 s slower (phpapp).

## Run again on the final code (2026-11-17, 7:09 PM PST)

Three changes came after the run above. The hook file is opened as itself when Lantern looks for its mark (never
through a link, never waiting on a pipe). The hook is written so that only its owner can run or change it: Lantern's
check of itself flagged the first version, which every user of the computer could read and run. And this measurement
no longer sets `PYTHONPATH` for the hook, which finds this checkout's Lantern by itself (`hook.STARTER`); the run was
started with no `PYTHONPATH` at all, so it shows that too. All 15 samples, 48 s for all of it, **0 results not as
written down, 0 tries to reach the network**. Every push took 1.16 to 1.42 s, a little longer than in the run above
(1.00 to 1.30 s); the measurement does not say why. The hook's own count of its two checks was 0.9 to 1.2 s of each
of the 36 pushes.

| Planted in a new branch of the shop sample | Must be | Result | Seconds (whole `git push`) |
|---|---|---|---|
| a route that runs the command it is sent (`shell=True`) | stopped | stopped: "new critical finding B602 at shop/app.py:30" | 1.27 |
| its twin: the route runs a fixed command (a list, no shell) | let through | let through | 1.19 |
| a payment key written into a file of the page | stopped | stopped: "a secret written into a file: new critical finding stripe-live-key at web/src/payments.ts:1" | 1.30 |
| its twin: the key's place kept by filler | let through | let through | 1.17 |
| the route the page asks for renamed under it | stopped | stopped: "a request the page still makes that no route answers now: POST /backup (web/src/api.ts:11)" | 1.19 |
| its twin: the route and the page's request renamed together | let through | let through | 1.20 |

Harmless pushes, every one let through (seconds, first push after the hook was written / second push): aiapp 1.38 /
1.16, androidapp 1.24 / 1.33, cppapp 1.36 / 1.30, csharpapp 1.42 / 1.30, flutterapp 1.42 / 1.28, goapp 1.34 / 1.21,
iosapp 1.30 / 1.27, javaapp 1.36 / 1.37, kotlinapp 1.33 / 1.34, nextapp 1.42 / 1.36, phpapp 1.28 / 1.40, rnapp 1.27 /
1.25, rubyapp 1.35 / 1.38, rustapp 1.29 / 1.39, shop 1.25 / 1.32.

## What it does not show

The samples are small (16 to 55 functions, `bench/workspace_results.md`). A push costs two whole checks of the
project, so a larger project takes longer: one check took 8.88 s of a medium project and 52.05 s of a large one with
nothing kept (`bench/speed_results.md`, excalidraw and django), and a push of such a project takes two.

🟧 **Lantern's own repository** (793 files), measured by hand the same way (a copy with a remote on this computer, the
hook written, a harmless notes file pushed twice, `tools/netguard` around each push, a home folder of its own): the
first push took 96.99 s (the hook's own count 96.6 s), the second 101.90 s (101.5 s), both let through, 0 tries to
reach the network. What the first push kept made the second no faster: what each file reads as is kept
(`lantern/kept.py`), but Bandit, the data-flow step and the other scanners look at the whole project on each side
(`docs/diff.md`, "For engineers"), and on a project of this size they are most of the time. So the check answers in
under 3 seconds on the sample apps, as the roadmap's finish check asks, and not on a large project.
