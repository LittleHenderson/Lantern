# Lantern audit package

Everything an outside reviewer (a person or another LLM) needs to audit and test Lantern end to end.
Read the files in this order:

| File | What it gives you |
|---|---|
| [`CURRENT_STATE.md`](CURRENT_STATE.md) | **Start here.** The commit to audit, what is released and live, what changed since the last outside audit, measured results with every miss, known open problems, where to look hardest |
| [`README.md`](README.md) (this file) | Setup, the one-command check, scope, how to report, and a ready-to-paste prompt for an auditing LLM |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How the pieces fit: pipeline, modules, data files and their fields, invariants the code must keep |
| [`CLAIMS.md`](CLAIMS.md) | Every product claim, the evidence for it, and how to try to falsify it |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Assets, trust boundaries, attackers, mitigations with file references, and known open risks |
| [`TEST_PLAN.md`](TEST_PLAN.md) | What the automated tests cover, manual and browser tests, adversarial cases to try, pass criteria |
| [`AUDIT_HISTORY.md`](AUDIT_HISTORY.md) | Earlier outside audits, what they found, and what changed |

The product spec is [`../Lantern_Product_Spec_v0.4.pdf`](../Lantern_Product_Spec_v0.4.pdf). Contributor notes are in
[`../../CLAUDE.md`](../../CLAUDE.md); accuracy measurements are in [`../../bench/README.md`](../../bench/README.md).

## What Lantern is, in one paragraph

Lantern reads a full-stack app (13 languages, phone apps included), builds a call graph with a confidence level on
every edge, links frontend HTTP calls to the backend routes that serve them, runs security scanners and its own rules,
follows request data across functions (Python and TypeScript/JavaScript), ranks each finding by who can reach it,
grades deployment readiness 0–100, makes a release decision (Blocked / Incomplete / Passed) that the score cannot
speak over, can run the project's tests and its app in a sandbox, and writes a commit-pinned Evidence Report with a
results digest anyone can re-check. A model of the user's choice only writes plain-language explanations, and every
phrase must anchor to real code or it is rejected. It runs locally (`lantern serve` opens a browser app; every
feature also has a command), and as a hosted website (`cloud/`) that reads code and never runs it, with a gateway
(`gateway/`) for sign-in and a free model allowance.

## Setup (about 2 minutes)

```bash
git clone https://github.com/LittleHenderson/Lantern && cd Lantern
python3 -m venv .venv && . .venv/bin/activate      # Python 3.11, 3.12, or 3.13
pip install -e ".[scan,dev]"
```

Optional, for browser tests: Node 18+ and `npm i -g playwright && npx playwright install chromium`.
No API key is needed: `tools/fake_model.py` is an offline OpenAI-compatible model for end-to-end runs.

To audit a specific commit, check it out (`git checkout <commit>`) and read this folder there: these seven files are
the whole audit package, and the source is the repository itself. No separate packet or source bundle is produced.

## The one-command check

```bash
bash tools/audit.sh            # tests, self-audit, both sample apps, digest verification, CLI smoke
bash tools/audit.sh --browser  # also drives the report viewer in Chromium (needs Playwright)
```

It prints PASS/FAIL per step and exits non-zero on any failure. Expected today: all PASS.

## Scope

In scope: everything under `lantern/`, `tools/`, `tests/`, the CI workflow, and the claims in `README.md` and
`CLAIMS.md`. Especially valuable:

1. **Correctness of facts**: wrong or missing call edges, wrong HTTP links, findings attached to the wrong function,
   wrong reachability paths, readiness checks that pass or fail for the wrong reason.
2. **Honesty**: anywhere the UI or a report claims more certainty than the code has (principle 2 in `CLAUDE.md`).
3. **Security of Lantern itself**: hostile repositories, hostile model output, other websites attacking the local
   server, key handling. See `THREAT_MODEL.md`.
4. **Usability**: can a non-expert install it, analyze their app, and understand the result?

In scope: the cloud service (`cloud/`, THREAT_MODEL T7, CLAIMS C1–C13), the gateway (`gateway/`, T8, G1) and the
test sandbox with its library fetch (`lantern/sandbox.py`, `_jail.py`, `libraries.py`, `_stores.py`, CLAIMS A4b–A4j).
Test the services on your own computer, never the live ones. Out of scope: device pairing (not built). Accuracy for the
languages other than Python and TypeScript/JavaScript is in scope as findings, but has no benchmark yet to compare with.

## How to report a finding

For each issue give: a title, severity (critical / high / medium / low / note), the file and line, a minimal
reproduction (ideally a tiny repo written with the `_write()` helper pattern from `tests/test_fullstack.py`), what
happened, what should happen, and a suggested fix. Separate verified issues from suspicions. Security issues in
Lantern itself go through the private process in `SECURITY.md`.

## Prompt for an auditing LLM

Paste this together with the repository (or give the model repository access):

> You are auditing Lantern, a local tool that maps, explains, audits, and grades full-stack apps. Start with
> `docs/audit/CURRENT_STATE.md` (the commit, what changed since the last outside audit, every recorded miss, where
> to look hardest), then `README.md`, `ARCHITECTURE.md`, `CLAIMS.md`, `THREAT_MODEL.md`, and `TEST_PLAN.md`.
> 1. Run `bash tools/audit.sh` and report its output. If you cannot run code, say so and do a static review only.
> 2. For each claim in `CLAIMS.md`, try to falsify it. Write the smallest repository that breaks it and show the
>    command and output. Mark each claim as held, broken, or not testable by you.
> 3. Work through every attacker in `THREAT_MODEL.md`. Try the adversarial cases in `TEST_PLAN.md` section 4 and
>    any others you can think of. Look hardest at: the local HTTP server (`lantern/server.py`), HTML generation
>    (`lantern/viewer/report.html`, `lantern/evidence.py`), file walking over untrusted repos, and anything that
>    reads model output.
> 4. Review the readiness checks in `lantern/readiness.py` for checks that can be gamed or that mislead.
> 5. Check that the user-facing text never claims more than the code proves (for example "your code never leaves
>    your computer" when a cloud model is selected).
> Report findings in the format in "How to report a finding". Do not invent results: if you did not run something,
> say so. End with the three changes you would make first.
