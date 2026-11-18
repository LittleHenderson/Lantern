# The security packs of roadmap stage 5, measured (2026-11-17)

Stage 5 of the roadmap of 2026-11-14 added rules for the ways full-stack and AI apps are broken into:
`LW-CLIENT-ENV-SECRET`, `LW-SERVER-IMPORT-IN-CLIENT`, `LW-SENSITIVE-COLUMN-RETURNED`, the project's data model read for
`LT-AUTHZ-OWNER` (the roadmap's `LAUTH-MISSING-TENANT-SCOPE`), `LW-UNSIGNED-WEBHOOK`, `LW-NONATOMIC-BALANCE`, and the
AI-app pack's second version: `LA-MODEL-OUTPUT-TO-TOOL` followed across functions and files, `LA-UNSAFE-MCP-TOOL` and
`LA-UNBOUNDED-AGENT-LOOP`. Each was measured on folders it was not written against, before and after its change, with
what the run had to show written down before its first run. Every folder was read and never run: no install, no test
run, no tracing, nothing of a project started. Linux, Python 3.13.18, four processor cores, the dependency audits off.

**This is not a recorded benchmark run.** The counts below come from Lantern's own result files, compared finding by
finding (rule, file, line text) by small scripts that are kept with the author's notes and not in this folder. Every
finding a rule of the stage made, and every place where one was expected to say something, was read by hand in the
project's code. The first numbers, the faults they showed and the numbers after the fixes are kept apart. Every rule of
the stage stays a heuristic (`tool_confidence: LOW`): for all but one of them no true case was found here, so no
precision is claimed.

## The folders

| Group | What | Folders |
|---|---|---|
| B | the seven projects of the map benchmark (`run_bench.py`) | 7 |
| S | the five starter projects downloaded for stage 1 (`modern_stack_results.md`, A to E) | 5 |
| F | the sample apps under `tests/fixtures` (one per language or kind of app; one of them calls a model) | 15 |
| L | Lantern's own gateway, website and engine, each read as it stood at the step measured | 3 |
| H | the held-out set (`heldout/`): its six local apps and the three public apps fetched on 2026-11-10 (its other five public apps were never fetched here, so they are not in these runs) | 9 |
| AI | seven public AI projects downloaded for this stage with the owner's permission (below) | 7 |

The rules were measured one by one on groups B, S, F and L (30 folders), the stage as a whole on group H, and the three
AI rules together on groups AI, B, S, F and L (37 folders).

## Rule by rule, on 30 folders (B, S, F, L)

"All findings" counts every finding outside test files, by rule, file and line text, before and after the step.

| Rule | What the folders hold for it | First numbers | After the fixes |
|---|---|---|---|
| `LW-CLIENT-ENV-SECRET` | 805 files read; 24 places give a setting every visitor's browser gets a value | 0 findings | (no fix) |
| `LW-SERVER-IMPORT-IN-CLIENT` | 590 JS/TS files; 75 begin with `"use client"`, 112 are loaded with them, 4 of those read a setting by name | 1 finding: a settings file of an env library that is made to be imported by pages; read by hand, a false alarm | fixed after a failing test: 0 findings |
| `LW-SENSITIVE-COLUMN-RETURNED` | 45 models; 34 places in 15 files ask for a record with a secret field; 23 Python routes | 0 findings; 11 models counted with a secret field, 14 queries as bringing one | a field that leads to another record and whose name says a secret was taken for a secret field of the record itself, and a record whose own name says a secret was not read as keeping it in its `hash`, `key` and `value` fields; fixed after a failing test: 12 models with a secret field, 9 queries that bring one, none handed to an answer, 0 findings |
| `LT-AUTHZ-OWNER` read with the data model | the findings of the rules that say who may reach what | 15 before, 15 after: none gone, none new, no rank changed | 3 of the 15 are false alarms that were there before: a web framework's own repository, whose tutorial app imports the framework's `g` from a folder of the project, so who is signed in is not known there |
| `LW-UNSIGNED-WEBHOOK`, and the two fixes of the login check | 3 webhook routes that write stored data, each only after the provider's own check | 0 findings; the 28 findings of `LW-AUTH-MISSING`, `LA-WALLET-DRAIN` and `LT-AUTHZ-*`: 28 before, 28 after, none moved | (no fix) |
| `LW-NONATOMIC-BALANCE` | 9 functions check a name with a balance word | none is a balance and none writes after its check: 0 findings; `LW-LIMIT-COUNTED-LATER` 0 before, 0 after its fix | (no fix) |
| `LA-MODEL-OUTPUT-TO-TOOL`, across functions and files | 2 model calls, both in the sample app that calls a model | all findings 478 before, 478 after: none gone, none new; one gained its flow (that sample's command run from the model's answer) | (no fix) |
| `LA-UNSAFE-MCP-TOOL`, and the fix of `x.write_text(text)` | no tool handed to a model in any of the 30 | all findings 478 before, 478 after: none changed | (no fix) |
| `LA-UNBOUNDED-AGENT-LOOP`, and the fix of a model call guessed by a method's name | 2 paid model calls (the same sample), no loop around them | all findings 478 before, 478 after: none changed | after the fix of three false alarms the author found by reading the rule as someone who wants it to fail: 478 and 478, none changed |

Time to read the 30 folders, where it was taken before and after a step (the webhook rule and each step after it):
from 9.3 percent less to 4.5 percent more; the largest increase was the agent-loop rule after that fix, 86.16 s before
the rule and 90.08 s after.

## The held-out set (H), before and after the whole stage

What it must show was written down before the run: every expected problem found before is found after, no new finding
at medium or above on a safe twin, every finding that is new, gone or changed read by hand, the release decisions and
call sites the same.

| | main (b1b3833) | Stage 5's code (bc8cc0a; the commits after it change documents and one comment only) |
|---|---|---|
| Findings | 235 | 235: 0 gone, 0 new, 0 with another rank, title, id, confidence or status |
| Expected problems (42) found at medium or above | 29 | 29 |
| Missed | 13 | 13 |
| Release decisions and call sites | | the same on all 9 apps |

The six rules `LW-CLIENT-ENV-SECRET` to `LW-NONATOMIC-BALANCE` alone were measured the same way earlier the same day,
as the stage's code stood before it was moved onto the new main, against Stage 4's head (2ca4915, the same tree as
main): the same numbers. In both runs the result pages of before and after are the same but for their label line.

## Seven public AI projects (AI), with the 30 folders

| | What | Language |
|---|---|---|
| P1 | a collection of MCP servers | Python and TypeScript |
| P2, P3, P4 | MCP servers | TypeScript |
| P5 | a chat bot with agents | Python |
| P6 | a command-line assistant | Python |
| P7 | a chat over documents | TypeScript |

They are not named in this repository. The run measured main (b1b3833) against the stage with all three AI rules
(6b44fe7), written down before its first run.

### First run

On all 37 folders: 1,124 findings before, 1,125 after; 0 gone, 1 new (below); 12 changed, read one by one: 11 gained
only the field that says where a flow's value came from, and one, in the sample app that calls a model, gained its flow
from the model call. The data-flow step finished on all seven projects (no time limit met). Time to read the 37 folders:
138.68 s before, 150.92 s after (8.8 percent more); the largest project 40.26 s and 42.28 s. Everything the stage
changed besides the three AI rules: 0 gone, 0 new, 0 changed.

| Rule | Findings | Read by hand |
|---|---|---|
| `LA-UNBOUNDED-AGENT-LOOP` | 1 | **real**: in P6, a function that makes a paid model call and calls itself again while the model asks for tool calls, with no count, clock or budget. 1 of 1. P3 has one paid call, in its evaluation scripts, with no loop around it: rightly none. P5 and P7 make no paid call Lantern knows: P5 calls its models through HTTP clients of its own, and P7 makes its chat model with `initChatModel` through a helper of its own (both expected to be known, both missed) |
| `LA-MODEL-OUTPUT-TO-TOOL` | 0 | nothing found, and that says little. P6 hands the model's streamed text through a generator and a printer object of its own to the command it runs after the person agrees: not followed, a miss; its other mode runs commands through a file of functions loaded at run time from the person's own folder: not followed. In P5 and P7 no model call is known (above) |
| `LA-UNSAFE-MCP-TOOL` | 0 | tools found in P4 only (2, no flow: the function handed to the library calls the tool's handler through an object of another file, which the map does not follow; read by hand, the tool keeps its folder inside the project's own with a check of its own, so no finding is right, but not for the reason Lantern can show). Not found at all: P1's Python servers (the MCP library's newer class `MCPServer`, a server made inside a function), P1's TypeScript servers (the newer package `@modelcontextprotocol/server`; and because one server puts a function of its own on its server objects' `registerTool`, the map withholds the library's name for every such call), P3's server (held as a field of a class, `this.server`). P2 is a thin wrapper, and the tools of P5 and P6 are classes of their own, not a library's: 0 there, as expected |

### After the fix, not an independent measurement

The newer names and a server made inside a function were then taught to the tool check after a failing test with
examples of the author's own (`tests/test_ai_tools.py`, 9a27cef). Run again on the same 37 folders, with what it must
show written down first: 1,125 findings before and after, none gone, new or changed; time 150.92 s and 150.40 s. P1's
three Python servers now have 18 tools, none of whose parameters reaches an action the rule names (the values go to a
library inside the folder the server allows, to an address fetched, or into a computation), so 0 findings, right for
each. Which address a tool fetches is not among the actions `LA-UNSAFE-MCP-TOOL` names. P1's TypeScript servers and P3
still have no tool found (`docs/ai-apps.md`, "What it does not do yet").

## The map benchmark (`run_bench.py`)

`python bench/run_bench.py WORKDIR --no-trace` on its seven projects, offline (`LANTERN_OFFLINE=1`), Stage 5's code
(bc8cc0a) against main (b1b3833): no count differs on any project. On both: 794 files, 6,917 functions, 11,372 links
inside the projects, 2,492 entry points, 4,561 calls not placed; findings outside test files 1 critical, 9 high, 17
medium and 184 low, and 4,730 in test files.

## What this says

* After the fixes above, no rule of the stage made a false alarm on these folders. The two first-run faults (one
  `LW-SERVER-IMPORT-IN-CLIENT` finding, the overcount of `LW-SENSITIVE-COLUMN-RETURNED`'s queries) were fixed after
  failing tests, and the numbers before the fixes are kept above.
* One true case on a real project: the agent loop in P6. For every other rule no true case was found here, so none has
  a measured precision, and all of them stay heuristics.
* The tool check and the model-text check do not yet find many of a real AI project's tools and model calls: the gaps
  that kept them quiet are named above and in `docs/ai-apps.md`.
