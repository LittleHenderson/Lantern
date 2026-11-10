# Real-model explanation runs

New rows come from `python bench/explain_eval.py tests/fixtures/shop --live --model lantern/claude-haiku-5-5
--destination lantern-gateway.fly.dev --max-requests 80 --record docs/explain-runs.md --note "…"` (or the `model-eval`
workflow in the Actions tab), which prints the row in the lens-v5 table's shape; paste it under the latest table. It is
part of the live suite (`bench/live.py`): without `--live`, the model, the one host the code may go to and the request
cap it sends nothing. Run it before the default model changes and after any provider announcement (test checklist 8.4).

The record of `lantern explain` against real models, with the anchor validator unchanged (it is never loosened to
make a model pass). Target: 90% of explanations validated on the first try. Sample: the 25 selected functions of
`tests/fixtures/shop` (React + FastAPI), one metaphor world, retries = 1.

| Date | Model (via) | Validated | First try | Tokens in / out | What changed before this run |
|---|---|---:|---:|---:|---|
| 2026-11-01 | claude-haiku-5-5 (gateway) | 7 / 25 | 2 | 54,630 / 115,225 | first run. Thinking ate the output budget: JSON cut off |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 10 / 25 | 3 | 77,908 / 55,944 | thinking off, forced tool call for JSON. Model wrapped the answer in `{"answer": …}` |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 12 / 25 | 3 | 79,901 / 57,908 | unwrap. Nested objects arrived as JSON strings; `term` anchors pointed at other units |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 18 / 25 | 16 | 59,608 / 42,077 | decode nested strings; `term` must be in this unit's lines; glossary extended; ids copied verbatim (lens-v4) |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 17 / 25 | 11 | 67,047 / 45,606 | same prompt, 4–5 pairs, bare symbol ids in the listing (run-to-run variance is real) |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 22 / 25 | 19 | 54,832 / 35,293 | pre-filled `findings` skeleton; "check every pair with an exact search" |
| 2026-11-01 | deepseek-flash (gateway fallback) | 1 / 1 | 1 | – | one function while Anthropic was out of credits |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 21 / 25 | 15 | 61,726 / 39,109 | final lens-v4 prompt, run A |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 22 / 25 | 18 | 56,500 / 35,581 | final lens-v4 prompt, run B |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 22 / 25 | 16 | 59,116 / 37,567 | model-invented findings dropped and counted (4 this run) instead of failing the explanation |

| 2026-11-01 | claude-haiku-5-5 (gateway) | 12 / 12 (nextapp) | 10 | 25,254 / 16,022 | Next.js + Supabase fixture, 12 functions, run A; 1 invented finding dropped |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 12 / 12 (nextapp) | 11 | 23,199 / 14,309 | Next.js + Supabase fixture, run B; 1 invented finding dropped |

### lens-v5: REPAIR, Lens 1 read-back, UNDETERMINED

Three ideas carried over from the HELM project's gate design: a failed answer gets a targeted REPAIR of only the
failing pairs instead of a full retry; Lens 1 may name only code the prompt actually showed (read-back); the model
may answer UNDETERMINED (at least 25 characters, a real sentence) instead of guessing, which is shown as "no plain-words
explanation", never as a failure.

| Date | Model (via) | Validated | First try | Repaired | Undetermined | Invented dropped | Tokens in / out | What changed before this run |
|---|---|---:|---:|---:|---:|---:|---:|---|
| 2026-11-01 | claude-haiku-5-5 (gateway) | 20 / 25 | 12 | 2 | 2 | 2 | – | first lens-v5. Read-back too strict: rejected `app.db`, `cli.py`, `self.execute`, names from callee summaries. UNDETERMINED misused ("no") |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 19 / 25 | 11 | 2 | 1 | 4 | – | same prompt, run B |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 11 / 12 (nextapp) | 8 | 1 | 1 | 0 | – | same prompt |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 10 / 12 (nextapp) | 6 | 1 | 1 | 0 | – | same prompt, run B |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 20 / 25 | 15 | 4 | 0 | 3 | 66,824 / 34,139 | read-back knows callee names, file name, `self.`/`this.`; UNDETERMINED needs a sentence and callee bodies are not an excuse |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 9 / 10 (nextapp, **partial**) | 7 | 2 | 0 | 0 | 24,019 / 11,904 | same; the free allowance ran out after 10 of 12 functions (stopped cleanly, work kept). 2 functions NOT RUN |

| 2026-11-01 | claude-haiku-5-5 (gateway) | **25 / 25** | **20** | 4 | 0 | 4 | 58,443 / 28,423 | pair-drop on (after a failed REPAIR). 0 pairs dropped: REPAIR fixed them. First run with every function passing |
| 2026-11-01 | claude-haiku-5-5 (gateway) | 11 / 12 (nextapp) | 10 | 1 | 0 | 0 | 27,878 / 14,052 | pair-drop on; the one miss took the full-retry path, which did not reach the drop step |
| 2026-11-01 | claude-haiku-5-5 (gateway) | **12 / 12** (nextapp) | **10** | 1 | 0 | 0 | 27,906 / 14,345 | pair-drop also applied when the last retry ends on a pair error. 0 pairs dropped |

**Best complete pair of runs so far (lens-v5 + REPAIR + pair-drop): shop 25 / 25 validated, 20 first try (80%);
nextapp 12 / 12, 10 first try (83%).** One run each, so run-to-run variance (seen at ±3 with lens-v4) is not yet
measured on this version. The first-try target of 90% is not met.

Re-scored offline from the stored answers of the two runs before those, with the pair-drop rule added afterwards (a pair the
REPAIR still could not anchor is removed and recorded in `dropped_pairs`; at least 3 pairs must remain; nothing is
added): shop would be 23 / 25, nextapp 10 / 10 of those run. This is a re-score of the same model output, not a new
run; it is listed so the next real run has a number to beat.

**Claim ceiling: FIXTURES_ONLY.** Every number above comes from Lantern's own two sample apps (25 + 12 functions),
written by the same people who wrote the prompt. Nothing here says how the explanations do on real repositories; the
`bench/` repos are the next step, and until they are run no accuracy claim beyond "on the fixtures" may be made in
the README, the app or the landing page.

**Hard gate: invented findings.** A run in which any model-invented finding reaches a reader is a FAILED run, whatever
its pass rate. Invented findings are dropped before storage and counted in `stats["invented_findings"]`; the viewer
never sees them. Every run above passed this gate (0 shown); the counts in the "Invented dropped" column are how many
were caught.

**Reading of lens-v5 so far.** It did not raise the first-try rate on the fixtures (15 of 25 vs 15–18 with lens-v4);
what it did was replace silent failures with named ones: 4 explanations saved by a targeted REPAIR instead of a full
re-ask, 0 false UNDETERMINEDs after the tightening, 3 invented findings caught. The read-back caught no real
hallucinated name in the final run, which is itself a finding: on these fixtures Haiku does not invent function names
in Lens 1. The remaining misses are paraphrased pair phrases that survive one REPAIR; the pair-drop rule addresses
exactly that and is measured next.

**Next.js sample: 12 of 12 validated in both runs, 10 and 11 on the first try (83%, 92%).**

**Stable number with the final prompt (three runs, shop): 21–22 of 25 validated, 15–18 on the first try (60–72%).**

The model keeps inventing a security finding when it sees an obvious problem the scanners did not report (4 times in
25 functions, even when told not to). Those entries are now removed before anything reaches a reader and counted in
`stats["invented_findings"]`; the explanation itself still has to pass every anchor check. Remaining misses: a nested
object sent as a JSON string with a stray trailing brace (now parsed leniently at the gateway), and a paraphrased
pair phrase now and then. Next: the bench repos; the first-try target is 90%. See the lens-v5 section above.

## Benchmark repos (code nobody on this project wrote)

The seven `bench/` repositories, `lantern explain --max-nodes 25` (entry points plus 3 call levels, bottom-up),
lens-v5 with REPAIR and pair-drop, Claude Haiku 5.5 through the gateway, one run each on 2026-11-01. Where a run hit
the allowance's daily cap it was resumed from the cache with another token; resumed runs are marked.

| Repo | Validated | First try | Repaired | Pairs dropped | Undetermined | Invented dropped | Tokens in / out | Notes |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| fastapi-template (Python + React/TS) | **25 / 25** | 19 | 5 | 4 | 0 | 0 | 72,743 / 32,745 | 441 functions, 109 entry points. Dropped pairs were paraphrases (`'a fresh notepad'` for "a notebook") and one duplicate |
| taxonomy (Next.js/TS) | 24 / 25 | 14 | 5 | 0 | 0 | 0 | 56,709 / 24,547 + 28,264 / 14,423 | resumed after the daily cap. Miss: Lens 1 of `CardTitle` named `onClick`, which the component does not have (read-back rejection) |
| click (Python CLI library) | 24 / 25 | 20 | 4 | 1 | 0 | 0 | 72,775 / 32,711 | 1,238 functions. Miss: a paraphrased pair phrase that survived REPAIR with too few pairs left to drop |
| flask (Python web framework) | **25 / 25** | 16 | 7 | 4 | 0 | 0 | 78,680 / 32,756 | 1,432 functions. Most REPAIRs of any repo |
| rich (Python terminal library) | **25 / 25** | 20 | 4 | 1 | 0 | 0 | 114,668 / 34,940 | 1,816 functions; the longest functions in the set |
| requests (Python HTTP library) | **5 / 5** | 4 | 0 | 0 | 0 | 0 | 13,118 / 4,557 | only 5 functions selected: the library has no app entry points, so the selection is its test-free public surface |
| httpie (Python CLI) | 24 / 25 | 20 | 4 | 1 | 0 | 0 | 67,821 / 34,857 | 1,073 functions. Miss: the model left two scanner findings unexplained in `build_packages`, twice |

**Totals across the 7 repos: 152 / 155 explanations validated (98.1%); 113 / 155 on the first try (72.9%); 29
saved by REPAIR; 11 pairs dropped; 0 UNDETERMINED; 0 invented findings reached a reader (hard gate passed on every
run).** On Lantern's own fixtures the same version did 37 / 37 and 30 first try (81.1%).

### Pass 2 (2026-11-01, same prompt, same settings, fresh cache)

| Repo | Validated | First try | Repaired | Pairs dropped | Undetermined | Invented dropped | Tokens in / out | Notes |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| fastapi-template | **25 / 25** | 18 | 5 | 2 | 0 | 0 | 75,494 / 33,989 | |
| taxonomy | **25 / 25** | 15 | 3 | 2 | 0 | 0 | 85,797 / 37,310 | pass 1's `CardTitle` read-back miss did not recur |
| click | 24 / 25 | 20 | 3 | 0 | 0 | 0 | 75,938 / 34,078 | resumed after the daily cap (12 from cache). Miss: two scanner findings left unexplained in `Editor.edit_file`, twice |
| flask | **25 / 25** | 19 | 4 | 2 | 0 | 0 | 75,114 / 32,307 | |
| rich | **25 / 25** | 20 | 4 | 2 | 0 | 0 | 96,652 / 32,292 | |
| requests | **5 / 5** | 3 | 1 | 1 | 0 | 0 | 15,970 / 6,131 | |
| httpie | 24 / 25 | 18 | 5 | 2 | 0 | 0 | 71,633 / 36,683 | resumed after the cap. Miss: two findings left unexplained in `docs.contributors.fetch.fetch`, twice (that answer also carried a rejected one-word UNDETERMINED, "none": the validator refused it as it should) |

**Pass 2 totals: 153 / 155 validated (98.7%); 113 / 155 first try (72.9%); 25 REPAIRs; 11 pairs dropped; 0
UNDETERMINED accepted; 0 invented findings shown.**

**Run-to-run swing, measured.** Pass 1 → pass 2 per repo, first try: fastapi-template 19 → 18, taxonomy 14 → 15,
click 20 → 20, flask 16 → 19, rich 20 → 20, requests 4 → 3, httpie 20 → 18. Largest per-repo swing: 3 (flask). The
totals landed on the same number both times (113 of 155 first try); end rate 98.1% → 98.7%. Both passes' misses
are the same kind: the model leaves two of the scanner's findings unexplained and does so again on the full retry.
That is not a pair problem, so REPAIR does not fire; a targeted "explain only these findings" repair is the obvious
next fix.

**Claim ceiling: BENCH_7_TWO_RUNS.** Two independent full passes, one model, one metaphor, 25 functions per repo
(5 for requests). What may be claimed: "on seven public repositories, in two separate runs, 98% of explanations
passed every anchor check and 73% passed on the first try, with Claude Haiku 5.5; 0 model-invented findings were
shown; the per-repository first-try swing between runs was at most 3 of 25." The 90% first-try target is not met.

(Pass 1 ceiling, superseded.) **Claim ceiling: BENCH_7_SINGLE_RUN.** One run per repo, 25 functions each (5 for requests), one model, one
metaphor. Run-to-run variance was ±3 on the fixtures and is not yet measured on the benchmark; a second full pass is
the next step before any number goes in the README. What may be claimed now: "on seven public repositories, 98% of
explanations passed every anchor check and 73% passed on the first try, with Claude Haiku 5.5; 0 model-invented
findings were shown." The 90% first-try target is not met.

The three misses are three different kinds: one true read-back catch (the model described a prop the component does
not have), one paraphrase with too few pairs to drop, one refusal to explain findings it was handed twice. None is a
false pass.
