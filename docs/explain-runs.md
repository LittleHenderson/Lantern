# Real-model explanation runs

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

The seven `bench/` repositories, `lantern explain --max-nodes 25`, lens-v5 with REPAIR and pair-drop, Claude Haiku 5.5
through the gateway, one run each. The free allowance's 120-a-day cap stopped the second repo part-way.

| Date | Repo | Validated | First try | Repaired | Pairs dropped | Undetermined | Invented dropped | Tokens in / out | Notes |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| 2026-11-01 | fastapi-template (Python + React/TS) | **25 / 25** | 19 | 5 | 4 | 0 | 0 | 72,743 / 32,745 | 441 functions, 109 entry points. The 4 dropped pairs were all paraphrased phrases (`'a fresh notepad'` for a text that said "a notebook"), one a duplicate |
| 2026-11-01 | taxonomy (Next.js/TS) | 17 / 17 (**partial**) | 11 | 4 | 0 | 0 | 0 | 56,709 / 24,547 | 229 functions. Daily allowance cap hit after 17 of 25; stopped cleanly. 8 NOT RUN |
| – | click, flask, rich, requests, httpie | NOT RUN | – | – | – | – | – | – | waiting on allowance |

**Claim ceiling: BENCH_PARTIAL** (2 of 7 repos, one of them cut short). Across the 42 benchmark functions run so far:
42 / 42 validated, 30 first try (71%). On the fixtures the same version did 37 / 37, 30 first try (81%). The
first-try rate on other people's code is lower, as expected; the end rate after REPAIR and pair-drop held at 100%
in both. The 90% first-try target is not met anywhere yet.
