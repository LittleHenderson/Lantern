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

**Next.js sample: 12 of 12 validated in both runs, 10 and 11 on the first try (83%, 92%).**

**Stable number with the final prompt (three runs, shop): 21–22 of 25 validated, 15–18 on the first try (60–72%).**

The model keeps inventing a security finding when it sees an obvious problem the scanners did not report (4 times in
25 functions, even when told not to). Those entries are now removed before anything reaches a reader and counted in
`stats["invented_findings"]`; the explanation itself still has to pass every anchor check. Remaining misses: a nested
object sent as a JSON string with a stray trailing brace (now parsed leniently at the gateway), and a paraphrased
pair phrase now and then. Next: the JS-heavy `nextapp` fixture, then the bench repos; the first-try target is 90%.
