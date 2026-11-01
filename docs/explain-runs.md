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

Remaining failure classes after the last run: a finding invented where none was listed (2; now forbidden in the
prompt), one `lens3` sent as a malformed JSON string (1). Next: rerun 3 times with the final prompt and record the
median; then the JS-heavy `nextapp` fixture and the bench repos.
