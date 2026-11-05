# Mutation testing: do the tests catch deliberate mistakes?

First run, 2026-11-05, `tools/mutation.py` with `--max 30 --seed 1`, each module against **its own test file only**
(the whole suite exercises these modules from many more places, so the real coverage is higher; running the whole suite
per mutant takes about three minutes each, so the per-module file is the honest quick number).

| Module | Tests | Killed | Score |
|---|---|---:|---:|
| `lantern/lanes.py` | `tests/test_lanes.py` | 19 / 30 | 63% |
| `lantern/bridge.py` | `tests/test_fullstack.py` | 19 / 30 | 63% |
| `lantern/scenarios.py` | `tests/test_scenarios.py` | 13 / 30 | 43% |

What the survivors say, reading them:

* **Numbers in data tables are not logic.** Most of the `scenarios.py` survivors are CWE numbers in the rule table
  (`95 -> 96`, `502 -> 503`): a mistake there changes a reference link, which no test checks. The tool mutates every
  integer; a next version should skip constants inside dict and list literals, or the scores undercount.
* **Scoring weights and caps are untested.** `bridge.py` lines 98–122 (`0 -> 1`, `1 -> 2`, `25 -> 26`, `Lt -> LtE`) are
  the match-ranking weights and the cap on candidate routes; the fixtures never have two routes close enough for the
  weights to decide. A test with two near-identical routes (`/api/items/{id}` and `/api/items/{id}/x`) would kill them.
* **Lane rules with `or` chains.** `lanes.py` lines 76, 91, 92 decide a lane from several path words; the tests use one
  word at a time, so swapping `and`/`or` passes. One test per branch of `lane_of` (a file that matches two words) closes
  this.

These are the next tests to write for these modules; the point of the measurement is that list. Re-run after writing
them and replace this file.

## Raw results

**`lantern/lanes.py`** against `tests/test_lanes.py`: 19 of 30 mutants killed (63%; 38 possible)

| Line | Change | Result |
|---:|---|---|
| 76 | `Eq -> NotEq` | **survived** |
| 76 | `And -> Or` | **survived** |
| 76 | `Or -> And` | **survived** |
| 86 | `1 -> 2` | **survived** |
| 91 | `Or -> And` | **survived** |
| 92 | `Or -> And` | **survived** |
| 92 | `And -> Or` | **survived** |
| 92 | `Eq -> NotEq` | **survived** |
| 99 | `And -> Or` | **survived** |
| 111 | `And -> Or` | **survived** |
| 132 | `And -> Or` | **survived** |

**`lantern/bridge.py`** against `tests/test_fullstack.py`: 19 of 30 mutants killed (63%; 79 possible)

| Line | Change | Result |
|---:|---|---|
| 53 | `1 -> 2` | **survived** |
| 70 | `And -> Or` | **survived** |
| 81 | `1 -> 2` | **survived** |
| 98 | `0 -> 1` | **survived** |
| 99 | `0 -> 1` | **survived** |
| 107 | `1 -> 2` | **survived** |
| 116 | `25 -> 26` | **survived** |
| 116 | `Lt -> LtE` | **survived** |
| 119 | `1 -> 2` | **survived** |
| 121 | `1 -> 2` | **survived** |
| 122 | `1 -> 2` | **survived** |

**`lantern/scenarios.py`** against `tests/test_scenarios.py`: 13 of 30 mutants killed (43%; 153 possible)

| Line | Change | Result |
|---:|---|---|
| 326 | `95 -> 96` | **survived** |
| 326 | `502 -> 503` | **survived** |
| 327 | `327 -> 328` | **survived** |
| 328 | `346 -> 347` | **survived** |
| 368 | `And -> Or` | **survived** |
| 392 | `Or -> And` | **survived** |
| 401 | `Eq -> NotEq` | **survived** |
| 415 | `Or -> And` | **survived** |
| 425 | `Or -> And` | **survived** |
| 453 | `Or -> And` | **survived** |
| 453 | `Or -> And` | **survived** |
| 454 | `And -> Or` | **survived** |
| 477 | `And -> Or` | **survived** |
| 481 | `And -> Or` | **survived** |
| 513 | `1 -> 2` | **survived** |
| 598 | `Or -> And` | **survived** |
| 615 | `1 -> 2` | **survived** |

