# What a side-by-side with another review tool changed (2026-11-19)

Another review tool and Lantern 0.11.0 were run on the same project, a trading service in Python, and their reports
were read side by side. Lantern's report read **Blocked, 59**, with 10 findings ranked critical. The other tool
named 11 problems Lantern had not named. This note lists what was changed because of that, and what it measured.

Nothing here was copied from that project: every rule was written from examples of Lantern's own, each beside safe
twins, and the project is named only as "the project".

## What was changed

| What the comparison showed | What Lantern does now | Where |
|---|---|---|
| The 10 critical findings were gitleaks' `generic-api-key` on file fingerprints (the SHA-256 of a file, under a name ending in `_sha256` or under the file's own name) and on one fixed label in capitals. None is a key | A flagged text that is a whole hexadecimal digest under a name that says digest or a file name, or a label in capitals under a name that says label, is ranked low with the reason written on it. It is still listed. A name with a password's word is never passed | `lantern/secretshape.py`, `security._no_key` |
| The project sent its model calls with `urllib.request` to addresses kept in a table, and Lantern's record said no model calls were found | A plain web request in a file whose code names a model provider's API address is listed as a model call (`how: "http"`). Files that name an address and make no request are counted. The paid-call rules do not read these calls yet | `aiapp.http_model_calls` |
| A bearer token was taken from a file whose place came from the environment, with no check of who owns the file | `LW-SECRET-FILE-UNCHECKED`: a whole file is read and kept as a secret, its place comes from outside, and nothing in the function asks who owns it or whether it is a link | `lantern/custody.py` |
| A spending limit was read from the environment as a `Decimal` (which takes `Infinity`), and a call limit fell back to a default when its value was wrong | `LW-LIMIT-FAILS-OPEN`: a limit read from the environment that turns a wrong value into the default, or that is read as a `Decimal` or `float` with no check that it is finite | `lantern/failopen.py` |
| A bank withdrawal was sent before the row that records it was written | `LW-EFFECT-BEFORE-RECORD`: a call that moves money or places an order comes before the first write, with no idempotency key | `lantern/effectfirst.py` |
| Many low findings of one kind read as a long list, and the findings in test code were only counted | Low findings of one rule and one title are folded into one row that opens to show each; the open findings in test code are listed in a fold of their own (at most 500) | `evidence._grouped` |
| The scorecard's words read as if a high score meant the code had been run | The scorecard says most points come from files and patterns, the Understanding section is labelled, and the scanner criterion says "left out nothing it reads" | `lantern/evidence.py`, `lantern/release.py` |

All three new rules are heuristics (`tool_confidence: LOW`, ranked medium) and say "check".

## Measured

31 folders: the 7 projects of `bench/run_bench.py`, 5 public web starters, the 15 sample apps, Lantern's gateway,
website and engine, and the project itself. Each was checked with the code before the change (main, 91b2a88) and
after it, offline, with no kept work (`LANTERN_CACHE=off`), with gitleaks 8.30.1 on PATH. What the runs had to show
was written down before the first run.

| | Before | After |
|---|---|---|
| Findings in all 31 folders | 16,362 | 16,366 |
| Findings gone | | 0 |
| Findings new | | 4 |
| Findings ranked otherwise | | 15 |
| The project: release decision | Blocked, 59 | Incomplete, 87 |
| The project: critical findings outside test code | 10 | 0 |
| The project: model calls found | 0 | 2 (plain web requests) |

- The 15 rank changes are all on the project: the 10 critical findings outside test code and 5 in test code went
  from critical to low, each as a digest (14) or a label (1). Read by hand: right in all 15.
- The 4 new findings are all on the project, and each is one of the problems the other tool named. Read by hand:
  all 4 real.
  - `LW-LIMIT-FAILS-OPEN` twice: a call limit that falls back to 5000 when its value is not a number, and a
    spending limit read as a `Decimal` with no check that it is finite.
  - `LW-SECRET-FILE-UNCHECKED`: the bearer token read from a file whose place the server was handed when it was
    made, with no look at who owns the file.
  - `LW-EFFECT-BEFORE-RECORD`: a bank withdrawal sent, and the row that records it written after it.
- The first run had one new finding of the three rules only, and two rules found nothing on the project. Each
  reason was read and fixed after a test that failed first (`tests/test_three_orders.py`):
  - On a public HTTP client, a size above which a warning is shown, read as a `float` and named `…_THRESHOLD`, was
    named as a limit. It limits nothing: "threshold" is no longer a word of a limit.
  - The token's place was kept on the object by its constructor (`self._token_file`), and the rule read only the
    function's own parameters and the environment. A field that a method of the class sets from outside counts now.
  - The withdrawal's function hands a request's id to the check of a one-time code before it sends the money, and
    the rule took any such id anywhere in the function for an idempotency key. Only a key handed to the send itself,
    or a function named for it (`dedup(...)`), counts now.
- After those three fixes the three rules were run again over every Python file of the same 31 folders that is not
  test code (the rest of the check is the code measured above): the 4 findings above and no other.
- Plain web requests to a model provider: 2 in the project, 9 in Lantern's own `providers.py` and 2 in its gateway
  (both real: that is how they talk to the providers). 6 files of Lantern and 1 test file of the project name a
  provider's address and make no request.

## Not done

- Two points of the comparison are not changed by this: a report that names who wrote it and how that can be
  checked by someone else, and a check made through the commit itself. They need a design of their own.
- Of the 11 problems the other tool named, the new rules find 4 on the project. The others are of kinds no rule of
  Lantern reads yet.
