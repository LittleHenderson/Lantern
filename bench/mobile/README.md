# Mobile findings benchmark: are Lantern's phone-app findings real?

Test checklist 8.2 and 10.4. The planted samples (`tests/fixtures/androidapp`, `iosapp`, `flutterapp`, `rnapp`)
prove that a known problem is found. This folder measures the other direction on real public apps: of the findings
Lantern raises, how many does an engineer agree with (**precision**), rule by rule.

```bash
python bench/mobile/run_mobile.py /tmp/mob --queue /tmp/mob/queue.json --results bench/mobile/results.md
python bench/mobile/run_mobile.py /tmp/mob --only hersheild
```

## Files

| File | What it is |
|---|---|
| `apps.json` | The apps: name, repository, git ref (`null` = default branch), platform (`android`, `ios`, `flutter`, `react-native`), or a local `path` |
| `labels.json` | One row per finding id and app: `label` (**real**, **false alarm** or **cannot tell**), a `reason` in one or two sentences, `by`, `date` |
| `run_mobile.py` | Clones each app shallowly, runs `lantern analyze --offline`, joins the findings with the labels, prints precision per rule and per platform, writes the unlabelled findings to `--queue` |
| `results.md` | The last run's tables (committed, so a change can be compared against it) |

## How to label

1. Run the script with `--queue`. The queue is every finding nobody has labelled yet: app, finding id, rule, file,
   line, headline and the flagged line.
2. Open the file at the line and decide, the way the tester round's task 4 asks an engineer to
   (`docs/tester-round.md`):
   * **real**: a user of the app, or someone with the phone, could be hurt by exactly this; the fix Lantern suggests is
     the right one.
   * **false alarm**: the pattern matched but there is no problem here, and say why (a framework convention, a URL
     that is only text, a test file). This is the row that improves Lantern: every false alarm with a reason becomes
     a rule change or a `tool_confidence: LOW` ("heuristic") label.
   * **cannot tell**: the answer depends on something outside the code (a console setting, a server). Say what.
3. Add the row to `labels.json` under the app's name, keyed by the finding id. Ids come from the flagged line's text,
   not its number, so a label survives the file growing; when an app moves on and a line changes, the script lists the
   label under "stale" in the queue file and it should be re-checked or removed.
4. Run the script again. A rule with at least five labels and a precision under 80% fails the run: fix the rule, or
   mark it heuristic, before the next release.

Labels written by Lantern's own developers are a first pass and say so in `by`; a tester round's engineer labels
(`docs/tester-round.md`, task 4) replace them. Never label from the headline alone: open the file.

## What this does not measure

Misses (**recall**): a real problem Lantern did not raise. There is no public set of phone apps with known, labelled
problems to measure that against; the planted samples are the stand-in, and every miss a tester reports becomes a
planted case in the fixtures (`tests/test_android.py`, `test_ios.py`, `test_flutter.py`, `test_rn.py`).
