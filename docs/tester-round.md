# A tester round: four tasks, one sheet (test checklist 10.2, 10.3, 10.4)

How companies run "user acceptance testing": the same few tasks for every tester, a pass or fail per task, the time it
took, and one sentence in the tester's words. Five people are enough to find most problems. This file is the script
for the host and the sheet for the results. Give each tester [docs/try-lantern.md](try-lantern.md) first.

## Who

Five Android or other phone-app creators who built their app with AI help and have it in a public repository (or are
willing to upload a .zip). One of them should be a working engineer, for task 4. Nobody who has seen Lantern before.

## Before the round (host)

1. Check lantern-cloud is up: open https://lantern-cloud.fly.dev/v1/health (or wait for the next green `uptime` run).
2. Make sure the day's limits are not spent: each account gets 50 checks a day.
3. Have the sheet below ready, one row per tester per task, and a timer.
4. Watch, do not help. When a tester gets stuck for more than three minutes, note what they were trying, then help
   and mark the task **fail**.

## The four tasks

Read each task aloud, exactly as written, and start the timer. A task **passes** when the tester reaches the goal
without help in the time given.

| # | Task, in the host's words | Goal (what you look for) | Time |
|---|---|---|---|
| 1 | "Open lantern-cloud.fly.dev, sign in, and check your own app." | A finished run with a grade on screen | 5 min |
| 2 | "Find the one thing Lantern says you should fix first, and tell me in your own words what a user would have to do to trigger it." | They open the top finding, read the click path and the Scenario, and retell it without reading code | 5 min |
| 3 | "Look at the On the phone card. Is there a permission or a screen there you did not expect?" (phone apps) **or** "Find a route that has no login check." (web apps) | They find the card (or the route) and say yes or no with a reason; note what they say for 10.4 | 5 min |
| 4 | "Pick any finding and decide whether it is real. Use anything you like." (the engineer) | They open the file at the line, judge it, and say **real**, **false alarm** or **cannot tell**; note the finding id and their reason | 10 min |

After the four tasks, ask two questions and write the answers down word for word:

* "What would you tell a friend Lantern is?"
* "What was the most confusing moment?"

## The sheet

Copy this table into `docs/tester-rounds/<date>.md` (make the folder the first time), one block per tester. Replace
nothing in the header row; a results file with a different shape cannot be compared with the next round's.

```
Tester: T1 · app: <name, Android/iOS/Flutter/RN/web> · date: YYYY-MM-DD · host: <name>

| task | pass/fail | minutes | what they said (one sentence) | finding id (task 4) | real / false alarm / cannot tell |
|---|---|---|---|---|---|
| 1 |  |  |  |  |  |
| 2 |  |  |  |  |  |
| 3 |  |  |  |  |  |
| 4 |  |  |  |  |  |

Friend: "…"
Most confusing: "…"
```

## After the round (host)

1. Count passes per task across testers. A task under 4 of 5 passes is the next thing to fix in the product, before
   anything else.
2. Every "false alarm" from task 4 becomes a row in the mobile benchmark (`bench/mobile/labels.json`, see
   `bench/mobile/README.md`), with the finding id and the engineer's reason, so the next release is measured against it.
3. Every "most confusing moment" becomes a tester report
   ([the form](https://github.com/LittleHenderson/Lantern/issues/new?template=tester-report.yml)) with the tester's
   words in "What happened".
4. Write three lines at the top of the results file: passes per task, false alarms found, the one change you will make.

## Why these four

Task 1 is the whole promise (anyone can check an app). Task 2 is the main audience's need (understand a problem
without reading code). Task 3 checks the phone work against someone who knows their own app, the cheapest accuracy
check there is. Task 4 is the sceptical engineer from the checklist's 10.4: Lantern's claims are only worth what an
engineer finds when they check one.
