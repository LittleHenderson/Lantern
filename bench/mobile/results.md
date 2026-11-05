# Mobile findings benchmark

Last run 2026-11-05: 10 real, 1 false alarms, 0 undecided, 216 not labelled yet; precision 91% over the labelled findings.
How to label: `bench/mobile/README.md`.

| App | Platform | Commit | Findings | Labelled | Real | False alarm | Cannot tell | Status |
|---|---|---|---:|---:|---:|---:|---:|---|
| hersheild | android | b735956 | 13 | 13 | 10 | 2 | 1 | ok |
| nowinandroid | android | 2982e63 | 3 | 3 | 3 | 0 | 0 | ok |
| simple-calendar | android | 599985c | 11 | 11 | 4 | 7 | 0 | ok |
| antennapod | android | 0810798 | 49 | 0 | 0 | 0 | 0 | ok |
| simplenote-ios | ios | 117113b | 28 | 0 | 0 | 0 | 0 | ok |
| ios-realworld | flutter | 9df2cac | 90 | 0 | 0 | 0 | 0 | ok |
| rn-realworld | react-native | fca832c | 49 | 0 | 0 | 0 | 0 | ok |

| Rule | Real | False alarm | Cannot tell | Labelled heuristic | Not labelled yet | Precision |
|---|---:|---:|---:|---:|---:|---:|
| `B112` | 0 | 0 | 0 | 0 | 1 | – |
| `B113` | 0 | 0 | 0 | 0 | 1 | – |
| `B318` | 0 | 0 | 0 | 0 | 3 | – |
| `B404` | 0 | 0 | 0 | 0 | 1 | – |
| `B408` | 0 | 0 | 0 | 0 | 1 | – |
| `B603` | 0 | 0 | 0 | 0 | 2 | – |
| `B607` | 0 | 0 | 0 | 0 | 2 | – |
| `LB-CLEARTEXT-URL` | 0 | 0 | 0 | 0 | 1 | – |
| `LB-EXEC` | 0 | 0 | 0 | 0 | 22 | – |
| `LF-CLEARTEXT-URL` | 0 | 0 | 0 | 0 | 1 | – |
| `LI-CLEARTEXT-URL` | 0 | 0 | 0 | 0 | 2 | – |
| `LI-LOG-SENSITIVE` | 0 | 0 | 0 | 0 | 3 | – |
| `LI-OLD-TARGET` | 0 | 0 | 0 | 0 | 22 | – |
| `LI-UNUSED-PERMISSION` | 0 | 0 | 0 | 0 | 1 | – |
| `LJ-EXEC` | 0 | 0 | 0 | 0 | 29 | – |
| `LJ-XSS-HTML` | 0 | 0 | 0 | 0 | 1 | – |
| `LM-BACKUP` | 4 | 0 | 0 | 0 | 23 | 100% |
| `LM-CLEARTEXT` | 0 | 0 | 0 | 0 | 4 | – |
| `LM-CLEARTEXT-URL` | 0 | 1 | 0 | 0 | 7 | 0% |
| `LM-EXPORTED` | 2 | 0 | 0 | 9 | 22 | 100% |
| `LM-EXTERNAL-STORAGE` | 1 | 0 | 0 | 0 | 0 | 100% |
| `LM-GOOGLE-KEY` | 0 | 0 | 0 | 1 | 0 | – |
| `LM-LOG-SENSITIVE` | 0 | 0 | 0 | 5 | 0 | – |
| `LM-NO-SHRINK` | 2 | 0 | 0 | 0 | 22 | 100% |
| `LM-OLD-TARGET` | 1 | 0 | 0 | 0 | 2 | 100% |
| `LM-PREFS-SECRET` | 0 | 0 | 0 | 0 | 2 | – |
| `LM-RELEASE-DEBUG-KEY` | 0 | 0 | 0 | 0 | 15 | – |
| `LM-SQL-CONCAT` | 0 | 0 | 0 | 0 | 7 | – |
| `LM-UNUSED-PERMISSION` | 0 | 0 | 0 | 1 | 6 | – |
| `LM-USER-CERTS` | 0 | 0 | 0 | 0 | 2 | – |
| `LN-BACKUP` | 0 | 0 | 0 | 0 | 1 | – |
| `LN-URL-SCHEME` | 0 | 0 | 0 | 0 | 1 | – |
| `LV-SQL-CONCAT` | 0 | 0 | 0 | 0 | 5 | – |
| `LV-WEAK-HASH` | 0 | 0 | 0 | 0 | 4 | – |
| **all** | 10 | 1 | 0 | 16 | 216 | 91% |

| Platform | Real | False alarm | Cannot tell | Labelled heuristic | Not labelled yet | Precision |
|---|---:|---:|---:|---:|---:|---:|
| android | 10 | 1 | 0 | 16 | 49 | 91% |
| flutter | 0 | 0 | 0 | 0 | 90 | – |
| ios | 0 | 0 | 0 | 0 | 28 | – |
| react-native | 0 | 0 | 0 | 0 | 49 | – |

Precision = real / (real + false alarm) over the findings an engineer labelled. A finding the report already marks "heuristic" (the check is known to be a guess) is counted in its own column, not against the rule.
