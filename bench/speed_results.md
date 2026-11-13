# Speed: before and after (directive point 10)

Measured 2026-11-12 with `bench/speed.py`, the unchanged engine first and this one straight after it, on one machine
kept quiet for it (4 processors, Linux, Python 3.13.18; the same clones for both, each at a fixed commit).
"Before" is `main` at 8f517f2 (the commit this work started from); "after" is this branch.

How to run it again:

```bash
python bench/speed.py WORK --engine PATH/TO/A/CHECKOUT/OF/8f517f2 --runs 3 --browser --json before.json
python bench/speed.py WORK --runs 3 --browser --compare before.json --must-match --json after.json
```

The second command ends with 1 when a result file both engines write, or what the two reports hold, differs for any
project. It ended with 0.

The numbers behind every table are in `bench/speed_results.json`: the two files those commands wrote (`before`,
`after`; the measuring machine's folder names replaced by `main` and `this branch`), every opening on the phone
(the commands open each report once; each report was opened twice more with `node tools/report_perf.js`), and the
three runs of "After one file was edited".

What the words mean:

* **first run**: nothing of an earlier run is there (no results folder, no kept work); the system's own file cache
  is warm, since the same files were read minutes before. **repeat run**: the same command again on the same folder.
* **the same**: every result file compared, with only what a clock put into it taken out (how long a step or a tool
  took, the minute the run was made). A run writes ten files; `graph.json` and `calls.json` are compared byte for
  byte, and so was `baseline.json` in this measurement (since then without the day it begins with: see "After the
  measurement"). Across the two engines the comparison is of `graph.json`, `calls.json`, `security.json`,
  `readiness.json`, `baseline.json`, the badge, and everything the report holds (read back out of `report.html`,
  with the map as rows again); the page around the data differs by design, and the evidence names the engine that
  made it.
* **the analysis itself / with every program it started**: the first is the highest memory of the analysis process
  as the system reports it at the end. The second adds the programs it starts (Bandit, git) and is read ten times
  a second while the run goes on, so a short peak can be missed and it can read lower than the first. It is the one
  to look at for "how much memory does a run need at once", because Bandit now runs beside the reading of the code.
* **start-up, map, scan, readiness, report, evidence**: the steps of a run as its own log times them. With this
  engine the scanners work while the map is built, so the scan step no longer holds their whole time.

## The numbers

### Time of a run (seconds; the middle one of three runs, lowest to highest in brackets)

| project | size | files | lines | first run before | first run after | repeat run before | repeat run after |
|---|---|---:|---:|---:|---:|---:|---:|
| shop | small | 12 | 181 | 0.63 (0.62 to 0.66) | 0.74 (0.72 to 0.83) | 0.63 (0.62 to 0.65) | 0.50 (0.46 to 0.52) |
| ripgrep | small | 99 | 50397 | 2.81 (2.72 to 2.83) | 1.88 (1.74 to 1.92) | 2.66 (2.66 to 2.78) | 1.91 (1.78 to 2.10) |
| excalidraw | medium | 378 | 86777 | 10.39 (10.33 to 10.40) | 8.88 (8.75 to 9.48) | 10.32 (10.05 to 10.51) | 8.88 (8.79 to 9.13) |
| hugo | medium | 864 | 194912 | 16.98 (16.95 to 18.61) | 10.15 (9.95 to 10.74) | 16.94 (16.46 to 17.07) | 10.03 (9.96 to 10.67) |
| django | large | 2839 | 481021 | 115.72 (113.60 to 116.52) | 52.05 (52.00 to 52.59) | 113.84 (107.39 to 116.25) | 41.03 (39.45 to 41.98) |
| laravel | large | 2241 | 415998 | 37.83 (37.34 to 39.34) | 19.38 (18.31 to 20.01) | 37.53 (37.38 to 37.99) | 18.50 (18.34 to 19.53) |

| project | first run: after minus before | repeat run: after minus before | processor seconds of a first run before | after |
|---|---:|---:|---:|---:|
| shop | +0.11 | −0.13 | 0.63 | 0.85 |
| ripgrep | −0.93 | −0.75 | 2.80 | 2.18 |
| excalidraw | −1.51 | −1.44 | 10.27 | 9.22 |
| hugo | −6.83 | −6.91 | 16.82 | 10.44 |
| django | −63.67 | −72.81 | 114.68 | 82.27 |
| laravel | −18.45 | −19.03 | 37.38 | 19.49 |

### Where the time of a first run went (seconds, the middle one of three)

| project | | start-up | map | scan | readiness | report | evidence |
|---|---|---:|---:|---:|---:|---:|---:|
| shop | before | 0.19 | 0.05 | 0.34 | 0.02 | 0.01 | 0.03 |
| shop | after | 0.24 | 0.19 | 0.24 | 0.02 | 0.01 | 0.04 |
| ripgrep | before | 0.19 | 0.82 | 1.42 | 0.09 | 0.14 | 0.09 |
| ripgrep | after | 0.24 | 0.99 | 0.26 | 0.07 | 0.13 | 0.12 |
| excalidraw | before | 0.18 | 3.11 | 5.19 | 1.32 | 0.13 | 0.35 |
| excalidraw | after | 0.25 | 3.49 | 3.78 | 0.65 | 0.11 | 0.48 |
| hugo | before | 0.21 | 6.87 | 7.46 | 1.15 | 0.53 | 0.59 |
| hugo | after | 0.27 | 6.00 | 1.80 | 0.76 | 0.46 | 0.61 |
| django | before | 0.27 | 32.14 | 70.20 | 6.38 | 4.41 | 1.07 |
| django | after | 0.29 | 21.14 | 20.23 | 6.30 | 3.21 | 0.91 |
| laravel | before | 0.33 | 16.74 | 12.76 | 5.55 | 1.81 | 0.96 |
| laravel | after | 0.38 | 9.15 | 3.80 | 3.03 | 1.61 | 1.10 |

### Where the time of a repeat run went (seconds, the middle one of three)

| project | | start-up | map | scan | readiness | report | evidence |
|---|---|---:|---:|---:|---:|---:|---:|
| shop | before | 0.18 | 0.05 | 0.35 | 0.02 | 0.01 | 0.03 |
| shop | after | 0.22 | 0.16 | 0.03 | 0.02 | 0.01 | 0.04 |
| ripgrep | before | 0.19 | 0.78 | 1.37 | 0.09 | 0.15 | 0.07 |
| ripgrep | after | 0.24 | 0.99 | 0.27 | 0.09 | 0.15 | 0.10 |
| excalidraw | before | 0.20 | 3.05 | 5.31 | 1.27 | 0.12 | 0.26 |
| excalidraw | after | 0.24 | 3.58 | 3.74 | 0.76 | 0.13 | 0.35 |
| hugo | before | 0.23 | 6.81 | 7.33 | 1.14 | 0.51 | 0.33 |
| hugo | after | 0.25 | 6.09 | 1.85 | 0.80 | 0.47 | 0.36 |
| django | before | 0.30 | 33.13 | 68.64 | 6.46 | 4.37 | 0.66 |
| django | after | 0.31 | 11.18 | 19.27 | 6.25 | 3.21 | 0.66 |
| laravel | before | 0.33 | 16.58 | 12.24 | 5.52 | 1.96 | 0.81 |
| laravel | after | 0.40 | 8.63 | 3.77 | 3.12 | 1.71 | 0.85 |

### Memory (MB at the highest point of a first run)

| project | the analysis itself before | after | with every program it started, before | after | repeat run, the analysis itself, before | after |
|---|---:|---:|---:|---:|---:|---:|
| shop | 39 | 45 | 47 | 55 | 39 | 45 |
| ripgrep | 126 | 122 | 114 | 116 | 126 | 127 |
| excalidraw | 125 | 130 | 116 | 122 | 126 | 130 |
| hugo | 401 | 377 | 353 | 357 | 402 | 376 |
| django | 885 | 740 | 858 | 694 | 881 | 755 |
| laravel | 999 | 690 | 990 | 639 | 999 | 689 |

### Size of what a run writes

| project | report.html before, bytes | after, bytes | report MB before | after | all result files MB before | after |
|---|---:|---:|---:|---:|---:|---:|
| shop | 356,447 | 340,936 | 0.34 | 0.33 | 0.53 | 0.52 |
| ripgrep | 4,477,102 | 2,445,769 | 4.27 | 2.33 | 7.78 | 5.84 |
| excalidraw | 3,955,971 | 2,533,709 | 3.77 | 2.42 | 15.19 | 13.83 |
| hugo | 15,126,042 | 7,669,778 | 14.43 | 7.31 | 27.28 | 20.16 |
| django | 73,896,338 | 38,050,642 | 70.47 | 36.29 | 211.22 | 177.04 |
| laravel | 43,554,190 | 22,894,752 | 41.54 | 21.83 | 77.52 | 57.82 |

### The report on a slowed phone (milliseconds; `tools/report_perf.js`, the middle one of three openings)

| project | | opens | findings tab | one finding | back to the map | memory MB | the three openings |
|---|---|---:|---:|---:|---:|---:|---|
| shop | before | 345 | 314 | 231 | 248 | 10 | 348, 345, 305 |
| shop | after | 372 | 349 | 256 | 248 | 10 | 356, 372, 404 |
| ripgrep | before | 766 | 306 | 237 | 314 | 14 | 699, 766, 803 |
| ripgrep | after | 701 | 312 | 252 | 358 | 11 | 655, 701, 840 |
| excalidraw | before | 708 | 323 | 252 | 286 | 11 | 724, 669, 708 |
| excalidraw | after | 679 | 380 | 254 | 299 | 10 | 737, 679, 634 |
| hugo | before | 1862 | 304 | 247 | 344 | 36 | 1881, 1862, 1762 |
| hugo | after | 1435 | 339 | 242 | 390 | 26 | 1435, 1477, 1344 |
| django | before | 4951 | 1841 | 516 | 809 | 159 | 4951, 4994, 4949 |
| django | after | 3548 | 1819 | 493 | 678 | 78 | 3757, 3362, 3548 |
| laravel | before | 3307 | 787 | 262 | 514 | 51 | 3307, 3187, 3362 |
| laravel | after | 2355 | 702 | 267 | 527 | 43 | 2612, 2274, 2355 |

Errors a page reported in any of these openings: none

### The same results

| project | the three first runs and the three repeat runs among themselves | a repeat run with kept work switched off | a first run that finds kept work | this engine beside the unchanged one |
|---|---|---|---|---|
| shop | the same | the same | the same | the same |
| ripgrep | the same | the same | the same | the same |
| excalidraw | the same | the same | the same | the same |
| hugo | the same | the same | the same | the same |
| django | the same | the same | the same | the same |
| laravel | the same | the same | the same | the same |

The unchanged engine among its own runs: shop the same; ripgrep the same; excalidraw the same; hugo the same; django the same; laravel the same

| project | commit read | functions | links | findings | repeat run with kept work off, s | first run on kept work, s |
|---|---|---:|---:|---:|---:|---:|
| shop | in this repository | 56 | 73 | 9 | 0.55 | 0.64 |
| ripgrep | 4649aa9700619f94cf | 3685 | 7657 | 4 | 1.59 | 1.90 |
| excalidraw | 0dbd2a39319d41fda3 | 2219 | 6178 | 13 | 8.74 | 8.97 |
| hugo | dacef0df92a9a20072 | 10132 | 27948 | 8 | 10.14 | 9.71 |
| django | 69bf08e3a324929988 | 43457 | 130080 | 1268 | 47.88 | 40.66 |
| laravel | dff716442d9c229d71 | 29708 | 69834 | 126 | 18.65 | 18.45 |

### After one file was edited (Django, this engine, one run each)

| run | seconds | MB | from kept work |
|---|---:|---:|---|
| first | 53.58 | 740 | bandit: 0 reused, 1 anew; python-file: 0 reused, 2788 anew |
| again nothing changed | 39.52 | 753 | bandit: 1 reused, 0 anew; python-file: 2788 reused, 0 anew |
| after one file edited | 45.40 | 757 | bandit: 0 reused, 1 anew; python-file: 2787 reused, 1 anew |

Machine: 4 processors, Linux-6.18.44-fc-v378-x86_64-with-glibc2.39, Python 3.13.18. The unchanged engine finished 2026-11-12 23:25 UTC, this one 2026-11-12 23:39 UTC; 3 first runs and 3 repeat runs a side.

## What the numbers do and do not say

* **No result moved.** For each of the six projects the three first runs and the three repeat runs wrote the same
  result files; a repeat run with kept work switched off wrote the same; a first run that found kept work wrote the
  same; and this engine wrote the same as the unchanged one, in every file both write and in everything the report
  holds (the table "The same results").
* **First run: faster on five of six, slower on the smallest.** Django 115.72 → 52.05 s, Laravel 37.83 → 19.38 s,
  Hugo 16.98 → 10.15 s, Excalidraw 10.39 → 8.88 s, ripgrep 2.81 → 1.88 s. The 12-file sample takes **0.74 s where
  it took 0.63 s**: a run now pays about a tenth of a second before it reads anything, for the digests kept work is
  found under (0.09 s measured apart, most of it reading Bandit's own files), and 12 files give nothing to win it
  back with.
* **Repeat run: kept work helps only where there is Python.** Django's repeat run takes 41.03 s against 52.05 s for
  its first, the sample 0.50 s against 0.74 s. For ripgrep, Excalidraw, Hugo and Laravel a repeat run takes what a
  first run takes (1.91 and 1.88 s, 8.88 and 8.88 s, 10.03 and 10.15 s, 18.50 and 19.38 s): nothing is kept for the
  Rust, TypeScript, Go and PHP readers. With the unchanged engine a repeat run took what a first run took everywhere.
* **Where Django's 63.67 s went.** 32.41 s is work no longer done (processor seconds 114.68 → 82.27: the folder
  walked once, patterns not tried on files that cannot match, tables in place of searches, memory housekeeping
  held back while the map is built). The rest is the same work done at the same time: Bandit reads the files while
  Lantern builds the map, where it used to start when the map was finished. On a computer with one processor
  nothing runs beside the map and that part of the gain is not there; no such computer was measured.
* **Memory.** The highest memory of the analysis itself is lower on the three largest (Django 885 → 740 MB, Laravel
  999 → 690 MB, Hugo 401 → 377 MB), about the same on ripgrep (126 → 122 MB) and higher on the sample (39 → 45 MB)
  and Excalidraw (125 → 130 MB). Counted with every program a run starts it is 2 to 8 MB higher on the four smaller
  projects (the scanners now work while the reader does) and lower on Django (858 → 694 MB) and Laravel
  (990 → 639 MB).
* **The report.** Smaller for all six; Django's is 38,050,642 bytes where it was 73,896,338, with the same data in
  it. It opens sooner on the slowed phone for five of six (Django 4951 → 3548 ms, Laravel 3307 → 2355 ms, Hugo
  1862 → 1435 ms, ripgrep 766 → 701 ms, Excalidraw 708 → 679 ms) and 27 ms later for the sample (345 → 372 ms).
  The page's own memory for Django is 78 MB where it was 159 MB. **The taps inside an open report were not worked
  on and are not faster**: the findings tab, one finding and the way back to the map came out between 131 ms
  faster and 57 ms slower across the six, and Django's findings tab still takes 1819 ms (1841 ms before), close to
  the 2,000 ms that `tools/report_perf.js` allows.

## After the measurement: `main` moved, and a fault in the comparison

`main` moved to 8c79479 while this was measured (#178, the Atlas breadcrumb and minimap: a change to the report's
page, nothing in the engine) and was merged into this branch. The numbers above are of the branch before that merge
(3e38b7d) against the commit it started from (8f517f2).

The merged branch was then compared with `main` at 8c79479 on the six projects, one first run and one repeat run a
side. The machine was running the whole test suite at the same time, so those seconds are not given here. Excalidraw,
Hugo, Django and Laravel: every result the same. For the shop sample and ripgrep the comparison said
`baseline.json` differs, and ended with 1.

Nothing in the two results differed but a day. `baseline.json` begins with the day the first analysis was made, the
tool compared that file byte for byte, and `main`'s side started at 23:59:33 UTC on 2026-11-12: its first analysis of
the shop sample and of ripgrep was written before midnight, everything else on both sides after it. With the day
set back to 2026-11-12, the branch's two files have exactly the SHA-256 `main`'s side had.

The fault was the measuring tool's, and it was fixed test first: the tests of `bench/speed.py` wrote an empty
`baseline.json`, so "another day" was never tried on that file. `test_two_runs_are_the_same_whatever_the_clock_said`
now writes it as Lantern does and failed (`['baseline.json']`);
`test_only_the_day_a_baseline_was_made_is_taken_out_of_it` and five more cases of
`test_anything_but_the_clock_is_a_difference` pin that the day at the start of the file is all that is taken out
(a line number, the commit, a `date` further inside, a first `date` that is not written as a day: each is still a
difference). The two projects were then compared again with the changed tool, `main` at 8c79479 against the merged
branch: every result the same, ended with 0.

The measurement above ran from 23:00 to 23:42 UTC of one day, so it could not meet this fault. The marks of
`baseline.json` in `bench/speed_results.json` are of the whole file, as the tool made them then.

## Breaking the new code on purpose

Every place in the four new modules where `tools/mutation.py` can change one thing (a comparison turned round,
`and` for `or`, a number one higher, a default switched) was changed, one at a time, in a copy of the repository,
and the tests of that module were run on the copy. A change the tests do not notice is either a hole in the tests
or a change that makes no difference; each one was read and sorted.

| module | places changed | noticed by the tests | not noticed: makes no difference | holes found in the tests on the way, all closed |
|---|---:|---:|---:|---:|
| `lantern/columns.py` | 179 | 165 | 14 | 5 |
| `lantern/kept.py` | 162 | 149 | 13 | 17 |
| `lantern/quick.py` | 34 | 32 | 2 | 2 |
| `lantern/listing.py` | 22 | 20 | 2 | 0 |
| all four | 397 | 366 | 31 | 24 |

What "makes no difference" means here, by module: `columns.py`, the sizes from which a column is written one way or
another (any choice round-trips to the same rows); `kept.py`, changes that only show on another system or with
another user (a flag that is already the default on Linux, a check that two other checks repeat), and sizes of
buffers; `quick.py`, a constant that only bounds how long a piece of text may be; `listing.py`, the counter that
says "the folder may have changed while it was walked", for which the same walk gives the same list.

The holes were real: among them, nothing pinned that `lantern cache --clear` never follows a link out of the cache
folder, that an entry exactly 30 days old stays and one a second older goes, that the note of the last tidy-up is
closed to other users, and that an answer over the size limit is neither kept nor read. Each got a test that fails
with the change and passes without it.

One defect was found by reading the new code again, not by a test: two threads that asked for the same folder
listing at the same moment could both walk the folder (`listing._Run.once` let the second one look before the
first had put its answer down). Nothing was wrong in any result, the work was done twice. A test that forces that
order was written first and failed (`made == [1, 1]`), then the answer was put down before the waiting thread is
let go.

## Measured and dropped

* One pass over a function's syntax tree for its fingerprint in place of two: 2.64 s became 2.03 s on Django's
  Python files read alone (1.56 s with a tree cursor). Under one second of a run of more than a minute for code
  that is harder to read; not taken.
* Breaking the cycle between a file's reader and the function that walks it, so its memory is freed at once: the
  one full pass of Python's memory collector after the map is built frees it anyway; no difference in peak memory.

## What is still slow, and what this does not cover

* **Work is kept for the Python reader and for Bandit, nothing else.** The readers of the other eleven
  languages, the links between files, the flow step, the pattern rules, readiness and the report are worked out in
  every run. A repeat run of Django still takes 41.03 s (map 11.18 s, scan 19.27 s, readiness 6.25 s).
* **One edited Python file and Bandit reads every file again.** Bandit's answer is kept for the whole set of files
  it was given. Django after one edited file: 45.40 s, against 39.52 s with nothing changed and 53.58 s with
  nothing kept; the reader took 2,787 of 2,788 files from kept work, Bandit none.
* **The hosted service keeps nothing**, on purpose (one service, many people's code): every run there is a first
  run, and gains only what a first run gains.
* **One machine, three runs a side.** The spread of the three is in brackets beside every time. Timings of another
  session are not comparable: the unchanged engine's first run of Django was 120.69 s when this work began and
  115.72 s here. Windows and macOS were not measured; neither was a computer with one processor.
* **Result files are written indented**, as they always were. For Django's map that costs Python 3.11 1.54 s and
  Python 3.12 1.09 s against 0.25 s on Python 3.13 (measured apart, on a busy machine). Left as it is, because the
  result files stay byte for byte what they were.
* **Found on the way, not fixed:** `readiness.Repo.grep` raises IndexError for a pattern that can match the empty
  text at the end of a file that ends in a newline. No pattern of Lantern's can.
