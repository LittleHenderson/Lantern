# The scanner's start-up, before and after (2026-11-14)

`bench/run_bench.py WORKDIR --no-trace` on the map benchmark's seven public projects, on the code before the change
of 2026-11-14 (137ec6f) and on the code after it, each without gitleaks on PATH (as CI's check of Lantern itself runs)
and with gitleaks 8.30.1 on PATH. One run each, one after the other on the same clones, Linux, Python 3.13.18, four
processor cores. Nothing of the projects was run: no tracing, no install.

What the change must not move, and did not: the map (files, functions, entry points, edges, their confidence, the
calls not followed) is the same in all four runs for every project, and so are the findings before and after, without
gitleaks and with it. None of the seven projects brings a file for gitleaks that changed what it found.

| Project | Ref | Functions | Edges | Findings without gitleaks, before = after | Findings with gitleaks, before = after | Scan seconds without gitleaks, before / after | Scan seconds with gitleaks, before / after |
|---|---|---|---|---|---|---|---|
| click | 8.1.8 | 1238 | 2374 | 1/1/0/36/777 | 1/1/0/36/777 | 2.26 / 2.04 | 2.51 / 2.49 |
| flask | main | 1441 | 1600 | 0/36/7/9/1070 | 6/36/7/9/1070 | 5.10 / 5.02 | 6.06 / 5.56 |
| rich | v13.9.4 | 1816 | 3911 | 0/26/4/68/1292 | 0/26/4/68/1292 | 11.80 / 12.47 | 16.05 / 15.30 |
| requests | v2.32.3 | 669 | 953 | 0/3/1/10/665 | 0/3/1/10/669 | 2.38 / 2.47 | 2.97 / 2.85 |
| httpie | 3.2.4 | 1074 | 1349 | 0/2/3/55/753 | 0/2/3/55/756 | 2.27 / 2.20 | 3.04 / 2.83 |
| fastapi-template | master | 441 | 846 | 0/2/1/6/173 | 0/2/1/6/173 | 4.29 / 5.31 | 4.92 / 6.76 |
| taxonomy | main | 238 | 339 | 0/0/1/0/0 | 0/0/1/0/0 | 0.88 / 0.84 | 1.09 / 0.96 |
| all seven | | | | | | 28.98 / 30.35 | 36.64 / 36.75 |

Findings are written critical / high / medium / low / in test code. The scan's seconds are one run each and include
the dependency audits, which ask over the network, so a second more or less between two columns is the run and not
the code: without gitleaks the scanners' code is the same before and after. With gitleaks the seven scans took
36.64 s before and 36.75 s after; the question Lantern now asks gitleaks before each project took about 0.05 s
when measured by itself.

Not measured here: precision and recall against a trace (the part of the benchmark that runs the projects' tests),
because the change touches no rule of the map; memory, which this benchmark does not record (gitleaks under the
address-space limit of the website's step, on a large project, is in `CHANGELOG.md`, 2026-11-14).
