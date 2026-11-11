# Large apps: time and memory (tools/large_apps.py)

First run, 2026-11-05, on a 4-core container (`python tools/large_apps.py /tmp/large`), budget 900 s and 4 GB per app, offline,
structure-only reports. The weekly GitHub Actions job (`large-apps.yml`) writes the same table to its step summary.

| app | ref | languages | files | lines | functions | edges | findings | grade | seconds | peak MB | report KB | status |
|---|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---|
| django | 5.1.3 | python + typescript/javascript | 2839 | 481021 | 43214 | 109503 | 1245 | F | 86.7 | 547 | 48104 | ok |
| excalidraw | v0.17.6 | typescript/javascript | 378 | 86777 | 2140 | 6031 | 13 | D | 4.8 | 61 | 2242 | ok |
| hugo | v0.139.0 | typescript/javascript + go | 865 | 194929 | 10107 | 28152 | 8 | D | 11.7 | 369 | 10421 | ok |
| ripgrep | 14.1.1 | rust + ruby | 99 | 50397 | 3685 | 7657 | 4 | D | 2.3 | 115 | 3113 | ok |
| spring-petclinic | main | typescript/javascript + java | 46 | 4354 | 438 | 876 | 1 | D | 1.0 | 39 | 649 | ok |
| nowinandroid | main | kotlin | 310 | 29646 | 1742 | 2639 | 31 | B | 3.6 | 83 | 2071 | ok |
| ios-sample-flutter | main | python + typescript/javascript + java + kotlin + swift + dart + c/c++ | 796 | 105895 | 6281 | 12803 | 91 | D | 12.0 | 156 | 5039 | ok |
| rails-sample | master | typescript/javascript + ruby | 51 | 1236 | 164 | 144 | 1 | F | 0.8 | 34 | 324 | ok |
| sqlite-cpp-httplib | v0.18.1 | python + c/c++ | 25 | 34193 | 2015 | 5755 | 22 | D | 2.0 | 58 | 2092 | ok |
| laravel | v11.30.0 | typescript/javascript + php | 2241 | 415998 | 29708 | 69834 | 126 | F | 32.8 | 996 | 30194 | ok |

Two problems this run found and the same change fixed:

* **Django** crashed Lantern with "maximum recursion depth exceeded": pairs of package files re-export a name from each
  other (`from .a import x` / `from .b import x`), and the Python reader followed the circle forever. The import chase now
  stops after twelve hops and leaves the call unresolved (`tests/test_robustness.py::test_import_cycles_do_not_recurse_forever`).
* **Laravel** did not finish in 15 minutes: PHP classes whose parents form a circle made the property-type lookup loop,
  and the parent lookups ran 27 million times. The loop now remembers where it has been, parent lookups are cached and
  subclasses are indexed once; the framework takes about 33 s (`test_php_parents_in_a_circle_do_not_loop_forever`).

## Before and after point 4 of the directive (2026-11-11)

The same ten apps at the same commits, analysed with the code before point 4 (eb3666e) and with the point-4 branch,
two runs a side: each run alone with nothing else running, on the same 4-core container, offline, structure-only
reports, the same budgets. The first pair is eb3666e against 1c7f819 (the first table). The second pair, later the
same afternoon, is the stage's last code (3e4687c, started 3:26 PM PST) and then eb3666e once more (started
3:29 PM PST); it is the second table. Every small app shows the same 233 or 234 MB in all four runs (34 to 156 MB
in the first run above): that is a floor of this way of measuring, most likely the measuring program's own size
after it has read Django's results, which a program it starts carries over. It was not looked into here; the time
and memory work of point 10 has to measure it apart.

| app | seconds before | after | peak MB before | after | findings before | after | report KB before | after | status |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| django | 99.0 | 103.9 | 759 | 790 | 1245 | 1268 | 53320 | 53404 | ok |
| excalidraw | 7.6 | 10.0 | 233 | 234 | 13 | 13 | 2341 | 2343 | ok |
| hugo | 15.8 | 15.9 | 371 | 376 | 8 | 8 | 10392 | 10394 | ok |
| ripgrep | 2.7 | 2.6 | 233 | 234 | 4 | 4 | 3143 | 3145 | ok |
| spring-petclinic | 1.2 | 1.2 | 233 | 234 | 1 | 1 | 676 | 678 | ok |
| nowinandroid | 5.0 | 5.0 | 233 | 234 | 3 | 3 | 2060 | 2061 | ok |
| ios-sample-flutter | 14.4 | 13.3 | 233 | 234 | 90 | 90 | 5198 | 5200 | ok |
| laravel | 35.0 | 35.5 | 997 | 1000 | 126 | 126 | 30443 | 30445 | ok |
| rails-sample | 0.9 | 0.9 | 233 | 234 | 1 | 1 | 350 | 352 | ok |
| sqlite-cpp-httplib | 2.2 | 2.0 | 233 | 234 | 22 | 22 | 2122 | 2124 | ok |
| all ten | 183.8 | 190.3 | | | 1513 | 1536 | 110045 | 110146 | |

Nothing was left out to get there: the same files are read and every check of the "before" still runs; the engine
that follows request data (`lantern/flow.py`) is added on top for Python and JavaScript/TypeScript. In this first
pair Django, the largest Python app, takes 4.9 s longer (99.0 to 103.9) and 31 MB more; the ten together 6.5 s
longer (183.8 to 190.3).

The second pair (eb3666e once more, and 3e4687c, which also reads a Python app's imports written from the top as the
project's own):

| app | seconds before | after | peak MB before | after | findings before | after | report KB before | after | status |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| django | 91.3 | 107.5 | 759 | 786 | 1245 | 1268 | 53320 | 53404 | ok |
| excalidraw | 7.5 | 10.9 | 233 | 233 | 13 | 13 | 2341 | 2343 | ok |
| hugo | 14.3 | 17.3 | 370 | 377 | 8 | 8 | 10392 | 10394 | ok |
| ripgrep | 2.7 | 2.8 | 233 | 233 | 4 | 4 | 3143 | 3145 | ok |
| spring-petclinic | 1.1 | 1.3 | 233 | 233 | 1 | 1 | 676 | 678 | ok |
| nowinandroid | 4.8 | 5.5 | 233 | 233 | 3 | 3 | 2060 | 2061 | ok |
| ios-sample-flutter | 13.5 | 13.7 | 233 | 233 | 90 | 90 | 5198 | 5200 | ok |
| laravel | 35.3 | 37.0 | 998 | 999 | 126 | 126 | 30443 | 30445 | ok |
| rails-sample | 1.0 | 1.0 | 233 | 233 | 1 | 1 | 350 | 352 | ok |
| sqlite-cpp-httplib | 1.9 | 1.9 | 233 | 233 | 22 | 22 | 2122 | 2124 | ok |
| all ten | 173.4 | 198.9 | | | 1513 | 1536 | 110045 | 110146 | |

**What point 4 costs in time is known only as a range.** The same code run twice (eb3666e) took 183.8 s and 173.4 s
for the ten, 10.4 s apart, 7.7 s of that on Django; apps the new engine does not read at all moved too
(nowinandroid, Kotlin only: 5.0 and 4.8 s before, 5.0 and 5.5 s after). An earlier version of this page said that
with one run each "a second or two either way is noise". That was wrong, and no run had been repeated to check it.
With two runs a side, the ten apps take between 6.5 s and 25.5 s longer with point 4 (3.54% and 14.71%: the slower
"before" against the faster "after", and the faster "before" against the slower "after"), and 16.0 s on the means
of the two sides (178.6 s and 194.6 s, 8.96%). Django takes between 4.9 s and 16.2 s longer and 27 to 31 MB more.
Excalidraw takes between 2.4 s and 3.4 s longer (7.6 and 7.5 s before, 10.0 and 10.9 s after); it is the one app
where the smallest difference between the two sides is larger than the largest difference inside a side (0.9 s).
The two "after" runs are not the same code (1c7f819 and 3e4687c), so the 8.6 s between them may in part be the last
change; four runs cannot tell. Every app lists in the second pair exactly the findings it listed in the first, on
each side (rule, file, line and rank compared), and the reports have the same sizes. Point 10 of the directive has
to measure time with repeated runs, cold and repeat, before any gain or cost is claimed.

What changed in the findings. Django: 18 of Bandit's low "possible hardcoded password" lines are gone and 21 low
`LW-SECRET-INLINE` lines stand in their place (all in Django's own tests); 20 medium `LW-XSS-RAW` lines are new, all
heuristic: 16 are `|safe` on a form's help text or a fieldset's description in Django's own admin and form
templates, 4 are the values of `registration/password_reset_email.html`, a plain-text e-mail inside
`{% autoescape off %}`. Those 4 are false alarms: an e-mail's text is not a page, and Lantern does not tell the two
apart yet (written under Known gaps). The other nine apps list exactly the findings they listed before (rule, file,
line and rank compared).

Two false alarms of the new rules that this run found, and the same change fixed (the first "after" run, d8a7980,
listed 5 findings more than the table above):

* **Hugo**: a script of its own sends the visitor to the page's own site
  (`location.protocol + '//' + location.host + …`) and was listed as a link that goes anywhere (`LT-REDIRECT`,
  medium). In the browser the scheme, host and port a page was loaded from are not the link maker's text; 49
  examples in `tests/test_flow_js.py` and `tests/test_flow.py`, 27 of which were read wrongly before.
* **Django**: `SESSION_KEY = "_auth_user_id"` and three lines like it were listed as secrets written in the code
  (`LW-SECRET-INLINE`, medium). A name like that says "signs" and "is kept under" alike, so its text decides; 22
  examples in `tests/test_secret_inline.py` (10 names beside 12 secrets that stay caught), 8 read wrongly before.
