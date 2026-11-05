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
