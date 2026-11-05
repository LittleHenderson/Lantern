# 2026-11-05: Django crashed the analysis, Laravel ran for over 15 minutes

**Noticed by / how:** the first run of the weekly large-app check (`tools/large_apps.py`, PR #115), before any person
hit either.

**For how long, who was affected:** nobody on the live service is known to have been affected; both are frameworks,
not typical apps. Anyone analysing a Python project with re-exports that chase each other in a circle, or a PHP project
with a parent-class circle, would have seen a crash or a run that never ended.

**What happened:** two unguarded loops. The Python reader followed `from .a import x` / `from .b import x` pairs
forever and hit the recursion limit. The PHP reader's property-type lookup walked parent classes without remembering
where it had been, and resolved each parent again and again (27 million lookups on Laravel).

**What fixed it:** PR #115: a twelve-hop limit on the import chase; a visited set, a cache and a one-time subclass
index in the PHP reader. Django now finishes in 87 s, Laravel in 33 s.

**What stops it next time:** `tests/test_robustness.py` has both shapes as small repositories; the weekly large-app job
fails on any app over 15 minutes or 4 GB; every sample analysis in `tools/audit.sh` has a 60-second budget in CI.

**Open:** nothing.
