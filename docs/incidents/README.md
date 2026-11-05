# Incident notes

One short file per time the live service (lantern-cloud or the gateway) or a release did something wrong for real
people: what happened, who noticed and how, what it cost them, what fixed it, and what now stops it happening again.
Written within a day, in plain words, without blame. Big companies call this a post-mortem; it exists so the same
mistake is made once.

File name: `YYYY-MM-DD-short-name.md`. Sections, always the same:

```
# <date>: <one line>

**Noticed by / how:** …
**For how long, who was affected:** …
**What happened:** …
**What fixed it:** … (commit or PR)
**What stops it next time:** … (a test, a check, a setting; link it)
**Open:** anything still to do
```

| Date | What | Prevented now by |
|---|---|---|
| 2026-11-04 | lantern-cloud crashed on repositories with files over 256 lines (tree-sitter 0.26.0 memory bug) | version pin + `tests/test_frontend.py` regression test, `requirements-lock.txt`, Dependabot PRs run the full suite before an upgrade lands ([note](2026-11-04-tree-sitter-crash.md)) |
| 2026-11-05 | Django crashed the analysis, Laravel ran over 15 minutes (found by the weekly large-app check before any person hit it) | guards and caches in the Python and PHP readers, `tests/test_robustness.py`, `large-apps.yml` ([note](2026-11-05-large-apps.md)) |
