# Analysis packs

An analysis pack teaches Lantern a framework or a set of security rules it does not know yet. A pack is a
JSON file of patterns, **not code**: it can add findings and entry points, and nothing else. That is the
point. Lantern judges other people's security, so its own extension system must not be a way in.

Packs are the first of Lantern's three plugin seams. The others are **explanation providers** (any
OpenAI-compatible endpoint, chosen in Settings) and **exporters** (`lantern export --sarif`; see
`lantern/exporters.py`). Everything else is closed on purpose.

## Where packs live

| Source | Path | Trust |
|---|---|---|
| Built in | `lantern/packs/*.json` | Tested in this repo; may declare `"confidence": "HIGH"` on a rule |
| Project | `<repo>/lantern-packs/*.json` | Committed with the project; treated like the project's code (untrusted) |
| User | `~/.lantern/packs/*.json` (`LANTERN_HOME/packs`) | Yours |

`lantern packs PATH` lists every pack found, which ones apply to this project, and any file that was skipped
and why. Packs that apply are also listed in the Evidence Report's Provenance and the report's About tab.

## Format

```json
{
  "pack": "django",
  "version": "1",
  "about": "One line on what the pack covers.",
  "homepage": "https://...",
  "requires": {"files": ["manage.py"], "text": ["django"]},
  "rules": [
    {"id": "LP-DJANGO-DEBUG",
     "title": "Django DEBUG is on (stack traces and settings shown to visitors)",
     "severity": "MEDIUM", "cwe": 489,
     "files": ["**/settings*.py"],
     "pattern": "^\\s*DEBUG\\s*=\\s*True\\b",
     "unless": "environ",
     "fix": "Read it from the environment and leave it unset in production.",
     "more": "With DEBUG on, any error page lists settings and source lines."}
  ],
  "entries": [
    {"kind": "route", "files": ["**/urls.py"],
     "pattern": "\\bpath\\(\\s*r?['\"]([^'\"]*)['\"]\\s*,\\s*([\\w.]+(?:\\.as_view\\(\\))?)",
     "detail": "ANY /{1}", "handler": "{2}"}
  ]
}
```

| Field | Meaning |
|---|---|
| `pack` | Short lowercase name; one pack per name is loaded (built-in wins) |
| `requires` | Optional. `files`: globs that must match something in the repo. `text`: words that must appear in a manifest (`requirements.txt`, `pyproject.toml`, `package.json`, ...). A pack whose requirements are not met is skipped for that project |
| `rules[].id` | `LP-` followed by uppercase letters, digits and dashes. `LP` keeps pack rules apart from Bandit's `B...` and Lantern's `LW-`/`LJ-` |
| `rules[].severity` | `HIGH`, `MEDIUM` or `LOW`. Lantern turns it into a rank (critical/high/medium/low) using reachability and whether outside input reaches the line, like every other finding |
| `rules[].files` | Globs, matched against repo-relative paths (`**/x.py`, `*.py`, `settings*.py`). Build and dependency folders are never scanned |
| `rules[].pattern` | A regular expression matched **one line at a time**. Lines that start with a comment marker are skipped |
| `rules[].unless` | Optional. A line that also matches this is not reported |
| `rules[].fix`, `more` | Plain language shown with the finding |
| `rules[].confidence` | `HIGH` or `LOW`. Only a built-in pack's `HIGH` is honored; every other pack's findings are labelled **heuristic**, because a pattern file has not been measured on real repositories |
| `entries[].kind` | `route`, `page`, `cli` or `main` |
| `entries[].pattern` | Matched one line at a time in `files`; capture groups feed `detail` and `handler` |
| `entries[].handler` | Which capture group names the function (`"{2}"`): `views.index`, `index`, `ItemView.as_view()`. Lantern looks the name up in the code map; for a class it marks the request methods (`get`, `post`, `delete`, `dispatch`, `handle`, ...). An ambiguous name is counted in `graph.meta.packs.ambiguous`, never guessed |
| `entries[].detail` | What the entry point is, with `{n}` placeholders: `"ANY /{1}"`, `"manage.py command"` |

Limits that keep packs safe: at most 60 rules and 20 entry patterns per pack, patterns up to 400 characters,
files over 600 kB and lines over 2000 characters are skipped, and matching is per line so a bad pattern
can slow a scan but not hang it.

## Writing one

1. Copy `lantern/packs/django.json` to `lantern-packs/<name>.json` in your project.
2. Run `lantern packs .` until it reports no problems.
3. Run `lantern analyze .` and open the report: pack findings say `lantern-pack:<name>`, pack entry points show
   `via: pack:<name>` in the function panel.
4. To propose it as a built-in pack, add a tiny repo test to `tests/test_packs.py` (like
   `test_django_pack_entries_and_rules`) and open a pull request. Built-in rules may claim `HIGH` confidence
   only with a test that shows the pattern does not fire on the safe form.

## What a pack cannot do

* Close, change or re-rank a finding. Packs only add. Accepting a risk still needs a person's written reason
  (`lantern accept`).
* Fake certainty: third-party pack findings are always marked heuristic; pack entry points always say which
  pack registered them and where (`registered_at`).
* Run code, read files outside the repository, or make network calls. There is no hook for any of it.

## Turning a pack off

Any pack (built-in, project or user) can be turned off in the app (Settings → Analysis packs) or by hand in
`~/.lantern/settings.json`: `{"packs": {"disabled": ["django"]}}`. A disabled pack adds no findings and no entry
points; `graph.json` lists it under `meta.packs.disabled`, `lantern packs` marks it `off`, and the Evidence Report's
provenance names it as `off (turned off in Settings)`, so a reader can see which packs were on. Reports made before a
change show "Re-check to apply" on the project's card.
