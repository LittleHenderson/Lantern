# Architecture

Lantern is one Python package (`lantern/`, standard library plus tree-sitter grammars) with two front doors that call
the same functions: the command line (`lantern/cli.py`) and the local app (`lantern/server.py`). There is no hosted
service. The only network calls are to the model provider the user configures and the dependency audits
(PyPI/OSV via pip-audit, the npm registry via `npm audit`), which `--offline` turns off.

## Pipeline

```
repo folder
  │
  ├─ engine.build_graph ─┬─ python_frontend   discover → tree-sitter parse → CallSites → Resolver
  │                      ├─ js_frontend       Walker (defs, imports, refs, HTTP calls, routes) → SpecResolver → JSResolver
  │                      └─ bridge.link       frontend HTTP calls ↔ backend routes (method + path segments)
  │        = Unified Code Graph (graph.py)
  │
  ├─ (optional) trace     run the user's command under sys.monitoring; edges seen running → "observed"
  ├─ security.scan        bandit, pip-audit, secret patterns/gitleaks, websec (LW-*/LJ-*) → pin to nodes →
  │                       reachability from entry points → rank → accepted risks (lantern-accepted.json)
  ├─ readiness.assess     ten weighted categories of file/pattern/graph checks → score, advisor, starter files
  ├─ report.write_report  one self-contained report.html (viewer/report.html + embedded JSON)
  └─ evidence.build       commit-pinned evidence.html/.json, digest, badge.svg
                          (baseline.json from the first run gives "before" counts and "fixed" findings)

explain (on request)      select_nodes (entry points + N levels, bottom-up) → prompt → provider → parse →
                          validate anchors → retry once → cache by code hash → explanations.json → re-render
```

`lantern/pipeline.py` holds `analyze`, `explain`, `plan_explain`, and `rebuild_outputs`; the CLI prints their log
lines and the server streams them to the browser.

## Modules

| Module | Responsibility | Key functions |
|---|---|---|
| `graph.py` | Node/Edge dataclasses, confidence ranks, JSON round-trip, stats | `Graph.add_edge` keeps the strongest confidence |
| `python_frontend.py` | Python discovery, parsing, name and type resolution | `discover`, `inside_repo`, `build_graph`, `Resolver` |
| `js_frontend.py` | TS/JS discovery, ES module resolution, React/Next/Express entry points | `add_js`, `Walker`, `SpecResolver`, `JSResolver` |
| `bridge.py` | Match `g.meta["http_calls"]` to route entries | `link`, `match` |
| `trace.py`, `tracehook.py` | Runtime tracing (Python only), merge into graph | `run_trace`, `merge_trace` |
| `security.py` | Scanner orchestration, node pinning, reachability, ranking, accepted risks | `scan`, `reachability`, `rank`, `load_accepted` |
| `websec.py` | Full-stack rules (public env secrets, Supabase, Firebase, CORS, missing auth, JS patterns) | `scan_web` |
| `readiness.py` | Readiness checks, shape classifier, advisor, hotspots, starter files | `assess`, `Repo`, `check_*` |
| `evidence.py` | Evidence Report, digest, badge, git facts | `build`, `digest_payload`, `render_html`, `git_info` |
| `explain.py` | Prompt, JSON parsing, anchor validation, selection, cache | `validate`, `select_nodes`, `run` |
| `providers.py` | Anthropic, OpenAI-compatible presets, fixture stub | `make_provider` |
| `report.py` | Bundle data into `viewer/report.html` | `write_report`, `collect_sources` |
| `server.py` | Local HTTP app, jobs, settings and keys store | `serve`, `Handler`, `Store`, `Jobs` |
| `viewer/app.html` | App shell: Projects, project tabs, Explanations, Settings, Help | vanilla JS |
| `viewer/report.html` | Atlas: map (path tree + flowchart), Findings, Readiness, About, node detail with lenses | vanilla JS |

## Output files (in `PATH/.lantern/`, git-ignored by default)

| File | Contents |
|---|---|
| `graph.json` | `schema`, `repo_root`, `meta` (languages, files, lines, `http_calls`, `bridge` stats), `nodes[]` (`id`, `kind`, `qualname`, `file`, `start_line`, `end_line`, `fingerprint`, `signature`, `entry`), `edges[]` (`src`, `dst`, `kind`, `confidence`, `lines`, `via`, `detail`), `unresolved` |
| `security.json` | `findings[]` (`id`, `tool`, `rule`, `title`, `tool_severity`, `tool_confidence`, `file`, `line`, `category`, `node`, `reachable`, `ui_path`, `rank`, `status`, `accepted`), `tools[]`, `counts` (open only, plus `in_tests`, `accepted`) |
| `readiness.json` | `score`, `grade`, `categories[]` → `checks[]` (`id`, `status` pass/fail/partial/skip, `points`, `earned`, `evidence`, `fix`, `how`), `shape`, `stack`, `advice`, `hotspots`, `next_steps`, `starter` |
| `explanations.json` | `metaphor`, `explanations{node_id → record}` (`lens1`, `lens2`, `lens3.pairs[]` with `anchor`, `findings`, `validated`, `validation_errors`, `model`, `prompt_version`, `code_hash`), `stats` |
| `run.json`, `baseline.json` | timings, privacy, trace exit code; first-run counts and finding ids |
| `report.html` | Self-contained viewer with all of the above embedded (source included only at privacy `full`) |
| `evidence.html`, `evidence.json`, `badge.svg` | Evidence Report, its data including `payload` and `digest`, README badge |

Files the user commits in their repo: `lantern-accepted.json` (accepted risks with reasons) and
`lantern-narratives.md` (their own walkthroughs, shown in the Evidence Report).

Local app state in `~/.lantern/` (or `$LANTERN_HOME`): `projects.json`, `settings.json`, `keys.json` (mode 0600).

## Identifiers

* Python node: `py:pkg.mod.Class.method`. JS node: `js:<path-without-ext>::<Local.name>`, module `js:<path>`.
  External: `ext:<pkg.member>` or `ext:HTTP <METHOD> <path-or-host>`.
* Finding id: first 12 hex of SHA-1 over tool, rule, file, line. Stable across runs while the line doesn't move.
* Project id (server): first 10 hex of SHA-256 of the absolute path.

## Invariants (break one and it is a bug)

1. Models never create, dismiss, or change a finding, an edge, or a score. They only fill `explanations.json`.
2. Every edge carries a confidence (`observed`, `resolved`, `inferred`, `possible`) and a `via`. Unresolvable calls are
   counted in `graph.unresolved`, not guessed.
3. An explanation is `validated` only if every Lens 3 pair anchors to an allowed symbol, a line range inside the
   unit, or a term in the source or glossary (`explain.validate`). Unvalidated ones are shown with a warning.
4. Pattern-based security rules that can misfire set `tool_confidence: LOW` and are labeled "heuristic".
5. A readiness check that does not apply is `skip` and leaves the denominator; every scored check has evidence.
6. Starter files are never written over an existing file or outside the project.
7. The digest covers only deterministic results, so the same commit and tool versions give the same digest.
8. `lantern analyze .` on Lantern itself has no open critical, high, or medium findings (CI enforces this).

## Request flow in the local app

Browser → `GET /?token=…` sets an HttpOnly SameSite=Strict cookie → `GET /` serves `app.html` with the token in
the page → reads use the cookie, writes also send `X-Lantern-Token`. Long work (`analyze`, `explain`, `accept`)
starts a thread job (one per project at a time) and returns `202 {id}`; the page polls `/api/jobs/{id}`.
`/p/{id}/report.html` is the saved report with `window.LANTERN_LIVE` injected, which turns on the live buttons.
