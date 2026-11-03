# Build brief: Lantern cloud mode ("analyze my repo in the browser")

**For:** the dev agent that builds it
**Owner:** Little Henderson (Wakil), GitHub `LittleHenderson` · repo `LittleHenderson/Lantern`
**Written:** 2026-11-02 by the previous dev agent, from spec v0.4 chapters 5, 12, 13 and the code on `main` at v0.9.0 (`5f7ada1`)
**Read first:** `CLAUDE.md`, `docs/handoff-to-design.md` (rules, build/ship routine, how the owner wants updates),
`docs/api.md`, `docs/deploy.md`, `gateway/README.md`

## 0. What this is, in one paragraph

Today Lantern runs only on the user's computer (`lantern serve`, or the CLI). The website shows a demo report but
cannot analyze a visitor's own code. Cloud mode is the version where a person signs in on the website, pastes a
repository link, and gets their own report in the browser — no install. The spec calls this "cloud mode" (5.1):
the same engine, run in a disposable sandbox on our side, clone destroyed when the job ends, only derived results
kept, privacy level chosen by the user. Nothing of it exists yet. This brief says what to build, in what order,
what to reuse, and what must not be broken.

## 1. Scope

**v1 (this brief):** public GitHub/GitLab/Codeberg repos by link · sign in with GitHub or Google (already built in the
gateway) · one job queue · the analysis the CLI already does (graph, bridge, scanners, readiness, protections,
evidence) · the same `report.html` served read-only from our server · privacy level chosen before the run ·
per-user and global limits · delete-my-results · optional public share link with revoke. Explanations and Ask
Lantern via the free allowance are v1.5 (same code, needs the model call wired through the cloud service).

**Not v1:** private repos (needs a GitHub App), runtime tracing / "Watch my tests run" (needs a real microVM
sandbox), opening fix PRs, paired local agents, push notifications, offline PWA caching, WebGL graph (spec 12.2 —
only needed past ~1k edges; the current viewer is fine for v1 repos).

## 2. What already exists and must be reused (do not rebuild)

| Need | Exists as | Notes |
|---|---|---|
| Analysis | `lantern.pipeline.analyze(repo, out, privacy, trace_cmd=None, no_scan=False, log, offline)` → writes `graph.json`, `security.json`, `readiness.json`, `report.html`, `evidence.html/json` into `out` | Pure Python + tree-sitter; **never executes the analysed code**. Scanners shell out to `bandit`, `pip-audit`, `npm audit --package-lock-only` (read lock files only; the audits are the only network calls; `offline=True` skips them). `trace_cmd` must stay `None` in the cloud. |
| Repo by link | `lantern.remote.parse(link)` (https only, allow-listed hosts, no credentials, `/tree/<branch>`), `remote.clone(link, log, dest, root)` (`--depth 1 --no-checkout`, size checked against `LANTERN_CLONE_MAX_MB` before checkout, nothing left behind on failure, every git call under `run_bounded` with a process-tree kill) | Already treats the clone as untrusted. Reuse as is; set the cap low in the cloud (e.g. 200 MB). |
| Report page | `lantern.report.read_bundle(path)`, `render(bundle, live=None, nonce=None)` → self-contained HTML with a hash CSP; `live` carries `{api, token, model, local}` only when actions are allowed | Serve with `live=None` in v1 (read-only). Everything from the data is escaped in the viewer; keep it that way. |
| Privacy levels | `privacy` = `full` (source snippets in the report) or `structure` (none); spec 5.3 also names `redacted` and `offline` | v1 offers `full` and `structure`; default to `structure` in the cloud and say in plain words what each keeps on our server. |
| Evidence Report | `lantern.evidence.build/render_html/verify`, digest, badge | Serve `evidence.html` next to the report; the badge SVG works unchanged. |
| Sign-in + allowance | `gateway/` (FastAPI, `create_app --factory`, SQLite `Store`, `auth.py`: GitHub/Google OAuth with HMAC state, one token per account, `/v1/auth/<p>/start|callback|claim`, `/v1/allowance`, `/v1/chat/completions` narrowed proxy, per-user and global daily caps, admin dashboard) live at `https://lantern-gateway.fly.dev` | The cloud service is a **second app in the same style** (or a second router in the same process — your call; see §3). Reuse `auth.py` and the token scheme (hashes only, never emails). |
| Explanations | `lantern.pipeline.plan_explain/explain`, `lantern.providers` (consent, `LanternHostedProvider` for the allowance, cache by `cache_model`) | v1.5: run `explain` server-side on the stored results with the signed-in user's allowance token. |
| Ask Lantern | `lantern.ask.facts/ask` | v1.5, same as above. Screenshot OCR stays local-only (never upload images). |
| Isolation | `lantern/sandbox.py` + `lantern/_jail.py` (v0.9.0): Docker backend (image pinned by digest, project read-only at `/app`, `--network none`, 2 CPU / 2 GB, uid 65534) or restricted subprocess (read-only temp copy, env allow-list, rlimits, Landlock writes-only-in-temp + no TCP, 10-min wall clock killing the tree); `LANTERN_SANDBOX=subprocess\|docker` | Built for "Watch my tests run"; **reuse it to run the cloud worker's analysis step** (see §3). Tests: `tests/test_sandbox.py`. |
| Connector | `lantern mcp` (stdio) | Out of scope for cloud v1; an HTTP transport is a separate backlog item. |
| Website | `site/` on GitHub Pages | Add the "Analyze my repo" entry point here; the app itself is served by the cloud service, not by Pages. |
| Deploy | Fly.io, org Little Henderson, region sjc; `gateway/fly.toml`, `gateway/Dockerfile`, `docs/deploy.md` | The agent cannot run `fly deploy` or set secrets; the owner does that from `docs/deploy.md`. Write the steps for him. |

## 3. Architecture for v1 (smallest honest version)

```
browser ── site/ (Pages) ──► "Analyze my repo" ──► cloud service (Fly app "lantern-cloud", FastAPI)
                                                     │  auth: gateway's auth.py (GitHub/Google), token hash in SQLite
                                                     │  POST /v1/repos  → job row (queued)
                                                     ▼
                                               worker (same image, separate Fly machine or process)
                                                     │  remote.clone → tmp dir (cap 200 MB, 10 min wall clock)
                                                     │  pipeline.analyze(privacy=<user's>, trace_cmd=None)
                                                     │  copy graph/security/readiness/evidence/report → results store
                                                     │  remove_tree(clone)         ← always, in `finally`
                                                     ▼
                                               results store: SQLite rows + files on a Fly volume (v1)
                                                              (object storage such as Tigris when > 1 machine)
browser ◄── GET /r/<run>/report  (report.html, live=None, nonce CSP) ── per-user, or public slug when shared
```

Decisions already made for you (the owner approved the pattern in the gateway; keep it):
- **Python/FastAPI, SQLite, one Docker image**, same layout as `gateway/`. No Postgres, no queue service, no Kubernetes
  in v1. Spec 13.1 allows exactly this ("Postgres-backed queue initially" — SQLite is the smaller first step).
- **Isolation in v1 reuses `lantern/sandbox.py`**, not a microVM. Sequence per job: (1) `remote.clone` on the
  service side (network needed, untrusted bytes only, size cap); (2) `pipeline.analyze(..., offline=True,
  trace_cmd=None)` **inside the sandbox** (Docker backend on Fly when the daemon is available, else the restricted
  subprocess: Landlock, no TCP, rlimits, uid 65534, 10-min wall clock) with the clone mounted read-only and results
  written to the sandbox temp dir; (3) the dependency audits (`lantern.depaudit`) run on the service side on the
  lock files only — they are data, not code, and need the network (OSV / npm registry); (4) results copied out,
  clone and temp removed. This is acceptable **only because the engine never runs the user's code** (no build, no
  tests, no `npm install`, no `pip install`). The spec's microVM (5.1) is the v2 target; say so in the Limits section
  of every cloud Evidence Report ("analysed in a sandboxed container, no runtime tracing").
- **Clone destroyed when the job ends**, success or failure (`remote.remove_tree` in a `finally`). Only derived
  results persist (spec 5.1 Retention). Verify with a test that lists the tmp dir after a failed job.
- **Privacy level is chosen before the run** and shown on the report and in Evidence provenance. Cloud default:
  `structure`. `full` must show the sentence "short source snippets of your code will be stored on Lantern's server
  so the report can show them" before the run starts.
- **Limits** (env-configurable, same style as `gateway.Settings`): runs per user per day (default 10), concurrent
  jobs (default 2), clone cap (200 MB), job wall clock (10 min), results retention (30 days unless the user keeps
  them), global runs per day. Over the limit → HTTP 429 with a plain-words message the UI shows.
- **Results are user-scoped.** A run is readable by its owner's token; a public slug (`/s/<slug>`) exists only after
  the user clicks Share, is revocable, and serves the report with `privacy` as stored (no way to widen it later).
- **No secrets, no PII**: store provider id + login (as the gateway does), token hashes, run metadata, result files.
  Never log request bodies, repo contents or tokens. The scanner finds secrets in the user's code — those strings
  are in `security.json` by design (that is the finding); the share page must therefore default to **off**.

## 4. API (v1), mapped to spec 13.3

All under the cloud service; auth by `Authorization: Bearer <token>` from the gateway sign-in (reuse the claim
flow: the website opens `/v1/login`, polls `/v1/auth/claim?cli=…`, keeps the token in `localStorage` on the site).

| Route | Does | Spec |
|---|---|---|
| `POST /v1/repos` `{link, privacy}` | validates with `remote.parse`, enforces limits, creates a run, enqueues | `POST /v1/repos` + `POST /v1/repos/{id}/runs` collapsed for v1 |
| `GET /v1/runs/{id}` | `{status: queued|running|done|error, stage, log_tail, started, finished, commit, privacy, counts, score}` | `GET /v1/runs/{id}` |
| `GET /v1/runs/{id}/stream` | server-sent events of the job log (the local app already streams job logs; same shape) | `WS /v1/runs/{id}/stream` (SSE is enough in v1) |
| `GET /v1/runs` | the user's runs, newest first | — |
| `GET /r/{id}/report` · `/r/{id}/evidence` · `/r/{id}/badge.svg` · `/r/{id}/findings.json` · `/r/{id}/graph.json` | the stored results, owner-only | `GET /v1/runs/{id}/graph`, `/findings` |
| `POST /v1/runs/{id}/share` → `{slug}` · `DELETE /v1/runs/{id}/share` | public read-only link, revoke | `POST /v1/runs/{id}/reports` |
| `GET /s/{slug}/report` (+ evidence, badge) | public page, no auth, same CSP | — |
| `DELETE /v1/runs/{id}` · `DELETE /v1/me` | delete results / delete everything about me | required by the privacy copy on the site |
| `GET /v1/health`, `GET /v1/admin/stats` (admin secret, as in the gateway) | ops | — |

v1.5 adds `POST /v1/runs/{id}/explain` (uses `pipeline.plan_explain/explain` with the user's allowance; consent
text first) and `POST /v1/runs/{id}/ask`.

Document every route and result shape in `docs/api.md` under a new "Cloud service" section **before** building the
UI against it (the design side builds only against documented routes).

## 5. UI for v1

- On the website (`site/index.html`): an "Analyze my repo" section — sign-in button, link box, privacy choice
  (two cards, plain words), "Start". Then a run page that streams the log (reuse the Running state copy from the
  app: four honest steps, "nothing is run, nothing is installed"), and on completion opens the report.
- The report is the existing `report.html`, standalone (`body` not `embed`), `live=None`: Paths, What to fix, Fix
  screen with "Paste this into your AI assistant" (works without a server), Readiness, Protections, About. Buttons
  that need the local app (I fixed it check again, Accept risk, Watch my tests, terminal) are already hidden when
  `LIVE` is null — verify each one.
- "My runs" list with delete and share controls.
- Copy must say, on the run page and in About: where the code went (a container on Lantern's server, deleted after
  the run), what was kept (per privacy level), and that nothing was executed. The owner cares about this wording;
  reuse the privacy section's phrasing from the site.

## 6. Rules that must not break (short form; full list in `docs/handoff-to-design.md` §2)

1. The worker never executes user code: no `trace_cmd`, no builds, no installs, no test runs. Audits read lock
   files only.
2. Facts from tools, words from models; nothing creates, closes or re-ranks a finding; accepting a risk needs a
   person's written reason (not offered in cloud v1 — no `lantern accept` without the local app).
3. Provider keys live only on Fly (gateway) and on the user's machine; never in the client, the repo or logs.
4. Everything rendered from data is escaped; the report keeps its hash CSP; validate enums from stored data.
5. `lantern analyze .` on this repo stays 0 critical / 0 high / 0 medium; CI enforces it.
6. Never commit real-looking secrets in fixtures; build them at test time.

## 7. Tests to write (minimum)

- `tests/test_cloud.py` against a local instance (the way `tests/test_allowance_flow.py` drives the gateway):
  sign-in stub → `POST /v1/repos` with a **local `file://`-style fixture** is refused (https only) → a tiny git
  server or a bare repo served over http on localhost (`LANTERN_GIT_HOSTS=localhost:PORT`) → run completes →
  report served with CSP → clone directory gone → privacy `structure` report contains no source → share slug
  works, revoke returns 404 → delete removes files → limits return 429 → a run over the size cap fails with the
  plain message and leaves nothing behind.
- Poisoned results (`tools/poison_report.py`) served through `/r/…` pass `tools/viewer_smoke.js`.
- A job whose analysis step tries to open a TCP connection or write outside its temp dir is killed and reported as `blocked` (the sandbox's `LANTERN-SANDBOX-BLOCKED:` marker), with nothing left behind.
- The self-audit covers the new package.

## 8. Milestones (each one a PR, merged only on the owner's "merge #N")

1. `cloud/` package skeleton: settings, SQLite store, auth reuse, `/v1/health`, Dockerfile + `fly.toml`, `docs/deploy.md`
   section. Owner creates the Fly app and sets secrets.
2. Jobs: `POST /v1/repos`, worker, `GET /v1/runs/{id}` + SSE, results on a volume, clone deleted, limits.
3. Serving: `/r/{id}/report|evidence|badge|findings.json|graph.json` owner-only, CSP, privacy respected.
4. Website: sign-in, link box, privacy choice, run page, My runs.
5. Share + delete + retention sweep.
6. v1.5: explain + Ask Lantern through the allowance, with consent copy.

Acceptance for "v1 done": a stranger can go to the website, sign in with GitHub, paste a public repo link, watch the
run, open their report on a phone, share it, revoke it, and delete it — and the server has no copy of their code
afterwards (prove it with the test in §7).

## 9. Open questions for the owner (ask before milestone 2)

- Which hosts are allowed for cloud clones: GitHub only (spec 5.4 says "GitHub only in v1") or every host in
  `remote.KNOWN_HOSTS`?
- Default retention of results: 30 days, or until deleted?
- Should the free allowance be spent by cloud runs' explanations, or should cloud v1 ship facts-only and keep the
  allowance for the local app?
- Public share: on by default off (recommended, because findings can contain secrets the scanner found), or ask
  per run?

## 10. How to work with the owner

Updates end with `🎉WHAT IS CURRENTLY HAPPENING:` / `🎁FOR WAKIL TO DO:` / `🚀NEXT:`, one mark per result from his
scale (✅ 🟩 🟨 🟧 🟥 ⬜ 🔧 🔒), plain words, exact numbers, negatives never deleted. He merges by saying
"merge #N". He enters every secret himself on Fly/GitHub; never ask for a key in chat. The agent cannot run
`fly deploy`; give him the exact commands. Full detail: `docs/handoff-to-design.md` §3 and §6.
