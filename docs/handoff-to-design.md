# Handoff: Claude Design takes over design and development of Lantern

**To:** Claude Design (the agent that made the Lantern UI board)
**From:** the dev agent (Claude Code) that built the app from your board
**Owner:** Little Henderson (Wakil), GitHub `LittleHenderson`
**Date:** 2026-11-02 · repo `LittleHenderson/Lantern`, branch `main` at `9d6de26`

## 0. The situation, in one paragraph

The owner has decided you take over both design **and** development from here. The engine, the local server, the
security scanners, the connector, the gateway, the website and every screen on your board exist and ship on `main`,
with 300 tests, a self-audit and a browser smoke in CI. What is left is the part you are best placed to do: making
every screen match your board pixel-close and copy-verbatim, plus the specific items listed in section 4 that I left
out or built differently. Treat section 4 as your work queue. Everything else in this file is what you need to not
break the product while you do it.

## 1. What exists today (built, on `main`)

| Area | What is there | Where |
|---|---|---|
| Engine | Python, TS/JS, Go, Rust, Java call graphs; HTTP bridge frontend→backend; Bandit/npm/pip audits; `LW-*`/`LJ-*`/`LG-*`/`LR-*`/`LV-*` rules; reachability, click paths (`ui_path`), "uses input"; readiness score; protections; evidence report with SHA-256 digest; stack lanes | `lantern/*.py` (map in `CLAUDE.md`) |
| Local app | `lantern serve`: Projects (Simple/Advanced), project tabs, Atlas iframe, Evidence, Explanations, Settings (Simple/Advanced, Connections card), Learn/Guide, Help/FAQ, first-run / running / zero-findings / bad-path / no-model states, Ask Lantern pill + window with screenshot OCR, terminal drawer (Lantern commands only), Watch my tests run (in the test sandbox, `lantern/sandbox.py`), keyboard shortcuts, backdrop, Simple/Advanced toggle, dark/light/system | `lantern/server.py`, `lantern/viewer/app.html` (1308 lines) |
| Report / Atlas | One self-contained file, offline, phone-capable: Paths (Lanes · Path · Flowchart · Graph), Findings (memo + table), Fix screen with "I fixed it, check again", Protections, Readiness, Explanations (three lenses), About, "? What am I looking at" on every page, Ask Lantern pill when standalone, stack strip + 4-dot glyph, rails that retract to 30px | `lantern/viewer/report.html` (1735 lines), `lantern/report.py` |
| Evidence Report | Commit-pinned HTML/JSON, baseline → fixed/changed, scorecard, provenance, Limits, badge SVG, `lantern verify` | `lantern/evidence.py` |
| Connector | MCP over stdio (`lantern mcp`), 8 tools, **no accept/close/dismiss tool**, connections log for Settings › Connections, "Send to…" on every finding, SARIF export | `lantern/mcp_server.py`, `lantern/exporters.py`, `docs/connectors.md` |
| Packs | Analysis packs (`LP-*` rules + entry patterns), Django built in, `lantern packs` | `lantern/packs.py`, `docs/packs.md` |
| Model / allowance | Default `anthropic/claude-haiku-5-5` (switched from DeepSeek on 2026-11-01 for price + US hosting; DeepSeek is the gateway's fallback); free allowance via `gateway/` on Fly (`https://lantern-gateway.fly.dev`), GitHub/Google sign-in, consent before code leaves the machine, clean stop when the allowance runs out | `lantern/providers.py`, `gateway/`, `docs/deploy.md` |
| Website | Landing page + 20 s intro (plays on every visit to `/`, ends on an "Add your app" card; deep links and `?intro=0` skip it; Replay in header), privacy section, live demo report built at publish time | `site/`, `.github/workflows/site.yml` → https://littlehenderson.github.io/Lantern/ |
| Docs | API contract and result-file shapes, acceptance checklist per screen, stack lanes rules | `docs/api.md` |

## 2. Rules that must not break (the owner holds these; CI enforces several)

1. **Facts from tools, words from models.** Edges, findings, paths, protections, scores, lanes are deterministic. A model only writes explanations; `explain.validate()` rejects unanchored phrases — do not loosen it. Nothing (model, connector, plugin, UI) may create, close, dismiss or re-rank a finding. Accepting a risk needs a person's written reason.
2. **Read, don't run.** Lantern never executes the user's app. The terminal drawer runs Lantern commands only; "Watch my tests run" runs only recognised test runners (`sandbox.check_command`) inside the test sandbox (`lantern/sandbox.py`: Docker, or a restricted process on a read-only temp copy), and the sheet says which before Run.
3. **Secrets never in the client or the repo.** Provider keys live only on the user's machine (`~/.lantern/keys.json`, 0600) or on Fly for the gateway. Never commit real-looking secrets in fixtures (GitHub push protection; build them at test time). Never put the owner's keys in chat, code or docs.
4. **Everything rendered from data is escaped.** `esc()` for values, `cls()` for class names, in both viewers; the report carries a hash-based CSP; CI opens a poisoned report (`tools/poison_report.py`) in Chromium and fails if any payload lands as markup. Validate every enum from the data against a known list before using it as a key (see `laneOk` in `report.html`).
5. **Lantern passes its own audit.** `lantern analyze .` must report 0 critical / 0 high / 0 medium; CI enforces it.
6. **One file, offline, phone.** `report.html` stays a single self-contained file with no network requests (no font CDNs; system font stacks). The design tokens at the top of `app.html`, `report.html` and `evidence.py` are one set — change all three together.
7. **Never overwrite** starter files; never force-push; never rewrite history on a shared branch.
8. **Plain language** in user-facing text; technical detail lives in Lens 1, `via` and `detail`. Status colours (good/warning/serious/critical) mean risk or results only and always sit beside a word or icon.

## 3. How to build, check and ship

```bash
pip install -e ".[scan,dev]"
python -m pytest -q                                  # ~70 s, 300 tests
lantern analyze . --out /tmp/self --offline          # self-audit: must be 0/0/0
python examples/make_demo.py /tmp/demo               # demo report with hand-written explanations, no key
node tools/viewer_smoke.js /tmp/demo/report.html /tmp/shot          # JS errors + screenshots, desk + phone
python tools/poison_report.py /tmp/demo/report.html /tmp/p/report.html && node tools/viewer_smoke.js /tmp/p/report.html /tmp/pshot
lantern serve tests/fixtures/shop                    # the app; prints a one-time link
```

Shipping conventions that exist because of how this environment works:
- Branch from `origin/main`, one PR per piece of work, squash-merge. GitHub's GraphQL is blocked here, so use REST: `gh api -X POST repos/LittleHenderson/Lantern/pulls --input body.json`, `gh api -X PUT …/pulls/N/merge -f merge_method=squash`.
- Stacked PRs conflict after each squash: retarget the next PR to `main` (`gh api -X PATCH …/pulls/N -f base=main`), `git merge origin/main`, resolve with `git checkout --ours <files>` when the branch is a superset, push, wait for green, merge. Avoid stacking when you can.
- CI must be green (3.11/3.12/3.13, Windows, browser) before any merge. The owner says "merge #N"; nothing merges without that.
- GitHub Pages: the site workflow deploys `site/`; the owner still has Pages Source set to "Deploy from a branch", which races and sometimes overwrites the site with a rendered README. Until he switches Source to "GitHub Actions", re-run the site workflow after a merge if the live page is wrong (`gh api -X POST …/actions/runs/<id>/rerun`).
- `fly deploy` and some `fly secrets set` are blocked for the agent; the owner runs those from `docs/deploy.md`.
- Commits end with `Co-Authored-By: Claude … <noreply@anthropic.com>` and the session link; PR bodies end with the Claude Code attribution.

## 4. Your work queue: what I left out or built differently from the board

Honest list, screen by screen. "Verify" means I believe it is partly there and you should check against the board before deciding.

**Fidelity (every screen)**
- Screens were built as fluid adaptations of the board, not pixel-matched. The acceptance bar in your README (copy verbatim, tokens within ±1 px at 1200×760, reflow at 760/1100) was **not** met anywhere. Expect to re-do spacing, type sizes and copy on every screen.
- Fonts: system stacks only (DM Sans / Lora / JetBrains Mono appear only when installed). Vendoring the OFL woff2 files into `lantern/viewer/fonts/` with `@font-face` is open; the report must still work offline (inline as data URIs or accept the system stack there).
- Phones: every screen reflows at ≤720 px (Simple only), but none is the 402×874 design from Lantern App turn 9 or Redesign 2d/1h/1o/1r. The standalone report's tab bar wraps badly on phones (the app hides it when embedded).
- Backdrop: in `app.html` (`#bg`, three drifting layers, off/subtle/bold). **Not** in the standalone `report.html`.

**Landing / intro** — built from `lantern-intro.jsx` (Babel-compiled to `site/intro/intro.js`); tones muted; plays on every visit and ends on an "Add your app" card (Claude Design's landing-intro directive, 2026-11-03; earlier: first three visits). Verify scene timing and captions against Lantern Landing; the video export from the timeline was not done.

**Projects (3b)** — Simple hero + drop zone + app cards with grade ring; Advanced strip + table + live log. Verify sort behaviour and the card's single action.

**Atlas (3c, 5a)** — Path / Flowchart / Graph + new Lanes view (turn 11b). Lanes layout is an SVG staircase with sub-rows per lane, curved connectors; the board's DOM-line connectors anchored to lane boundaries were not reproduced; with the right panel open the chart scrolls sideways instead of fitting. Progressive loading (entry points first, "97 more hidden"), canvas/WebGL past ~1k edges and 10k-row virtualisation are **not** built (section "Scale and performance" of your README is open).

**Findings (4a) / Fix (1k)** — memo + table, Fix screen with queue, "Paste this into your AI assistant", "I fixed it, check again" (works end to end), Send to… Stack strip, sentence and four-card walk (11a) are built; the walk's wording is generated from the real path, not the board's example copy. "Isolate path" is not built.

**Protections (7d)** — statuses add / check / in place. "What already protects you" is thin until a Protections pass exists in the engine (backlog); the screen shows it half-empty on most repos.

**Readiness (7a)** — Simple hero/moves, Advanced categories/rubric/starters. Verify the "already-good" list and point values layout.

**Evidence (4b)** — document + scorecard + diff + provenance + Limits, badge. Glyph on rows added. Phone version (1o) not designed in.

**Explanations (7c)** — one lens at a time (Simple) / three side by side (Advanced), provenance, batch explain with cost and consent. Default model is Haiku, not DeepSeek — a deliberate owner-approved change; update the board's Settings copy to match rather than reverting the code.

**Settings (7b, 10a, 10c, 10d)** — Simple three-choice and Advanced key list exist. **Connections (10a)** exists as a card inside Settings (log rows, setup snippet, can/can-never) — verify against the 10a layout. **Badge (10c)** sub-screen: not built (the badge itself exists in the Evidence Report). **Analysis packs (10d)**: built (v0.9.0) as a card in Advanced Settings (`#packs`, reached from Simple Settings → Also → Analysis packs): one sentence that Python web / TypeScript web are the engine, a "Built in" section (Django) and a "Project and user packs" section, each pack a bordered card with an on/off switch (`role=switch`), and a dashed empty state naming `lantern-packs/*.json` and `~/.lantern/packs/*.json`. Data: `GET /api/packs?all=1`, `POST /api/packs`; project cards show "Re-check to apply" after a change. Verify against the 10d layout.

**Learn / Guide (4c, 5b)** — starter guide with steps and "Run this" into the terminal drawer; catalogue. Verify before/after diff view.

**Help / FAQ (3a)** — search, chips, accordion, Command-line chip → CLI reference + shortcuts. Built; verify copy.

**Ask Lantern** — pill + window, suggestion chips per page, screenshot chip with local OCR, footer line. Opacity slider: verify. Standalone report has a built-in guide version without a model.

**Terminal drawer (5a)** — built; Lantern commands only; ids/paths as links: verify. Phone bottom sheet at 46%: not built as designed.

**Watch my tests run (8f)** — sheet, rewards, success toast and failure toast (exit code, last lines, Try again / Change the command / Skip) exist. Runs in the sandbox (`lantern/sandbox.py`); the sheet names the backend and its limits. JavaScript, Go, Rust and Java tests run but only Python calls are recorded yet ("Tests run; your map upgrades for Python only for now").

**States (turn 8)** — first run, running, zero findings, bad path, no model exist; verify each against the board's copy.

**Stack strip (turn 11)** — done per README: strip, sentence, walk, Lanes mode, glyph + legend, hover definitions verbatim, phone collapse to glyph + words, Evidence rows, `docs/api.md` section, `lane`/`hot_lane`/`lanes` fields. Glyph hot dot is coloured by rank (critical red, high orange, …) rather than always red — your call.

## 5. Where things are in the viewers (for touch-ups)

`report.html`: tokens at top; `S` state; `render()` → `renderLeft()` / tab renderers `renderMap` (`renderLanes`, `renderTree`, `renderChart`, `renderGraph`), `renderFindings` (`findingCard`, `wireFindings`), `renderFix`, `renderProtections`, `renderReady`, `renderExplanations`, `renderAbout`, `renderRight` (function panel, lenses), `findingPanel`; helpers `laneStrip`, `laneGlyph`, `laneSentence`, `laneWalk`, `chainHtml`, `pathsHtml`, `helpBtns`/`PAGE_HELP`, `modeSeg`, Ask: `RASK`/`renderRAsk`. `body.embed` hides chrome when inside the app; `LIVE = window.LANTERN_LIVE` gives `{api, token, model, local}` when served by the app.

`app.html`: `S` state, `go()`, `render()` → `renderHome`/`renderHomePro`, `renderProject` (tabs, iframe reuse via `S.frame`), `renderExplain`, `renderLearn`, `renderGuide`, `renderSettingsSimple`/`renderSettings`, `renderHelp`; `watch(jobId)` streams job logs; Ask: `ASK`, `PAGE_CHIPS`, `window.askAbout(ctx)`; terminal `TERM`/`termRun` → `POST /api/projects/<id>/cmd`; tests sheet `watchTestsSheet`.

`server.py`: routes in `docs/api.md`; every page is rebuilt from templates with a per-response CSP nonce; never serve `.lantern/` files as pages.

## 6. How the owner wants to be talked to

Every update ends with three headings, in this order: `🎉WHAT IS CURRENTLY HAPPENING:`, `🎁FOR WAKIL TO DO:`, `🚀NEXT:`. No jargon; explain plainly when he says he doesn't understand. Each result gets exactly one mark and its word: ✅ CONFIRMED WIN · 🟩 STRONG · 🟨 PARTIAL · 🟧 WEAK · 🟥 FAILED/WITHDRAWN (kept in the record) · ⬜ NULL/INCONCLUSIVE/NOT RUN · 🔧 METHOD/PROCESS WIN · 🔒 BLOCKED ON OWNER. Never delete a negative; ⬜ is not 🟥; every number exact. He merges by saying "merge #N". He enters secrets himself (Fly, GitHub settings); never ask him to paste a key into chat, and never sign in or enter passwords for him.

## 7. Current open items outside the UI

- PR #40 (manual gateway deploy workflow) is open and not yours.
- Backlog after the UI (from `CLAUDE.md`): Protections pass (found protections), explainer first-try anchor rate toward 90%, Deployment Readiness for Go/Rust/Java, more packs (Remix, tRPC, SvelteKit, Rails), type-aware resolution, JS runtime tracing, cloud mode.
