# CLAUDE.md

Context for working on Lantern in Claude Code. The product spec is `docs/Lantern_Product_Spec_v0.1.pdf`;
this repo is its **Phase 0 spike** (Python engine, scanners, Three-Lens explainer, static HTML report).

## Non-negotiable principles (from the spec)

1. **Facts from tools, words from models.** Call edges, findings, and reachability come from
   deterministic code. Models only explain, and never create, dismiss, or close a finding.
2. **Show confidence, never fake certainty.** Every edge has `observed | resolved | inferred | possible`
   plus a `via` saying how it was resolved. A new resolution rule gets a confidence level backed by
   `bench/` numbers: "inferred" (UI: "likely") needs about 90%+ measured precision across repos.
   Unresolvable calls are counted in `graph.unresolved`, not guessed.
3. **Every Lens 3 pair must anchor** to an allowed symbol, a line range inside the unit, or a term found
   in the source or `GLOSSARY`. `explain.validate()` enforces this; don't loosen it to make a model pass.
4. **Lantern must pass its own audit.** `lantern analyze .` should report no critical/high/medium.

## Commands

```bash
pip install -e ".[scan,dev]"
python -m pytest -q                                   # ~2 s, 48 tests
lantern analyze tests/fixtures/shop --out /tmp/shop   # end to end on the fixture
python examples/make_demo.py /tmp/demo                # report with hand-written explanations, no key
python bench/run_bench.py /tmp/bench                  # clones 6 public repos; ~2 min with tracing
node tools/viewer_smoke.js /tmp/demo/report.html /tmp/shot   # screenshots + JS error check
                                                      # (needs Playwright + Chromium)
```

## Layout

| File | Role |
|---|---|
| `lantern/graph.py` | Unified Code Graph: `Node`, `Edge`, confidence ranks, JSON round-trip, `stats()` |
| `lantern/python_frontend.py` | Discover → tree-sitter parse (`_visit_body`, `CallSite`s) → `Resolver` → `build_graph()` |
| `lantern/tracehook.py` | Runs a program with `sys.monitoring`, records repo-internal caller→callee pairs |
| `lantern/trace.py` | Runs the hook in a subprocess, maps pairs to nodes, collapses wrapper hops, upgrades edges to `observed` |
| `lantern/security.py` | Bandit, pip-audit, secrets → findings pinned to nodes → BFS reachability from entry points → rank |
| `lantern/explain.py` | Prompt, `validate()`, retry, bottom-up ordering (`select_nodes`), cache, metaphor world |
| `lantern/providers.py` | Anthropic, OpenAI-compatible (OpenAI, OpenRouter, Mistral, Gemini, Ollama, LM Studio, vLLM), fixture stub |
| `lantern/report.py` + `viewer/report.html` | Bundle JSON into one self-contained HTML file (vanilla JS, no build step) |
| `lantern/cli.py` | `analyze`, `trace`, `explain`, `report`; results in `PATH/.lantern/` |
| `tests/fixtures/shop` | Tiny app with planted SQL injection, shell injection, and MD5 for end-to-end tests |
| `bench/` | Accuracy benchmark and its write-up; `results.json` is the latest run |

## How resolution works (python_frontend.py)

The walker emits `CallSite`s with a `kind`:
`call` (normal), `depends` (FastAPI `Depends(fn)`), `depends-alias` (param typed with an `Annotated`
alias defined elsewhere), `decorator-result` (the closure a decorator factory returns), `attr`
(attribute read; kept only if it hits a `@property`), `with` / `with-obj` (`__enter__`/`__exit__`).

`Resolver.resolve_call` handles `call`; `resolve_special` handles the rest. Typing sources, in order:
`self`/`cls` → class; `self.x = Foo()` → attr type; `x = Foo()` / `x = make()` (return type) / param
hints / `with Foo() as x` → local type; pytest fixture by parameter name. Imports are canonicalized
through a suffix index so `from app import crud` finds `backend.app.crud`; stdlib names are never
remapped onto repo files.

To add a rule: write a failing test in `tests/test_frontend.py` with a tiny repo via `_write()`, give
the edge a distinct `via`, then run `bench/run_bench.py` and check the per-method table before choosing
its confidence.

## Phase 1 backlog (priority order)

1. **Run real models through `lantern explain`** on the benchmark repos with two providers; record the
   first-try anchor pass rate (Phase 0 exit criterion, target 90%). Tune `SYSTEM` prompt from failures.
2. **Pyright for type-aware resolution** (spec 6.3) to lift recall, especially attributes typed only
   by annotations on class fields.
3. **Framework adapters:** Flask/Django URL routing to view functions, Django `urls.py`, Celery tasks,
   Typer/argparse subcommands, `app.include_router(prefix=...)` for FastAPI global prefixes.
4. **Deployment Readiness Score** (spec section 10): deterministic checks for secrets/config, lockfile,
   tests, Dockerfile, CI, logging, timeouts.
5. **Evidence Report** (spec section 11): commit-pinned summary with provenance and a Limits section.
6. **PWA shell + local agent pairing** (spec sections 5 and 12). The current viewer becomes the Atlas
   screen; keep it framework-free or port to SvelteKit/React as the spec suggests.
7. Scanner licensing for cloud mode: Opengrep with own or permissively licensed rules (spec 9.1).
   Bandit and pip-audit are fine locally.

## Known gaps

* Callbacks passed as values (`ctx.invoke(f)`, `map(fn, ...)`) aren't edges yet.
* Calls into libraries that call back into the repo (framework dispatch) only show when traced.
* `pip-audit` only reads `requirements*.txt`; `pyproject.toml`/lockfiles are Phase 1.
* The report embeds source by default; `--privacy structure` omits it.
* Explanations exist only for the selected nodes (entry points + 3 levels, capped at 40 by default).

## Conventions

* Python 3.11+, standard library plus tree-sitter; no network calls except model providers.
* Keep `report.html` a single self-contained file that works offline and on a phone.
* Plain language in user-facing text; technical detail lives in Lens 1 and `via`.
