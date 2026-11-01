# Lantern as a connector, and Lantern's plugin seams

Two directions, kept apart on purpose:

1. **Lantern inside AI assistants.** One MCP server (`lantern mcp`) works in Claude Desktop, Claude Code,
   ChatGPT, Cursor, Windsurf, Codex and anything else that speaks the Model Context Protocol.
2. **Other people extending Lantern.** Exactly three seams: analysis packs, explanation providers, and
   exporters. Everything else is closed.

## 1. The connector

### Set up

```bash
claude mcp add lantern -- lantern mcp          # Claude Code
lantern mcp --setup                            # prints the JSON for Claude Desktop, Cursor, Windsurf, Codex
```

ChatGPT and Claude on the web need a URL. Put the stdio server behind an MCP bridge on a host you control and
add it as a custom connector. Lantern never opens a port by itself.

Settings › **Connections** in the app lists each assistant by the name it gave in the MCP handshake, with
when it last called and which tool: "Claude Code · used 2 minutes ago". There is no on/off switch, because a
switch cannot tell you whether anything is actually connected.

### What the assistant gets

| Tool | What it does | Changes anything? |
|---|---|---|
| `lantern_projects` | The projects Lantern knows, with score and open findings | no |
| `lantern_findings` | Findings with file, line, the click path from the page that triggers them, whether outside input reaches the line, and the fix. `id` fetches one finding | no |
| `lantern_paths` | What calls a function, what it calls, with confidence per link, and the path a user takes to reach it. For the assistant to call **before** editing | no |
| `lantern_explain` | The stored three-lens explanation and the source. Never calls a model | no |
| `lantern_readiness` | Score, grade, failed checks with fixes, what to do first, protections | no |
| `lantern_analyze` | (Re-)analyze a folder; reports fixed and new findings since last time | rewrites `.lantern/` |
| `lantern_recheck` | After a fix: is this finding gone, still open, or moved? | rewrites `.lantern/` |
| `lantern_verify` | Re-run an Evidence Report's analysis and compare digests | no |

Every answer carries both readable text and structured JSON (`structuredContent`).

### What it never gets

* **Accept, close or dismiss a finding.** There is no such tool, and asking for one returns "this connector
  cannot accept or close findings". Accepting a risk needs a person's written reason, through
  `lantern accept` or the Accept button in the app, and appears in the Evidence Report with that reason.
  So "a model never closes a finding" holds by construction.
* **Run the project's code.** `lantern_verify` refuses a report made with a runtime trace, because
  replaying the trace would run whatever command the report named. The builder runs that from a terminal.
* **Your code.** The connector returns function source only for `lantern_explain`, to the assistant you chose,
  on your machine. Nothing is sent anywhere by Lantern.

### "Send to…"

Every finding card in the report has a **Send to…** button: Claude, ChatGPT, or copy (for Cursor, Claude
Code and others). It sends a **reference**, not a pasted blob:

> Fix Lantern finding 57fa455f7b3b (B602) in the shop project. If the Lantern connector is available, call
> lantern_findings with id 57fa455f7b3b for the file, line, click path and fix, lantern_paths before editing,
> and lantern_recheck with the finding id after the fix. Do not try to accept or close it; only I can, with a
> reason. Essentials: subprocess call with shell=True at shop/app.py:16 (uses outside input: parameter
> `name`). Reachable from the app: /admin page → BackupButton → … → app.backup.

With the connector installed, the assistant pulls the exact facts from Lantern, so they cannot go stale or be
edited in transit, and verifies its own fix the same way. Without it, the one-line essentials are enough to
start.

### The badge

`badge.svg` reads **Lantern · commit 1a2b3c · 0 critical · Oct 31** and links to the Evidence Report, whose
Limits section says what was not checked. It never says "verified" or "secure": no tool can promise that,
and an engineer will pick at it. Color follows the open findings (red: critical open; orange: high open;
teal: neither), not the readiness score, which stays in the tooltip.

## 2. The three plugin seams

| Seam | Form | Why it is safe |
|---|---|---|
| **Analysis packs** | JSON pattern files: security rules and framework entry points (routes, pages, commands). See [`packs.md`](packs.md) | Not code. Third-party pack findings are always labelled heuristic; pack entry points say which pack registered them and where. Packs only add; they cannot close or re-rank |
| **Explanation providers** | Any OpenAI-compatible endpoint, chosen in Settings (`openai-compatible`, or a local Ollama/LM Studio) | A provider only ever receives the prompt and returns words. `explain.validate()` rejects any phrase that does not anchor to real code, whatever model wrote it |
| **Exporters** | `lantern export --sarif` (GitHub code scanning, SARIF viewers); the JSON files in `.lantern/` for anything else | Read-only over `security.json` and `evidence.json` |

What is deliberately **not** a seam: scanners that run code, hooks into the pipeline, service connectors that
read live infrastructure, and anything that could create, dismiss or re-rank a finding. If those ever come,
they come signed and permission-scoped ("this plugin wants to read your Supabase schema"), after a plugin
directory exists. Rule packs first, because they cannot run code.
