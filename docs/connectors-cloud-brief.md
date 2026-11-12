# Build brief: Lantern inside Claude and ChatGPT — connectors and plugins for the cloud version

**For:** the dev agent working on `https://lantern-cloud.fly.dev/` (`cloud/`, Fly app `lantern-cloud`)
**Owner:** Little Henderson (Wakil), GitHub `LittleHenderson` · repo `LittleHenderson/Lantern`
**Written:** 2026-11-03 from `main` at v0.10.0 (`675dbdc`), `docs/connectors.md`, spec v0.4 chapter 20, and the
platform docs cited in §9 (read today; they change, so re-check the cited pages before building each milestone)
**Read first:** `CLAUDE.md`, `docs/cloud-mode-brief.md`, `docs/connectors.md`, `docs/api.md` ("Cloud service")

## 0. What this is, in one paragraph

Lantern already works inside AI assistants on a person's own computer: `lantern mcp` is an MCP server over stdio
with eight tools, and every finding has a "Send to…" button that hands the assistant a reference. That path needs
the local app. The cloud version has no such path yet: someone who analysed their repo at lantern-cloud.fly.dev
cannot ask Claude or ChatGPT about it. This brief says how to give the cloud service a **remote MCP endpoint**
(`https://lantern-cloud.fly.dev/mcp`) that Claude (web, Desktop, mobile, Cowork, Claude Code) and ChatGPT (plugins /
Apps SDK) can connect to with the user's own Lantern sign-in, how to list it in both directories, and what a
**plugin** adds on top (a skill that teaches the assistant the fix-and-recheck loop). The one rule that never
moves: **no tool can accept, close, dismiss or re-rank a finding**, in any transport, ever.

## 1. What exists today (reuse, don't rebuild)

| Piece | Where | What it gives you |
|---|---|---|
| Local MCP server | `lantern/mcp_server.py` (stdlib JSON-RPC over stdio, `lantern mcp`, `--setup` prints config snippets) | Tools `lantern_projects`, `lantern_findings`, `lantern_paths`, `lantern_explain` (stored only), `lantern_readiness`, `lantern_analyze`, `lantern_recheck`, `lantern_verify`; each answer carries text + `structuredContent`; records client `clientInfo` (names + times only) to `LANTERN_HOME/connections.json` for Settings › Connections. **Refactor the tool bodies so they take a results folder** (`out` dir with `graph.json`, `security.json`, `readiness.json`, `evidence.json`) and a project label; the stdio server keeps passing `.lantern/`, the cloud passes a run's stored results. The JSON-RPC framing stays; only the transport changes. |
| Cloud service | `cloud/lantern_cloud/app.py` (FastAPI), `store.py` (SQLite: accounts, runs, counters), `identity.py` (sign-in reused from the gateway: token → `GET /v1/whoami`, cached by hash), `worker.py` (clone → audits → jailed `lantern analyze` → results), `/r/{id}/…` result files, share slugs, `/v1/runs/{id}/explain`, `/v1/ask` | The runs and their result files are exactly what the tools read. `Identity` is how a bearer token becomes a user. |
| Sign-in | `gateway/lantern_gateway/auth.py`: GitHub/Google OAuth, HMAC state, one token per account, `/v1/login`, `/v1/auth/<p>/start|callback|claim`; the cloud site uses it through `/v1/signin/start|poll` and an `lt` cookie | The user accounts the connector must map to. The gateway is **not** an OAuth authorization server for third-party clients yet — that is the main thing to build (§3). |
| Send to… | `report.html` `sendText()`/`sendMenu()`; copy in `docs/connectors.md` | Reuse the wording; the cloud version names the run instead of a local project. |
| Badge, Evidence, verify | `lantern/evidence.py`, `/r/{id}/badge.svg`, `/s/<slug>/…` | `lantern_verify` in the cloud compares stored digests; it never re-runs user code. |
| Plugin seams | `docs/connectors.md` §2 (packs, providers, exporters) | Unchanged. A plugin for Claude/ChatGPT is a *client-side* bundle (skill + connector reference); it is not a new seam into the engine. |

## 2. What the platforms require today (checked 2026-11-03)

**Claude (claude.ai web, Desktop, mobile, Cowork, Claude Code) — "custom connector" and the Connectors Directory**
- Remote server over HTTPS at a path such as `/mcp`; Streamable HTTP transport (current MCP spec; Claude's docs
  reference spec 2025-11-25 for authorization). Anthropic egress is `160.79.104.0/21` if you ever allow-list.
- Auth types: `none`, `oauth_dcr` (Dynamic Client Registration, RFC 7591), `oauth_cimd` (Client ID Metadata
  Document — preferred for anything with traffic; needs `client_id_metadata_document_supported: true` **and**
  `"none"` in `token_endpoint_auth_methods_supported`, otherwise Claude falls back to DCR), `oauth_anthropic_creds`
  (you create a confidential client and enter it in the portal), `static_headers` (beta, org-level key; wrong for
  per-user data). Machine-to-machine `client_credentials` is not supported.
- Discovery: an unauthenticated call must get **`401`** with `WWW-Authenticate: Bearer resource_metadata="…"`
  pointing at an RFC 9728 protected-resource document whose `resource` equals the MCP URL exactly and whose
  `authorization_servers[0]` is your issuer; the issuer serves RFC 8414 (or OIDC discovery) metadata at
  `/.well-known/…`. A `WWW-Authenticate` on a `200` is ignored.
- PKCE `S256` on every authorization request; advertise `code_challenge_methods_supported: ["S256"]`.
- Redirect URIs: hosted Claude apps use exactly `https://claude.ai/api/mcp/auth_callback`; Claude Code uses a
  loopback redirect on a random port — accept `http://localhost/callback` and `http://127.0.0.1/callback` with the
  port ignored.
- Token endpoint accepts `application/x-www-form-urlencoded`; refresh errors use `invalid_grant`; rotate refresh
  tokens for public clients; discovery/registration/token answer within 10 s, refresh within 30 s.
- Lazy auth is allowed: public tools work without sign-in; the first call to a tool that needs the account returns
  the `401` challenge.
- Directory listing (optional, after it works as a custom connector): every tool needs a `title` and a
  `readOnlyHint` or `destructiveHint`; documentation URL, privacy-policy URL, support contact, icon, a test
  account for reviewers; submit at `claude.ai/directory/manage` → **MCP connector**; any paid Claude plan can
  submit; listed as Community by default, Verified after review. Local (stdio) servers are no longer listed on
  their own — they ride inside a **plugin**.
- Plugins: a GitHub repo folder with `.claude-plugin/plugin.json`, skills, optional MCP server references; validated
  with `claude plugin validate`; submitted at the same portal → **Plugin bundle**; appears in claude.ai chat,
  Cowork and Claude Code; a plugin that points at a remote server should also submit that server as a connector.

**ChatGPT (and Codex) — "plugins" (the Apps SDK) and custom MCP servers**
- Remote server on a public HTTPS domain, Streamable HTTP, URL entered with its path (e.g. `/mcp`).
- Auth: none, or OAuth; CIMD preferred (public client `none` or `private_key_jwt`), DCR still accepted. The
  2026-07-28 MCP spec deprecates DCR in favour of CIMD — build CIMD first, keep DCR as fallback.
- Users test it through **Settings → Security and login → Developer mode**, then **Plugins → + → Add custom MCP
  server** (name, description, URL, auth) → **Create as a plugin**; tool metadata is captured at creation (press
  Refresh after changing tools).
- Deep research / company knowledge use two read-only tools named exactly **`search`** (query → `results[]` of
  `{id, title, url}`) and **`fetch`** (id → `{id, title, text, url, metadata?}`), each returned both as
  `structuredContent` and as a JSON string in `content`; citations appear only when `url` is non-empty.
- Review for the directory: hosted publicly; demo account for reviewers (no MFA); `readOnlyHint` true only for
  pure reads; `destructiveHint` true for anything irreversible, with a written justification naming safeguards;
  `openWorldHint` false for a bounded account; privacy-policy URL; tools return only what is needed; one version
  in review at a time; organisation identity verification; `api.apps.write` permission; EU-data-residency projects
  can't submit.

## 3. What to build

### 3.1 OAuth authorization server for Lantern (the hard part; everything else hangs on it)

Lantern's users already sign in with GitHub or Google through the gateway. Claude and ChatGPT need Lantern itself
to be an **OAuth 2.1 authorization server** that issues tokens *to them* on behalf of a signed-in Lantern user.
Build it in the gateway (`gateway/lantern_gateway/oauth.py`), since that is where accounts and the GitHub/Google
flow live; the cloud service (resource server) validates the tokens it issues.

Endpoints and documents:
- `GET /.well-known/oauth-authorization-server` (RFC 8414): `issuer`, `authorization_endpoint`, `token_endpoint`,
  `registration_endpoint` (DCR fallback), `code_challenge_methods_supported: ["S256"]`,
  `token_endpoint_auth_methods_supported: ["none"]`, `client_id_metadata_document_supported: true`,
  `grant_types_supported: ["authorization_code", "refresh_token"]`, `scopes_supported: ["lantern.read",
  "lantern.analyze", "offline_access"]`, `response_types_supported: ["code"]`.
- `GET /oauth/authorize`: validates `client_id` (a CIMD URL → fetch and cache the client document, check
  `redirect_uris`; or a DCR-registered id), `redirect_uri` (exact match for `https://claude.ai/api/mcp/auth_callback`
  and ChatGPT's callback; port-agnostic match for `http://localhost/callback` and `http://127.0.0.1/callback`),
  `code_challenge` + `S256`, `scope`, `state`, `resource` (RFC 8707: must be the MCP URL). Then the existing
  GitHub/Google sign-in, then a **consent screen** that names the client's hostname and says in plain words what
  the assistant will be able to do ("read your Lantern runs, findings, paths and readiness; start a new analysis;
  it can never accept or close a finding"). Issue a one-time code (10 min, bound to client, redirect URI, PKCE
  challenge, scope, resource, user).
- `POST /oauth/token` (form-encoded): `authorization_code` with PKCE verifier → access token (JWT or opaque,
  1 h, audience = the MCP URL) + refresh token (rotated on every use, 30 days); `refresh_token` grant; errors per
  RFC 6749 (`invalid_grant`). Answer in well under 10 s (no upstream calls on this path).
- `POST /oauth/register` (RFC 7591, JSON) for clients without CIMD: store `client_name`, `redirect_uris`,
  `token_endpoint_auth_method: none`; cap registrations per day; prune unused clients.
- Revocation: `POST /oauth/revoke`; the user's Settings › Connections page lists every assistant with a live
  grant and a **Disconnect** button (this is the one place a per-assistant switch makes sense, because it is a
  real token, not a guess).
- Store only hashes of codes/refresh tokens; the gateway's existing rule (hashes and counters, never bodies or
  emails) applies.

The cloud service as **resource server**: `GET /.well-known/oauth-protected-resource` →
`{"resource": "https://lantern-cloud.fly.dev/mcp", "authorization_servers": ["https://lantern-gateway.fly.dev"],
"scopes_supported": ["lantern.read", "lantern.analyze"], "bearer_methods_supported": ["header"]}`. Every request to
`/mcp` without a valid bearer token → `401` + `WWW-Authenticate: Bearer resource_metadata="https://lantern-cloud.fly.dev/.well-known/oauth-protected-resource", scope="lantern.read"`.
Tokens are accepted only from the `Authorization` header, never from the query string. Validate audience, expiry,
scope; map to the Lantern account; apply the same per-user limits as the website.

### 3.2 The remote MCP endpoint

`POST /mcp` (and `GET /mcp` for the optional SSE stream, `DELETE /mcp` to end a session) implementing MCP
**Streamable HTTP** with the current spec version negotiated in `initialize`. Use the official Python MCP SDK's
Streamable HTTP server if its licence and size are acceptable; otherwise port the stdlib JSON-RPC loop from
`mcp_server.py` (it is small) and add the HTTP framing: `Mcp-Session-Id` header, JSON responses for single
requests, SSE for streamed responses, `Origin` check (reject unknown origins), request body cap, 30 s per call.

Tools (names fixed; each has `title`, `description`, `inputSchema`, annotations):

| Tool | Scope | Annotations | Does |
|---|---|---|---|
| `lantern_runs` | read | readOnly, !openWorld | The user's cloud runs (id, label/link, commit, date, score, grade, open counts, privacy level). Replaces `lantern_projects`. |
| `lantern_findings` | read | readOnly | Findings of a run (`run_id`, optional `id`, `rank`, `reachable_only`): file, line, rule, title, click path, uses-input, scenario, fix; share-safe (no source text when privacy = structure). |
| `lantern_paths` | read | readOnly | Callers/callees with confidence, path from the page, for a node id or a finding id. |
| `lantern_explain` | read | readOnly | The stored three lenses + scenario for a node; **never calls a model** (unchanged rule). |
| `lantern_readiness` | read | readOnly | Score, grade, failed checks with fixes, moves, protections. |
| `lantern_evidence` | read | readOnly | Evidence summary, digest, badge text, Limits section. |
| `lantern_analyze` | analyze | !readOnly, !destructive, openWorld (it clones a public link) | Starts a new run for a link the user gives (same limits and privacy default as the website); returns the run id and a `/v1/runs/{id}` status; the assistant polls with `lantern_runs`. |
| `lantern_recheck` | analyze | !readOnly, !destructive | New run for the same link as an earlier run; answers "gone / still open / moved" for one finding id by comparing stable ids. |
| `lantern_verify` | read | readOnly | Compares a run's stored digest with a re-computation of the stored results (no re-clone, no code run). |
| `search` | read | readOnly | ChatGPT's deep-research pair: full-text over the user's runs and findings → `{id, title, url}` where `url` is the run's `/r/{id}/report.html#f-<finding>` (owner view) — only for that user. |
| `fetch` | read | readOnly | `id` → one finding or run as text + `url` + `metadata`. |

Things that must not exist, and the test that proves it: no `accept`, `close`, `dismiss`, `rerank`, `delete`
tools; a tool call named like one returns the fixed refusal text from `mcp_server.py`. Deleting a run stays on the
website (it needs the person).

Every tool answer carries both readable text and `structuredContent` (ChatGPT needs the JSON string in `content`
too). Write the `connections` row on every `initialize` (client name + version + time) so Settings › Connections on
the cloud site shows "Claude · used 2 min ago", as the local app does.

### 3.3 Website and report changes

- **Settings › Connections** on lantern-cloud: the setup block (URL `https://lantern-cloud.fly.dev/mcp`, the
  Claude steps, the ChatGPT steps, Claude Code one-liner `claude mcp add --transport http lantern https://lantern-cloud.fly.dev/mcp`,
  Cursor/Windsurf/Codex JSON with `"url"`), the live log of assistants with Disconnect, and the can / can-never
  lists verbatim from `docs/connectors.md`.
- **Send to…** on cloud reports: Claude → `https://claude.ai/new?q=<message>`; ChatGPT → `https://chatgpt.com/?q=<message>`;
  Copy. Message text (adapt `sendText()`): "Fix Lantern finding 57fa455f7b3b (B602) in run shop-2026-11-03. If the
  Lantern connector is available, call lantern_findings with run_id … and id … for the file, line, click path and fix,
  lantern_paths before editing, and lantern_recheck after. You cannot accept or close it; only I can, with a
  reason. Essentials: …". Without the connector the essentials line stands alone, as today.
- The report's About page and the Evidence Limits line say the connector can read and re-analyse, never close.

### 3.4 Plugins (after the connector works)

- **Claude plugin** `plugins/lantern/` in this repo: `.claude-plugin/plugin.json` (name, version, description,
  `mcpServers` → the remote URL), `skills/fix-a-lantern-finding/SKILL.md` (the loop: `lantern_findings` →
  `lantern_paths` → edit → `lantern_recheck`; never claim a finding is fixed until recheck says gone; never try to
  accept), `skills/read-a-lantern-report/SKILL.md` (what the four stops, ranks, "uses input" and confidence words
  mean), README with a Privacy Policy section, LICENSE (MIT). `claude plugin validate ./plugins/lantern` passes.
  Submit as **Plugin bundle** and the server as **MCP connector** (both, per Anthropic's docs).
- **ChatGPT plugin**: the same MCP server plus the same skills in OpenAI's plugin package format (their "Build
  skills" + "Package the plugin" pages); no UI component in v1 (an Apps SDK component that renders the stack
  strip and the path is a v2 idea — it would need the report's CSS in their CSP rules).
- Local users keep `lantern mcp` (stdio); the plugin's SKILL.md works for both, because tool names match.

## 4. Rules that must not break

1. **No accept/close/dismiss/re-rank through any connector or plugin**, with a test per transport.
2. **Never run the user's code** from a tool: `lantern_analyze` runs the same jailed pipeline as the website;
   `lantern_verify` never re-clones or replays anything.
3. **Per-user data only**: every tool call is scoped to the token's account; shared slugs are not reachable through
   the connector; `search`/`fetch` never cross accounts.
4. **Tokens** only in the `Authorization` header; hashes at rest; refresh rotation; revocation in Settings.
5. **Secrets never in the repo or the client**; OAuth client secrets for `oauth_anthropic_creds` (if used) are
   entered by the owner in Anthropic's portal and on Fly, never pasted in chat.
6. **Escape everything** the tools return into text (finding titles and snippets are user-controlled strings);
   keep `structuredContent` exact.
7. **Self-audit stays 0/0/0**, CI green, squash-merge on the owner's "merge #N" only.

## 5. Tests (minimum)

- `tests/test_oauth.py`: metadata documents; full authorization-code + PKCE flow with a CIMD client and with a DCR
  client; wrong verifier → `invalid_grant`; refresh rotation (old refresh token dead after use); loopback
  redirect with any port accepted for `localhost`/`127.0.0.1`, `https://claude.ai/api/mcp/auth_callback` exact;
  `resource` mismatch refused; revoke kills access + refresh; token in query string refused.
- `tests/test_mcp_http.py`: `initialize` → `tools/list` has every tool with `title` + annotations; `401` challenge
  shape on an unauthenticated call; each tool against a stored run; another user's run id → not found; a call named
  `lantern_accept` → the refusal; `search`/`fetch` shapes exactly as ChatGPT requires; session id handling; body
  cap; Origin check.
- MCP Inspector run documented in `docs/connectors.md` (both directories ask you to confirm you ran every tool).
- Existing: `tests/test_mcp.py` (stdio) must keep passing after the refactor of tool bodies.

## 6. Milestones (one PR each; merged only on the owner's word)

1. Refactor `mcp_server.py` tool bodies to take a results folder + label; stdio behaviour unchanged (tests green).
2. OAuth server in the gateway (§3.1) + protected-resource metadata and `401` challenge on the cloud; docs in
   `docs/api.md` ("OAuth" and "MCP endpoint" sections) **before** the UI. Owner deploys the gateway.
3. `/mcp` Streamable HTTP endpoint with the read tools; Connections log; test as a Claude custom connector and a
   ChatGPT custom MCP server (developer mode) on the live site.
4. `lantern_analyze` / `lantern_recheck` / `lantern_verify`; `search` / `fetch`; Send to… on cloud reports.
5. Settings › Connections on the cloud site with Disconnect; `docs/connectors.md` updated with the cloud setup.
6. Claude plugin folder + validation; directory submissions (connector, then plugin) — the owner submits from his
   account (paid plan required; test account for reviewers; privacy policy URL on the site; support contact).
7. ChatGPT plugin package and submission — the owner submits (org identity verification required).

Acceptance for "done": a person signs in at lantern-cloud, runs an analysis, adds `https://lantern-cloud.fly.dev/mcp`
in Claude and in ChatGPT, signs in through Lantern's consent screen, asks "what should I fix first in my shop run?"
and gets the real top finding with its click path; says "I fixed it, check again" and the assistant calls
`lantern_recheck` and reports gone/still open; asks the assistant to accept the finding and is told it cannot; then
disconnects the assistant in Settings and the next call gets `401`.

## 7. Open questions for the owner (ask before milestone 2)

- OAuth client registration for the hosted Claude apps: CIMD/DCR only (zero coordination), or also create a
  confidential client and hand it to Anthropic (`oauth_anthropic_creds`) for the directory listing?
- Should `lantern_analyze` from an assistant count against the same 10 runs/day as the website, or a separate
  (lower) limit?
- Directory listings: submit to Claude's directory and OpenAI's at v1, or only after a few weeks of custom-connector
  use? Both need a privacy-policy page on the site (there is a privacy *section*; a dedicated page is required) and
  a support contact (an email or a GitHub issues link).
- Plugin name and icon: "Lantern" (collision risk in both directories) or "Lantern Code Map"?

## 8. How to work with the owner

Updates end with `🎉WHAT IS CURRENTLY HAPPENING:` / `🎁FOR WAKIL TO DO:` / `🚀NEXT:`, one mark per result from his
scale (✅ 🟩 🟨 🟧 🟥 ⬜ 🔧 🔒), plain words, exact numbers, negatives never deleted. He merges by saying "merge #N".
He enters every secret himself on Fly / GitHub / the portals; never ask for a key in chat. The agent cannot run
`fly deploy`; give him the exact commands (`docs/deploy.md`). Full detail: `docs/handoff-to-design.md` §3 and §6.

## 9. Sources read on 2026-11-03

- Anthropic, *Authentication for connectors*: https://claude.com/docs/connectors/building/authentication
- Anthropic, *Submit a connector to the directory*: https://claude.com/docs/connectors/building/submission
- Anthropic, *Submit your plugin*: https://claude.com/docs/plugins/submit
- OpenAI, *MCP servers in ChatGPT* (plugins, search/fetch, CIMD): https://developers.openai.com/docs/mcp
- OpenAI, *MCP server review requirements* (annotations, privacy, submission): https://developers.openai.com/plugins/deploy/app-review
- Vercel KB, *MCP server as a ChatGPT connector* (Streamable HTTP, developer mode, 2026-07-28 spec note): https://vercel.com/kb/guide/mcp-server-chatgpt-connector
- Sunpeak, *Claude connector authentication* (summary of the same rules): https://sunpeak.ai/blogs/claude-connector-oauth-authentication/
- MCP specification, authorization (2025-11-25): https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
