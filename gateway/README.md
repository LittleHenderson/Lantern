# Lantern gateway

Hosts Lantern's free allowance. Users get a token; the gateway holds the owner's model keys (Anthropic for
Claude Haiku 5.5, DeepSeek as the fallback), forwards narrowed requests, and meters each user. When a user's allowance is used up they get
HTTP 402 and the Lantern CLI/app tells them how to add their own key.

**Never put a model key in the Lantern app or CLI.** The client is open source; a shipped key
can be extracted and spent by anyone. It belongs here, in the gateway's environment, only.

## Run

```bash
pip install -e gateway/
export DEEPSEEK_API_KEY=sk-...                 # the owner's key
export LANTERN_ADMIN_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
uvicorn lantern_gateway.app:create_app --factory --port 8080
# or: docker build -t lantern-gateway gateway/ && docker run -p 8080:8080 -e DEEPSEEK_API_KEY -e LANTERN_ADMIN_SECRET -v lantern-data:/home/app/data lantern-gateway
```

Put it behind HTTPS (any host with TLS termination: Fly.io, Render, Railway, a VPS with Caddy). The Fly.io
setup, step by step, is in [`../docs/deploy.md`](../docs/deploy.md) (`fly.toml` is beside this file).
Then set `DEFAULT_GATEWAY_URL` in `lantern/providers.py` to `https://<your-host>/v1` for releases,
or have users set `LANTERN_GATEWAY_URL`.

## Give someone an allowance

```bash
curl -X POST https://<host>/v1/tokens -H "Authorization: Bearer $LANTERN_ADMIN_SECRET" \
     -H "content-type: application/json" -d '{"label": "github:octocat"}'
# -> {"token": "lt_...", ...}   shown once; only its hash is stored
```

The user runs `lantern login --token lt_...`. Next step for a public launch: issue tokens through
"Sign in with GitHub" (one token per account) so the allowance can't be farmed.

## Limits (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `LANTERN_FREE_REQUESTS` | 300 | Free explanations per user, lifetime |
| `LANTERN_FREE_TOKENS` | 1500000 | Free tokens per user, lifetime |
| `LANTERN_DAILY_REQUESTS` | 120 | Per user per UTC day |
| `LANTERN_GLOBAL_DAILY_USD` | 10 | Total spend per UTC day; the allowance pauses for everyone when reached |
| `LANTERN_MAX_TOKENS` | 3000 | Cap on `max_tokens` per request |
| `LANTERN_MAX_BODY` | 250000 | Max request body in bytes |
| `LANTERN_PRIMARY` | anthropic | Which provider answers first: `anthropic` or `deepseek`; the other is the fallback |
| `ANTHROPIC_API_KEY`, `LANTERN_ANTHROPIC_MODEL` | –, claude-haiku-5-5 | Anthropic key and model |
| `LANTERN_ANTHROPIC_USD_PER_M_INPUT` / `_OUTPUT` | 0.10 / 0.50 | Haiku 5.5 standard rates (prompts under 100k tokens) |
| `DEEPSEEK_API_KEY`, `LANTERN_MODEL_ID`, `UPSTREAM_URL` | –, deepseek-flash, https://api.deepseek.com | DeepSeek key, model, host |
| `LANTERN_USD_PER_M_INPUT` / `_OUTPUT` | 0.30 / 1.20 | deepseek-flash peak rates |
| `LANTERN_DB` | lantern_gateway.db | SQLite file: token hashes and counters only |

An explanation on Haiku 5.5 costs about $0.0007 (roughly 1,000 input and 1,000 output tokens), so a full
300-explanation allowance is about $0.20 and the default $10/day cap covers roughly 14,000 explanations a day.
On DeepSeek at peak prices it is about $0.0015.

## Primary and fallback

The primary provider (Anthropic by default) answers every request. When it fails (no balance, rate limited,
5xx, unreachable) the same narrowed request goes to the other provider, if its key is set. A healthy primary
means the fallback is never called. The `x-lantern-model` header and the dashboard's "Which model answered"
table say which one did; each is billed at its own prices under the same global daily cap. Anthropic has no
JSON mode, so prose around the JSON object is trimmed; the client's validator and retry still apply. The
client's consent text names both providers.

## Owner dashboard

Open `https://<gateway>/v1/admin` and enter the admin secret (it stays in that browser tab; nothing stores it).
You get: people who used the allowance today / 7 days / 30 days, explanations and spend per day with charts,
sign-ups, how many used up the free allowance, the heaviest users by the label you gave their token, and the
app's opt-in usage counts (installs, active installs per day, uses per feature, versions, operating systems).
`GET /v1/admin/stats?days=30` returns the same as JSON with the admin secret as a Bearer token.

## Opt-in usage counts from the app

When a person turns on "Share anonymous usage counts" in Lantern's Settings (off by default), the app sends
`POST /v1/usage` at most once a day: a random install id, the app version, the operating system name, and how
many times each feature was used that day. The gateway accepts only the feature names in `USAGE_FEATURES` and
drops everything else, so no project name, file name or code can arrive through this channel even from a
modified client. `lantern usage --show` prints exactly what the next ping contains.

## What it stores

Token hashes, request and token counts, daily spend, and the usage counts above (install id, version, OS,
feature counts per day). Never request or response bodies; nothing about anyone's code. Upstream error bodies
are never passed back to clients.
