# Lantern gateway

Hosts Lantern's free DeepSeek allowance. Users get a token; the gateway holds the owner's DeepSeek
key, forwards narrowed requests, and meters each user. When a user's allowance is used up they get
HTTP 402 and the Lantern CLI/app tells them how to add their own key.

**Never put the DeepSeek key in the Lantern app or CLI.** The client is open source; a shipped key
can be extracted and spent by anyone. It belongs here, in the gateway's environment, only.

## Run

```bash
pip install -e gateway/
export DEEPSEEK_API_KEY=sk-...                 # the owner's key
export LANTERN_ADMIN_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
uvicorn lantern_gateway.app:create_app --factory --port 8080
# or: docker build -t lantern-gateway gateway/ && docker run -p 8080:8080 -e DEEPSEEK_API_KEY -e LANTERN_ADMIN_SECRET -v lantern-data:/home/app/data lantern-gateway
```

Put it behind HTTPS (any host with TLS termination: Fly.io, Render, Railway, a VPS with Caddy).
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
| `LANTERN_USD_PER_M_INPUT` / `_OUTPUT` | 0.30 / 1.20 | Prices used for the spend cap (deepseek-flash peak rates, Oct 2026) |
| `LANTERN_MODEL_ID` | deepseek-flash | The only model the gateway will call |
| `UPSTREAM_URL` | https://api.deepseek.com | Any OpenAI-compatible host serving the model |
| `LANTERN_DB` | lantern_gateway.db | SQLite file: token hashes and counters only |

An explanation costs about $0.0015 at peak prices, so a full 300-explanation allowance is about
$0.45–0.90 and the default $10/day cap covers roughly 3,000–6,000 explanations a day.

## What it stores

Token hashes, request and token counts, and daily spend. Never request or response bodies; nothing
about anyone's code. Upstream error bodies are never passed back to clients.
