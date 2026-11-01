# Deploying Lantern's hosted pieces

Two hosted pieces, two hosts. Everything else runs on people's own computers.

| Piece | Host | Why |
|---|---|---|
| **Gateway** (free DeepSeek allowance, owner dashboard, usage counts) | Fly.io | One small always-on server with a disk; the Dockerfile deploys as is. About $2–4/month plus the DeepSeek bill, which the gateway caps at `LANTERN_GLOBAL_DAILY_USD` per day |
| **Landing page** (public website) | Cloudflare Pages | Static files, free, deploys from GitHub; Cloudflare Web Analytics (free, no cookies) for visitor numbers |

## Gateway on Fly.io

You need: a Fly.io account with a card, your DeepSeek API key, and the `fly` command installed
(`curl -L https://fly.io/install.sh | sh` on Mac/Linux; `pwsh -Command "iwr https://fly.io/install.ps1 -useb | iex"` on Windows).

From the repository root:

```bash
cd gateway
fly auth login                          # opens the browser once

# 1. Create the app from gateway/fly.toml. Say NO to Postgres/Redis, NO to deploying yet.
fly launch --copy-config --no-deploy
#    If "lantern-gateway" is taken, pick another name here and tell Claude so the app's default URL matches.

# 2. The disk that keeps the counters across restarts (one, in San Jose: Fly has no Seattle region; `sjc` is the nearest).
fly volumes create lantern_data --region sjc --size 1

# 3. The two secrets. The DeepSeek key is typed here, by you, and nowhere else.
fly secrets set DEEPSEEK_API_KEY=sk-...
fly secrets set LANTERN_ADMIN_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
#    Copy the admin secret somewhere safe: it opens the dashboard and mints tokens.
#    To see it again later: fly secrets list shows only names; run `fly ssh console -C "printenv LANTERN_ADMIN_SECRET"`.

# 4. Deploy. First time takes about two minutes.
fly deploy

# 5. Check.
curl https://lantern-gateway.fly.dev/v1/health
#    -> {"ok": true, "model": "deepseek-flash", "configured": true}
```

Then:

* **Dashboard:** open `https://lantern-gateway.fly.dev/v1/admin` and enter the admin secret.
* **Your first token:** on the dashboard, "Give someone a free allowance" → type a label → Create token. Then
  `lantern login --token lt_...` and `lantern explain tests/fixtures/shop` (`lantern allowance` shows what's left).
  From a terminal instead: `curl -X POST .../v1/tokens -H "Authorization: Bearer <admin secret>" -H "content-type: application/json" -d '{"label": "wakil"}'`.
* **Default for everyone:** `DEFAULT_GATEWAY_URL` in `lantern/providers.py` is `https://lantern-gateway.fly.dev/v1`.
  `LANTERN_GATEWAY_URL` overrides it (tests and a second gateway).

**Deployed 2026-11-01** in the Little Henderson organization, region `sjc`, machine `shared-cpu-1x` 256 MB, volume
`lantern_data` 1 GB. Secrets are set on the Fly website (app → Secrets): `DEEPSEEK_API_KEY`, `LANTERN_ADMIN_SECRET`.
Note: `fly deploy` from a machine behind a TLS-inspecting proxy fails on Fly's default (Depot) builder; `fly deploy
--depot=false` uses the classic builder and works.

Changing a limit later: `fly secrets set LANTERN_GLOBAL_DAILY_USD=20` (any variable from `gateway/README.md`),
which restarts the machine. Logs: `fly logs`. Updating the code: `fly deploy` again from `gateway/`.

What can go wrong and what it looks like:

| Symptom | Cause | Fix |
|---|---|---|
| `health` says `"configured": false` | DeepSeek key not set | step 3 |
| Explanations return "allowance paused" | The global daily dollar cap was reached | wait for 00:00 UTC, or raise `LANTERN_GLOBAL_DAILY_USD` |
| Dashboard says "That secret was not accepted" | Wrong admin secret | `fly ssh console -C "printenv LANTERN_ADMIN_SECRET"` |
| Counters reset after a deploy | Volume not mounted | `fly volumes list` should show `lantern_data` attached |

## Landing page on Cloudflare Pages

You need: a Cloudflare account (free) and the landing page files in the repository (the design package's
"Lantern Landing", once it is turned into a static `site/` folder).

1. Cloudflare dashboard → **Workers & Pages → Create → Pages → Connect to Git** → pick `LittleHenderson/Lantern`.
2. Build settings: framework preset **None**, build command empty, output directory `site`.
3. Deploy. The page is live at `lantern-xxx.pages.dev`; add your own domain under **Custom domains** when you have one.
4. **Analytics & Logs → Web Analytics → Add a site** → choose the Pages site. Automatic setup; no script to paste.
   Visitors, pages, referrers, countries and devices appear within a few minutes of the first visit.

The analytics beacon goes on the landing page only. The app and its reports never make outside requests.
