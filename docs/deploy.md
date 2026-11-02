# Deploying Lantern's hosted pieces

Two hosted pieces, two hosts. Everything else runs on people's own computers.

| Piece | Host | Why |
|---|---|---|
| **Gateway** (free allowance on Claude Haiku with DeepSeek as fallback, owner dashboard, usage counts) | Fly.io | One small always-on server with a disk; the Dockerfile deploys as is. About $2–4/month plus the DeepSeek bill, which the gateway caps at `LANTERN_GLOBAL_DAILY_USD` per day |
| **Landing page** (public website) | Cloudflare Pages | Static files, free, deploys from GitHub; Cloudflare Web Analytics (free, no cookies) for visitor numbers |

## Gateway on Fly.io

You need: a Fly.io account with a card, your Anthropic API key (and optionally a DeepSeek key for the fallback), and the `fly` command installed
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

# 3. The secrets. Model keys are typed here (or on the Fly website, app > Secrets), by you, and nowhere else.
fly secrets set ANTHROPIC_API_KEY=sk-ant-...
fly secrets set DEEPSEEK_API_KEY=sk-...          # optional fallback
fly secrets set LANTERN_ADMIN_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
#    Copy the admin secret somewhere safe: it opens the dashboard and mints tokens.
#    To see it again later: fly secrets list shows only names; run `fly ssh console -C "printenv LANTERN_ADMIN_SECRET"`.

# 4. Deploy. First time takes about two minutes.
fly deploy

# 5. Check.
curl https://lantern-gateway.fly.dev/v1/health
#    -> {"ok": true, "model": "claude-haiku-5-5", "configured": true, "primary": "anthropic", "fallback": "deepseek-flash"}
```

Then:

* **Dashboard:** open `https://lantern-gateway.fly.dev/v1/admin` and enter the admin secret.
* **Your first token:** on the dashboard, "Give someone a free allowance" → type a label → Create token. Then
  `lantern login --token lt_...` and `lantern explain tests/fixtures/shop` (`lantern allowance` shows what's left).
  From a terminal instead: `curl -X POST .../v1/tokens -H "Authorization: Bearer <admin secret>" -H "content-type: application/json" -d '{"label": "wakil"}'`.
* **Default for everyone:** `DEFAULT_GATEWAY_URL` in `lantern/providers.py` is `https://lantern-gateway.fly.dev/v1`.
  `LANTERN_GATEWAY_URL` overrides it (tests and a second gateway).

**Deployed 2026-11-01** in the Little Henderson organization, region `sjc`, machine `shared-cpu-1x` 256 MB, volume
`lantern_data` 1 GB. Secrets are set on the Fly website (app → Secrets): `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `LANTERN_ADMIN_SECRET`.
Note: `fly deploy` from a machine behind a TLS-inspecting proxy fails on Fly's default (Depot) builder; `fly deploy
--depot=false` uses the classic builder and works.

Changing a limit later: `fly secrets set LANTERN_GLOBAL_DAILY_USD=20` (any variable from `gateway/README.md`),
which restarts the machine. Logs: `fly logs`. Updating the code: `fly deploy` again from `gateway/`.

What can go wrong and what it looks like:

| Symptom | Cause | Fix |
|---|---|---|
| `health` says `"configured": false` | No model key set | step 3 |
| A secret saved on the website shows "Staged" | Fly saved it without restarting the app | click **Deploy Secrets** on that page, or `fly secrets deploy` |
| Explanations return "allowance paused" | The global daily dollar cap was reached | wait for 00:00 UTC, or raise `LANTERN_GLOBAL_DAILY_USD` |
| Dashboard says "That secret was not accepted" | Wrong admin secret | `fly ssh console -C "printenv LANTERN_ADMIN_SECRET"` |
| Counters reset after a deploy | Volume not mounted | `fly volumes list` should show `lantern_data` attached |

## Deploying from GitHub instead of your computer

If `fly` cannot run on your machine (no install, blocked network), deploy from GitHub's servers: the workflow
`.github/workflows/deploy-gateway.yml` does the same `fly deploy`. One-time setup: on the Fly website open the app
→ **Tokens** → **Create deploy token**, copy it, then on GitHub open the repo → Settings → Secrets and variables →
Actions → **New repository secret**, name `FLY_API_TOKEN`, paste the token. After that, every deploy is: GitHub →
**Actions** tab → **Deploy gateway** → **Run workflow** → type `deploy` → Run. It deploys whatever is on `main` and
prints the health and sign-in-providers checks at the end.

## Sign in with GitHub and Google (free allowance without minting tokens by hand)

Once these are set, anyone can get their own allowance token by signing in at `https://lantern-gateway.fly.dev/v1/login`,
with `lantern login --github` / `--google`, or from the app's Settings. One token per account; signing in again rotates
the token and keeps the usage count. The gateway stores the provider's stable user id and, for GitHub, the login name;
never an email address.

**GitHub** (GitHub → Settings → Developer settings → OAuth Apps → New OAuth App):
- Application name: `Lantern`
- Homepage URL: `https://lantern-gateway.fly.dev/v1/login`
- Authorization callback URL: `https://lantern-gateway.fly.dev/v1/auth/github/callback`
- Copy the **Client ID**; click **Generate a new client secret** and copy it.

**Google** (Google Cloud Console → APIs & Services → Credentials → Create credentials → OAuth client ID, type "Web application";
the consent screen needs only the `openid` scope, and the app can stay in "Testing" with up to 100 test users or be published):
- Authorized redirect URI: `https://lantern-gateway.fly.dev/v1/auth/google/callback`
- Copy the **Client ID** and **Client secret**.

Then, on the Fly website (app → Secrets) or in the terminal, set them yourself:

```bash
fly secrets set GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=...
fly secrets set GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=...
fly secrets set LANTERN_AUTH_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"   # signs the sign-in state
# LANTERN_PUBLIC_URL defaults to https://lantern-gateway.fly.dev; set it if the gateway lives elsewhere
```

A provider with no id/secret is simply not offered: `GET /v1/auth/providers` lists what is on. The client secrets are
used only for the server-side code exchange and never reach a browser or the CLI.

## Landing page on Cloudflare Pages

You need: a Cloudflare account (free) and the landing page files in the repository (the design package's
"Lantern Landing", once it is turned into a static `site/` folder).

1. Cloudflare dashboard → **Workers & Pages → Create → Pages → Connect to Git** → pick `LittleHenderson/Lantern`.
2. Build settings: framework preset **None**, build command empty, output directory `site`.
3. Deploy. The page is live at `lantern-xxx.pages.dev`; add your own domain under **Custom domains** when you have one.
4. **Analytics & Logs → Web Analytics → Add a site** → choose the Pages site. Automatic setup; no script to paste.
   Visitors, pages, referrers, countries and devices appear within a few minutes of the first visit.

The analytics beacon goes on the landing page only. The app and its reports never make outside requests.
