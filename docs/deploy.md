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

## Free allowance limits as configured

Read from the repository on 2026-11-03, with nothing changed. A Fly secret with the same name would override a value
here; `fly secrets list` shows names only. **Bold** marks a value that is unset or has no limit.

| Limit | Value | Where |
|---|---|---|
| Per-user lifetime requests | 300 (`LANTERN_FREE_REQUESTS`) | `gateway/fly.toml:15`, default `gateway/lantern_gateway/app.py:81` |
| Per-user lifetime tokens | 1,500,000 (`LANTERN_FREE_TOKENS`, **not set in fly.toml**, so the code default applies) | `gateway/lantern_gateway/app.py:82` |
| Per-user daily requests | 120 per UTC day (`LANTERN_DAILY_REQUESTS`) | `gateway/fly.toml:13`, default `app.py:83` |
| Global daily dollar cap | $10 per UTC day, then HTTP 503 until 00:00 UTC (`LANTERN_GLOBAL_DAILY_USD`) | `gateway/fly.toml:16`, default `app.py:85`, check `app.py:559` |
| Output tokens per request | 3,000 max (`LANTERN_MAX_TOKENS`, **not set in fly.toml**) | `app.py:86` |
| Request body | 250,000 bytes max (`LANTERN_MAX_BODY`, **not set in fly.toml**) | `app.py:87` |
| Model order | Anthropic `claude-haiku-5-5` first, DeepSeek `deepseek-flash` when Anthropic fails; `LANTERN_PRIMARY=deepseek` swaps them (**not set**, so Anthropic first) | `app.py:58`, `:61`, `:67`, `Settings.order()` `:109` |
| Token hash retention | SHA-256 of each token in `users`; **kept with no limit** (a re-sign-in marks the old hash disabled, it is not deleted); per-day counters in `daily` and `spend` are **kept with no limit** too | `app.py:126`, `:139`, `:142` |
| Unclaimed sign-in tokens | the plain token waits in `pending` for one claim, deleted after 10 minutes | `app.py:195` |

`GET /v1/health` is public and returns `{ok, version, model, configured, primary, fallback}`: no counters, users or
spend. CI (`gateway` job in `ci.yml`) and the release workflow (`gateway-up`) curl it and print it to the job summary.

## Releases (GitHub now, PyPI later)

A pushed tag `v*` runs `.github/workflows/release.yml`: it builds the sdist and wheel, runs the tests against the
built wheel in a clean venv, checks `https://lantern-gateway.fly.dev/v1/health`, and creates a GitHub Release with
both files and the matching `CHANGELOG.md` section. Testers install with
`pip install "git+https://github.com/LittleHenderson/Lantern@v0.9.0"`.

TODO (not in wave 1): publish to PyPI so the command becomes `pip install lantern`.
1. Create a PyPI account (pypi.org → Register) with two-factor sign-in, and check the name `lantern` is free
   (if not, pick one such as `lantern-code` and change `[project] name`).
2. PyPI → Your account → Publishing → **Add a new pending publisher**: owner `LittleHenderson`, repository `Lantern`,
   workflow `release.yml`, environment `pypi` (a *trusted publisher*: no token is stored anywhere).
3. In `release.yml`, add a `pypi` job after `test-wheel` with `environment: pypi`, `permissions: id-token: write`,
   that downloads the `dist` artifact and runs `pypa/gh-action-pypi-publish@release/v1` with `packages-dir: built/dist`.

## Landing page on Cloudflare Pages

You need: a Cloudflare account (free) and the landing page files in the repository (the design package's
"Lantern Landing", once it is turned into a static `site/` folder).

1. Cloudflare dashboard → **Workers & Pages → Create → Pages → Connect to Git** → pick `LittleHenderson/Lantern`.
2. Build settings: framework preset **None**, build command empty, output directory `site`.
3. Deploy. The page is live at `lantern-xxx.pages.dev`; add your own domain under **Custom domains** when you have one.
4. **Analytics & Logs → Web Analytics → Add a site** → choose the Pages site. Automatic setup; no script to paste.
   Visitors, pages, referrers, countries and devices appear within a few minutes of the first visit.

The analytics beacon goes on the landing page only. The app and its reports never make outside requests.
