# Deploying Lantern's hosted pieces

Three hosted pieces. Everything else runs on people's own computers.

| Piece | Host | Why |
|---|---|---|
| **Gateway** (free allowance on Claude Haiku with DeepSeek as fallback, owner dashboard, usage counts) | Fly.io | One small always-on server with a disk; the Dockerfile deploys as is. About $2–4/month plus the DeepSeek bill, which the gateway caps at `LANTERN_GLOBAL_DAILY_USD` per day |
| **Cloud service** (cloud mode: sign in, paste a repository link, get a report in the browser; `cloud/`) | Fly.io, a second app | Handles strangers' repositories, so it runs apart from the machine that holds the model keys. See "Cloud service on Fly.io" |
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
| Dashboard says "Too many wrong secrets in the last minute" | Five wrong secrets from your network in this minute, or 30 from everyone together; until the minute ends no secret is looked at, the right one included | wait a minute, then enter the secret once. If it keeps coming back without you typing anything wrong, somebody else is guessing: they cannot get in, and `fly logs` shows the `403` and `429` lines for `/v1/admin/stats` |
| A person signing in sees "This sign-in link was already used" | The page that came back from GitHub or Google was loaded a second time (Back, reload) | they start the sign-in again from Lantern |
| A person signing in sees "Too many sign-ins in the last minute" | More than 10 sign-ins came back from their network in a minute, or 120 from everyone together | they wait a minute and load that page again (the link is still good) |
| The app's "Share anonymous usage counts" says "not taken (the gateway answered 429)" | A limit on usage reports was reached (per network per hour, new installs per network per day, new installs for everyone per day) | nothing: the app keeps its counts and tries again. To raise a limit: `LANTERN_SENDER_PINGS_PER_HOUR`, `LANTERN_SENDER_INSTALLS_PER_DAY`, `LANTERN_INSTALLS_PER_DAY` (`gateway/README.md`) |
| Counters reset after a deploy | Volume not mounted | `fly volumes list` should show `lantern_data` attached |

## Sign in with GitHub and Google (free allowance without minting tokens by hand)

Once these are set, anyone can get their own allowance token by signing in at `https://lantern-gateway.fly.dev/v1/login`,
with `lantern login --github` / `--google`, or from the app's Settings. Each sign-in gets its own token and the
account's other sign-ins keep working (up to 8 places, least recently used signed out first); all of them share one
usage count. The gateway stores the provider's stable user id and, for GitHub, the login name;
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

Read from the repository on 2026-11-03. The only change since: retention set to 90 days (Wakil's decision, 2026-11-03). A Fly secret with the same name would override a value
here; `fly secrets list` shows names only. **Bold** marks a value that is unset or has no limit.

| Limit | Value | Where |
|---|---|---|
| Per-user lifetime requests | 300 (`LANTERN_FREE_REQUESTS`) | `gateway/fly.toml:15`, default `gateway/lantern_gateway/app.py:81` |
| Per-user lifetime tokens | 1,500,000 (`LANTERN_FREE_TOKENS`, **not set in fly.toml**, so the code default applies) | `gateway/lantern_gateway/app.py:82` |
| Per-user daily requests | 120 per UTC day (`LANTERN_DAILY_REQUESTS`) | `gateway/fly.toml:13`, default `app.py:83` |
| Global daily dollar cap | $10 per UTC day, then HTTP 503 until 00:00 UTC (`LANTERN_GLOBAL_DAILY_USD`) | `gateway/fly.toml:16`, default `app.py:85`, check `app.py:601` |
| Output tokens per request | 3,000 max (`LANTERN_MAX_TOKENS`, **not set in fly.toml**) | `app.py:86` |
| Request body | 250,000 bytes max for `/v1/chat/completions` (`LANTERN_MAX_BODY`, **not set in fly.toml**); 4,000 bytes for every other address. Since gateway 0.2.6 nothing past the limit is read (413) | `Settings.max_body_bytes`, `limits.SMALL_BODY`, `limits.BodyCap` |
| Usage reports (no sign-in) | Since gateway 0.2.6: 300 reports per sender per hour (`LANTERN_SENDER_PINGS_PER_HOUR`), 50 new installs per sender per day (`LANTERN_SENDER_INSTALLS_PER_DAY`), 1,000 new installs per UTC day for everyone together (`LANTERN_INSTALLS_PER_DAY`); **none set in fly.toml**, so the code defaults apply; 0 switches a limit off. Past one: 429 with `Retry-After` | `Settings`, `usage` in `app.py`, `Store.record_usage` |
| Wrong admin secrets | Since gateway 0.2.6: 5 a minute per sender, 30 a minute for everyone together, then 429 until the minute ends (fixed in the code, no variable) | `Settings.admin_wrong_per_minute`, `admin` in `app.py` |
| Sign-ins coming back from GitHub or Google | Since gateway 0.2.6: a link works once; the provider is asked at most 10 times a minute per sender and 120 a minute for everyone together (fixed in the code, no variable) | `auth_callback`, `first_use` in `app.py` |
| Who a sender is | The address in the header named by `LANTERN_ADDRESS_HEADER` (default `fly-client-ip`, which Fly's proxy sets; **not set in fly.toml**), else the connection's address; IPv6 by /64. Kept in memory under a keyed hash, never written | `limits.sender`, `limits.Limiter` |
| Model order | Anthropic `claude-haiku-5-5` first, DeepSeek `deepseek-flash` when Anthropic fails; `LANTERN_PRIMARY=deepseek` swaps them (**not set**, so Anthropic first) | `app.py:58`, `:61`, `:67`, `Settings.order()` `:112` |
| Token hash retention | 90 days (`LANTERN_RETENTION_DAYS`, **not set in fly.toml**, so the code default applies). The SHA-256 of a token in `users` is deleted 90 days after its last request or sign-in, together with the account mapping in `accounts` that points at it; a hash disabled by a re-sign-in is deleted 90 days after that re-sign-in | default `app.py:90`, `Store.prune` `:248`, `users` `:141` |
| Per-day counters | 90 days: rows in `daily`, `spend`, `models` and `usage` dated more than 90 days ago, and `installs` not seen for 90 days, are deleted. Pruning runs at start-up and on the first request of each UTC day. `LANTERN_RETENTION_DAYS=0` keeps everything | `Store.prune` `:248`, `daily` `:144` |
| Unclaimed sign-in tokens | the token waits in `pending` for one claim, deleted after 10 minutes. Since gateway 0.2.6 it waits sealed with the app's own code (the gateway keeps a hash of that code), and a row left in clear by an earlier version is deleted at start-up; until then the plain token waited there | `_seal`, `Store.park`, `Store.claim` in `app.py` |

`GET /v1/health` is public and returns `{ok, version, model, configured, primary, fallback}`: no counters, users or
spend. CI (`gateway` job in `ci.yml`) and the release workflow (`gateway-up`) curl it and print it to the job summary.

What the 90 days mean for a tester: a GitHub or Google account that makes no request and does not sign in for 90
days is forgotten. Its old token stops working, and the next sign-in starts a fresh allowance (300 requests). An
account in use keeps its counters, and signing in again within 90 days still carries them over. Retention applies
to the running gateway only after `fly deploy`; the first prune runs when the new version starts, and
`/v1/health` then reports `"version": "0.2.0"` (or later). Version 0.2.1 adds `GET /v1/whoami`, which the cloud
service below uses to recognise a signed-in person; deploy it before the cloud service.

Version 0.2.6 adds the limits on what anybody can send without signing in (`gateway/README.md`, "What anybody can
send"). They apply only once that version is deployed: `/v1/health` then says `"version": "0.2.6"`. At that
deploy a person who is in the middle of signing in signs in again (the token that waited for their app was kept in
clear by the version before and is deleted, not handed out), and the counts of the limits start empty at every
restart. Nothing needs setting: the four new variables have defaults.

## Cloud service on Fly.io (cloud mode)

The cloud service is the "analyze my repo in the browser" part (`cloud/`, brief: `docs/cloud-mode-brief.md`). It is
a **second Fly app**, `lantern-cloud`, separate from the gateway on purpose: it handles strangers' repositories, and
the gateway holds the model keys. If something ever went wrong while reading a repository, the keys are on a
different machine.

It has no sign-in of its own. A person signs in once at the gateway (GitHub or Google, the same as the app's free
allowance) and the cloud service asks the gateway `GET /v1/whoami` who the token belongs to. So there is **no new
OAuth app and no model key to set here**: the only secret is the cloud service's own admin secret.

What it runs: `GET /v1/health` (public), `GET /v1/me`, `POST /v1/repos` and `GET /v1/runs…` (signed in),
`POST /v1/runs/{id}/view` and the report pages under `/r/` (the run's owner, through a short-lived link),
`GET /v1/admin/stats` (admin secret), and **the website itself at `/`**: the same look as the Lantern app, with
"Sign in", a box to paste a link, the privacy choice, a live progress page and "My runs". It can be installed on a
phone or computer like the app (browser menu → Install / Add to Home Screen). Sign-in on the website goes through the
gateway's GitHub and Google apps that are already set up, so nothing new is needed for it.

Cost: the service **sleeps when nobody uses it**. After 10 minutes with no visitor and no run going, it stops
itself, and Fly bills a stopped machine only for its stored disk image and the 1 GB volume (Fly's price list put
those at about $0.15 per GB per month each when this was written; check fly.io/pricing). While it runs it is a
`shared-cpu-1x` machine with 1 GB of memory, billed by the second (roughly a cent per hour of use). The first
visitor after a sleep waits a few seconds while it starts. Fly has also been waiving monthly bills under $5, but
that is not a written promise; to be sure, ask billing@fly.io. Free alternatives and their trade-offs:
"Free hosting options" below.

From the **repository root** (not `cloud/`: the image also packs the analysis engine):

```bash
# 0. The gateway first, so it has /v1/whoami and the sign-in pages in the app's style (version 0.2.5 or later).
cd gateway && fly deploy --depot=false && cd ..
curl https://lantern-gateway.fly.dev/v1/health          # -> "version": "0.2.6" (0.2.5 before the limits of 0.2.6)

# 1. Create the empty app (once). `fly orgs list` shows your organisation's short name.
fly apps create lantern-cloud --org <your-org>
#    If "lantern-cloud" is taken, pick another name and tell Claude, so `app` and LANTERN_PUBLIC_URL in cloud/fly.toml match.

# 2. The disk that keeps results and the run list across restarts (one, San Jose).
fly volumes create lantern_cloud_data --region sjc --size 1 -a lantern-cloud

# 3. The one secret: the cloud service's own admin secret (opens /v1/admin/stats). Copy it somewhere safe.
fly secrets set -a lantern-cloud LANTERN_ADMIN_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

# 4. Deploy (about three minutes the first time; the image includes git, Node's npm and the engine).
#    Fly may offer to create a second machine for redundancy; one is enough (`fly scale count 1 -a lantern-cloud`).
fly deploy . --config cloud/fly.toml --dockerfile cloud/Dockerfile --depot=false

# 5. Check.
curl https://lantern-cloud.fly.dev/v1/health
#    -> {"ok": true, "service": "lantern-cloud", "version": "0.1.0", "engine": "0.10.0", "limits": {...}, "hosts": "all"}
#    Then open https://lantern-cloud.fly.dev/ in a browser, press Sign in, and paste a repository link.
```

Windows PowerShell: step 3 is two lines (PowerShell passes `NAME=(...)` as two separate words, which `fly` refuses):
`$s = python -c "import secrets; print(secrets.token_urlsafe(32))"` then `fly secrets set -a lantern-cloud "LANTERN_ADMIN_SECRET=$s"`; `$s | Set-Clipboard` copies it for your password manager without printing it on screen.
Or set it on the Fly website: lantern-cloud → Secrets → New secret, then **Deploy Secrets**.

Limits (environment variables; the values in `cloud/fly.toml` are the owner's choices of 2026-11-03):

| Variable | Default | Meaning |
|---|---|---|
| `LANTERN_CLOUD_RUNS_PER_DAY` | 10 | Runs per person per UTC day (`cloud/fly.toml` sets 50, the owner's choice of 2026-11-04). To change it without a full deploy: `fly secrets set LANTERN_CLOUD_RUNS_PER_DAY=<n> -a lantern-cloud` (the machine restarts with the new value; a secret wins over the `[env]` value until `fly secrets unset`) |
| `LANTERN_CLOUD_GLOBAL_RUNS_PER_DAY` | 300 | Runs for everyone per UTC day (`cloud/fly.toml` sets 1000; change it the same way) |
| `LANTERN_CLOUD_CONCURRENT_JOBS` | 2 | Runs analysed at the same time; the rest wait in the queue |
| `LANTERN_CLOUD_ACTIVE_PER_USER` | 1 | Runs one person may have waiting or going at once |
| `LANTERN_CLOUD_AUDITS` | 1 | Dependency audits (pip-audit, npm audit on lock files); `0` skips them and reports say so |
| `LANTERN_CLONE_MAX_MB` | 500 | A repository whose code is larger than this is refused before its files are written. Above it, the pictures, video, sound, fonts, archives, compiled programs, model weights and datasets Lantern never reads are left out first (`remote.BULK_EXT`, and files over 20 MB of a type Lantern does not read), and the Evidence report's Limits says so. Each run holds its download and its files on the volume, so keep the volume at least 6 × this (two runs at once): the deploy workflow extends it to 3 GB |
| `LANTERN_CLOUD_JOB_SECONDS` | 1200 | Wall clock per run; the analysis is stopped after it |
| `LANTERN_CLOUD_IDLE_MINUTES` | 0 (10 in `cloud/fly.toml`) | Minutes with no visitor and no run before the service stops itself; 0 = never |
| `LANTERN_CLOUD_RETENTION_DAYS` | 0 | 0 = results kept until the person deletes them (Delete on a run, or Delete my account); a number N deletes finished runs older than N days, checked every hour by the clean-up pass ("Clean-up" below; a pass that failed is tried again five minutes later and shown in the owner's statistics) |
| `LANTERN_CLOUD_VIEW_MINUTES` | 60 | How long a "open my report" link works |
| `LANTERN_CLOUD_VIEW_SECRET` | derived from the admin secret | Signs those links; set it only to make all open links stop working at once (`fly secrets set`) |
| `LANTERN_CLOUD_HOSTS` | (empty) | Comma-separated clone hosts; empty = every public forge Lantern knows |
| `LANTERN_GATEWAY_URL` | `https://lantern-gateway.fly.dev/v1` | Where sign-ins are checked |
| `LANTERN_CLOUD_DB`, `LANTERN_CLOUD_RESULTS`, `LANTERN_CLOUD_WORK` | on the volume | Run list (SQLite), result folders, temp folders of runs in progress. Each run's temp folder is removed when the run ends, and the ones cut-off runs left are removed at start-up. The service removes only the folders it made there (each carries its mark file `.lantern-work`); anything else in these folders is left alone and counted ("Clean-up" below). Until 2026-11-10 start-up deleted everything in the work folder, whatever it was |
| `LANTERN_CLOUD_UPLOADS` | `<LANTERN_CLOUD_WORK>-uploads` (on the volume) | Uploaded .zip files waiting for their run to start; each is moved into its run's temp folder when the run starts. At start-up half-received uploads and the uploads of runs that are over are removed; a waiting run's upload stays, and so does anything that is not an upload of the service's (counted, "Clean-up" below) |

Explanations and Ask Lantern (milestone 6) need no new setting or secret: they go to the same gateway the
sign-in uses, with each person's own allowance token, and only after that person agrees on the website. The gateway's
per-person and daily dollar limits apply to them as to the app.

What the cloud database holds: the account id the gateway gives (`github:<number>`, `google:<id>`), its label (the
GitHub login), when the person agreed to send work to a model (if they did), and each run's link, privacy level,
status, times, commit, counts, share link and explanation counts. Never a token (not even its hash), an email, or the
repository's files.

| Symptom | Cause | Fix |
|---|---|---|
| `/v1/me` answers 503 "can't check your sign-in" | The gateway is down, or older than 0.2.1 (no `/v1/whoami`) | step 0 |
| The website's sign-in sheet says sign-in is not switched on | The gateway has no GitHub/Google app secrets | "Sign in with GitHub and Google" above |
| `fly deploy` says it can't find `lantern/` or `pyproject.toml` | Run from `cloud/` instead of the repository root | `cd ..`, repeat step 4 |
| Health check fails right after deploy | Volume not created, so the database can't be written | step 2, then `fly deploy` again |
| The first request after a quiet spell takes a few seconds | The service was asleep (normal, it saves money) | nothing |
| A large repository's run ends with an error about memory | 1 GB is not enough for it | `fly scale memory 2048 -a lantern-cloud` (doubles the running cost) |
| The uptime mail says `lantern-cloud clean-up` is `OWED` | Files the service should have removed (a deleted run's results, a run's temp folder) have been waiting for more than a day, or runs past the retention time are still there | "Clean-up" below: read the reason in the owner's statistics first |
| After deleting a run the website says "Deleted, with one thing still to do" | The run is gone for everyone, but the server could not remove its files from its disk yet. It has written that down and tries again at every start and every hour | Nothing, unless the uptime mail above arrives a day later |

### Watching the live services (uptime, and "is the live version behind?")

`.github/workflows/uptime.yml` asks both services for `/v1/health` every 30 minutes (`tools/uptime.py`). A run fails,
and GitHub emails the repository owner, when either service is down, answers without `"ok": true`, takes more than
5 seconds, when lantern-cloud's engine version is older than the latest GitHub release (the live service is behind;
redeploy, below), or when lantern-cloud's health page says its clean-up is behind ("Clean-up" below). The health pages are public and show versions and limits only, so the check needs no secret.
`python tools/uptime.py --cloud https://lantern-cloud.fly.dev --gateway https://lantern-gateway.fly.dev` runs the same
check by hand. Fly's own status page is https://status.flyio.net/. To get the mails, keep "Actions: send notifications
for failed workflows" on in your GitHub notification settings (it is on by default for the repository owner).

### Clean-up: what the service removes by itself, and what it leaves to you

The service deletes only what it made: a run's temp folder when the run ends, the results of a run when its owner
deletes it (or the retention time is over), a half-received upload, the upload of a run that is over. When the disk
refuses, nothing is lost track of: the service writes down what it still has to remove, tells the person, and tries
again every time it starts and every hour while it is awake. (The live service sleeps when nobody uses it, and the
uptime check wakes it every 30 minutes, so "again" is at least that often.)

What it knows is in the owner's statistics, `GET /v1/admin/stats` with the admin secret, under `cleanup`:

| Field | Meaning | What to do |
|---|---|---|
| `waiting`, `by_kind`, `oldest` | How many things are still to be removed, of which kind (`results`, `work`, `upload`), and since when the oldest has been waiting | Nothing while `behind` is false |
| `reasons` | Why, one sentence each with the system's reason (five at most; no file names), for example "it could not be removed; the reason: the disk is read-only (OSError 30)" or "3 things in it could not be removed; the first reason: no permission (PermissionError 13)" | A read-only disk or a disk error: look at the volume (`fly volumes list -a lantern-cloud`, `fly ssh console -a lantern-cloud -C "df -h /home/app/data"`). "it belongs to another user" or "it is a link": something other than the service wrote into its folders; look at what it is before removing it by hand |
| `behind` | True when something has been waiting for 24 hours or more, or runs more than a day past the retention time are still there. The health page then says `"cleanup": "behind"` and the uptime check fails, which mails you | Fix the cause above; the next pass removes what is waiting and the word goes back to `ok` by itself |
| `last_pass` | When the last pass ended, whether it went through (`ok`), the kind of error if not, and how many things it removed | `ok: false` twice in a row with the same error is worth a look at `fly logs -a lantern-cloud` |
| `left_alone` | How many things in the work folder, the uploads folder and the results folder are **not** the service's own. It never deletes these | See below |
| `refused` | Deletes that were refused since the start because the name was not one the service gives, or the thing was in use | Should stay 0; anything else is a bug to report |

`left_alone` is normally `{work: 0, uploads: 0, results: 0}`. Two cases are known where it is not, and both are safe
to clean by hand **while no run is going** (My runs shows none running; or right after a deploy):

* `work` above 0 after the first deploy of this version: a temp folder that a run of the older version left when it
  was cut off (the older version put no mark in its folders, so the service cannot know such a folder for its own).
  `fly ssh console -a lantern-cloud -C "ls -la /home/app/data/work"` shows them; a folder named `run-…` or
  `explain-…` there with no run going is such a leftover:
  `fly ssh console -a lantern-cloud -C "rm -rf /home/app/data/work/run-XXXXXXXX"` (the exact name, one at a time).
* `results` above 0: a results folder that no run points at. Until 2026-11-10 a delete whose files could not be
  removed left them there with no record. `ls /home/app/data/results` lists one folder per run; the statistics do not
  name the orphans (they never name a run), so compare with the run list in the database before removing anything, or
  leave them: nobody can open them, they only take space.

Never point `LANTERN_CLOUD_WORK`, `LANTERN_CLOUD_UPLOADS` or `LANTERN_CLOUD_RESULTS` at a folder other programs use.
The service no longer deletes what it finds there, but it still counts on these folders being its own.

### Backups and a way back (rollback)

Both apps keep everything on one Fly volume (`lantern_data` for the gateway, `lantern_cloud_data` for the cloud
service): a SQLite database and, for the cloud service, the result folders. Fly takes a daily snapshot of every volume
and keeps five days of them; nothing to set up, but worth knowing how to use:

```bash
fly volumes list -a lantern-cloud                       # the volume's id (vol_…)
fly volumes snapshots list vol_XXXXXXXX                 # the daily snapshots, newest first
# Restore = make a NEW volume from a snapshot, then point the app at it (the old volume is kept until you delete it):
fly volumes create lantern_cloud_data --snapshot-id vs_XXXXXXXX --region sjc --size 1 -a lantern-cloud
fly machines list -a lantern-cloud                      # the machine id
fly machine update <machine-id> --volume <new-volume-id> -a lantern-cloud   # or destroy the old volume and redeploy
```

A copy of the database onto your own computer, any time (the database is small; no run is interrupted):

```bash
fly ssh sftp get /data/cloud.db ./cloud-backup-$(date +%F).db -a lantern-cloud
fly ssh sftp get /data/lantern_gateway.db ./gateway-backup-$(date +%F).db -a lantern-gateway
```

(`fly ssh console -C "ls /data"` shows the exact file names if they differ.) Keep these with your password manager's
attachments or another private place: the gateway file holds token hashes and counters, the cloud file holds account
ids and run lists, never emails, tokens or repository files.

Rolling back a bad release means deploying the previous image again, which takes a minute and loses nothing on the
volume:

```bash
fly releases -a lantern-cloud                           # the list, newest first, with each image name
fly deploy -a lantern-cloud --image <image of the previous good release>
```

If the database format changed between the two versions, the older code still opens it: both services create any
missing table at start-up and never delete columns, so an old version reads a new database (new columns are ignored).

### Deploying from GitHub, not only from one laptop

`.github/workflows/deploy-cloud.yml` deploys either app from the Actions tab (Run workflow → pick `lantern-cloud` or
`lantern-gateway`, optionally a git ref), builds on Fly's builders, and ends with the uptime check against the new
version. It needs one repository secret, **`FLY_API_TOKEN`**: on any computer with `fly` signed in, run
`fly tokens create deploy -a lantern-cloud` (a token that can deploy that one app and nothing else; make a second one
for the gateway if you want both, or an org token), copy the output, and paste it under the repository's Settings →
Secrets and variables → Actions → New repository secret. The gateway is in another Fly organisation, so it reads its own secret,
**`FLY_GATEWAY_TOKEN`** (`fly tokens create deploy -a lantern-gateway`, or the app's Tokens page on fly.io); the cloud
keeps using `FLY_API_TOKEN`. Without it the workflow stops at its first step and says so.
With it, the laptop is no longer the only place a fix can ship from, and the admin secret never leaves Fly's secret
store (the workflow does not need it).

### Connect GitHub: private repositories (optional)

Without this, a private repository's check stops and the website offers Upload. With it, the website also offers
**Connect GitHub**: the person installs Lantern's GitHub App on the repositories they choose, and Lantern then reads
those with a token that covers one repository, is read-only, and lasts an hour at most. It reads one only for someone
GitHub says may read it (their GitHub account id, from the sign-in), so a stranger who pastes the link gets nothing.
Nothing about installations is stored; the token is never written to disk or a log.

Create the app once (about 5 minutes, in a browser signed in as the account that owns Lantern):

1. Open https://github.com/settings/apps/new
2. **GitHub App name**: `Lantern Checks` (names are unique across GitHub; if it is taken, add your name).
3. **Homepage URL**: `https://lantern-cloud.fly.dev`
4. **Callback URL**: leave empty. Leave "Request user authorization (OAuth) during installation" unticked.
5. **Setup URL**: `https://lantern-cloud.fly.dev/`, and tick **Redirect on update**.
6. **Webhook**: untick **Active**.
7. **Permissions → Repository permissions → Contents**: **Read-only** (Metadata turns Read-only by itself). Nothing else.
8. **Where can this GitHub App be installed?**: **Any account**. Click **Create GitHub App**.
9. On the page that opens, note the **App ID** (a number) and the app's short name in the address bar
   (`github.com/settings/apps/<short-name>`).
10. Scroll to **Private keys**, click **Generate a private key**; a `.pem` file downloads.

Then, in PowerShell from `C:\Users\<you>\Lantern` (the key goes to Fly without being shown; never `echo` it):

```powershell
fly secrets set LANTERN_GITHUB_APP_ID=<App ID> LANTERN_GITHUB_APP_SLUG=<short-name> -a lantern-cloud
$k = (Get-Content (Get-ChildItem "$HOME\Downloads\*.private-key.pem" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName -Raw) -replace "`r?`n", "\n"
fly secrets set LANTERN_GITHUB_APP_KEY="$k" -a lantern-cloud
Remove-Variable k
```

Then delete the `.pem` from Downloads (keep a copy in your password manager if you like; GitHub can make a new one
any time). All three settings are needed; with any missing, Connect GitHub stays off.

| Setting | Meaning |
|---|---|
| `LANTERN_GITHUB_APP_ID` | The app's number |
| `LANTERN_GITHUB_APP_SLUG` | Its short name (the install page is `https://github.com/apps/<slug>/installations/new`) |
| `LANTERN_GITHUB_APP_KEY` | Its private key, the `.pem` text (line breaks may be written as `\n`); a Fly secret |

### Free hosting options (checked 2026-11-03)

The cloud service needs: a Docker container with about 1 GB of memory, a disk that survives restarts (the run list
and results), and, for the safety wall around the analysis, a Linux kernel with Landlock (any recent one). What the
free offers give, from the providers' pages and a dated comparison (snapdeploy.dev "state of free hosting",
2026-09-28; InfoQ on Oracle, 2026-07):

| Host | Free? | Fits? | The catch |
|---|---|---|---|
| **Fly.io, sleeping** (the setup above) | No free tier for new accounts, but a sleeping app costs cents; bills under $5 have been waived in practice | Yes: same account as the gateway, disk, Landlock | Not a written guarantee of $0 |
| **Oracle Cloud Always Free** | Yes: 2 Arm cores and 12 GB of memory (halved in June 2026), plus disk | Yes, a real server | Card and phone to sign up; free-tier servers idle for 7 days can be reclaimed; popular regions often have no free capacity; you look after the server yourself (updates, HTTPS) |
| Render free web service | Yes | No | 512 MB, sleeps after 15 minutes, no disk that survives a restart, so results vanish |
| Koyeb free | Yes (card hold) | No | 512 MB, no volumes on the free plan |
| Hugging Face Spaces | Docker Spaces need the $9/month plan | No | |
| Railway | Trial credit, then 0.5 GB per service | No | Stops when the credit runs out |
| Your own laptop with a free tunnel | Yes | Not safe | Strangers' repositories would be read on your personal computer, and it only works while the laptop is on |

The Docker image runs the same on any of them; only the steps in this file are Fly-specific.

## Releases (GitHub now, PyPI later)

A pushed tag `v*` runs `.github/workflows/release.yml`: it builds the sdist and wheel, runs the tests against the
built wheel in a clean venv, checks `https://lantern-gateway.fly.dev/v1/health`, and creates a GitHub Release with
both files and the matching `CHANGELOG.md` section. Testers install with
`pip install "git+https://github.com/LittleHenderson/Lantern@v0.10.0"`.

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
