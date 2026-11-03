# Lantern cloud service

Cloud mode: a person signs in on the website, pastes a repository link, and gets their own Lantern report in the
browser, with nothing installed. The same engine as the CLI, run on Lantern's server. Plan, scope and milestones:
[`../docs/cloud-mode-brief.md`](../docs/cloud-mode-brief.md). Routes: [`../docs/api.md`](../docs/api.md),
"Cloud service". Deploying: [`../docs/deploy.md`](../docs/deploy.md), "Cloud service on Fly.io".

Built so far (milestone 1): settings, the SQLite store, sign-in reused from the gateway (`GET /v1/whoami`),
`/v1/health`, `/v1/me`, `/v1/admin/stats`, the Docker image and `fly.toml`. Milestone 2: runs from a link
(`POST /v1/repos`, `GET /v1/runs…` with a live log stream) and the worker (`worker.py`) that clones, audits and
analyses in the restricted process, keeps the result files and deletes the clone. Milestone 3: the owner opens
the finished report, evidence, badge and data in a browser through a short-lived signed link (`/v1/runs/{id}/view`,
`/r/{id}/…`), every page rebuilt from Lantern's templates. Milestone 4: the website at `/`, built from the Lantern app's own page
(`site.py` reads its stylesheet, typefaces, brand mark, icons and backdrop from `lantern/viewer/app.html`), so the
two look and behave alike: sign in with GitHub or Google, paste a link, choose what is kept, watch the run, open the
report, all runs in "My runs". Installable like the app. Milestone 5: Share (off until the person clicks it; a
random `/s/<slug>/` link, read-only, that dies for good on "Stop sharing"), deleting a run, and deleting your account
(everything the cloud keeps about you). Optional retention sweep (`LANTERN_CLOUD_RETENTION_DAYS`).

## Run locally

```bash
pip install -e ".[scan,dev]" -e cloud/          # the engine and this service
LANTERN_GATEWAY_URL=http://127.0.0.1:8080/v1 uvicorn lantern_cloud.app:create_app --factory --port 8090
python -m pytest -q tests/test_cloud.py tests/test_cloud_runs.py tests/test_cloud_view.py tests/test_cloud_site.py
python tools/cloud_site_demo.py --port 8872 --token-file /tmp/tok   # the website with sample runs, signed-in token in /tmp/tok
```

## Rules this service keeps

* The analysed code is never executed: no builds, installs, test runs or runtime tracing.
* The clone is deleted when the job ends, success or failure; only derived results are kept, at the privacy level
  the person chose before the run (`structure` by default).
* No tokens (not even hashes), emails, request bodies or repository files in the database or the logs.
* A run is readable by its owner only until the owner clicks Share; a share link can be revoked.
* No model key lives here. Explanations (v1.5) go through the gateway with the person's own allowance.
