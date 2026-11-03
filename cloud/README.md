# Lantern cloud service

Cloud mode: a person signs in on the website, pastes a repository link, and gets their own Lantern report in the
browser, with nothing installed. The same engine as the CLI, run on Lantern's server. Plan, scope and milestones:
[`../docs/cloud-mode-brief.md`](../docs/cloud-mode-brief.md). Routes: [`../docs/api.md`](../docs/api.md),
"Cloud service". Deploying: [`../docs/deploy.md`](../docs/deploy.md), "Cloud service on Fly.io".

Built so far (milestone 1): settings, the SQLite store, sign-in reused from the gateway (`GET /v1/whoami`),
`/v1/health`, `/v1/me`, `/v1/admin/stats`, the Docker image and `fly.toml`. Milestone 2: runs from a link
(`POST /v1/repos`, `GET /v1/runs…` with a live log stream) and the worker (`worker.py`) that clones, audits and
analyses in the restricted process, keeps the result files and deletes the clone.

## Run locally

```bash
pip install -e ".[scan,dev]" -e cloud/          # the engine and this service
LANTERN_GATEWAY_URL=http://127.0.0.1:8080/v1 uvicorn lantern_cloud.app:create_app --factory --port 8090
python -m pytest -q tests/test_cloud.py tests/test_cloud_runs.py
```

## Rules this service keeps

* The analysed code is never executed: no builds, installs, test runs or runtime tracing.
* The clone is deleted when the job ends, success or failure; only derived results are kept, at the privacy level
  the person chose before the run (`structure` by default).
* No tokens (not even hashes), emails, request bodies or repository files in the database or the logs.
* A run is readable by its owner only until the owner clicks Share; a share link can be revoked.
* No model key lives here. Explanations (v1.5) go through the gateway with the person's own allowance.
