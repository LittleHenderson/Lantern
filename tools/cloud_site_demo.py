"""Run the cloud website locally with sample runs, for screenshots and the browser smoke (tools/cloud_site_smoke.js).

    python tools/cloud_site_demo.py --port 8872 --token-file /tmp/tok [--poison]

The gateway runs in the same process (sign-in switched on with dummy GitHub/Google apps, so the sign-in sheet shows
its buttons), and one account is signed in; its token is written to --token-file for the browser's cookie. Runs are
put straight into the database (no worker, no cloning): one finished run analysed from tests/fixtures/shop, one still
going, one that failed. With --poison every text the website shows from a run (link, error, stage, log, and the
summary read from result files) carries an HTML payload that must stay text.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "gateway"), str(ROOT / "cloud"), str(ROOT / "tools")]

import httpx  # noqa: E402
import uvicorn  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_cloud.store import now  # noqa: E402
from lantern_cloud.worker import STAGES, _summary  # noqa: E402
from lantern_gateway.app import Settings as GwSettings  # noqa: E402
from lantern_gateway.app import create_app as create_gateway  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8872)
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--poison", action="store_true")
    a = ap.parse_args()
    from poison_report import PAYLOAD
    bad = PAYLOAD if a.poison else ""

    base = Path(tempfile.mkdtemp(prefix="lantern-site-demo-"))
    gw = create_gateway(GwSettings(admin_secret="d" * 24, db_path=str(base / "gw.db"), github_client_id="demo",
                                   github_client_secret="demo", google_client_id="demo", google_client_secret="demo"))
    token = gw.state.store.sign_in("github:1", "github:octo")
    s = Settings(gateway_url="http://gateway.test/v1", public_url=f"http://127.0.0.1:{a.port}", admin_secret="d" * 24,
                 db_path=str(base / "cloud.db"), results_dir=str(base / "results"), work_dir=str(base / "work"),
                 audits=False)
    app = create_app(s, transport=httpx.ASGITransport(app=gw), start_worker=False)
    store = app.state.store

    def add(rid, link, status, **f):
        with store.lock:
            store.db.execute("insert into runs (id, account, link, host, privacy, status, stage, created) values "
                             "(?, 'github:1', ?, ?, 'structure', ?, ?, ?)", (rid, link, "github.com", status, f.pop("stage", ""), now()))
            store.db.commit()
        store.update_run(rid, **f)

    out = Path(s.results_dir) / "done1"
    subprocess.run([sys.executable, "-m", "lantern.cli", "analyze", str(ROOT / "tests" / "fixtures" / "shop"), "--out", str(out),
                    "--offline", "--privacy", "structure"], check=True, capture_output=True, text=True, encoding="utf-8",
                   env={**os.environ, "LANTERN_OFFLINE": "1"})
    summary = _summary(out)
    if a.poison:   # what a planted result file could hold, if the worker did not clean it
        summary = {"score": bad, "grade": bad, "shape": bad, "counts": {"critical": bad, "high": 1}, "files": bad}
    add("done1", "https://github.com/octo/shop" + (f"/tree/{bad}" if bad else ""), "done", started=now(), finished=now(),
        stage="finished", summary=summary, commit_sha="9cc6c88" + bad, log_tail="done" + bad)
    add("going1", "https://gitlab.com/maya/notes-api", "running", started=now(), stage=STAGES["analyze"] + bad,
        log_tail="· " + STAGES["clone"] + "\n· " + STAGES["analyze"] + "\nreading 12 files" + bad)
    add("failed1", "https://codeberg.org/sam/blog", "error", started=now(), finished=now(), stage="finished",
        error="could not clone it: not found" + bad, log_tail="could not clone" + bad)
    Path(a.token_file).write_text(token, encoding="utf-8")
    print(json.dumps({"ready": f"http://127.0.0.1:{a.port}/", "work": str(base)}), flush=True)
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
