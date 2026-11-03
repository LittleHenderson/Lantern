"""Lantern cloud service (milestone 1 of docs/cloud-mode-brief.md): settings, store, sign-in, health.

Later milestones add the job queue and worker (POST /v1/repos, GET /v1/runs/...), result pages (/r/<id>/...),
the website flow, share links and deletion. The rules that hold from the first line:
  * the analysed code is never executed: no builds, installs or test runs, no runtime tracing;
  * the clone is deleted when the job ends; only derived results are kept, at the privacy level chosen first;
  * no tokens, emails, request bodies or repository contents in the database or the logs;
  * a run is readable by its owner only, until the owner clicks Share (off by default).

Run:  LANTERN_ADMIN_SECRET=... uvicorn lantern_cloud.app:create_app --factory --port 8080
"""

from __future__ import annotations

import asyncio
import hmac
import json
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from . import __version__
from .identity import GatewayUnavailable, Identity
from .idle import IdleExit
from .settings import Settings
from .store import FINISHED, LimitReached, Store
from .worker import Worker

PRIVACY = {"structure", "full"}
FULL_NOTICE = ("Short source snippets of your code will be stored on Lantern's server so the report can show them. "
               "Send stored_snippets_ok: true to agree, or choose privacy \"structure\" (no code kept).")


def _engine_version() -> str | None:
    try:
        import lantern
        return lantern.__version__
    except ImportError:
        return None


def _host_of(link: str, allowed: list[str] | None) -> str:
    """The link's host, after `lantern.remote.parse` (https only, known forges, no credentials). ValueError with a
    plain sentence otherwise."""
    from lantern import remote
    if not isinstance(link, str) or not link.strip() or len(link) > 500:
        raise ValueError("Paste the https link of a public repository, such as https://github.com/owner/name.")
    try:
        info = remote.parse(link.strip())
    except (ValueError, RuntimeError) as e:
        raise ValueError(str(e)) from None
    host = info["host"].lower().removeprefix("www.")
    if allowed is not None and host not in allowed:
        raise ValueError("Cloud mode accepts links from " + ", ".join(allowed) + " for now.")
    return host


def run_view(r: dict, logs=None) -> dict:
    """What the owner sees about a run. Never the account id."""
    tail = (logs.tail(r["id"]) if logs and r["status"] not in FINISHED else None) or r.get("log_tail") or ""
    return {"id": r["id"], "link": r["link"], "host": r["host"], "privacy": r["privacy"], "status": r["status"],
            "stage": r["stage"], "error": r["error"], "created": r["created"], "started": r["started"],
            "finished": r["finished"], "commit": r["commit_sha"], "summary": r["summary"],
            "shared": bool(r["share_slug"]), "log_tail": tail}


def create_app(settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None,
               start_worker: bool = True) -> FastAPI:
    s = settings or Settings()
    Path(s.results_dir).mkdir(parents=True, exist_ok=True)
    store = Store(s.db_path)
    ident = Identity(s.gateway_url, s.identity_ttl, transport=transport)
    worker = Worker(s, store) if start_worker else None
    app = FastAPI(title="Lantern cloud", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.settings, app.state.identity, app.state.worker = store, s, ident, worker
    idle = IdleExit(s.idle_minutes, busy=lambda: store.active_runs() > 0)
    app.state.idle = idle
    idle.start()

    @app.middleware("http")
    async def _seen(request: Request, call_next):
        idle.touch()
        return await call_next(request)

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException):
        kind = {401: "signed_out", 403: "forbidden", 404: "not_found", 429: "limit", 503: "unavailable"}.get(
            exc.status_code, "error")
        return JSONResponse({"error": {"type": kind, "message": str(exc.detail)}}, status_code=exc.status_code)

    async def signed_in(authorization: str | None) -> dict:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "Sign in first.")
        try:
            who = await ident.whoami(authorization[7:].strip())
        except GatewayUnavailable:
            raise HTTPException(503, "Lantern can't check your sign-in right now. Try again in a minute.") from None
        if who is None:
            raise HTTPException(401, "That sign-in has expired or was replaced. Sign in again.")
        store.touch_user(who["account"], who["label"])
        return who

    def admin(authorization: str | None) -> None:
        if not s.admin_secret or not authorization or not hmac.compare_digest(
                authorization.removeprefix("Bearer ").strip(), s.admin_secret):
            raise HTTPException(403, "admin only")

    @app.get("/v1/health")
    def health():
        # Public: versions and limits only, never counters, accounts or links.
        return {"ok": True, "service": "lantern-cloud", "version": __version__, "engine": _engine_version(),
                "limits": s.limits(), "hosts": s.hosts() or "all"}

    @app.get("/v1/me")
    async def me(authorization: str | None = Header(default=None)):
        who = await signed_in(authorization)
        acc = who["account"]
        return {"account": acc.split(":", 1)[0], "label": who["label"],
                "runs_today": store.runs_today(acc), "runs_active": store.active_runs(acc),
                "limits": s.limits()}

    # ---- runs ----
    def own_run(rid: str, who: dict) -> dict:
        r = store.run(rid) if isinstance(rid, str) and len(rid) <= 40 else None
        if not r or not hmac.compare_digest(r["account"], who["account"]):
            raise HTTPException(404, "No run with that id in your account.")   # same answer for someone else's run
        return r

    @app.post("/v1/repos", status_code=202)
    async def start_run(payload: dict, authorization: str | None = Header(default=None)):
        who = await signed_in(authorization)
        if worker is None:
            raise HTTPException(503, "Runs are paused on this server.")
        privacy = payload.get("privacy") or s.default_privacy
        if privacy not in PRIVACY:
            raise HTTPException(400, 'privacy is "structure" (no code kept) or "full" (short snippets kept).')
        if privacy == "full" and payload.get("stored_snippets_ok") is not True:
            raise HTTPException(400, FULL_NOTICE)
        try:
            host = _host_of(payload.get("link"), s.hosts())
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        try:
            rid = store.create_run(who["account"], payload["link"].strip(), host, privacy, per_day=s.runs_per_day,
                                   global_per_day=s.global_runs_per_day, per_user_active=s.per_user_active)
        except LimitReached as e:
            raise HTTPException(429, str(e)) from None
        worker.submit(rid)
        return run_view(store.run(rid))

    @app.get("/v1/runs")
    async def list_runs(authorization: str | None = Header(default=None)):
        who = await signed_in(authorization)
        return {"runs": [run_view(r) for r in store.runs(who["account"])]}

    @app.get("/v1/runs/{rid}")
    async def get_run(rid: str, authorization: str | None = Header(default=None)):
        who = await signed_in(authorization)
        return run_view(own_run(rid, who), worker.logs if worker else None)

    @app.get("/v1/runs/{rid}/stream")
    async def stream_run(rid: str, authorization: str | None = Header(default=None)):
        """Server-sent events: `log` events (one line each), then one `end` event with the run, then the stream
        closes. A finished run sends its saved tail and `end` at once."""
        who = await signed_in(authorization)
        own_run(rid, who)

        async def events():
            n = 0
            while True:
                r = store.run(rid)
                if r is None:
                    return
                if r["status"] in FINISHED:
                    lines = (r.get("log_tail") or "").splitlines() if n == 0 else []
                    lines += worker.logs.since(rid, n)[0] if worker and n else []
                    for ln in lines:
                        yield "event: log\ndata: " + json.dumps(ln) + "\n\n"
                    yield "event: end\ndata: " + json.dumps(run_view(r)) + "\n\n"
                    return
                lines, n = worker.logs.since(rid, n) if worker else ([], n)
                for ln in lines:
                    yield "event: log\ndata: " + json.dumps(ln) + "\n\n"
                await asyncio.sleep(0.4)
        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"cache-control": "no-store", "x-accel-buffering": "no"})

    @app.get("/v1/admin/stats")
    def admin_stats(authorization: str | None = Header(default=None)):
        admin(authorization)
        return store.stats()

    return app
