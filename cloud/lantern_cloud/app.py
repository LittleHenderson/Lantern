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

import hmac
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from . import __version__
from .identity import GatewayUnavailable, Identity
from .idle import IdleExit
from .settings import Settings
from .store import Store


def _engine_version() -> str | None:
    try:
        import lantern
        return lantern.__version__
    except ImportError:
        return None


def create_app(settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    s = settings or Settings()
    Path(s.results_dir).mkdir(parents=True, exist_ok=True)
    store = Store(s.db_path)
    ident = Identity(s.gateway_url, s.identity_ttl, transport=transport)
    app = FastAPI(title="Lantern cloud", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.settings, app.state.identity = store, s, ident
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

    @app.get("/v1/admin/stats")
    def admin_stats(authorization: str | None = Header(default=None)):
        admin(authorization)
        return store.stats()

    return app
