"""Lantern cloud service (docs/cloud-mode-brief.md): the website, sign-in, runs from a link, results in the browser,
sharing and deleting, and plain-words explanations and Ask Lantern through the person's free allowance.

The rules that hold from the first line:
  * the analysed code is never executed: no builds, installs or test runs, no runtime tracing;
  * the clone is deleted when the job ends; only derived results are kept, at the privacy level chosen first;
  * no tokens, emails, request bodies or repository contents in the database or the logs;
  * a run is readable by its owner only, until the owner clicks Share (off by default) or puts it in a team
    workspace, where the workspace's members can read it too (and only they: never changed, shared or deleted by them);
  * nothing goes to a model until the person has read where it goes and agreed (`/v1/ai/consent`), and then only
    with their own allowance token: facts from tools, words from models, and the model never changes a finding.

Run:  LANTERN_ADMIN_SECRET=... uvicorn lantern_cloud.app:create_app --factory --port 8080
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from lantern import learn, scope

from . import __version__
from .identity import GatewayUnavailable, Identity
from .idle import IdleExit
from .settings import Settings
from . import site
from .store import FINISHED, LimitReached, Store
from .worker import ACTIVE_EXPLAIN, HINTS, SAMPLE_PREFIX, STAGES, UPLOAD_EXPLAIN, UPLOAD_PREFIX, Worker, backfill_lanes, is_upload

log = logging.getLogger("lantern_cloud")
PRIVACY = {"structure", "full"}
SESSION_COOKIE = "lt"          # the gateway token, HttpOnly: the website's script never reads it
SIGNIN_COOKIE = "lsi"          # the one-time code a sign-in in progress is parked under, for this browser only
SESSION_DAYS = 30
# What /r/{id}/<name> serves, and the result file behind each. Every page is rebuilt from our templates
# (`lantern.server.result_page`); nothing in the run's folder is sent as a page.
VIEWABLE = {"report.html": "report.html", "evidence.html": "evidence.html", "badge.svg": "badge.svg",
            "findings.json": "security.json", "graph.json": "graph.json", "readiness.json": "readiness.json"}
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


def _sample(sid) -> dict:
    """A shipped starter app by id; ValueError with a plain sentence otherwise."""
    try:
        return learn.get(sid)
    except (ValueError, TypeError):
        raise ValueError("Choose one of the sample apps on the home page.") from None


def _note_page(title: str, text: str) -> str:
    """A small page in the app's colours for a link that no longer works (no script, inline style only)."""
    return ("<!doctype html><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{title} · Lantern</title><body style=\"margin:0;min-height:100vh;display:grid;place-items:center;"
            "background:#F5F5F2;color:#46464C;font:15px/1.55 -apple-system,'Segoe UI',Roboto,sans-serif;padding:24px\">"
            "<div style=\"max-width:420px;text-align:center\"><div style=\"font:700 22px -apple-system,'Segoe UI',sans-serif;"
            f"color:#161618;margin-bottom:8px;letter-spacing:-.02em\">{title}</div>{text}</div>")


SHARE_GONE = _note_page("This link is off", "Its owner stopped sharing this report, or deleted it. "
                        "<a href=\"/\" style=\"color:#0B5F5A\">Check your own app with Lantern</a>.")
SHAREABLE = {"report.html", "evidence.html", "badge.svg"}     # a shared run shows its pages, not its raw data files


def remove_results(results_dir: str, rid: str) -> None:
    import shutil
    if rid and "/" not in rid and "\\" not in rid and rid not in (".", ".."):
        shutil.rmtree(Path(results_dir) / rid, ignore_errors=True)


def sweep(store, results_dir: str, days: int) -> list[str]:
    """Delete finished runs older than `days` and their results (0 = keep until the person deletes them)."""
    gone = store.expired(days)
    for rid in gone:
        store.delete_run(rid)
        remove_results(results_dir, rid)
    return gone


EXPIRED_PAGE = _note_page("This link has expired", "Report links work for an hour. Open the run again from "
                          "<a href=\"/\" style=\"color:#0B5F5A\">My runs</a>.")


def _page_headers(extra: dict | None) -> dict:
    """Every result response: never cached, never sniffed, no referrer (the link carries its key)."""
    h = {"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
         "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"}
    h.update(extra or {})
    return h


# A big project's report is one page with all its data inside (noetic-compass: 54,909,481 bytes). Sent as it is, the
# browser waits for every byte before it can draw anything, and the run page looks stuck. The page is text and
# shrinks about 17 times (to 3,247,600 bytes), so result pages are sent gzip-compressed to any browser that asks.
# Each request still builds the page from our template with its own nonce; at most RENDERS are built at once so
# reloading a slow page does not stack builds of half a gigabyte each until the machine runs out of memory.
COMPRESS_FROM = 1024
RENDERS = threading.BoundedSemaphore(2)


def result_response(out: Path, name: str, request: Request, extra: dict | None = None, lanes=None) -> Response:
    """A result page or file rebuilt by `lantern.server.result_page`, compressed when the browser accepts gzip.
    `lanes` limits the map to a team member's layers (see `scope.py`)."""
    from lantern.server import result_page
    with RENDERS:
        code, body, ctype, headers = result_page(out, name, None, lanes)
        data = body.encode("utf-8") if isinstance(body, str) else body
        headers = {**headers, **(extra or {}), "Vary": "Accept-Encoding"}
        if len(data) >= COMPRESS_FROM and "gzip" in (request.headers.get("accept-encoding") or "").lower():
            data = gzip.compress(data, compresslevel=6)
            headers["Content-Encoding"] = "gzip"
    return Response(data, code, media_type=ctype, headers=_page_headers(headers))


def run_view(r: dict, logs=None) -> dict:
    """What the owner (or a member of the run's workspace) sees about a run. Never the account id."""
    tail = (logs.tail(r["id"]) if logs and r["status"] not in FINISHED else None) or r.get("log_tail") or ""
    return {"id": r["id"], "link": r["link"], "host": r["host"], "privacy": r["privacy"], "status": r["status"],
            "stage": r["stage"], "error": r["error"], "created": r["created"], "started": r["started"],
            "finished": r["finished"], "commit": r["commit_sha"], "summary": r["summary"],
            "shared": bool(r["share_slug"]), "log_tail": tail, "workspace": r.get("workspace"),
            "hint": HINTS.get(r["error"]),   # "upload" / "connect": what the website offers in place of the link
            "step": next((k for k, v in STAGES.items() if v == r["stage"]), None),
            "explain": {"status": r.get("explain_status"), "error": r.get("explain_error"),
                        "summary": r.get("explain_summary"),
                        "log": logs.tail("x:" + r["id"], 12) if logs and r.get("explain_status") in ACTIVE_EXPLAIN else ""}}


def hosted(token: str, gateway_url: str):
    """The person's free allowance at the gateway (Claude Haiku, DeepSeek if Anthropic is down)."""
    from lantern.providers import LanternHostedProvider
    return LanternHostedProvider(token, gateway_url.rstrip("/"))


def create_app(settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None,
               start_worker: bool = True, provider_for=None) -> FastAPI:
    s = settings or Settings()
    Path(s.results_dir).mkdir(parents=True, exist_ok=True)
    store = Store(s.db_path)
    ident = Identity(s.gateway_url, s.identity_ttl, transport=transport)
    worker = Worker(s, store) if start_worker else None
    gh = s.github_app()     # Connect GitHub (private repositories), or None
    app = FastAPI(title="Lantern cloud", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.settings, app.state.identity, app.state.worker = store, s, ident, worker
    provider_for = provider_for or (lambda token: hosted(token, s.gateway_url))
    idle = IdleExit(s.idle_minutes, busy=lambda: store.busy() > 0)
    app.state.idle = idle
    idle.start()
    if s.retention_days > 0:
        def _retention():
            while True:
                try:
                    sweep(store, s.results_dir, s.retention_days)
                except Exception:  # noqa: BLE001: the next pass tries again
                    pass
                time.sleep(3600)
        threading.Thread(target=_retention, name="lantern-retention", daemon=True).start()

    @app.middleware("http")
    async def _seen(request: Request, call_next):
        idle.touch()
        return await call_next(request)

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException):
        kind = {401: "signed_out", 402: "allowance", 403: "forbidden", 404: "not_found", 412: "consent_needed",
                429: "limit", 503: "unavailable"}.get(exc.status_code, "error")
        return JSONResponse({"error": {"type": kind, "message": str(exc.detail)}}, status_code=exc.status_code)

    async def signed_in(request: Request) -> dict:
        """The account behind the request: a gateway token as `Authorization: Bearer` (apps, scripts), or the
        website's HttpOnly `lt` cookie. A cookie only counts for a change (anything but GET) when the request also
        carries `X-Lantern-Site`, a header another site's page cannot send here (no CORS is offered), so a link or
        form elsewhere can never start a run or sign someone out."""
        authorization = request.headers.get("authorization") or ""
        if authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        else:
            token = request.cookies.get(SESSION_COOKIE) or ""
            if token and request.method != "GET" and request.headers.get("x-lantern-site") != "1":
                raise HTTPException(403, "This request did not come from Lantern's own page.")
        if not token:
            raise HTTPException(401, "Sign in first.")
        try:
            who = await ident.whoami(token)
        except GatewayUnavailable:
            raise HTTPException(503, "Lantern can't check your sign-in right now. Try again in a minute.") from None
        if who is None:
            raise HTTPException(401, "That sign-in has expired or was replaced. Sign in again.")
        store.touch_user(who["account"], who["label"])
        request.state.token = token      # for the person's own allowance; never stored or logged
        return who

    def admin(authorization: str | None) -> None:
        if not s.admin_secret or not authorization or not hmac.compare_digest(
                authorization.removeprefix("Bearer ").strip(), s.admin_secret):
            raise HTTPException(403, "admin only")

    @app.get("/v1/samples")
    def samples():
        # Public: Lantern's built-in starter apps, which a signed-in person can check with one click.
        return {"samples": [{k: c.get(k) for k in ("id", "title", "stack", "level", "summary")} for c in learn.catalog()]}

    @app.get("/v1/health")
    def health():
        # Public: versions and limits only, never counters, accounts or links.
        return {"ok": True, "service": "lantern-cloud", "version": __version__, "engine": _engine_version(),
                "limits": s.limits(), "hosts": s.hosts() or "all"}

    @app.get("/v1/me")
    async def me(request: Request):
        who = await signed_in(request)
        acc = who["account"]
        return {"account": acc.split(":", 1)[0], "label": who["label"],
                "runs_today": store.runs_today(acc), "runs_active": store.active_runs(acc),
                "limits": s.limits(), "connect_url": gh.install_url if gh else None}

    # ---- runs ----
    def own_run(rid: str, who: dict) -> dict:
        r = store.run(rid) if isinstance(rid, str) and len(rid) <= 40 else None
        if not r or not hmac.compare_digest(r["account"], who["account"]):
            raise HTTPException(404, "No run with that id in your account.")   # same answer for someone else's run
        return r

    def readable_run(rid: str, who: dict) -> dict:
        """The owner's run, or one in a workspace this person is in: they may read it, never change it. `lanes` on
        the result is the scope code of the layers they may see ("all" for the run's owner and full members)."""
        r = store.run(rid) if isinstance(rid, str) and len(rid) <= 40 else None
        if r and hmac.compare_digest(r["account"], who["account"]):
            return {**r, "lanes": "all"}
        if r and r.get("workspace") and store.role(r["workspace"], who["account"]):
            return {**r, "lanes": store.member_lanes(r["workspace"], who["account"]) or "all"}
        raise HTTPException(404, "No run with that id in your account.")

    def seen(v: dict, lanes: str) -> dict:
        """A run's view for someone who may see only some layers: the score and counts and the log describe the
        whole app, so they are left out. The scoped report is the one place they read results."""
        if lanes == "all":
            return v
        return {**v, "summary": None, "log_tail": "", "explain": {**v["explain"], "summary": None, "log": ""},
                "lanes": list(scope.decode(lanes) or ())}

    @app.post("/v1/repos", status_code=202)
    async def start_run(payload: dict, request: Request):
        who = await signed_in(request)
        if worker is None:
            raise HTTPException(503, "Runs are paused on this server.")
        privacy = payload.get("privacy") or s.default_privacy
        if privacy not in PRIVACY:
            raise HTTPException(400, 'privacy is "structure" (no code kept) or "full" (short snippets kept).')
        if privacy == "full" and payload.get("stored_snippets_ok") is not True:
            raise HTTPException(400, FULL_NOTICE)
        try:
            if payload.get("sample") is not None:      # one of Lantern's own starter apps, for people with no repo
                link, host = SAMPLE_PREFIX + _sample(payload["sample"])["id"], "sample"
            else:
                host, link = _host_of(payload.get("link"), s.hosts()), payload["link"].strip()
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        try:
            rid = store.create_run(who["account"], link, host, privacy, per_day=s.runs_per_day,
                                   global_per_day=s.global_runs_per_day, per_user_active=s.per_user_active)
        except LimitReached as e:
            raise HTTPException(429, str(e)) from None
        worker.submit(rid)
        return run_view(store.run(rid))

    @app.post("/v1/uploads", status_code=202)
    async def upload_run(request: Request, name: str = "app", privacy: str | None = None, snippets_ok: str = "0"):
        """Check an app uploaded from the person's computer: the request body is a .zip (at most the clone size cap).
        It waits in the uploads folder until its run starts, is then moved into the run's temp folder and unpacked
        by `lantern.archive` inside the restricted process, and is gone when the run ends, like a clone."""
        who = await signed_in(request)
        if worker is None:
            raise HTTPException(503, "Runs are paused on this server.")
        privacy = privacy or s.default_privacy
        if privacy not in PRIVACY:
            raise HTTPException(400, 'privacy is "structure" (no code kept) or "full" (short snippets kept).')
        if privacy == "full" and snippets_ok != "1":
            raise HTTPException(400, FULL_NOTICE)
        label = "".join(ch for ch in str(name) if ch.isalnum() or ch in "._-")[:80].strip(".") or "app"
        cap = s.clone_max_mb << 20
        too_big = f"The upload is larger than {s.clone_max_mb} MB. Leave out folders like node_modules, .git and build output."
        try:
            if int(request.headers.get("content-length") or 0) > cap:
                raise HTTPException(413, too_big)
        except ValueError:
            raise HTTPException(400, "The upload had a bad size.") from None
        up = Path(s.uploads())
        up.mkdir(parents=True, exist_ok=True)
        part = up / f".part-{secrets.token_hex(8)}"
        size, head = 0, b""
        try:
            with open(part, "wb") as f:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > cap:
                        raise HTTPException(413, too_big)
                    if len(head) < 4:
                        head += chunk[:4]
                    f.write(chunk)
            if size == 0 or not head.startswith(b"PK"):
                raise HTTPException(400, "That is not a .zip file. Choose your app's folder, or a .zip of it.")
            try:
                rid = store.create_run(who["account"], UPLOAD_PREFIX + label, "upload", privacy, per_day=s.runs_per_day,
                                       global_per_day=s.global_runs_per_day, per_user_active=s.per_user_active)
            except LimitReached as e:
                raise HTTPException(429, str(e)) from None
            part.replace(worker.upload_path(rid))
        finally:
            part.unlink(missing_ok=True)
        worker.submit(rid)
        return run_view(store.run(rid))

    @app.get("/v1/runs")
    async def list_runs(request: Request):
        who = await signed_in(request)
        rows = store.runs(who["account"])
        for r in rows:   # runs from before the list showed stack parts: read them from the stored results, once
            if r["status"] == "done":
                filled = backfill_lanes(Path(s.results_dir), r["id"], r["summary"])
                if filled:
                    store.update_run(r["id"], summary=filled)
                    r["summary"] = filled
        return {"runs": [run_view(r) for r in rows]}

    @app.get("/v1/runs/{rid}")
    async def get_run(rid: str, request: Request):
        who = await signed_in(request)
        r = readable_run(rid, who)
        v = seen(run_view(r, worker.logs if worker else None), r["lanes"])
        return {**v, "mine": r["account"] == who["account"]}

    @app.get("/v1/runs/{rid}/stream")
    async def stream_run(rid: str, request: Request):
        """Server-sent events: `log` events (one line each), then one `end` event with the run, then the stream
        closes. A finished run sends its saved tail and `end` at once."""
        who = await signed_in(request)
        lanes = readable_run(rid, who)["lanes"]
        quiet = lanes != "all"    # the log describes the whole app

        async def events():
            n = 0
            while True:
                r = store.run(rid)
                if r is None:
                    return
                if r["status"] in FINISHED:
                    lines = (r.get("log_tail") or "").splitlines() if n == 0 else []
                    lines += worker.logs.since(rid, n)[0] if worker and n else []
                    for ln in [] if quiet else lines:
                        yield "event: log\ndata: " + json.dumps(ln) + "\n\n"
                    yield "event: end\ndata: " + json.dumps(seen(run_view(r), lanes)) + "\n\n"
                    return
                lines, n = worker.logs.since(rid, n) if worker else ([], n)
                for ln in [] if quiet else lines:
                    yield "event: log\ndata: " + json.dumps(ln) + "\n\n"
                await asyncio.sleep(0.4)
        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"cache-control": "no-store", "x-accel-buffering": "no"})

    # ---- results in the browser (owner only, through a short-lived signed link) ----
    vsecret = (s.view_secret or (hashlib.sha256(("view:" + s.admin_secret).encode()).hexdigest() if s.admin_secret
                                 else secrets.token_hex(32))).encode()

    def view_key(rid: str, exp: int, lanes: str = "all") -> str:
        """`exp.sig` for the whole report; `exp.lanes.sig` for a member who may see only some layers, so the
        link itself says which layers it opens and can't be edited to open more."""
        if lanes == "all":
            return f"{exp}.{hmac.new(vsecret, f'{rid}:{exp}'.encode(), hashlib.sha256).hexdigest()[:32]}"
        return f"{exp}.{lanes}.{hmac.new(vsecret, f'{rid}:{exp}:{lanes}'.encode(), hashlib.sha256).hexdigest()[:32]}"

    def key_lanes(rid: str, k: str | None) -> str | None:
        """The layers a view link opens ("all", or a scope code), or None when it is wrong or has expired."""
        parts = (k or "").split(".")
        try:
            exp, lanes = int(parts[0]), (parts[1] if len(parts) == 3 else "all")
            if scope.code(scope.decode(lanes)) != lanes:    # one spelling per set of layers
                return None
        except ValueError:
            return None
        if len(parts) not in (2, 3) or exp <= time.time():
            return None
        return lanes if hmac.compare_digest(view_key(rid, exp, lanes), k or "") else None

    @app.post("/v1/runs/{rid}/view")
    async def view_link(rid: str, request: Request):
        """Links that open this run's report, evidence and files in a browser for the next `view_minutes`. Anyone
        holding a link can open it until then, so the website opens it at once and never stores it."""
        who = await signed_in(request)
        r = readable_run(rid, who)
        if r["status"] != "done":
            raise HTTPException(409, "This run has no report yet.")
        exp = int(time.time()) + s.view_minutes * 60
        k = view_key(rid, exp, r["lanes"])
        base = f"{s.public_url}/r/{rid}/"
        return {"expires_in": s.view_minutes * 60,
                **{name.split(".")[0]: f"{base}{name}?k={k}" for name in VIEWABLE}}

    @app.get("/r/{rid}/{name}")
    def view(rid: str, name: str, request: Request, k: str | None = None):
        if name not in VIEWABLE or len(rid) > 40:
            raise HTTPException(404, "Not found.")
        cookie = request.cookies.get("lv")
        lanes = key_lanes(rid, k) or key_lanes(rid, cookie)
        if lanes is None:
            return Response(EXPIRED_PAGE, 401,
                            media_type="text/html; charset=utf-8", headers=_page_headers(None))
        r = store.run(rid)
        if not r or r["status"] != "done":
            raise HTTPException(404, "No report here.")
        resp = result_response(Path(s.results_dir) / rid, VIEWABLE[name], request, lanes=scope.decode(lanes))
        if k and key_lanes(rid, k) is not None:
            # the report links to evidence.html and badge.svg by relative path; the cookie lets those open too
            resp.set_cookie("lv", k, max_age=max(1, int(k.split(".", 1)[0]) - int(time.time())), path=f"/r/{rid}/",
                            secure=s.public_url.startswith("https://"), httponly=True, samesite="lax")
        return resp

    # ---- share (off until the owner turns it on), delete ----
    def done_run(rid: str, who: dict) -> dict:
        r = own_run(rid, who)
        if r["status"] != "done":
            raise HTTPException(409, "This run has no report yet.")
        return r

    def share_view(slug: str | None) -> dict:
        return {"shared": bool(slug), "url": f"{s.public_url}/s/{slug}/report.html" if slug else None}

    @app.get("/v1/runs/{rid}/share")
    async def share_state(rid: str, request: Request):
        who = await signed_in(request)
        return share_view(own_run(rid, who)["share_slug"])

    @app.post("/v1/runs/{rid}/share")
    async def share_on(rid: str, request: Request):
        """A public, read-only link to this run's report, evidence and badge. Anyone holding it can open them until
        the owner turns it off. The report shows what the run kept (privacy as chosen before the run)."""
        who = await signed_in(request)
        r = done_run(rid, who)
        return share_view(store.set_share(r["id"], True))

    @app.delete("/v1/runs/{rid}/share")
    async def share_off(rid: str, request: Request):
        who = await signed_in(request)
        store.set_share(own_run(rid, who)["id"], False)
        return share_view(None)

    @app.get("/s/{slug}/{name}")
    def shared(slug: str, name: str, request: Request):
        r = store.run_by_slug(slug)
        if name not in SHAREABLE or not r or r["status"] != "done":
            return Response(SHARE_GONE, 404, media_type="text/html; charset=utf-8",
                            headers=_page_headers({"X-Robots-Tag": "noindex"}))
        return result_response(Path(s.results_dir) / r["id"], VIEWABLE[name], request, {"X-Robots-Tag": "noindex"})

    @app.delete("/v1/runs/{rid}")
    async def delete_run(rid: str, request: Request):
        """Delete a run: its row, its result files and its share link. A run still going is refused (409)."""
        who = await signed_in(request)
        r = own_run(rid, who)
        if r["status"] not in FINISHED:
            raise HTTPException(409, "This check is still going. Delete it once it has finished.")
        if r.get("explain_status") in ACTIVE_EXPLAIN:
            raise HTTPException(409, "Lantern is still writing this check's explanations. Delete it once they are done.")
        store.delete_run(r["id"])
        remove_results(s.results_dir, r["id"])
        return {"deleted": r["id"]}

    @app.delete("/v1/me")
    async def delete_me(request: Request):
        """Forget the person here: every run, result file, share link and daily counter, and the sign-in cookie.
        Their sign-in at the gateway (and its free allowance) is separate and stays."""
        who = await signed_in(request)
        if store.busy(who["account"]):
            raise HTTPException(409, "A check is still going. Delete your account once it has finished.")
        ids = store.delete_user(who["account"])
        for rid in ids:
            remove_results(s.results_dir, rid)
        resp = JSONResponse({"deleted": True, "runs": len(ids)})
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    # ---- words from a model: explanations and Ask Lantern, through the person's own free allowance ----
    from lantern.providers import DATA_NOTICES

    AI_NOTICE = DATA_NOTICES["lantern"]

    def agreed(who: dict) -> None:
        if not store.consent(who["account"]):
            raise HTTPException(412, "Before Lantern sends anything to a model, read where it goes and agree. " + AI_NOTICE)

    @app.get("/v1/ai")
    async def ai_state(request: Request):
        """Whether the person has agreed, what they agree to, and what is left of their free allowance."""
        who = await signed_in(request)
        try:
            left = await ident.allowance(request.state.token)
        except GatewayUnavailable:
            left = None
        return {"consent": bool(store.consent(who["account"])), "notice": AI_NOTICE, "allowance": left}

    @app.post("/v1/ai/consent")
    async def ai_consent(payload: dict, request: Request):
        who = await signed_in(request)
        on = payload.get("agree")
        if not isinstance(on, bool):
            raise HTTPException(400, "agree is true or false.")
        store.set_consent(who["account"], on)
        return {"consent": on, "notice": AI_NOTICE}

    @app.post("/v1/runs/{rid}/explain", status_code=202)
    async def explain_run(rid: str, request: Request):
        """Write plain-words explanations for this finished run (entry points and three levels down, up to 40
        functions), with the person's allowance. The repository is copied again at the run's commit to read the code,
        and deleted afterwards; the report is rebuilt with the explanations, at the privacy chosen before the run."""
        who = await signed_in(request)
        if worker is None:
            raise HTTPException(503, "Explanations are paused on this server.")
        r = done_run(rid, who)
        if is_upload(r["link"]):
            raise HTTPException(409, UPLOAD_EXPLAIN)
        agreed(who)
        if not store.queue_explain(r["id"]):
            raise HTTPException(409, "Lantern is already writing this check's explanations.")
        worker.submit_explain(r["id"], request.state.token)
        return run_view(store.run(r["id"]), worker.logs)

    @app.post("/v1/ask")
    async def ask_lantern(payload: dict, request: Request):
        """Ask Lantern: the answer comes from the run's own results (or, with no run, from what Lantern is), in the
        model's words. Finding ids the model makes up are replaced with "[unknown finding]"."""
        who = await signed_in(request)
        agreed(who)
        q = payload.get("question")
        if not isinstance(q, str) or not q.strip():
            raise HTTPException(400, "Type a question.")
        out, name = None, None
        if payload.get("run") is not None:
            r = readable_run(str(payload["run"]), who)
            if r["lanes"] != "all":
                raise HTTPException(403, "Ask Lantern reads the whole app, and you can see only some of its layers here. "
                                         "Ask the workspace owner, or open the report.")
            if r["status"] != "done":
                raise HTTPException(409, "This run has no report yet.")
            out, name = Path(s.results_dir) / r["id"], r["link"].rstrip("/").rsplit("/", 1)[-1][:80]
        f = payload.get("focus") if isinstance(payload.get("focus"), dict) else {}
        focus = {k: f[k][:300] for k in ("node", "finding") if isinstance(f.get(k), str) and f[k]}
        from fastapi.concurrency import run_in_threadpool
        from lantern import ask as _ask
        from lantern.providers import AllowanceExhausted, ProviderError, why_failed
        try:
            res = await run_in_threadpool(_ask.ask, provider_for(request.state.token), q[:2000], None, focus or None,
                                          out, name)
        except AllowanceExhausted:
            raise HTTPException(402, "Your free allowance is used up for now. Everything else on Lantern still works; "
                                     "the local app can use your own key.") from None
        except ProviderError as e:
            kind, words = why_failed(e)
            if kind == "signed_out":     # the gateway no longer knows this token: forget the cached "signed in"
                ident.forget(request.state.token)
                raise HTTPException(401, words) from None
            log.warning("ask: gateway failed: %s (HTTP %s)", kind, getattr(e, "status", None))
            raise HTTPException(413 if kind == "too_big" else 503, words) from None
        except (KeyError, IndexError, TypeError) as e:   # an answer in a shape the client cannot read
            log.warning("ask: unreadable model answer: %s", type(e).__name__)
            raise HTTPException(502, "The model answered, but in a shape Lantern could not read. "
                                     "Try again; if it keeps happening, this needs fixing on Lantern's side.") from None
        return {"answer": res["answer"], "cited": res["cited"], "invented": len(res["invented"])}

    shot_slots = threading.BoundedSemaphore(2)    # screenshots read at once on this machine (Tesseract is CPU-heavy)
    SHOT_PIXELS = 40_000_000                       # 8K × 5K: any real screenshot, never a decompression bomb

    @app.post("/v1/ask/screenshot")
    async def ask_screenshot(request: Request):
        """Read the text in a screenshot for Ask Lantern, the way the app does (`lantern.ask.read_screenshot`: Pillow,
        then the Tesseract program through a pipe). The image stays in this request's memory: never written to disk,
        never stored, never sent to a model. Only the text comes back; the website shows it, and it goes to the model
        only as part of a question the person sends."""
        await signed_in(request)
        from lantern.ask import SCREENSHOT_MAX, read_screenshot
        try:
            n = int(request.headers.get("content-length") or 0)
        except ValueError:
            n = 0
        if not 0 < n <= SCREENSHOT_MAX + 64 * 1024:
            raise HTTPException(413 if n else 400, "Send one PNG, JPEG or WebP screenshot, up to 8 MB.")
        raw = await request.body()
        if len(raw) > SCREENSHOT_MAX + 64 * 1024:
            raise HTTPException(413, "Send one PNG, JPEG or WebP screenshot, up to 8 MB.")
        if not shot_slots.acquire(blocking=False):
            raise HTTPException(429, "Lantern is reading other screenshots right now. Try again in a few seconds.")
        try:
            from fastapi.concurrency import run_in_threadpool
            res = await run_in_threadpool(read_screenshot, raw, request.headers.get("content-type") or "", SHOT_PIXELS)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        finally:
            shot_slots.release()
            del raw
        if res.get("text") is None:     # the server's own setup, not something the person can install
            res = {**res, "how": None, "reason": "this server cannot read text in images yet"
                   if res.get("reason") in ("tesseract not installed", "Pillow not installed") else res.get("reason")}
        return res

    # ---- team workspaces (directive: user first, step 3) ----
    # A workspace is a few people who can open each other's runs. Its owner invites people with one-time links
    # (7 days; only a hash is kept; no email is ever asked for) and can take people out or close it. A run joins a
    # workspace only when its own owner puts it there, and leaves when they take it out. Members read; they never
    # change, share, explain or delete someone else's run. Each person keeps their own view (Simple or Advanced)
    # and lens: those live in their own browser.
    def member_id(wid: str, account: str) -> str:
        return hmac.new(vsecret, f"member:{wid}:{account}".encode(), hashlib.sha256).hexdigest()[:16]

    def team_name(payload: dict) -> str:
        n = payload.get("name")
        n = " ".join(n.split()) if isinstance(n, str) else ""
        if not n or len(n) > 60 or any(ord(ch) < 32 for ch in n):
            raise HTTPException(400, "Give the workspace a name, up to 60 characters.")
        return n

    def in_team(wid: str, who: dict, owner: bool = False) -> dict:
        w = store.workspace(wid) if isinstance(wid, str) and len(wid) <= 40 else None
        role = store.role(wid, who["account"]) if w else None
        if not role:
            raise HTTPException(404, "No workspace with that id that you are in.")
        if owner and role != "owner":
            raise HTTPException(403, "Only the workspace's owner can do that.")
        return {**w, "role": role}

    def team_view(w: dict, who: dict) -> dict:
        acc = who["account"]
        mine = store.member_lanes(w["id"], acc) or "all"
        people = [{"id": member_id(w["id"], m["account"]), "name": m["label"].split(":", 1)[-1] or "Someone",
                   "role": m["role"], "joined": m["joined"], "you": m["account"] == acc,
                   "lanes": list(scope.decode(m["lanes"]) or ()) if m["lanes"] and m["role"] != "owner" else None}
                  for m in store.members(w["id"])]
        labels = {m["account"]: m["label"].split(":", 1)[-1] for m in store.members(w["id"])}
        runs = [r for r in store.runs(acc) if r.get("workspace") == w["id"]] + \
               [r for r in store.team_runs(acc) if r.get("workspace") == w["id"]]
        runs.sort(key=lambda r: r["created"], reverse=True)
        return {"id": w["id"], "name": w["name"], "role": w["role"], "people": people,
                "invites_open": store.open_invites(w["id"]) if w["role"] == "owner" else None,
                "runs": [{**seen(run_view(r), "all" if r["account"] == acc else mine), "mine": r["account"] == acc,
                          "by": labels.get(r["account"]) or "Someone"} for r in runs],
                "lanes": None if mine == "all" else list(scope.decode(mine) or ()),
                "limits": {"people": s.workspace_people, "invite_days": 7}}

    @app.get("/v1/workspaces")
    async def list_workspaces(request: Request):
        who = await signed_in(request)
        return {"workspaces": store.workspaces(who["account"])}

    @app.post("/v1/workspaces", status_code=201)
    async def create_workspace(payload: dict, request: Request):
        who = await signed_in(request)
        try:
            wid = store.create_workspace(who["account"], team_name(payload), most=s.workspaces_per_owner)
        except LimitReached as e:
            raise HTTPException(429, str(e)) from None
        return team_view(in_team(wid, who), who)

    @app.get("/v1/workspaces/{wid}")
    async def get_workspace(wid: str, request: Request):
        who = await signed_in(request)
        return team_view(in_team(wid, who), who)

    @app.patch("/v1/workspaces/{wid}")
    async def rename_workspace(wid: str, payload: dict, request: Request):
        who = await signed_in(request)
        w = in_team(wid, who, owner=True)
        store.rename_workspace(w["id"], team_name(payload))
        return team_view(in_team(wid, who), who)

    @app.delete("/v1/workspaces/{wid}")
    async def close_workspace(wid: str, request: Request):
        """Close a workspace: everyone leaves, open invites stop working, and every run in it goes back to being its
        owner's alone. No run or result is deleted."""
        who = await signed_in(request)
        w = in_team(wid, who, owner=True)
        store.close_workspace(w["id"])
        return {"closed": w["id"]}

    @app.post("/v1/workspaces/{wid}/invites", status_code=201)
    async def invite(wid: str, request: Request):
        """A one-time invite link. Whoever opens it first and signs in joins as a member; then it stops working. It
        also stops after 7 days. Lantern keeps only a hash of it, so it is shown this once."""
        who = await signed_in(request)
        w = in_team(wid, who, owner=True)
        try:
            secret, exp = store.create_invite(w["id"], open_most=s.open_invites)
        except LimitReached as e:
            raise HTTPException(429, str(e)) from None
        return JSONResponse({"url": f"{s.public_url}/#/join/{secret}", "expires": exp, "one_time": True},
                            status_code=201, headers={"Cache-Control": "no-store"})

    @app.delete("/v1/workspaces/{wid}/invites")
    async def cancel_invites(wid: str, request: Request):
        who = await signed_in(request)
        w = in_team(wid, who, owner=True)
        return {"cancelled": store.cancel_invites(w["id"])}

    @app.post("/v1/invites/peek")
    async def peek_invite(payload: dict):
        """Which workspace an invite opens, so the page can say so before anyone signs in. Nothing else."""
        i = store.invite(payload.get("code"))
        if not i:
            raise HTTPException(404, "This invite link has been used, has expired, or was cancelled. Ask for a new one.")
        return {"name": i["name"], "expires": i["expires"]}

    @app.post("/v1/invites/accept")
    async def accept_invite(payload: dict, request: Request):
        who = await signed_in(request)
        try:
            wid = store.join(payload.get("code"), who["account"], most=s.workspace_people)
        except LimitReached as e:
            raise HTTPException(429, str(e)) from None
        if not wid:
            raise HTTPException(404, "This invite link has been used, has expired, or was cancelled. Ask for a new one.")
        return team_view(in_team(wid, who), who)

    @app.delete("/v1/workspaces/{wid}/people/{mid}")
    async def remove_person(wid: str, mid: str, request: Request):
        """The owner takes someone out, or a member leaves. Their runs in the workspace go back to being theirs
        alone. The owner cannot leave; they close the workspace instead."""
        who = await signed_in(request)
        w = in_team(wid, who)
        target = next((m for m in store.members(w["id"]) if hmac.compare_digest(member_id(w["id"], m["account"]), mid)), None)
        if not target:
            raise HTTPException(404, "That person is not in this workspace.")
        if target["role"] == "owner":
            raise HTTPException(409, "The owner can't leave their own workspace. Close it instead.")
        if target["account"] != who["account"] and w["role"] != "owner":
            raise HTTPException(403, "Only the workspace's owner can take someone out.")
        store.remove_member(w["id"], target["account"])
        return {"removed": mid, "left": target["account"] == who["account"]}

    @app.put("/v1/workspaces/{wid}/people/{mid}")
    async def set_layers(wid: str, mid: str, payload: dict, request: Request):
        """The owner chooses which layers of the app a member can see in this workspace's runs:
        {"lanes": ["frontend", "browser"]}, or {"lanes": null} for all of them. Hidden layers never reach that
        member's browser: their report is built without them (`lantern.scope`)."""
        who = await signed_in(request)
        w = in_team(wid, who, owner=True)
        target = next((m for m in store.members(w["id"]) if hmac.compare_digest(member_id(w["id"], m["account"]), mid)), None)
        if not target:
            raise HTTPException(404, "That person is not in this workspace.")
        if target["role"] == "owner":
            raise HTTPException(409, "The owner always sees every layer.")
        try:
            lanes = scope.parse(payload.get("lanes"))
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        store.set_member_lanes(w["id"], target["account"], None if lanes is None else scope.code(lanes))
        return team_view(in_team(wid, who), who)

    # ---- notes on the map (directive: user first, step 5) ----
    # Short notes people leave on a function in a run's map, for the others who can open that run. Words only: a
    # note is never part of the analysis and never reaches a model. Someone who sees only some layers neither sees
    # nor leaves notes on the rest (each note keeps its function's layer). The author or the run's owner deletes one.
    graph_cache: dict[str, tuple[float, dict]] = {}

    def lanes_of(rid: str) -> dict:
        """{node id: layer} for a finished run, from its own report data (cached while the file is unchanged)."""
        f = Path(s.results_dir) / rid / "report.html"
        try:
            m = f.stat().st_mtime
        except OSError:
            raise HTTPException(409, "This run has no report yet.") from None
        hit = graph_cache.get(rid)
        if hit and hit[0] == m:
            return hit[1]
        from lantern.report import read_bundle
        try:
            nodes = (read_bundle(f).get("graph") or {}).get("nodes") or []
        except Exception:  # noqa: BLE001: a damaged result file
            raise HTTPException(409, "This report can't be read. Check the app again.") from None
        got = {n["id"]: n.get("lane") for n in nodes if isinstance(n, dict) and isinstance(n.get("id"), str)}
        if len(graph_cache) > 64:
            graph_cache.clear()
        graph_cache[rid] = (m, got)
        return got

    def may_see(lane, lanes: str) -> bool:
        return lanes == "all" or lane is None or lane in (scope.decode(lanes) or scope.LANES)

    def note_body(payload: dict) -> str:
        b = payload.get("body")
        b = b.strip() if isinstance(b, str) else ""
        if not b or len(b) > 1000 or any(ord(ch) < 32 and ch not in "\n\t" for ch in b):
            raise HTTPException(400, "Write a note of up to 1000 characters.")
        return b

    @app.get("/v1/runs/{rid}/notes")
    async def list_notes(rid: str, request: Request):
        who = await signed_in(request)
        r = readable_run(rid, who)
        owner = r["account"] == who["account"]
        return {"notes": [{"id": n["id"], "node": n["node"], "body": n["body"], "created": n["created"],
                           "by": n["label"].split(":", 1)[-1] or "Someone", "mine": n["account"] == who["account"],
                           "can_delete": owner or n["account"] == who["account"]}
                          for n in store.notes(r["id"]) if may_see(n["lane"], r["lanes"])]}

    @app.post("/v1/runs/{rid}/notes", status_code=201)
    async def add_note(rid: str, payload: dict, request: Request):
        who = await signed_in(request)
        r = readable_run(rid, who)
        if r["status"] != "done":
            raise HTTPException(409, "This run has no report yet.")
        node, body = payload.get("node"), note_body(payload)
        lanes = lanes_of(r["id"])
        if not isinstance(node, str) or node not in lanes or not may_see(lanes[node], r["lanes"]):
            raise HTTPException(404, "That function is not on this report's map.")
        try:
            nid = store.add_note(r["id"], node, lanes[node], who["account"], body, most=s.notes_per_run)
        except LimitReached as e:
            raise HTTPException(429, str(e)) from None
        return {"id": nid}

    @app.delete("/v1/notes/{nid}")
    async def delete_note(nid: str, request: Request):
        who = await signed_in(request)
        n = store.note(nid) if isinstance(nid, str) and len(nid) <= 40 else None
        r = readable_run(n["run"], who) if n else None    # 404 for someone who can't open the run
        if not n or not may_see(n["lane"], r["lanes"]):
            raise HTTPException(404, "No note with that id.")
        if n["account"] != who["account"] and r["account"] != who["account"]:
            raise HTTPException(403, "Only the note's author or the report's owner can delete it.")
        store.delete_note(n["id"])
        return {"deleted": n["id"]}

    @app.put("/v1/runs/{rid}/workspace")
    async def put_in_workspace(rid: str, payload: dict, request: Request):
        """Put one of your own finished runs in a workspace you are in (its members can then open it), or take it
        out again with {"workspace": null}."""
        who = await signed_in(request)
        r = own_run(rid, who)
        wid = payload.get("workspace")
        if wid is not None:
            in_team(wid, who)
            if r["status"] not in FINISHED:
                raise HTTPException(409, "This check is still going. Add it to the workspace once it has finished.")
        store.set_run_workspace(r["id"], wid)
        return run_view(store.run(r["id"]))

    # ---- the website (same origin as the API, so no CORS is offered or needed) ----
    secure = s.public_url.startswith("https://")

    @app.get("/")
    def website():
        html, nonce = site.page(__version__)
        from lantern.server import _csp
        return Response(html, 200, media_type="text/html; charset=utf-8", headers={
            "Content-Security-Policy": _csp(nonce), "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()"})

    @app.get("/guide")
    def guide():
        """How to use Lantern: the guide page with its animated demos (fixed content, no account needed)."""
        from lantern.guide import page as guide_page
        from lantern.server import _csp
        html, nonce = guide_page(__version__, "/")
        return Response(html, 200, media_type="text/html; charset=utf-8", headers={
            "Content-Security-Policy": _csp(nonce), "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()"})

    @app.get("/{name}")
    def website_asset(name: str):
        a = site.asset(name)
        if a is None:
            raise HTTPException(404, "Not found.")
        body, ctype = a
        return Response(body, 200, media_type=ctype, headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"})

    def site_only(request: Request) -> None:
        if request.headers.get("x-lantern-site") != "1":
            raise HTTPException(403, "This request did not come from Lantern's own page.")

    @app.get("/v1/signin/providers")
    async def signin_providers():
        try:
            return {"providers": await ident.providers()}
        except GatewayUnavailable:
            raise HTTPException(503, "Sign-in is unavailable right now. Try again in a minute.") from None

    @app.post("/v1/signin/start")
    async def signin_start(payload: dict, request: Request):
        """Begin a sign-in: a fresh one-time code, kept in an HttpOnly cookie for this browser only, and the page to
        open. The person signs in on GitHub or Google through the gateway, which parks the token under the code."""
        site_only(request)
        provider = payload.get("provider")
        try:
            ok = provider in await ident.providers()
        except GatewayUnavailable:
            raise HTTPException(503, "Sign-in is unavailable right now. Try again in a minute.") from None
        if not ok:
            raise HTTPException(400, "Choose GitHub or Google.")
        cli = secrets.token_urlsafe(36)
        resp = JSONResponse({"url": ident.login_url(provider, cli)}, headers={"Cache-Control": "no-store"})
        resp.set_cookie(SIGNIN_COOKIE, cli, max_age=600, path="/v1/signin", secure=secure, httponly=True, samesite="strict")
        return resp

    @app.post("/v1/signin/poll")
    async def signin_poll(request: Request):
        """Collect the token once the person has signed in; it goes into an HttpOnly cookie, never to the page."""
        site_only(request)
        cli = request.cookies.get(SIGNIN_COOKIE) or ""
        if not (32 <= len(cli) <= 128):
            raise HTTPException(400, "No sign-in in progress here. Start again.")
        try:
            token = await ident.claim(cli)
            who = await ident.whoami(token) if token else None
        except GatewayUnavailable:
            raise HTTPException(503, "Sign-in is unavailable right now. Try again in a minute.") from None
        if not token:
            return JSONResponse({"signed_in": False}, headers={"Cache-Control": "no-store"})
        if who is None:
            raise HTTPException(401, "That sign-in did not work. Try again.")
        store.touch_user(who["account"], who["label"])
        resp = JSONResponse({"signed_in": True, "label": who["label"]}, headers={"Cache-Control": "no-store"})
        resp.delete_cookie(SIGNIN_COOKIE, path="/v1/signin")
        resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_DAYS * 86400, path="/", secure=secure, httponly=True,
                        samesite="strict")
        return resp

    @app.post("/v1/signout")
    async def signout(request: Request, payload: dict | None = None):
        """Sign this browser out (its sign-in ends at the gateway too), or with `{"everywhere": true}` every place
        the account is signed in: the website on other devices, the app and the CLI."""
        site_only(request)
        everywhere = bool((payload or {}).get("everywhere"))
        token = request.cookies.get(SESSION_COOKIE) or ""
        ended = 0
        if token:
            try:
                ended = await ident.sign_out(token, everywhere)
            except GatewayUnavailable:
                if everywhere:
                    raise HTTPException(503, "Lantern can't reach sign-in right now, so nothing was signed out. "
                                             "Try again in a minute.") from None
        resp = JSONResponse({"signed_in": False, "ended": ended})
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.get("/v1/admin/stats")
    def admin_stats(authorization: str | None = Header(default=None)):
        admin(authorization)
        return store.stats()

    return app
