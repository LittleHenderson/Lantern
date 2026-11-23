"""Inside the sandbox: start a project's web app with no network and answer the requests of Lantern's browser
checks (`lantern.browse`, docs/browser.md), which come as files in a folder of the run's own and leave the same way.

Standard library only, and only ever started by `lantern.sandbox.run_inside` (it refuses to work without the
sandbox's guard). One process: the app (ASGI) is loaded by name and started the way a server starts it
(`lantern._behave_inside._started`), and each request is served as it comes, several at once, as a server does. A
request the app never answers stays unanswered, and Lantern's side says so. There is no socket anywhere: nothing
reaches the app but these files, which the sandbox's walls keep in its own temp folder.

The folder (`browse` in the run's temp folder, made by Lantern's side before the run starts): `in/` holds the
requests Lantern's side writes (`<number>.json`, put in place whole), `out/` the answers (the same name, put in place
whole) and `ready.json`, which says whether the app started; `in/stop.json` ends the run. What the app prints goes to
a file of the run (`browse-app.txt`), read here only for the guard's own lines (what the app tried and was refused)."""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import os
import re
import secrets
import sys
import urllib.parse

from . import _behave_inside

POLL = 0.01                 # seconds between two looks for new requests
MOST_BODY = 16 << 20        # bytes of an answer that are handed back
MOST_REQUEST = 32 << 20     # bytes of a request's file that are read
REQUEST_NAME = re.compile(r"\d{8}\.json")
NAME = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
FOLDER = "browse"
APP_LINES = "browse-app.txt"


def _put(folder: str, name: str, data: dict) -> None:
    """`data` as JSON under `name` in `folder`, put in place whole."""
    part = os.path.join(folder, name + ".part")
    with open(part, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(part, os.path.join(folder, name))


async def _serve(app, req: dict, state: dict, server: tuple[str, int]) -> dict:
    body = base64.b64decode(req.get("body") or "")
    path, _, query = str(req.get("path") or "/").partition("?")
    headers = [(str(k).lower().encode("latin-1", "replace"), str(v).encode("latin-1", "replace"))
               for k, v in req.get("headers") or []]
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
             "method": str(req.get("method") or "GET").upper(), "scheme": "http",
             "path": urllib.parse.unquote(path), "raw_path": path.encode("utf-8"),
             "query_string": query.encode("utf-8"), "root_path": "", "headers": headers,
             "client": ("127.0.0.1", 50000), "server": server, "state": dict(state)}
    got: dict = {"status": None, "headers": [], "body": bytearray(), "bytes": 0, "cut": False}
    finished = asyncio.Event()
    handed = False

    async def receive():
        nonlocal handed
        if not handed:
            handed = True
            return {"type": "http.request", "body": body, "more_body": False}
        await finished.wait()
        return {"type": "http.disconnect"}

    async def send(event):
        if event["type"] == "http.response.start":
            got["status"] = int(event["status"])
            got["headers"] = [[k.decode("latin-1"), v.decode("latin-1")] for k, v in event.get("headers", [])]
        elif event["type"] == "http.response.body":
            piece = event.get("body", b"")
            got["bytes"] += len(piece)
            room = MOST_BODY - len(got["body"])
            if len(piece) > room:
                got["cut"] = True
            got["body"] += piece[:max(room, 0)]
            if not event.get("more_body"):
                finished.set()

    error = None
    try:
        await app(scope, receive, send)
    except asyncio.CancelledError:
        raise
    except BaseException as e:              # a server answers 500 and carries on; so does this
        error = type(e).__name__
    answer = {"status": got["status"] if got["status"] is not None else 500, "headers": got["headers"],
              "body": base64.b64encode(bytes(got["body"])).decode("ascii"), "bytes": got["bytes"], "cut": got["cut"]}
    if error:
        answer["error"] = error
    return answer


async def _answer_all(app, state: dict, chan_in: str, chan_out: str, server: tuple[str, int]) -> int:
    going: set = set()
    served = 0

    async def one(name: str, req: dict) -> None:
        nonlocal served
        answer = await _serve(app, req, state, server)
        _put(chan_out, name, answer)
        served += 1

    while True:
        try:
            names = sorted(os.listdir(chan_in))
        except OSError:
            break
        if "stop.json" in names:
            break
        for name in names:
            if not REQUEST_NAME.fullmatch(name):
                continue
            path = os.path.join(chan_in, name)
            try:
                if os.path.getsize(path) > MOST_REQUEST:
                    os.unlink(path)
                    continue
                with open(path, encoding="utf-8") as f:
                    req = json.load(f)
                os.unlink(path)
            except (OSError, ValueError):
                continue
            if isinstance(req, dict):
                task = asyncio.ensure_future(one(name, req))
                going.add(task)
                task.add_done_callback(going.discard)
        await asyncio.sleep(POLL)
    for task in list(going):
        task.cancel()
    if going:
        await asyncio.wait(list(going), timeout=2)
    return served


def _refused(lines_path: str) -> list[str]:
    """The guard's own lines in what the app printed: what it tried and was refused."""
    try:
        with open(lines_path, "rb") as f:
            text = f.read(4 << 20).decode("utf-8", "replace")
    except OSError:
        return []
    mark = _behave_inside.MARK
    return list(dict.fromkeys(ln.split(mark, 1)[1].strip()[:200] for ln in text.splitlines() if mark in ln))[:40]


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: python -m lantern._browse_inside SCENE OUT APP")
        return 2
    if not _behave_inside._guarded():
        print("browse: the sandbox's guard is not in place, so the app was not started")
        return 97
    scene_path, out_path, app_dir = argv
    with open(scene_path, encoding="utf-8") as f:
        scene = json.load(f)
    work = os.path.dirname(os.path.abspath(out_path))
    chan_in, chan_out = (os.path.join(work, FOLDER, part) for part in ("in", "out"))
    data = os.path.join(work, "browse-data")
    os.makedirs(data, exist_ok=True)
    spec = scene.get("app") or {}
    values = {"data": data, "secret": secrets.token_hex(24)}

    def fill(value) -> str:
        text = str(value)
        whole = NAME.fullmatch(text)
        if whole and whole.group(1) in values:
            return values[whole.group(1)]
        return NAME.sub(lambda m: values.get(m.group(1), m.group(0)), text)

    os.environ.pop("PYTHONDONTWRITEBYTECODE", None)
    os.environ.update({str(k): fill(v) for k, v in (spec.get("env") or {}).items()})
    site = scene.get("site") or {}
    server = (str(site.get("host") or "localhost"), int(site.get("port") or 80))
    lines_path = os.path.join(work, APP_LINES)
    lines = open(lines_path, "wb")
    say = os.fdopen(os.dup(1), "w", encoding="utf-8", newline="\n")
    os.dup2(lines.fileno(), 1)              # whatever the app prints is not Lantern's to show
    os.dup2(lines.fileno(), 2)
    cwd = os.path.join(app_dir, str(spec.get("cwd") or "")) if spec.get("cwd") else app_dir
    observed: dict = {"version": 1, "guard": "on", "served": 0}
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    code = 0
    try:
        os.chdir(cwd)
        sys.path.insert(0, cwd)             # the app's own folder first, as a server started there has it
        module, _, name = str(spec.get("asgi") or "").partition(":")
        app = getattr(importlib.import_module(module), name or "app")
        app = app() if spec.get("factory") is True else app
        state = loop.run_until_complete(_behave_inside._started(app))
    except BaseException as e:      # noqa: BLE001 - whatever the app raises while it starts is its own
        _put(chan_out, "ready.json", {"ready": False, "error": f"{type(e).__name__}: {e}"[:300]})
        say.write("browse: the app could not be started\n")
        observed["started"] = False
        code = 3
    else:
        _put(chan_out, "ready.json", {"ready": True})
        say.write("browse: the app started; answering the browser\n")
        say.flush()
        observed["started"] = True
        observed["served"] = loop.run_until_complete(_answer_all(app, state, chan_in, chan_out, server))
    observed["refused"] = _refused(lines_path)
    try:
        _put(work, os.path.basename(out_path), observed)
    except OSError:
        pass
    say.write(f"browse: {observed['served']} requests answered\n")
    say.flush()
    for stream in (sys.stdout, sys.stderr, lines, say):
        try:
            stream.flush()
        except (OSError, ValueError):
            pass
    os._exit(code)          # threads the app left (a library's pool) do not hold the end of the run


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
