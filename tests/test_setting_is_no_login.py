"""A secret setting of the server that is read and handed on asks nobody who is calling (roadmap of 2026-11-14,
stage 5).

A route that calls another service reads the token for it from its settings (`process.env.NOTES_API_TOKEN`,
`settings.API_TOKEN`). That token is the server's own: reading it, and putting it on the request to the other
service, says nothing about who sent the request to this route. Until this change the login check took any name
built from the word "token" for a sign of a login, a setting's name included, so such a route, with nothing asked
of its caller, was not listed.

A setting does stand in a login's place where the request is held against it: the statement it stands in compares
something or calls a function named for checking, however many lines that statement is written over, or a later
statement does so with the name the setting was kept under; a setting that lists several secrets counts the same
way. A comparison with nothing (`=== undefined`, `== null`) only asks whether the setting is set, and a comparison
in the statement before is not about the setting. Those routes stand beside the open ones: the checked ones must
stay unlisted, the look-alikes must be listed. Small made-up projects; none of these files comes from an app of a
benchmark.
"""
import pytest

from lantern.engine import build_graph
from lantern.security import scan

RULE = "LW-AUTH-MISSING"
NEXT = {
    "package.json": '{"name": "pad", "dependencies": {"next": "15.0.0", "react": "19.0.0", "openai": "4.60.0"}}\n',
    "tsconfig.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["./*"]}}}\n',
    "lib/caller.ts": ("export function checkCaller(req: Request, want: string | undefined) {\n"
                      '  return Boolean(want) && req.headers.get("x-pad-key") === want;\n}\n'),
}
HEAD = ('import { timingSafeEqual } from "crypto";\nimport { NextResponse } from "next/server";\n'
        'import { checkCaller } from "@/lib/caller";\n\n')
NO = 'return NextResponse.json({ error: "no" }, { status: 401 });'
SEND = ("  const { id } = await req.json();\n"
        '  await fetch("https://notes.example.com/v1/notes/" + encodeURIComponent(id), {\n'
        '    method: "DELETE",\n    headers: { Authorization: "Bearer " + process.env.NOTES_API_TOKEN },\n  });\n'
        "  return NextResponse.json({ ok: true });\n")


def _post(body):
    return HEAD + "export async function POST(req: Request) {\n" + body + "}\n"


# each: the route's file, its text, and whether it must be listed as a route with no login
ROUTES = {
    "the server's token is read and handed on to another service": (
        "app/api/notes/remove/route.ts", _post(SEND), True),
    "the same token kept under a name first, and handed on": (
        "app/api/notes/drop/route.ts",
        _post("  const token = process.env.NOTES_API_TOKEN;\n  const { id } = await req.json();\n"
              '  await fetch("https://notes.example.com/v1/notes/" + encodeURIComponent(id), '
              '{ method: "DELETE", headers: { Authorization: "Bearer " + token } });\n'
              "  return NextResponse.json({ ok: true });\n"), True),
    "the request's key compared with the setting": (
        "app/api/notes/remove-keyed/route.ts",
        _post(f'  if (req.headers.get("x-pad-key") !== process.env.PAD_TOKEN) {{\n    {NO}\n  }}\n' + SEND), False),
    "the setting kept under a name, and the request's key compared with that": (
        "app/api/notes/remove-named/route.ts",
        _post('  const want = process.env.PAD_TOKEN;\n  const got = req.headers.get("x-pad-key");\n'
              f"  if (!want || got !== want) {{\n    {NO}\n  }}\n" + SEND), False),
    "the request and the setting handed to a function named for checking": (
        "app/api/notes/remove-checked/route.ts",
        _post(f"  if (!checkCaller(req, process.env.PAD_TOKEN)) {{\n    {NO}\n  }}\n" + SEND), False),
    # --- the same check written over several lines is still a check
    "the two compared by a library's function, each on a line of its own": (
        "app/api/notes/remove-timed/route.ts",
        _post('  const key = req.headers.get("x-pad-key") ?? "";\n'
              "  if (\n    !timingSafeEqual(\n      Buffer.from(key),\n"
              '      Buffer.from(process.env.PAD_TOKEN ?? ""),\n    )\n  ) {\n'
              f"    {NO}\n  }}\n" + SEND), False),
    "the request's key looked for among two settings": (
        "app/api/notes/remove-among/route.ts",
        _post('  const key = req.headers.get("x-pad-key") ?? "";\n'
              "  const known = [process.env.PAD_TOKEN, process.env.OLD_PAD_TOKEN].includes(\n    key,\n  );\n"
              f"  if (!known) {{\n    {NO}\n  }}\n" + SEND), False),
    "the request's key looked for in one setting that lists several": (
        "app/api/notes/remove-listed/route.ts",
        _post('  const key = req.headers.get("x-pad-key") ?? "";\n'
              '  if (!key || !(process.env.PAD_TOKENS ?? "").split(",").includes(key)) {\n'
              f"    {NO}\n  }}\n" + SEND), False),
    "the comparison broken after its sign, the setting on the next line": (
        "app/api/notes/remove-broken/route.ts",
        _post('  if (\n    req.headers.get("x-pad-key") !==\n    process.env.PAD_TOKEN\n  ) {\n'
              f"    {NO}\n  }}\n" + SEND), False),
    "the setting kept under a name and handed to a checking function on a later line": (
        "app/api/notes/remove-later/route.ts",
        _post("  const want = process.env.PAD_TOKEN;\n  const ok = checkCaller(\n    req,\n    want,\n  );\n"
              f"  if (!ok) {{\n    {NO}\n  }}\n" + SEND), False),
    "a comparison kept under a name, broken after its sign with no brackets around it": (
        "app/api/notes/remove-plain/route.ts",
        _post('  const key = req.headers.get("x-pad-key") ?? "";\n'
              "  const same = key.length > 0 && key ===\n    process.env.PAD_TOKEN;\n"
              f"  if (!same) {{\n    {NO}\n  }}\n" + SEND), False),
    "the list of settings, cut up and asked on the lines after it": (
        "app/api/notes/remove-chained/route.ts",
        _post('  const key = req.headers.get("x-pad-key") ?? "";\n'
              "  const known = process.env.PAD_TOKENS\n    ?.split(\",\")\n    .includes(key);\n"
              f"  if (!known) {{\n    {NO}\n  }}\n" + SEND), False),
    # --- what looks like a check and asks nobody who is calling
    "the setting only asked whether it is set, then handed on": (
        "app/api/notes/remove-if-set/route.ts",
        _post("  if (process.env.NOTES_API_TOKEN === undefined) {\n"
              '    return NextResponse.json({ error: "not set up" }, { status: 500 });\n  }\n' + SEND), True),
    "kept under a name, the name only asked whether anything is in it": (
        "app/api/notes/drop-if-set/route.ts",
        _post("  const token = process.env.NOTES_API_TOKEN;\n  if (token == null || token === \"\") {\n"
              '    return NextResponse.json({ error: "not set up" }, { status: 500 });\n  }\n'
              "  const { id } = await req.json();\n"
              '  await fetch("https://notes.example.com/v1/notes/" + encodeURIComponent(id), '
              '{ method: "DELETE", headers: { Authorization: "Bearer " + token } });\n'
              "  return NextResponse.json({ ok: true });\n"), True),
    "something else compared in the statement before, written with no semicolons": (
        "app/api/notes/remove-kind/route.ts",
        _post("  const kind = new URL(req.url).searchParams.get(\"kind\")\n"
              "  const all = kind === \"all\"\n"
              "  const { id } = await req.json()\n"
              '  await fetch("https://notes.example.com/v1/notes/" + encodeURIComponent(id) + (all ? "?all=1" : ""), {\n'
              '    method: "DELETE",\n    headers: { Authorization: "Bearer " + process.env.NOTES_API_TOKEN },\n  })\n'
              "  return NextResponse.json({ ok: true })\n"), True),
    "the settings reached through an object of the handler's own": (
        "app/api/notes/remove-through/route.ts",
        _post("  const ctx = { env: process.env };\n  const { id } = await req.json();\n"
              '  await fetch("https://notes.example.com/v1/notes/" + encodeURIComponent(id), '
              '{ method: "DELETE", headers: { Authorization: "Bearer " + ctx.env.NOTES_API_TOKEN } });\n'
              "  return NextResponse.json({ ok: true });\n"), True),
}


def _page(rel):
    """A page of the project that calls the route written in `rel`."""
    path = "/" + rel.removeprefix("app/").removesuffix("/route.ts")
    return ('"use client";\n\nexport default function Page() {\n  async function go() {\n'
            f'    await fetch("{path}", {{ method: "POST", body: JSON.stringify({{ id: "1" }}) }});\n  }}\n'
            "  return <button onClick={go}>Go</button>;\n}\n")


def _scan(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    sec = scan(build_graph(root), offline=True)
    return [f for f in sec["findings"] if not f["in_tests"]]


@pytest.mark.parametrize("case", sorted(ROUTES))
def test_a_route_that_reads_a_secret_setting_and_whom_it_asked(tmp_path, case):
    rel, text, listed = ROUTES[case]
    fs = _scan(tmp_path, {**NEXT, rel: text, "app/page.tsx": _page(rel)})
    got = sorted(f["file"] for f in fs if f["rule"] == RULE)
    assert got == ([rel] if listed else []), [(f["rule"], f["file"], f["title"]) for f in fs]


FLASK_ROUTES = ["remove", "remove-either", "remove-kept-secret", "remove-keyed", "remove-keyed-wide", "remove-digest",
                "remove-among", "remove-if-among"]
FLASK = {
    "requirements.txt": "Flask==3.0.3\nrequests==2.32.3\npydantic-settings==2.6.1\n",
    "config.py": ('import os\n\nfrom pydantic import SecretStr\nfrom pydantic_settings import BaseSettings\n\n'
                  'NOTES_TOKEN = os.environ.get("NOTES_TOKEN", "")\nPAD_TOKEN = os.environ.get("PAD_TOKEN", "")\n'
                  'PAD_TOKENS = [t for t in os.environ.get("PAD_TOKENS", "").split(",") if t]\n\n\n'
                  "class Settings(BaseSettings):\n    NOTES_TOKEN: SecretStr\n\n\nsettings = Settings()\n"),
    "web/package.json": '{"name": "web", "dependencies": {"react": "19.0.0"}}\n',
    "web/src/api.js": "".join(
        f'export const call{i} = (id) => fetch("/notes/{name}", {{ method: "POST", body: JSON.stringify({{ id }}) }});\n'
        for i, name in enumerate(FLASK_ROUTES)),
    "app.py": '''import hmac

import requests
from flask import Flask, abort, jsonify, request

import config
from config import settings

app = Flask(__name__)
NOTES = "https://notes.example.com/v1/notes/"


@app.post("/notes/remove")
def remove_note():
    note = int(request.json["id"])
    requests.delete(f"{NOTES}{note}", headers={"X-Token": config.NOTES_TOKEN}, timeout=10)
    return jsonify(ok=True)


@app.route("/notes/remove-either", methods=["POST", "DELETE"])
def remove_note_either():
    note = int(request.json["id"])
    if request.method == "POST":
        requests.delete(f"{NOTES}{note}", headers={"X-Token": config.NOTES_TOKEN}, timeout=10)
    return jsonify(ok=True)


@app.post("/notes/remove-kept-secret")
def remove_note_kept_secret():
    note = int(request.json["id"])
    requests.delete(f"{NOTES}{note}", headers={"X-Token": settings.NOTES_TOKEN.get_secret_value()}, timeout=10)
    return jsonify(ok=True)


@app.post("/notes/remove-keyed")
def remove_note_keyed():
    if request.headers.get("X-Pad-Key", "") != config.PAD_TOKEN:
        abort(401)
    note = int(request.json["id"])
    requests.delete(f"{NOTES}{note}", headers={"X-Token": config.NOTES_TOKEN}, timeout=10)
    return jsonify(ok=True)


@app.post("/notes/remove-keyed-wide")
def remove_note_keyed_wide():
    if (
        request.headers.get("X-Pad-Key", "")
        != config.PAD_TOKEN
    ):
        abort(401)
    note = int(request.json["id"])
    requests.delete(f"{NOTES}{note}", headers={"X-Token": config.NOTES_TOKEN}, timeout=10)
    return jsonify(ok=True)


@app.post("/notes/remove-digest")
def remove_note_digest():
    same = hmac.compare_digest(
        request.headers.get("X-Pad-Key", ""),
        config.PAD_TOKEN,
    )
    if not same:
        abort(401)
    note = int(request.json["id"])
    requests.delete(f"{NOTES}{note}", headers={"X-Token": config.NOTES_TOKEN}, timeout=10)
    return jsonify(ok=True)


@app.post("/notes/remove-among")
def remove_note_among():
    if request.headers.get("X-Pad-Key", "") not in config.PAD_TOKENS:
        abort(401)
    note = int(request.json["id"])
    requests.delete(f"{NOTES}{note}", headers={"X-Token": config.NOTES_TOKEN}, timeout=10)
    return jsonify(ok=True)


@app.post("/notes/remove-if-among")
def remove_note_if_among():
    if request.headers.get("X-Pad-Key", "") in config.PAD_TOKENS:
        note = int(request.json["id"])
        requests.delete(f"{NOTES}{note}", headers={"X-Token": config.NOTES_TOKEN}, timeout=10)
        return jsonify(ok=True)
    abort(401)
''',
}


def test_the_same_in_a_flask_app(tmp_path):
    """Three routes hand the server's token on and ask nobody (one only under a condition about the request's
    verb, one through the wrapper a settings library keeps a secret in); five hold the request's key against a
    setting first, each written another way."""
    fs = _scan(tmp_path, FLASK)
    assert sorted(f["title"].split(" ", 2)[1] for f in fs if f["rule"] == RULE) == [
        "/notes/remove", "/notes/remove-either", "/notes/remove-kept-secret"], [(f["rule"], f["title"]) for f in fs]


def test_a_paid_call_made_with_the_servers_own_token_is_still_open_to_anyone(tmp_path):
    """The check on a route that reaches a paid service asks the same question of the same lines: the token the
    server pays with is no login of the caller's."""
    rel = "app/api/draw/route.ts"
    text = ('import { NextResponse } from "next/server";\nimport OpenAI from "openai";\n\n'
            "export async function POST(req: Request) {\n"
            "  const client = new OpenAI({ apiKey: process.env.MODEL_API_TOKEN });\n"
            "  const { prompt } = await req.json();\n"
            '  const out = await client.chat.completions.create({ model: "gpt-4o-mini", '
            'messages: [{ role: "user", content: prompt }] });\n'
            "  return NextResponse.json({ text: out.choices[0].message.content });\n}\n")
    fs = [f for f in _scan(tmp_path, {**NEXT, rel: text, "app/page.tsx": _page(rel)}) if f["rule"] == "LA-WALLET-DRAIN"]
    assert [f["file"] for f in fs] == [rel]
    # until this change: "... with no rate limit", as if somebody had to sign in for it
    assert "anyone can call it" in fs[0]["title"] and fs[0]["tool_severity"] == "HIGH", fs[0]["title"]
