"""A check made on every item of a list at once: `any(...)`, `all(...)`, `some`, `every` (directive point 6).

Until this stage a path check was read only where it stood on one value (`if not full.startswith(folder): raise`).
Code that resolves a whole list of names and then refuses the request when any of them leaves the folder was not
read as a check at all, so the lines that open those files were listed as request data naming a file: two false
alarms, ranked high, on the safe version of the behaviour benchmark's own app (`bench/behaviour/apps.py`,
`import_zip`), which would have made a clean app read Blocked.

Now what such a check proves of one item is known of every item of the list, where the check covers every item
and the request is turned away when it fails. Each safe shape stands beside look-alikes that prove nothing and
must still be listed. None of these files comes from the held-out benchmark.
"""
import pytest

from lantern.engine import build_graph

PY = '''import os

from flask import Flask, abort, request

app = Flask(__name__)
FILES = os.path.join(os.path.dirname(__file__), "files")


@app.post("/remove")
def remove():
    names = request.get_json()["names"]
    inside = os.path.realpath(FILES) + os.sep
{body}
    return "removed"
'''
RESOLVED = "    targets = [os.path.realpath(os.path.join(FILES, n)) for n in names]\n"
USE = "    for t in targets:\n        os.remove(t)\n"

JS = '''const express = require('express')
const fs = require('fs')
const path = require('path')

const app = express()
app.use(express.json())
const FILES = path.join(__dirname, 'files')

app.post('/remove', (req, res) => {
  const inside = path.resolve(FILES) + path.sep
  const targets = req.body.names.map((n) => path.resolve(FILES, n))
%s
  res.json({ removed: targets.length })
})

app.listen(3000)
'''
JS_USE = "  for (const t of targets) fs.unlinkSync(t)\n"


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _paths(root, files):
    from lantern import flow
    res = flow.analyze(build_graph(_write(root, files)))
    assert not res.errors, res.errors
    return [f for f in res.flows if f["class"] == "path"]


def _py(root, body):
    return _paths(root, {"requirements.txt": "flask==3.0.0\n", "app.py": PY.format(body=body)})


def _js(root, body):
    return _paths(root, {"package.json": '{"dependencies": {"express": "^4.19.0"}}', "server.js": JS % body})


def test_the_names_are_listed_when_nothing_checks_them(tmp_path):
    """The control: with no check the lines that remove the files are listed, in both languages."""
    assert len(_py(tmp_path / "py", RESOLVED + USE)) == 1
    assert len(_js(tmp_path / "js", JS_USE)) == 1


SAFE = {
    "any item outside the folder refuses the request":
        RESOLVED + "    if any(not t.startswith(inside) for t in targets):\n        abort(400)\n" + USE,
    "not all inside refuses the request":
        RESOLVED + "    if not all(t.startswith(inside) for t in targets):\n        abort(400)\n" + USE,
    "the files are used only where all are inside":
        RESOLVED + "    if all(t.startswith(inside) for t in targets):\n        for t in targets:\n"
                   "            os.remove(t)\n",
    "each item goes with the name it was made from":
        RESOLVED + "    if any(not t.startswith(inside) for t in targets):\n        abort(400)\n"
                   "    for name, target in zip(names, targets):\n        os.remove(target)\n",
    "the check stands in a list of conditions":
        RESOLVED + "    if not names or any(not t.startswith(inside) for t in targets):\n        abort(400)\n" + USE,
}


@pytest.mark.parametrize("case", sorted(SAFE))
def test_a_check_on_every_item_of_the_list_is_a_check(tmp_path, case):
    assert _py(tmp_path, SAFE[case]) == [], case


NEAR = {
    "one item inside is enough":
        RESOLVED + "    if not any(t.startswith(inside) for t in targets):\n        abort(400)\n" + USE,
    "the check is on another list":
        RESOLVED + "    others = [os.path.realpath(os.path.join(FILES, n)) for n in request.args.getlist('n')]\n"
                   "    if any(not t.startswith(inside) for t in others):\n        abort(400)\n" + USE,
    "only the first item is checked":
        RESOLVED + "    if any(not t.startswith(inside) for t in targets[:1]):\n        abort(400)\n" + USE,
    "only some items are checked":
        RESOLVED + "    if any(not t.startswith(inside) for t in targets if t.endswith('.txt')):\n        abort(400)\n"
        + USE,
    "the answer is not acted on":
        RESOLVED + "    bad = any(not t.startswith(inside) for t in targets)\n    print(bad)\n" + USE,
    "the request goes on after the check failed":
        RESOLVED + "    if any(not t.startswith(inside) for t in targets):\n        print('outside')\n" + USE,
    "the check comes after the files are removed":
        RESOLVED + USE + "    if any(not t.startswith(inside) for t in targets):\n        abort(400)\n",
    "the names are not resolved before they are compared":
        "    targets = [os.path.join(FILES, n) for n in names]\n"
        "    if any(not t.startswith(inside) for t in targets):\n        abort(400)\n" + USE,
    "what the names are compared with is the request's too":
        RESOLVED + "    where = os.path.realpath(request.args['folder'])\n"
                   "    if any(not t.startswith(where) for t in targets):\n        abort(400)\n" + USE,
    "the names the items were made from are used, not the items":
        RESOLVED + "    if any(not t.startswith(inside) for t in targets):\n        abort(400)\n"
                   "    for name, target in zip(names, targets):\n        os.remove(os.path.join(FILES, '..', name))\n",
    "a name is added to the list after the check":
        RESOLVED + "    if any(not t.startswith(inside) for t in targets):\n        abort(400)\n"
                   "    targets.append(os.path.join(FILES, request.args['more']))\n" + USE,
    "the check is made through a function handed to map":
        RESOLVED + "    if any(map(lambda t: not t.startswith(inside), targets)):\n        abort(400)\n" + USE,
    "the check is about something else than the item":
        RESOLVED + "    if any(not inside.startswith(t) for t in targets):\n        abort(400)\n" + USE,
}


@pytest.mark.parametrize("case", sorted(NEAR))
def test_a_look_alike_that_proves_nothing_is_still_listed(tmp_path, case):
    found = _py(tmp_path, NEAR[case])
    assert len(found) == 1, (case, [(f["line"], f["sink"]) for f in found])


JS_SAFE = {
    "some item outside refuses":
        "  if (targets.some((t) => !t.startsWith(inside))) return res.status(400).end()\n" + JS_USE,
    "not every item inside refuses":
        "  if (!targets.every((t) => t.startsWith(inside))) {\n    return res.status(400).end()\n  }\n" + JS_USE,
    "a function with a body":
        "  if (targets.some(function (t) { return !t.startsWith(inside) })) return res.status(400).end()\n" + JS_USE,
}
JS_NEAR = {
    "one item inside is enough": "  if (!targets.some((t) => t.startsWith(inside))) return res.status(400).end()\n" + JS_USE,
    "the answer is not acted on": "  const bad = targets.some((t) => !t.startsWith(inside))\n  console.log(bad)\n" + JS_USE,
    "the request goes on": "  if (targets.some((t) => !t.startsWith(inside))) console.log('outside')\n" + JS_USE,
    "only some are looked at":
        "  if (targets.filter((t) => t.endsWith('.txt')).some((t) => !t.startsWith(inside))) return res.status(400).end()\n"
        + JS_USE,
    "a name is added to the list after the check":
        "  if (targets.some((t) => !t.startsWith(inside))) return res.status(400).end()\n"
        "  targets.push(path.join(FILES, req.query.more))\n" + JS_USE,
    "the function says nothing of the item": "  if (targets.some((t) => !inside.startsWith(t))) return res.status(400).end()\n"
                                              + JS_USE,
}


@pytest.mark.parametrize("case", sorted(JS_SAFE))
def test_the_same_in_javascript(tmp_path, case):
    assert _js(tmp_path, JS_SAFE[case]) == [], case


@pytest.mark.parametrize("case", sorted(JS_NEAR))
def test_the_javascript_look_alikes_are_still_listed(tmp_path, case):
    found = _js(tmp_path, JS_NEAR[case])
    assert len(found) == 1, (case, [(f["line"], f["sink"]) for f in found])


CHECK = "        if not t.startswith(inside):\n            abort(400)\n"
LOOP_SAFE = {
    "a loop that turns the request away at the first item outside, then a loop that uses them":
        RESOLVED + "    for t in targets:\n" + CHECK + USE,
    "the loop raises":
        RESOLVED + "    for t in targets:\n        if not t.startswith(inside):\n            raise ValueError(t)\n" + USE,
    "the loop does something else with the item after the check":
        RESOLVED + "    for t in targets:\n" + CHECK + "        print(t)\n" + USE,
    "the loop answers with a refusal":
        RESOLVED + "    for t in targets:\n        if not t.startswith(inside):\n            return 'no', 403\n" + USE,
}
LOOP_NEAR = {
    "an item outside is passed over and the loop goes on":
        RESOLVED + "    for t in targets:\n        if not t.startswith(inside):\n            continue\n        print(t)\n"
        + USE,
    "an item outside is only noted":
        RESOLVED + "    for t in targets:\n        if not t.startswith(inside):\n            print('outside')\n" + USE,
    "the loop stops before it has seen every item":
        RESOLVED + "    for t in targets:\n" + CHECK + "        if t.endswith('.last'):\n            break\n" + USE,
    "some items go round the check":
        RESOLVED + "    for t in targets:\n        if t.endswith('.txt'):\n            continue\n" + CHECK + USE,
    "the loop is over a part of the list":
        RESOLVED + "    for t in targets[:1]:\n" + CHECK + USE,
    "the loop is over another list":
        RESOLVED + "    others = [os.path.realpath(os.path.join(FILES, n)) for n in request.args.getlist('n')]\n"
                   "    for t in others:\n" + CHECK + USE,
    "names are added to the list inside the loop":
        RESOLVED + "    for t in targets:\n" + CHECK +
        "        if os.path.isdir(t):\n            targets.extend(os.path.join(t, n) for n in request.args.getlist('more'))\n"
        + USE,
    "the check says nothing of the item":
        RESOLVED + "    for t in targets:\n        if not inside.startswith(t):\n            abort(400)\n" + USE,
    "the check comes after the files are removed":
        RESOLVED + USE + "    for t in targets:\n" + CHECK,
    "the refusal is caught and the request goes on":
        RESOLVED + "    try:\n        for t in targets:\n            if not t.startswith(inside):\n"
                   "                raise ValueError(t)\n    except ValueError:\n        print('outside')\n" + USE,
    "the loop is left by a function of its own, which the route does not ask":
        RESOLVED + "    look(targets, inside)\n" + USE.rstrip("\n") + "\n    return 'removed'\n\n\n"
                   "def look(targets, inside):\n    for t in targets:\n        if not t.startswith(inside):\n"
                   "            return False\n    return True\n\n\ndef unused():",
}


@pytest.mark.parametrize("case", sorted(LOOP_SAFE))
def test_a_loop_that_checks_every_item_and_turns_the_request_away_is_a_check(tmp_path, case):
    """Found by trying the rule on more shapes of its own examples (2026-11-11): the check written as a loop of its
    own, before the loop that uses the files, was still two lines listed at high."""
    assert _py(tmp_path, LOOP_SAFE[case]) == [], case


@pytest.mark.parametrize("case", sorted(LOOP_NEAR))
def test_a_loop_that_lets_an_item_by_is_still_listed(tmp_path, case):
    found = _py(tmp_path, LOOP_NEAR[case])
    # one line listed; where names are added in the loop, once for each of the two places the names come from
    want = 2 if case == "names are added to the list inside the loop" else 1
    assert len(found) == want and len({f["line"] for f in found}) == 1, (case, [(f["line"], f["sink"]) for f in found])


def test_the_checking_loop_in_javascript(tmp_path):
    safe = "  for (const t of targets) {\n    if (!t.startsWith(inside)) return res.status(400).end()\n  }\n" + JS_USE
    assert _js(tmp_path / "safe", safe) == []
    thrown = "  for (const t of targets) {\n    if (!t.startsWith(inside)) throw new Error('outside')\n  }\n" + JS_USE
    assert _js(tmp_path / "thrown", thrown) == []
    near = "  for (const t of targets) {\n    if (!t.startsWith(inside)) continue\n    console.log(t)\n  }\n" + JS_USE
    assert len(_js(tmp_path / "near", near)) == 1
    part = "  for (const t of targets.slice(1)) {\n    if (!t.startsWith(inside)) return res.status(400).end()\n  }\n"
    assert len(_js(tmp_path / "part", part + JS_USE)) == 1


def test_a_list_made_with_map_holds_what_its_function_gave_back(tmp_path):
    """Found on the way: in JavaScript a list made with `map` kept the request's names beside what the function
    made of them, so a check on each item inside the loop was not seen either. The twin maps the names to
    themselves and is still listed."""
    loop = ("  for (const t of targets) {\n    if (!t.startsWith(inside)) return res.status(400).end()\n"
            "    fs.unlinkSync(t)\n  }\n")
    assert _js(tmp_path / "safe", loop) == []
    same = (JS % loop).replace("req.body.names.map((n) => path.resolve(FILES, n))", "req.body.names.map((n) => n)")
    found = _paths(tmp_path / "same", {"package.json": '{"dependencies": {"express": "^4.19.0"}}', "server.js": same})
    assert len(found) == 1, found


def test_the_benchmarks_own_safe_app_has_no_file_finding(tmp_path):
    """The shape that showed it: names out of an uploaded zip, resolved, checked all at once, then written."""
    code = '''import io
import os
import secrets
import zipfile

from fastapi import FastAPI, HTTPException, Request

app = FastAPI()
UPLOADS = os.path.join(os.path.dirname(__file__), "uploads")


@app.post("/import", status_code=201)
async def import_zip(request: Request):
    data = await request.body()
    archive = zipfile.ZipFile(io.BytesIO(data))
    entries = [e for e in archive.infolist() if not e.is_dir()]
    folder = os.path.join(UPLOADS, "import-" + secrets.token_hex(6))
    inside = os.path.realpath(folder) + os.sep
    targets = [os.path.realpath(os.path.join(folder, e.filename)) for e in entries]
{check}
    for entry, target in zip(entries, targets):
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with archive.open(entry) as src, open(target, "wb") as dst:
            dst.write(src.read())
    return {{"files": len(entries)}}
'''
    check = ("    if any(not t.startswith(inside) for t in targets):\n"
             "        raise HTTPException(400, 'The zip holds a name that leaves its folder')")
    files = {"requirements.txt": "fastapi==0.115.0\n", "app.py": code.format(check=check)}
    assert _paths(tmp_path / "safe", files) == []
    files["app.py"] = code.format(check="    pass")
    assert _paths(tmp_path / "unsafe", files) != []
