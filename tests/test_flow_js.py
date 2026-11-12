"""Following a value across functions (directive point 4, 2026-11-11): JavaScript and TypeScript.

The same engine as `tests/test_flow.py`, fed by the JavaScript reader (`lantern/flow_js.py`). Each dangerous example
sits beside safe twins that must stay clean and near-misses that must still be caught. None of these files is copied
from an app of the held-out benchmark; they were written before the reader was."""

import pytest

from lantern.engine import build_graph

PACKAGE = ('{"dependencies": {"express": "4.19.2", "mysql2": "3.9.7", "axios": "1.7.2", "escape-html": "1.0.3", '
           '"lodash": "4.17.21", "mongoose": "8.4.0", "node-serialize": "0.0.4", "libxmljs": "1.0.11", "pg": "8.11.5", '
           '"next": "14.2.3", "react": "18.3.1", "react-router-dom": "6.23.1"}}')
HEAD = ("const express = require('express')\n"                       # 1
        "const mysql = require('mysql2')\n"                          # 2
        "const { exec, execFile } = require('child_process')\n"      # 3
        "const path = require('path')\n"                             # 4
        "const fs = require('fs')\n"                                 # 5
        "const axios = require('axios')\n"                           # 6
        "const escapeHtml = require('escape-html')\n"                # 7
        "const app = express()\n"                                    # 8
        "const pool = mysql.createPool({ host: 'localhost' })\n"     # 9
        "const BASE = path.join(__dirname, 'files')\n"               # 10
        "const ALLOWED = ['/home', '/account']\n"                    # 11
        "const HOSTS = new Set(['api.example.com'])\n"               # 12
        "\n")                                                        # 13: a case's first line is 14


def _write(root, files):
    for rel, text in {"package.json": PACKAGE, **files}.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _flows(root, files):
    from lantern import flow
    _write(root, files)
    res = flow.analyze(build_graph(root))
    assert not res.errors, res.errors
    return res.flows


def _kinds(flows):
    return sorted({f["class"] for f in flows})


def _route(body, verb="get", url="/x"):
    return f"app.{verb}('{url}', (req, res) => {{\n{body}}})\n"


def _check(tmp_path, cases, case, head=HEAD):
    body, want = cases[case]
    flows = _flows(tmp_path, {"server.js": head + body})
    assert _kinds(flows) == want, flows
    return flows


# ------------------------------------------------------------- one request value through three files to a query

APP = {
    "server.js": ("const express = require('express')\nconst routes = require('./routes/main')\nconst app = express()\n"
                  "app.use(express.json())\napp.use('/api', routes)\napp.listen(3000)\n"),
    "routes/main.js": ("const router = require('express').Router()\nconst handlers = require('../core/handlers')\n\n"
                       "router.get('/users', handlers.search)\nmodule.exports = router\n"),
    "core/handlers.js": ("const db = require('./db')\n\nmodule.exports.search = function (req, res) {\n"
                         "  const name = req.query.name.trim()\n  db.findUsers(name, function (err, rows) {\n"
                         "    res.json(rows)\n  })\n}\n"),
    "core/db.js": ("const mysql = require('mysql2')\nconst pool = mysql.createPool({ host: 'localhost' })\n\n"
                   "function findUsers (name, cb) {\n"
                   "  const sql = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n"
                   "  pool.query(sql, cb)\n}\n\nmodule.exports = { findUsers }\n"),
}


def test_a_request_value_is_followed_from_a_handler_through_another_file_to_the_query(tmp_path):
    flows = _flows(tmp_path, APP)
    assert [f["class"] for f in flows] == ["sql"], flows
    f = flows[0]
    assert (f["file"], f["line"]) == ("core/db.js", 6)                 # pool.query(sql, cb)
    assert f["source"]["file"] == "core/handlers.js" and "`name`" in f["source"]["what"], f["source"]
    words = " | ".join(s["what"] for s in f["steps"])
    assert "findUsers" in words and "database query" in words, words
    assert f["steps"][0]["file"] == "core/handlers.js" and f["steps"][-1]["file"] == "core/db.js"


def test_the_same_app_with_the_value_handed_to_the_driver_apart_is_clean(tmp_path):
    files = dict(APP)
    files["core/db.js"] = APP["core/db.js"].replace(
        "\"SELECT * FROM users WHERE name = '\" + name + \"'\"", "'SELECT * FROM users WHERE name = ?'").replace(
        "pool.query(sql, cb)", "pool.query(sql, [name], cb)")
    assert _flows(tmp_path, files) == []


# A handler written inside the call that registers it is read as part of the code around it. The function it calls
# may be in a file that is read later: the handler's file has to be read again once that function is known. (Until
# 2026-11-11 it was not, and such a flow was missed or found depending on the files' names.)
INLINE_SERVER = ("const express = require('express')\nconst { findUsers } = require('./{dir}/db')\n"
                 "const app = express()\n\napp.get('/users', (req, res) => {\n"
                 "  findUsers(req.query.name, (err, rows) => res.json(rows))\n})\napp.listen(3000)\n")


@pytest.mark.parametrize("folder", ["core", "lib", "util", "zz"])
def test_a_handler_written_inline_that_calls_into_another_file(tmp_path, folder):
    flows = _flows(tmp_path, {"server.js": INLINE_SERVER.replace("{dir}", folder),
                              f"{folder}/db.js": APP["core/db.js"]})
    assert [(f["class"], f["file"], f["line"]) for f in flows] == [("sql", f"{folder}/db.js", 6)], flows
    assert flows[0]["source"]["file"] == "server.js", flows


@pytest.mark.parametrize("name", ["app.js", "index.js", "server.js", "zserver.js"])
def test_the_same_whatever_the_handlers_file_is_called(tmp_path, name):
    flows = _flows(tmp_path, {name: INLINE_SERVER.replace("{dir}", "lib"), "lib/db.js": APP["core/db.js"]})
    assert [(f["class"], f["file"]) for f in flows] == [("sql", "lib/db.js")], flows


# ------------------------------------------------------------- database queries

SQL = {
    "caught: a template string":
        (_route("  pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`, (e, rows) => res.json(rows))\n"),
         ["sql"]),
    "clean: the driver gets the value apart":
        (_route("  pool.query('SELECT * FROM users WHERE id = ?', [req.params.id], (e, rows) => res.json(rows))\n"), []),
    "clean: made a number first":
        (_route("  const id = parseInt(req.params.id, 10)\n"
                "  pool.query(`SELECT * FROM users WHERE id = ${id}`, (e, rows) => res.json(rows))\n"), []),
    "caught: escaped for a page, then used in a query":
        (_route("  const id = escapeHtml(req.params.id)\n"
                "  pool.query(`SELECT * FROM users WHERE id = '${id}'`, (e, rows) => res.json(rows))\n"), ["sql"]),
    "clean: escaped for the database":
        (_route("  const id = pool.escape(req.params.id)\n"
                "  pool.query(`SELECT * FROM users WHERE id = ${id}`, (e, rows) => res.json(rows))\n"), []),
    "clean: who is signed in is not request data":
        (_route("  pool.query(`SELECT * FROM orders WHERE owner = ${req.user.id}`, (e, rows) => res.json(rows))\n"), []),
    "caught: taken apart from the query string":
        (_route("  const { name } = req.query\n"
                "  pool.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\", (e, rows) => res.json(rows))\n"),
         ["sql"]),
    "caught: the check comes after the query":
        (_route("  const sort = req.query.sort\n"
                "  pool.query('SELECT * FROM users ORDER BY ' + sort, (e, rows) => res.json(rows))\n"
                "  if (!['name', 'age'].includes(sort)) return res.status(400).end()\n"), ["sql"]),
    "clean: the check comes first":
        (_route("  const sort = req.query.sort\n"
                "  if (!['name', 'age'].includes(sort)) return res.status(400).end()\n"
                "  pool.query('SELECT * FROM users ORDER BY ' + sort, (e, rows) => res.json(rows))\n"), []),
    "caught: a database library Lantern has no table for, by the method's name and what the text reads like":
        ("const acme = require('acme-db')\n" +
         _route("  acme.query(\"SELECT * FROM users WHERE name = '\" + req.query.name + \"'\").then((r) => res.json(r))\n"),
         ["sql"]),
    "clean: the same library handed text that is no query":
        ("const acme = require('acme-db')\n" +
         _route("  acme.get('/status/' + req.query.name).then((r) => res.json(r))\n"), []),
    "caught: a method of a class the handler calls":
        ("class Users {\n  constructor (db) { this.db = db }\n\n  byName (name) {\n"
         "    return this.db.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n  }\n}\n"
         "const users = new Users(pool)\n"
         "app.get('/users', async (req, res) => {\n  res.json(await users.byName(req.query.name))\n})\n", ["sql"]),
    "caught: an async helper and await":
        ("async function find (q) {\n  const [rows] = await pool.query(\"SELECT * FROM t WHERE c LIKE '%\" + q + \"%'\")\n"
         "  return rows\n}\n"
         "app.get('/find', async (req, res) => {\n  const rows = await find(req.query.q)\n  res.json(rows)\n})\n",
         ["sql"]),
}


@pytest.mark.parametrize("case", sorted(SQL))
def test_queries(tmp_path, case):
    _check(tmp_path, SQL, case)


# ------------------------------------------------------------- pages

XSS = {
    "caught: text with the value in it sent as a page":
        (_route("  res.send('<h1>Hello ' + req.query.name + '</h1>')\n"), ["xss"]),
    "clean: escaped for a page":
        (_route("  res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>')\n"), []),
    "clean: sent as JSON":
        (_route("  res.json({ name: req.query.name })\n"), []),
    "clean: a template the view engine escapes":
        (_route("  res.render('hello', { name: req.query.name })\n"), []),
    "caught: escaped for a query, then sent as a page":
        (_route("  res.send('<p>' + pool.escape(req.query.name) + '</p>')\n"), ["xss"]),
    "clean: a number":
        (_route("  res.send('<p>Page ' + Number(req.query.page) + '</p>')\n"), []),
    "clean: what the database gave back is not what the request sent":
        (_route("  pool.query('SELECT name FROM users WHERE id = ?', [req.query.id], (e, rows) => {\n"
                "    res.send('<p>' + rows[0].name + '</p>')\n  })\n"), []),
}


@pytest.mark.parametrize("case", sorted(XSS))
def test_pages(tmp_path, case):
    flows = _check(tmp_path, XSS, case)
    if flows:
        assert (flows[0]["file"], flows[0]["line"]) == ("server.js", 15), flows


# A page escaped by hand, or sent as something that is no page. 2026-11-11: the first measurement on the held-out set
# showed a false alarm on a safe page. The held-out app was not read; 29 shapes were written here instead, and the
# engine was wrong on these two kinds, each kept beside its near-misses.
ESC = ("function esc (s) {\n  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')"
       ".replace(/\"/g, '&quot;')\n}\n")
ESC_MAP = ("const ENTITIES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;' }\n"
           "function esc (s) {\n  return String(s).replace(/[&<>\"]/g, (c) => ENTITIES[c])\n}\n")
HELLO = _route("  res.send('<h1>Hello ' + esc(req.query.name) + '</h1>')\n")
BY_HAND = {
    "clean: the project's own escape, which replaces every <":
        (ESC + HELLO, []),
    "clean: the same escape, with a table of what each character becomes":
        (ESC_MAP + HELLO, []),
    "clean: the own escape inside the text of a template literal":
        (ESC + _route("  res.send(`<h1>Hello ${esc(req.query.name)}</h1>`)\n"), []),
    "clean: every < is taken out":
        (_route("  res.send('<h1>Hello ' + req.query.name.replace(/[<>]/g, '') + '</h1>')\n"), []),
    "caught: an escape that replaces the first < only":       # replace with a text, not a pattern: once
        ("function esc (s) {\n  return String(s).replace('<', '&lt;')\n}\n" + HELLO, ["xss"]),
    "caught: a pattern without g replaces the first < only":
        ("function esc (s) {\n  return String(s).replace(/</, '&lt;')\n}\n" + HELLO, ["xss"]),
    "caught: an escape that forgets <":
        ("function esc (s) {\n  return String(s).replace(/&/g, '&amp;').replace(/\"/g, '&quot;')\n}\n" + HELLO,
         ["xss"]),
    "caught: an escape that puts a tag where < was":
        ("function esc (s) {\n  return String(s).replace(/</g, '<b>')\n}\n" + HELLO, ["xss"]),
    "caught: the table gives < back":
        ("const ENTITIES = { '&': '&amp;', '<': '<' }\n"
         "function esc (s) {\n  return String(s).replace(/[&<]/g, (c) => ENTITIES[c])\n}\n" + HELLO, ["xss"]),
    "caught: every < but the ones in the value's first line":       # a pattern that does not stand for < alone
        ("function esc (s) {\n  return String(s).replace(/\\n.*</g, '&lt;')\n}\n" + HELLO, ["xss"]),
    "caught: escaped for a page by hand, then put into a query":
        (ESC + _route("  pool.query(\"SELECT * FROM users WHERE name = '\" + esc(req.query.name) + \"'\", "
                      "(e, rows) => res.json(rows))\n"), ["sql"]),
    "clean: sent as plain text":
        (_route("  res.type('text/plain').send('Hello ' + req.query.name)\n"), []),
    "clean: the kind of answer is set to plain text first":
        (_route("  res.set('Content-Type', 'text/plain')\n  res.send('Hello ' + req.query.name)\n"), []),
    "clean: JSON written by hand, with its kind set":
        (_route("  res.setHeader('Content-Type', 'application/json')\n"
                "  res.end(JSON.stringify({ name: req.query.name }))\n"), []),
    "clean: plain text, after the status":
        (_route("  res.status(200).type('txt').send('Hello ' + req.query.name)\n"), []),
    "caught: the kind of answer is set to a page":
        (_route("  res.type('html').send('<h1>Hello ' + req.query.name + '</h1>')\n"), ["xss"]),
    "caught: plain text on one way only":
        (_route("  if (req.query.plain) res.type('text/plain')\n  res.send('Hello ' + req.query.name)\n"), ["xss"]),
    "caught: the kind is set after the text was sent":
        (_route("  res.send('Hello ' + req.query.name)\n  res.type('text/plain')\n"), ["xss"]),
    "caught: plain text was set, then a page":
        (_route("  res.type('text/plain')\n  res.type('html')\n  res.send('<p>' + req.query.name + '</p>')\n"),
         ["xss"]),
    "caught: another header is set to plain text":
        (_route("  res.set('X-Kind', 'text/plain')\n  res.send('Hello ' + req.query.name)\n"), ["xss"]),
}


@pytest.mark.parametrize("case", sorted(BY_HAND))
def test_a_page_escaped_by_hand_or_sent_as_plain_text(tmp_path, case):
    _check(tmp_path, BY_HAND, case)


# ------------------------------------------------------------- redirects

REDIRECT = {
    "caught: the request says where to go":
        (_route("  res.redirect(req.query.next)\n"), ["redirect"]),
    "clean: one of the app's own addresses, checked first":
        (_route("  const next = req.query.next\n  if (!ALLOWED.includes(next)) return res.status(400).end()\n"
                "  res.redirect(next)\n"), []),
    "caught: the check comes after the redirect":
        (_route("  const next = req.query.next\n  res.redirect(next)\n"
                "  if (!ALLOWED.includes(next)) return res.status(400).end()\n"), ["redirect"]),
    "caught: starting with one slash is not enough":
        (_route("  const next = req.query.next\n  if (!next.startsWith('/')) return res.status(400).end()\n"
                "  res.redirect(next)\n"), ["redirect"]),
    "clean: one slash and not two":
        (_route("  const next = req.query.next\n"
                "  if (!next.startsWith('/') || next.startsWith('//')) return res.status(400).end()\n"
                "  res.redirect(next)\n"), []),
    "clean: the value is only a part after the app's own path":
        (_route("  res.redirect('/login?next=' + encodeURIComponent(req.query.next))\n"), []),
}


@pytest.mark.parametrize("case", sorted(REDIRECT))
def test_redirects(tmp_path, case):
    _check(tmp_path, REDIRECT, case)


# ------------------------------------------------------------- outbound requests

NET = ("const dns = require('dns/promises')\n"
       "const net = require('net')\n"
       "const inside = new net.BlockList()\n"
       "inside.addSubnet('10.0.0.0', 8, 'ipv4')\n"
       "inside.addSubnet('127.0.0.0', 8, 'ipv4')\n"
       "inside.addSubnet('169.254.0.0', 16, 'ipv4')\n"
       "async function isOutside (url) {\n"
       "  const { address, family } = await dns.lookup(new URL(url).hostname)\n"
       "  return !inside.check(address, family === 6 ? 'ipv6' : 'ipv4')\n"
       "}\n")
FETCH = "  const r = await fetch(req.query.url)\n  res.json(await r.json())\n"


def _later(body):
    return _route(body).replace("(req, res)", "async (req, res)")


SSRF = {
    "caught: the request gives the address":
        (_route("  axios.get(req.query.url).then((r) => res.json(r.data))\n"), ["ssrf"]),
    "clean: the host is fixed text":
        (_route("  axios.get('https://api.example.com/users/' + req.query.id).then((r) => res.json(r.data))\n"), []),
    "clean: the host is looked up in a list first":
        (_route("  const u = new URL(req.query.url)\n  if (!HOSTS.has(u.hostname)) return res.status(400).end()\n"
                "  axios.get(u.href).then((r) => res.json(r.data))\n"), []),
    "caught: a function named validate that proves nothing":
        ("function validateUrl (u) {\n  return u.trim()\n}\n" +
         _route("  axios.get(validateUrl(req.query.url)).then((r) => res.json(r.data))\n"), ["ssrf"]),
    "clean: a check of the host in a function of its own":
        ("function allowed (u) {\n  return HOSTS.has(new URL(u).hostname)\n}\n" +
         _route("  if (!allowed(req.query.url)) return res.status(400).end()\n"
                "  axios.get(req.query.url).then((r) => res.json(r.data))\n"), []),
    "caught: fetch with the address from the body":
        (_route("  const r = await fetch(req.body.target)\n  res.json(await r.json())\n", "post").replace(
            "(req, res)", "async (req, res)"), ["ssrf"]),
    # the other proper guard: the name is looked up, and the address it leads to must not be inside the network
    "clean: the name is looked up and an address inside the network is refused":
        (NET + _later("  if (!(await isOutside(req.query.url))) return res.status(400).end()\n" + FETCH), []),
    "caught: the same check, asked about another value":
        (NET + _later("  if (!(await isOutside(req.query.other))) return res.status(400).end()\n" + FETCH), ["ssrf"]),
    "clean: a library says whether the address is inside the network":
        (NET + "const ipTool = require('ip')\n" +
         _later("  const { address } = await dns.lookup(new URL(req.query.url).hostname)\n"
                "  if (ipTool.isPrivate(address)) return res.status(400).end()\n" + FETCH), []),
    "clean: the kind of address is asked of a library":
        (NET + "const ipaddr = require('ipaddr.js')\n" +
         _later("  const { address } = await dns.lookup(new URL(req.query.url).hostname)\n"
                "  if (ipaddr.parse(address).range() !== 'unicast') return res.status(400).end()\n" + FETCH), []),
    "caught: a function of the project named isPrivate that proves nothing":
        (NET + "function isPrivate (a) {\n  return a.length === 0\n}\n" +
         _later("  const { address } = await dns.lookup(new URL(req.query.url).hostname)\n"
                "  if (isPrivate(address)) return res.status(400).end()\n" + FETCH), ["ssrf"]),
    "caught: the host name itself is asked, and a name is no address":
        (NET + "const ipTool = require('ip')\n" +
         _later("  const host = new URL(req.query.url).hostname\n"
                "  if (ipTool.isPrivate(host)) return res.status(400).end()\n" + FETCH), ["ssrf"]),
    "caught: the block list is asked about the host name":
        (NET + _later("  const host = new URL(req.query.url).hostname\n"
                      "  if (inside.check(host)) return res.status(400).end()\n" + FETCH), ["ssrf"]),
    "caught: the name is looked up and nothing is asked about the address":
        (NET + _later("  const { address } = await dns.lookup(new URL(req.query.url).hostname)\n"
                      "  console.log(address)\n" + FETCH), ["ssrf"]),
    # the list guard in the shapes people write it (2026-11-11, see tests/test_flow.py)
    "clean: the answer is kept in a variable and asked afterwards":
        (_later("  const ok = HOSTS.has(new URL(req.query.url).hostname)\n"
                "  if (!ok) return res.status(400).end()\n" + FETCH), []),
    "caught: the answer kept in the variable is about another value":
        (_later("  const ok = HOSTS.has(new URL(req.query.other).hostname)\n"
                "  if (!ok) return res.status(400).end()\n" + FETCH), ["ssrf"]),
    "caught: the answer is asked the wrong way round":
        (_later("  const ok = HOSTS.has(new URL(req.query.url).hostname)\n"
                "  if (ok) return res.status(400).end()\n" + FETCH), ["ssrf"]),
    "clean: the host is lower-cased first, with an empty text when there is none":
        (_later("  const host = (new URL(req.query.url).hostname || '').toLowerCase()\n"
                "  if (!HOSTS.has(host)) return res.status(400).end()\n" + FETCH), []),
    "clean: the host must end with the site's own name, dot first":
        (_later("  const host = new URL(req.query.url).hostname\n"
                "  if (!host.endsWith('.example.com')) return res.status(400).end()\n" + FETCH), []),
    "caught: the host must end with the name, with no dot before it":
        (_later("  const host = new URL(req.query.url).hostname\n"
                "  if (!host.endsWith('example.com')) return res.status(400).end()\n" + FETCH), ["ssrf"]),
    "caught: the whole address must end with the name":
        (_later("  if (!req.query.url.endsWith('.example.com')) return res.status(400).end()\n" + FETCH), ["ssrf"]),
    "clean: a fixed site, the value only in the path after it":
        (_later("  const r = await fetch(new URL(`/v1/items/${req.query.id}`, 'https://api.example.com'))\n"
                "  res.json(await r.json())\n"), []),
    "caught: a fixed site, but the value may be a whole address":
        (_later("  const r = await fetch(new URL(req.query.path, 'https://api.example.com'))\n"
                "  res.json(await r.json())\n"), ["ssrf"]),
    "caught: a fixed path on a site the request names":
        (_later("  const r = await fetch(new URL('/v1/items', req.query.site))\n"
                "  res.json(await r.json())\n"), ["ssrf"]),
}


@pytest.mark.parametrize("case", sorted(SSRF))
def test_outbound_requests(tmp_path, case):
    _check(tmp_path, SSRF, case)


# ------------------------------------------------------------- commands

SHELL = {
    "caught: put into a shell command":
        (_route("  exec('ping -c 1 ' + req.query.host, (e, out) => res.type('text').send(out))\n"), ["shell"]),
    "clean: no shell, and the program is fixed":
        (_route("  execFile('ping', ['-c', '1', req.query.host], (e, out) => res.type('text').send(out))\n"), []),
    "caught: the library is asked for on the line that uses it":
        (_route("  require('child_process').exec('ping -c 1 ' + req.query.host, (e, out) => res.type('text').send(out))\n"),
         ["shell"]),
    "caught: the request chooses the program":
        (_route("  execFile(req.query.tool, ['-v'], (e, out) => res.type('text').send(out))\n"), ["shell"]),
    "clean: a pattern that bounds the whole value":
        (_route("  const host = req.query.host\n  if (!/^[\\w.-]+$/.test(host)) return res.status(400).end()\n"
                "  exec('ping -c 1 ' + host, (e, out) => res.type('text').send(out))\n"), []),
    "caught: a pattern that only has to match somewhere":
        (_route("  const host = req.query.host\n  if (!/[\\w.-]+/.test(host)) return res.status(400).end()\n"
                "  exec('ping -c 1 ' + host, (e, out) => res.type('text').send(out))\n"), ["shell"]),
    "caught: escaped for a page, then put into a command":
        (_route("  exec('ping -c 1 ' + escapeHtml(req.query.host), (e, out) => res.type('text').send(out))\n"),
         ["shell"]),
}


@pytest.mark.parametrize("case", sorted(SHELL))
def test_commands(tmp_path, case):
    _check(tmp_path, SHELL, case)


# ------------------------------------------------------------- files

PATHS = {
    "caught: joined to a folder":
        (_route("  res.sendFile(path.join(BASE, req.params.name))\n", url="/files/:name"), ["path"]),
    "clean: only the last part of the name":
        (_route("  res.sendFile(path.join(BASE, path.basename(req.params.name)))\n", url="/files/:name"), []),
    "clean: express keeps it under a root":
        (_route("  res.sendFile(req.params.name, { root: BASE })\n", url="/files/:name"), []),
    "caught: read with fs":
        (_route("  fs.readFile(path.join(BASE, req.query.f), 'utf8', (e, d) => res.type('text').send(d))\n"), ["path"]),
    "caught: no dot-dot, then opened as it is (a full path still gets out)":
        (_route("  const f = req.query.f\n  if (f.includes('..')) return res.status(400).end()\n"
                "  fs.readFile(f, 'utf8', (e, d) => res.type('text').send(d))\n"), ["path"]),
    "clean: no dot-dot, then glued after the folder":
        (_route("  const f = req.query.f\n  if (f.includes('..')) return res.status(400).end()\n"
                "  fs.readFile(BASE + '/' + f, 'utf8', (e, d) => res.type('text').send(d))\n"), []),
    "clean: resolved, then kept under the folder":
        (_route("  const p = path.resolve(BASE, req.query.f)\n"
                "  if (!p.startsWith(BASE + path.sep)) return res.status(403).end()\n"
                "  fs.readFile(p, 'utf8', (e, d) => res.type('text').send(d))\n"), []),
    "caught: glued together, where starting with the folder proves nothing":
        (_route("  const p = BASE + '/' + req.query.f\n"
                "  if (!p.startsWith(BASE)) return res.status(403).end()\n"
                "  fs.readFile(p, 'utf8', (e, d) => res.type('text').send(d))\n"), ["path"]),
    "clean: no dot-dot, then joined (join does not start again at a full path)":
        (_route("  const f = req.query.f\n  if (f.includes('..')) return res.status(400).end()\n"
                "  fs.readFile(path.join(BASE, f), 'utf8', (e, d) => res.type('text').send(d))\n"), []),
    "caught: no dot-dot, then resolved (resolve starts again at a full path)":
        (_route("  const f = req.query.f\n  if (f.includes('..')) return res.status(400).end()\n"
                "  fs.readFile(path.resolve(BASE, f), 'utf8', (e, d) => res.type('text').send(d))\n"), ["path"]),
}


@pytest.mark.parametrize("case", sorted(PATHS))
def test_files(tmp_path, case):
    _check(tmp_path, PATHS, case)


# The everyday safe helper, with the folder as its parameter (see the same section of `tests/test_flow.py`).
INSIDE = ("function inside (folder, name) {\n  const full = path.resolve(folder, name)\n"
          "  if (!full.startsWith(folder + path.sep)) throw new Error('outside')\n  return full\n}\n")
SEND = _route("  res.sendFile(inside(BASE, req.query.name))\n")
FOLDER = {
    "clean: the helper works the path out and compares it with its folder":
        (INSIDE + SEND, []),
    "clean: the folder is worked out first, then compared":
        ("function inside (folder, name) {\n  const root = path.resolve(folder)\n"
         "  const full = path.resolve(root, name)\n"
         "  if (!full.startsWith(root + path.sep)) throw new Error('outside')\n  return full\n}\n" + SEND, []),
    "caught: glued together, where starting with the folder proves nothing":
        ("function inside (folder, name) {\n  const full = folder + '/' + name\n"
         "  if (!full.startsWith(folder)) throw new Error('outside')\n  return full\n}\n" + SEND, ["path"]),
    "caught: the request chooses the folder too, and the check compares with what it chose":
        (INSIDE + _route("  res.sendFile(inside(req.query.folder, req.query.name))\n"), ["path"]),
    "clean: the way from the folder to the path, kept in a name, must not begin with two dots":
        ("function inside (folder, name) {\n  const full = path.resolve(folder, name)\n"
         "  const rel = path.relative(folder, full)\n"
         "  if (rel.startsWith('..') || path.isAbsolute(rel)) throw new Error('outside')\n  return full\n}\n" + SEND,
         []),
    "caught: the way from the folder is worked out and never looked at":
        ("function inside (folder, name) {\n  const full = path.resolve(folder, name)\n"
         "  const rel = path.relative(folder, full)\n"
         "  if (rel.length > 200) throw new Error('too long')\n  return full\n}\n" + SEND, ["path"]),
    "clean: a yes-or-no helper that is handed the folder":
        ("function stays (folder, full) {\n  return path.resolve(full).startsWith(path.resolve(folder) + path.sep)\n}\n" +
         _route("  const full = path.join(BASE, req.query.name)\n"
                "  if (!stays(BASE, full)) return res.status(400).end()\n  res.sendFile(full)\n"), []),
}


@pytest.mark.parametrize("case", sorted(FOLDER))
def test_a_check_against_a_folder_that_is_a_parameter(tmp_path, case):
    _check(tmp_path, FOLDER, case)


# ------------------------------------------------------------- an uploaded archive, unpacked entry by entry
# The names of the entries inside an archive are whatever its maker wrote (`../../etc/cron.d/x`): written to disk
# where the name says, they land outside the folder. Added 2026-11-11: until then no archive was followed in
# JavaScript at all.
ZIP_HEAD = HEAD + ("const multer = require('multer')\nconst AdmZip = require('adm-zip')\n"
                   "const unzipper = require('unzipper')\nconst upload = multer({ dest: 'tmp/' })\n")
UP = "app.post('/import', upload.single('archive'), async (req, res) => {\n"
ARCHIVES = {
    "caught: each entry is written where its name says":
        (UP + "  const zip = new AdmZip(req.file.buffer)\n  for (const entry of zip.getEntries()) {\n"
              "    fs.writeFileSync(path.join(BASE, entry.entryName), entry.getData())\n  }\n  res.end()\n})\n",
         ["path"]),
    "caught: the archive is opened by the path the upload was kept under":
        (UP + "  const zip = new AdmZip(req.file.path)\n  zip.getEntries().forEach((entry) => {\n"
              "    fs.writeFileSync(path.join(BASE, entry.entryName), entry.getData())\n  })\n  res.end()\n})\n",
         ["path"]),
    "caught: read as a stream, each entry piped to a file named after it":
        (UP + "  fs.createReadStream(req.file.path)\n    .pipe(unzipper.Parse())\n    .on('entry', (entry) => {\n"
              "      entry.pipe(fs.createWriteStream(path.join(BASE, entry.path)))\n    })\n  res.end()\n})\n",
         ["path"]),
    "caught: opened from the buffer, each file written under its own path":
        (UP + "  const directory = await unzipper.Open.buffer(req.file.buffer)\n"
              "  for (const file of directory.files) {\n"
              "    fs.writeFileSync(path.join(BASE, file.path), await file.buffer())\n  }\n  res.end()\n})\n",
         ["path"]),
    "clean: an entry that would land outside the folder is passed over":
        (UP + "  const zip = new AdmZip(req.file.buffer)\n  for (const entry of zip.getEntries()) {\n"
              "    const target = path.resolve(BASE, entry.entryName)\n"
              "    if (!target.startsWith(BASE + path.sep)) continue\n"
              "    fs.writeFileSync(target, entry.getData())\n  }\n  res.end()\n})\n", []),
    "clean: only the last part of each entry's name is used":
        (UP + "  const zip = new AdmZip(req.file.buffer)\n  for (const entry of zip.getEntries()) {\n"
              "    fs.writeFileSync(path.join(BASE, path.basename(entry.entryName)), entry.getData())\n  }\n"
              "  res.end()\n})\n", []),
    "clean: an archive of the server's own":
        (UP + "  const zip = new AdmZip(path.join(BASE, 'seed.zip'))\n  for (const entry of zip.getEntries()) {\n"
              "    fs.writeFileSync(path.join(BASE, entry.entryName), entry.getData())\n  }\n  res.end()\n})\n", []),
    "clean: the entries are only counted":
        (UP + "  const zip = new AdmZip(req.file.buffer)\n  res.json({ entries: zip.getEntries().length })\n})\n", []),
    "caught: a function in another part of the file is handed the buffer and the folder":
        ("function unpack (buffer, dest) {\n  const zip = new AdmZip(buffer)\n  zip.getEntries().forEach((entry) => {\n"
         "    fs.writeFileSync(path.join(dest, entry.entryName), entry.getData())\n  })\n}\n" +
         UP + "  unpack(req.file.buffer, BASE)\n  res.end()\n})\n", ["path"]),
}


@pytest.mark.parametrize("case", sorted(ARCHIVES))
def test_an_uploaded_archive_and_the_names_inside_it(tmp_path, case):
    _check(tmp_path, ARCHIVES, case, head=ZIP_HEAD)


UNPACK_HEAD = "const fs = require('fs')\nconst path = require('path')\nconst AdmZip = require('adm-zip')\n\n"
UNPACKS = {
    "caught: the helper writes each entry where its name says":
        ("exports.unpack = function (buffer, dest) {\n  const zip = new AdmZip(buffer)\n"
         "  zip.getEntries().forEach((entry) => {\n"
         "    fs.writeFileSync(path.join(dest, entry.entryName), entry.getData())\n  })\n}\n",
         [("path", "lib/archive.js", 8)]),
    "clean: the helper uses only the last part of each entry's name":
        ("exports.unpack = function (buffer, dest) {\n  const zip = new AdmZip(buffer)\n"
         "  zip.getEntries().forEach((entry) => {\n"
         "    fs.writeFileSync(path.join(dest, path.basename(entry.entryName)), entry.getData())\n  })\n}\n", []),
    "clean: the helper only counts the entries":
        ("exports.unpack = function (buffer, dest) {\n  const zip = new AdmZip(buffer)\n"
         "  return zip.getEntries().length\n}\n", []),
}


@pytest.mark.parametrize("case", sorted(UNPACKS))
def test_an_uploaded_archive_handed_to_a_helper_in_another_file(tmp_path, case):
    helper, want = UNPACKS[case]
    flows = _flows(tmp_path, {
        "server.js": ZIP_HEAD + "const { unpack } = require('./lib/archive')\n" + UP +
                     "  unpack(req.file.buffer, BASE)\n  res.end()\n})\n",
        "lib/archive.js": UNPACK_HEAD + helper})
    assert [(f["class"], f["file"], f["line"]) for f in flows] == want, flows
    if want:
        assert flows[0]["source"]["file"] == "server.js", flows


# ------------------------------------------------------------- code, stored objects, XML, filters, merged objects

OTHER_HEAD = HEAD + ("const serialize = require('node-serialize')\nconst libxmljs = require('libxmljs')\n"
                     "const _ = require('lodash')\nconst User = require('./models/user')\nconst settings = {}\n\n")
MODEL = {"models/user.js": "const mongoose = require('mongoose')\n"
                           "module.exports = mongoose.model('User', new mongoose.Schema({ name: String }))\n"}
OTHER = {
    "caught: text from the request run as code":
        (_route("  res.json({ result: eval(req.body.expr) })\n", "post"), ["eval"]),
    "caught: a function built from request text":
        (_route("  const f = new Function('x', req.body.code)\n  res.json({ result: f(1) })\n", "post"), ["eval"]),
    "clean: read as JSON":
        (_route("  res.json({ result: JSON.parse(req.body.text) })\n", "post"), []),
    "caught: an object rebuilt from a cookie":
        (_route("  const profile = serialize.unserialize(req.cookies.profile)\n  res.json(profile)\n"), ["deserialize"]),
    "caught: XML read with outside references switched on":
        (_route("  const doc = libxmljs.parseXml(req.body.xml, { noent: true })\n  res.json({ root: doc.root().name() })\n",
                "post"), ["xxe"]),
    "clean: XML read with the parser's safe defaults":
        (_route("  const doc = libxmljs.parseXml(req.body.xml)\n  res.json({ root: doc.root().name() })\n", "post"), []),
    "caught: a database filter straight from the body":
        (_route("  User.findOne({ name: req.body.name, password: req.body.password }).then((u) => res.json(u))\n",
                "post"), ["nosql"]),
    "clean: a database filter made of text":
        (_route("  User.findOne({ name: String(req.body.name), password: String(req.body.password) })\n"
                "    .then((u) => res.json(u))\n", "post"), []),
    "clean: a database filter whose type was checked first":
        (_route("  const { name, password } = req.body\n"
                "  if (typeof name !== 'string' || typeof password !== 'string') return res.status(400).end()\n"
                "  User.findOne({ name, password }).then((u) => res.json(u))\n", "post"), []),
    "clean: a part of the address is always text":
        (_route("  User.findOne({ _id: req.params.id }).then((u) => res.json(u))\n", url="/u/:id"), []),
    "caught: request text inside a filter the database runs as code":
        (_route("  User.find({ $where: \"this.name == '\" + req.query.name + \"'\" }).then((u) => res.json(u))\n"),
         ["nosql"]),
    "caught: an object from the request merged into the app's own":
        (_route("  _.merge(settings, req.body)\n  res.json(settings)\n", "post"), ["pollution"]),
    "clean: fixed objects merged":
        (_route("  res.json(_.merge({}, { theme: 'dark' }, { size: 2 }))\n"), []),
}


@pytest.mark.parametrize("case", sorted(OTHER))
def test_code_objects_xml_filters_and_merges(tmp_path, case):
    body, want = OTHER[case]
    flows = _flows(tmp_path, {"server.js": OTHER_HEAD + body, **MODEL})
    assert _kinds(flows) == want, flows


# ------------------------------------------------------------- TypeScript, a Next.js route

NEXT = {
    "lib/db.ts": "import { Pool } from 'pg'\n\nexport const db = new Pool()\n",
    "app/api/users/route.ts": (
        "import { NextRequest, NextResponse } from 'next/server'\nimport { db } from '../../../lib/db'\n\n"
        "export async function GET (request: NextRequest) {\n"
        "  const q = request.nextUrl.searchParams.get('q')\n"
        "  const rows = await db.query(`SELECT * FROM users WHERE name LIKE '%${q}%'`)\n"
        "  return NextResponse.json(rows)\n}\n"),
}


def test_a_typed_request_in_a_next_route_is_followed_to_the_query(tmp_path):
    flows = _flows(tmp_path, NEXT)
    assert [(f["class"], f["file"], f["line"]) for f in flows] == [("sql", "app/api/users/route.ts", 6)], flows


def test_the_same_route_with_a_placeholder_is_clean(tmp_path):
    files = dict(NEXT)
    files["app/api/users/route.ts"] = NEXT["app/api/users/route.ts"].replace(
        "db.query(`SELECT * FROM users WHERE name LIKE '%${q}%'`)",
        "db.query('SELECT * FROM users WHERE name LIKE $1', ['%' + q + '%'])")
    assert _flows(tmp_path, files) == []


# ------------------------------------------------------------- a page template that prints a value without escaping

def _page(root, body, template, name="views/profile.ejs"):
    flows = _flows(root, {"server.js": HEAD + "app.set('view engine', 'ejs')\n" + _route(body), name: template})
    return [(f["class"], f["file"], f["line"]) for f in flows]


NAME = "  res.render('profile', { name: req.query.name, bio: 'none yet' })\n"
PRINTED = {
    "caught: the page prints the value without escaping":
        (NAME, "<h1><%- name %></h1>\n", [("xss", "views/profile.ejs", 1)]),
    "clean: the page prints it escaped":
        (NAME, "<h1><%= name %></h1>\n", []),
    "clean: the page prints another of its values without escaping, one the code set":
        (NAME, "<h1><%= name %></h1>\n<p><%- bio %></p>\n", []),
    "clean: escaped for a page in the route, then printed as it is":
        ("  res.render('profile', { name: escapeHtml(req.query.name) })\n", "<h1><%- name %></h1>\n", []),
    "clean: a number made from the request":
        ("  res.render('profile', { name: parseInt(req.query.name, 10) })\n", "<h1><%- name %></h1>\n", []),
    "caught: a member of an object the route hands in":
        ("  const user = { name: req.query.name, id: 7 }\n  res.render('profile', { user })\n",
         "<h1>\n<%- user.name %>\n</h1>\n", [("xss", "views/profile.ejs", 2)]),
    "caught: each item of a list the request sent":
        ("  res.render('profile', { tags: req.query.tags })\n",
         "<% tags.forEach(function (tag) { %>\n<li><%- tag %></li>\n<% }) %>\n", [("xss", "views/profile.ejs", 2)]),
    "caught: everything the request sent is the page's values":
        ("  res.render('profile', req.query)\n", "<h1><%- name %></h1>\n", [("xss", "views/profile.ejs", 1)]),
    "clean: the page of that name prints nothing raw; another page does":
        (NAME, "<h1><%= name %></h1>\n", []),
}


@pytest.mark.parametrize("case", sorted(PRINTED))
def test_a_page_template_that_prints_a_value_without_escaping(tmp_path, case):
    body, template, want = PRINTED[case]
    extra = {"views/other.ejs": "<%- name %>\n"} if "another page does" in case else {}
    _write(tmp_path, extra)
    assert _page(tmp_path, body, template) == want


def test_other_template_languages_and_a_page_in_a_folder(tmp_path):
    files = {"server.js": HEAD + _route("  res.render('users/card', { name: req.query.name })\n", url="/a")
             + _route("  res.render('note', { text: req.query.text })\n", url="/b"),
             "views/users/card.hbs": "<div>\n  {{{name}}}\n</div>\n", "views/note.pug": "p= text\np!= text\n"}
    flows = _flows(tmp_path, files)
    assert [(f["class"], f["file"], f["line"]) for f in flows] == [("xss", "views/note.pug", 2),
                                                                    ("xss", "views/users/card.hbs", 2)]
    steps = [s["what"] for s in flows[1]["steps"]]
    assert any("views/users/card.hbs" in s and "`name`" in s for s in steps), steps


# ------------------------------------------------------------- text saved as a template

VIEWS = "const VIEWS = path.join(__dirname, 'views')\n"
SAVED = {
    "caught: the text is written into a file of the views folder, which is then rendered":
        (_route("  fs.writeFileSync(path.join(__dirname, 'views', 'note.ejs'), req.body.text)\n"
                "  res.render('note')\n", "post"), ["eval"]),
    "caught: the views folder is named at the top of the file":
        (VIEWS + _route("  fs.writeFile(path.join(VIEWS, 'note.ejs'), '<p>' + req.body.text + '</p>', () => "
                        "res.render('note'))\n", "post"), ["eval"]),
    "caught: escaped for a page, then written into the template file":
        (VIEWS + _route("  fs.writeFileSync(path.join(VIEWS, 'note.ejs'), escapeHtml(req.body.text))\n"
                        "  res.render('note')\n", "post"), ["eval"]),
    "clean: the text is written into a data folder":
        (_route("  fs.writeFileSync(path.join(BASE, 'note.txt'), req.body.text)\n  res.end()\n", "post"), []),
    "clean: fixed text is written into the views folder":
        (VIEWS + _route("  fs.writeFileSync(path.join(VIEWS, 'note.ejs'), '<p>nothing yet</p>')\n"
                        "  res.render('note', { text: req.body.text })\n", "post"), []),
    "clean: a data file kept beside the views":
        (VIEWS + _route("  fs.writeFileSync(path.join(VIEWS, 'note.json'), JSON.stringify({ text: req.body.text }))\n"
                        "  res.end()\n", "post"), []),
}


@pytest.mark.parametrize("case", sorted(SAVED))
def test_text_saved_as_a_template(tmp_path, case):
    _check(tmp_path, SAVED, case)


# ------------------------------------------------------------- a value put into an object and read back out

JS_GLUED = "  pool.query(`SELECT * FROM items WHERE name = '${{{x}}}'`, (e, rows) => res.json(rows))\n"
JS_APART = "  pool.query('SELECT * FROM items WHERE name = ?', [{x}], (e, rows) => res.json(rows))\n"
KEEPS = ("class Search {\n  constructor (term, table = 'items') {\n    this.term = term\n    this.table = table\n"
         "    this.size = term.length\n  }\n}\n")
OLD_STYLE = "function Search (term) {\n  this.term = term\n  this.table = 'items'\n}\n"
OBJECTS = {
    "caught: a constructor keeps the value":
        (KEEPS + _route("  const s = new Search(req.query.q)\n" + JS_GLUED.format(x="s.term")), ["sql"]),
    "clean: the kept value is handed to the driver apart":
        (KEEPS + _route("  const s = new Search(req.query.q)\n" + JS_APART.format(x="s.term")), []),
    "clean: another field of the same object, which the code set":
        (KEEPS + _route("  const s = new Search(req.query.q)\n" + JS_GLUED.format(x="s.table")), []),
    "clean: a field that holds only the value's length":
        (KEEPS + _route("  const s = new Search(req.query.q)\n" + JS_GLUED.format(x="s.size")), []),
    "caught: the field the request did set":
        (KEEPS + _route("  const s = new Search('x', req.query.table)\n" + JS_GLUED.format(x="s.table")), ["sql"]),
    "caught: the parent's constructor keeps the value":
        (KEEPS + "class Paged extends Search {\n  constructor (term, page) {\n    super(term)\n"
         "    this.page = page\n  }\n}\n"
         + _route("  const s = new Paged(req.query.q, 1)\n" + JS_GLUED.format(x="s.term")), ["sql"]),
    "caught: a function used as a constructor keeps the value":
        (OLD_STYLE + _route("  const s = new Search(req.query.q)\n" + JS_GLUED.format(x="s.term")), ["sql"]),
    "clean: the other field of an object made by a function used as a constructor":
        (OLD_STYLE + _route("  const s = new Search(req.query.q)\n" + JS_GLUED.format(x="s.table")), []),
    "caught: a class with no constructor of its own, handed the value":
        ("const { Model } = require('objection')\n\nclass Search extends Model {}\n"
         + _route("  const s = new Search(req.query.q)\n" + JS_GLUED.format(x="s.term")), ["sql"]),
    "clean: an object made of the code's own values":
        (KEEPS + _route("  const s = new Search('all')\n  if (!req.query.q) return res.end()\n"
                        + JS_GLUED.format(x="s.term")), []),
}


@pytest.mark.parametrize("case", sorted(OBJECTS))
def test_a_value_put_into_an_object_is_read_back_out_of_it(tmp_path, case):
    _check(tmp_path, OBJECTS, case)


# ------------------------------------------------------------- a redirect that stays on this site (Next.js middleware)
# The address a request was made to names this site: `new URL('/login', req.url)` and `req.nextUrl.clone()` with
# another path go nowhere else. What is read out of that address (a parameter, the path) is still the caller's text.

def _mw(body):
    return ("import { NextResponse } from 'next/server'\nimport type { NextRequest } from 'next/server'\n\n"
            "export function middleware (req: NextRequest) {\n  const session = req.cookies.get('session')\n"
            + body + "  return NextResponse.next()\n}\n\nexport const config = { matcher: ['/dashboard/:path*'] }\n")


NEXT_PARAM = "  const next = req.nextUrl.searchParams.get('next')\n"
SAME_SITE = {
    "clean: a fixed path on this site":
        ("  if (!session) return NextResponse.redirect(new URL('/login', req.url))\n", []),
    "clean: a fixed path, and where the person came from as a parameter":
        ("  if (!session) {\n    return NextResponse.redirect("
         "new URL(`/login?from=${encodeURIComponent(req.nextUrl.pathname)}`, req.url))\n  }\n", []),
    "clean: where the person came from, built in two steps":
        ("  if (!session) {\n    let from = req.nextUrl.pathname\n    if (req.nextUrl.search) from += req.nextUrl.search\n"
         "    return NextResponse.redirect(new URL(`/login?from=${encodeURIComponent(from)}`, req.url))\n  }\n", []),
    "clean: the request's own address with another path":
        ("  if (!session) {\n    const url = req.nextUrl.clone()\n    url.pathname = '/login'\n"
         "    return NextResponse.redirect(url)\n  }\n", []),
    "clean: the request's own address, another path and a parameter set on it":
        ("  if (!session) {\n    const url = req.nextUrl.clone()\n    url.pathname = '/login'\n"
         "    url.searchParams.set('from', req.nextUrl.pathname)\n    return NextResponse.redirect(url)\n  }\n", []),
    "clean: the request's own address, its path and its query set from the request":
        ("  if (!session) {\n    const url = req.nextUrl.clone()\n    url.pathname = '/login'\n"
         "    url.search = `?from=${req.nextUrl.pathname}`\n    return NextResponse.redirect(url)\n  }\n", []),
    "clean: the address parsed again, with another path":
        ("  if (!session) {\n    const url = new URL(req.url)\n    url.pathname = '/login'\n"
         "    return NextResponse.redirect(url)\n  }\n", []),
    "clean: a login address on this site, with a parameter set on it":
        ("  if (!session) {\n    const loginUrl = new URL('/login', req.url)\n"
         "    loginUrl.searchParams.set('from', req.nextUrl.pathname)\n    return NextResponse.redirect(loginUrl)\n"
         "  }\n", []),
    "clean: a fixed path on the request's own origin":
        ("  if (!session) return NextResponse.redirect(new URL('/login', req.nextUrl.origin))\n", []),
    "clean: the request's own origin and a fixed path, glued":
        ("  if (!session) return NextResponse.redirect(`${req.nextUrl.origin}/login`)\n", []),
    "clean: the request's own origin, a fixed path, then a value":
        ("  if (!session) {\n    return NextResponse.redirect("
         "`${req.nextUrl.origin}/login?from=${req.nextUrl.pathname}`)\n  }\n", []),
    "clean: origin and path taken out of the request's own address by name":
        ("  const { origin, pathname } = req.nextUrl\n"
         "  if (!session) return NextResponse.redirect(new URL(`/login?from=${pathname}`, origin))\n", []),
    "clean: the origin of the address parsed again":
        ("  const { origin } = new URL(req.url)\n"
         "  if (!session) return NextResponse.redirect(`${origin}/login`)\n", []),
    "clean: a fixed path on a fixed site":
        ("  if (!session) return NextResponse.redirect(new URL('/login', 'https://app.example.com'))\n", []),
    "clean: a fixed path on the site named in the settings":
        ("  if (!session) return NextResponse.redirect(new URL('/login', process.env.NEXT_PUBLIC_APP_URL))\n", []),
    "caught: the request says where to go":
        (NEXT_PARAM + "  if (session && next) return NextResponse.redirect(next)\n", ["redirect"]),
    "caught: the request says where, read against this site (a whole address wins over the site)":
        (NEXT_PARAM + "  if (session && next) return NextResponse.redirect(new URL(next, req.url))\n", ["redirect"]),
    "caught: the same with a default":
        ("  const next = req.nextUrl.searchParams.get('next') ?? '/'\n"
         "  if (session) return NextResponse.redirect(new URL(next, req.url))\n", ["redirect"]),
    "caught: one slash and the value (two slashes name another site)":
        (NEXT_PARAM + "  if (session) return NextResponse.redirect(new URL('/' + next, req.url))\n", ["redirect"]),
    "caught: a fixed path on a site the request names":
        ("  const site = req.nextUrl.searchParams.get('site')\n"
         "  if (session) return NextResponse.redirect(new URL('/login', site))\n", ["redirect"]),
    "caught: the request's own address, then its host is set from the request":
        ("  const url = req.nextUrl.clone()\n  url.host = req.nextUrl.searchParams.get('h')\n"
         "  if (session) return NextResponse.redirect(url)\n", ["redirect"]),
    "caught: the address parsed again, then its host is set from the request":
        ("  const url = new URL(req.url)\n  url.hostname = req.nextUrl.searchParams.get('h')\n"
         "  if (session) return NextResponse.redirect(url)\n", ["redirect"]),
    "caught: the request's own address, then the whole of it is set from the request":
        ("  const url = req.nextUrl.clone()\n  url.href = req.nextUrl.searchParams.get('next')\n"
         "  if (session) return NextResponse.redirect(url)\n", ["redirect"]),
    "caught: the request's own origin with the value glued straight after it":
        (NEXT_PARAM + "  if (session && next) return NextResponse.redirect(`${req.nextUrl.origin}${next}`)\n",
         ["redirect"]),
    "caught: a parameter read out of the request's own address":
        ("  const url = req.nextUrl.clone()\n"
         "  if (session) return NextResponse.redirect(url.searchParams.get('next'))\n", ["redirect"]),
    "caught: a parameter read out of the address parsed again, taken by name":
        ("  const { searchParams } = new URL(req.url)\n"
         "  if (session) return NextResponse.redirect(searchParams.get('next'))\n", ["redirect"]),
    "caught: the parameters taken out of the request's own address by name":
        ("  const { searchParams } = req.nextUrl\n"
         "  if (session) return NextResponse.redirect(searchParams.get('next'))\n", ["redirect"]),
}


@pytest.mark.parametrize("case", sorted(SAME_SITE))
def test_a_redirect_that_stays_on_this_site(tmp_path, case):
    body, want = SAME_SITE[case]
    flows = _flows(tmp_path, {"middleware.ts": _mw(body),
                              "app/page.tsx": "export default function Page () {\n  return <main>Hi</main>\n}\n"})
    assert _kinds(flows) == want, flows


# ------------------------------------------------------------- TypeScript, a NestJS controller

NEST_HEAD = ("import { Controller, Get, Param, ParseIntPipe, Query } from '@nestjs/common'\n"
             "import { DataSource } from 'typeorm'\n\n@Controller('users')\nexport class UsersController {\n"
             "  constructor (private readonly db: DataSource) {}\n\n  @Get()\n")
NEST = {
    "caught: the decorator says the parameter is part of the address":
        ("  find (@Query('name') name: string) {\n"
         "    return this.db.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n  }\n}\n", ["sql"]),
    "clean: the driver gets the value apart":
        ("  find (@Query('name') name: string) {\n"
         "    return this.db.query('SELECT * FROM users WHERE name = $1', [name])\n  }\n}\n", []),
    "clean: a pipe makes it a number before the handler runs":
        ("  one (@Param('id', ParseIntPipe) id: number) {\n"
         "    return this.db.query('SELECT * FROM users WHERE id = ' + id)\n  }\n}\n", []),
    "caught: a number in the type only (nothing parses it)":
        ("  one (@Param('id') id: number) {\n"
         "    return this.db.query('SELECT * FROM users WHERE id = ' + id)\n  }\n}\n", ["sql"]),
}


@pytest.mark.parametrize("case", sorted(NEST))
def test_a_nest_controller_parameter_is_what_its_decorator_says(tmp_path, case):
    body, want = NEST[case]
    flows = _flows(tmp_path, {"src/users.controller.ts": NEST_HEAD + body})
    assert _kinds(flows) == want, flows
    if flows:
        assert (flows[0]["file"], flows[0]["line"]) == ("src/users.controller.ts", 10), flows


# ------------------------------------------------------------- in the browser

BROWSER = {
    "caught: a part of the page's address put into the page as HTML":
        ("const q = new URLSearchParams(location.search).get('q')\n"
         "document.getElementById('out').innerHTML = 'Results for ' + q\n", ["xss"]),
    "clean: put into the page as text":
        ("const q = new URLSearchParams(location.search).get('q')\n"
         "document.getElementById('out').textContent = 'Results for ' + q\n", []),
    "caught: a part of the page's address chooses the next page":
        ("const next = new URLSearchParams(location.search).get('next')\nwindow.location.href = next\n", ["redirect"]),
    "clean: sent to the app's own server (not the server asking for an address)":
        ("const q = new URLSearchParams(location.search).get('q')\n"
         "fetch('/api/items?q=' + encodeURIComponent(q)).then((r) => r.json())\n", []),
}


@pytest.mark.parametrize("case", sorted(BROWSER))
def test_in_the_browser(tmp_path, case):
    body, want = BROWSER[case]
    flows = _flows(tmp_path, {"web/main.js": body})
    assert _kinds(flows) == want, flows


# The page's own address. The scheme, the host and the port a page was loaded from are not what whoever made the
# link chose, and going to the page's own address again leaves the site nowhere. A part read out of the address is
# still the link maker's text. (Written after two false alarms on a real app's own script; the caught ones beside
# them are near-misses that already read right and are kept so.)
ASKED_NEXT = "const next = new URLSearchParams(location.search).get('next')\n"
BROWSER_OWN = {
    "clean: the page's own scheme and host, a port and a path of the script's":
        ("const port = 1313\nconst path = '/livereload'\n"
         "window.location = location.protocol + '//' + location.hostname + ':' + port + path\n", []),
    "clean: own scheme and host, a port out of the options, a path handed in":
        ("function go (path, options) {\n"
         "  window.location = location.protocol + '//' + location.hostname + ':' + options.overrideURL + path\n}\n", []),
    "clean: the page's own origin and a written path":
        ("window.location.href = window.location.origin + '/login'\n", []),
    "clean: own origin, a written path, then a word out of the address":
        (ASKED_NEXT + "location.href = location.origin + '/settings/' + next\n", []),
    "clean: own origin, one slash, then a word out of the address (the origin is never empty)":
        (ASKED_NEXT + "location.href = location.origin + '/' + next\n", []),
    "clean: the page's own host put into the page as text":
        ("document.getElementById('host').textContent = location.host\n", []),
    "clean: the page's own host name put into the page as HTML":
        ("document.getElementById('host').innerHTML = '<b>' + location.hostname + '</b>'\n", []),
    "clean: document.location.origin and a written path":
        ("window.location.assign(document.location.origin + '/home')\n", []),
    "clean: own scheme and host in a template text":
        ("window.location.href = `${location.protocol}//${location.host}/app/`\n", []),
    "clean: the origin of the page's address read through URL":
        ("const here = new URL(location.href)\nwindow.location.href = here.origin + '/login'\n", []),
    "clean: own origin kept under a name":
        ("const site = window.location.origin\nwindow.location.href = site + '/login'\n", []),
    "clean: the same page again":
        ("window.location.href = window.location.href\n", []),
    "clean: the same page again, by the bare name":
        ("window.location = location\n", []),
    "clean: the same address with one parameter set through URL":
        ("function page (n) {\n  const url = new URL(window.location.href)\n  url.searchParams.set('page', n)\n"
         "  window.location.href = url.toString()\n}\n", []),
    "clean: the same address as a URL object, handed over":
        ("function page (n) {\n  const url = new URL(location.href)\n  url.searchParams.set('page', n)\n"
         "  location.assign(url)\n}\n", []),
    "clean: the same address and written text after it":
        ("window.location.href = window.location.href + '&done=1'\n", []),
    "clean: the same address without what follows the #":
        ("location.replace(location.href.split('#')[0])\n", []),
    "clean: the same address, http made https":
        ("location.replace(location.href.replace('http:', 'https:'))\n", []),
    "clean: the same address, what follows the # cut by a pattern":
        ("window.location = location.href.replace(/#.*$/, '')\n", []),
    "clean: own origin and the page's path, the query left out":
        ("window.location = location.origin + location.pathname\n", []),
    "clean: own origin, the page's path and a written query":
        ("window.location.href = location.origin + location.pathname + '?tab=2'\n", []),
    "clean: own scheme, host and the page's path":
        ("window.location.href = location.protocol + '//' + location.host + location.pathname\n", []),
    "clean: document.URL again":
        ("window.location.href = document.URL\n", []),
    "clean: own scheme and host kept under a name, then the page's path":
        ("const base = location.protocol + '//' + location.host\nwindow.location.href = base + location.pathname\n",
         []),
    "clean: own scheme and host in a template text, then the page's path":
        ("window.location.href = `${location.protocol}//${location.host}${location.pathname}`\n", []),
    "clean: own scheme, host and port, one slash, then a word out of the address":
        (ASKED_NEXT + "window.location.href = location.protocol + '//' + location.hostname + ':' + location.port + '/' + next\n",
         []),
    "clean: the same address, the scheme swapped by a pattern":
        ("location.replace(location.href.replace(/^http:/, 'https:'))\n", []),
    "caught: own scheme and host kept under a name, the address's text straight after":
        (ASKED_NEXT + "const base = location.protocol + '//' + location.host\nwindow.location.href = base + next\n",
         ["redirect"]),
    "caught: own scheme and host name, then the address's text where the port stands":
        (ASKED_NEXT + "window.location.href = location.protocol + '//' + location.hostname + ':' + next\n", ["redirect"]),
    "caught: the site taken off the front of the address by a pattern":
        ("window.location = location.href.replace(/^https?:\\/\\/[^/]+/, '')\n", ["redirect"]),
    "caught: the site's written address taken off the front of the address":
        ("window.location = location.href.replace('https://app.example.com', '')\n", ["redirect"]),
    "caught: the address's text straight after the own origin":
        (ASKED_NEXT + "window.location.href = location.origin + next\n", ["redirect"]),
    "caught: only the scheme is the page's own":
        (ASKED_NEXT + "window.location.href = location.protocol + '//' + next + '/start'\n", ["redirect"]),
    "caught: own host, a dot, then the address's text":
        (ASKED_NEXT + "window.location.href = 'https://' + location.hostname + '.' + next\n", ["redirect"]),
    "caught: the address's text in front of the own host":
        (ASKED_NEXT + "window.location.href = 'https://' + next + location.host + '/x'\n", ["redirect"]),
    "caught: the whole address put into the page as HTML":
        ("document.getElementById('at').innerHTML = 'You are at ' + location.href\n", ["xss"]),
    "caught: the query put into the page as HTML":
        ("document.getElementById('q').innerHTML = location.search\n", ["xss"]),
    "caught: what follows the # is the next page":
        ("window.location = location.hash.slice(1)\n", ["redirect"]),
    "caught: the path alone is the next page (a path may begin with two slashes)":
        ("window.location = window.location.pathname\n", ["redirect"]),
    "caught: the path and a written query":
        ("location.assign(location.pathname + '?tab=2')\n", ["redirect"]),
    "caught: a piece cut out of the address by split":
        ("window.location = location.href.split('next=')[1]\n", ["redirect"]),
    "caught: the half of the address after the #":
        ("window.location.href = location.href.split('#')[1]\n", ["redirect"]),
    "caught: a piece cut out by substring":
        ("const h = location.href\nwindow.location = h.substring(h.indexOf('url=') + 4)\n", ["redirect"]),
    "caught: a piece found by a pattern":
        ("const m = location.href.match(/[?&]to=([^&]+)/)\nif (m) window.location = decodeURIComponent(m[1])\n",
         ["redirect"]),
    "caught: a parameter read through URL":
        ("const u = new URL(location.href)\nwindow.location.href = u.searchParams.get('next')\n", ["redirect"]),
    "caught: the page that linked here is the next page":
        ("window.location = document.referrer\n", ["redirect"]),
    "caught: the address's own text put in front by replace":
        (ASKED_NEXT + "window.location = location.href.replace(location.origin, next)\n", ["redirect"]),
    "caught: the host of the address is set by hand":
        (ASKED_NEXT + "const u = new URL(location.href)\nu.hostname = next\nwindow.location.href = u.toString()\n",
         ["redirect"]),
}


@pytest.mark.parametrize("case", sorted(BROWSER_OWN))
def test_the_pages_own_address_in_the_browser(tmp_path, case):
    body, want = BROWSER_OWN[case]
    flows = _flows(tmp_path, {"web/main.js": body})
    assert _kinds(flows) == want, flows


REACT = {
    "caught: a part of the address given to React as raw HTML":
        ("  return <div dangerouslySetInnerHTML={{ __html: params.get('msg') }} />\n", ["xss"]),
    "clean: React escapes what is written between tags":
        ("  return <div>{params.get('msg')}</div>\n", []),
}


@pytest.mark.parametrize("case", sorted(REACT))
def test_react(tmp_path, case):
    body, want = REACT[case]
    page = ("import { useSearchParams } from 'react-router-dom'\n\nexport function Notice () {\n"
            "  const [params] = useSearchParams()\n" + body + "}\n")
    flows = _flows(tmp_path, {"web/Notice.jsx": page})
    assert _kinds(flows) == want, flows


# ------------------------------------------------------------- in the findings (security.scan)

def _scan(root, files):
    from lantern.security import scan
    _write(root, files)
    return [f for f in scan(build_graph(root), offline=True)["findings"] if not f["in_tests"]]


def test_a_flow_on_a_line_the_pattern_rules_flagged_is_one_finding(tmp_path):
    body, _ = SHELL["caught: put into a shell command"]
    fs = [f for f in _scan(tmp_path, {"server.js": HEAD + body}) if f["file"] == "server.js" and f["line"] == 15]
    shell = [f for f in fs if f["rule"] in ("LJ-EXEC", "LT-SHELL")]
    assert [f["rule"] for f in shell] == ["LJ-EXEC"], [(f["rule"], f["line"]) for f in fs]
    f = shell[0]
    assert f["flow"]["class"] == "shell" and f["rank"] == "critical" and f["input"]["flow"], f
    assert "`host`" in f["flow"]["source"]["what"], f["flow"]


def test_a_flow_no_pattern_rule_saw_is_a_finding_of_its_own(tmp_path):
    fs = _scan(tmp_path, APP)
    f = next(f for f in fs if f["rule"] == "LT-SQL")
    assert (f["tool"], f["file"], f["line"], f["rank"]) == ("lantern-flow", "core/db.js", 6, "critical"), f
    assert f["reachable"] and f["flow"]["steps"], f


def test_a_handler_no_route_uses_is_found_but_not_ranked_as_reached(tmp_path):
    files = dict(APP)
    files["routes/main.js"] = APP["routes/main.js"].replace("router.get('/users', handlers.search)\n", "")
    fs = _scan(tmp_path, files)
    f = next(f for f in fs if f["rule"] == "LT-SQL")
    assert f["reachable"] is None and f["rank"] in ("medium", "low"), (f["reachable"], f["rank"])


RUN = "function run (cmd, cb) {\n  exec(cmd + ' 2>&1', cb)\n}\n"
FIXED_CALLERS = {
    "lowered: every caller hands it fixed text":
        (_route("  run('df -h', (e, out) => res.type('text').send(out))\n", url="/disk") +
         _route("  run('uptime', (e, out) => res.type('text').send(out))\n", url="/up"), "low"),
    "kept: one caller hands it request data":
        (_route("  run('df -h', (e, out) => res.type('text').send(out))\n", url="/disk") +
         _route("  run(req.query.c, (e, out) => res.type('text').send(out))\n", url="/any"), "critical"),
    "kept: the function is also handed to code Lantern cannot see into":
        (_route("  run('df -h', (e, out) => res.type('text').send(out))\n", url="/disk") +
         "module.exports = { run }\n", "kept"),
}


@pytest.mark.parametrize("case", sorted(FIXED_CALLERS))
def test_fixed_text_from_every_caller_lowers_a_finding_and_a_near_miss_does_not(tmp_path, case):
    body, want = FIXED_CALLERS[case]
    fs = _scan(tmp_path, {"server.js": HEAD + RUN + body})
    f = next(f for f in fs if f["rule"] == "LJ-EXEC")
    if want == "kept":
        assert f["rank"] != "low" and "rank_note" not in f, (f["rank"], f.get("rank_note"))
        return
    assert f["rank"] == want, (f["rank"], f.get("rank_note"), f.get("input"))
    if want == "low":
        assert "fixed text" in f["rank_note"] and f["input"] is False, f


# ------------------------------------------------------------- a raw place in a page template, in the findings
# The template's own line is the finding (LW-XSS-RAW, a heuristic), and what Lantern knows about the value decides
# the rank: followed from the request, not followed to where it comes from, or fixed text wherever the page is shown.

def _raw(fs):
    return [(f["rule"], f["file"], f["line"], f["tool_confidence"], f["rank"], bool(f.get("flow"))) for f in fs
            if f["rule"] in ("LW-XSS-RAW", "LT-XSS")]


def _shown(body, template):
    return {"server.js": HEAD + "app.set('view engine', 'ejs')\n" + _route(body), "views/profile.ejs": template}


# line 14 is `app.set(...)`, 15 the route, 16 its first line
FROM_DB = ("  pool.query('SELECT bio FROM users WHERE id = 7', (err, rows) => {\n"
           "    res.render('profile', { bio: rows[0].bio })\n  })\n")
RAW_BIO = "<h1>Profile</h1>\n<p><%- bio %></p>\n"
RAW_PLACES = {
    "request data is followed into it: one finding with the way there, ranked as request data":
        ("  res.render('profile', { bio: req.query.bio })\n", RAW_BIO,
         [("LW-XSS-RAW", "views/profile.ejs", 2, "LOW", "high", True)], "route code reaches it"),
    "a value Lantern cannot follow to where it comes from: a heuristic finding, medium":
        (FROM_DB, RAW_BIO, [("LW-XSS-RAW", "views/profile.ejs", 2, "LOW", "medium", False)], "server.js:17"),
    "the route hands the page no value under that name: medium":
        ("  res.render('profile', { title: 'Profile' })\n", RAW_BIO,
         [("LW-XSS-RAW", "views/profile.ejs", 2, "LOW", "medium", False)], "server.js:16"),
    "no place in the code shows the page: medium, and the reason says so":
        ("  res.send('ok')\n", RAW_BIO, [("LW-XSS-RAW", "views/profile.ejs", 2, "LOW", "medium", False)],
         "no place in the code that shows this page"),
    "fixed text in the one place that shows the page: listed, ranked low":
        ("  res.render('profile', { bio: 'none yet' })\n", RAW_BIO,
         [("LW-XSS-RAW", "views/profile.ejs", 2, "LOW", "low", False)], "(`server.js:16`)"),
    "escaped for a page in the route before it is handed over: listed, ranked low":
        ("  res.render('profile', { bio: escapeHtml(req.query.bio) })\n", RAW_BIO,
         [("LW-XSS-RAW", "views/profile.ejs", 2, "LOW", "low", False)], "(`server.js:16`)"),
    "fixed text in one place and a database value in another: medium":
        ("  if (req.query.demo) return res.render('profile', { bio: 'none yet' })\n" + FROM_DB, RAW_BIO,
         [("LW-XSS-RAW", "views/profile.ejs", 2, "LOW", "medium", False)], "server.js:18"),
    "the escaped twin: nothing":
        (FROM_DB, "<h1>Profile</h1>\n<p><%= bio %></p>\n", [], ""),
    "an include, a layout slot and fixed text: nothing":
        (FROM_DB, "<%- include('head') %>\n<%- body %>\n<%- '<br>' %>\n<p><%= bio %></p>\n", [], ""),
}


@pytest.mark.parametrize("case", sorted(RAW_PLACES))
def test_a_template_that_prints_a_value_raw_is_ranked_by_what_is_known_of_the_value(tmp_path, case):
    body, template, want, why = RAW_PLACES[case]
    fs = _scan(tmp_path, _shown(body, template))
    assert _raw(fs) == want, [(f["rule"], f["file"], f["line"], f["rank"]) for f in fs]
    for f in fs:
        if f["rule"] == "LW-XSS-RAW":
            from lantern.security import rank_reason
            assert why in rank_reason(f), rank_reason(f)
            assert f["cwe"] == 79 and "without escaping" in f["title"], f
            assert not f.get("flow") or (f["input"]["flow"] and f["flow"]["sink"]["file"] == "views/profile.ejs"), f


# ------------------------------------------------------------- an escape of the project's own, written other ways
# Round 3 (2026-11-11): the one false alarm left on the safe twins of the held-out set was a page escaped by a small
# helper. The held-out app was not read; 28 shapes of my own were, and the engine was wrong on the ways below of
# saying what each character becomes. What it has to know is what the helper gives for `<`: worked out from the
# helper's own code, never taken from its name.
def _esc(body):
    return "function esc (s) {\n" + body + "}\n" + HELLO


TABLE3 = "const TABLE = { '&': '&amp;', '<': '&lt;', '>': '&gt;' }\n"
BY_REPLACER = {
    "clean: the table is written in the replacer itself":
        (_esc("  return String(s).replace(/[&<>\"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "
              "'\"': '&quot;', \"'\": '&#39;' }[c]))\n"), []),
    "clean: each character becomes its number":
        (_esc("  return String(s).replace(/[&<>\"']/g, (c) => '&#' + c.charCodeAt(0) + ';')\n"), []),
    "clean: the same, written as a template":
        (_esc("  return String(s).replace(/[&<>\"']/g, (c) => `&#${c.charCodeAt(0)};`)\n"), []),
    "clean: a switch on the character":
        (_esc("  return String(s).replace(/[&<>]/g, function (c) {\n    switch (c) {\n"
              "      case '&': return '&amp;'\n      case '<': return '&lt;'\n      default: return '&gt;'\n"
              "    }\n  })\n"), []),
    "clean: an if on the character":
        (_esc("  return String(s).replace(/[&<>]/g, function (c) {\n    if (c === '<') return '&lt;'\n"
              "    if (c === '>') return '&gt;'\n    return '&amp;'\n  })\n"), []),
    "clean: a question on the character":
        (_esc("  return String(s).replace(/[<>]/g, (c) => c === '<' ? '&lt;' : '&gt;')\n"), []),
    "clean: the table, or the character itself where the table has none":
        (TABLE3 + _esc("  return String(s).replace(/[&<>]/g, (c) => TABLE[c] || c)\n"), []),
    "clean: the replacer is a function with a name":
        (TABLE3 + "function one (c) {\n  return TABLE[c]\n}\n" + _esc("  return String(s).replace(/[&<>]/g, one)\n"),
         []),
    "clean: split at each character and joined with what it becomes":
        (_esc("  return String(s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;')\n"),
         []),
    "clean: single characters between bars, each asked of the table":
        (TABLE3 + _esc("  return String(s).replace(/<|>|&/g, (c) => TABLE[c])\n"), []),
    "caught: a longer match is handed to the replacer whole, and the table has no such entry":
        (TABLE3 + _esc("  return String(s).replace(/<script|</g, (c) => TABLE[c] || c)\n"), ["xss"]),
    "caught: the table written in the replacer has no <":
        (_esc("  return String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '>': '&gt;' }[c]))\n"), ["xss"]),
    "caught: the replacer gives the character back":
        (_esc("  return String(s).replace(/[&<>]/g, (c) => c)\n"), ["xss"]),
    "caught: the replacer puts the character after its number":
        (_esc("  return String(s).replace(/[&<>]/g, (c) => '&#' + c.charCodeAt(0) + ';' + c)\n"), ["xss"]),
    "caught: the switch has no case for < and gives the character back otherwise":
        (_esc("  return String(s).replace(/[&<>]/g, function (c) {\n    switch (c) {\n"
              "      case '&': return '&amp;'\n      case '>': return '&gt;'\n      default: return c\n"
              "    }\n  })\n"), ["xss"]),
    "caught: the question is asked of > only":
        (_esc("  return String(s).replace(/[<>]/g, (c) => c === '>' ? '&gt;' : c)\n"), ["xss"]),
    "caught: the table has no <, and the character itself is what is left":
        ("const TABLE = { '&': '&amp;', '>': '&gt;' }\n"
         + _esc("  return String(s).replace(/[&<>]/g, (c) => TABLE[c] || c)\n"), ["xss"]),
    "caught: the replacer with a name gives back what another table says, which Lantern does not know":
        ("function one (c) {\n  return lookup(c)\n}\n" + _esc("  return String(s).replace(/[&<>]/g, one)\n"),
         ["xss"]),
    "caught: split and joined at > only":
        (_esc("  return String(s).split('>').join('&gt;')\n"), ["xss"]),
    "caught: split at < and joined with a tag":
        (_esc("  return String(s).split('<').join('<wbr>')\n"), ["xss"]),
    "caught: escaped, then turned back":
        ("const _ = require('lodash')\n" + _route("  res.send('<p>' + _.unescape(_.escape(req.query.name)) + '</p>')\n"),
         ["xss"]),
    "caught: escaped by the project's own helper, then decoded":
        (ESC + _route("  res.send('<p>' + decodeURIComponent(encodeURIComponent(req.query.name)) + '</p>')\n"),
         ["xss"]),
}


@pytest.mark.parametrize("case", sorted(BY_REPLACER))
def test_an_escape_that_says_what_each_character_becomes(tmp_path, case):
    _check(tmp_path, BY_REPLACER, case)


def test_the_same_escape_in_the_handlers_file_of_an_app_split_over_files(tmp_path):
    files = {"server.js": "const express = require('express')\nconst handlers = require('./core/handlers')\n"
                          "const app = express()\napp.get('/hello', handlers.hello)\n",
             "core/handlers.js": "function escapeHtml (s) {\n  return String(s).replace(/[&<>\"']/g, (c) => "
                                 "({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' }[c]))\n"
                                 "}\n\nexports.hello = function (req, res) {\n"
                                 "  res.send('<p>Hello ' + {use} + '</p>')\n}\n"}
    safe = dict(files, **{"core/handlers.js": files["core/handlers.js"].replace("{use}", "escapeHtml(req.query.q)")})
    assert _kinds(_flows(tmp_path / "safe", safe)) == []
    raw = dict(files, **{"core/handlers.js": files["core/handlers.js"].replace("{use}", "req.query.q")})
    assert _kinds(_flows(tmp_path / "raw", raw)) == ["xss"]


# ------------------------------------------------------------- an address that starts with a value of the server's own
# 2026-11-11, the JavaScript twin of `OWN_START` in tests/test_flow.py: the request chooses a path or a query on a
# host the server names; the near-misses beside each safe shape must still be caught.

OWN_START_JS = ("const express = require('express')\nconst axios = require('axios')\nconst app = express()\n"
                "const API = process.env.API_URL\nconst proto = process.env.PROTO\n"
                "const HOST = process.env.API_HOST\nconst PORT = process.env.API_PORT\n"
                "const REGIONS = { eu: 'https://eu.example', us: 'https://us.example' }\n"
                "const SITES = { docs: 'https://docs.example.com/start', shop: 'https://shop.example.com/start' }\n"
                "function get (path) {\n  return fetch(API + path)\n}\n")
OWN_START_X = "app.get('/x/:id', async (req, res) => {\n"
OWN_START_END = "  res.json(await r.json())\n})\n"
OWN_START_GO = "app.get('/go', (req, res) => {\n"
OWN_START_CASES = {
    "clean: the setting, then a path":
        (OWN_START_X + "  const r = await fetch(`${API}/items/${req.params.id}`)\n" + OWN_START_END, []),
    "clean: with plus":
        (OWN_START_X + "  const r = await axios.get(API + '/items/' + req.params.id)\n  res.json(r.data)\n})\n", []),
    "clean: the setting, then one slash":
        (OWN_START_X + "  const r = await fetch(API + '/' + req.params.id)\n" + OWN_START_END, []),
    "clean: read from the environment in place":
        (OWN_START_X + "  const r = await fetch(`${process.env.API_URL}/items/${req.params.id}`)\n" + OWN_START_END, []),
    "clean: a helper that puts its own setting in front":
        (OWN_START_X + "  const r = await get('/items/' + req.params.id)\n" + OWN_START_END, []),
    "clean: the host and the port are settings":
        (OWN_START_X + "  const r = await fetch(`http://${HOST}:${PORT}/api/${req.params.id}`)\n" + OWN_START_END, []),
    "clean: an address out of a table in the code, then a path":
        (OWN_START_X + "  const r = await fetch(REGIONS[req.query.region] + '/items/' + req.params.id)\n" +
         OWN_START_END, []),
    "caught: the request's text straight after the setting":
        (OWN_START_X + "  const r = await fetch(API + req.query.path)\n" + OWN_START_END, ["ssrf"]),
    "caught: the helper is handed the request's text as it came":
        (OWN_START_X + "  const r = await get(req.query.path)\n" + OWN_START_END, ["ssrf"]),
    "caught: the scheme, two slashes, then the request's host":
        (OWN_START_X + "  const r = await fetch(`${proto}//${req.query.host}/status`)\n" + OWN_START_END, ["ssrf"]),
    "caught: a dot after the setting":
        (OWN_START_X + "  const r = await fetch(`${API}.${req.query.zone}/status`)\n" + OWN_START_END, ["ssrf"]),
    "caught: the host is a setting, the port is the request's":
        (OWN_START_X + "  const r = await fetch(`http://${HOST}:${req.query.port}/api`)\n" + OWN_START_END, ["ssrf"]),
    "caught: a table of hosts with nothing after them, the request's text straight after":
        (OWN_START_X + "  const r = await fetch(REGIONS[req.query.region] + req.query.path)\n" + OWN_START_END,
         ["ssrf"]),
    "clean: a redirect to the server's own site and a path":
        (OWN_START_GO + "  res.redirect(`${process.env.APP_URL}/welcome?next=${req.query.next}`)\n})\n", []),
    "clean: a redirect to a whole address out of a table in the code, the request's text in the query":
        (OWN_START_GO + "  res.redirect(SITES[req.query.site] + '?from=' + req.query.from)\n})\n", []),
    "caught: a redirect with the request's text straight after the site":
        (OWN_START_GO + "  res.redirect(process.env.APP_URL + req.query.next)\n})\n", ["redirect"]),
    "caught: the site, one slash, then the request's text (an empty setting makes it two slashes and a host)":
        (OWN_START_GO + "  res.redirect(process.env.APP_URL + '/' + req.query.next)\n})\n", ["redirect"]),
    "caught: hosts out of a table with nothing after them, the request's text straight after":
        (OWN_START_GO + "  res.redirect(REGIONS[req.query.region] + req.query.next)\n})\n", ["redirect"]),
}


@pytest.mark.parametrize("case", sorted(OWN_START_CASES))
def test_an_address_that_starts_with_a_value_of_the_servers_own(tmp_path, case):
    _check(tmp_path, OWN_START_CASES, case, head=OWN_START_JS)


# ------------------------------------------------------------- an address with no host in it, and the request's own
# The JavaScript twin of `PATH_ONLY` in tests/test_flow.py (2026-11-11): a client made with a base address, the
# `baseURL` option, `concat`, an array joined with a slash; beside them one slash and the request's text, parts
# joined with nothing or a dot, and the host the request itself names.

PATH_ONLY_JS = ("const express = require('express')\nconst axios = require('axios')\n"
                "const punycode = require('punycode')\nconst psl = require('psl')\nconst app = express()\n"
                "const API = process.env.API_URL\nconst api = axios.create({ baseURL: API })\n"
                "function trimmed(text) {\n  return text.trim().toLowerCase()\n}\n"
                "app.get('/x/:id', async (req, res) => {\n")
PATH_ONLY_END = "  res.json(r.data)\n})\n"
PATH_ONLY_CASES = {
    "clean: a client with a base address, handed a path":
        ("  const r = await api.get('/items/' + req.params.id)\n" + PATH_ONLY_END, []),
    "clean: the baseURL option":
        ("  const r = await axios.get('/items/' + req.params.id, { baseURL: API })\n" + PATH_ONLY_END, []),
    "caught: a client with a base address, handed the request's text as it came":
        ("  const r = await api.get(req.query.path)\n" + PATH_ONLY_END, ["ssrf"]),
    "caught: the same, one slash and the request's text":
        ("  const r = await api.get('/' + req.query.path)\n" + PATH_ONLY_END, ["ssrf"]),
    "clean: concat":
        ("  const r = await axios.get(API.concat('/items/', req.params.id))\n" + PATH_ONLY_END, []),
    "caught: concat with the request's text straight after the setting":
        ("  const r = await axios.get(API.concat(req.query.path))\n" + PATH_ONLY_END, ["ssrf"]),
    "clean: an array joined with a slash":
        ("  const r = await axios.get([API, 'items', req.params.id].join('/'))\n" + PATH_ONLY_END, []),
    "caught: an array joined with nothing":
        ("  const r = await axios.get([API, req.query.path].join(''))\n" + PATH_ONLY_END, ["ssrf"]),
    "caught: an array joined with a dot":
        ("  const r = await axios.get([API, req.query.zone].join('.'))\n" + PATH_ONLY_END, ["ssrf"]),
    "caught: the host name the request names":
        ("  const r = await axios.get('http://' + req.hostname + '/x/' + req.params.id)\n" + PATH_ONLY_END, ["ssrf"]),
    # what a library call gave back after the request's text went into it is not a value of the server's own
    # (`Val.lost`; the caught one failed first, the clean one pins what read right)
    "caught: the host came out of a library call the request's text went into":
        ("  const host = punycode.toASCII(req.query.host)\n"
         "  const r = await axios.get('https://' + host + '/api/' + req.params.id)\n" + PATH_ONLY_END, ["ssrf"]),
    "clean: a later part came out of such a call, after the setting and a path":
        ("  const name = punycode.toASCII(req.query.name)\n"
         "  const r = await axios.get(API + '/items/' + name + '/' + req.params.id)\n" + PATH_ONLY_END, []),
    # ... and the ways such a value gets into the address (the changelog says which of these failed before)
    "caught: a field of what such a call gave back":
        ("  const host = psl.parse(req.query.host).domain\n"
         "  const r = await axios.get('https://' + host + '/api/' + req.params.id)\n" + PATH_ONLY_END, ["ssrf"]),
    "caught: such a call's result in a template text":
        ("  const r = await axios.get(`https://${punycode.toASCII(req.query.host)}/api/${req.params.id}`)\n"
         + PATH_ONLY_END, ["ssrf"]),
    "caught: such a call's result in one branch, written text in the other":
        ("  const host = req.query.host ? punycode.toASCII(req.query.host) : 'api.example.com'\n"
         "  const r = await axios.get('https://' + host + '/api/' + req.params.id)\n" + PATH_ONLY_END, ["ssrf"]),
    "caught: such a call's result turned into text with String()":
        ("  const host = String(punycode.toASCII(req.query.host))\n"
         "  const r = await axios.get('https://' + host + '/api/' + req.params.id)\n" + PATH_ONLY_END, ["ssrf"]),
    "caught: such a call's result handed on to a second library call":
        ("  const host = punycode.toUnicode(punycode.toASCII(req.query.host))\n"
         "  const r = await axios.get('https://' + host + '/api/' + req.params.id)\n" + PATH_ONLY_END, ["ssrf"]),
    "caught: such a call's result handed through a helper of the project and back":
        ("  const host = trimmed(punycode.toASCII(req.query.host))\n"
         "  const r = await axios.get('https://' + host + '/api/' + req.params.id)\n" + PATH_ONLY_END, ["ssrf"]),
    "clean: a setting handed through the same helper":
        ("  const host = trimmed(process.env.API_HOST)\n"
         "  const r = await axios.get('https://' + host + '/api/' + req.params.id)\n" + PATH_ONLY_END, []),
    "clean: the library call was handed written text":
        ("  const host = punycode.toASCII('api.example.com')\n"
         "  const r = await axios.get('https://' + host + '/api/' + req.params.id)\n" + PATH_ONLY_END, []),
    "caught: the Host header":
        ("  const r = await axios.get(`${req.protocol}://${req.get('host')}/internal`)\n" + PATH_ONLY_END, ["ssrf"]),
}


@pytest.mark.parametrize("case", sorted(PATH_ONLY_CASES))
def test_an_address_with_no_host_in_it_and_the_hosts_the_request_names(tmp_path, case):
    _check(tmp_path, PATH_ONLY_CASES, case, head=PATH_ONLY_JS)
