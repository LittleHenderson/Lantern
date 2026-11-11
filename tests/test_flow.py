"""Following a value across functions (directive point 4, 2026-11-11): Python.

Each dangerous example sits beside safe twins that must stay clean and near-misses that must still be caught: a
function named "validate" that proves nothing, the wrong kind of escaping, a check that comes after the action.
None of these files is copied from an app of the held-out benchmark; they were written before the engine was."""

import pytest

from lantern.engine import build_graph

FASTAPI = ("import os\nimport sqlite3\nimport subprocess\n\nfrom fastapi import Depends, FastAPI, HTTPException\n\n"
           "app = FastAPI()\n\n\ndef get_db():\n    conn = sqlite3.connect('app.db')\n    try:\n        yield conn\n"
           "    finally:\n        conn.close()\n\n\n")
FLASK = ("import os\n\nfrom flask import Flask, abort, jsonify, redirect, render_template, render_template_string, "
         "request, url_for\n\napp = Flask(__name__)\n\n\n")
PROJECT = {"pyproject.toml": '[project]\nname="a"\nversion="0"\n', "app/__init__.py": ""}


def _write(root, files):
    for rel, text in {**PROJECT, **files}.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _flows(root, files):
    from lantern import flow
    _write(root, files)
    res = flow.analyze(build_graph(root))
    assert not res.errors, res.errors          # a function the engine could not read is a defect, never a clean result
    return res.flows


def _kinds(flows):
    return sorted(f["class"] for f in flows)


def _one(root, body, head=FASTAPI):
    return _flows(root, {"app/main.py": head + body})


# ------------------------------------------------------------- a request value through three functions to a query

CHAIN = {
    "app/main.py": FASTAPI + "from . import service\nfrom .helpers import clean, pick_sort\n\n\n"
                             "@app.get('/items')\ndef list_items(q: str, sort: str = 'name', db=Depends(get_db)):\n"
                             "    term = clean(q)\n    return service.find_items(db, term, pick_sort(sort))\n",
    "app/helpers.py": "ALLOWED = {'name': 'name ASC', 'price': 'price DESC'}\n\n\ndef clean(value):\n"
                      "    return value.strip()\n\n\ndef pick_sort(sort):\n    return ALLOWED.get(sort, 'name ASC')\n",
    "app/service.py": "def find_items(db, term, order):\n"
                      "    sql = \"SELECT id, name FROM items WHERE name LIKE '%\" + term + \"%' ORDER BY \" + order\n"
                      "    return run_query(db, sql)\n\n\ndef run_query(db, sql):\n    cur = db.cursor()\n"
                      "    cur.execute(sql)\n    return cur.fetchall()\n",
}


def test_a_request_value_is_followed_through_a_helper_and_a_service_to_the_query(tmp_path):
    flows = _flows(tmp_path, CHAIN)
    assert _kinds(flows) == ["sql"], flows
    f = flows[0]
    assert (f["file"], f["line"]) == ("app/service.py", 8)            # cur.execute(sql)
    assert f["source"]["file"] == "app/main.py" and "`q`" in f["source"]["what"]
    words = " | ".join(s["what"] for s in f["steps"])
    for name in ("clean", "find_items", "run_query"):
        assert name in words, words
    assert [s["file"] for s in f["steps"]][0] == "app/main.py" and f["steps"][-1]["file"] == "app/service.py"
    # the sort order went through a table of fixed texts: it is not request data any more
    assert "sort" not in f["source"]["what"]


def test_the_same_chain_with_the_value_handed_to_the_driver_apart_is_clean(tmp_path):
    files = dict(CHAIN)
    files["app/service.py"] = (
        "def find_items(db, term, order):\n"
        "    sql = 'SELECT id, name FROM items WHERE name LIKE ? ORDER BY ' + order\n"
        "    return run_query(db, sql, ('%' + term + '%',))\n\n\ndef run_query(db, sql, params):\n"
        "    cur = db.cursor()\n    cur.execute(sql, params)\n    return cur.fetchall()\n")
    assert _flows(tmp_path, files) == []


def test_a_request_value_spliced_where_the_fixed_table_was_is_caught(tmp_path):
    files = dict(CHAIN)
    files["app/helpers.py"] = files["app/helpers.py"].replace("return ALLOWED.get(sort, 'name ASC')",
                                                              "return ALLOWED.get(sort, sort)")
    files["app/service.py"] = files["app/service.py"].replace("LIKE '%\" + term + \"%' ORDER BY \"",
                                                              "LIKE ? ORDER BY \"")
    flows = _flows(tmp_path, files)
    assert _kinds(flows) == ["sql"] and "`sort`" in flows[0]["source"]["what"], flows


# ------------------------------------------------------------- a function named validate is not proof

TABLES = "TABLES = ('items', 'orders')\n\n\n"
ROUTE = ("@app.get('/rows')\ndef rows(table: str, db=Depends(get_db)):\n{use}"
         "    return db.execute('SELECT * FROM ' + {name}).fetchall()\n")

VALIDATE = {
    "caught: validate only tidies the text":
        ("def validate(value):\n    return value.strip().lower()\n\n\n"
         + ROUTE.format(use="    name = validate(table)\n", name="name"), ["sql"]),
    "caught: validate returns a yes or no that nobody reads":
        (TABLES + "def validate(value):\n    return value in TABLES\n\n\n"
         + ROUTE.format(use="    validate(table)\n", name="table"), ["sql"]),
    "caught: the yes or no is read, and the query runs either way":
        (TABLES + "def validate(value):\n    return value in TABLES\n\n\n"
         + ROUTE.format(use="    if validate(table):\n        print('known')\n", name="table"), ["sql"]),
    "caught: validate checks another value":
        (TABLES + "def validate(value):\n    if value not in TABLES:\n        raise HTTPException(400)\n\n\n"
         + ROUTE.format(use="    validate('items')\n", name="table"), ["sql"]),
    "clean: validate refuses what is not in the list and returns the value":
        (TABLES + "def validate(value):\n    if value not in TABLES:\n        raise HTTPException(400)\n"
         "    return value\n\n\n" + ROUTE.format(use="    name = validate(table)\n", name="name"), []),
    "clean: validate refuses what is not in the list and returns nothing":
        (TABLES + "def validate(value):\n    if value not in TABLES:\n        raise HTTPException(400)\n\n\n"
         + ROUTE.format(use="    validate(table)\n", name="table"), []),
    "clean: a yes or no that stops the request":
        (TABLES + "def known(value):\n    return value in TABLES\n\n\n"
         + ROUTE.format(use="    if not known(table):\n        raise HTTPException(400)\n", name="table"), []),
    "clean: the check is written in the route":
        (TABLES + ROUTE.format(use="    if table not in TABLES:\n        raise HTTPException(400)\n", name="table"),
         []),
    "clean: a pattern that allows letters only":
        ("import re\n\n\n" + ROUTE.format(
            use="    if not re.fullmatch(r'[a-z_]+', table):\n        raise HTTPException(400)\n", name="table"), []),
    "caught: a pattern that allows anything":
        ("import re\n\n\n" + ROUTE.format(
            use="    if not re.match(r'.+', table):\n        raise HTTPException(400)\n", name="table"), ["sql"]),
    "caught: a pattern that only looks at the start":
        ("import re\n\n\n" + ROUTE.format(
            use="    if not re.match(r'[a-z_]+', table):\n        raise HTTPException(400)\n", name="table"), ["sql"]),
    "clean: turned into a number first":
        (ROUTE.format(use="    name = int(table)\n", name="str(name)"), []),
    # the answer kept in a variable first (2026-11-11)
    "clean: the answer is kept in a variable and asked afterwards":
        (TABLES + ROUTE.format(use="    known = table in TABLES\n    if not known:\n"
                                   "        raise HTTPException(400)\n", name="table"), []),
    "clean: what the pattern found is kept, and nothing found stops the request":
        ("import re\n\n\n" + ROUTE.format(
            use="    found = re.fullmatch(r'[a-z_]+', table)\n    if found is None:\n"
                "        raise HTTPException(400)\n", name="table"), []),
    "caught: what the pattern found is kept, and the request goes on when nothing was found":
        ("import re\n\n\n" + ROUTE.format(
            use="    found = re.fullmatch(r'[a-z_]+', table)\n    if found is not None:\n"
                "        raise HTTPException(400)\n", name="table"), ["sql"]),
    "caught: the kept answer is about the list, the query uses a value set afterwards":
        (TABLES + ROUTE.format(use="    known = table in TABLES\n    table = table.strip() + '_old'\n"
                                   "    if not known:\n        raise HTTPException(400)\n", name="table"),
         ["sql"]),
}


@pytest.mark.parametrize("case", sorted(VALIDATE))
def test_a_check_counts_for_what_its_code_proves_not_for_its_name(tmp_path, case):
    body, want = VALIDATE[case]
    assert _kinds(_one(tmp_path, body)) == want


# ------------------------------------------------------------- the right guard for the action, before the action

GUARDS = {
    "caught: HTML escaping before a database query":
        ("import html\n\n\n@app.get('/a')\ndef a(q: str, db=Depends(get_db)):\n    safe = html.escape(q)\n"
         "    return db.execute(\"SELECT * FROM items WHERE name = '\" + safe + \"'\").fetchall()\n", ["sql"]),
    "caught: shell quoting before a database query":
        ("import shlex\n\n\n@app.get('/a')\ndef a(q: str, db=Depends(get_db)):\n    safe = shlex.quote(q)\n"
         "    return db.execute(\"SELECT * FROM items WHERE name = \" + safe).fetchall()\n", ["sql"]),
    "clean: shell quoting before a shell command":
        ("import shlex\n\n\n@app.get('/a')\ndef a(name: str):\n"
         "    return subprocess.run('ls ' + shlex.quote(name), shell=True, capture_output=True).stdout\n", []),
    "caught: HTML escaping before a shell command":
        ("import html\n\n\n@app.get('/a')\ndef a(name: str):\n"
         "    return subprocess.run('ls ' + html.escape(name), shell=True, capture_output=True).stdout\n", ["shell"]),
    "caught: the check comes after the command has run":
        ("@app.post('/run')\ndef run(cmd: str):\n    out = subprocess.run(cmd, shell=True, capture_output=True)\n"
         "    if cmd not in ('ls', 'date'):\n        raise HTTPException(400)\n    return out.stdout\n", ["shell"]),
    "clean: the same check before the command":
        ("@app.post('/run')\ndef run(cmd: str):\n    if cmd not in ('ls', 'date'):\n        raise HTTPException(400)\n"
         "    out = subprocess.run(cmd, shell=True, capture_output=True)\n    return out.stdout\n", []),
    "caught: the check is on one branch only":
        ("@app.post('/run')\ndef run(cmd: str, strict: bool = False):\n    if strict:\n"
         "        if cmd not in ('ls', 'date'):\n            raise HTTPException(400)\n"
         "    return subprocess.run(cmd, shell=True, capture_output=True).stdout\n", ["shell"]),
    "clean: a fixed program, the value as one argument":
        ("@app.post('/convert')\ndef convert(name: str):\n"
         "    return subprocess.run(['convert', '/srv/in/' + name], capture_output=True).returncode\n", []),
    "caught: the value chooses the program":
        ("@app.post('/tool')\ndef tool(name: str):\n"
         "    return subprocess.run([name, '--version'], capture_output=True).stdout\n", ["shell"]),
}


@pytest.mark.parametrize("case", sorted(GUARDS))
def test_the_guard_has_to_fit_the_action_and_come_before_it(tmp_path, case):
    body, want = GUARDS[case]
    assert _kinds(_one(tmp_path, body)) == want


def test_the_steps_say_what_an_escape_does_not_protect(tmp_path):
    body, _ = GUARDS["caught: HTML escaping before a database query"]
    f = _one(tmp_path, body)[0]
    words = " | ".join(s["what"] for s in f["steps"])
    assert "html.escape" in words and "not" in words, words


def test_a_command_across_two_functions(tmp_path):
    body = ("def convert(name):\n    os.system('convert /srv/in/' + name + ' /srv/out/' + name + '.png')\n\n\n"
            "@app.post('/convert')\ndef conv(name: str):\n    convert(name)\n")
    flows = _one(tmp_path, body)
    assert _kinds(flows) == ["shell"] and flows[0]["line"] == 19, flows   # the os.system line, not the route


# ------------------------------------------------------------- an address the server is sent to fetch

DOWNLOAD = "import requests\nfrom urllib.parse import urlparse\n\nHOSTS = {'api.example.com'}\n\n\n" \
           "def download(url):\n    return requests.get(url, timeout=5).text\n\n\n"
LOOKUP = "import ipaddress\nimport socket\n\n\n"
SSRF = {
    "caught: the address comes from the request":
        ("@app.get('/fetch')\ndef fetch(url: str):\n    return download(url)\n", ["ssrf"]),
    "caught: only the scheme is fixed":
        ("@app.get('/fetch')\ndef fetch(host: str):\n    return download('https://' + host + '/status')\n", ["ssrf"]),
    "caught: a check that the address starts with https":
        ("@app.get('/fetch')\ndef fetch(url: str):\n    if not url.startswith('https://'):\n"
         "        raise HTTPException(400)\n    return download(url)\n", ["ssrf"]),
    "caught: the list is asked about another value":
        ("@app.get('/fetch')\ndef fetch(url: str, other: str = ''):\n"
         "    if urlparse(other).hostname not in HOSTS:\n        raise HTTPException(400)\n"
         "    return download(url)\n", ["ssrf"]),
    "clean: the host is on a list":
        ("@app.get('/fetch')\ndef fetch(url: str):\n    if urlparse(url).hostname not in HOSTS:\n"
         "        raise HTTPException(400)\n    return download(url)\n", []),
    "clean: the host is on a list, through a variable":
        ("@app.get('/fetch')\ndef fetch(url: str):\n    host = urlparse(url).hostname\n    if host not in HOSTS:\n"
         "        raise HTTPException(400)\n    return download(url)\n", []),
    "clean: the address is taken apart first, and its host is on a list":
        ("@app.get('/fetch')\ndef fetch(url: str):\n    parts = urlparse(url)\n    if parts.hostname not in HOSTS:\n"
         "        raise HTTPException(400)\n    return download(url)\n", []),
    "caught: another address is taken apart and checked":
        ("@app.get('/fetch')\ndef fetch(url: str, other: str = ''):\n    parts = urlparse(other)\n"
         "    if parts.hostname not in HOSTS:\n        raise HTTPException(400)\n    return download(url)\n", ["ssrf"]),
    "clean: a check of the host in a function of its own":
        ("def allowed(u):\n    return urlparse(u).hostname in HOSTS\n\n\n@app.get('/fetch')\ndef fetch(url: str):\n"
         "    if not allowed(url):\n        raise HTTPException(400)\n    return download(url)\n", []),
    "caught: a function named allowed that looks at the scheme only":
        ("def allowed(u):\n    return urlparse(u).scheme == 'https'\n\n\n@app.get('/fetch')\ndef fetch(url: str):\n"
         "    if not allowed(url):\n        raise HTTPException(400)\n    return download(url)\n", ["ssrf"]),
    "clean: the host is fixed and the value is part of the path":
        ("@app.get('/fetch')\ndef fetch(name: str):\n"
         "    return download('https://api.example.com/users/' + name)\n", []),
    "clean: a number":
        ("@app.get('/fetch')\ndef fetch(user_id: int):\n"
         "    return download('https://api.example.com/users/' + str(user_id))\n", []),
    # the other proper guard: the name is looked up, and the address it leads to must not be inside the network
    "clean: the name is looked up and an address inside the network is refused":
        (LOOKUP + "@app.get('/fetch')\ndef fetch(url: str):\n"
         "    ip = socket.gethostbyname(urlparse(url).hostname)\n    if ipaddress.ip_address(ip).is_private:\n"
         "        raise HTTPException(400)\n    return download(url)\n", []),
    "clean: only an address out on the internet is let through":
        (LOOKUP + "@app.get('/fetch')\ndef fetch(url: str):\n"
         "    ip = socket.gethostbyname(urlparse(url).hostname)\n    if not ipaddress.ip_address(ip).is_global:\n"
         "        raise HTTPException(400)\n    return download(url)\n", []),
    "clean: every address the name has is looked at":
        (LOOKUP + "@app.get('/fetch')\ndef fetch(url: str):\n"
         "    for info in socket.getaddrinfo(urlparse(url).hostname, 443):\n"
         "        if ipaddress.ip_address(info[4][0]).is_private:\n            raise HTTPException(400)\n"
         "    return download(url)\n", []),
    "clean: a helper that refuses addresses inside the network":
        (LOOKUP + "def outside_only(u):\n"
         "    addr = ipaddress.ip_address(socket.gethostbyname(urlparse(u).hostname))\n"
         "    if addr.is_private or addr.is_loopback or addr.is_link_local:\n        raise HTTPException(400)\n\n\n"
         "@app.get('/fetch')\ndef fetch(url: str):\n    outside_only(url)\n    return download(url)\n", []),
    "clean: a helper that says whether the address is outside":
        (LOOKUP + "def is_outside(u):\n    host = urlparse(u).hostname\n    ip = socket.gethostbyname(host)\n"
         "    return ipaddress.ip_address(ip).is_global\n\n\n"
         "@app.get('/fetch')\ndef fetch(url: str):\n    if not is_outside(url):\n        raise HTTPException(400)\n"
         "    return download(url)\n", []),
    "caught: a helper named is_outside that looks the name up and asks nothing about the address":
        (LOOKUP + "def is_outside(u):\n    ip = socket.gethostbyname(urlparse(u).hostname)\n    return bool(ip)\n\n\n"
         "@app.get('/fetch')\ndef fetch(url: str):\n    if not is_outside(url):\n        raise HTTPException(400)\n"
         "    return download(url)\n", ["ssrf"]),
    "caught: the address that is looked up belongs to another value":
        (LOOKUP + "@app.get('/fetch')\ndef fetch(url: str, other: str = ''):\n"
         "    ip = socket.gethostbyname(urlparse(other).hostname)\n    if ipaddress.ip_address(ip).is_private:\n"
         "        raise HTTPException(400)\n    return download(url)\n", ["ssrf"]),
    "caught: only the address of this computer is refused":
        (LOOKUP + "@app.get('/fetch')\ndef fetch(url: str):\n"
         "    ip = socket.gethostbyname(urlparse(url).hostname)\n    if ipaddress.ip_address(ip).is_loopback:\n"
         "        raise HTTPException(400)\n    return download(url)\n", ["ssrf"]),
    "clean: the usual helper: every address of the name, and False for one inside the network":
        (LOOKUP + "def is_safe(u):\n    host = urlparse(u).hostname\n    try:\n"
         "        infos = socket.getaddrinfo(host, None)\n    except socket.gaierror:\n        return False\n"
         "    for info in infos:\n        ip = ipaddress.ip_address(info[4][0])\n"
         "        if ip.is_private or ip.is_loopback or ip.is_link_local:\n            return False\n"
         "    return True\n\n\n"
         "@app.get('/fetch')\ndef fetch(url: str):\n    if not is_safe(url):\n        raise HTTPException(400)\n"
         "    return download(url)\n", []),
    "caught: the loop stops at the first good address and the rest are not looked at":
        (LOOKUP + "@app.get('/fetch')\ndef fetch(url: str):\n"
         "    for info in socket.getaddrinfo(urlparse(url).hostname, 443):\n"
         "        if not ipaddress.ip_address(info[4][0]).is_private:\n            break\n"
         "    return download(url)\n", ["ssrf"]),
    "clean: the host must be an IP address, and one inside the network is refused":
        (LOOKUP + "@app.get('/fetch')\ndef fetch(url: str):\n"
         "    if ipaddress.ip_address(urlparse(url).hostname).is_private:\n        raise HTTPException(400)\n"
         "    return download(url)\n", []),
    "caught: the same question, but a host that is a name is let through unasked":
        (LOOKUP + "@app.get('/fetch')\ndef fetch(url: str):\n    try:\n"
         "        if ipaddress.ip_address(urlparse(url).hostname).is_private:\n            raise HTTPException(400)\n"
         "    except ValueError:\n        pass\n    return download(url)\n", ["ssrf"]),
    "caught: is_private asked of something that is no address":
        (LOOKUP + "class Repo:\n    is_private = False\n\n\nREPOS = {}\n\n\n"
         "@app.get('/fetch')\ndef fetch(url: str):\n    if REPOS.get(url, Repo()).is_private:\n"
         "        raise HTTPException(400)\n    return download(url)\n", ["ssrf"]),
    "caught: the host was checked, then the address was given another value":
        ("@app.get('/fetch')\ndef fetch(url: str, other: str = ''):\n    host = urlparse(url).hostname\n"
         "    url = other\n    if host not in HOSTS:\n        raise HTTPException(400)\n"
         "    return download(url)\n", ["ssrf"]),
    "clean: a helper that refuses a host that is not on the list":
        ("def check(u):\n    if urlparse(u).hostname not in HOSTS:\n        raise HTTPException(400)\n\n\n"
         "@app.get('/fetch')\ndef fetch(url: str):\n    check(url)\n    return download(url)\n", []),
    "caught: the text is an IP address, which says nothing about whose":
        (LOOKUP + "@app.get('/fetch')\ndef fetch(host: str):\n"
         "    return download('http://' + str(ipaddress.ip_address(host)) + '/status')\n", ["ssrf"]),
    # The same proper guard in the shapes people write it. 2026-11-11: after the first measurement on the held-out
    # set showed a false alarm on a safe address check, 22 safe shapes were written here (the held-out app was not
    # read) and three of them were reported: these, each beside its near-misses.
    "clean: the answer is kept in a variable and asked afterwards":
        ("@app.get('/fetch')\ndef fetch(url: str):\n    ok = urlparse(url).hostname in HOSTS\n    if not ok:\n"
         "        raise HTTPException(400)\n    return download(url)\n", []),
    "caught: the answer kept in the variable is about another value":
        ("@app.get('/fetch')\ndef fetch(url: str, other: str = ''):\n    ok = urlparse(other).hostname in HOSTS\n"
         "    if not ok:\n        raise HTTPException(400)\n    return download(url)\n", ["ssrf"]),
    "caught: the answer is asked the wrong way round":
        ("@app.get('/fetch')\ndef fetch(url: str):\n    ok = urlparse(url).hostname in HOSTS\n    if ok:\n"
         "        raise HTTPException(400)\n    return download(url)\n", ["ssrf"]),
    "caught: the answer was taken, then the address was given another value":
        ("@app.get('/fetch')\ndef fetch(url: str, other: str = ''):\n    ok = urlparse(url).hostname in HOSTS\n"
         "    url = other\n    if not ok:\n        raise HTTPException(400)\n    return download(url)\n", ["ssrf"]),
    "caught: the variable was given another answer since":
        ("@app.get('/fetch')\ndef fetch(url: str):\n    ok = urlparse(url).hostname in HOSTS\n    ok = True\n"
         "    if not ok:\n        raise HTTPException(400)\n    return download(url)\n", ["ssrf"]),
    "caught: the variable holds the answer on one way only":
        ("@app.get('/fetch')\ndef fetch(url: str, force: bool = False):\n    ok = True\n    if not force:\n"
         "        ok = urlparse(url).hostname in HOSTS\n    if not ok:\n        raise HTTPException(400)\n"
         "    return download(url)\n", ["ssrf"]),
    "clean: the host is lower-cased first, with an empty text when there is none":
        ("@app.get('/fetch')\ndef fetch(url: str):\n    host = (urlparse(url).hostname or '').lower()\n"
         "    if host not in HOSTS:\n        raise HTTPException(400)\n    return download(url)\n", []),
    "caught: the host when there is one, else another value from the request":
        ("@app.get('/fetch')\ndef fetch(url: str, other: str = ''):\n"
         "    host = (urlparse(other).hostname or url).lower()\n"
         "    if host not in HOSTS:\n        raise HTTPException(400)\n    return download(url)\n", ["ssrf"]),
    "clean: the host must end with the site's own name, dot first":
        ("@app.get('/fetch')\ndef fetch(url: str):\n    host = urlparse(url).hostname or ''\n"
         "    if not host.endswith('.example.com'):\n        raise HTTPException(400)\n"
         "    return download(url)\n", []),
    "clean: the site's own name, or a name under it":
        ("@app.get('/fetch')\ndef fetch(url: str):\n    host = urlparse(url).hostname or ''\n"
         "    if not (host == 'example.com' or host.endswith('.example.com')):\n        raise HTTPException(400)\n"
         "    return download(url)\n", []),
    "caught: the host must end with the name, with no dot before it":      # evilexample.com
        ("@app.get('/fetch')\ndef fetch(url: str):\n    host = urlparse(url).hostname or ''\n"
         "    if not host.endswith('example.com'):\n        raise HTTPException(400)\n"
         "    return download(url)\n", ["ssrf"]),
    "caught: the whole address must end with the name":                     # http://evil.test/?x=.example.com
        ("@app.get('/fetch')\ndef fetch(url: str):\n"
         "    if not url.endswith('.example.com'):\n        raise HTTPException(400)\n"
         "    return download(url)\n", ["ssrf"]),
    "caught: any host under .com":
        ("@app.get('/fetch')\ndef fetch(url: str):\n    host = urlparse(url).hostname or ''\n"
         "    if not host.endswith('.com'):\n        raise HTTPException(400)\n"
         "    return download(url)\n", ["ssrf"]),
}


@pytest.mark.parametrize("case", sorted(SSRF))
def test_an_address_from_the_request_reaches_an_outbound_call(tmp_path, case):
    body, want = SSRF[case]
    flows = _one(tmp_path, DOWNLOAD + body)
    assert _kinds(flows) == want
    if flows:
        assert flows[0]["line"] == 25     # requests.get, inside the helper


# ------------------------------------------------------------- file paths

BASE = "BASE = '/srv/files'\n\n\n"
PATHS = {
    "caught: the name is joined to the folder":
        ("@app.get('/file')\ndef read_file(name: str):\n    with open(os.path.join(BASE, name)) as f:\n"
         "        return f.read()\n", ["path"]),
    "caught: the check is on the path before it is made whole":
        ("@app.get('/file')\ndef read_file(name: str):\n    full = os.path.join(BASE, name)\n"
         "    if not full.startswith(BASE):\n        raise HTTPException(400)\n    return open(full).read()\n",
         ["path"]),
    "caught: only two dots are refused, a full path still gets out":
        ("@app.get('/file')\ndef read_file(name: str):\n    if '..' in name:\n        raise HTTPException(400)\n"
         "    return open(os.path.join(BASE, name)).read()\n", ["path"]),
    "clean: two dots and a full path are refused":
        ("@app.get('/file')\ndef read_file(name: str):\n    if '..' in name or name.startswith('/'):\n"
         "        raise HTTPException(400)\n    return open(os.path.join(BASE, name)).read()\n", []),
    "clean: two dots are refused and the name is glued after the folder (glued text cannot start again)":
        ("@app.get('/file')\ndef read_file(name: str):\n    if '..' in name:\n        raise HTTPException(400)\n"
         "    return open(BASE + '/' + name).read()\n", []),
    "caught: glued after the folder with nothing refused":
        ("@app.get('/file')\ndef read_file(name: str):\n    return open(BASE + '/' + name).read()\n", ["path"]),
    "caught: two dots are refused, and the request also chooses what stands in front":
        ("@app.get('/file')\ndef read_file(folder: str, name: str):\n    if '..' in name:\n"
         "        raise HTTPException(400)\n    return open(folder + name).read()\n", ["path", "path"]),
    "clean: only the last part of the name is used":
        ("@app.get('/file')\ndef read_file(name: str):\n"
         "    return open(os.path.join(BASE, os.path.basename(name))).read()\n", []),
    "clean: the whole path is worked out and must lie in the folder":
        ("@app.get('/file')\ndef read_file(name: str):\n    full = os.path.realpath(os.path.join(BASE, name))\n"
         "    if not full.startswith(BASE + os.sep):\n        raise HTTPException(400)\n"
         "    return open(full).read()\n", []),
    "clean: pathlib, worked out and inside the folder":
        ("from pathlib import Path\n\n\n@app.get('/file')\ndef read_file(name: str):\n"
         "    full = (Path(BASE) / name).resolve()\n    if not full.is_relative_to(BASE):\n"
         "        raise HTTPException(400)\n    return full.read_text()\n", []),
    "caught: pathlib, not checked":
        ("from pathlib import Path\n\n\n@app.get('/file')\ndef read_file(name: str):\n"
         "    return (Path(BASE) / name).read_text()\n", ["path"]),
    "clean: the name picks an entry of a fixed table":
        ("FILES = {'terms': 'terms.txt', 'privacy': 'privacy.txt'}\n\n\n@app.get('/file')\n"
         "def read_file(name: str):\n    return open(os.path.join(BASE, FILES[name])).read()\n", []),
}


@pytest.mark.parametrize("case", sorted(PATHS))
def test_a_name_from_the_request_reaches_a_file(tmp_path, case):
    body, want = PATHS[case]
    assert _kinds(_one(tmp_path, BASE + body)) == want


UPLOAD = ("import io\nimport tarfile\nimport zipfile\n\nfrom fastapi import UploadFile\n\nDEST = '/srv/import'\n\n\n"
          "@app.post('/import')\nasync def import_archive(file: UploadFile):\n    data = await file.read()\n{body}")
ARCHIVES = {
    "caught: each entry is written where its name says":
        ("    return unpack(zipfile.ZipFile(io.BytesIO(data)))\n\n\ndef unpack(z):\n    for name in z.namelist():\n"
         "        with open(os.path.join(DEST, name), 'wb') as out:\n            out.write(z.read(name))\n", ["path"]),
    "clean: an entry that would land outside the folder is passed over":
        ("    return unpack(zipfile.ZipFile(io.BytesIO(data)))\n\n\ndef unpack(z):\n    for name in z.namelist():\n"
         "        target = os.path.realpath(os.path.join(DEST, name))\n"
         "        if not target.startswith(DEST + os.sep):\n            continue\n"
         "        with open(target, 'wb') as out:\n            out.write(z.read(name))\n", []),
    "clean: zipfile's own extractall, which tidies the names":
        ("    zipfile.ZipFile(io.BytesIO(data)).extractall(DEST)\n", []),
    "caught: a tar archive unpacked as it is":
        ("    tarfile.open(fileobj=io.BytesIO(data)).extractall(DEST)\n", ["path"]),
    "clean: a tar archive unpacked with the data filter":
        ("    tarfile.open(fileobj=io.BytesIO(data)).extractall(DEST, filter='data')\n", []),
    "caught: the upload is saved under the name it came with":
        ("    with open(os.path.join(DEST, file.filename), 'wb') as out:\n        out.write(data)\n", ["path"]),
    "clean: the upload is saved under a name of the server's own":
        ("    import uuid\n    with open(os.path.join(DEST, uuid.uuid4().hex), 'wb') as out:\n"
         "        out.write(data)\n", []),
}


@pytest.mark.parametrize("case", sorted(ARCHIVES))
def test_an_uploaded_archive_and_the_names_inside_it(tmp_path, case):
    body, want = ARCHIVES[case]
    assert _kinds(_one(tmp_path, UPLOAD.format(body=body))) == want


# ------------------------------------------------------------- pages, redirects, templates, stored objects (Flask)

PAGES = {
    "caught: the name is put into the page":
        ("@app.route('/hello')\ndef hello():\n    name = request.args.get('name', '')\n"
         "    return '<h1>Hello ' + name + '</h1>'\n", ["xss"]),
    "clean: escaped for a page":
        ("import html\n\n\n@app.route('/hello')\ndef hello():\n    name = request.args.get('name', '')\n"
         "    return '<h1>Hello ' + html.escape(name) + '</h1>'\n", []),
    "clean: sent as data":
        ("@app.route('/hello')\ndef hello():\n    return jsonify(name=request.args.get('name', ''))\n", []),
    "clean: handed to a template that escapes":
        ("@app.route('/hello')\ndef hello():\n"
         "    return render_template('hello.html', name=request.args.get('name', ''))\n", []),
    "caught: the name is part of the template's own text":
        ("@app.route('/hello')\ndef hello():\n"
         "    return render_template_string('<p>Hi ' + request.args.get('name', '') + '</p>')\n", ["eval"]),
    "clean: the template is fixed and the name is a value in it":
        ("@app.route('/hello')\ndef hello():\n"
         "    return render_template_string('<p>Hi {{ name }}</p>', name=request.args.get('name', ''))\n", []),
    "caught: sent on to wherever the request says":
        ("@app.route('/go')\ndef go():\n    return redirect(request.args['next'])\n", ["redirect"]),
    "caught: only the first slash is checked":
        ("@app.route('/go')\ndef go():\n    target = request.args.get('next', '/')\n"
         "    if not target.startswith('/'):\n        target = '/'\n    return redirect(target)\n", ["redirect"]),
    "clean: a path on this site only":
        ("@app.route('/go')\ndef go():\n    target = request.args.get('next', '/')\n"
         "    if not target.startswith('/') or target.startswith('//'):\n        target = '/'\n"
         "    return redirect(target)\n", []),
    "clean: the address is built by the app":
        ("@app.route('/go')\ndef go():\n    return redirect(url_for('hello'))\n", []),
    "clean: back to the address the request was made to":
        ("@app.route('/go', methods=['POST'])\ndef go():\n    return redirect(request.url)\n", []),
    "clean: the same address over https":
        ("@app.before_request\ndef secure():\n    if not request.is_secure:\n"
         "        return redirect(request.url.replace('http://', 'https://', 1), code=301)\n", []),
    "clean: the site's own root and a fixed path":
        ("@app.route('/go')\ndef go():\n    return redirect(request.url_root + 'login')\n", []),
    "clean: the site's own root (which ends the host with a slash) and a value after it":
        ("@app.route('/go')\ndef go():\n    return redirect(request.url_root + request.args['next'])\n", []),
    "caught: where the request says, else the address it was made to":
        ("@app.route('/go')\ndef go():\n    return redirect(request.args.get('next') or request.url)\n",
         ["redirect"]),
    "caught: a parameter cut out of the address the request was made to":
        ("@app.route('/go')\ndef go():\n    return redirect(request.url.split('next=', 1)[1])\n", ["redirect"]),
    "caught: the address it was made to, with its host replaced by what the request says":
        ("@app.route('/go')\ndef go():\n"
         "    return redirect(request.url.replace(request.host, request.args['to']))\n", ["redirect"]),
    "caught: an object is rebuilt from what was sent":
        ("import base64\nimport pickle\n\n\n@app.route('/load', methods=['POST'])\ndef load():\n"
         "    return str(pickle.loads(base64.b64decode(request.data)))\n", ["deserialize"]),
    "clean: read as JSON":
        ("import json\n\n\n@app.route('/load', methods=['POST'])\ndef load():\n"
         "    return jsonify(json.loads(request.data))\n", []),
    "caught: YAML read with the loader that builds objects":
        ("import yaml\n\n\n@app.route('/load', methods=['POST'])\ndef load():\n"
         "    return jsonify(yaml.load(request.data, Loader=yaml.Loader))\n", ["deserialize"]),
    "clean: YAML read with the safe loader":
        ("import yaml\n\n\n@app.route('/load', methods=['POST'])\ndef load():\n"
         "    return jsonify(yaml.load(request.data, Loader=yaml.SafeLoader))\n", []),
    "caught: XML read by a parser that follows outside references":
        ("from lxml import etree\n\n\n@app.route('/xml', methods=['POST'])\ndef xml():\n"
         "    return etree.tostring(etree.fromstring(request.data))\n", ["xxe"]),
    "clean: XML read by a parser told not to":
        ("from lxml import etree\n\n\n@app.route('/xml', methods=['POST'])\ndef xml():\n"
         "    parser = etree.XMLParser(resolve_entities=False, no_network=True)\n"
         "    return etree.tostring(etree.fromstring(request.data, parser=parser))\n", []),
    "clean: who is signed in is not what the request sent":
        ("import sqlite3\n\n\n@app.route('/mine')\ndef mine():\n    db = sqlite3.connect('app.db')\n"
         "    return jsonify(db.execute(\"SELECT * FROM notes WHERE owner = '\" + request.user.name + \"'\")"
         ".fetchall())\n", []),
}


@pytest.mark.parametrize("case", sorted(PAGES))
def test_pages_redirects_templates_and_stored_objects(tmp_path, case):
    body, want = PAGES[case]
    assert _kinds(_one(tmp_path, body, head=FLASK)) == want


def test_what_a_fastapi_route_returns_is_data_unless_it_says_html(tmp_path):
    body = ("from fastapi.responses import HTMLResponse\n\n\n@app.get('/a')\ndef a(q: str):\n"
            "    return '<p>' + q + '</p>'\n\n\n@app.get('/b')\ndef b(q: str):\n"
            "    return HTMLResponse('<p>' + q + '</p>')\n")
    flows = _one(tmp_path, body)
    assert [(f["class"], f["line"]) for f in flows] == [("xss", 28)], flows


# A page escaped by hand, or sent as something that is no page (2026-11-11; the same in tests/test_flow_js.py). Found
# on shapes written here after the first measurement on the held-out set; the held-out apps were not read.
HELLO = "@app.route('/hello')\ndef hello():\n    name = request.args.get('name', '')\n"
ESC = "def esc(s):\n    return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')\n\n\n"
MORE = "import re\n\nfrom flask import Response, make_response\n\n\n"
BY_HAND = {
    "clean: the project's own escape, which replaces every <":
        (ESC + HELLO + "    return '<h1>Hello ' + esc(name) + '</h1>'\n", []),
    "clean: every < is taken out with a pattern":
        (MORE + HELLO + "    return '<h1>Hello ' + re.sub(r'[<>]', '', name) + '</h1>'\n", []),
    "clean: the same with a pattern kept under a name":
        (MORE + "TAGS = re.compile(r'[<>]')\n\n\n" + HELLO + "    return '<h1>Hello ' + TAGS.sub('', name) + '</h1>'\n",
         []),
    "caught: an escape that forgets <":
        ("def esc(s):\n    return s.replace('&', '&amp;').replace('\"', '&quot;')\n\n\n" + HELLO
         + "    return '<h1>Hello ' + esc(name) + '</h1>'\n", ["xss"]),
    "caught: a pattern that takes out <script only":
        (MORE + HELLO + "    return '<h1>Hello ' + re.sub(r'<script', '', name) + '</h1>'\n", ["xss"]),
    "caught: < is replaced by text from the request":
        (HELLO + "    return '<h1>Hello ' + name.replace('<', request.args.get('with', '')) + '</h1>'\n",
         ["xss", "xss"]),         # both values reach the page
    "caught: < is replaced by a tag":
        (HELLO + "    return '<h1>Hello ' + name.replace('<', '<br>') + '</h1>'\n", ["xss"]),
    "caught: escaped for a page by hand, then put into a query":
        ("import sqlite3\n\n\n" + ESC + HELLO + "    db = sqlite3.connect('app.db')\n"
         "    return jsonify(db.execute(\"SELECT id FROM users WHERE name = '\" + esc(name) + \"'\").fetchall())\n",
         ["sql"]),
    "clean: the answer's kind is set to plain text afterwards":
        (MORE + HELLO + "    resp = make_response('Hello ' + name)\n    resp.headers['Content-Type'] = 'text/plain'\n"
         "    return resp\n", []),
    "clean: the same through mimetype":
        (MORE + HELLO + "    resp = Response('Hello ' + name)\n    resp.mimetype = 'text/plain'\n    return resp\n", []),
    "clean: text, a status and a header that says plain text":
        (HELLO + "    return 'Hello ' + name, 200, {'Content-Type': 'text/plain'}\n", []),
    "caught: the kind is set to a page":
        (MORE + HELLO + "    resp = make_response('<h1>Hello ' + name + '</h1>')\n"
         "    resp.headers['Content-Type'] = 'text/html'\n    return resp\n", ["xss"]),
    "caught: plain text on one way only":
        (MORE + HELLO + "    resp = make_response('Hello ' + name)\n    if request.args.get('plain'):\n"
         "        resp.mimetype = 'text/plain'\n    return resp\n", ["xss"]),
    "caught: the kind of another answer is set":
        (MORE + HELLO + "    resp = make_response('Hello ' + name)\n    other = make_response('ok')\n"
         "    other.mimetype = 'text/plain'\n    return resp\n", ["xss"]),
    "caught: another header is set to plain text":
        (HELLO + "    return 'Hello ' + name, 200, {'X-Kind': 'text/plain'}\n", ["xss"]),
}


@pytest.mark.parametrize("case", sorted(BY_HAND))
def test_a_page_escaped_by_hand_or_sent_as_plain_text(tmp_path, case):
    body, want = BY_HAND[case]
    assert _kinds(_one(tmp_path, body, FLASK)) == want


def test_a_fastapi_route_that_says_its_text_is_a_page(tmp_path):
    body = ("from fastapi.responses import HTMLResponse, PlainTextResponse\n\n\n"
            "@app.get('/a', response_class=HTMLResponse)\ndef a(q: str):\n    return '<p>' + q + '</p>'\n\n\n"
            "@app.get('/b', response_class=PlainTextResponse)\ndef b(q: str):\n    return 'You asked for ' + q\n")
    flows = _one(tmp_path, body)
    assert [(f["class"], f["line"]) for f in flows] == [("xss", 23)], flows      # route `a`, not the plain-text `b`


# ------------------------------------------------------------- a page template that prints a value without escaping

def _printed(root, files):
    return [(f["class"], f["file"], f["line"]) for f in _flows(root, files)]


HELLO_ROUTE = "@app.route('/hello')\ndef hello():\n    return render_template('hello.html', name={name})\n"
REQ_NAME = "request.args.get('name', '')"
PRINTED = {
    "caught: the page marks the value safe":
        (HELLO_ROUTE.format(name=REQ_NAME), "<h1>{{ name|safe }}</h1>\n", [("xss", "app/templates/hello.html", 1)]),
    "clean: the page lets the engine escape it":
        (HELLO_ROUTE.format(name=REQ_NAME), "<h1>{{ name }}</h1>\n", []),
    "caught: escaping is switched off around it":
        (HELLO_ROUTE.format(name=REQ_NAME), "{% autoescape false %}\n<h1>{{ name }}</h1>\n{% endautoescape %}\n",
         [("xss", "app/templates/hello.html", 2)]),
    "clean: escaped for a page in the route, then marked safe":
        ("import html\n\n\n" + HELLO_ROUTE.format(name="html.escape(" + REQ_NAME + ")"),
         "<h1>{{ name|safe }}</h1>\n", []),
    "clean: the page marks another of its values safe":
        (HELLO_ROUTE.format(name=REQ_NAME), "<h1>{{ name }}</h1>{{ footer|safe }}\n", []),
    "caught: the values are put together before the page is rendered":
        ("@app.route('/hello')\ndef hello():\n    values = {'name': request.args.get('name', ''), 'n': 1}\n"
         "    return render_template('hello.html', **values)\n", "<h1>{{ name|safe }}</h1>\n",
         [("xss", "app/templates/hello.html", 1)]),
}


@pytest.mark.parametrize("case", sorted(PRINTED))
def test_a_page_template_that_prints_a_value_without_escaping(tmp_path, case):
    body, template, want = PRINTED[case]
    assert _printed(tmp_path, {"app/main.py": FLASK + body, "app/templates/hello.html": template}) == want


def test_a_django_page_and_a_fastapi_page_that_mark_a_value_safe(tmp_path):
    files = {"blog/views.py": "from django.shortcuts import render\n\n\ndef post(request):\n"
                              "    return render(request, 'blog/post.html', {'text': request.GET.get('text', '')})\n",
             "blog/templates/blog/post.html": "{% for w in words %}{{ w }}{% endfor %}\n<p>{{ text|safe }}</p>\n",
             "app/main.py": FASTAPI + "from fastapi import Request\nfrom fastapi.templating import Jinja2Templates\n\n"
                            "pages = Jinja2Templates(directory='app/templates')\n\n\n@app.get('/item')\n"
                            "def item(request: Request, q: str):\n"
                            "    return pages.TemplateResponse('item.html', {'request': request, 'q': q})\n",
             "app/templates/item.html": "<p>{{ q | safe }}</p>\n"}
    assert _printed(tmp_path, files) == [("xss", "app/templates/item.html", 1),
                                         ("xss", "blog/templates/blog/post.html", 2)]


# ------------------------------------------------------------- text that is run as a template
# The text of a template is code for the template engine. Escaping it for a page changes nothing about that.

DJANGO = ("import os\nfrom pathlib import Path\n\nfrom django.http import HttpResponse\n"
          "from django.shortcuts import render\nfrom django.template import Context, Engine, Template, engines\n"
          "from django.utils.html import escape\n\n"
          "TEMPLATES = os.path.join(os.path.dirname(__file__), 'templates', 'blog')\nDATA = '/srv/data'\n\n\n")
POST = "def post(request):\n    text = request.POST.get('text', '')\n"
SAVE = "    with open(os.path.join({where}), 'w') as f:\n        f.write({what})\n    return render(request, 'blog/latest.html')\n"
TEMPLATE_TEXT = {
    "caught: the text is the template":
        (POST + "    return HttpResponse(Template(text).render(Context({})))\n", ["eval"]),
    "clean: the template is fixed and the text is a value in it":
        (POST + "    return HttpResponse(Template('<p>{{ text }}</p>').render(Context({'text': text})))\n", []),
    "caught: the engine is asked for a template made of the text":
        (POST + "    return HttpResponse(engines['django'].from_string(text).render({}, request))\n", ["eval"]),
    "caught: the default engine is asked for a template made of the text":
        (POST + "    return HttpResponse(Engine.get_default().from_string(text).render(Context({})))\n", ["eval"]),
    "caught: escaped for a page, the text is still a template":
        (POST + "    return HttpResponse(Template(escape(text)).render(Context({})))\n", ["eval"]),
    "caught: the text is written into a file of the templates folder, which is then rendered":
        (POST + SAVE.format(where="TEMPLATES, 'latest.html'", what="text"), ["eval"]),
    "caught: the same with fixed template text around it":
        (POST + SAVE.format(where="TEMPLATES, 'latest.html'",
                            what="'{% extends \"blog/base.html\" %}{% block body %}' + text + '{% endblock %}'"),
         ["eval"]),
    "caught: escaped for a page, then written into the template file":
        (POST + SAVE.format(where="TEMPLATES, 'latest.html'", what="escape(text)"), ["eval"]),
    "caught: written with write_text into the templates folder":
        (POST + "    (Path(__file__).parent / 'templates' / 'blog' / 'latest.html').write_text(text)\n"
         "    return render(request, 'blog/latest.html')\n", ["eval"]),
    "clean: the text is written into a data folder":
        (POST + SAVE.format(where="DATA, 'latest.txt'", what="text"), []),
    "clean: fixed text is written into the templates folder":
        (POST + SAVE.format(where="TEMPLATES, 'latest.html'", what="'<p>nothing yet</p>'"), []),
    "clean: only a number made from the request is written into the template file":
        (POST + SAVE.format(where="TEMPLATES, 'latest.html'", what="'<p>' + str(int(text)) + '</p>'"), []),
    "clean: a data file kept beside the templates":
        (POST + SAVE.format(where="TEMPLATES, 'latest.json'", what="text"), []),
    "clean: the templates folder is only read":
        (POST + "    with open(os.path.join(TEMPLATES, 'latest.html')) as f:\n        page = f.read()\n"
         "    return HttpResponse(page.replace('__TEXT__', escape(text)))\n", []),
}


@pytest.mark.parametrize("case", sorted(TEMPLATE_TEXT))
def test_text_that_is_run_as_a_template(tmp_path, case):
    body, want = TEMPLATE_TEXT[case]
    assert _kinds(_one(tmp_path, body, head=DJANGO)) == want


JINJA = {
    "caught: an environment is asked for a template made of the text":
        ("from jinja2 import Environment\n\nenv = Environment()\n\n\n@app.route('/hi')\ndef hi():\n"
         "    return env.from_string(request.args['tpl']).render()\n", ["eval"]),
    "caught: the app's own environment is asked":
        ("@app.route('/hi')\ndef hi():\n    return app.jinja_env.from_string(request.args['tpl']).render()\n",
         ["eval"]),
    "clean: an environment made for templates from outside":
        ("from jinja2.sandbox import SandboxedEnvironment\n\nenv = SandboxedEnvironment()\n\n\n"
         "@app.route('/hi')\ndef hi():\n    return env.from_string(request.args['tpl']).render()\n", []),
    "clean: a fixed template with the value handed in":
        ("from jinja2 import Template\n\n\n@app.route('/hi')\ndef hi():\n"
         "    return Template('Hello {{ name }}').render(name=request.args['name'])\n", []),
}


@pytest.mark.parametrize("case", sorted(JINJA))
def test_text_that_is_run_as_a_jinja_template(tmp_path, case):
    body, want = JINJA[case]
    assert _kinds(_one(tmp_path, body, head=FLASK)) == want


# ------------------------------------------------------------- shapes of code the value passes through

SHAPES = {
    "caught: built in a loop":
        ("@app.get('/s')\ndef s(q: str, db=Depends(get_db)):\n    parts = []\n    for word in q.split():\n"
         "        parts.append(\"name LIKE '%\" + word + \"%'\")\n"
         "    return db.execute('SELECT * FROM items WHERE ' + ' OR '.join(parts)).fetchall()\n", ["sql"]),
    "caught: through a class the route builds":
        ("class Repo:\n    def __init__(self, db):\n        self.db = db\n\n    def search(self, term):\n"
         "        return self.db.execute(\"SELECT * FROM items WHERE name = '\" + term + \"'\").fetchall()\n\n\n"
         "@app.get('/s')\ndef s(q: str, db=Depends(get_db)):\n    repo = Repo(db)\n    return repo.search(q)\n",
         ["sql"]),
    "caught: an f-string":
        ("@app.get('/s')\ndef s(q: str, db=Depends(get_db)):\n"
         "    return db.execute(f\"SELECT * FROM items WHERE name = '{q}'\").fetchall()\n", ["sql"]),
    "caught: the percent form":
        ("@app.get('/s')\ndef s(q: str, db=Depends(get_db)):\n"
         "    return db.execute(\"SELECT * FROM items WHERE name = '%s'\" % q).fetchall()\n", ["sql"]),
    "clean: the percent sign is the driver's own placeholder":
        ("@app.get('/s')\ndef s(q: str, db=Depends(get_db)):\n"
         "    return db.execute('SELECT * FROM items WHERE name = %s', (q,)).fetchall()\n", []),
    "caught: one branch replaces the value, the other does not":
        ("@app.get('/s')\ndef s(q: str, exact: bool = False, db=Depends(get_db)):\n    if exact:\n"
         "        q = 'fixed'\n    return db.execute(\"SELECT * FROM items WHERE name = '\" + q + \"'\").fetchall()\n",
         ["sql"]),
    "clean: both branches replace the value":
        ("@app.get('/s')\ndef s(q: str, exact: bool = False, db=Depends(get_db)):\n    if exact:\n"
         "        q = 'fixed'\n    else:\n        q = 'other'\n"
         "    return db.execute(\"SELECT * FROM items WHERE name = '\" + q + \"'\").fetchall()\n", []),
    "caught: handed back by a helper that reads the request":
        ("from starlette.requests import Request\n\n\ndef wanted(request):\n"
         "    return request.query_params.get('q')\n\n\n@app.get('/s')\n"
         "def s(request: Request, db=Depends(get_db)):\n"
         "    return db.execute(\"SELECT * FROM items WHERE name = '\" + wanted(request) + \"'\").fetchall()\n",
         ["sql"]),
    "clean: a value typed as a number in the route":
        ("@app.get('/s/{item_id}')\ndef s(item_id: int, db=Depends(get_db)):\n"
         "    return db.execute('SELECT * FROM items WHERE id = ' + str(item_id)).fetchall()\n", []),
}


@pytest.mark.parametrize("case", sorted(SHAPES))
def test_the_value_is_followed_through_loops_classes_and_branches(tmp_path, case):
    body, want = SHAPES[case]
    assert _kinds(_one(tmp_path, body)) == want


# ------------------------------------------------------------- a value put into an object and read back out
# What a constructor keeps is on the object (`self.term = term`), field by field; a class with no constructor of its
# own (a dataclass, a form or a model of a library) holds what it was given.

GLUED = "    return db.execute(\"SELECT * FROM items WHERE name = '\" + {x} + \"'\").fetchall()\n"
APART = "    return db.execute('SELECT * FROM items WHERE name = ?', ({x},)).fetchall()\n"
FIND = "@app.get('/s')\ndef s(q: str, db=Depends(get_db)):\n"
DATA = "from dataclasses import dataclass\n\n\n@dataclass\nclass Search:\n    term: str\n    page: int = 1\n\n\n"
KEEPS = "class Search:\n    def __init__(self, term, table='items'):\n        self.term = term\n" \
        "        self.table = table\n        self.size = len(term)\n\n\n"
OBJECTS = {
    "caught: a dataclass holds the value":
        (DATA + FIND + "    s = Search(q)\n" + GLUED.format(x="s.term"), ["sql"]),
    "clean: the dataclass's value is handed to the driver apart":
        (DATA + FIND + "    s = Search(q)\n" + APART.format(x="s.term"), []),
    "clean: a dataclass made of the code's own values":
        (DATA + FIND + "    s = Search('all')\n" + GLUED.format(x="s.term"), []),
    "caught: a constructor keeps the value":
        (KEEPS + FIND + "    s = Search(q)\n" + GLUED.format(x="s.term"), ["sql"]),
    "clean: another field of the same object, which the code set":
        (KEEPS + FIND + "    s = Search(q)\n" + GLUED.format(x="s.table"), []),
    "clean: a field that holds only the value's length":
        (KEEPS + FIND + "    s = Search(q)\n" + GLUED.format(x="str(s.size)"), []),
    "caught: the field the request did set":
        (KEEPS + FIND + "    s = Search('x', table=q)\n" + GLUED.format(x="s.table"), ["sql"]),
    "caught: the parent's constructor keeps the value":
        (KEEPS + "class Paged(Search):\n    def __init__(self, term, page):\n        super().__init__(term)\n"
         "        self.page = page\n\n\n" + FIND + "    s = Paged(q, 1)\n" + GLUED.format(x="s.term"), ["sql"]),
    "caught: a form of a library holds what it was given":
        ("from wtforms import Form, StringField\n\n\nclass SearchForm(Form):\n    term = StringField()\n\n\n"
         + FIND + "    form = SearchForm(term=q)\n" + GLUED.format(x="form.term.data"), ["sql"]),
    "caught: a model of a library made of everything that was sent":
        ("from pydantic import BaseModel\nfrom starlette.requests import Request\n\n\nclass Search(BaseModel):\n"
         "    term: str\n\n\n@app.post('/s')\nasync def s(request: Request, db=Depends(get_db)):\n"
         "    found = Search(**(await request.json()))\n" + GLUED.format(x="found.term"), ["sql"]),
    "caught: the constructor itself puts the value into the query":
        ("class Lookup:\n    def __init__(self, db, term):\n"
         "        self.rows = db.execute(\"SELECT * FROM items WHERE name = '\" + term + \"'\").fetchall()\n\n\n"
         + FIND + "    return Lookup(db, q).rows\n", ["sql"]),
    "clean: the constructor hands the value to the driver apart":
        ("class Lookup:\n    def __init__(self, db, term):\n"
         "        self.rows = db.execute('SELECT * FROM items WHERE name = ?', (term,)).fetchall()\n\n\n"
         + FIND + "    return Lookup(db, q).rows\n", []),
    "caught: the parent's constructor, called by its class name, keeps the value":
        (KEEPS + "class Paged(Search):\n    def __init__(self, term, page):\n        Search.__init__(self, term)\n"
         "        self.page = page\n\n\n" + FIND + "    s = Paged(q, 1)\n" + GLUED.format(x="s.term"), ["sql"]),
    "caught: a named tuple":
        ("from typing import NamedTuple\n\n\nclass Search(NamedTuple):\n    term: str\n\n\n"
         + FIND + "    s = Search(term=q)\n" + GLUED.format(x="s.term"), ["sql"]),
    "clean: a function whose code is not in the project is no object":
        ("from helpers import count\n\n\n" + FIND + "    n = count(q)\n" + GLUED.format(x="str(n)"), []),
}


@pytest.mark.parametrize("case", sorted(OBJECTS))
def test_a_value_put_into_an_object_is_read_back_out_of_it(tmp_path, case):
    body, want = OBJECTS[case]
    assert _kinds(_one(tmp_path, body)) == want


def test_an_object_of_a_class_in_another_file(tmp_path):
    files = {"app/forms.py": "from wtforms import Form, StringField\n\n\nclass SearchForm(Form):\n"
                             "    term = StringField()\n",
             "app/main.py": FASTAPI + "from .forms import SearchForm\n\n\n" + FIND + "    form = SearchForm(term=q)\n"
                            + GLUED.format(x="form.term.data")}
    assert _kinds(_flows(tmp_path, files)) == ["sql"]


def test_a_django_view_reads_the_request_it_is_handed(tmp_path):
    files = {"app/views.py": (
        "from django.db import connection\nfrom django.http import HttpResponse\n\n\ndef profile(request):\n"
        "    name = request.GET.get('name')\n    with connection.cursor() as cur:\n"
        "        cur.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n"
        "    return HttpResponse('<b>' + name + '</b>')\n\n\ndef safe(request):\n"
        "    with connection.cursor() as cur:\n"
        "        cur.execute('SELECT * FROM users WHERE name = %s', [request.GET.get('name')])\n"
        "    return HttpResponse('ok')\n")}
    flows = _flows(tmp_path, files)
    assert sorted((f["class"], f["line"]) for f in flows) == [("sql", 8), ("xss", 9)], flows


# ------------------------------------------------------------- in the findings (security.scan)

def _scan(root, files):
    from lantern.security import scan
    _write(root, files)
    return [f for f in scan(build_graph(root), offline=True)["findings"] if not f["in_tests"]]


def test_a_flow_becomes_a_finding_with_its_steps_and_ranks_as_request_data(tmp_path):
    fs = _scan(tmp_path, CHAIN)
    with_flow = [f for f in fs if f.get("flow")]
    assert len(with_flow) == 1, [(f["rule"], f["file"], f["line"], bool(f.get("flow"))) for f in fs]
    f = with_flow[0]
    assert f["flow"]["class"] == "sql" and f["rank"] == "critical" and f["input"], f
    assert f["flow"]["steps"][0]["file"] == "app/main.py" and f["flow"]["steps"][-1]["file"] == "app/service.py"
    # one finding for one problem: the flow sits on the line another tool flagged, or is a finding of its own
    assert len([x for x in fs if x["file"] == "app/service.py" and x["rank"] in ("critical", "high")]) == 1, fs


def test_a_flow_no_other_tool_saw_is_a_finding_of_its_own(tmp_path):
    body, _ = SSRF["caught: the address comes from the request"]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + DOWNLOAD + body})
    f = next(f for f in fs if f["rule"] == "LT-SSRF")
    assert f["tool"] == "lantern-flow" and f["line"] == 25 and f["rank"] in ("critical", "high"), f
    assert f["flow"]["source"]["what"] and f["title"] and f["cwe"], f


RUN = "def run(cmd):\n    return subprocess.run(cmd, shell=True, capture_output=True).stdout\n\n\n"
FIXED_CALLERS = {
    "lowered: every caller hands it fixed text":
        ("@app.get('/disk')\ndef disk():\n    return run('df -h')\n\n\n@app.get('/up')\ndef up():\n"
         "    return run('uptime')\n", "low"),
    "kept: one caller hands it request data":
        ("@app.get('/disk')\ndef disk():\n    return run('df -h')\n\n\n@app.get('/any')\ndef any_(c: str):\n"
         "    return run(c)\n", "critical"),
    "kept: one caller hands it a value Lantern cannot read":
        ("@app.get('/disk')\ndef disk():\n    return run('df -h')\n\n\n@app.get('/env')\ndef env():\n"
         "    return run(os.environ['CMD'])\n", "critical"),
    "kept: the function is also handed to code Lantern cannot see into":
        ("import atexit\n\natexit.register(run, 'sync')\n\n\n@app.get('/disk')\ndef disk():\n"
         "    return run('df -h')\n\n\ndef table():\n    return {'run': run}\n", "critical"),
}


@pytest.mark.parametrize("case", sorted(FIXED_CALLERS))
def test_fixed_text_from_every_caller_lowers_a_finding_and_a_near_miss_does_not(tmp_path, case):
    body, want = FIXED_CALLERS[case]
    fs = _scan(tmp_path, {"app/main.py": FASTAPI + RUN + body})
    f = next(f for f in fs if f["rule"] == "B602")
    assert f["rank"] == want, (f["rank"], f.get("rank_note"), f.get("input"))
    if want == "low":
        # the calls are the evidence, written on the finding; it stays listed
        assert f["rank_before_context"] in ("critical", "high") and "fixed text" in f["rank_note"], f
        assert f["input"] is False and [c["from"] for c in f["context"]["fixed"]["calls"]] == ["disk", "up"], f


def test_the_viewer_escapes_every_step_of_a_flow():
    # the steps are text from the analyzed code (a file name, a line, the words of a call): none of it may reach the
    # page as markup. `at()` is the box's own helper, which escapes the file and the line.
    import re
    from pathlib import Path
    html = (Path(__file__).parents[1] / "lantern" / "viewer" / "report.html").read_text(encoding="utf-8")
    body = html[html.index("function flowBox(f)"):html.index("// Every call site Lantern read")]
    assert "esc(s.file)" in body and "esc(s.line)" in body, "at() has to escape what it shows"
    seen = 0
    for m in re.finditer(r"\$\{([^}]*)\}", body):
        expr = m.group(1)
        if re.search(r"\b(fl|s|o)\.\w+", expr):
            seen += 1
            assert "esc(" in expr or "at(" in expr or "ticks(" in expr or "?" in expr, f"unescaped flow value: {expr}"
    assert "const ticks = s => esc(s).replace(" in body, "ticks() has to escape before it adds its own tag"
    assert seen >= 6, seen
    assert html.count("${flowBox(f)}") == 2          # the finding card and the finding panel


# ------------------------------------------------------------- a raw place in a page template, in the findings

def _raw(fs):
    return [(f["rule"], f["file"], f["line"], f["tool_confidence"], f["rank"], bool(f.get("flow"))) for f in fs
            if f["rule"] in ("LW-XSS-RAW", "LT-XSS")]


STORED = ("import sqlite3\n\n\n@app.route('/hello')\ndef hello():\n"
          "    row = sqlite3.connect('app.db').execute('SELECT name FROM people WHERE id = 7').fetchone()\n"
          "    return render_template('hello.html', name=row[0])\n")
SAFE_MARK = {
    "request data is followed into it: one finding with the way there":
        (HELLO_ROUTE.format(name=REQ_NAME), "<h1>{{ name|safe }}</h1>\n",
         [("LW-XSS-RAW", "app/templates/hello.html", 1, "LOW", "high", True)]),
    "a value read from the database: a heuristic finding, medium":
        (STORED, "<h1>{{ name|safe }}</h1>\n", [("LW-XSS-RAW", "app/templates/hello.html", 1, "LOW", "medium", False)]),
    "fixed text in the one place that shows the page: ranked low":
        (HELLO_ROUTE.format(name="'you'"), "<h1>{{ name|safe }}</h1>\n",
         [("LW-XSS-RAW", "app/templates/hello.html", 1, "LOW", "low", False)]),
    "the twin that lets the engine escape: nothing":
        (STORED, "<h1>{{ name }}</h1>\n", []),
    "escaped by a filter before it is marked safe: nothing":
        (STORED, "<h1>{{ name|escape|safe }}</h1>\n", []),
}


@pytest.mark.parametrize("case", sorted(SAFE_MARK))
def test_a_template_that_marks_a_value_safe_is_ranked_by_what_is_known_of_the_value(tmp_path, case):
    body, template, want = SAFE_MARK[case]
    fs = _scan(tmp_path, {"app/main.py": FLASK + body, "app/templates/hello.html": template})
    assert _raw(fs) == want, [(f["rule"], f["file"], f["line"], f["rank"]) for f in fs]


# ------------------------------------------------------------- a request body described by a class of the project
# FastAPI hands a route the request's body as an object of a class the project wrote (a pydantic model). Each field is
# one value the request sent, whatever the parameter is called.
BODY = "from pydantic import BaseModel\n\n\nclass NewItem(BaseModel):\n    name: str\n    shelf: str = 'a'\n\n\n"
ADD = "@app.post('/items')\ndef add({p}: NewItem, db=Depends(get_db)):\n"
BODY_CASES = {
    "caught: a field of the body glued into the query":
        (BODY + ADD.format(p="item") + GLUED.format(x="item.name"), ["sql"]),
    "clean: the field goes to the driver apart":
        (BODY + ADD.format(p="item") + APART.format(x="item.name"), []),
    "caught: the parameter is named req, and is the body all the same":
        (BODY + ADD.format(p="req") + GLUED.format(x="req.name"), ["sql"]),
    "clean: the parameter named req, its field handed to the driver apart":
        (BODY + ADD.format(p="req") + APART.format(x="req.name"), []),
    "caught: a helper whose parameter is named req is handed the body":
        (BODY + "def find(db, req: NewItem):\n" + GLUED.format(x="req.name") + "\n\n" +
         ADD.format(p="item") + "    return find(db, item)\n", ["sql"]),
    "clean: the same helper handed a body made of fixed text":
        (BODY + "def find(db, req: NewItem):\n" + GLUED.format(x="req.name") + "\n\n" +
         "@app.post('/items')\ndef add(db=Depends(get_db)):\n    return find(db, NewItem(name='tea'))\n", []),
    "caught: the class comes through a base class of the project's own":
        ("from pydantic import BaseModel\n\n\nclass Strict(BaseModel):\n    pass\n\n\nclass NewItem(Strict):\n"
         "    name: str\n\n\n" + ADD.format(p="item") + GLUED.format(x="item.name"), ["sql"]),
}


@pytest.mark.parametrize("case", sorted(BODY_CASES))
def test_a_body_described_by_a_class_is_what_the_request_sent_field_by_field(tmp_path, case):
    body, want = BODY_CASES[case]
    assert _kinds(_one(tmp_path, body)) == want


def test_a_flow_from_a_body_class_names_the_field(tmp_path):
    (f,) = _one(tmp_path, BODY + ADD.format(p="item") + GLUED.format(x="item.name"))
    assert f["source"]["what"] == "`name` in `item` is what the request sent", f["source"]
    assert f["source"]["line"] == f["line"]             # where the field is read, not where the route begins


# What the class says a field is: pydantic turns the request away unless a field written as a number, a date or a
# UUID is one, so such a field cannot carry text into a query. A field written as text, or not written at all, can.
NUM = "    return db.execute('SELECT * FROM items WHERE id = ' + str({x})).fetchall()\n"
SIZED = ("from datetime import date\nfrom typing import Any, Optional\nfrom uuid import UUID\n\n"
         "from pydantic import BaseModel\n\n\n"
         "class Place(BaseModel):\n    shelf: int\n    label: str\n\n\n"
         "class NewItem(BaseModel):\n    count: int\n    price: float = 0.0\n    limit: Optional[int] = None\n"
         "    page: int | None = None\n    day: date\n    ref: UUID\n    code: str\n    size: Any = None\n"
         "    place: Place\n\n\n")
BODY_NUMBERS = {
    "clean: a field written as a whole number":
        (SIZED + ADD.format(p="item") + NUM.format(x="item.count"), []),
    "clean: a number with a fraction, an optional number, a number or nothing":
        (SIZED + ADD.format(p="item") + "    n = str(item.price) + str(item.limit) + str(item.page)\n" +
         NUM.format(x="n"), []),
    "clean: a date and a UUID":
        (SIZED + ADD.format(p="item") + "    n = str(item.day) + str(item.ref)\n" + NUM.format(x="n"), []),
    "caught: a field written as text, in the same class":
        (SIZED + ADD.format(p="item") + NUM.format(x="item.code"), ["sql"]),
    "caught: a field that may hold anything":
        (SIZED + ADD.format(p="item") + NUM.format(x="item.size"), ["sql"]),
    "caught: a field the class does not write down":
        (SIZED + ADD.format(p="item") + NUM.format(x="item.extra"), ["sql"]),
    "caught: a number field and a text field glued together":
        (SIZED + ADD.format(p="item") + NUM.format(x="item.count) + item.code + str(0"), ["sql"]),
    "clean: a number field of a class kept inside the body":
        (SIZED + ADD.format(p="item") + NUM.format(x="item.place.shelf"), []),
    "caught: a text field of a class kept inside the body":
        (SIZED + ADD.format(p="item") + NUM.format(x="item.place.label"), ["sql"]),
    "clean: the number field comes from a base class of the project's own":
        ("from pydantic import BaseModel\n\n\nclass Sized(BaseModel):\n    count: int\n\n\n"
         "class NewItem(Sized):\n    code: str\n\n\n" + ADD.format(p="item") + NUM.format(x="item.count"), []),
    "caught: the class writes the field again as text":
        ("from pydantic import BaseModel\n\n\nclass Sized(BaseModel):\n    count: int\n\n\n"
         "class NewItem(Sized):\n    count: str\n\n\n" + ADD.format(p="item") + NUM.format(x="item.count"), ["sql"]),
    "clean: a helper is handed the body and reads its number field":
        (SIZED + "def find(db, req: NewItem):\n" + NUM.format(x="req.count") + "\n\n" +
         ADD.format(p="item") + "    return find(db, item)\n", []),
    "caught: the same helper reads the text field":
        (SIZED + "def find(db, req: NewItem):\n" + NUM.format(x="req.code") + "\n\n" +
         ADD.format(p="item") + "    return find(db, item)\n", ["sql"]),
    "caught: a class that is no body class says its field is a number, which nothing enforces":
        ("class NewItem:\n    count: int\n\n\n@app.post('/items')\nasync def add(request: Request, "
         "db=Depends(get_db)):\n    item = NewItem()\n    item.count = (await request.json())['count']\n" +
         NUM.format(x="item.count"), ["sql"]),
}


@pytest.mark.parametrize("case", sorted(BODY_NUMBERS))
def test_a_number_field_of_a_body_class_carries_no_text(tmp_path, case):
    body, want = BODY_NUMBERS[case]
    head = FASTAPI.replace("from fastapi import Depends, FastAPI, HTTPException",
                           "from fastapi import Depends, FastAPI, HTTPException, Request")
    assert _kinds(_one(tmp_path, body, head=head)) == want


def test_a_number_field_of_a_body_class_in_another_file(tmp_path):
    files = {"app/schemas.py": "from pydantic import BaseModel\n\n\nclass NewItem(BaseModel):\n    count: int\n"
                               "    code: str\n",
             "app/main.py": FASTAPI + "from . import schemas\nfrom .schemas import NewItem\n\n\n" +
             ADD.format(p="item") + NUM.format(x="item.count") + "\n\n"
             "@app.post('/more')\ndef more(item: schemas.NewItem, db=Depends(get_db)):\n" +
             NUM.format(x="item.count") + "\n\n"
             "@app.post('/text')\ndef text(item: schemas.NewItem, db=Depends(get_db)):\n" +
             NUM.format(x="item.code")}
    flows = _flows(tmp_path, files)
    assert [(f["class"], f["source"]["what"]) for f in flows] == [
        ("sql", "`code` in `item` is what the request sent")], flows
