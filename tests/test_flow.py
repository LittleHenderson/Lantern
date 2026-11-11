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
