"""Paired controls for context.py: for each false alarm found on a real app (Noetic Compass, 2026-11-08), a safe example
that must NOT be raised and an unsafe one that MUST still be raised, including wrappers, aliases and misleading names.
None of these files is copied from that app; they are written to have the same shape."""

import pytest

from lantern.engine import build_graph
from lantern.readiness import assess
from lantern.security import scan

HEAD = "import base64\nimport hashlib\nfrom fastapi import FastAPI\n\napp = FastAPI()\n\n"


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _findings(root, files, rule):
    _write(root, files)
    g = build_graph(root)
    return [f for f in scan(g, offline=True)["findings"] if f["rule"] == rule and not f["in_tests"]]


def _one(root, body, rule="B324"):
    fs = _findings(root, {"pyproject.toml": '[project]\nname="a"\nversion="0"\n', "a/main.py": HEAD + body}, rule)
    assert len(fs) == 1, [(f["rule"], f["line"]) for f in fs]
    return fs[0]


# ---------------------------------------------------------------- weak hashes: safe uses must not be critical

SAFE_HASHES = {
    "synthetic id through a wrapper": (
        "def _short_hash(value: str) -> str:\n    return hashlib.sha1(value.encode('utf-8')).hexdigest()[:12]\n\n"
        "@app.post('/records')\ndef make_record(seed: str, source_id: str):\n"
        "    digest = _short_hash(f'{seed}|{source_id}')\n    return 'rec-' + digest\n"),
    "random seed": (
        "import random\n\n@app.post('/variants')\ndef variants(group_id: str):\n"
        "    group_seed = int.from_bytes(\n        hashlib.md5(group_id.encode('utf-8')).digest()[:4], 'big',\n    )\n"
        "    return random.Random(group_seed).random()\n"),
    "S3 ContentMD5 header": (
        "@app.post('/anchor')\ndef anchor(manifest: dict):\n    body = repr(manifest).encode()\n"
        "    put_kwargs = {'Body': body}\n"
        "    put_kwargs['ContentMD5'] = base64.b64encode(hashlib.md5(body).digest()).decode('ascii')\n"
        "    return put_kwargs\n"),
    "S3 ContentMD5 in a dict literal": (
        "@app.post('/store')\ndef store(body: bytes):\n"
        "    return {'ContentType': 'application/json',\n"
        "            'ContentMD5': base64.b64encode(hashlib.md5(body).digest()).decode('ascii')}\n"),
    "cache key with an alias import": (
        "from hashlib import md5 as fast\n\n@app.get('/page')\ndef page(path: str):\n"
        "    cache_key = fast(path.encode()).hexdigest()\n    return cache_key\n"),
}


@pytest.mark.parametrize("case", sorted(SAFE_HASHES))
def test_a_weak_hash_used_as_an_id_seed_or_checksum_is_low(tmp_path, case):
    f = _one(tmp_path, SAFE_HASHES[case])
    assert f["context"]["hash"]["purpose"] == "non-security", f["context"]
    assert f["rank"] == "low"
    # the finding stays, with the reason and the rank it would have had
    assert f["rank_note"] and f["rank_before_context"] in ("critical", "high", "medium")


# ---------------------------------------------------------------- weak hashes: real security uses must stay

UNSAFE_HASHES = {
    "password hashed directly": (
        "@app.post('/signup')\ndef signup(email: str, password: str):\n"
        "    return hashlib.md5(password.encode()).hexdigest()\n"),
    "password through a neutral wrapper": (
        "def h(x: str) -> str:\n    return hashlib.md5(x.encode()).hexdigest()[:16]\n\n"
        "@app.post('/signup')\ndef signup(email: str, password: str):\n    stored = h(password)\n    return stored\n"),
    "password behind a misleading name": (
        "@app.post('/signup')\ndef make_cache_key(pw: str):\n    record_id = hashlib.sha1(pw.encode()).hexdigest()\n"
        "    return record_id\n"),
    "token signature": (
        "@app.post('/sign')\ndef sign_message(msg: str):\n"
        "    signature = hashlib.sha1(('k' + msg).encode()).hexdigest()\n    return signature\n"),
    "password through an alias import": (
        "from hashlib import md5 as fast\n\n@app.post('/login')\ndef login(passwd: str):\n"
        "    return fast(passwd.encode()).hexdigest()\n"),
}


@pytest.mark.parametrize("case", sorted(UNSAFE_HASHES))
def test_a_weak_hash_protecting_a_secret_is_still_critical(tmp_path, case):
    f = _one(tmp_path, UNSAFE_HASHES[case])
    assert f["context"]["hash"]["purpose"] == "security", f["context"]
    assert f["rank"] == "critical", (f["rank"], f.get("input"))
    assert "rank_note" not in f


def test_a_weak_hash_of_unknown_purpose_is_not_critical_but_stays_visible(tmp_path):
    f = _one(tmp_path, "@app.post('/x')\ndef handle(data: str):\n    digest = hashlib.md5(data.encode()).hexdigest()\n"
                       "    return digest\n")
    assert f["context"]["hash"]["purpose"] == "unknown"
    assert f["rank"] == "medium" and f["rank_before_context"] == "critical" and "could not tell" in f["rank_note"]


# ---------------------------------------------------------------- SQL: fixed text spliced, values as parameters

SAFE_SQL = {
    "choice between two fixed strings": (
        "@app.get('/lease')\ndef get_lease(conn, tenant_id: str, resource_id: str, now=None):\n"
        "    if now is None:\n        cmp_now_sql = 'now()'\n        params = (tenant_id, resource_id)\n"
        "    else:\n        cmp_now_sql = '%s'\n        params = (tenant_id, resource_id, now)\n"
        "    return conn.execute(\n        f'''\n        SELECT tenant_id, holder FROM leases\n"
        "         WHERE tenant_id = %s AND resource_id = %s\n           AND expires_at > {cmp_now_sql}\n        ''',\n"
        "        params,\n    ).fetchone()\n"),
    "conditional expression of literals": (
        "@app.get('/items')\ndef items(conn, desc: bool, owner: str):\n    order = 'DESC' if desc else 'ASC'\n"
        "    return conn.execute(f'SELECT * FROM items WHERE owner = %s ORDER BY id {order}', (owner,))\n"),
    "module constant": (
        "TABLE = 'leases'\n\n@app.get('/rows')\ndef rows(conn, row_id: str):\n"
        "    return conn.execute(f'SELECT * FROM {TABLE} WHERE id = %s', (row_id,))\n"),
}

UNSAFE_SQL = {
    "parameter spliced into an f-string": (
        "@app.get('/items')\ndef items(conn, sort: str):\n    return conn.execute(f'SELECT * FROM items ORDER BY {sort}')\n"),
    "misleading name holding input": (
        "@app.get('/items')\ndef items(conn, sort: str):\n    safe_sql = sort\n"
        "    return conn.execute(f'SELECT * FROM items ORDER BY {safe_sql}', ())\n"),
    "one branch is input": (
        "@app.get('/items')\ndef items(conn, desc: bool, col: str):\n    order = 'id' if desc else col\n"
        "    return conn.execute(f'SELECT * FROM items ORDER BY {order}', ())\n"),
    "concatenation": (
        "@app.get('/items')\ndef items(conn, name: str):\n"
        "    return conn.execute('SELECT * FROM items WHERE name = ' + name)\n"),
    "format call": (
        "@app.get('/items')\ndef items(conn, name: str):\n"
        "    return conn.execute(\"SELECT * FROM items WHERE name = '{}'\".format(name))\n"),
    # from the independent review (2026-11-09): fixed text first, then input through a binding Lantern did not follow
    "match capture replaces the fixed text": (
        "@app.get('/rows')\ndef rows(conn, payload: dict):\n    order = 'id'\n    match payload:\n"
        "        case {'order': order}:\n            pass\n"
        "    return conn.execute(f'SELECT * FROM items ORDER BY {order}')\n"),
    "inner function rebinds it with nonlocal": (
        "@app.get('/rows')\ndef rows(conn, text: str):\n    order = 'id'\n    def replace():\n"
        "        nonlocal order\n        order = text\n    replace()\n"
        "    return conn.execute(f'SELECT * FROM items ORDER BY {order}')\n"),
    "inner function rebinds a module value with global": (
        "ORDER = 'id'\n\n@app.get('/rows')\ndef rows(conn, text: str):\n    def replace():\n"
        "        global ORDER\n        ORDER = text\n    replace()\n"
        "    return conn.execute(f'SELECT * FROM items ORDER BY {ORDER}')\n"),
    "another function rebinds a module value with global": (
        "ORDER = 'id'\n\ndef set_order(text):\n    global ORDER\n    ORDER = text\n\n"
        "@app.get('/rows')\ndef rows(conn, text: str):\n    set_order(text)\n"
        "    return conn.execute(f'SELECT * FROM items ORDER BY {ORDER}')\n"),
    "except as rebinds it": (
        "@app.get('/rows')\ndef rows(conn, text: str):\n    order = 'id'\n    try:\n        int(text)\n"
        "    except ValueError as order:\n        pass\n"
        "    return conn.execute(f'SELECT * FROM items ORDER BY {order}')\n"),
}


@pytest.mark.parametrize("case", sorted(SAFE_SQL))
def test_sql_that_splices_only_fixed_text_is_low(tmp_path, case):
    f = _one(tmp_path, SAFE_SQL[case], "B608")
    assert f["context"]["sql"]["fixed_only"], f["context"]
    assert f["rank"] == "low" and f["input"] is False and "Only fixed text" in f["rank_note"]


@pytest.mark.parametrize("case", sorted(UNSAFE_SQL))
def test_sql_that_splices_a_value_is_still_raised(tmp_path, case):
    f = _one(tmp_path, UNSAFE_SQL[case], "B608")
    assert not f["context"]["sql"]["fixed_only"], f["context"]
    assert f["rank"] == "high" and "rank_note" not in f
    assert any(not s["fixed"] for s in f["context"]["sql"]["spliced"])


# ---------------------------------------------------------------- slow password hashing

def _prot(root, files):
    _write(root, {"pyproject.toml": '[project]\nname="a"\nversion="0"\ndependencies=["fastapi"]\n', **files})
    g = build_graph(root)
    return {p["id"]: p for p in assess(g, scan(g, offline=True), {})["protections"]}


def test_a_seed_hash_and_the_word_password_in_a_regex_is_not_a_password_problem(tmp_path):
    p = _prot(tmp_path, {"a/main.py": HEAD + (
        "import re\nBLOCKED = [r'\\bpassword(?:s)?\\b', r'\\breset (?:your )?password\\b']\n\n"
        "def _text_seed(text: str) -> int:\n    return int(hashlib.sha256(text.encode()).hexdigest()[:8], 16)\n\n"
        "@app.post('/score')\ndef score(text: str):\n    return _text_seed(text) + sum(bool(re.search(b, text)) for b in BLOCKED)\n")})
    assert "password-hashing" not in p


def test_a_password_value_without_hashing_is_check_not_add(tmp_path):
    p = _prot(tmp_path, {"a/main.py": HEAD + (
        "import os\n\ndef _text_seed(text: str) -> int:\n    return int(hashlib.sha256(text.encode()).hexdigest()[:8], 16)\n\n"
        "@app.post('/db')\ndef db(text: str):\n    db_password = os.environ['DB_PASSWORD']\n"
        "    return _text_seed(text), connect(password=db_password)\n")})
    assert p["password-hashing"]["status"] == "check"


def test_a_fast_hash_on_a_password_through_a_wrapper_is_add(tmp_path):
    p = _prot(tmp_path, {"a/main.py": HEAD + (
        "def digest(x: str) -> str:\n    return hashlib.sha256(x.encode()).hexdigest()\n\n"
        "@app.post('/signup')\ndef signup(email: str, password: str):\n    stored = digest(password)\n    return stored\n")})
    assert p["password-hashing"]["status"] == "add"
    assert p["password-hashing"]["evidence"] == ["a/main.py:8"]


def test_the_word_bcrypt_inside_a_regex_string_is_not_a_hashing_library(tmp_path):
    """`r"\\bcrypto"` reads as "bcrypt" to a plain search; that once marked a repo's passwords as safely hashed."""
    files = {"a/main.py": HEAD + (
        "import os\nWORDS = [r'\\bcrypto(?:currency)?\\b']\n\n@app.post('/db')\ndef db():\n"
        "    db_password = os.environ['DB_PASSWORD']\n    return connect(password=db_password), WORDS\n")}
    assert _prot(tmp_path / "regex", files)["password-hashing"]["status"] == "check"
    files["a/main.py"] = "import bcrypt\n" + files["a/main.py"]
    assert _prot(tmp_path / "real", files)["password-hashing"]["status"] == "in place"


def test_a_cut_short_hash_inside_an_auth_class_is_not_called_an_identifier(tmp_path):
    """Held-out check (requests' HTTPDigestAuth): a client nonce cut to 16 characters is part of a login scheme."""
    f = _one(tmp_path, "import os\n\nclass HTTPDigestAuth:\n    def build_header(self, nonce: str):\n"
                       "        s = nonce.encode() + os.urandom(8)\n        cnonce = hashlib.sha1(s).hexdigest()[:16]\n"
                       "        return cnonce\n\n@app.get('/x')\ndef x(n: str):\n    return HTTPDigestAuth().build_header(n)\n")
    assert f["context"]["hash"]["purpose"] == "security" and "rank_note" not in f


# ---------------------------------------------------------------- a value the browser can see: does the server trust it?

FRONT = ("web/package.json", '{"name":"web","dependencies":{"react":"18"}}')
FRONT_CODE = ("export function mintHeaders() {\n  const s = import.meta.env.VITE_AUTH_MINT_SECRET ?? '';\n"
              "  return s ? { 'X-Auth-Mint-Secret': s } : {};\n}\n")
API_HEAD = ("from fastapi import FastAPI, Request, HTTPException, Depends\nfrom pydantic import BaseModel\n\n"
            "app = FastAPI()\n\nclass TokenResponse(BaseModel):\n    token: str\n\n")


def _trust(root, server: str | None, extra=None):
    files = {FRONT[0]: FRONT[1], "web/src/config.ts": FRONT_CODE, **(extra or {})}
    if server is not None:
        files["pyproject.toml"] = '[project]\nname="api"\nversion="0"\ndependencies=["fastapi"]\n'
        files["api/main.py"] = API_HEAD + server
    _write(root, files)
    g = build_graph(root)
    fs = [f for f in scan(g, offline=True)["findings"] if f["rule"] == "LW-PUBLIC-SECRET" and not f["in_tests"]]
    assert len(fs) == 1
    return fs[0]


def test_exposed_value_that_the_server_checks_names_route_controls_and_conditions(tmp_path):
    f = _trust(tmp_path, (
        "import os\nimport hmac\nMINT = os.environ.get('NC_AUTH_MINT_SECRET', '')\nACCOUNTS = False\n\n"
        "class settings:\n    accounts_enabled = False\n\n"
        "@app.post('/auth/token', response_model=TokenResponse)\ndef mint(request: Request):\n"
        "    if settings.accounts_enabled:\n        raise HTTPException(401)\n"
        "    presented = request.headers.get('X-Auth-Mint-Secret') or ''\n"
        "    if not hmac.compare_digest(presented, MINT):\n        raise HTTPException(401)\n"
        "    return TokenResponse(token='t')\n"))
    t = f["trust"]
    assert t["browser"]["sent_as"] == "X-Auth-Mint-Secret" and t["server_trusts"] == "server-checks-it"
    assert t["routes"] == ["POST /auth/token"] and "accounts_enabled" in t["conditions"]
    assert t["stranger_access"] == "not determined"     # visible + trusted is never called a confirmed bypass
    assert f["rank"] == "high"                          # and it is never lowered


def test_exposed_value_with_no_server_use_says_so_and_stays_high(tmp_path):
    f = _trust(tmp_path, "@app.get('/health')\ndef health():\n    return {'ok': True}\n")
    assert f["trust"]["server_trusts"] == "not-seen-on-server" and f["rank"] == "high"


def test_exposed_value_with_no_server_in_the_repo_is_unknown(tmp_path):
    f = _trust(tmp_path, None)
    assert f["trust"]["server_trusts"] == "no-server-code"
    assert any("not in this repository" in u for u in f["trust"]["unknown"])


def test_a_docstring_about_the_header_is_not_server_code_checking_it(tmp_path):
    f = _trust(tmp_path, ('"""Clients send X-Auth-Mint-Secret; the check lives elsewhere."""\n\n'
                          "@app.get('/health')\ndef health():\n    return {'ok': True}\n"))
    assert f["trust"]["server_trusts"] == "not-seen-on-server"


def test_other_server_side_controls_are_reported_per_route(tmp_path):
    f = _trust(tmp_path, (
        "def require_role(*roles):\n    def dep(request: Request):\n        return request.state.user\n    return dep\n\n"
        "@app.post('/accounts/invite')\ndef invite(request: Request, _role=Depends(require_role('admin'))):\n"
        "    if request.headers.get('X-Auth-Mint-Secret'):\n        raise HTTPException(400)\n    return {}\n"))
    ctl = {c["route"]: c for c in f["trust"]["other_controls"]}
    assert ctl["POST /accounts/invite"]["login_check"] == "strong"


# ---------------------------------------------------------------- route login checks: what a decorator says it returns

def _auth_missing(root, deco):
    _write(root, {"pyproject.toml": '[project]\nname="a"\nversion="0"\ndependencies=["fastapi"]\n',
                  "a/main.py": API_HEAD + "def verify_token():\n    return True\n\n"
                  + deco + "\ndef delete_item(item_id: int):\n    return {'deleted': item_id}\n"})
    g = build_graph(root)
    from lantern.websec import call_adjacency, login_check
    n = next(x for x in g.nodes.values() if x.name == "delete_item")
    return login_check(g, n, call_adjacency(g), (root / "a/main.py").read_text(encoding="utf-8"))


def test_a_response_model_named_token_is_not_a_login_check(tmp_path):
    assert _auth_missing(tmp_path, "@app.delete('/items/{item_id}', response_model=TokenResponse)") is None


def test_a_dependency_in_the_decorator_still_is(tmp_path):
    lc = _auth_missing(tmp_path, "@app.delete('/items/{item_id}', response_model=TokenResponse, "
                                 "dependencies=[Depends(verify_token)])")
    assert lc and lc[0] == "strong"


def test_a_request_body_type_named_token_is_not_a_login_check(tmp_path):
    from lantern.websec import signature_sign
    assert signature_sign("def mint(body: TokenRequest, request: Request)") is None
    assert signature_sign("def login(form: OAuth2PasswordRequestForm = Depends())") is None
    # the caller's identity still counts
    assert signature_sign("def me(user: CurrentUser)")
    assert signature_sign("def me(user: Annotated[User, Depends(get_current_user)])")
    assert signature_sign("def me(token: str = Depends(oauth2_scheme))")


# ---------------------------------------------------------------- unresolved calls: one denominator, kinds, test code apart

def test_call_sites_share_one_denominator_and_test_code_is_counted_apart(tmp_path):
    _write(tmp_path, {
        "pyproject.toml": '[project]\nname="a"\nversion="0"\n',
        "a/core.py": "import json\n\ndef helper():\n    return 1\n\ndef run(x, rows):\n    helper()\n    helper()\n"
                     "    json.dumps(x)\n    x.frobnicate()\n    rows[0]()\n    make()()\n    self_made()\n",
        "tests/test_core.py": "def test_run(x):\n    x.assert_called()\n"})
    g = build_graph(tmp_path)
    c = g.call_sites()
    assert c["resolved_internal"] == 2 and c["known_external"] == 1          # two lines call helper: two call sites
    assert c["total"] == sum(c[k] for k in ("resolved_internal", "inferred_internal", "several_possible_targets",
                                             "name_only_guess", "known_external", "unresolved"))
    assert c["unresolved_in_tests"] == 1                                    # counted, and said apart
    k = c["unresolved_kinds"]
    assert k["method on a value of unknown type"] == 1 and k["name not found"] >= 1
    # saved and loaded: the totals travel; nothing is recomputed from the 200 most common texts
    g.save(tmp_path / "g.json")
    from lantern.graph import Graph
    c2 = Graph.load(tmp_path / "g.json").call_sites()
    assert c2 == c


def test_unresolved_kind_reads_the_shape_only():
    from lantern.graph import unresolved_kind
    assert unresolved_kind("self.client.get") == "member of self or this"
    assert unresolved_kind("payload.get") == "method on a value of unknown type"
    assert unresolved_kind("Path(__file__).resolve") == "on another call's result"
    assert unresolved_kind("getattr(mod, name)") == "dynamic (subscript, getattr, computed)"
    assert unresolved_kind("model") == "name not found"
