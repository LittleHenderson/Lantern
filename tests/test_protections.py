from lantern.engine import build_graph
from lantern.readiness import assess
from lantern.security import scan


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _prot(root):
    g = build_graph(root)
    return {p["id"]: p for p in assess(g, scan(g), {})["protections"]}


BARE = {
    "pyproject.toml": '[project]\nname = "svc"\nversion = "0.1"\ndependencies = ["fastapi", "requests"]\n',
    "svc/main.py": (
        "import hashlib\nimport requests\nfrom fastapi import FastAPI, UploadFile\n\napp = FastAPI()\n\n"
        "@app.post('/login')\ndef login(email: str, password: str):\n"
        "    return hashlib.sha256(password.encode()).hexdigest()\n\n"
        "@app.post('/preview')\ndef preview(url: str):\n    return requests.get(url).text\n\n"
        "@app.post('/avatar')\nasync def avatar(file: UploadFile):\n    return await file.read()\n"),
}


def test_missing_protections_come_with_evidence(tmp_path):
    _write(tmp_path, BARE)
    p = _prot(tmp_path)
    for k in ("rate-limit", "security-headers", "ssrf-allowlist", "password-hashing", "upload-checks"):
        assert p[k]["status"] == "add" and p[k]["how"] and p[k]["heuristic"], k
    assert any("/login" in e for e in p["rate-limit"]["evidence"])
    assert p["password-hashing"]["evidence"] == ["svc/main.py:9"]
    assert p["ssrf-allowlist"]["evidence"] == ["svc/main.py:13"]


def test_protections_in_place_are_recognized(tmp_path):
    files = dict(BARE)
    files["pyproject.toml"] = files["pyproject.toml"].replace('"requests"]', '"requests", "slowapi", "bcrypt"]')
    files["svc/main.py"] = (files["svc/main.py"].replace("hashlib.sha256(password.encode()).hexdigest()",
                                                         "bcrypt.hashpw(password.encode(), bcrypt.gensalt())")
                            .replace("import hashlib", "import bcrypt")
                            .replace("return requests.get(url).text", "assert host_of(url) in ALLOWED_HOSTS\n"
                                     "    return requests.get(url).text")
                            .replace("return await file.read()", "assert file.content_type == 'image/png'\n"
                                     "    return await file.read()")
                            + "\n@app.middleware('http')\nasync def headers(request, call_next):\n"
                              "    r = await call_next(request)\n    r.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
                              "    return r\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)
    for k in ("rate-limit", "security-headers", "ssrf-allowlist", "password-hashing", "upload-checks"):
        assert p[k]["status"] == "in place", (k, p[k])


def test_managed_auth_and_fixed_urls_raise_nothing(tmp_path):
    _write(tmp_path, {
        "pyproject.toml": '[project]\nname = "svc"\nversion = "0.1"\ndependencies = ["fastapi", "fastapi-users"]\n',
        "svc/main.py": ("import requests\nfrom fastapi import FastAPI\n\napp = FastAPI()\n\n"
                        "@app.get('/rate')\ndef rate(password_hint: str):\n"
                        "    return requests.get('https://api.example.com/rate').json()\n"),
    })
    p = _prot(tmp_path)
    assert "password-hashing" not in p and "ssrf-allowlist" not in p and "upload-checks" not in p


# No frontend at all: nothing for LW-AUTH-MISSING to link, yet the routes are open to anyone.
BACKEND_ONLY = {
    "pyproject.toml": '[project]\nname = "svc"\nversion = "0.1"\ndependencies = ["fastapi"]\n',
    "svc/main.py": (
        "from fastapi import FastAPI\n\napp = FastAPI()\n\n"
        "@app.post('/items')\ndef create_item(name: str):\n    return {'name': name}\n\n"
        "@app.delete('/items/{item_id}')\ndef delete_item(item_id: int):\n    return item_id\n\n"
        "@app.get('/items')\ndef list_items():\n    return []\n"),
}


def test_route_auth_is_missing_without_a_frontend(tmp_path):
    _write(tmp_path, BACKEND_ONLY)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "add"
    assert p["evidence"] == ["POST /items (svc/main.py:5)", "DELETE /items/{item_id} (svc/main.py:9)"]
    assert "2 route(s)" in p["why"] and p["found"] == []


def test_route_auth_in_place_when_every_route_checks(tmp_path):
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = (
        "from fastapi import Depends, FastAPI, Request\n\napp = FastAPI()\n\n"
        "def get_current_user():\n    return 1\n\n"
        "@app.post('/items')\ndef create_item(name: str, user=Depends(get_current_user)):\n    return {'name': name}\n\n"
        "@app.delete('/items/{item_id}')\ndef delete_item(item_id: int, request: Request):\n"
        "    if not request.user.is_admin:\n        raise ValueError('no')\n    return item_id\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "in place", p
    assert p["found"] == ["POST /items: `current_user` in its parameters",
                          "DELETE /items/{item_id}: handler mentions `request.user`"]


def test_route_auth_needs_checking_when_only_middleware_exists(tmp_path):
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] += (
        "\n@app.middleware('http')\nasync def require_login(request, call_next):\n"
        "    if not request.headers.get('authorization'):\n        return deny()\n    return await call_next(request)\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "check", p
    assert p["evidence"][0].startswith("POST /items") and p["found"] == ["svc/main.py:17"]
    assert "confirm" in p["why"]


def test_public_write_routes_need_no_login(tmp_path):
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = ("from fastapi import FastAPI\n\napp = FastAPI()\n\n"
                            "@app.post('/login')\ndef login(email: str, password: str):\n    return email\n\n"
                            "@app.post('/webhooks/stripe')\ndef hook(payload: dict):\n    return payload\n")
    _write(tmp_path, files)
    assert "route-auth" not in _prot(tmp_path)


def test_a_route_path_is_not_a_login_check(tmp_path):
    """'/authors' contains 'auth'; neither the decorator's path nor the route name counts as a check."""
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = files["svc/main.py"].replace("/items", "/authors")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "add" and len(p["evidence"]) == 2


def test_a_comment_or_docstring_is_not_a_login_check(tmp_path):
    """Strings and comments are blanked before the handler's lines are read for login words."""
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = (
        "from fastapi import FastAPI\n\napp = FastAPI()\n\n"
        "@app.post('/items')\ndef create_item(name: str):\n    # TODO: add auth here later\n    return {'name': name}\n\n"
        "@app.delete('/items/{item_id}')\ndef delete_item(item_id: int):\n"
        "    \"\"\"Delete an item.\n\n    Needs a permission check and current_user once login exists.\n    \"\"\"\n"
        "    msg = 'authorized by nobody'\n    return item_id\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "add", p
    assert p["evidence"] == ["POST /items (svc/main.py:5)", "DELETE /items/{item_id} (svc/main.py:10)"]


def test_looking_up_the_target_user_is_not_a_login_check(tmp_path):
    """`who = get_user(payload['owner'])` fetches the record's owner, not the caller (the IDOR shape). With the
    result tested it is a weak sign, so the status is `check`, never `in place`. `get_user(token)` is a real check."""
    files = dict(BACKEND_ONLY)
    files["svc/main.py"] = (
        "from fastapi import FastAPI, Header\n\napp = FastAPI()\n\n"
        "def get_user(key):\n    return {'id': key}\n\n"
        "@app.post('/items')\ndef create_item(payload: dict):\n    who = get_user(payload.get('owner'))\n"
        "    if not who:\n        raise ValueError('no such user')\n    return {'owner': who['id']}\n\n"
        "@app.delete('/items/{item_id}')\ndef delete_item(item_id: int, x_key: str = Header()):\n"
        "    who = get_user(token=x_key)\n    return who\n")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "check", p
    assert p["evidence"] == ["POST /items (svc/main.py:8): `get_user(payload.get('owner'))` looks up a user by "
                             "`payload.get('owner')`, not by who is calling"]
    assert p["found"] == ["DELETE /items/{item_id}: handler calls `get_user(token=x_key)`"]
    assert "record's owner" in p["why"]
    # the same lookup without testing the result is no sign at all
    files["svc/main.py"] = files["svc/main.py"].replace("    if not who:\n        raise ValueError('no such user')\n", "")
    _write(tmp_path, files)
    p = _prot(tmp_path)["route-auth"]
    assert p["status"] == "add" and p["evidence"] == ["POST /items (svc/main.py:8)"], p
