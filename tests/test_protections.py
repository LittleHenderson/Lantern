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
