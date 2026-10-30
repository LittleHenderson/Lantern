import json
from pathlib import Path

from lantern.cli import main
from lantern.engine import build_graph
from lantern.readiness import CATEGORIES, assess
from lantern.security import scan

FIX = Path(__file__).parent / "fixtures"
EMPTY_SEC = {"findings": [], "tools": [], "counts": {}}


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _checks(r):
    return {c["id"]: c for cat in r["categories"] for c in cat["checks"]}


API = {
    "pyproject.toml": '[project]\nname = "svc"\nversion = "0.1"\ndependencies = ["fastapi>=0.110", "httpx>=0.27"]\n',
    "svc/__init__.py": "",
    "svc/main.py": (
        "import os\nimport httpx\nfrom fastapi import FastAPI\n\napp = FastAPI()\n"
        "TOKEN = os.environ['PAYMENT_TOKEN']\n\n"
        "@app.post('/charge')\ndef charge():\n    try:\n        return httpx.post('https://pay.example/x')\n"
        "    except:\n        return None\n"
    ),
}


def test_weights_sum_to_100():
    assert sum(w for _, _, w in CATEGORIES) == 100


def test_bare_api_scores_low_with_reasons(tmp_path):
    _write(tmp_path, API)
    g = build_graph(tmp_path)
    r = assess(g, EMPTY_SEC)
    c = _checks(r)
    assert r["shape"] == "web API"
    assert c["input-bare-except"]["status"] in ("partial", "fail")
    assert "svc/main.py:12" in c["input-bare-except"]["evidence"]
    assert c["res-timeout"]["status"] == "fail"
    assert c["obs-health"]["status"] == "fail"
    assert c["secrets-example"]["status"] == "fail"
    assert c["pkg-docker"]["status"] == "fail"
    assert c["ci-exists"]["status"] == "fail"
    assert r["score"] < 60 and r["grade"] == "F"
    # every failed check says how to fix it or why it failed
    assert all(k["evidence"] for k in c.values())
    # Starter files for what's missing; .env.example lists the variable the code reads
    st = r["starter"]
    assert "PAYMENT_TOKEN=" in st[".env.example"]["content"]
    assert "USER app" in st["Dockerfile"]["content"] and "svc.main:app" in st["Dockerfile"]["content"]
    assert ".github/workflows/ci.yml" in st and "SECURITY.md" in st
    assert any("health" in k for k in st)


def test_fixing_things_raises_the_score(tmp_path):
    _write(tmp_path, API)
    before = assess(build_graph(tmp_path), EMPTY_SEC)["score"]
    fixed = dict(API)
    fixed["svc/main.py"] = (
        "import logging\nimport os\nimport httpx\nfrom fastapi import FastAPI\n\napp = FastAPI()\n"
        "log = logging.getLogger(__name__)\nTOKEN = os.environ['PAYMENT_TOKEN']\n\n"
        "@app.get('/health')\ndef health():\n    return {'ok': True}\n\n"
        "@app.post('/charge')\ndef charge():\n    return httpx.post('https://pay.example/x', timeout=5)\n"
    )
    fixed.update({
        ".env.example": "PAYMENT_TOKEN=\n",
        "uv.lock": "",
        "Dockerfile": "FROM python:3.12-slim\nRUN useradd app\nUSER app\nCMD [\"uvicorn\", \"svc.main:app\"]\n",
        ".dockerignore": ".env\n",
        ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: python -m pytest\n      - run: lantern analyze .\n",
        "README.md": "# svc\n\n```\npip install -e .\n```\n",
        "LICENSE": "MIT",
        "SECURITY.md": "Report privately.",
        "tests/test_charge.py": "from svc.main import charge\n\ndef test_charge():\n    charge()\n",
    })
    _write(tmp_path, fixed)
    r = assess(build_graph(tmp_path), EMPTY_SEC)
    c = _checks(r)
    assert c["obs-health"]["status"] == "pass"
    assert c["res-timeout"]["status"] == "pass"
    assert c["pkg-user"]["status"] == "pass" and c["pkg-slim"]["status"] == "pass"
    assert c["ci-tests"]["status"] == "pass" and c["ci-scan"]["status"] == "pass"
    assert c["deps-lock"]["status"] == "pass"
    assert r["score"] > before + 30
    assert "Dockerfile" not in r["starter"] and ".env.example" not in r["starter"]


def test_skipped_checks_do_not_count_against_a_library(tmp_path):
    _write(tmp_path, {"pyproject.toml": '[project]\nname = "lib"\n', "lib/__init__.py": "def add(a, b):\n    return a + b\n",
                      "README.md": "pip install lib", "LICENSE": "MIT", "SECURITY.md": "x",
                      ".github/workflows/ci.yml": "run: pytest && bandit -r lib",
                      "tests/test_add.py": "from lib import add\n\ndef test_add():\n    assert add(1, 2) == 3\n"})
    r = assess(build_graph(tmp_path), EMPTY_SEC)
    c = _checks(r)
    assert r["shape"] == "library"
    for cid in ("obs-health", "pkg-docker", "res-shutdown", "input-validation", "obs-logging"):
        assert cid not in c or c[cid]["status"] == "skip"
    assert r["score"] >= 90


def test_test_fixtures_do_not_describe_the_project(tmp_path):
    _write(tmp_path, {"pyproject.toml": '[project]\nname = "tool"\n[project.scripts]\ntool = "tool:main"\n',
                      "tool/__init__.py": "def main():\n    pass\n",
                      "tests/fixtures/app/package.json": '{"dependencies": {"next": "14"}}',
                      "tests/fixtures/app/vercel.json": "{}"})
    r = assess(build_graph(tmp_path), EMPTY_SEC)
    assert "Next.js" not in r["stack"]["frameworks"] and not r["stack"]["deploy_targets"]


def test_shop_fixture_end_to_end(tmp_path):
    g = build_graph(FIX / "shop")
    sec = scan(g)
    r = assess(g, sec)
    c = _checks(r)
    assert r["shape"] == "full-stack web app"
    assert c["sec-critical"]["status"] == "fail"
    assert c["secrets-none"]["status"] == "fail"
    assert "VITE_ADMIN_SECRET" in r["starter"][".env.example"]["content"]
    assert "sent to the browser" in r["starter"][".env.example"]["content"]
    ci = r["starter"][".github/workflows/ci.yml"]["content"]
    assert "working-directory: web" in ci


def test_accept_finding_and_fail_on(tmp_path):
    _write(tmp_path, {"app.py": "import subprocess\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n\n"
                                "if __name__ == '__main__':\n    run('ls')\n"})
    out = tmp_path / "out"
    assert main(["analyze", str(tmp_path), "--out", str(out)]) == 0
    sec = json.loads((out / "security.json").read_text(encoding="utf-8"))
    f = next(x for x in sec["findings"] if x["rule"] == "B602")
    worst = f["rank"]
    assert main(["analyze", str(tmp_path), "--out", str(out), "--fail-on", worst]) == 1
    assert main(["accept", str(tmp_path), f["id"], "--out", str(out), "--reason", "short"]) == 2
    assert main(["accept", str(tmp_path), f["id"], "--out", str(out),
                 "--reason", "Only runs fixed commands from our own admin script", "--by", "tester"]) == 0
    saved = json.loads((tmp_path / "lantern-accepted.json").read_text(encoding="utf-8"))
    assert saved["accepted"][0]["by"] == "tester"
    assert main(["analyze", str(tmp_path), "--out", str(out), "--fail-on", worst]) == 0
    sec = json.loads((out / "security.json").read_text(encoding="utf-8"))
    f2 = next(x for x in sec["findings"] if x["id"] == f["id"])
    assert f2["status"] == "accepted" and f2["accepted"]["reason"].startswith("Only runs")
    assert sec["counts"]["accepted"] == 1
    rd = json.loads((out / "readiness.json").read_text(encoding="utf-8"))
    assert "accepted" in _checks(rd)[f"sec-{worst}"]["evidence"]
    assert main(["accept", str(tmp_path), f["id"], "--out", str(out), "--remove"]) == 0


def test_starter_write_never_overwrites(tmp_path, capsys):
    _write(tmp_path, API)
    out = tmp_path / ".lantern"
    assert main(["analyze", str(tmp_path), "--no-scan"]) == 0
    (tmp_path / "SECURITY.md").write_text("mine", encoding="utf-8")
    assert main(["starter", str(tmp_path), "--write", "all"]) == 0
    assert (tmp_path / "SECURITY.md").read_text(encoding="utf-8") == "mine"
    assert (tmp_path / "Dockerfile").exists() and (tmp_path / ".github/workflows/ci.yml").exists()
    assert (out / "readiness.json").exists()
    assert main(["starter", str(tmp_path), "--write", "../evil"]) == 0
    assert not (tmp_path.parent / "evil").exists()
