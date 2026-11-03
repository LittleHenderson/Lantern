"""Per-pack on/off (Settings → Analysis packs): a pack turned off is not used, is listed as off, and the Evidence
Report's provenance says so; turning it back on brings its findings back."""
import json
import os
import time

from lantern import pipeline

from test_packs import DJANGO_APP, _write
from test_server import call, srv  # noqa: F401  (fixture)


def _settings(home, data):
    home.mkdir(parents=True, exist_ok=True)
    (home / "settings.json").write_text(json.dumps(data), encoding="utf-8")


def _analyze(repo):
    out = repo / ".lantern"
    out.mkdir(exist_ok=True)
    pipeline.analyze(repo, out, offline=True, log=lambda m: None)
    sec = json.loads((out / "security.json").read_text(encoding="utf-8"))
    ev = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    g = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    lp = [f for f in sec["findings"] if f["rule"].startswith("LP-")]
    prov = [r for r in ev["provenance"]["rules"] if r.startswith("analysis pack django")]
    return lp, prov, g["meta"].get("packs") or {}


def test_django_off_then_on(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("LANTERN_HOME", str(home))
    repo = tmp_path / "app"
    _write(repo, DJANGO_APP)

    _settings(home, {"packs": {"disabled": ["django"]}})
    lp, prov, meta = _analyze(repo)
    assert lp == []
    assert prov == ["analysis pack django v1 (off (turned off in Settings))"]
    assert meta.get("disabled") == ["django"] and meta.get("added") == 0
    entries = [n for n in json.loads((repo / ".lantern/graph.json").read_text(encoding="utf-8"))["nodes"]
               if (n.get("entry") or {}).get("via") == "pack:django"]
    assert entries == []

    _settings(home, {"packs": {"disabled": []}})
    lp, prov, meta = _analyze(repo)
    assert {f["rule"] for f in lp} >= {"LP-DJANGO-DEBUG", "LP-DJANGO-HOSTS-ANY"}
    assert len(prov) == 1 and prov[0].startswith("analysis pack django v1 (ok (builtin,")
    assert "disabled" not in meta and meta["packs"] == ["django"]


def test_packs_endpoints_and_stale_card(srv, tmp_path, monkeypatch):  # noqa: F811
    base, store = srv
    monkeypatch.setenv("LANTERN_HOME", str(store.root))
    repo = tmp_path / "app"
    _write(repo, DJANGO_APP)
    code, proj = call(base, "/api/projects", "POST", {"path": str(repo)})
    pid = (proj.get("project") or proj)["id"]
    (repo / ".lantern").mkdir(exist_ok=True)
    (repo / ".lantern" / "report.html").write_text("x", encoding="utf-8")
    old = time.time() - 100
    os.utime(repo / ".lantern" / "report.html", (old, old))

    code, d = call(base, f"/api/packs?project={pid}")
    assert code == 200
    dj = next(p for p in d["packs"] if p["name"] == "django")
    assert dj == {"name": "django", "version": "1", "source": "builtin", "rules": dj["rules"], "entry_patterns": 2,
                  "path": "lantern/packs/django.json", "enabled": True, "active": True, "about": dj["about"]}
    assert dj["rules"] >= 3

    code, r = call(base, "/api/packs", "POST", {"name": "django", "enabled": False, "project": pid})
    assert code == 200 and next(p for p in r["packs"] if p["name"] == "django")["enabled"] is False
    assert store.settings()["packs"]["disabled"] == ["django"]
    code, st = call(base, "/api/state")
    card = next(p for p in st["projects"] if p["id"] == pid)
    assert card["stale"] == "packs"   # "Re-check to apply"
    store.save_settings({**store.settings(), "backdrop": "off"})   # another settings save keeps the packs choice
    assert store.settings()["packs"]["disabled"] == ["django"]

    code, r = call(base, "/api/packs", "POST", {"name": "django", "enabled": True})
    assert code == 200 and store.settings()["packs"]["disabled"] == []
    code, e = call(base, "/api/packs", "POST", {"name": "nope", "enabled": False})
    assert code == 400
    code, e = call(base, "/api/packs", "POST", {"name": "django", "enabled": "no"})
    assert code == 400
    code, e = call(base, "/api/packs", "POST", {"name": "django", "enabled": False}, token=None)
    assert code == 403
