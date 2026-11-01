"""Analysis packs: pattern files that add rules and framework entry points without running code."""

import json
from pathlib import Path

from lantern import packs
from lantern.engine import build_graph
from lantern.security import scan


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


DJANGO_APP = {
    "requirements.txt": "django==5.1\n",
    "manage.py": "import sys\nfrom django.core.management import execute_from_command_line\n"
                 "execute_from_command_line(sys.argv)\n",
    "site/__init__.py": "",
    "site/settings.py": "import os\nDEBUG = True\nALLOWED_HOSTS = ['*']\n"
                        "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']\n",
    "site/urls.py": "from django.urls import path\nfrom shop import views\nfrom shop.views import ItemView\n\n"
                    "urlpatterns = [\n    path('items/', views.list_items),\n"
                    "    path('items/<int:pk>/', ItemView.as_view()),\n    path('ping/', views.ping),\n]\n",
    "shop/__init__.py": "",
    "shop/views.py": "from django.http import JsonResponse\nfrom django.views import View\nfrom . import store\n\n"
                     "def list_items(request):\n    return JsonResponse(store.all_items())\n\n"
                     "def ping(request):\n    return JsonResponse({'ok': True})\n\n"
                     "class ItemView(View):\n    def delete(self, request, pk):\n        store.remove(pk)\n"
                     "        return JsonResponse({})\n",
    "shop/store.py": "def all_items():\n    return []\n\ndef remove(pk):\n    pass\n",
}


def test_django_pack_entries_and_rules(tmp_path):
    _write(tmp_path, DJANGO_APP)
    g = build_graph(tmp_path)
    entries = {n.qualname: n.entry for n in g.entry_points()}
    assert entries["shop.views.list_items"]["detail"] == "ANY /items/"
    assert entries["shop.views.list_items"]["via"] == "pack:django"
    assert entries["shop.views.list_items"]["registered_at"] == "site/urls.py:6"
    # a class-based view: the methods that answer requests become the entry points
    assert entries["shop.views.ItemView.delete"]["detail"] == "ANY /items/<int:pk>/"
    assert g.meta["packs"] == {"added": 3, "ambiguous": 0, "unresolved": 0, "packs": ["django"]}
    sec = scan(g, offline=True)
    rules = {f["rule"]: f for f in sec["findings"]}
    assert rules["LP-DJANGO-DEBUG"]["file"] == "site/settings.py" and rules["LP-DJANGO-DEBUG"]["line"] == 2
    assert rules["LP-DJANGO-DEBUG"]["tool_confidence"] == "HIGH"       # built-in pack, declared HIGH
    assert "LP-DJANGO-HOSTS-ANY" in rules
    assert "LP-DJANGO-SECRET-INLINE" not in rules                       # read from the environment: `unless` matched
    assert rules["LP-DJANGO-DEBUG"]["tool"] == "lantern-pack:django"
    # pack entries feed the rest of the pipeline: the view is reachable from a route, so findings in it rank by it
    assert any(t["tool"] == "lantern-pack:django" and t["status"].startswith("ok") for t in sec["tools"])
    assert sec["reachable_nodes"] >= 3


def test_pack_not_applied_without_django(tmp_path):
    _write(tmp_path, {"app.py": "DEBUG = True\n", "site/urls.py": "path('x/', f)\n", "requirements.txt": "flask\n"})
    g = build_graph(tmp_path)
    assert "packs" not in g.meta
    assert not [f for f in scan(g, offline=True)["findings"] if f["rule"].startswith("LP-")]


def test_project_pack_is_heuristic_and_validated(tmp_path, monkeypatch):
    monkeypatch.setenv("LANTERN_HOME", str(tmp_path / "home"))
    _write(tmp_path, {
        "app.py": "def send(to):\n    mail(to, html=True)\n",
        "lantern-packs/mail.json": json.dumps({"pack": "mail", "version": "1", "rules": [
            {"id": "LP-MAIL-HTML", "title": "Email sent as HTML", "severity": "LOW", "files": ["*.py"],
             "pattern": "mail\\(.*html=True", "confidence": "HIGH"}]}),
        "lantern-packs/broken.json": json.dumps({"pack": "Broken Name", "rules": [{"id": "x", "pattern": "("}]}),
        "lantern-packs/notjson.json": "{",
    })
    loaded, problems = packs.load_all(tmp_path)
    assert [p["pack"] for p in loaded] == ["mail"] and loaded[0]["source"] == "project"
    assert sorted(w for w, _ in problems) == ["project pack broken.json", "project pack notjson.json"]
    assert "lowercase" in dict(problems)["project pack broken.json"]
    f = [f for f in scan(build_graph(tmp_path), offline=True)["findings"] if f["rule"] == "LP-MAIL-HTML"]
    assert len(f) == 1 and f[0]["tool_confidence"] == "LOW"      # third-party packs can't claim certainty
    assert f[0]["line"] == 2 and f[0]["rank"] == "low"


def test_validate_messages():
    errs = packs.validate({"pack": "ok", "rules": [{"id": "LP-AA", "title": "A rule here", "severity": "HIGH",
                                                   "files": ["*.py"], "pattern": "x"}],
                           "entries": [{"kind": "webhook", "files": ["*.py"], "pattern": "(a)", "handler": "1"}]})
    assert any("`kind`" in e for e in errs) and any("`handler`" in e for e in errs)
    assert packs.validate({"pack": "ok", "rules": [{"id": "LP-AA", "title": "A rule here", "severity": "HIGH",
                                                   "files": ["*.py"], "pattern": "x"}]}) == []
    assert packs.validate({"pack": "empty"}) == ["a pack needs at least one rule or entry pattern"]
    assert "LP-" in packs.validate({"pack": "p", "rules": [{"id": "B602", "title": "t t t", "severity": "LOW",
                                                            "files": ["*"], "pattern": "x"}]})[0]


def test_builtin_packs_are_valid():
    for p in packs.BUILTIN_DIR.glob("*.json"):
        assert packs.validate(json.loads(p.read_text(encoding="utf-8"))) == [], p.name
