from pathlib import Path

import pytest

from lantern.bridge import match
from lantern.engine import build_graph
from lantern.security import reachability, run_public_env, run_secrets
from lantern.ts_frontend import normalize_url

FIX = Path(__file__).parent / "fixtures" / "fullstack"


@pytest.fixture(scope="module")
def g():
    return build_graph(FIX)


def edge(g, src, dst):
    for e in g.call_edges():
        if e.src == src and e.dst == dst:
            return e
    return None


@pytest.mark.parametrize("src,dst,conf,via", [
    # TS resolution
    ("ts:web.src.pages.items.ItemsPage", "ts:web.src.components.SaveButton.SaveButton", "resolved", "jsx-render"),
    ("ts:web.src.pages.items.ItemsPage", "ts:web.src.lib.api.listItems", "resolved", "ts-import"),     # tsconfig @/
    ("ts:web.src.components.SaveButton.SaveButton.onSave", "ts:web.src.lib.api.updateItem", "resolved", "ts-import"),  # export *
    ("ts:web.src.components.SaveButton.SaveButton.onSave", "ts:web.src.lib.format.format", "resolved", "ts-import"),  # re-exported default
    ("ts:web.src.components.SaveButton.SaveButton", "ts:web.src.components.SaveButton.SaveButton.onSave", "possible", "jsx-event onClick"),
    ("ts:web.src.components.SaveButton.SaveButton.refresh", "ts:web.src.lib.api.ItemsClient.refresh", "resolved", "ts-new-method"),
    ("ts:web.src.lib.api.ItemsClient.refresh", "ts:web.src.lib.api.ItemsClient.load", "resolved", "ts-this"),
    ("ts:web.src.lib.api.ItemsClient.load", "ts:web.src.lib.api.ItemsClient.read", "resolved", "ts-static"),
    ("ts:web.server.index.login", "ts:web.server.index.check", "resolved", "ts-local"),
    # bridge: frontend -> backend
    ("ts:web.src.lib.api.updateItem", "py:backend.main.update_item", "inferred", "http PUT /api/items/{}"),
    ("ts:web.src.lib.api.listItems", "py:backend.main.list_items", "inferred", "http GET /api/items"),
    ("ts:web.src.lib.api.myItems", "py:backend.main.my_items", "inferred", "http GET /api/items/mine"),  # literal beats {}
    ("ts:web.src.lib.api.ItemsClient.read", "py:backend.main.read_item", "inferred", "http GET /api/items/{}"),
])
def test_edges(g, src, dst, conf, via):
    e = edge(g, src, dst)
    assert e is not None, f"missing {src} -> {dst}"
    assert e.confidence == conf
    assert (e.via or "").startswith(via)


def test_entry_points(g):
    entries = {n.id: n.entry for n in g.entry_points()}
    assert entries["ts:web.src.pages.items.ItemsPage"] == {"kind": "page", "detail": "/items"}
    assert entries["ts:web.server.index.GET /health"] == {"kind": "route", "detail": "GET /health"}
    assert entries["ts:web.server.index.login"] == {"kind": "route", "detail": "POST /login"}
    assert entries["ts:web.server.index"]["kind"] == "main"


def test_third_party_call_keeps_host(g):
    assert edge(g, "ts:web.src.lib.api.chargeCard", "ext:http POST api.payments.example/v1/charges")


def test_bridge_stats(g):
    b = g.meta["bridge"]
    assert (b["http_calls"], b["linked"], b["unmatched"], b["ambiguous"]) == (5, 4, 1, 0)
    assert set(g.meta["languages"]) == {"python", "typescript"}


def test_button_to_backend_path(g):
    """The signature feature: one path from a page through a click handler to the backend."""
    adj = {}
    for e in g.call_edges():
        adj.setdefault(e.src, []).append(e.dst)
    seen, stack = set(), ["ts:web.src.pages.items.ItemsPage"]
    while stack:
        cur = stack.pop()
        if cur not in seen:
            seen.add(cur)
            stack += adj.get(cur, [])
    assert "py:backend.main.save_item" in seen
    assert "py:backend.main.get_current_user" in seen


def test_routes_stay_their_own_entries(g):
    # a backend route is still reached from itself (untrusted input) in security reachability
    r = reachability(g)
    assert r["py:backend.main.update_item"]["entry"] == "py:backend.main.update_item"


def test_ambiguous_match_is_not_guessed():
    routes = [("a", {"GET"}, ["users", "{}"]), ("b", {"GET"}, ["teams", "{}"])]
    assert match("GET", "/api/users/{}", routes)[0][0] == "a"
    # equal scores on two routes: both come back tied, and link() makes them "possible" edges
    tied = match("GET", "/api/{}/stats", [("a", {"GET"}, ["teams", "stats"]), ("b", {"GET"}, ["{}", "stats"]),
                                          ("c", {"GET"}, ["users", "stats"])])
    assert tied[0][0] == "b" and tied[0][2] > tied[1][2]   # {} in both lines up best
    tied = match("GET", "/teams/stats", [("a", {"GET"}, ["{}", "stats"]), ("b", {"GET"}, ["teams", "{}"])])
    assert len(tied) == 2 and tied[0][2] == tied[1][2]
    assert match("POST", "/api/users/1", routes) == []


@pytest.mark.parametrize("raw,norm", [
    ("/api/items/{}", "/api/items/{}"),
    ("https://example.com/api/items/?q=1", "/api/items"),
    ("/users/:id/posts", "/users/{}/posts"),
    ("/blog/[slug]", "/blog/{}"),
    ("/x/<int:id>", "/x/{}"),
    ("{}/items", "/items"),
])
def test_normalize_url(raw, norm):
    assert normalize_url(raw) == norm


def test_secret_scan_reads_frontend_files(tmp_path):
    (tmp_path / "src").mkdir()
    key = "sk-ant-" + "a" * 30
    (tmp_path / "src" / "client.tsx").write_text(f'const k = "{key}"\n')
    (tmp_path / ".env").write_text(f"KEY={key}\n")
    found, _ = run_secrets(tmp_path)
    assert {f["file"] for f in found} == {"src/client.tsx", ".env"}


def test_public_env_secret():
    found, _ = run_public_env(FIX)
    names = {f["snippet"] for f in found}
    assert "VITE_OPENAI_API_KEY" in names
    assert not any("ANON" in n for n in names)
