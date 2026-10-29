import json
import re
from pathlib import Path

import pytest

from lantern.explain import (Context, build_context, parse_json, render_prompt, run, select_nodes,
                             validate)
from lantern.providers import FixtureProvider
from lantern.python_frontend import build_graph
from lantern.security import scan

FIX = Path(__file__).parent / "fixtures" / "shop"


@pytest.fixture(scope="module")
def gs():
    g = build_graph(FIX)
    return g, scan(g)["findings"]


def good_record(user: str) -> dict:
    """A stub 'model' that answers correctly using only what the prompt gives it."""
    unit = re.search(r"^UNIT: (\S+)", user, re.M).group(1)
    lo, hi = map(int, re.search(r"lines (\d+)-(\d+)", user).groups())
    sym = re.search(r"ALLOWED SYMBOLS.*?\n\s+(py:\S+)", user, re.S).group(1)
    fids = re.findall(r"id=([0-9a-f]{12})", user)
    text = "The helper at the counter takes a request, checks it, and hands back an answer."
    return {
        "lens1": {"summary": f"{unit} does its job.", "inputs": [], "outputs": "a value",
                  "side_effects": [], "errors": [], "role": "step"},
        "lens2": {"text": text, "example": "If you ask for soup, you get soup.",
                  "analogy": "Like a waiter taking an order."},
        "lens3": {"text": text, "pairs": [
            {"plain": "the helper", "technical": unit, "anchor": {"type": "symbol", "id": sym}},
            {"plain": "takes a request", "technical": "parameters", "anchor": {"type": "term", "term": "argument"}},
            {"plain": "hands back an answer", "technical": "return", "anchor": {"type": "lines", "start": lo, "end": hi}},
        ]},
        "findings": [{"id": f, "lens1": "x", "lens2": "y", "fix": "z"} for f in fids],
    }


def responder(system, user):
    if system.startswith("Pick ONE everyday setting"):
        return json.dumps({"world": "a restaurant", "why": "orders flow", "roles": {}})
    return json.dumps(good_record(user))


def ctx_for(gs, nid):
    g, findings = gs
    return g, build_context(g, nid, findings, {}, "a restaurant")


def test_good_record_validates(gs):
    g, ctx = ctx_for(gs, "py:shop.repo.UserRepo.get")
    rec = good_record(render_prompt(ctx, g))
    assert validate(rec, ctx) == []


def test_rejects_invented_symbol(gs):
    g, ctx = ctx_for(gs, "py:shop.repo.UserRepo.get")
    rec = good_record(render_prompt(ctx, g))
    rec["lens3"]["pairs"][0]["anchor"]["id"] = "py:shop.payments.charge_card"
    assert any("unknown symbol" in e for e in validate(rec, ctx))


def test_rejects_line_outside_unit(gs):
    g, ctx = ctx_for(gs, "py:shop.repo.UserRepo.get")
    rec = good_record(render_prompt(ctx, g))
    rec["lens3"]["pairs"][2]["anchor"] = {"type": "lines", "start": 1, "end": 2}
    assert any("outside" in e for e in validate(rec, ctx))


def test_rejects_plain_phrase_not_in_text(gs):
    g, ctx = ctx_for(gs, "py:shop.repo.UserRepo.get")
    rec = good_record(render_prompt(ctx, g))
    rec["lens3"]["pairs"][0]["plain"] = "the chef"
    assert any("verbatim" in e for e in validate(rec, ctx))


def test_rejects_code_identifiers_in_lens2(gs):
    g, ctx = ctx_for(gs, "py:shop.repo.UserRepo.get")
    rec = good_record(render_prompt(ctx, g))
    rec["lens2"]["text"] = "UserRepo looks up a guest."
    assert any("code identifiers" in e for e in validate(rec, ctx))


def test_rejects_unknown_term(gs):
    g, ctx = ctx_for(gs, "py:shop.repo.UserRepo.get")
    rec = good_record(render_prompt(ctx, g))
    rec["lens3"]["pairs"][1]["anchor"] = {"type": "term", "term": "quantum flux capacitor"}
    assert any("neither in the source" in e for e in validate(rec, ctx))


def test_requires_every_finding_explained(gs):
    g, ctx = ctx_for(gs, "py:shop.repo.UserRepo.get")
    assert ctx.findings, "fixture should have a SQL injection finding on UserRepo.get"
    rec = good_record(render_prompt(ctx, g))
    rec["findings"] = []
    assert any("findings not explained" in e for e in validate(rec, ctx))


def test_parse_json_strips_fences():
    assert parse_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json('Sure! {"a": 2} hope that helps') == {"a": 2}
    assert parse_json("nope") is None


def test_select_is_bottom_up(gs):
    g, _ = gs
    order = select_nodes(g)
    assert order.index("py:shop.repo.UserRepo.get") < order.index("py:shop.auth.Session.login")
    assert order.index("py:shop.auth.Session.login") < order.index("py:shop.app.read_user")
    assert "py:tests.test_auth.test_check_password" not in order


def test_run_end_to_end_with_cache(gs, tmp_path):
    g, findings = gs
    nids = select_nodes(g)
    p1 = FixtureProvider(responder)
    out = run(g, p1, findings, tmp_path, nids)
    assert out["stats"]["validated"] == len(nids)
    assert out["metaphor"]["world"] == "a restaurant"
    # callee summaries flow into caller prompts (bottom-up ordering)
    login_prompt = next(u for s, u in p1.calls if "UNIT: shop.auth.Session.login" in u)
    assert "shop.repo.UserRepo.get: shop.repo.UserRepo.get does its job." in login_prompt
    p2 = FixtureProvider(responder)
    out2 = run(g, p2, findings, tmp_path, nids)
    assert out2["stats"]["cached"] == len(nids)
    assert len(p2.calls) == 1  # only the metaphor call


def test_retry_fixes_invalid_answer(gs, tmp_path):
    g, findings = gs
    state = {"n": 0}

    def flaky(system, user):
        if system.startswith("Pick ONE everyday setting"):
            return '{"world": "a hotel"}'
        state["n"] += 1
        rec = good_record(user)
        if state["n"] == 1:
            rec["lens3"]["pairs"][0]["anchor"]["id"] = "py:made.up"
        return json.dumps(rec)

    out = run(g, FixtureProvider(flaky), findings, tmp_path, ["py:shop.repo.UserRepo.get"])
    rec = out["explanations"]["py:shop.repo.UserRepo.get"]
    assert rec["validated"] and rec["attempts"] == 2
