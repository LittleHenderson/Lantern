import json
import re
from pathlib import Path

import pytest

from lantern.explain import (build_context, parse_json, render_prompt, run, select_nodes,
                             validate)
from lantern.providers import FixtureProvider
from lantern.engine import build_graph
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
    sym = re.search(r"ALLOWED SYMBOLS.*?\n\s+((?:py|js):\S+)", user, re.S).group(1)
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
    assert any("neither a word" in e for e in validate(rec, ctx))


@pytest.mark.parametrize("term", ["1", "|", "a", "   ", "ge", "12345"])
def test_rejects_meaningless_terms(gs, term):
    g, ctx = ctx_for(gs, "py:shop.repo.UserRepo.get")
    rec = good_record(render_prompt(ctx, g))
    rec["lens3"]["pairs"][1]["anchor"] = {"type": "term", "term": term}
    assert any("neither a word" in e for e in validate(rec, ctx)), term


def test_accepts_a_real_name_from_the_code(gs):
    g, ctx = ctx_for(gs, "py:shop.repo.UserRepo.get")
    rec = good_record(render_prompt(ctx, g))
    rec["lens3"]["pairs"][1]["anchor"] = {"type": "term", "term": "execute"}
    assert validate(rec, ctx) == []


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


@pytest.mark.parametrize("left", ["", '{"lens1": {"summary": "half a rec', "[1, 2]"],
                         ids=["empty", "cut short", "not a record"])
def test_a_damaged_cache_entry_is_asked_for_again(gs, tmp_path, left):
    """A cache file that was cut short while it was written (the program was stopped, the disk was full), or that is
    not a record at all, is not an explanation. Until 2026-11-10 it stopped every later `explain` of the project with
    an error, until somebody deleted the cache folder by hand. Now that one function is asked for again and its file
    written anew. The safe twin is in the same run: the entry that is whole is used, with no second request."""
    g, findings = gs
    nids = ["py:shop.repo.UserRepo.get", "py:shop.auth.Session.login"]
    assert run(g, FixtureProvider(responder), findings, tmp_path, nids)["stats"]["generated"] == 2
    files = sorted(tmp_path.glob("*.json"))
    assert len(files) == 2
    whole = files[1].read_bytes()
    files[0].write_text(left, encoding="utf-8")
    p = FixtureProvider(responder)
    out = run(g, p, findings, tmp_path, nids)
    assert (out["stats"]["validated"], out["stats"]["cached"], out["stats"]["generated"]) == (2, 1, 1)
    assert len(p.calls) == 2                       # the setting, and the one function whose entry was damaged
    assert isinstance(json.loads(files[0].read_text(encoding="utf-8")), dict) and files[1].read_bytes() == whole


def test_retry_fixes_invalid_answer(gs, tmp_path):
    g, findings = gs
    state = {"n": 0}

    def flaky(system, user):
        if system.startswith("Pick ONE everyday setting"):
            return '{"world": "a hotel"}'
        state["n"] += 1
        if system.startswith("You fix one part"):          # the REPAIR request: only the failing pair comes back fixed
            pairs = json.loads(re.search(r"PAIRS:\n(.*?)\n\nPROBLEMS", user, re.S).group(1))
            sym = re.search(r"ALLOWED SYMBOLS:\n(\S+)", user).group(1)
            pairs[0]["anchor"] = {"type": "symbol", "id": sym}
            state["repair_prompt"] = user
            return json.dumps({"pairs": pairs})
        rec = good_record(user)
        if state["n"] == 1:
            rec["lens3"]["pairs"][0]["anchor"]["id"] = "py:made.up"
        return json.dumps(rec)

    out = run(g, FixtureProvider(flaky), findings, tmp_path, ["py:shop.repo.UserRepo.get"])
    rec = out["explanations"]["py:shop.repo.UserRepo.get"]
    assert rec["validated"] and rec["attempts"] == 2 and rec["repaired"] is True
    assert out["stats"]["repaired"] == 1 and "py:made.up" in state["repair_prompt"]
    assert "Fix only pairs [0]" in state["repair_prompt"]


def test_structural_failure_gets_a_full_retry_not_a_repair(gs, tmp_path):
    g, findings = gs
    systems = []

    def flaky(system, user):
        if system.startswith("Pick ONE everyday setting"):
            return '{"world": "a hotel"}'
        systems.append(system[:12])
        rec = good_record(user)
        if len(systems) == 1:
            del rec["lens2"]                                    # not a pair problem: the whole answer is re-asked
        return json.dumps(rec)

    out = run(g, FixtureProvider(flaky), findings, tmp_path, ["py:shop.repo.UserRepo.get"])
    rec = out["explanations"]["py:shop.repo.UserRepo.get"]
    assert rec["validated"] and rec["attempts"] == 2 and rec["repaired"] is False
    assert systems == ["You explain ", "You explain "]


def test_lens1_read_back_rejects_names_not_in_the_map(gs):
    """HELM's round trip, light form: Lens 1 may only name code the context shows."""
    from lantern.explain import build_context, validate
    g, findings = gs
    ctx = build_context(g, "py:shop.repo.UserRepo.get", [], {}, "a hotel")
    lo, hi = ctx.line_range
    sym = next(iter(ctx.allowed_symbols))
    text = "The helper takes a request and hands back an answer."
    base = {"lens2": {"text": text, "example": "e", "analogy": "a"},
            "lens3": {"text": text, "pairs": [
                {"plain": "The helper", "technical": "t", "anchor": {"type": "symbol", "id": sym}},
                {"plain": "takes a request", "technical": "t", "anchor": {"type": "term", "term": "argument"}},
                {"plain": "hands back an answer", "technical": "t", "anchor": {"type": "lines", "start": lo, "end": hi}}]}}
    ok = {**base, "lens1": {"summary": "Runs a SELECT through self.execute() and returns one row.", "role": "r"}}
    assert validate(ok, ctx) == []
    bad = {**base, "lens1": {"summary": "Calls fetch_profile_cache() and then self.execute().", "role": "r"}}
    errs = validate(bad, ctx)
    assert errs and "fetch_profile_cache" in errs[0] and "not in this function" in errs[0]


def test_undetermined_is_an_honest_answer(gs, tmp_path):
    g, findings = gs

    def model(system, user):
        if system.startswith("Pick ONE everyday setting"):
            return '{"world": "a hotel"}'
        return json.dumps({"lens1": {"summary": "Executes a query via self.execute().", "inputs": [], "outputs": "a row",
                                     "side_effects": [], "errors": [], "role": "data access"},
                           "undetermined": "The body only forwards to execute(), whose behavior is not shown."})

    out = run(g, FixtureProvider(model), [], tmp_path, ["py:shop.repo.UserRepo.get"])
    rec = out["explanations"]["py:shop.repo.UserRepo.get"]
    assert rec["validated"], rec["validation_errors"]
    assert rec["attempts"] == 1 and rec["undetermined"].startswith("The body only")
    assert "lens2" not in rec and out["stats"]["undetermined"] == 1


def test_model_invented_findings_are_dropped_not_shown(tmp_path):
    """A findings entry with an id the scanners never reported is a finding the model made up: removed, counted."""
    from lantern.explain import build_context, validate
    from lantern.engine import build_graph
    g = build_graph(FIX)
    ctx = build_context(g, "py:shop.auth.make_repo", [], {}, "a hotel")   # no scanner findings here
    lo, hi = ctx.line_range
    sym = next(iter(ctx.allowed_symbols))
    text = "The helper takes a request and hands back an answer."
    rec = {"lens1": {"summary": "s"}, "lens2": {"text": text, "example": "e", "analogy": "a"},
           "lens3": {"text": text, "pairs": [
               {"plain": "The helper", "technical": "t", "anchor": {"type": "symbol", "id": sym}},
               {"plain": "takes a request", "technical": "t", "anchor": {"type": "term", "term": "argument"}},
               {"plain": "hands back an answer", "technical": "t", "anchor": {"type": "lines", "start": lo, "end": hi}}]},
           "findings": [{"id": "hardcoded-password", "lens1": "x", "lens2": "y", "fix": "z"}]}
    assert validate(rec, ctx) == []
    assert rec["findings"] == [] and rec["dropped_findings"][0]["id"] == "hardcoded-password"


def test_unfixable_pair_is_dropped_after_repair_not_the_whole_answer(gs, tmp_path):
    """REPAIR gets one chance; if a pair still cannot be highlighted it is removed and recorded, the rest stands."""
    g, findings = gs

    def model(system, user):
        if system.startswith("Pick ONE everyday setting"):
            return '{"world": "a hotel"}'
        if system.startswith("You fix one part"):
            pairs = json.loads(re.search(r"PAIRS:\n(.*?)\n\nPROBLEMS", user, re.S).group(1))
            return json.dumps({"pairs": pairs})                 # the model "fixes" nothing
        rec = good_record(user)
        rec["lens3"]["pairs"].append({"plain": "the chef", "technical": "t",
                                      "anchor": {"type": "term", "term": "argument"}})   # not in the text
        return json.dumps(rec)

    out = run(g, FixtureProvider(model), findings, tmp_path, ["py:shop.repo.UserRepo.get"])
    rec = out["explanations"]["py:shop.repo.UserRepo.get"]
    assert rec["validated"] and rec["attempts"] == 2 and len(rec["lens3"]["pairs"]) == 3
    assert rec["dropped_pairs"][0]["pair"]["plain"] == "the chef" and "verbatim" in rec["dropped_pairs"][0]["reason"]
    assert out["stats"]["pairs_dropped"] == 1 and out["stats"]["validated"] == 1


def test_pair_drop_also_applies_when_the_full_retry_ends_on_a_pair_error(gs, tmp_path):
    """First answer fails structurally (full retry, no REPAIR); the retry fails on one pair: drop it, keep the rest."""
    g, findings = gs
    n = {"i": 0}

    def model(system, user):
        if system.startswith("Pick ONE everyday setting"):
            return '{"world": "a hotel"}'
        n["i"] += 1
        rec = good_record(user)
        if n["i"] == 1:
            del rec["lens2"]
        else:
            rec["lens3"]["pairs"].append({"plain": "the chef", "technical": "t", "anchor": {"type": "term", "term": "argument"}})
        return json.dumps(rec)

    out = run(g, FixtureProvider(model), findings, tmp_path, ["py:shop.repo.UserRepo.get"])
    rec = out["explanations"]["py:shop.repo.UserRepo.get"]
    assert rec["validated"] and rec["attempts"] == 2 and len(rec["lens3"]["pairs"]) == 3 and len(rec["dropped_pairs"]) == 1
