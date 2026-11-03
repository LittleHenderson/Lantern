"""Scenarios: Lantern's own story for every finding (scenarios.py), and the model's story checked like Lens 2."""

import json
import re
from pathlib import Path

import pytest

from lantern import scenarios
from lantern.engine import build_graph
from lantern.explain import SYSTEM, build_context, render_prompt, run, validate
from lantern.providers import FixtureProvider
from lantern.security import reachability, scan

FIX = Path(__file__).parent / "fixtures" / "shop"


@pytest.fixture(scope="module")
def gs():
    g = build_graph(FIX)
    return g, scan(g)["findings"]


def by_rule(findings, rule):
    return next(f for f in findings if f["rule"] == rule)


# ------------------------------------------------------------------ Lantern's own scenarios (no model)

def test_every_finding_gets_a_scenario_from_the_scan(gs):
    _, findings = gs
    assert findings
    for f in findings:
        sc = f["scenario"]
        assert sc["kind"] and sc["who"] and sc["steps"] and sc["harm"] and sc["after_fix"]
        assert "did not try any of this" in sc["basis"]          # read, don't run: said every time


def test_shell_injection_story_walks_the_real_page_click_and_input(gs):
    _, findings = gs
    sc = by_rule(findings, "B602")["scenario"]
    text = " ".join(sc["steps"])
    assert sc["kind"] == "shell"
    assert "opens the /admin page" in text                        # the page from ui_path
    assert "click the backup button" in text                      # the onClick hop the map recorded
    assert "`name`" in text and "report; whoami" in text          # the input check's parameter, then the example
    assert "page and clicks come from the map" in sc["basis"]
    assert "input check (parameter `name`)" in sc["basis"]


def test_same_finding_always_gets_the_same_person(gs):
    g, findings = gs
    f = by_rule(findings, "B608")
    assert scenarios.for_finding(f, g) == scenarios.for_finding(f, g)
    assert scenarios.for_finding(f, g)["who"].split(",")[0] in scenarios.NAMES


def test_unreached_code_says_nobody_can_do_this_yet(gs):
    g, _ = gs
    f = {"id": "abc", "rule": "B608", "tool": "bandit", "title": "sql", "file": "x.py", "line": 3, "category": "code",
         "reachable": None, "ui_path": None, "input": None, "in_tests": False}
    sc = scenarios.for_finding(f, g)
    assert "nobody can do this yet" in sc["steps"][0]
    assert "nothing in the map reaches this code" in sc["basis"]


def test_input_false_says_typing_does_not_reach_the_line(gs):
    g, findings = gs
    f = dict(by_rule(findings, "B608"), input=False)
    text = " ".join(scenarios.for_finding(f, g)["steps"])
    assert "nothing from the request reaches this line today" in text


def test_heuristic_findings_say_so(gs):
    _, findings = gs
    sc = by_rule(findings, "LW-AUTH-MISSING")["scenario"]
    assert sc["kind"] == "auth"
    assert "heuristic" in sc["harm"]
    assert "POST /backup" in " ".join(sc["steps"])                # the route from the map


def test_test_code_and_public_secret_stories(gs):
    _, findings = gs
    assert "test code" in by_rule(findings, "B101")["scenario"]["steps"][0]
    sec = by_rule(findings, "LW-PUBLIC-SECRET")["scenario"]
    assert sec["kind"] == "secret" and "developer tools" in sec["steps"][0]
    assert "rotate" in sec["after_fix"]


@pytest.mark.parametrize("f,kind", [
    ({"rule": "LJ-XSS-HTML"}, "xss"), ({"rule": "LA-WALLET-DRAIN"}, "wallet"), ({"rule": "X", "cwe": 89}, "sql"),
    ({"rule": "X", "cwe": "78"}, "shell"), ({"rule": "X", "category": "dependency"}, "dependency"),
    ({"rule": "X", "category": "secret"}, "secret"), ({"rule": "LP-SOMETHING-NEW", "cwe": None}, "generic"),
])
def test_kind_by_rule_then_cwe_then_category(f, kind):
    assert scenarios.kind_of(f) == kind


def test_unknown_rule_gets_a_generic_story_not_an_invented_harm():
    f = {"id": "1", "rule": "LP-NEW", "tool": "lantern-pack:x", "title": "Does a thing.", "category": "code"}
    sc = scenarios.for_finding(f, None)
    assert sc["kind"] == "generic"
    assert "Does a thing" in sc["harm"] and "no ready-made story" in sc["harm"]


def test_every_story_kind_is_complete_and_uses_they():
    for kind, (_typed, harm, after) in scenarios.STORIES.items():
        assert harm and after, kind
        assert not re.search(r"\b(she|her|he|his|him)\b", harm + " " + after, re.I), kind


# ------------------------------------------------------------------ the model's scenarios

def _record(user: str, scenario: str, finding_scenario: str) -> dict:
    unit = re.search(r"^UNIT: (\S+)", user, re.M).group(1)
    lo, hi = map(int, re.search(r"lines (\d+)-(\d+)", user).groups())
    sym = re.search(r"ALLOWED SYMBOLS.*?\n\s+((?:py|js):\S+)", user, re.S).group(1)
    fids = re.findall(r"id=([0-9a-f]{12})", user)
    text = "The helper at the counter takes a request, checks it, and hands back an answer."
    return {
        "lens1": {"summary": f"{unit} does its job.", "inputs": [], "outputs": "a value", "side_effects": [],
                  "errors": [], "role": "step"},
        "lens2": {"text": text, "example": "If you ask for soup, you get soup.", "analogy": "Like a waiter."},
        "lens3": {"text": text, "pairs": [
            {"plain": "the helper", "technical": unit, "anchor": {"type": "symbol", "id": sym}},
            {"plain": "takes a request", "technical": "parameters", "anchor": {"type": "term", "term": "argument"}},
            {"plain": "hands back an answer", "technical": "return", "anchor": {"type": "lines", "start": lo, "end": hi}},
        ]},
        "scenario": {"who": "Maria, a tester", "story": scenario},
        "findings": [{"id": f, "lens1": "x", "lens2": "y", "fix": "z", "scenario": finding_scenario} for f in fids],
    }


def test_prompt_asks_for_scenarios_and_shows_the_path(gs):
    g, findings = gs
    assert "SCENARIO:" in SYSTEM and '"scenario":{"who":str,"story":str}' in SYSTEM
    reach = reachability(g, kinds={"page", "main"})
    ctx = build_context(g, "py:shop.app.backup", findings, {}, "a hotel", reach)
    prompt = render_prompt(ctx, g)
    assert "REACHED FROM (from the map, for the scenario): page /admin" in prompt
    assert "(onClick)" in prompt and "POST /backup" in prompt


def test_good_scenarios_are_kept(gs):
    g, findings = gs
    ctx = build_context(g, "py:shop.app.backup", findings, {}, "a hotel")
    story = "Maria opens the /admin page, types a name and presses the button. The server starts a backup."
    rec = _record(render_prompt(ctx, g), story, "Maria types report; whoami as the name and a second command runs.")
    assert validate(rec, ctx) == []
    assert rec["scenario"]["story"] == story and all(f.get("scenario") for f in rec["findings"])
    assert "dropped_scenarios" not in rec


@pytest.mark.parametrize("story,why", [
    ("Maria calls make_repo and it opens the database file for her.", "code identifiers"),
    ("Maria opens the /billing page and presses Pay, and the server runs this code.", "map does not show"),
    ("Short.", "too short"),
])
def test_bad_scenarios_are_removed_not_shown_and_never_fail_the_lenses(gs, story, why):
    g, findings = gs
    ctx = build_context(g, "py:shop.app.backup", findings, {}, "a hotel")
    rec = _record(render_prompt(ctx, g), story, story)
    assert validate(rec, ctx) == []                                # the three lenses still pass
    assert "scenario" not in rec
    assert all("scenario" not in f for f in rec["findings"])
    assert rec["dropped_scenarios"] and all(why in d["reason"] for d in rec["dropped_scenarios"])


def test_run_counts_dropped_scenarios(gs, tmp_path):
    g, findings = gs

    def respond(system, user):
        if system.startswith("Pick ONE everyday setting"):
            return json.dumps({"world": "a hotel", "why": "-", "roles": {}})
        return json.dumps(_record(user, "Sam opens the /nowhere page and the server answers.", "x"))

    res = run(g, FixtureProvider(respond), findings, tmp_path / "c", ["py:shop.app.backup"])
    rec = res["explanations"]["py:shop.app.backup"]
    assert rec["validated"] and "scenario" not in rec
    assert res["stats"]["scenarios_dropped"] >= 1


def test_connector_finding_view_carries_the_scenario(gs):
    from lantern.mcp_server import _finding_view
    g, findings = gs
    f = by_rule(findings, "B602")
    view = _finding_view(f, g, None)
    assert view["scenario"]["steps"] == f["scenario"]["steps"] and view["scenario"]["what_goes_wrong"]
    exp = {"explanations": {f["node"]: {"model": "m", "findings": [{"id": f["id"], "lens2": "y", "fix": "z",
                                                                  "scenario": "Priya types a name and it runs."}]}}}
    assert _finding_view(f, g, exp)["scenario"] == {"story": "Priya types a name and it runs.", "written_by": "m"}


# ------------------------------------------------------------------ plain headings (Simple view)

def test_headline_names_the_clicked_thing_only_when_input_reaches_the_line(gs):
    g, fs = gs
    shell = by_rule(fs, "B602")
    assert shell["input"] and shell["headline"] == "The backup button can run shell commands on your server"
    # the same rule with no input reaching the line keeps a neutral sentence and names nothing
    f = dict(shell, input=False)
    assert scenarios.headline(f, g) == "A shell command is put together from text"


def test_headline_uses_only_fixed_words_and_map_names(gs):
    g, fs = gs
    for f in fs:
        h = f.get("headline")
        if not h:
            continue
        left = h
        for name in ("The backup button", "The /users/:id page", "POST /backup"):
            left = left.replace(name, "")
        templates = [t for pair in scenarios.HEADLINES.values() for t in pair] + list(scenarios.FIXED_HEADLINES.values())
        assert any(left == t.replace("{who}", "") or h == t for t in templates) or "works without checking" in h \
            or "sent to every visitor" in h, h


def test_headline_for_a_route_without_login_and_a_public_secret(gs):
    g, fs = gs
    assert by_rule(fs, "LW-AUTH-MISSING")["headline"] == "POST /backup works without checking who is signed in"
    assert by_rule(fs, "LW-PUBLIC-SECRET")["headline"] == "A secret setting is sent to every visitor's browser"


def test_unknown_rule_keeps_the_scanners_title(gs):
    g, _ = gs
    assert scenarios.headline({"rule": "X-NEW", "tool": "x", "title": "Something"}, g) is None
