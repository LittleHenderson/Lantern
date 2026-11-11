"""The live suite's gate (bench/live.py): a real model is used only when the person running it has named the model,
the one host the code may go to and a spending cap. Everything here runs offline, on a scripted stand-in."""
import argparse
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

from lantern import providers
from lantern.pipeline import analyze
from lantern.providers import FixtureProvider

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bench"))
import ask_eval  # noqa: E402
import explain_eval  # noqa: E402
import live  # noqa: E402

SHOP = ROOT / "tests" / "fixtures" / "shop"


def _args(*argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--model")
    live.add_arguments(ap)
    return ap.parse_args(list(argv))


def _answers(system, user):
    return json.dumps({"world": "a library", "why": "books", "roles": {}, "answer": "It is not in the results."})


@pytest.fixture
def stand_in(monkeypatch):
    """`make_provider` hands out a scripted model that answers inside this process; `made` lists what was asked for."""
    made = []

    def make(spec, *a, **k):
        made.append(spec)
        return FixtureProvider(_answers)
    monkeypatch.setattr(providers, "make_provider", make)
    return made


@pytest.fixture(scope="module")
def project(tmp_path_factory):
    repo = tmp_path_factory.mktemp("live") / "shop"
    shutil.copytree(SHOP, repo)
    (repo / ".lantern").mkdir()
    analyze(repo, repo / ".lantern", "full", log=lambda *a, **k: None)
    return repo


ALL = ["--live", "--model", "fixture/stub", "--destination", "localhost", "--max-requests", "3"]


@pytest.mark.parametrize("script", [explain_eval, ask_eval])
def test_without_live_nothing_starts(script, stand_in, capsys, network_attempts):
    assert script.main([str(SHOP)]) == 2
    assert script.main([str(SHOP), "--model", "anthropic/claude-haiku-5-5"]) == 2      # a model alone is not a yes
    said = capsys.readouterr().err
    assert "Nothing was sent" in said and "--live" in said and "--max-requests" in said
    assert stand_in == [] and network_attempts() == []           # no provider was even made


@pytest.mark.parametrize("left_out, names", [
    (("--model", "fixture/stub"), "--model"),
    (("--destination", "localhost"), "--destination"),
    (("--max-requests", "3"), "--max-requests"),
])
def test_a_live_run_needs_the_model_the_destination_and_the_cap(left_out, names, stand_in):
    argv = [x for x in ALL if x not in left_out]
    with pytest.raises(live.NotApproved, match=names):
        live.gate(_args(*argv), SHOP)
    assert stand_in == []


def test_there_is_no_default_model_and_no_falling_back_to_a_key_in_the_shell(stand_in, monkeypatch):
    """Before: `make_provider(a.model or resolve_default())` took whatever key or sign-in the shell held."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "not-a-key-" + "x" * 8)
    monkeypatch.setenv("LANTERN_MODEL", "anthropic/claude-haiku-5-5")
    monkeypatch.setattr(providers, "resolve_default", lambda *a, **k: pytest.fail("the default must not be consulted"))
    with pytest.raises(live.NotApproved, match="--model"):
        live.gate(_args("--live", "--destination", "api.anthropic.com", "--max-requests", "3"), SHOP)
    assert stand_in == []


def test_a_cap_of_zero_is_not_a_cap(stand_in):
    with pytest.raises(live.NotApproved, match="--max-requests"):
        live.gate(_args(*ALL[:-1], "0"), SHOP)


def test_the_destination_must_be_where_the_model_is_served_from(monkeypatch):
    monkeypatch.delenv(providers.NO_REAL_ENV)                     # as in a live run; nothing is sent in this test
    monkeypatch.setenv("ANTHROPIC_API_KEY", "not-a-key-" + "x" * 8)
    with pytest.raises(live.NotApproved, match="served from api.anthropic.com.*approved destination is example.org"):
        live.gate(_args("--live", "--model", "anthropic/claude-haiku-5-5", "--destination", "example.org",
                        "--max-requests", "3"), SHOP)


def test_a_real_destination_is_refused_inside_a_test_or_benchmark_run(stand_in):
    assert providers.real_providers_off()                         # every test run has the switch on
    with pytest.raises(live.NotApproved, match="switched off"):
        live.gate(_args("--live", "--model", "anthropic/claude-haiku-5-5", "--destination", "api.anthropic.com",
                        "--max-requests", "3"), SHOP)
    assert stand_in == []


def test_code_that_is_not_a_lantern_sample_needs_its_own_yes(stand_in, tmp_path):
    with pytest.raises(live.NotApproved, match="--send-this-code"):
        live.gate(_args(*ALL), tmp_path)
    assert live.gate(_args(*ALL, "--send-this-code"), tmp_path).max_requests == 3
    assert live.gate(_args(*ALL), SHOP).max_requests == 3         # tests/fixtures is Lantern's own


def test_a_missing_key_is_said_plainly(monkeypatch):
    monkeypatch.delenv(providers.NO_REAL_ENV)
    with pytest.raises(live.NotApproved, match="set ANTHROPIC_API_KEY"):
        live.gate(_args("--live", "--model", "anthropic/claude-haiku-5-5", "--destination", "api.anthropic.com",
                        "--max-requests", "3"), SHOP)


def test_the_gate_says_what_will_happen_before_it_happens(stand_in, capsys):
    live.gate(_args(*ALL), SHOP)
    said = capsys.readouterr().err
    assert "LIVE RUN" in said and "destination localhost" in said and "at most 3 requests" in said
    assert "a Lantern sample" in said


def test_the_cap_stops_the_questions():
    inner = FixtureProvider(_answers)
    capped = live.Capped(inner, 2)
    assert capped.complete("s", "u") and capped.complete("s", "u")
    with pytest.raises(live.SpendingCap, match="2 requests"):
        capped.complete("s", "u")
    assert len(inner.calls) == 2 and capped.requests == 2         # the third question never reached the model
    assert capped.label == inner.label and capped.usage is inner.usage


def test_the_explanation_eval_stops_at_the_cap_and_keeps_what_it_has(project, stand_in, capsys):
    assert explain_eval.main([str(project), "--limit", "4", "--live", "--model", "fixture/stub", "--destination",
                              "localhost", "--max-requests", "2", "--send-this-code"]) == 1
    out = capsys.readouterr().out
    assert "STOPPED EARLY" in out and "spending cap" in out and "requests to the model: 2 of at most 2" in out


def test_the_ask_eval_stops_at_the_cap(project, stand_in, capsys):
    assert ask_eval.main([str(project), "--live", "--model", "fixture/stub", "--destination", "localhost",
                          "--max-requests", "2", "--send-this-code"]) == 1
    assert "STOPPED EARLY" in capsys.readouterr().err


def test_a_full_run_on_the_stand_in_reports_its_requests(project, stand_in, capsys):
    code = ask_eval.main([str(project), "--live", "--model", "fixture/stub", "--destination", "localhost",
                          "--max-requests", "50", "--send-this-code"])
    out = capsys.readouterr().out
    assert code in (0, 1) and f"requests to the model: {len(ask_eval.CASES)} of at most 50" in out
    assert stand_in == ["fixture/stub"]


def test_the_workflow_that_runs_the_live_suite_gives_every_answer():
    """model-eval is started by hand; its inputs are the approval, and each script gets all of it."""
    text = (ROOT / ".github" / "workflows" / "model-eval.yml").read_text(encoding="utf-8")
    triggers = re.search(r"^on:\n((?:  .*\n|\n)+)", text, re.M).group(1)
    assert re.findall(r"^  (\w+):", triggers, re.M) == ["workflow_dispatch"]      # started by hand, never by itself
    runs = [line for line in text.splitlines() if "python bench/" in line and "_eval.py" in line]
    assert len(runs) == 3
    for line in runs:
        for flag in ("--live", "--model", "--destination", "--max-requests"):
            assert flag in line, line
    for name in ("model", "destination", "max_requests"):
        assert f"      {name}:" in text
