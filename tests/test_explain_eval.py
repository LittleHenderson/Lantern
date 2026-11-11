"""The explanation eval harness (bench/explain_eval.py) counts what the validator says, on scripted models, offline."""
import json
import shutil
import sys
from pathlib import Path

import pytest

from lantern.pipeline import analyze
from lantern.providers import FixtureProvider

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bench"))
import explain_eval  # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "shop"


@pytest.fixture(scope="module")
def project(tmp_path_factory):
    repo = tmp_path_factory.mktemp("explaineval") / "shop"
    shutil.copytree(FIX, repo)
    (repo / ".lantern").mkdir()
    analyze(repo, repo / ".lantern", "full", log=lambda *a, **k: None)
    return repo


def _silent(system, user):
    """A model that answers every unit with UNDETERMINED in valid JSON: validated, never anchored, never first-try wrong."""
    if "metaphor" in user.lower() and "world" in user.lower() and "roles" in user.lower():
        return json.dumps({"world": "a library", "why": "books", "roles": {}})
    return json.dumps({"lens1": {"summary": "This part does one small step and hands its result on."},
                       "undetermined": "The function body was not shown in enough detail to describe it safely here."})


def _garbage(system, user):
    return "I am not JSON and I never will be."


def test_the_harness_counts_validated_first_try_and_the_reasons_for_failures(project):
    """UNDETERMINED with a real sentence passes on a unit with no findings; on a unit that has a finding the validator
    insists the finding is explained, so the harness must count that unit as failed and keep the reason."""
    res = explain_eval.run_eval(FixtureProvider(_silent), project, limit=6)
    failed = [r for r in res["rows"] if not r["validated"]]
    assert res["selected"] == 6 and res["validated"] + len(failed) == 6 and 0 < res["validated"] < 6
    assert res["first_try"] == res["validated"] and res["undetermined"] == res["validated"] and res["invented_dropped"] == 0
    assert all("findings not explained" in "; ".join(r["errors"]) for r in failed)
    assert res["first_try_rate"] == round(res["validated"] / 6, 3)
    line = explain_eval.row(res, "scripted")
    assert line.startswith("| ") and f"{res['validated']} / 6 (shop)" in line and line.endswith("| scripted |")


def test_a_model_that_never_answers_in_shape_scores_zero(project):
    res = explain_eval.run_eval(FixtureProvider(_garbage), project, limit=4)
    assert res["validated"] == 0 and res["first_try"] == 0 and res["first_try_rate"] == 0.0
    assert all(not r["validated"] and r["errors"] for r in res["rows"])


def test_main_fails_under_the_first_try_floor(project, monkeypatch):
    monkeypatch.setattr("lantern.providers.make_provider", lambda spec: FixtureProvider(_garbage))
    said = ["--live", "--model", "fixture/stub", "--destination", "localhost", "--max-requests", "40", "--send-this-code"]
    assert explain_eval.main([str(project), "--limit", "2", "--min-first-try", "0.9", *said]) == 1
    assert explain_eval.main([str(project), "--limit", "2", *said]) == 0
