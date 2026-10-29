from pathlib import Path

import pytest

from lantern.python_frontend import build_graph
from lantern.security import rank, reachability, scan

FIX = Path(__file__).parent / "fixtures" / "shop"


@pytest.fixture(scope="module")
def result():
    g = build_graph(FIX)
    return g, scan(g)


def by_rule(findings, rule):
    return [f for f in findings if f["rule"] == rule]


def test_sql_injection_reachable_from_route(result):
    g, s = result
    (f,) = by_rule(s["findings"], "B608")
    assert f["node"] == "py:shop.repo.UserRepo.get"
    assert f["reachable"]["path"] == [
        "py:shop.app.read_user", "py:shop.auth.Session.login", "py:shop.repo.UserRepo.get"]
    assert f["rank"] == "high"


def test_shell_injection_is_critical(result):
    _, s = result
    (f,) = by_rule(s["findings"], "B602")
    assert f["rank"] == "critical"


def test_test_only_code_is_not_reachable(result):
    g, _ = result
    r = reachability(g)
    assert "py:tests.test_auth.test_check_password" not in r
    assert "py:tests.test_auth.test_check_password" in reachability(g, include_tests=True)


def test_rank_rules():
    base = {"category": "code", "reachable": None}
    assert rank({**base, "tool_severity": "HIGH"}) == "medium"
    assert rank({**base, "tool_severity": "LOW"}) == "low"
    assert rank({**base, "tool_severity": "HIGH", "reachable": {"kind": "route"}}) == "critical"
    assert rank({**base, "tool_severity": "HIGH", "reachable": {"kind": "test"}}) == "high"
    assert rank({"category": "secret", "tool_severity": "HIGH", "reachable": None}) == "critical"


def test_builtin_secret_scan(tmp_path):
    (tmp_path / "config.py").write_text('KEY = "AKIA' + "ABCDEFGHIJKLMNOP" + '"\n')
    g = build_graph(tmp_path)
    s = scan(g)
    secrets = [f for f in s["findings"] if f["category"] == "secret"]
    assert secrets and secrets[0]["rank"] == "critical"
    assert secrets[0]["snippet"] == "[redacted]"
