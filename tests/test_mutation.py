"""The mutation tool (tools/mutation.py) makes one change at a time and tells a caught mistake from a missed one."""
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import mutation  # noqa: E402

SRC = "def ok(x, y=True):\n    if x > 3 and y:\n        return not x == 4\n    return 0\n"


def test_every_mutant_is_one_small_change_that_still_parses():
    ms = mutation.mutants(SRC)
    descs = sorted(d for d, _, _ in ms)
    assert descs == ["0 -> 1", "3 -> 4", "4 -> 5", "And -> Or", "Eq -> NotEq", "Gt -> GtE", "True -> False", "not x -> x"], descs
    for _, line, text in ms:
        ast.parse(text)
        assert text != ast.unparse(ast.parse(SRC)) and line in (1, 2, 3, 4)


def test_the_verdict_comes_from_the_tests(tmp_path, monkeypatch):
    """A mutant the tests catch is killed; one they miss survives; the score is the share killed."""
    calls = []

    def fake_run_tests(copy_root, tests, timeout):
        text = (copy_root / "mod.py").read_text(encoding="utf-8")
        calls.append(text)
        return "killed" if "x >= 3" in text else "survived"   # the pretend tests catch exactly one mistake
    monkeypatch.setattr(mutation, "ROOT", tmp_path)
    monkeypatch.setattr(mutation, "run_tests", fake_run_tests)
    (tmp_path / "mod.py").write_text(SRC, encoding="utf-8")
    res = mutation.run("mod.py", ["tests/test_mod.py"], None, 1, 10, log=lambda s: None)
    assert res["run"] == 8 and res["killed"] == 1 and res["survived"] == 7 and res["score"] == round(1 / 8, 3)
    assert [r["change"] for r in res["rows"] if r["verdict"] == "killed"] == ["Gt -> GtE"]
    assert "**survived**" in mutation.table(res) and "`Gt -> GtE`" not in mutation.table(res)
    assert (tmp_path / "mod.py").read_text(encoding="utf-8") == SRC     # the real file is never touched
