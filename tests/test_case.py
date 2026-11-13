"""The case for a finding (case.py): every finding outside tests says what is claimed, the evidence, what has to be
true for it to hurt (and whether Lantern saw it), how bad and how sure, what is unknown, and its status words.
Paired: a real problem's conditions read "yes"; a lowered one's read "no"; nothing is ever marked tested or
independently reviewed by Lantern itself."""

import json
import shutil
from pathlib import Path

import lantern_files
from lantern import pipeline
from lantern.case import STATUS_WORDS
from lantern.engine import build_graph
from lantern.security import scan

FIX = Path(__file__).parent / "fixtures"
HEAD = "import hashlib\nfrom fastapi import FastAPI\n\napp = FastAPI()\n\n"
KEYS = {"version", "where", "claim", "evidence", "conditions", "impact", "severity", "confidence", "unknown", "status"}


def _scan(root, body):
    (root / "a").mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text('[project]\nname="a"\nversion="0"\n', encoding="utf-8")
    (root / "a" / "main.py").write_text(HEAD + body, encoding="utf-8")
    return scan(build_graph(root), offline=True)["findings"]


def _cond(f, word):
    return next(c for c in f["case"]["conditions"] if word in c["need"])


def test_every_finding_outside_tests_has_a_full_case_and_test_findings_do_not(tmp_path):
    shutil.copytree(FIX / "shop", tmp_path / "shop")
    fs = scan(build_graph(tmp_path / "shop"), offline=True)["findings"]
    live = [f for f in fs if not f["in_tests"]]
    assert live and all(set(f["case"]) == KEYS for f in live)
    assert all("case" not in f for f in fs if f["in_tests"])
    for f in live:
        c = f["case"]
        assert c["where"]["file"] == f["file"] and c["where"]["line"] == f["line"]
        assert c["severity"]["rank"] == f["rank"] and c["severity"]["why"]
        assert [s["word"] for s in c["status"]] == list(STATUS_WORDS)
        assert c["status"][0]["done"] is True
        # Lantern never claims a test or an independent review on its own
        assert c["status"][3]["done"] is None and c["status"][4]["done"] is None
        assert c["confidence"]["level"] in ("high", "medium", "low", "unknown")
        assert "not a confirmed" in c["claim"] or "not test" in c["claim"] or "not proof" in c["claim"] \
            or "not checked" in c["claim"]


def test_a_real_injection_shows_its_conditions_met(tmp_path):
    fs = _scan(tmp_path, "import subprocess\n\n@app.post('/run')\ndef run(name: str):\n"
                         "    subprocess.run('ls ' + name, shell=True)\n")
    f = next(f for f in fs if f["rule"] == "B602")
    assert f["rank"] == "critical"
    assert _cond(f, "outside")["met"] is True
    assert _cond(f, "send")["met"] is True
    assert "request data" in f["case"]["severity"]["why"]
    # the evidence that what they send reaches the line is the followed data, from where the request is read
    ev = [e for e in f["case"]["evidence"] if e["from"] == "data flow"]
    assert len(ev) == 1 and "`name` arrives with the request" in ev[0]["fact"], f["case"]["evidence"]
    assert _cond(f, "send")["why"].startswith("data flow: followed in 2 steps")


def test_a_lowered_hash_shows_the_condition_that_is_not_met(tmp_path):
    fs = _scan(tmp_path, "import random\n\n@app.post('/v')\ndef v(group_id: str):\n"
                         "    seed = int.from_bytes(hashlib.md5(group_id.encode()).digest()[:4], 'big')\n"
                         "    return random.Random(seed).random()\n")
    f = next(f for f in fs if f["rule"] == "B324")
    assert f["rank"] == "low"
    assert _cond(f, "protects a password")["met"] is False
    assert f["case"]["severity"]["before_context"] in ("critical", "high")
    assert "lowered by context" in f["case"]["severity"]["why"]
    assert "at least one condition for harm is not met" in f["case"]["confidence"]["why"]


def test_a_password_hash_keeps_its_condition_met(tmp_path):
    fs = _scan(tmp_path, "@app.post('/login')\ndef login(password: str):\n"
                         "    return hashlib.md5(password.encode()).hexdigest()\n")
    f = next(f for f in fs if f["rule"] == "B324")
    assert f["rank"] == "critical"
    assert _cond(f, "protects a password")["met"] is True


def test_sql_that_splices_only_fixed_text_says_input_does_not_become_sql(tmp_path):
    fs = _scan(tmp_path, "@app.get('/n')\ndef n(conn, when: str, fresh: bool):\n"
                         "    stamp = 'now()' if fresh else '%s'\n"
                         "    return conn.execute(f'UPDATE t SET at = {stamp} WHERE k = %s', (when,))\n")
    f = next(f for f in fs if f["rule"] == "B608")
    assert _cond(f, "SQL text")["met"] is False


def test_a_browser_value_is_never_called_a_way_in(tmp_path):
    shutil.copytree(FIX / "shop", tmp_path / "shop")
    fs = scan(build_graph(tmp_path / "shop"), offline=True)["findings"]
    f = next(f for f in fs if f["rule"] == "LW-PUBLIC-SECRET")
    assert _cond(f, "reaches the browser")["met"] is True
    assert _cond(f, "stops a stranger")["met"] is None
    assert "not proof" in f["case"]["claim"]


def test_a_second_run_marks_findings_reproduced_and_records_the_revision(tmp_path):
    shutil.copytree(FIX / "shop", tmp_path / "shop")
    out = tmp_path / "out"
    out.mkdir()
    pipeline.analyze(tmp_path / "shop", out, offline=True, log=lambda *_: None)
    first = json.loads((out / "security.json").read_text(encoding="utf-8"))["findings"]
    assert all(f["case"]["status"][1]["done"] is None for f in first if "case" in f)
    pipeline.analyze(tmp_path / "shop", out, offline=True, log=lambda *_: None)
    again = json.loads((out / "security.json").read_text(encoding="utf-8"))["findings"]
    assert all(f["case"]["status"][1]["done"] is True for f in again if "case" in f)
    assert "revision" in again[0]["case"]["where"]   # None here: the copy is not a git folder


def test_the_viewer_escapes_every_case_field(tmp_path):
    html = lantern_files.page("report.html")
    body = html[html.index("function caseBox(f)"):html.index("// Every call site Lantern read")]
    import re
    for m in re.finditer(r"\$\{([^}]*)\}", body):
        expr = m.group(1)
        if re.search(r"\b(c|w|x|e|sev|conf)\.\w+", expr) and "esc(" not in expr and "?" not in expr:
            raise AssertionError(f"unescaped case value: {expr}")


def test_code_reached_only_by_running_the_program_is_not_called_reachable_by_outsiders(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="a"\nversion="0"\n', encoding="utf-8")
    (tmp_path / "tool.py").write_text("import subprocess\nimport sys\n\n\ndef main():\n"
                                      "    subprocess.run('ls ' + sys.argv[1], shell=True)\n\n\n"
                                      "if __name__ == '__main__':\n    main()\n", encoding="utf-8")
    fs = scan(build_graph(tmp_path), offline=True)["findings"]
    f = next(f for f in fs if f["rule"] == "B602")
    c = _cond(f, "outside")
    assert c["met"] is None and "runs the program" in c["why"]
