"""Ask Lantern: answers come from the model, facts from the results on disk; invented finding ids never show."""

from pathlib import Path

from lantern import ask
from lantern.engine import build_graph
from lantern.pipeline import analyze
from lantern.providers import FixtureProvider

FIX = Path(__file__).parent / "fixtures" / "shop"


def test_facts_and_cited_ids(tmp_path):
    import shutil
    repo = tmp_path / "shop"
    shutil.copytree(FIX, repo)
    (repo / ".lantern").mkdir(exist_ok=True)
    analyze(repo, repo / ".lantern", "full", log=lambda *a, **k: None)
    f = ask.facts(repo)
    assert "Readiness:" in f and "Findings open:" in f and "Routes:" in f
    ids = [line.split("]")[0][3:] for line in f.splitlines() if line.startswith("- [")]
    assert ids and all(len(i) == 12 for i in ids)
    real, fake = ids[0], "0123456789ab"

    def model(system, user):
        assert "FACTS for project" in user and "QUESTION: what first?" in user
        return f"Fix [{real}] first. Also [{fake}] (made up)."
    r = ask.ask(FixtureProvider(model), "what first?", repo)
    assert r["cited"] == [real] and r["invented"] == [fake]
    assert f"[{real}]" in r["answer"] and fake not in r["answer"] and "[unknown finding]" in r["answer"]


def test_no_project_answers_about_lantern():
    seen = {}

    def model(system, user):
        seen["user"] = user
        return "Lantern maps your app."
    r = ask.ask(FixtureProvider(model), "what is this?", None)
    assert "no project is selected" in seen["user"] and r["answer"] == "Lantern maps your app."


def test_screenshot_without_tesseract_reports_size():
    import io
    try:
        from PIL import Image
    except ImportError:
        return
    buf = io.BytesIO()
    Image.new("RGB", (40, 30), "white").save(buf, format="PNG")
    body = (b"--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shot.png\"\r\nContent-Type: image/png\r\n\r\n"
            + buf.getvalue() + b"\r\n--b--\r\n")
    r = ask.read_screenshot(body, "multipart/form-data; boundary=b")
    assert r["width"] == 40 and r["height"] == 30 and ("lines" in r or "error" in r)
