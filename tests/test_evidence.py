import json
import subprocess
from pathlib import Path

from lantern import evidence
from lantern.cli import main

APP = {"app.py": "import hashlib\n\ndef h(x):\n    return hashlib.md5(x).hexdigest()\n\n"
                 "if __name__ == '__main__':\n    h(b'x')\n"}


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@example.com", "PATH": "/usr/bin:/bin:/usr/local/bin",
                        "HOME": str(root)})


def _repo(tmp_path):
    _write(tmp_path, APP | {".gitignore": ".lantern/\n"})
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "init")
    return tmp_path


def test_report_is_commit_pinned_and_verifiable(tmp_path, capsys):
    repo = _repo(tmp_path)
    assert main(["analyze", str(repo)]) == 0
    out = repo / ".lantern"
    ev = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    assert ev["header"]["commit"] == head and not ev["header"]["dirty"]
    assert ev["digest"].startswith("sha256:") and ev["digest"] in (out / "evidence.html").read_text(encoding="utf-8")
    assert ev["limits"] and any("Business-logic" in x for x in ev["limits"])
    assert (out / "badge.svg").read_text(encoding="utf-8").startswith("<svg")
    # A reviewer re-runs the analysis on the same commit and gets the same digest
    assert main(["verify", str(repo), "--report", str(out / "evidence.html")]) == 0
    # Change the code: the digest no longer matches
    (repo / "app.py").write_text(APP["app.py"].replace("md5", "sha256"), encoding="utf-8")
    _git(repo, "commit", "-qam", "fix")
    assert main(["verify", str(repo), "--report", str(out / "evidence.html")]) == 1


def test_fixed_findings_show_against_the_baseline(tmp_path):
    repo = _repo(tmp_path)
    assert main(["analyze", str(repo)]) == 0
    (repo / "app.py").write_text(APP["app.py"].replace("md5", "sha256"), encoding="utf-8")
    assert main(["analyze", str(repo)]) == 0
    ev = json.loads((repo / ".lantern/evidence.json").read_text(encoding="utf-8"))
    assert any(f["rule"] == "B324" for f in ev["security"]["fixed"])
    assert sum(ev["scorecard"]["before"].values()) >= 1
    assert "fixed · verified by rescan" in (repo / ".lantern/evidence.html").read_text(encoding="utf-8")


def test_narratives_are_escaped(tmp_path):
    repo = _repo(tmp_path)
    (repo / evidence.NARRATIVES_FILE).write_text("# Checkout\n\nThe <script>alert(1)</script> flow.\n", encoding="utf-8")
    assert main(["analyze", str(repo), "--no-scan"]) == 0
    html = (repo / ".lantern/evidence.html").read_text(encoding="utf-8")
    assert "<h4>Checkout</h4>" in html and "&lt;script&gt;" in html and "<script>alert" not in html


def test_no_git_is_stated_plainly(tmp_path):
    _write(tmp_path, APP)
    assert main(["analyze", str(tmp_path), "--no-scan"]) == 0
    html = (tmp_path / ".lantern/evidence.html").read_text(encoding="utf-8")
    assert "not pinned" in html


def test_remote_credentials_are_not_echoed(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "remote", "add", "origin", "https://user:tok123@example.com/a/b.git")
    assert evidence.git_info(repo)["remote"] == "https://example.com/a/b.git"
