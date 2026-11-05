import json
import subprocess

from lantern import depaudit
from lantern.security import rank


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def test_python_pins_from_locks_requirements_and_pyproject(tmp_path):
    _write(tmp_path, {
        "uv.lock": '[[package]]\nname = "Requests"\nversion = "2.19.0"\n\n'
                   '[[package]]\nname = "myapp"\nversion = "0.1"\nsource = { editable = "." }\n',
        "backend/requirements.txt": "flask==2.0.1\n--index-url https://evil.example/simple\nhttpx>=0.27\n",
        "pyproject.toml": '[project]\nname = "myapp"\nversion = "0.1"\ndependencies = ["requests>=2", "pyyaml==5.3"]\n',
        "tests/fixtures/app/requirements.txt": "django==1.0\n",       # sample apps don't count
    })
    pins, loose, files = depaudit.python_pins(tmp_path)
    assert pins == {"requests": ("2.19.0", "uv.lock"), "flask": ("2.0.1", "backend/requirements.txt"),
                    "pyyaml": ("5.3", "pyproject.toml")}
    assert loose == ["backend/requirements.txt: httpx>=0.27"]     # requests>=2 is pinned by uv.lock
    assert "tests/fixtures/app/requirements.txt" not in files


def test_pip_audit_gets_only_name_version_pairs(tmp_path, monkeypatch):
    _write(tmp_path, {"requirements.txt": "--extra-index-url https://evil.example\nflask==2.0.1\n"})
    seen = {}

    def fake_run(cmd, **kw):
        seen["req"] = open(cmd[cmd.index("-r") + 1], encoding="utf-8").read()
        out = {"dependencies": [{"name": "flask", "version": "2.0.1", "vulns": [
            {"id": "PYSEC-1", "fix_versions": ["2.2.5"], "description": "bad"}]}]}
        return subprocess.CompletedProcess(cmd, 1, json.dumps(out), "")
    monkeypatch.setattr(depaudit.shutil, "which", lambda n: "/bin/" + n)
    monkeypatch.setattr(depaudit.subprocess, "run", fake_run)
    f, info = depaudit.run_pip_audit(tmp_path, no_network=False)
    assert seen["req"] == "flask==2.0.1\n" and info["status"] == "ok"
    assert f[0]["rule"] == "PYSEC-1" and f[0]["file"] == "requirements.txt" and f[0]["category"] == "dependency"


def test_ranges_only_are_reported_as_not_checked(tmp_path):
    _write(tmp_path, {"pyproject.toml": '[project]\nname = "x"\nversion = "1"\ndependencies = ["flask>=2"]\n'})
    _, info = depaudit.run_pip_audit(tmp_path, no_network=False)
    assert info["status"].startswith("skipped: no exact versions")


def test_offline_skips_the_network(tmp_path):
    _write(tmp_path, {"requirements.txt": "flask==2.0.1\n", "package.json": "{}", "package-lock.json": "{}"})
    assert depaudit.run_pip_audit(tmp_path, no_network=True)[1]["status"] == "skipped: offline"
    assert depaudit.run_npm_audit(tmp_path, no_network=True)[1]["status"] == "skipped: offline"


def test_npm_audit_findings_and_severity(tmp_path, monkeypatch):
    _write(tmp_path, {"web/package.json": "{}", "web/package-lock.json": "{}", "api/package.json": "{}"})
    report = {"auditReportVersion": 2, "vulnerabilities": {
        "lodash": {"severity": "high", "range": "<4.17.21", "fixAvailable": {"name": "lodash", "version": "4.17.21"},
                   "via": [{"source": 1, "title": "Command Injection", "url": "https://github.com/advisories/GHSA-x",
                            "severity": "high", "range": "<4.17.21"},
                           {"source": 2, "title": "ReDoS", "url": "https://github.com/advisories/GHSA-y",
                            "severity": "moderate"}]},
        "wrapper": {"severity": "high", "via": ["lodash"], "fixAvailable": True}}}
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw.get("cwd")))
        if cmd[1] == "--version":
            return subprocess.CompletedProcess(cmd, 0, "10.9.0\n", "")
        return subprocess.CompletedProcess(cmd, 1, json.dumps(report), "")
    monkeypatch.setattr(depaudit.shutil, "which", lambda n: "/bin/npm")
    monkeypatch.setattr(depaudit.subprocess, "run", fake_run)
    f, info = depaudit.run_npm_audit(tmp_path, no_network=False)
    audit_cmd = calls[-1][0]
    assert "--package-lock-only" in audit_cmd and f"--registry={depaudit.NPM_REGISTRY}" in audit_cmd
    assert info["status"] == "ok" and info["files"] == ["web/package-lock.json"] and info["not_checked"] == ["api"]
    assert {x["rule"] for x in f} == {"GHSA-x", "GHSA-y"}            # "wrapper" is only vulnerable through lodash
    by = {x["rule"]: x for x in f}
    assert rank(by["GHSA-x"]) == "high" and rank(by["GHSA-y"]) == "medium"
    assert "4.17.21" in by["GHSA-x"]["snippet"]


def test_other_lockfiles_say_why_they_are_skipped(tmp_path):
    _write(tmp_path, {"package.json": "{}", "pnpm-lock.yaml": "lockfileVersion: 9\n"})
    assert "pnpm audit" in depaudit.run_npm_audit(tmp_path, no_network=False)[1]["status"]


def test_pip_audit_duplicate_and_aliased_advisories_merge(tmp_path, monkeypatch):
    """pip-audit can list the same id twice, and the same CVE under a PYSEC and a GHSA id: one finding each."""
    _write(tmp_path, {"requirements.txt": "python-multipart==0.0.6\n"})

    def fake_run(cmd, **kw):
        out = {"dependencies": [{"name": "python-multipart", "version": "0.0.6", "vulns": [
            {"id": "PYSEC-2026-1851", "aliases": ["CVE-2026-24486", "GHSA-wp53"], "fix_versions": ["0.0.7"]},
            {"id": "PYSEC-2024-38", "aliases": ["GHSA-2jv5", "CVE-2024-24762", "PYSEC-2026-1850"], "fix_versions": ["0.0.7"]},
            {"id": "PYSEC-2026-1851", "aliases": ["GHSA-wp53", "CVE-2026-24486"], "fix_versions": ["0.0.7"]},
            {"id": "PYSEC-2026-1850", "aliases": ["GHSA-2jv5", "CVE-2024-24762"], "fix_versions": ["0.0.7"]},
        ]}]}
        return subprocess.CompletedProcess(cmd, 1, json.dumps(out), "")
    monkeypatch.setattr(depaudit.shutil, "which", lambda n: "/bin/" + n)
    monkeypatch.setattr(depaudit.subprocess, "run", fake_run)
    f, _ = depaudit.run_pip_audit(tmp_path, no_network=False)
    assert [x["rule"] for x in f] == ["PYSEC-2024-38", "PYSEC-2026-1851"]
    assert "Also listed as CVE-2024-24762, GHSA-2jv5, PYSEC-2026-1850" in f[0]["more_info"]
    assert len({x["id"] for x in f}) == 2


# ---------------------------------------------------------------- Gradle / Maven through OSV

GRADLE = """plugins { id 'com.android.application' }
ext.retrofitVersion = '2.6.1'
dependencies {
    implementation 'com.squareup.okhttp3:okhttp:3.12.0'
    implementation "com.squareup.retrofit2:retrofit:$retrofitVersion"
    implementation 'com.example:dynamic:1.+'
    testImplementation 'junit:junit:4.12'
    androidTestImplementation 'androidx.test.espresso:espresso-core:3.3.0'
}
"""


def test_maven_coords_from_gradle_catalog_and_pom(tmp_path):
    _write(tmp_path, {
        "app/build.gradle": GRADLE,
        "gradle/libs.versions.toml": '[versions]\ngson = "2.8.5"\n[libraries]\n'
                                     'gson = { module = "com.google.code.gson:gson", version.ref = "gson" }\n'
                                     'junit = { module = "junit:junit", version = "4.13" }\n',
        "server/pom.xml": "<project><properties><jackson.version>2.9.8</jackson.version></properties><dependencies>"
                          "<dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId>"
                          "<version>${jackson.version}</version></dependency>"
                          "<dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version>"
                          "<scope>test</scope></dependency></dependencies></project>",
    })
    pins, loose, files = depaudit.maven_coords(tmp_path)
    assert pins["com.squareup.okhttp3:okhttp"][:2] == ("3.12.0", "app/build.gradle")
    assert pins["com.squareup.okhttp3:okhttp"][2] == 4                      # the line it is written on
    assert pins["com.squareup.retrofit2:retrofit"][0] == "2.6.1"            # $variable resolved
    assert pins["com.google.code.gson:gson"][0] == "2.8.5"                  # version catalog
    assert pins["com.fasterxml.jackson.core:jackson-databind"][0] == "2.9.8"   # pom property
    assert not any("junit" in k or "espresso" in k for k in pins)           # test libraries are not shipped
    assert loose == ["com.example:dynamic:1.+"]
    assert set(files) == {"app/build.gradle", "gradle/libs.versions.toml", "server/pom.xml"}


def test_maven_audit_asks_osv_names_and_versions_only(tmp_path, monkeypatch):
    _write(tmp_path, {"app/build.gradle": GRADLE})
    asked = {}

    def post(path, body, timeout=60):
        asked["post"] = (path, body)
        return {"results": [{"vulns": [{"id": "GHSA-aaaa"}]} if q["package"]["name"].endswith("okhttp") else {}
                            for q in body["queries"]]}

    def get(path, timeout=30):
        asked.setdefault("get", []).append(path)
        return {"id": "GHSA-aaaa", "summary": "Certificate pinning bypass", "aliases": ["CVE-2021-0341"],
                "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"name": "com.squareup.okhttp3:okhttp", "ecosystem": "Maven"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.12.13"}]}]}]}
    monkeypatch.setattr(depaudit, "_osv_post", post)
    monkeypatch.setattr(depaudit, "_osv_get", get)
    f, info = depaudit.run_maven_audit(tmp_path, no_network=False)
    assert asked["post"][0] == "querybatch"
    assert {q["package"]["ecosystem"] for q in asked["post"][1]["queries"]} == {"Maven"}
    assert set(asked["post"][1]["queries"][0]) == {"package", "version"}
    assert asked["get"] == ["vulns/GHSA-aaaa"]
    assert len(f) == 1
    assert f[0]["package"] == "com.squareup.okhttp3:okhttp" and f[0]["line"] == 4 and f[0]["dep_severity"] == "high"
    assert "3.12.13" in f[0]["more_info"] and "CVE-2021-0341" in f[0]["more_info"]
    assert info["status"] == "ok" and info["checked"] == 2 and info["unpinned"] == 1


def test_maven_audit_offline_and_errors(tmp_path, monkeypatch):
    _write(tmp_path, {"app/build.gradle": GRADLE})
    assert depaudit.run_maven_audit(tmp_path, no_network=True)[1]["status"] == "skipped: offline"
    assert depaudit.run_maven_audit(tmp_path / "none", no_network=False)[1]["status"] == "skipped: no Gradle or Maven files"

    def boom(*a, **k):
        raise OSError("no route")
    monkeypatch.setattr(depaudit, "_osv_post", boom)
    f, info = depaudit.run_maven_audit(tmp_path, no_network=False)
    assert f == [] and info["status"].startswith("error: OSError")
