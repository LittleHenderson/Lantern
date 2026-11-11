"""npm takes no settings from the project it audits, and reads nothing outside a folder of Lantern's own
(stage 7 of the 2026-11-09 directive, part 3).

`npm audit` takes settings from the folder it is started in (`.npmrc`), and until 2026-11-10 Lantern started it in
the project. Lantern named the registry itself, but a settings file there could still switch the audit off while the
record said `ok`, send the question through a proxy of the project's choosing, switch the check of the registry's
certificate off, and make npm write where the project said. npm also reads the `package.json` of every folder a lock
file names on the computer, inside the project or not.

The first half starts the real npm against stand-in registries on 127.0.0.1 (nothing leaves this computer; skipped
where npm is not installed). The second half puts a stand-in in npm's place and looks at the folder it is started
in, so it runs everywhere. Each dangerous case has a twin that must go on working.
"""
import gzip
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from lantern import depaudit, programs, scanresult
from lantern.scanresult import ToolRun

needs_npm = pytest.mark.skipif(programs.find("npm") is None, reason="npm is not installed")
only_posix = pytest.mark.skipif(os.name != "posix", reason="needs a POSIX system (symbolic links, pipes)")

ADVISORY = {"id": 1100001, "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "title": "Stand-in advisory",
            "severity": "high", "vulnerable_versions": "<=1.3.0", "cwe": ["CWE-400"],
            "cvss": {"score": 7.5, "vectorString": None}}
KNOWN = {"left-pad": [ADVISORY], "is-odd": [dict(ADVISORY, id=1100002, vulnerable_versions="<=2.0.0")]}
PAD = {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
ODD = {"version": "2.0.0", "resolved": "https://registry.npmjs.org/is-odd/-/is-odd-2.0.0.tgz"}
APP = {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "^1.3.0"}}
PLAIN = {"package.json": APP,
         "package-lock.json": {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
                               "packages": {"": APP, "node_modules/left-pad": PAD}}}
WORKSPACES = {
    "package.json": {"name": "mono", "version": "1.0.0", "workspaces": ["packages/*"]},
    "packages/a/package.json": {"name": "a", "version": "1.0.0", "dependencies": {"left-pad": "^1.3.0"}},
    "packages/a/index.js": "module.exports = 1\n",
    "packages/b/package.json": {"name": "b", "version": "2.0.0", "dependencies": {"is-odd": "^2.0.0", "a": "*"}},
    "package-lock.json": {"name": "mono", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
        "": {"name": "mono", "version": "1.0.0", "workspaces": ["packages/*"]},
        "node_modules/a": {"resolved": "packages/a", "link": True},
        "node_modules/b": {"resolved": "packages/b", "link": True},
        "node_modules/left-pad": PAD, "node_modules/is-odd": ODD,
        "packages/a": {"name": "a", "version": "1.0.0", "dependencies": {"left-pad": "^1.3.0"}},
        "packages/b": {"name": "b", "version": "2.0.0", "dependencies": {"a": "*", "is-odd": "^2.0.0"}}}}}
LIBRARY = {
    "package.json": {"name": "app", "version": "1.0.0", "dependencies": {"lib": "file:lib"}},
    "lib/package.json": {"name": "lib", "version": "3.0.0", "dependencies": {"left-pad": "^1.3.0"}},
    "package-lock.json": {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
        "": {"name": "app", "version": "1.0.0", "dependencies": {"lib": "file:lib"}},
        "lib": {"version": "3.0.0", "dependencies": {"left-pad": "^1.3.0"}},
        "node_modules/lib": {"resolved": "lib", "link": True}, "node_modules/left-pad": PAD}}}
NEXT_DOOR = {"name": "the-neighbours-private-library", "version": "9.9.9"}     # a folder beside the project, not of it


def linked(place):
    """A project whose lock file (as npm 7 and later write it) names `place` as the folder of a library."""
    root = {"name": "app", "version": "1.0.0", "dependencies": {"next-door": "file:" + place, "left-pad": "^1.3.0"}}
    return {"package.json": root,
            "package-lock.json": {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
                "": root, place: {}, "node_modules/next-door": {"resolved": place, "link": True},
                "node_modules/left-pad": PAD}}}


def older(version):
    """A project whose lock file (as npm 6 and earlier wrote it) gives `version` for a library."""
    return {"package.json": {"name": "app", "version": "1.0.0", "dependencies": {"next-door": version, "left-pad": "^1.3.0"}},
            "package-lock.json": {"name": "app", "version": "1.0.0", "lockfileVersion": 1, "requires": True, "dependencies": {
                "next-door": {"version": version}, "left-pad": dict(PAD)}}}


def project(tmp_path, files, at="project"):
    """`files` (name: text, or what to write as JSON) in a new folder; a name may lead out of it (`../next-door/…`)."""
    repo = tmp_path / at
    repo.mkdir(parents=True, exist_ok=True)
    for rel, what in files.items():
        p = Path(os.path.normpath(repo / rel))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(what if isinstance(what, str) else json.dumps(what), encoding="utf-8")
    return repo


def listing(folder):
    return sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*"))


class Registry:
    """A stand-in npm registry on 127.0.0.1 that writes down what it was asked. It answers a request that names a
    whole address too (what a proxy is sent), so the same class plays the address a project's settings name."""

    def __init__(self, known=None, tls=None):
        self.known = KNOWN if known is None else known
        self.asked = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _answer(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _note(self, body=None):
                outer.asked.append({"method": self.command, "path": self.path, "body": body,
                                    "authorization": self.headers.get("Authorization"),
                                    "agent": self.headers.get("User-Agent") or ""})

            def do_CONNECT(self):
                self._note()
                self._answer(502, {"error": "no tunnels here"})

            def do_GET(self):
                self._note()
                self._answer(404, {"error": "not found"})

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if self.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = None
                self._note(body)
                if self.path.endswith("/-/npm/v1/security/advisories/bulk") and isinstance(body, dict):
                    return self._answer(200, {name: adv for name, adv in outer.known.items() if name in body})
                self._answer(404, {"error": "not found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*tls)
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{self.port}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def questions(self):
        """What the audit asked about: {package: [versions]} per request."""
        return [x["body"] for x in self.asked if x["method"] == "POST" and x["path"].endswith("/advisories/bulk")]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def registry(monkeypatch):
    """The registry Lantern names to npm, for this test a stand-in on this computer."""
    r = Registry()
    monkeypatch.setattr(depaudit, "NPM_REGISTRY", r.url)
    yield r
    r.close()


@pytest.fixture
def elsewhere():
    """The address a project's own settings name. It knows of no problem."""
    r = Registry(known={})
    yield r
    r.close()


@pytest.fixture(scope="module")
def nobodys_certificate(tmp_path_factory):
    """A certificate for 127.0.0.1 that nobody vouches for, and its key, made here."""
    pytest.importorskip("cryptography")
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    folder = tmp_path_factory.mktemp("certificate")
    (folder / "certificate.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                       serialization.NoEncryption()))
    return folder / "certificate.pem", folder / "key.pem"


@pytest.fixture
def unvouched(monkeypatch, nobodys_certificate):
    """Lantern's registry behind that certificate: npm must refuse to talk to it."""
    r = Registry(tls=nobodys_certificate)
    monkeypatch.setattr(depaudit, "NPM_REGISTRY", r.url)
    yield r
    r.close()


# ---------------------------------------------------------------------------- the real npm

@needs_npm
def test_npm_finds_what_the_registry_knows(tmp_path, registry):
    repo = project(tmp_path, PLAIN)
    findings, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok" and [f["package"] for f in findings] == ["left-pad"]
    assert registry.questions() == [{"left-pad": ["1.3.0"]}]


@needs_npm
@pytest.mark.parametrize("settings", [
    "offline=true\n",                           # before: nobody was asked, nothing was found, and the record said ok
    "global=true\n", "location=global\n",       # before: the audit failed
    "workspace=nope\n",
    "fetch-timeout=1\nfetch-retries=0\n",
])
def test_a_settings_file_in_the_project_changes_nothing(tmp_path, registry, settings):
    repo = project(tmp_path, {**PLAIN, ".npmrc": settings})
    findings, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok", info
    assert [f["package"] for f in findings] == ["left-pad"]
    assert registry.questions() == [{"left-pad": ["1.3.0"]}]


@needs_npm
def test_a_settings_file_one_folder_up_changes_nothing(tmp_path, registry):
    """npm also takes the settings of a folder above whose package.json names this one as a workspace."""
    repo = project(tmp_path, {"package.json": {"name": "mono", "version": "1.0.0", "workspaces": ["web"]},
                              ".npmrc": "offline=true\n",
                              "web/package.json": PLAIN["package.json"], "web/package-lock.json": PLAIN["package-lock.json"]})
    findings, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok", info
    assert [(f["package"], f["file"]) for f in findings] == [("left-pad", "web/package-lock.json")]


@needs_npm
def test_the_projects_proxy_is_never_asked(tmp_path, registry, elsewhere, monkeypatch):
    for name in ("NO_PROXY", "no_proxy"):       # as on a person's computer: nothing says "not through a proxy"
        monkeypatch.delenv(name, raising=False)
    repo = project(tmp_path, {**PLAIN, ".npmrc": f"proxy={elsewhere.url}\nhttps-proxy={elsewhere.url}\n"})
    findings, info = depaudit.run_npm_audit(repo, False)
    assert elsewhere.asked == []                # before: both of npm's requests went there, and the record said ok
    assert info["state"] == "ok" and [f["package"] for f in findings] == ["left-pad"]
    assert registry.questions() == [{"left-pad": ["1.3.0"]}]


@needs_npm
@pytest.mark.parametrize("how", ["strict-ssl=false", "cafile"])
def test_a_project_cannot_switch_the_check_of_the_certificate_off(tmp_path, unvouched, nobodys_certificate, how):
    repo = project(tmp_path, PLAIN)
    if how == "cafile":                         # the project brings the certificate and says "trust this one"
        (repo / "ca.pem").write_bytes(nobodys_certificate[0].read_bytes())
        (repo / ".npmrc").write_text(f"cafile={(repo / 'ca.pem').as_posix()}\n", encoding="utf-8")
    else:
        (repo / ".npmrc").write_text(how + "\n", encoding="utf-8")
    findings, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "failed" and findings == [], info
    assert unvouched.asked == []                # before: npm talked to it, and the record said ok


@needs_npm
def test_the_persons_own_npm_settings_still_count(tmp_path, unvouched, monkeypatch):
    """Twin: what the person set for their own npm is theirs to set (a company's registry with its own certificate)."""
    own = tmp_path / "the-persons-npmrc"
    own.write_text("strict-ssl=false\n", encoding="utf-8")
    monkeypatch.setenv("NPM_CONFIG_USERCONFIG", str(own))
    findings, info = depaudit.run_npm_audit(project(tmp_path, PLAIN), False)
    assert info["state"] == "ok" and [f["package"] for f in findings] == ["left-pad"]
    assert unvouched.questions() == [{"left-pad": ["1.3.0"]}]


@needs_npm
def test_npm_writes_nothing_where_the_project_says(tmp_path, registry):
    repo = project(tmp_path, PLAIN)
    planted = tmp_path / "planted"
    (repo / ".npmrc").write_text(f"cache={(planted / 'cache').as_posix()}\nlogs-dir={(repo / 'logs').as_posix()}\n",
                                 encoding="utf-8")
    before = listing(repo)
    _, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok"
    assert listing(repo) == before and not planted.exists()     # before: npm's cache and its logs were written there


@needs_npm
def test_the_projects_token_and_name_are_not_sent(tmp_path, registry):
    token = "-".join(["the", "projects", "token"])
    repo = project(tmp_path, {**PLAIN, ".npmrc": f"//127.0.0.1:{registry.port}/:_authToken={token}\n"
                                                 "user-agent=THE-PROJECTS-AGENT\n"})
    _, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok" and registry.questions()
    assert [x["authorization"] for x in registry.asked if x["authorization"]] == []
    assert not [x["agent"] for x in registry.asked if "THE-PROJECTS" in x["agent"]]


@needs_npm
@pytest.mark.parametrize("settings", [None, "offline=true\n"])
def test_the_packages_of_a_workspace_project_are_asked_about(tmp_path, registry, settings):
    """npm finds a workspace package by its folder: a copy without those folders asks about nothing and says that
    nothing is known."""
    repo = project(tmp_path, WORKSPACES if settings is None else {**WORKSPACES, ".npmrc": settings})
    findings, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok", info
    assert registry.questions() == [{"left-pad": ["1.3.0"], "is-odd": ["2.0.0"], "a": ["1.0.0"], "b": ["2.0.0"]}]
    assert sorted(f["package"] for f in findings) == ["is-odd", "left-pad"]


@needs_npm
@pytest.mark.parametrize("on_disk", ["3.0.0", "3.1.0"])
def test_a_library_in_a_folder_of_the_project_is_asked_about_as_it_is_there(tmp_path, registry, on_disk):
    """npm reads such a folder's package.json and believes it before the lock file; the copy has to hold it."""
    files = {**LIBRARY, "lib/package.json": {**LIBRARY["lib/package.json"], "version": on_disk}}
    findings, info = depaudit.run_npm_audit(project(tmp_path, files), False)
    assert info["state"] == "ok", info
    assert registry.questions() == [{"lib": [on_disk], "left-pad": ["1.3.0"]}]
    assert [f["package"] for f in findings] == ["left-pad"]


@needs_npm
@pytest.mark.parametrize("files", [linked("../next-door"), older("file:../next-door"), older("file:..\\next-door")],
                         ids=["a lock file of npm 7 and later", "an older lock file", "an older lock file, backslash"])
def test_a_folder_beside_the_project_is_not_read(tmp_path, registry, files):
    """Before, npm read the neighbour's package.json and sent what it found there (its version) to the registry."""
    repo = project(tmp_path, {**files, "../next-door/package.json": NEXT_DOOR})
    findings, info = depaudit.run_npm_audit(repo, False)
    said = json.dumps([registry.asked, info, findings])
    assert "9.9.9" not in said and NEXT_DOOR["name"] not in said
    assert info["state"] == "ok" and [f["package"] for f in findings] == ["left-pad"], info


@needs_npm
def test_the_lock_file_npm_prefers_is_the_one_audited(tmp_path, registry):
    """Twin: npm takes npm-shrinkwrap.json before package-lock.json, in the project and so in the copy."""
    root = {"name": "app", "version": "1.0.0", "dependencies": {"is-odd": "^2.0.0"}}
    wrap = {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
            "packages": {"": root, "node_modules/is-odd": ODD}}
    repo = project(tmp_path, {**PLAIN, "package.json": root, "npm-shrinkwrap.json": wrap})
    findings, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok" and registry.questions() == [{"is-odd": ["2.0.0"]}]
    assert [f["package"] for f in findings] == ["is-odd"]


# ---------------------------------------------------------------------------- a stand-in for npm

REPORT = {"auditReportVersion": 2, "vulnerabilities": {"left-pad": {
    "name": "left-pad", "severity": "high", "range": "<=1.3.0", "fixAvailable": False,
    "via": [{"source": 1, "name": "left-pad", "title": "Stand-in advisory", "url": ADVISORY["url"], "severity": "high",
             "range": "<=1.3.0"}]}}}


class Started:
    """In npm's place: writes down the folder it was started in and every file of Lantern's folder around it."""

    def __init__(self, monkeypatch):
        self.runs = []
        monkeypatch.setattr(programs, "find", lambda name: "/bin/" + name)
        monkeypatch.setattr(scanresult, "run_tool", self)

    def __call__(self, cmd, **kw):
        if "--version" in cmd:
            return ToolRun(0, "10.0.0\n", "")
        cwd = Path(kw["cwd"])
        own = next((p for p in [cwd, *cwd.parents] if p.name.startswith("lantern-own-")), None)
        files = {} if own is None else {p.relative_to(own).as_posix(): p.read_text(encoding="utf-8")
                                        for p in sorted(own.rglob("*")) if p.is_file()}
        self.runs.append({"cwd": cwd, "own": own, "files": files, "cmd": list(cmd)})
        return ToolRun(1, json.dumps(REPORT), "")

    def there(self, place, run=0):
        """The file npm finds at `place`, as seen from the folder it was started in; None when there is none.
        Never outside Lantern's own folder."""
        r = self.runs[run]
        path = Path(os.path.normpath(r["cwd"] / place))
        assert r["own"] in path.parents, f"{place} leads out of Lantern's own folder"
        return r["files"].get(path.relative_to(r["own"]).as_posix())


def text(what):
    return json.dumps(what)


def test_npm_is_started_in_a_folder_of_lanterns_own(tmp_path, monkeypatch):
    npm = Started(monkeypatch)
    repo = project(tmp_path, {**PLAIN, ".npmrc": "offline=true\n", "src/app.js": "x = 1\n",
                              "node_modules/left-pad/package.json": {"name": "left-pad", "version": "0.0.1"}})
    findings, info = depaudit.run_npm_audit(repo, False)
    (run,) = npm.runs
    assert run["own"] is not None, "npm was started in " + str(run["cwd"])
    assert run["cwd"] == run["own"] / "project"         # no `..` in the lock file: no folder above the copy
    assert repo not in [run["cwd"], *run["cwd"].parents] and run["own"] not in [repo, *repo.parents]
    assert sorted(run["files"].values()) == sorted([text(PLAIN["package.json"]), text(PLAIN["package-lock.json"])])
    assert npm.there("package.json") == text(PLAIN["package.json"])
    assert npm.there("package-lock.json") == text(PLAIN["package-lock.json"])
    assert not run["own"].exists()              # and gone afterwards
    assert info["state"] == "ok" and [f["file"] for f in findings] == ["package-lock.json"]
    assert "--package-lock-only" in run["cmd"] and f"--registry={depaudit.NPM_REGISTRY}" in run["cmd"]


def test_the_folders_a_lock_file_names_in_the_project_are_copied_as_they_lie(tmp_path, monkeypatch):
    npm = Started(monkeypatch)
    repo = project(tmp_path, {**WORKSPACES, "packages/a/.npmrc": "offline=true\n"})
    _, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok", info
    assert npm.there("packages/a/package.json") == text(WORKSPACES["packages/a/package.json"])
    assert npm.there("packages/b/package.json") == text(WORKSPACES["packages/b/package.json"])
    assert len(npm.runs[0]["files"]) == 4       # those two, package.json and package-lock.json: no source, no settings


def test_a_lock_file_in_a_folder_of_the_project_may_name_the_folder_beside_it(tmp_path, monkeypatch):
    """Twin: `web/` and `shared/` in one project. The copy keeps the project's layout, so npm finds `../shared`."""
    npm = Started(monkeypatch)
    files = linked("../shared")
    shared = {"name": "shared", "version": "4.0.0"}
    repo = project(tmp_path, {"web/package.json": files["package.json"], "web/package-lock.json": files["package-lock.json"],
                              "shared/package.json": shared, "shared/secret.txt": "not npm's business\n"})
    findings, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok" and [f["file"] for f in findings] == ["web/package-lock.json"], info
    assert npm.there("../shared/package.json") == text(shared)
    assert npm.there("package-lock.json") == text(files["package-lock.json"])
    assert len(npm.runs[0]["files"]) == 3


OUTSIDE = [(linked("../next-door"), "../next-door"), (linked("../../next-door"), "../../next-door"),
           (older("file:../next-door"), "../next-door"), (older("file:..\\next-door"), "../next-door"),
           (linked("packages/../../next-door"), "../next-door"), (linked("../some/../next-door"), "../next-door"),
           (linked("node_modules/../../next-door"), "../next-door")]


@pytest.mark.parametrize("files, place", OUTSIDE, ids=[json.dumps(f["package.json"]["dependencies"]["next-door"])
                                                       for f, _ in OUTSIDE])
def test_where_a_lock_file_points_out_of_the_project_there_is_nothing(tmp_path, monkeypatch, files, place):
    npm = Started(monkeypatch)
    for beside in ("some/next-door", "next-door"):      # one level up and two
        project(tmp_path, {"package.json": NEXT_DOOR}, at=beside)
    repo = project(tmp_path, files, at="some/project")
    _, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok", info
    (run,) = npm.runs
    assert run["own"] is not None, "npm was started in " + str(run["cwd"])
    assert npm.there(place + "/package.json") is None  # `there` fails, too, when the place is not in Lantern's folder
    assert text(NEXT_DOOR) not in run["files"].values() and len(run["files"]) == 2


FULL = ["/etc", "//server/share/x", "\\\\server\\share\\x", "C:/Windows", "C:\\Windows", "c:x", "C|/Windows"]


@pytest.mark.parametrize("files", [linked(p) for p in FULL] + [older("file:" + p) for p in FULL]
                         + [older("file:/../next-door"), older("FILE:///etc"), older("/etc"),
                            {**PLAIN, "package-lock.json": {**PLAIN["package-lock.json"], "dependencies": {
                                "x": {"version": "1.0.0", "requires": {}, "dependencies": {"y": {"from": "\\\\server\\x"}}}}}}])
def test_a_folder_named_by_its_full_path_means_npm_is_not_started(tmp_path, monkeypatch, files):
    npm = Started(monkeypatch)
    findings, info = depaudit.run_npm_audit(project(tmp_path, files), False)
    assert npm.runs == [] and findings == []
    assert info["state"] == "failed" and len(info["errors"]) == 1
    assert info["errors"][0].startswith("package-lock.json: names a folder by its full path (")
    assert info["errors"][0].endswith("so npm was not started on it")


@pytest.mark.parametrize("version", ["file:..%2Fnext-door", "file:%2e%2e/next-door", "file:.\t./next-door",
                                     "file:x/\n../../next-door", "file:~/next-door", "file:./~", "file:lib/../~/x",
                                     "next-door\x7f/x"])
def test_a_folder_named_in_words_that_read_two_ways_means_npm_is_not_started(tmp_path, monkeypatch, version):
    """An older lock file's `file:` version is read as an address: `%2e%2e` may be `..` there, a tab is taken out,
    `~` is the person's home folder."""
    npm = Started(monkeypatch)
    findings, info = depaudit.run_npm_audit(project(tmp_path, older(version)), False)
    assert npm.runs == [] and findings == []
    assert info["state"] == "failed" and "in words that programs read in different ways" in info["errors"][0]
    assert info["errors"][0].isascii() and info["errors"][0].isprintable()


@pytest.mark.parametrize("version", ["1.3.0", "^1.0.0 || ~2.0.0", "github:user/repo#semver:^1.0.0", "user/repo#v1",
                                     "git+ssh://git@github.com/user/repo.git#0123abc", "npm:other@1.0.0",
                                     "https://registry.npmjs.org/@scope%2fname/-/name-1.0.0.tgz", "file:lib", "file:c#-sdk"])
def test_what_an_older_lock_file_ordinarily_says_is_handed_to_npm(tmp_path, monkeypatch, version):
    """Twin: versions, ranges and addresses elsewhere are no folders; `#`, `|` and `:` in them refuse nothing."""
    npm = Started(monkeypatch)
    files = older(version)
    for key in ("from", "resolved"):
        files["package-lock.json"]["dependencies"]["next-door"][key] = version
    _, info = depaudit.run_npm_audit(project(tmp_path, files), False)
    assert info["state"] == "ok" and len(npm.runs) == 1, info
    assert npm.there("package-lock.json") == text(files["package-lock.json"])


def test_a_lock_file_may_climb_only_so_far(tmp_path, monkeypatch):
    npm = Started(monkeypatch)
    most = "../" * 16 + "x"
    _, info = depaudit.run_npm_audit(project(tmp_path, linked(most)), False)
    assert info["state"] == "ok" and len(npm.runs) == 1, info                  # twin: as far as that, it is started
    assert npm.there(most + "/package.json") is None
    findings, info = depaudit.run_npm_audit(project(tmp_path, linked("../" + most), at="second"), False)
    assert len(npm.runs) == 1 and findings == [] and info["state"] == "failed"
    assert info["errors"] == ["package-lock.json: names a folder 17 levels up, so npm was not started on it"]


def test_a_lock_file_may_name_only_so_many_folders_of_so_many_bytes(tmp_path, monkeypatch):
    npm = Started(monkeypatch)
    repo = project(tmp_path, WORKSPACES)
    monkeypatch.setattr(depaudit, "NPM_LOCAL_MAX", 2)
    assert depaudit.run_npm_audit(repo, False)[1]["state"] == "ok" and len(npm.runs) == 1      # twin: two are two
    monkeypatch.setattr(depaudit, "NPM_LOCAL_MAX", 1)
    findings, info = depaudit.run_npm_audit(repo, False)
    assert len(npm.runs) == 1 and findings == [] and info["state"] == "failed"
    assert info["errors"] == ["package-lock.json: names more than 1 folders of its own, so npm was not started on it"]
    monkeypatch.setattr(depaudit, "NPM_LOCAL_MAX", 5000)
    size = sum(len(text(WORKSPACES[f"packages/{x}/package.json"])) for x in "ab")
    monkeypatch.setattr(depaudit, "NPM_LOCAL_BYTES", size)
    assert depaudit.run_npm_audit(repo, False)[1]["state"] == "ok" and len(npm.runs) == 2      # twin: exactly that much
    monkeypatch.setattr(depaudit, "NPM_LOCAL_BYTES", size - 1)
    findings, info = depaudit.run_npm_audit(repo, False)
    assert len(npm.runs) == 2 and findings == [] and info["state"] == "failed"
    assert "hold more than 0 MB together, so npm was not started on it" in info["errors"][0]


BAD_PATTERNS = [["../*"], ["packages/*", "../../*"], ["{..,packages}/*"], ["{.,packages}{.,x}/*"], ["/tmp/*"],
                ["{/tmp,packages}/*"], ["{,packages}/tmp/*"], ["packages\\..\\..\\*"], ["C:/x/*"], ["!../*"],
                {"packages": ["../*"]}, "../*"]
GOOD_PATTERNS = [["packages/*"], ["{apps,packages}/*"], ["./packages/*", "!packages/private"], ["packages/**"],
                 {"packages": ["packages/*"]}, "packages/*", 5, [5, None]]


@pytest.mark.parametrize("patterns", BAD_PATTERNS, ids=[json.dumps(p) for p in BAD_PATTERNS])
def test_workspace_folders_asked_for_outside_the_project_mean_npm_is_not_started(tmp_path, monkeypatch, patterns):
    """npm reads the package.json of every folder a workspace pattern finds; a pattern with `..` finds the
    neighbours'."""
    npm = Started(monkeypatch)
    files = {**WORKSPACES, "package.json": {**WORKSPACES["package.json"], "workspaces": patterns}}
    findings, info = depaudit.run_npm_audit(project(tmp_path, files), False)
    assert npm.runs == [] and findings == [] and info["state"] == "failed"
    assert info["errors"][0].startswith("package-lock.json: its package.json asks for workspace folders outside "
                                        "its own folder (")
    assert info["errors"][0].endswith("so npm was not started on it")


@pytest.mark.parametrize("patterns", GOOD_PATTERNS, ids=[json.dumps(p) for p in GOOD_PATTERNS])
def test_ordinary_workspace_patterns_are_handed_to_npm(tmp_path, monkeypatch, patterns):
    npm = Started(monkeypatch)
    files = {**WORKSPACES, "package.json": {**WORKSPACES["package.json"], "workspaces": patterns}}
    _, info = depaudit.run_npm_audit(project(tmp_path, files), False)
    assert info["state"] == "ok" and len(npm.runs) == 1, info
    assert npm.there("package.json") == text(files["package.json"])


def test_a_package_json_of_the_project_that_asks_for_folders_outside_is_not_copied(tmp_path, monkeypatch):
    """A folder above the lock file's whose package.json names workspaces is read by npm for them too."""
    npm = Started(monkeypatch)
    files = linked("..")
    repo = project(tmp_path, {"web/package.json": files["package.json"], "web/package-lock.json": files["package-lock.json"],
                              "package.json": {"name": "top", "version": "1.0.0", "workspaces": ["../*"]}})
    findings, info = depaudit.run_npm_audit(repo, False)
    assert len(npm.runs) == 1 and npm.there("../package.json") is None
    assert info["state"] == "partial" and [f["file"] for f in findings] == ["web/package-lock.json"]
    assert info["errors"] == ['package.json: asks for workspace folders outside its own folder ("../*"), '
                              "so npm was not given it"]


@only_posix
@pytest.mark.parametrize("what", ["a link out of the project", "a pipe"])
def test_a_folders_package_json_that_is_not_a_file_of_the_project_is_not_copied(tmp_path, monkeypatch, what):
    npm = Started(monkeypatch)
    repo = project(tmp_path, {**WORKSPACES, "../next-door/package.json": NEXT_DOOR})
    (repo / "packages/a/package.json").unlink()
    if what == "a pipe":
        os.mkfifo(repo / "packages/a/package.json")
    else:
        (repo / "packages/a/package.json").symlink_to(tmp_path / "next-door" / "package.json")
    findings, info = depaudit.run_npm_audit(repo, False)
    assert len(npm.runs) == 1 and npm.there("packages/a/package.json") is None
    assert npm.there("packages/b/package.json") == text(WORKSPACES["packages/b/package.json"])
    assert text(NEXT_DOOR) not in npm.runs[0]["files"].values()
    assert info["state"] == "partial" and len(findings) == 1           # said: the audit is not the whole project's
    assert len(info["errors"]) == 1 and info["errors"][0].startswith("packages/a/package.json: ")
    assert info["errors"][0].endswith("so it was not read")


@only_posix
def test_a_shrinkwrap_file_that_is_a_link_out_of_the_project_means_npm_is_not_started(tmp_path, monkeypatch):
    """npm would take it before the lock file: without it the copy would be audited for another lock file."""
    npm = Started(monkeypatch)
    repo = project(tmp_path, {**PLAIN, "../elsewhere/npm-shrinkwrap.json": PLAIN["package-lock.json"]})
    (repo / "npm-shrinkwrap.json").symlink_to(tmp_path / "elsewhere" / "npm-shrinkwrap.json")
    findings, info = depaudit.run_npm_audit(repo, False)
    assert npm.runs == [] and findings == [] and info["state"] == "failed"
    assert info["errors"][0].startswith("package-lock.json: npm was not started on it (npm-shrinkwrap.json: ")


def test_a_shrinkwrap_file_is_copied_and_its_folders_too(tmp_path, monkeypatch):
    npm = Started(monkeypatch)
    wrap = LIBRARY["package-lock.json"]
    repo = project(tmp_path, {**PLAIN, "package.json": LIBRARY["package.json"], "npm-shrinkwrap.json": wrap,
                              "lib/package.json": LIBRARY["lib/package.json"]})
    _, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok" and npm.there("npm-shrinkwrap.json") == text(wrap)
    assert npm.there("lib/package.json") == text(LIBRARY["lib/package.json"])


def test_without_a_folder_of_its_own_npm_is_not_started(tmp_path, monkeypatch):
    npm = Started(monkeypatch)

    def no_folder():
        raise PermissionError(13, "Permission denied", "/tmp/lantern-own-x")
    monkeypatch.setattr(programs, "folder", no_folder)
    findings, info = depaudit.run_npm_audit(project(tmp_path, PLAIN), False)
    assert npm.runs == [] and findings == [] and info["state"] == "failed"
    assert info["errors"] == ["package-lock.json: a folder of Lantern's own for npm could not be made "
                              "(PermissionError), so npm was not started on it"]


def test_a_folder_of_lanterns_own_that_cannot_be_cleared_away_does_not_cost_the_audit(tmp_path, monkeypatch):
    """Windows may hold a file a moment longer than its writer (a virus scanner reading it). What npm found stands,
    and the record does not say that the folder could not be made."""
    npm = Started(monkeypatch)
    repo = project(tmp_path, PLAIN)
    (tmp_path / "temp").mkdir()
    monkeypatch.setattr(programs.tempfile, "tempdir", str(tmp_path / "temp"))   # what is left stays in the test's folder
    real, held = os.unlink, []

    def busy(path, *a, **k):
        if os.path.basename(os.fspath(path)) == "package-lock.json":
            held.append(path)
            raise OSError(16, "Device or resource busy")
        return real(path, *a, **k)
    monkeypatch.setattr(os, "unlink", busy)
    findings, info = depaudit.run_npm_audit(repo, False)
    monkeypatch.undo()
    assert held, "the folder was never cleared away: the test shows nothing"
    assert len(npm.runs) == 1 and info["state"] == "ok" and "errors" not in info, info
    assert [f["file"] for f in findings] == ["package-lock.json"]


def test_one_lock_file_refused_and_another_audited_is_a_partial_audit(tmp_path, monkeypatch):
    npm = Started(monkeypatch)
    bad = linked("/etc")
    repo = project(tmp_path, {"a/package.json": PLAIN["package.json"], "a/package-lock.json": PLAIN["package-lock.json"],
                              "b/package.json": bad["package.json"], "b/package-lock.json": bad["package-lock.json"]})
    findings, info = depaudit.run_npm_audit(repo, False)
    assert len(npm.runs) == 1 and [f["file"] for f in findings] == ["a/package-lock.json"]
    assert info["state"] == "partial" and info["files"] == ["a/package-lock.json"]
    assert info["errors"] == ['b/package-lock.json: names a folder by its full path ("/etc"), so npm was not started on it']


DEEP = "[" * 200_000 + "]" * 200_000          # valid JSON: Node reads it, Python does not follow it that deep


def deep(lock):
    """`lock` as JSON with one more part, which nobody reads and which is nested deeper than Python follows."""
    return json.dumps(lock)[:-1] + ', "x": ' + DEEP + "}"


@needs_npm
def test_a_lock_file_only_npm_can_read_does_not_lead_npm_out_of_lanterns_folder(tmp_path, registry, monkeypatch):
    """Two readers of one text can disagree: Node reads JSON nested 200,000 deep, Python does not. Handed over as
    it was, such a lock file was one Lantern had not looked into, and npm followed it out of Lantern's folder."""
    (tmp_path / "temp").mkdir()
    monkeypatch.setattr(programs.tempfile, "tempdir", str(tmp_path / "temp"))
    files = linked("../../next-door")
    repo = project(tmp_path, {"package.json": files["package.json"], "package-lock.json": deep(files["package-lock.json"]),
                              "../temp/next-door/package.json": NEXT_DOOR})
    findings, info = depaudit.run_npm_audit(repo, False)
    said = json.dumps([registry.asked, info, findings])
    assert "9.9.9" not in said and NEXT_DOOR["name"] not in said
    assert registry.asked == [] and findings == [] and info["state"] == "failed"
    assert info["errors"] == ["package-lock.json: npm was not started on it (package-lock.json: not valid JSON, "
                              "so it was not read)"]


@needs_npm
def test_a_package_json_npm_cannot_use_does_not_send_npm_to_the_lock_files_own_patterns(tmp_path, registry, monkeypatch):
    """Where npm cannot use package.json it takes the lock file's first entry in its place, workspace patterns and
    all: it then read the package.json of every folder two levels up, and its complaint about one of them (where
    that file stops being JSON) was in Lantern's record."""
    (tmp_path / "temp").mkdir()
    monkeypatch.setattr(programs.tempfile, "tempdir", str(tmp_path / "temp"))
    lock = {"name": "mono", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
        "": {"name": "mono", "version": "1.0.0", "workspaces": ["../../*"], "dependencies": {"left-pad": "^1.3.0"}},
        "node_modules/left-pad": PAD}}
    repo = project(tmp_path, {"package.json": "{not json", "package-lock.json": lock,
                              "../temp/next-door/package.json": '{"the neighbours own words'})
    findings, info = depaudit.run_npm_audit(repo, False)
    assert "EJSONPARSE" not in json.dumps(info)         # npm's complaint about the neighbour's file: it had read it
    assert "neighbours own words" not in json.dumps([registry.asked, info, findings])
    assert registry.asked == [] and findings == [] and info["state"] == "failed"
    assert info["errors"] == ["package-lock.json: npm was not started on it (package.json: not valid JSON (line 1), "
                              "so it was not read)"]


CANNOT_READ = {"cut off": "{not json", "empty": "", "nested deeper than Python follows": DEEP,
               "a number that is none": '{"lockfileVersion": NaN}', "a number too large": '{"x": 1e999}'}


@pytest.mark.parametrize("name", ["package-lock.json", "npm-shrinkwrap.json", "package.json"])
@pytest.mark.parametrize("words", list(CANNOT_READ.values()), ids=list(CANNOT_READ))
def test_a_file_lantern_cannot_read_means_npm_is_not_started(tmp_path, monkeypatch, name, words):
    """npm is handed only what Lantern has read. (Before, npm was started in the project and said what was wrong.)"""
    npm = Started(monkeypatch)
    findings, info = depaudit.run_npm_audit(project(tmp_path, {**PLAIN, name: words}), False)
    assert npm.runs == [] and findings == [] and info["state"] == "failed"
    (line,) = info["errors"]
    assert line.startswith(f"package-lock.json: npm was not started on it ({name}: not valid JSON") and \
        line.endswith(", so it was not read)"), line


@pytest.mark.parametrize("lock", ["[]", '{"packages": 5, "dependencies": [1]}', '{"packages": {"x": 5}}', "null", '"text"'])
def test_a_lock_file_of_another_shape_is_handed_to_npm(tmp_path, monkeypatch, lock):
    """Twin: it is JSON and names no folder; npm says what is wrong with it, as before."""
    npm = Started(monkeypatch)
    depaudit.run_npm_audit(project(tmp_path, {"package.json": "{}", "package-lock.json": lock}), False)
    assert len(npm.runs) == 1 and npm.there("package-lock.json") == lock and npm.there("package.json") == "{}"


def test_npm_is_handed_what_lantern_read_written_out_anew(tmp_path, monkeypatch):
    """Never a file's own text: where a name stands twice, a mark stands first or a letter is written as an escape,
    npm and Lantern might each read their own. Here the first `packages` leads two folders up and the second,
    which counts for both, does not; npm is not shown the first at all."""
    npm = Started(monkeypatch)
    packages = PLAIN["package-lock.json"]["packages"]
    twice = '﻿{"packages": {"../../x": {}},\n\n  "pack\\u0061ges": ' + json.dumps(packages) + ', "lockfileVersion": 3}'
    repo = project(tmp_path, {"package.json": "  " + text(APP) + "\n", "package-lock.json": twice})
    findings, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok" and [f["file"] for f in findings] == ["package-lock.json"], info
    assert npm.there("package-lock.json") == text({"packages": packages, "lockfileVersion": 3})
    assert npm.there("package.json") == text(APP)
    assert npm.runs[0]["cwd"] == npm.runs[0]["own"] / "project"


def test_a_folders_package_json_lantern_cannot_read_is_not_copied(tmp_path, monkeypatch):
    npm = Started(monkeypatch)
    repo = project(tmp_path, {**WORKSPACES, "packages/a/package.json": DEEP})
    findings, info = depaudit.run_npm_audit(repo, False)
    assert len(npm.runs) == 1 and npm.there("packages/a/package.json") is None
    assert npm.there("packages/b/package.json") == text(WORKSPACES["packages/b/package.json"])
    assert info["state"] == "partial" and info["errors"] == ["packages/a/package.json: not valid JSON, so it was not read"]


@pytest.mark.parametrize("name", ["package-lock.json", "npm-shrinkwrap.json"])
def test_a_lock_file_whose_own_first_entry_asks_for_folders_outside_means_npm_is_not_started(tmp_path, monkeypatch, name):
    """That entry is what npm takes for the package.json when it cannot use that file."""
    npm = Started(monkeypatch)
    lock = json.loads(text(PLAIN["package-lock.json"]))
    lock["packages"][""]["workspaces"] = ["packages/*", "../*"]
    findings, info = depaudit.run_npm_audit(project(tmp_path, {**PLAIN, name: lock}), False)
    assert npm.runs == [] and findings == [] and info["state"] == "failed"
    who = "" if name == "package-lock.json" else "its npm-shrinkwrap.json "
    assert info["errors"] == [f'package-lock.json: {who}asks for workspace folders outside its own folder ("../*"), '
                              "so npm was not started on it"]


@pytest.mark.parametrize("mark", [True, 1, 1.5, "yes", "", [], {}], ids=repr)
def test_a_link_is_counted_however_it_is_marked(tmp_path, monkeypatch, mark):
    """npm takes anything but false, 0, "" and nothing for the mark of a link: with 1, "yes" and [] it read the
    folder beside the project (measured). So the copy lies as deep as such an entry climbs."""
    npm = Started(monkeypatch)
    lock = {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
        "": APP, "node_modules/next-door": {"resolved": "../../next-door", "link": mark}, "node_modules/left-pad": PAD}}
    depaudit.run_npm_audit(project(tmp_path, {"package.json": APP, "package-lock.json": lock}), False)
    (run,) = npm.runs
    assert run["cwd"] == run["own"] / "above" / "above" / "project"
    assert npm.there("../../next-door/package.json") is None


@pytest.mark.parametrize("mark", [False, None, 0])
def test_the_twin_what_is_no_link_is_not_read_as_a_folder(tmp_path, monkeypatch, mark):
    """An ordinary entry's `resolved` is an address, with `%` and all, and refuses nothing."""
    npm = Started(monkeypatch)
    lock = {"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
        "": APP, "node_modules/@scope/name": {"version": "1.0.0", "link": mark,
                                              "resolved": "https://registry.npmjs.org/@scope%2fname/-/../name-1.0.0.tgz"},
        "node_modules/left-pad": PAD}}
    _, info = depaudit.run_npm_audit(project(tmp_path, {"package.json": APP, "package-lock.json": lock}), False)
    (run,) = npm.runs
    assert info["state"] == "ok" and run["cwd"] == run["own"] / "project"


def test_a_link_written_like_an_address_is_counted_all_the_same(tmp_path, monkeypatch):
    """npm joins a link's `resolved` to its folder as a path whatever it looks like: `https://x/../../../next-door`
    is the folder beside the project (measured)."""
    npm = Started(monkeypatch)
    place = "https://x/../../../next-door"
    depaudit.run_npm_audit(project(tmp_path, linked(place)), False)
    (run,) = npm.runs
    assert run["cwd"] == run["own"] / "above" / "above" / "above" / "project"
    assert npm.there(place + "/package.json") is None


def test_a_place_that_leaves_the_project_and_comes_back_by_a_name_is_no_folder_of_it(tmp_path, monkeypatch):
    """`../packages/a` is a folder beside the project, not the project's own `packages/a`."""
    npm = Started(monkeypatch)
    repo = project(tmp_path, {**linked("../packages/a"), "packages/a/package.json": {"name": "a", "version": "1.0.0"}})
    depaudit.run_npm_audit(repo, False)
    (run,) = npm.runs
    assert sorted(run["files"]) == ["above/project/package-lock.json", "above/project/package.json"]


def test_a_lock_file_two_folders_down_names_the_folder_beside_its_own(tmp_path, monkeypatch):
    """Twin: `..` is one folder up from the lock file's own, `apps/shared` and not the project's `shared`."""
    npm = Started(monkeypatch)
    files = linked("../shared")
    shared = {"name": "shared", "version": "4.0.0"}
    repo = project(tmp_path, {"apps/web/package.json": files["package.json"],
                              "apps/web/package-lock.json": files["package-lock.json"],
                              "apps/shared/package.json": shared, "shared/package.json": {"name": "another", "version": "0.0.1"}})
    depaudit.run_npm_audit(repo, False)
    (run,) = npm.runs
    assert npm.there("../shared/package.json") == text(shared)
    assert sorted(run["files"]) == ["above/project/apps/shared/package.json", "above/project/apps/web/package-lock.json",
                                    "above/project/apps/web/package.json"]


def test_a_lock_file_in_a_folder_may_name_the_project_itself(tmp_path, monkeypatch):
    """Twin: `web/` keeps the project's top folder as a library. Its package.json is copied to where it lies, a
    folder of the copy that is there already."""
    npm = Started(monkeypatch)
    files = linked("..")
    top = {"name": "top", "version": "5.0.0"}
    repo = project(tmp_path, {"package.json": top, "web/package.json": files["package.json"],
                              "web/package-lock.json": files["package-lock.json"]})
    findings, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok" and [f["file"] for f in findings] == ["web/package-lock.json"], info
    assert npm.there("../package.json") == text(top)


@pytest.mark.parametrize("version", ["file:libs/x", "FILE:libs/x", "file:./libs/x", "./libs/x", ".\\libs\\x"])
def test_a_folder_of_the_project_an_older_lock_file_names_is_copied(tmp_path, monkeypatch, version):
    """npm reads the package.json of a folder an older lock file names, written `file:…` or as a bare path (measured:
    `../next-door` without `file:` put the neighbour's version into the question)."""
    npm = Started(monkeypatch)
    lib = {"name": "x", "version": "3.0.0"}
    repo = project(tmp_path, {**older(version), "libs/x/package.json": lib})
    _, info = depaudit.run_npm_audit(repo, False)
    assert info["state"] == "ok" and npm.there("libs/x/package.json") == text(lib), info


@pytest.mark.skipif(os.name == "nt", reason="a path this long needs a setting of its own on Windows")
@pytest.mark.parametrize("case", ["a place refused", "a file not read", "a folder left out"])
def test_what_the_record_says_of_a_file_with_a_long_path_keeps_the_reason(tmp_path, monkeypatch, case):
    """Of a long path the end is kept (the file's own name), so the reason is not what gets cut off."""
    npm = Started(monkeypatch)
    at = "/".join(f"a-folder-with-a-rather-long-name-{i}-{'x' * 20}" for i in range(6))
    files = {**linked("/etc"), "lib/package.json": {"name": "lib", "version": "1.0.0"}} if case == "a place refused" else \
        {**PLAIN, "package-lock.json": "{not json"} if case == "a file not read" else \
        {**linked("lib"), "lib/package.json": {"name": "lib", "version": "1.0.0", "workspaces": ["../*"]}}
    repo = project(tmp_path, {f"{at}/{name}": what for name, what in files.items()})
    _, info = depaudit.run_npm_audit(repo, False)
    (line,) = info["errors"]
    assert len(at) > 300 and len(line) < 300 and line.startswith("...") and line.isascii() and line.isprintable()
    assert line.endswith({"a place refused": '(\"/etc\"), so npm was not started on it',
                          "a file not read": "(package-lock.json: not valid JSON (line 1), so it was not read)",
                          "a folder left out": '(\"../*\"), so npm was not given it'}[case]), line
    assert len(npm.runs) == (1 if case == "a folder left out" else 0)


def test_the_folder_of_lanterns_own_is_new_empty_and_closed_to_others(tmp_path):
    with programs.folder() as own:
        assert own.is_dir() and list(own.iterdir()) == [] and own.name.startswith("lantern-own-")
        assert tmp_path not in own.parents
        if os.name == "posix":
            assert own.stat().st_mode & 0o077 == 0
        (own / "deep" / "er").mkdir(parents=True)
        (own / "deep" / "er" / "file").write_text("x", encoding="utf-8")
    assert not own.exists()
