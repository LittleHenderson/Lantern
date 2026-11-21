"""The test machine's image, started and asked the way the website will ask it (a firm pass or fail, stage 3, step 4).

    docker build -f cloud/runner/Dockerfile -t lantern-runner .
    python tools/runner_image.py lantern-runner [--host-network] [--pytest FOLDER]

Each case starts a machine of its own from the image (a container started as root and privileged, the way the
hosting company starts a machine), with the fingerprint of a key made for that one case. Its door is asked with no
key, with a wrong key and with the key of another check, and each must be refused; then the case's archive is handed
in, the check is followed to its end, the machine is ended and must stop with 0. The cases: tests that pass, as an
ordinary user; tests that fail; tests that try to reach the door and to read what the program holds, each of which
passes only where it was refused, beside a server of their own that answers; JavaScript tests run by npm; tests on a
library handed in with the project, and the same tests without it; an archive that is no check, which runs nothing;
and with `--pytest FOLDER` (a folder made by `pip install --target`), pytest from that folder. Exit 0 only when
every case held. `--host-network` gives each machine this computer's network (for a container program with no
network of its own for containers); without it each machine has a network of its own and its door is published on
127.0.0.1 alone.

Lantern's own code is imported from this checkout (`lantern.runner` packs the archives); nothing is installed.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import secrets
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lantern import runner  # noqa: E402

END = ("done", "refused", "unable", "stopped")
PORT = 8080          # the door's port inside the machine (cloud/runner/Dockerfile's CMD)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Machine:
    """One machine of the image, with a key of its own."""

    def __init__(self, image: str, docker: str, host_network: bool):
        self.docker, self.key = docker, secrets.token_urlsafe(32)
        digest = hashlib.sha256(self.key.encode("ascii")).hexdigest()
        cmd = [docker, "run", "-d", "--privileged", "-e", f"{runner.KEY_VARIABLE}={digest}"]
        if host_network:
            self.port = self.inside = _free_port()
            cmd += ["--network", "host", image, "python", "-I", "-m", "lantern.runner", "serve",
                    "--host", "127.0.0.1", "--port", str(self.port)]
        else:
            self.inside = PORT
            cmd += ["-p", f"127.0.0.1::{PORT}", image]
        self.id = subprocess.run(cmd, check=True, capture_output=True, text=True, encoding="utf-8").stdout.strip()
        if not host_network:
            said = subprocess.run([docker, "port", self.id, f"{PORT}/tcp"], check=True, capture_output=True,
                                  text=True, encoding="utf-8").stdout
            self.port = int(said.strip().splitlines()[0].rsplit(":", 1)[1])
        deadline = time.monotonic() + 90
        while True:
            try:
                if self.ask("GET", "/v1/check")[0] == 200:
                    return
            except (OSError, http.client.HTTPException):
                pass
            if time.monotonic() > deadline:
                raise RuntimeError("the machine's door did not open in 90 seconds")
            time.sleep(0.5)

    def ask(self, method: str, path: str, body: bytes | None = None, key: str | None = "") -> tuple[int, dict | None]:
        """`key` "" is the machine's own, None sends none."""
        headers = {} if key is None else {"Authorization": "Bearer " + (key or self.key)}
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            c.request(method, path, body=body, headers=headers)
            r = c.getresponse()
            data = r.read()
        finally:
            c.close()
        try:
            return r.status, json.loads(data) if data else None
        except ValueError:
            return r.status, None

    def follow(self, seconds: float) -> dict:
        deadline = time.monotonic() + seconds
        while True:
            status, said = self.ask("GET", "/v1/check")
            if status == 200 and said and said.get("state") in END:
                return said
            if time.monotonic() > deadline:
                raise RuntimeError(f"the check did not end in {seconds:.0f} seconds (last: {said and said.get('state')})")
            time.sleep(1)

    def end(self) -> int:
        """Ends the machine through its door; the machine's own exit code."""
        status = self.ask("POST", "/v1/end")[0]
        if status != 202:
            raise RuntimeError(f"the door answered {status} to the end")
        done = subprocess.run([self.docker, "wait", self.id], capture_output=True, text=True, encoding="utf-8",
                              timeout=90)
        return int(done.stdout.strip() or "-1")

    def logs(self) -> str:
        done = subprocess.run([self.docker, "logs", self.id], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=60)
        return (done.stdout + done.stderr)[-4000:]

    def remove(self) -> None:
        subprocess.run([self.docker, "rm", "-f", self.id], capture_output=True, timeout=90)


# ---------------------------------------------------------------------------- the cases
def _python(folder: Path, name: str, tests: str) -> Path:
    project = folder / name
    project.mkdir()
    (project / "test_it.py").write_text(textwrap.dedent(tests), encoding="utf-8")
    return project


def _check(cond: bool, what: str, broken: list[str]) -> None:
    if not cond:
        broken.append(what)


def _ran(said: dict, broken: list[str], returncode: int) -> dict:
    _check(said["state"] == "done", f"the check ended {said['state']}, not done", broken)
    result = said.get("result") or {}
    tests = result.get("tests") or {}
    _check(tests.get("returncode") == returncode, f"the tests ended {tests.get('returncode')}, not {returncode}", broken)
    _check(all(w.get("stands") for w in (result.get("runner") or {}).get("walls", [])) and
           len((result.get("runner") or {}).get("walls", [])) == 4, "a wall of the four did not stand", broken)
    _check(tests.get("backend") == "subprocess", "the tests did not run in Lantern's sandbox", broken)
    _check(tests.get("own_network") is True and tests.get("off_network") is True,
           "the tests did not run in a network of their own", broken)
    return tests


def passes(folder: Path, m: Machine):
    project = _python(folder, "passes", """
        import os, unittest
        class T(unittest.TestCase):
            def test_an_ordinary_user(self):
                self.assertEqual(os.geteuid(), 65534)
            def test_it_works(self):
                self.assertEqual(1 + 2, 3)
    """)
    out = folder / "passes.zip"
    runner.pack(project, out, ["python", "-m", "unittest", "-v"], minutes=2, memory=512)

    def judge(said, broken):
        tests = _ran(said, broken, 0)
        _check("test_an_ordinary_user" in tests.get("output_tail", ""), "the tests' output names no test", broken)
    return out, judge


def fails(folder: Path, m: Machine):
    project = _python(folder, "fails", """
        import unittest
        class T(unittest.TestCase):
            def test_it_fails(self):
                self.assertEqual(1, 2)
    """)
    out = folder / "fails.zip"
    runner.pack(project, out, ["python", "-m", "unittest", "-v"], minutes=2, memory=512)
    return out, lambda said, broken: _ran(said, broken, 1)


HOSTILE = ("test_the_door_on_the_machines_own_address", "test_every_address_of_the_machine",
           "test_the_programs_settings", "test_the_programs_open_files", "test_the_programs_folder",
           "test_its_own_settings_it_may_read", "test_a_server_of_its_own_answers")


def hostile(folder: Path, m: Machine):
    project = _python(folder, "hostile", f"""
        import os, socket, threading, unittest, http.server
        PORT = {m.inside}
        class Door(unittest.TestCase):
            def test_the_door_on_the_machines_own_address(self):
                with self.assertRaises(OSError):
                    socket.create_connection(("127.0.0.1", PORT), timeout=5)
            def test_every_address_of_the_machine(self):
                try:
                    found = socket.getaddrinfo(socket.gethostname(), PORT, type=socket.SOCK_STREAM)
                except OSError:
                    found = []
                for name in sorted({{a[4][0] for a in found}} | {{"127.0.0.1", "::1"}}):
                    with self.assertRaises(OSError):
                        socket.create_connection((name, PORT), timeout=5)
            def test_the_programs_settings(self):
                with self.assertRaises(OSError):
                    open("/proc/1/environ", "rb").read()
            def test_the_programs_open_files(self):
                with self.assertRaises(OSError):
                    os.listdir("/proc/1/fd")
            def test_the_programs_folder(self):
                try:
                    names = [n for n in os.listdir("/tmp") if n.startswith("lantern-runner-")]
                except OSError:
                    names = []
                for n in names:
                    with self.assertRaises(OSError):
                        os.listdir("/tmp/" + n)
            def test_its_own_settings_it_may_read(self):
                self.assertTrue(open("/proc/self/environ", "rb").read())
            def test_a_server_of_its_own_answers(self):
                class H(http.server.BaseHTTPRequestHandler):
                    def do_GET(self):
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b"mine")
                    def log_message(self, *a):
                        pass
                s = http.server.HTTPServer(("127.0.0.1", 0), H)
                threading.Thread(target=s.serve_forever, daemon=True).start()
                c = socket.create_connection(("127.0.0.1", s.server_address[1]), timeout=5)
                c.sendall(b"GET / HTTP/1.0\\r\\n\\r\\n")
                got = b""
                while True:             # the answer may come in more than one piece; the server closes after it
                    piece = c.recv(4096)
                    if not piece:
                        break
                    got += piece
                self.assertIn(b"mine", got)
                c.close()
                s.shutdown()
    """)
    out = folder / "hostile.zip"
    runner.pack(project, out, ["python", "-m", "unittest", "-v"], minutes=2, memory=512)

    def judge(said, broken):
        tests = _ran(said, broken, 0)
        tail = tests.get("output_tail", "")
        for name in HOSTILE:
            _check(f"{name} (test_it." in tail, f"{name} did not run", broken)
        _check(f"Ran {len(HOSTILE)} tests" in tail and "\nOK" in tail, "not every one of those tests passed", broken)
    return out, judge


def javascript(folder: Path, m: Machine):
    project = folder / "javascript"
    (project / "test").mkdir(parents=True)
    (project / "package.json").write_text(json.dumps({"name": "js-check", "version": "1.0.0", "private": True,
                                                      "scripts": {"test": "node --test"}}, indent=1),
                                          encoding="utf-8")
    (project / "test" / "add.test.js").write_text(textwrap.dedent("""
        const test = require("node:test");
        const assert = require("node:assert");
        test("adds", () => { assert.strictEqual(1 + 2, 3); });
        test("an ordinary user", () => { assert.strictEqual(process.geteuid(), 65534); });
    """), encoding="utf-8")
    out = folder / "javascript.zip"
    runner.pack(project, out, ["npm", "test"], minutes=3, memory=1024)

    def judge(said, broken):
        tests = _ran(said, broken, 0)
        _check("pass 2" in tests.get("output_tail", ""), "node's test runner did not say both tests passed", broken)
    return out, judge


LIBRARY_TESTS = """
    import unittest
    class T(unittest.TestCase):
        def test_the_library(self):
            import hello_lib
            self.assertEqual(hello_lib.WORD, "hello")
"""


def library(folder: Path, m: Machine):
    project = _python(folder, "library", LIBRARY_TESTS)
    libs = folder / "library-libs"
    (libs / "hello_lib").mkdir(parents=True)
    (libs / "hello_lib" / "__init__.py").write_text('WORD = "hello"\n', encoding="utf-8")
    record = {"state": "fetched", "language": "python", "store": "pypi.org", "added": [],
              "packages": [{"name": "hello-lib", "version": "1.0", "fingerprint": "sha256:" + "1" * 64,
                            "file": "hello_lib-1.0-py3-none-any.whl", "asked": True, "exact": True, "checked": True}]}
    out = folder / "library.zip"
    runner.pack(project, out, ["python", "-m", "unittest", "-v"], minutes=2, memory=512, libraries=libs, record=record)

    def judge(said, broken):
        tests = _ran(said, broken, 0)
        _check(tests.get("libraries") == record, "the result's record of the libraries is not the one handed in", broken)
    return out, judge


def no_library(folder: Path, m: Machine):
    """The twin: the same tests without the library fail, and nothing of the machine stands in for it."""
    project = _python(folder, "no-library", LIBRARY_TESTS)
    out = folder / "no-library.zip"
    runner.pack(project, out, ["python", "-m", "unittest", "-v"], minutes=2, memory=512)

    def judge(said, broken):
        tests = _ran(said, broken, 1)
        _check("hello_lib" in tests.get("output_tail", ""), "the failure does not name the missing library", broken)
    return out, judge


def not_a_check(folder: Path, m: Machine):
    out = folder / "not-a-check.zip"
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("check.json", json.dumps({"version": 1, "command": ["python", "-m", "unittest"], "minutes": 2,
                                             "memory": 512, "libraries": {"state": "none", "language": "python"}}))
        z.writestr("project/../outside.py", "print('never')\n")

    def judge(said, broken):
        _check(said["state"] == "refused", f"the check ended {said['state']}, not refused", broken)
        result = said.get("result") or {}
        _check("tests" not in result, "something was run", broken)
        _check("outside its folder" in (result.get("why_not") or ""), "the reason does not say why", broken)
    return out, judge


def pytest_from(libs: Path):
    """pytest from a folder `pip install --target` made: each library's row read from its own record there."""
    rows = []
    for meta in sorted(libs.glob("*.dist-info/METADATA")):
        head = meta.read_text(encoding="utf-8", errors="replace").split("\n\n", 1)[0]
        said = dict(line.split(": ", 1) for line in head.splitlines() if ": " in line)
        rows.append({"name": said["Name"], "version": said["Version"], "fingerprint": "sha256:" + "0" * 64,
                     "file": f"{said['Name'].replace('-', '_')}-{said['Version']}-py3-none-any.whl",
                     "asked": said["Name"].lower() == "pytest", "exact": True, "checked": False})
    if not any(r["name"].lower() == "pytest" for r in rows):
        raise SystemExit(f"{libs} holds no pytest")

    def case(folder: Path, m: Machine):
        project = _python(folder, "pytest", """
            from app import add
            def test_add():
                assert add(1, 2) == 3
        """)
        (project / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        record = {"state": "fetched", "language": "python", "store": "pypi.org", "added": ["pytest"], "packages": rows}
        out = folder / "pytest.zip"
        runner.pack(project, out, ["python", "-m", "pytest", "-q"], minutes=3, memory=1024, libraries=libs,
                    record=record)

        def judge(said, broken):
            tests = _ran(said, broken, 0)
            _check("1 passed" in tests.get("output_tail", ""), "pytest did not say the test passed", broken)
            files = {row[side][0] for row in tests.get("pairs", []) for side in ("caller", "callee")}
            _check({"app.py", "test_it.py"} <= files, "the calls the tests made were not recorded", broken)
        return out, judge
    case.__name__ = "pytest"
    return case


def _doors(m: Machine, broken: list[str]) -> None:
    """Asked with no key, a wrong key and another check's key, the door says nothing but "not allowed"."""
    other = secrets.token_urlsafe(32)
    for what, key in (("no key", None), ("a wrong key", "x" * 43), ("another check's key", other)):
        status, said = m.ask("GET", "/v1/check", key=key)
        _check(status == 401 and said == {"error": "not allowed"}, f"asked with {what}, the door answered {status}",
               broken)
        status, _ = m.ask("PUT", "/v1/check", body=b"PK", key=key)
        _check(status == 401, f"handed an archive with {what}, the door answered {status}", broken)


def run_case(case, image: str, docker: str, host_network: bool) -> list[str]:
    broken: list[str] = []
    with tempfile.TemporaryDirectory(prefix="lantern-runner-image-") as tmp:
        m = Machine(image, docker, host_network)
        try:
            out, judge = case(Path(tmp), m)
            _doors(m, broken)
            status, _ = m.ask("PUT", "/v1/check", out.read_bytes())
            _check(status == 202, f"the archive was answered {status}, not 202", broken)
            if status == 202:
                said = m.follow(420)
                judge(said, broken)
                if broken:
                    result = said.get("result") or {}
                    print(f"  state {said.get('state')}; {result.get('why_not') or ''}".rstrip("; "))
                    print("  " + ((result.get("tests") or {}).get("output_tail") or "")[-3000:].replace("\n", "\n  "))
            code = m.end()
            _check(code == 0, f"the machine stopped with {code}, not 0", broken)
        except Exception as e:      # the case broke; say how, and go on with the next one
            broken.append(f"{type(e).__name__}: {e}")
        if broken:
            print("  the machine said:\n  " + m.logs().replace("\n", "\n  "))
        m.remove()
    return broken


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("image")
    ap.add_argument("--docker", default="docker")
    ap.add_argument("--host-network", action="store_true")
    ap.add_argument("--pytest", type=Path, help="a folder made by `pip install --target FOLDER pytest`")
    ap.add_argument("--only", default="", help="names of cases, with commas")
    a = ap.parse_args(argv)
    cases = [passes, fails, hostile, javascript, library, no_library, not_a_check]
    if a.pytest:
        cases.append(pytest_from(a.pytest))
    if a.only:
        cases = [c for c in cases if c.__name__ in a.only.split(",")]
    held = 0
    for case in cases:
        began = time.monotonic()
        broken = run_case(case, a.image, a.docker, a.host_network)
        took = time.monotonic() - began
        if broken:
            print(f"BROKEN {case.__name__} ({took:.0f} s): " + "; ".join(broken), flush=True)
        else:
            held += 1
            print(f"held   {case.__name__} ({took:.0f} s)", flush=True)
    print(f"{held} of {len(cases)} cases held")
    return 0 if held == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
