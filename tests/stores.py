"""Stand-in library stores on this computer, for the tests of fetched libraries (`tests/test_libraries.py`).

No test reaches PyPI or the npm registry. `PyStore` answers the way PyPI's simple index does and `NpmStore` the way
the npm registry does, each on 127.0.0.1 with wheels and packages made here from a few lines of text. Each keeps
every path it was asked for (`seen`), so a test can say what was fetched and what was never asked."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import tarfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def wheel(name: str, version: str, files: dict[str, str], requires: tuple[str, ...] = (),
          tag: str = "py3-none-any") -> tuple[str, bytes]:
    """(file name, bytes) of a wheel holding `files` (path -> text), for any Python and any system; `tag` says
    another Python or system, as a store writes it (`py3-none-macosx_11_0_arm64`)."""
    dist = re.sub(r"[-.]+", "_", name)
    info = f"{dist}-{version}.dist-info"
    meta = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n" + "".join(f"Requires-Dist: {r}\n" for r in requires)
    parts = {**files, f"{info}/METADATA": meta,
             f"{info}/WHEEL": f"Wheel-Version: 1.0\nGenerator: lantern-tests\nRoot-Is-Purelib: true\nTag: {tag}\n"}
    record = []
    for path, text in parts.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(text.encode()).digest()).rstrip(b"=").decode()
        record.append(f"{path},sha256={digest},{len(text.encode())}")
    parts[f"{info}/RECORD"] = "\n".join(record + [f"{info}/RECORD,,"]) + "\n"
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for path, text in parts.items():
            z.writestr(zipfile.ZipInfo(path, (2026, 1, 1, 0, 0, 0)), text)
    return f"{dist}-{version}-{tag}.whl", out.getvalue()


def sdist(name: str, version: str, files: dict[str, str]) -> tuple[str, bytes]:
    """(file name, bytes) of a source package: a library that has to be built, by running code it brings."""
    top = f"{name}-{version}"
    parts = {"PKG-INFO": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", **files}
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as t:
        for path, text in parts.items():
            data = text.encode()
            item = tarfile.TarInfo(f"{top}/{path}")
            item.size, item.mode = len(data), 0o644
            t.addfile(item, io.BytesIO(data))
    return f"{top}.tar.gz", out.getvalue()


def package(name: str, version: str, files: dict[str, str], more: dict | None = None) -> tuple[str, bytes, dict]:
    """(file name, bytes, its package.json) of an npm package holding `files`; `more` goes into its package.json
    (`scripts`, `dependencies`)."""
    manifest = {"name": name, "version": version, "main": "index.js", **(more or {})}
    parts = {"package.json": json.dumps(manifest), **files}
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as t:
        for path, text in parts.items():
            data = text.encode()
            item = tarfile.TarInfo(f"package/{path}")
            item.size, item.mode = len(data), 0o644
            t.addfile(item, io.BytesIO(data))
    return f"{name.rsplit('/', 1)[-1]}-{version}.tgz", out.getvalue(), manifest


class _Store:
    """A server on 127.0.0.1 that answers from a table of paths and writes down every path it is asked for."""

    def __init__(self):
        self.pages: dict[str, tuple[str, bytes]] = {}
        self.seen: list[str] = []
        store = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):   # noqa: N802 - the name the standard library calls
                path = self.path.split("?", 1)[0].split("#", 1)[0]
                store.seen.append(path)
                kind, body = store.answer(path) or ("", b"")
                self.send_response(200 if kind else 404)
                self.send_header("Content-Type", kind or "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):  # noqa: N802 - npm's advisory questions and the like: nothing to say
                store.seen.append("POST " + self.path)
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.host = f"127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def answer(self, path: str):
        return self.pages.get(path)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class PyStore(_Store):
    """PyPI's simple index: `/simple/<name>/` lists a library's files, each with its SHA-256."""

    def __init__(self):
        super().__init__()
        self.url = f"http://{self.host}/simple/"
        self.files: dict[str, list[tuple[str, str]]] = {}
        self.sha256: dict[str, str] = {}

    def add(self, name: str, version: str, files: dict[str, str], requires: tuple[str, ...] = (), source=False,
            tag: str = "py3-none-any") -> str:
        """Put a library in the store; returns the SHA-256 of the file a fetch would get. One version may be added
        more than once: as source, and ready-built for one system and another (`tag`)."""
        fname, data = sdist(name, version, files) if source else wheel(name, version, files, requires, tag)
        digest = hashlib.sha256(data).hexdigest()
        self.pages[f"/files/{fname}"] = ("application/octet-stream", data)
        self.files.setdefault(_norm(name), []).append((fname, digest))
        self.sha256[fname] = digest
        return digest

    def answer(self, path: str):
        m = re.fullmatch(r"/simple/([^/]+)/?", path)
        if m and _norm(m.group(1)) in self.files:
            links = "".join(f'<a href="/files/{f}#sha256={d}">{f}</a>\n' for f, d in self.files[_norm(m.group(1))])
            return "text/html", f"<!DOCTYPE html><html><body>{links}</body></html>".encode()
        return self.pages.get(path)


class NpmStore(_Store):
    """The npm registry: `/<name>` says which versions there are, `/<name>/-/<file>.tgz` is one of them."""

    def __init__(self):
        super().__init__()
        self.url = f"http://{self.host}/"
        self.docs: dict[str, dict] = {}

    def add(self, name: str, version: str, files: dict[str, str], more: dict | None = None) -> dict:
        """Put a package in the store; returns what a lock file says of it (`version`, `resolved`, `integrity`),
        with the address the real registry would have."""
        fname, data, manifest = package(name, version, files, more)
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
        self.pages[f"/{name}/-/{fname}"] = ("application/octet-stream", data)
        doc = self.docs.setdefault(name, {"name": name, "dist-tags": {}, "versions": {}})
        doc["dist-tags"]["latest"] = version
        doc["versions"][version] = {**manifest, "dist": {"tarball": f"{self.url}{name}/-/{fname}", "integrity": integrity,
                                                         "shasum": hashlib.sha1(data, usedforsecurity=False).hexdigest()}}
        entry = {"version": version, "resolved": f"https://registry.npmjs.org/{name}/-/{fname}", "integrity": integrity}
        if (more or {}).get("scripts"):
            entry["hasInstallScript"] = True
        return entry

    def answer(self, path: str):
        name = path.lstrip("/").replace("%2f", "/").replace("%2F", "/")
        if name in self.docs:
            return "application/json", json.dumps(self.docs[name]).encode()
        return self.pages.get(path)
