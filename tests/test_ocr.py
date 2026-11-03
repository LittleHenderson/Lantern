"""Ask Lantern screenshots: read on this computer (Pillow + the Tesseract program), never stored or uploaded."""
import io
import shutil
import uuid

import pytest

PIL = pytest.importorskip("PIL", reason="Pillow is part of the dev extras")
from PIL import Image, ImageDraw, ImageFont  # noqa: E402

from lantern import ask  # noqa: E402

from test_server import srv  # noqa: F401,E402  (fixture)

KNOWN = "LANTERN 4821 READS"


def _png(text=KNOWN, fmt="PNG", size=(900, 160)) -> bytes:
    img = Image.new("RGB", size, "white")
    d = ImageDraw.Draw(img)
    d.text((30, 40), text, fill="black", font=ImageFont.load_default(size=56))
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


def _post(base, data: bytes, name="shot.png", ctype="image/png", token="tok-123"):
    import json
    import urllib.error
    import urllib.request
    b = "----lantern" + uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
            f"Content-Type: {ctype}\r\n\r\n").encode() + data + f"\r\n--{b}--\r\n".encode()
    req = urllib.request.Request(base + "/api/ask/screenshot", data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={b}")
    req.add_header("Cookie", "lantern_token=tok-123")
    if token:
        req.add_header("X-Lantern-Token", token)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.mark.skipif(not shutil.which("tesseract"), reason="the Tesseract program is not installed (CI installs it on Linux)")
def test_known_text_is_read(srv):  # noqa: F811
    base, _ = srv
    code, j = _post(base, _png())
    assert code == 200, j
    assert j["format"] == "PNG" and j["width"] == 900 and j["lines"] >= 1
    assert "4821" in j["text"] and "LANTERN" in j["text"].upper()
    for fmt, ctype in (("JPEG", "image/jpeg"), ("WEBP", "image/webp")):
        code, j = _post(base, _png(fmt=fmt), name="s." + fmt.lower(), ctype=ctype)
        assert code == 200 and j["format"] == fmt and "4821" in j["text"], j


def test_without_tesseract_says_how_to_install(srv, monkeypatch):  # noqa: F811
    base, _ = srv
    monkeypatch.setattr(ask.shutil, "which", lambda name, *a, **k: None)
    code, j = _post(base, _png())
    assert code == 200
    assert j["text"] is None and j["reason"] == "tesseract not installed" and j["how"] == ask.tesseract_how()
    assert any(w in j["how"] for w in ("apt", "brew", "winget"))


def test_oversize_and_wrong_types_are_refused(srv):  # noqa: F811
    base, _ = srv
    big = _png() + b"\0" * (8 * 1024 * 1024)
    code, j = _post(base, big)
    assert code == 400 and "8 MB" in j["error"]
    code, j = _post(base, _png(fmt="GIF"), name="x.gif", ctype="image/gif")
    assert code == 400 and "PNG, JPEG or WebP" in j["error"]
    code, j = _post(base, b"not an image at all")
    assert code == 400
    code, j = _post(base, _png(), token=None)
    assert code == 403


def test_image_goes_to_tesseract_through_a_pipe_not_a_file(monkeypatch, tmp_path):
    seen = {}

    class R:
        returncode, stdout, stderr = 0, b"hello\n", b""

    def fake_run(cmd, input=None, **kw):
        seen["cmd"], seen["input"] = cmd, input
        return R()
    monkeypatch.setattr(ask.shutil, "which", lambda name, *a, **k: "/usr/bin/tesseract")
    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("tempfile.tempdir", str(tmp_path))
    assert ask.ocr_image(Image.open(io.BytesIO(_png()))) == "hello\n"
    assert seen["cmd"][1:] == ["stdin", "stdout"] and seen["input"][:4] == b"\x89PNG"
    assert list(tmp_path.iterdir()) == []
