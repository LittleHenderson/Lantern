"""lantern.archive: an uploaded .zip is unpacked only when every entry is safe, and never past the size cap."""

import stat
import zipfile

import pytest

from lantern import archive


def make_zip(path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for e in entries:
            if isinstance(e, zipfile.ZipInfo):
                z.writestr(e, b"target")
            else:
                name, data = e
                z.writestr(name, data)
    return path


def test_a_zipped_folder_is_unwrapped(tmp_path):
    src = make_zip(tmp_path / "a.zip", [("myapp/app.py", "print(1)\n"), ("myapp/web/index.js", "x()\n"), ("myapp/", "")])
    n = archive.unpack(src, tmp_path / "out", 1 << 20)
    assert n == 2
    assert (tmp_path / "out" / "app.py").read_text() == "print(1)\n" and (tmp_path / "out" / "web" / "index.js").is_file()


def test_files_at_the_top_stay_where_they_are(tmp_path):
    src = make_zip(tmp_path / "a.zip", [("app.py", "1"), ("lib/x.py", "2")])
    archive.unpack(src, tmp_path / "out", 1 << 20)
    assert (tmp_path / "out" / "app.py").is_file() and (tmp_path / "out" / "lib" / "x.py").is_file()


@pytest.mark.parametrize("name", ["../evil.py", "a/../../evil.py", "/etc/evil", "C:/evil.py", "a\\..\\evil.py"])
def test_names_that_escape_are_refused(tmp_path, name):
    src = make_zip(tmp_path / "a.zip", [("ok.py", "1"), (name, "x")])
    with pytest.raises(archive.Refused):
        archive.unpack(src, tmp_path / "out", 1 << 20)
    assert not (tmp_path / "out").exists() and not (tmp_path / "evil.py").exists()


def test_links_are_refused(tmp_path):
    link = zipfile.ZipInfo("app/link")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    src = make_zip(tmp_path / "a.zip", [("app/x.py", "1"), link])
    with pytest.raises(archive.Refused, match="link"):
        archive.unpack(src, tmp_path / "out", 1 << 20)
    assert not (tmp_path / "out").exists()


def test_the_size_cap_holds_even_when_the_archive_lies(tmp_path):
    big = make_zip(tmp_path / "big.zip", [("a.py", "x" * 5000)])
    with pytest.raises(archive.Refused, match="larger than"):
        archive.unpack(big, tmp_path / "out", 4000)
    # a header that understates the size: the bytes written are counted too
    with zipfile.ZipFile(big) as z:
        info = z.infolist()[0]
    raw = bytearray(big.read_bytes())
    lie = (100).to_bytes(4, "little")
    i = raw.find(b"PK\x03\x04"); raw[i + 22:i + 26] = lie            # local header uncompressed size
    j = raw.find(b"PK\x01\x02"); raw[j + 24:j + 28] = lie            # central directory uncompressed size
    (tmp_path / "lie.zip").write_bytes(bytes(raw))
    try:   # Python's zipfile stops at the declared size (or fails the checksum); either way no more than that is written
        archive.unpack(tmp_path / "lie.zip", tmp_path / "out2", 4000)
        assert (tmp_path / "out2" / "a.py").stat().st_size <= 100
    except archive.Refused:
        assert not (tmp_path / "out2").exists()
    assert info.file_size == 5000


def test_not_a_zip_and_empty_zip(tmp_path):
    (tmp_path / "x.zip").write_bytes(b"hello")
    with pytest.raises(archive.Refused, match="not a .zip"):
        archive.unpack(tmp_path / "x.zip", tmp_path / "o1", 1 << 20)
    empty = make_zip(tmp_path / "e.zip", [("dir/", "")])
    with pytest.raises(archive.Refused, match="empty"):
        archive.unpack(empty, tmp_path / "o2", 1 << 20)


def test_cli_exit_codes(tmp_path, capsys):
    good = make_zip(tmp_path / "g.zip", [("a.py", "1")])
    assert archive.main([str(good), str(tmp_path / "o"), "--max-mb", "1"]) == 0
    assert archive.main([str(good), str(tmp_path / "o"), "--max-mb", "1"]) == 2     # DEST already there
    assert "not empty" in capsys.readouterr().err
