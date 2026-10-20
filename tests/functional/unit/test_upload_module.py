# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""dionaea/upload.py: the size bound of uploaded files and the url of an upload.

The module imports dionaea.core only inside complete(); a stand-in module
makes that work without the binding.
"""

import importlib.util
import os
import stat
import sys
import tempfile
import types
from pathlib import Path

import pytest


class FakeIncident:
    reported = []

    def __init__(self, name):
        self.name = name

    def report(self):
        # the file is there when the incident is reported (store.py reads it)
        FakeIncident.reported.append((self.name, self.url, self.con, Path(self.path).read_bytes()))


def _load():
    core = types.ModuleType("dionaea.core")
    core.incident = FakeIncident
    package = sys.modules.setdefault("dionaea", types.ModuleType("dionaea"))
    package.__path__ = getattr(package, "__path__", [])
    sys.modules["dionaea.core"] = core
    root = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")
    spec = importlib.util.spec_from_file_location("upload_under_test", root / "upload.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


upload = _load()


@pytest.fixture(autouse=True)
def clear_reported():
    FakeIncident.reported.clear()


def make(tmp_path, max_size=1000):
    return upload.UploadFile("ftp-", max_size=max_size, download_dir=str(tmp_path), suffix=".tmp")


def left_over(download_dir):
    """What is left in download.dir and in its folder of the temporary files."""
    incoming = Path(download_dir) / ".incoming"
    names = [p.name for p in Path(download_dir).iterdir() if p != incoming]
    if incoming.is_dir():
        names += [".incoming/" + p.name for p in incoming.iterdir()]
    return names


@pytest.mark.parametrize("value, expected", [
    (None, upload.DEFAULT_MAX_UPLOAD_SIZE),
    (1000, 1000),
    ("2048", 2048),
    (0, upload.DEFAULT_MAX_UPLOAD_SIZE),
    (-5, upload.DEFAULT_MAX_UPLOAD_SIZE),
    ("lots", upload.DEFAULT_MAX_UPLOAD_SIZE),
    ([1], upload.DEFAULT_MAX_UPLOAD_SIZE),
])
def test_max_upload_size_option(value, expected):
    assert upload.parse_max_upload_size(value) == expected


def test_sequential_writes_are_appended_and_reported_once(tmp_path):
    f = make(tmp_path)
    assert os.path.basename(f.name).startswith("ftp-") and f.name.endswith(".tmp")
    # in download.dir/.incoming: a file made and removed there does not change download.dir (store.py, DirQuota)
    assert os.path.dirname(f.name) == str(tmp_path / ".incoming")
    f.write(b"abc")
    f.write(b"def")
    assert f.size == 6
    assert f.complete("the con", "ftp://1.2.3.4/x") is True
    assert FakeIncident.reported == [("dionaea.download.complete", "ftp://1.2.3.4/x", "the con", b"abcdef")]
    assert left_over(tmp_path) == []


def test_write_at_an_offset_keeps_the_hole(tmp_path):
    f = make(tmp_path)
    f.write(b"tail", 10)
    f.write(b"head", 0)
    assert f.size == 14
    f.complete("c", "smb://x/y")
    assert FakeIncident.reported[0][3] == b"head" + b"\x00" * 6 + b"tail"


@pytest.mark.parametrize("offset, size", [
    (1000, 1),            # starts at the limit
    (997, 4),             # ends one byte beyond
    (0xffffffff, 1),      # 32 bit offset
    (2 ** 40, 1),         # 64 bit offset of the SMB write
    (-1, 1),
])
def test_write_beyond_the_limit_is_refused_and_nothing_is_written(tmp_path, offset, size):
    f = make(tmp_path)
    f.write(b"x" * 10)
    with pytest.raises(upload.UploadTooLarge):
        f.write(b"y" * size, offset)
    assert f.size == 10
    f._fp.flush()
    assert os.path.getsize(f.name) == 10


def test_write_up_to_the_limit_is_fine_and_one_more_byte_is_not(tmp_path):
    f = make(tmp_path)
    f.write(b"x" * 1000)
    with pytest.raises(upload.UploadTooLarge):
        f.write(b"x")
    assert f.complete("c", "u") is True


def test_a_discarded_file_is_gone_and_not_reported(tmp_path):
    f = make(tmp_path)
    f.write(b"data")
    f.discard()
    assert left_over(tmp_path) == []
    with pytest.raises(upload.UploadError):
        f.write(b"more")
    assert f.complete("c", "u") is False
    f.discard()  # twice is fine
    assert FakeIncident.reported == []


def test_an_empty_file_is_not_reported_but_removed(tmp_path):
    f = make(tmp_path)
    assert f.complete("c", "u") is False
    assert FakeIncident.reported == []
    assert left_over(tmp_path) == []


@pytest.mark.parametrize("scheme, host, name, expected", [
    ("ftp", "192.0.2.1", "a.bin", "ftp://192.0.2.1/a.bin"),
    ("ftp", "192.0.2.1", "/etc/x y", "ftp://192.0.2.1/etc/x%20y"),
    ("ftp", "192.0.2.1", "a/ä#?%.bin", "ftp://192.0.2.1/a/%C3%A4%23%3F%25.bin"),
    ("smb", "192.0.2.1", "\\dir\\file.exe", "smb://192.0.2.1/dir/file.exe"),
    ("smb", "192.0.2.1", "file\x00.exe", "smb://192.0.2.1/file.exe"),
    ("smb", "192.0.2.1", b"b\xffd", "smb://192.0.2.1/b%EF%BF%BDd"),
    ("ftp", "::ffff:192.0.2.1", "a", "ftp://192.0.2.1/a"),
    ("ftp", "2001:db8::1", "a", "ftp://[2001:db8::1]/a"),
    ("ftp", "192.0.2.1", "", "ftp://192.0.2.1/"),
    ("ftp", "192.0.2.1", "line\r\nbreak", "ftp://192.0.2.1/line%0D%0Abreak"),
])
def test_upload_url(scheme, host, name, expected):
    assert upload.upload_url(scheme, host, name) == expected


def test_the_name_in_the_url_is_shortened():
    url = upload.upload_url("ftp", "192.0.2.1", "a" * 5000)
    assert url == "ftp://192.0.2.1/" + "a" * upload.MAX_URL_NAME_LENGTH


def test_a_file_of_holes_is_not_reported(tmp_path):
    f = make(tmp_path, max_size=64 * 1024 * 1024)
    f.write(b"x" * 100, 32 * 1024 * 1024 - 100)
    assert f.size - f.received > upload.MAX_SPARSE_GAP
    assert f.complete("c", "u") is False
    assert FakeIncident.reported == []
    assert left_over(tmp_path) == []


def test_small_holes_and_rewrites_are_fine(tmp_path):
    f = make(tmp_path, max_size=64 * 1024 * 1024)
    f.write(b"a" * 100, upload.MAX_SPARSE_GAP)  # hole of exactly the slack
    f.write(b"b" * 50, 0)
    f.write(b"c" * 10, 0)  # overlap
    assert f.complete("c", "u") is True


def test_writes_after_a_drop_for_size_say_too_large_again(tmp_path):
    f = make(tmp_path)
    with pytest.raises(upload.UploadTooLarge):
        f.write(b"x", 5000)
    f.discard()
    with pytest.raises(upload.UploadTooLarge):
        f.write(b"x", 0)


def test_the_folder_of_the_temporary_files_is_made_if_it_is_gone(tmp_path):
    """dionaea makes .incoming at the start (src/util.c); a folder removed meanwhile is made again, 0700."""
    f = upload.incoming_file("http-", suffix=".tmp", download_dir=str(tmp_path))
    f.write(b"x")
    f.close()
    incoming = tmp_path / ".incoming"
    assert Path(f.name).parent == incoming
    assert stat.S_IMODE(incoming.stat().st_mode) == 0o700
    assert stat.S_IMODE(os.stat(f.name).st_mode) == 0o600
    os.unlink(f.name)
    incoming.rmdir()
    g = upload.incoming_file("http-", suffix=".tmp", download_dir=str(tmp_path))
    g.close()
    assert Path(g.name).parent == incoming
    os.unlink(g.name)


def test_a_missing_download_dir_is_not_made(tmp_path):
    with pytest.raises(FileNotFoundError):
        upload.incoming_file("http-", download_dir=str(tmp_path / "gone"))
    assert not (tmp_path / "gone").exists()


def test_without_a_download_dir_the_file_is_in_the_folder_of_the_system(tmp_path):
    f = upload.incoming_file("http-", suffix=".tmp", download_dir=None)
    f.close()
    try:
        assert Path(f.name).parent == Path(tempfile.gettempdir())
    finally:
        os.unlink(f.name)


def test_a_failed_write_keeps_its_errno(tmp_path):
    # the FTP service answers a full disk (ENOSPC, EDQUOT) with 452, other errors with 425
    import errno

    class Full:
        name = "full"

        def seek(self, offset):
            pass

        def write(self, data):
            raise OSError(errno.ENOSPC, "No space left on device")

        def close(self):
            pass
    f = make(tmp_path)
    real, f._fp = f._fp, Full()
    with pytest.raises(upload.UploadError) as raised:
        f.write(b"abc")
    assert raised.value.errno == errno.ENOSPC
    assert upload.UploadError("no errno").errno is None
    assert upload.UploadTooLarge("too large").errno is None
    f._fp = real
    f.discard()


@pytest.mark.parametrize("share, name, expected", [
    ("C$", "\\dir\\file.exe", "smb://192.0.2.1/C$/dir/file.exe"),
    ("IPC$\x00", "x.bin", "smb://192.0.2.1/IPC$/x.bin"),
    ("\\\\HOST\\my share", "x.bin", "smb://192.0.2.1/my%20share/x.bin"),
    (b"D\xffATA", "x.bin", "smb://192.0.2.1/D%EF%BF%BDATA/x.bin"),
    ("a/../b", "x.bin", "smb://192.0.2.1/b/x.bin"),
    ("", "x.bin", "smb://192.0.2.1/x.bin"),
    (None, "x.bin", "smb://192.0.2.1/x.bin"),
    ("\\", "x.bin", "smb://192.0.2.1/x.bin"),
])
def test_upload_url_with_a_share(share, name, expected):
    assert upload.upload_url("smb", "192.0.2.1", name, share=share) == expected


def test_the_share_in_the_url_is_shortened():
    url = upload.upload_url("smb", "192.0.2.1", "x", share="s" * 5000)
    assert url == "smb://192.0.2.1/" + "s" * upload.MAX_URL_NAME_LENGTH + "/x"


@pytest.mark.parametrize("share, name, expected", [
    (None, "\\..\\..\\etc\\x", "smb://192.0.2.1/%2E%2E/%2E%2E/etc/x"),
    (None, "a/./b", "smb://192.0.2.1/a/%2E/b"),
    ("..", "x.bin", "smb://192.0.2.1/%2E%2E/x.bin"),
    (".", "..", "smb://192.0.2.1/%2E/%2E%2E"),
    ("...", "a..b/.x", "smb://192.0.2.1/%2E%2E%2E/a..b/.x"),
])
def test_a_name_of_only_dots_is_encoded(share, name, expected):
    url = upload.upload_url("smb", "192.0.2.1", name, share=share)
    assert url == expected
    assert "/../" not in url and "/./" not in url and not url.endswith("/..")
