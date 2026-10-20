# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""dionaea/store.py: mode of the stored samples and the size cap (``max_size``).

store.py imports the binding (dionaea.core, ihandler and incident); stand-in
modules make that work without it. They are in sys.modules only while the
module is loaded, so the stand-ins of other unit tests stay what they are.
"""

import contextlib
import hashlib
import importlib.util
import os
import stat
import sys
import threading
import time
import types
from pathlib import Path

import pytest

MIB = 1024 * 1024


class FakeIncident:
    reported = []

    def __init__(self, name):
        self.name = name

    def report(self):
        FakeIncident.reported.append((self.name, dict(vars(self))))


class FakeIHandler:
    def __init__(self, path):
        self.path = path


class FakeLoaderError(Exception):
    def __init__(self, msg, *args):  # noqa: B042 - emulate LoaderError's historical API
        super().__init__(msg % args if args else msg)
        self.msg = msg
        self.args = args


class FakeDionaea:
    download_dir = None

    def config(self):
        return {"dionaea": {"download.dir": FakeDionaea.download_dir}}


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


def _load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def _stand_ins():
    saved = {name: sys.modules.get(name) for name in
             ("dionaea", "dionaea.core", "dionaea.exception", "dionaea.util", "dionaea.upload")}
    package = types.ModuleType("dionaea")
    package.__path__ = []
    package.IHandlerLoader = type("IHandlerLoader", (), {})
    core = types.ModuleType("dionaea.core")
    core.ihandler = FakeIHandler
    core.incident = FakeIncident
    core.g_dionaea = FakeDionaea()
    exception = types.ModuleType("dionaea.exception")
    exception.LoaderError = FakeLoaderError
    sys.modules.update({"dionaea": package, "dionaea.core": core, "dionaea.exception": exception})
    sys.modules["dionaea.util"] = _load_file("dionaea_util_for_store", _src_root() / "util.py")
    sys.modules["dionaea.upload"] = _load_file("dionaea_upload_for_store", _src_root() / "upload.py")
    try:
        yield
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def _load():
    with _stand_ins():
        return _load_file("store_under_test", _src_root() / "store.py")


store = _load()
# the temporary files of the services (FTP STOR, SMB write, the printer); stdlib only at import
upload = _load_file("upload_for_store", _src_root() / "upload.py")


@pytest.fixture(autouse=True)
def clear_reported():
    FakeIncident.reported.clear()


@pytest.fixture
def binaries(tmp_path):
    path = tmp_path / "binaries"
    path.mkdir()
    FakeDionaea.download_dir = str(path)
    return path


def make_handler(config=None):
    handler = store.storehandler("dionaea.download.complete", config=config)
    # the first count of download.dir runs beside dionaea; the tests start after it
    handler.quota.wait()
    return handler


def temp_file(directory, data, name="http-tmp.tmp"):
    """The temporary file of a sample, where the services make it: ``<download.dir>/.incoming`` (upload.py)."""
    incoming = Path(directory) / ".incoming"
    incoming.mkdir(mode=0o700, exist_ok=True)
    path = incoming / name
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def store_sample(handler, directory, data, name="http-tmp.tmp"):
    """What a service does: temp file, incident, temp file removed afterwards."""
    path = temp_file(directory, data, name)
    icd = FakeIncident("dionaea.download.complete")
    icd.path = str(path)
    icd.url = "http://198.51.100.7/x"
    icd.con = "the con"
    handler.handle_incident(icd)
    path.unlink()
    return hashlib.md5(data).hexdigest()


def names():
    return [name for name, _ in FakeIncident.reported]


# --- parse_max_size -------------------------------------------------------------


@pytest.mark.parametrize("value, expected", [
    (None, 0),
    ("", 0),
    (0, 0),
    ("0", 0),
    (1, MIB),
    ("2", 2 * MIB),
    (1024, 1024 * MIB),
    (0.5, MIB // 2),
    ("0.5", MIB // 2),
    # below one byte is one byte: 0 would be no limit
    ("0.0000001", 1),
    (1e-300, 1),
    ("0.0000005", 1),
])
def test_max_size_option(value, expected):
    assert store.parse_max_size(value) == expected


@pytest.mark.parametrize("value", [2 ** 40, "1099511627776", float(2 ** 40)])
def test_the_largest_max_size_is_2_to_the_40_mib(value):
    assert store.parse_max_size(value) == 2 ** 40 * MIB


def test_a_config_max_size_out_of_range_is_unlimited_with_a_warning(binaries, caplog, monkeypatch):
    monkeypatch.delenv("DIONAEA_STORE_MAX_SIZE", raising=False)
    with caplog.at_level("INFO", logger="store"):
        handler = make_handler({"max_size": 1e305})
    assert handler.max_size == 0
    assert any(r.levelname == "WARNING" and "max_size" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("value", [-1, "-3", "lots", [1], {"a": 1}, True, float("nan"), float("inf"),
                                   # above 2^40 MiB, as config.max_size of the streamdumper
                                   1e305, "1e305", 2 ** 40 + 1, "9" * 303, "1" + "0" * 303, 1e20,
                                   10 ** 400])
def test_invalid_max_size_is_refused(value):
    with pytest.raises(ValueError):
        store.parse_max_size(value)


# --- DirQuota -------------------------------------------------------------------


class Clock:
    now = 1000.0

    def __call__(self):
        return Clock.now


def _old_mtime(path):
    """An mtime long ago: a change of the folder from now on gives it another one, however coarse the clock of
    the filesystem is (a removal in the same tick as the count would keep it)."""
    os.utime(path, ns=(10 ** 9, 10 ** 9))


def test_quota_without_limit_allows_everything(tmp_path):
    quota = store.DirQuota(str(tmp_path), 0)
    assert quota.allows(10 ** 12)


def test_quota_counts_the_files_at_the_start(tmp_path):
    (tmp_path / "a").write_bytes(b"x" * 600)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "ignored").write_bytes(b"x" * 5000)
    quota = store.DirQuota(str(tmp_path), 1000)
    quota.wait()
    assert quota.allows(400)
    assert not quota.allows(401)


def test_quota_counts_a_hard_link_once(tmp_path):
    (tmp_path / "a").write_bytes(b"x" * 600)
    os.link(tmp_path / "a", tmp_path / "b")
    quota = store.DirQuota(str(tmp_path), 1000)
    quota.wait()
    assert quota.allows(400)
    assert not quota.allows(401)


def test_quota_add_raises_the_total(tmp_path):
    quota = store.DirQuota(str(tmp_path), 1000)
    quota.wait()
    assert quota.allows(600)
    quota.add(600)
    assert not quota.allows(401)
    assert quota.allows(400)


def test_quota_rescans_after_the_refresh_time(tmp_path):
    Clock.now = 1000.0
    folder = tmp_path / "binaries"
    folder.mkdir()
    (folder / "a").write_bytes(b"x" * 900)
    quota = store.DirQuota(str(folder), 1000, refresh=60, clock=Clock())
    quota.wait()
    assert not quota.allows(200)
    # T-Pot empties the folder: rm -rf, mkdir (the old one is kept here, so its inode is not reused)
    folder.rename(tmp_path / "binaries.old")
    folder.mkdir()
    assert not quota.allows(200), "the running total is kept until the refresh time"
    Clock.now = 1061.0
    quota.allows(200)   # starts the rescan
    quota.wait()
    assert quota.allows(200)


def test_quota_rescan_leaves_the_incoming_file_out(tmp_path):
    Clock.now = 1000.0
    folder = tmp_path / "binaries"
    folder.mkdir()
    quota = store.DirQuota(str(folder), 1000, refresh=60, clock=Clock())
    quota.wait()
    # a replaced folder is counted while a file is being stored in it
    folder.rename(tmp_path / "binaries.old")
    folder.mkdir()
    # the temporary file of the sample that is being stored is in .incoming (upload.py)
    (folder / ".incoming").mkdir()
    incoming = folder / ".incoming" / "http-tmp.tmp"
    incoming.write_bytes(b"x" * 600)
    Clock.now = 1061.0
    quota.allows(600)
    quota.wait()
    # it is below the folder, but not in the total
    assert quota.used == 0
    assert quota.allows(600)
    assert not quota.allows(1001)


def test_quota_rescan_does_not_hold_up_the_caller(tmp_path, monkeypatch):
    """A count reads the whole folder (21,000 files after an hour of the replay, seconds on a
    bind mount): it runs beside the event loop, allows() answers from the running total meanwhile."""
    Clock.now = 1000.0
    folder = tmp_path / "binaries"
    folder.mkdir()
    (folder / "a").write_bytes(b"x" * 900)
    quota = store.DirQuota(str(folder), 1000, refresh=60, clock=Clock())
    quota.wait()
    folder.rename(tmp_path / "binaries.old")
    folder.mkdir()
    release = threading.Event()
    scanning = threading.Event()
    real_scandir = store.os.scandir

    def slow_scandir(path):
        scanning.set()
        assert release.wait(10)
        return real_scandir(path)

    monkeypatch.setattr(store.os, "scandir", slow_scandir)
    Clock.now = 1061.0
    assert not quota.allows(200), "answered from the running total while the folder is read"
    assert scanning.wait(5), "the rescan was started"
    quota.add(50)          # a sample stored meanwhile counts after the rescan as well
    assert not quota.allows(200)
    release.set()
    quota.wait()
    assert quota.used == 50
    assert quota.allows(200)
    # one rescan per refresh time, not one per call
    calls = []
    monkeypatch.setattr(store.os, "scandir", lambda path: calls.append(path) or real_scandir(path))
    for _ in range(5):
        quota.allows(1)
    quota.wait()
    assert calls == []


def test_quota_remembers_only_files_with_more_than_one_link(tmp_path, monkeypatch):
    """A rescan of 50,000 samples kept a set of all their inodes (6.6 MiB for the time of the scan, growing
    with the folder): a file with one link can not come twice, only the others are remembered."""
    for name in "abc":
        (tmp_path / name).write_bytes(b"x" * 100)
    os.link(tmp_path / "a", tmp_path / "a2")
    remembered = []

    class Seen(set):
        def add(self, item):
            remembered.append(item)
            super().add(item)

    monkeypatch.setattr(store, "set", Seen, raising=False)
    quota = store.DirQuota(str(tmp_path), 10000)
    quota.wait()
    assert quota.used == 300
    assert len(remembered) == 1, "only the file with two links"


def test_quota_of_a_missing_folder_counts_nothing(tmp_path):
    quota = store.DirQuota(str(tmp_path / "gone"), 1000)
    quota.wait()
    assert quota.allows(1000)


# --- DirQuota: counted once, then only the folder itself is looked at -----------


def test_quota_start_does_not_wait_for_the_count(tmp_path, monkeypatch):
    """dionaea loads the handlers before it listens: the first count of the folder runs beside it,
    and until it ended the total is what was stored since the start (the samples of an earlier run are not
    in it yet)."""
    (tmp_path / "a").write_bytes(b"x" * 900)
    release = threading.Event()
    scanning = threading.Event()
    real_scandir = store.os.scandir

    def slow_scandir(path):
        scanning.set()
        release.wait(3)
        return real_scandir(path)

    monkeypatch.setattr(store.os, "scandir", slow_scandir)
    start = time.monotonic()
    quota = store.DirQuota(str(tmp_path), 1000)
    took = time.monotonic() - start
    release.set()
    assert took < 1, "the start waited %.1f s for the count" % took
    assert scanning.wait(5)
    quota.wait()
    assert quota.used == 900
    assert not quota.allows(200)


def test_quota_does_not_read_an_unchanged_folder_again(tmp_path, monkeypatch):
    """35,000 samples on a Docker Desktop bind mount: a read of all of them every minute held up
    every file request of dionaea. After the first count only the folder itself is looked at."""
    Clock.now = 1000.0
    for i in range(50):
        (tmp_path / ("s%d" % i)).write_bytes(b"x")
    quota = store.DirQuota(str(tmp_path), 1000, refresh=60, clock=Clock())
    quota.wait()
    calls = []
    real_scandir = store.os.scandir
    monkeypatch.setattr(store.os, "scandir", lambda path: calls.append(path) or real_scandir(path))
    for minute in range(1, 6):
        Clock.now = 1000.0 + 61 * minute
        assert quota.allows(1)
        quota.wait()
    assert calls == []
    assert quota.used == 50


def test_quota_counts_a_removed_file_while_the_samples_fit(tmp_path):
    """A sample removed from outside stays counted (the total counts more than the folder holds, so fewer samples
    are stored, never more than the limit) until a sample is refused (or the folder is replaced)."""
    Clock.now = 1000.0
    (tmp_path / "a").write_bytes(b"x" * 900)
    _old_mtime(tmp_path)
    quota = store.DirQuota(str(tmp_path), 1000, refresh=60, clock=Clock())
    quota.wait()
    (tmp_path / "a").unlink()
    Clock.now = 1061.0
    assert quota.allows(100)
    quota.wait()
    assert quota.used == 900
    assert quota.counts == 1


def test_quota_stop_ends_a_slow_count(tmp_path, monkeypatch):
    """At the stop of dionaea a count ends after the entry it reads, not after the folder."""
    for i in range(200):
        (tmp_path / ("s%d" % i)).write_bytes(b"x")
    real_scandir = store.os.scandir
    reading = threading.Event()

    class SlowEntries:
        def __init__(self, path):
            self._it = real_scandir(path)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._it.close()

        def __iter__(self):
            for entry in self._it:
                reading.set()
                time.sleep(0.05)   # 200 entries: 10 s
                yield entry

    monkeypatch.setattr(store.os, "scandir", SlowEntries)
    quota = store.DirQuota(str(tmp_path), 1000)
    assert reading.wait(5)
    start = time.monotonic()
    quota.stop()
    took = time.monotonic() - start
    assert took < 1, "the stop waited %.1f s for the count" % took
    assert quota._scan is None or not quota._scan.is_alive()


def test_quota_counts_again_at_a_refusal_once_the_folder_changed(tmp_path):
    """ewsposter removes a sample once it was sent (del_malware_after_send), the running total does not see that.
    A refused sample starts a count of the folder when its
    mtime changed since the last count (every create and unlink in the flat folder changes it); the next sample
    is taken from the new total."""
    Clock.now = 1000.0
    (tmp_path / "a").write_bytes(b"x" * 900)
    _old_mtime(tmp_path)
    quota = store.DirQuota(str(tmp_path), 1000, refresh=60, clock=Clock())
    quota.wait()
    (tmp_path / "a").unlink()
    assert not quota.allows(200), "the refused sample is answered from the running total"
    quota.wait()
    assert quota.used == 0
    assert quota.counts == 2
    assert quota.allows(200)


def test_quota_does_not_read_a_full_folder_that_did_not_change(tmp_path, monkeypatch):
    """A folder that is really full is not read at every refused sample: one stat shows that it did not change."""
    Clock.now = 1000.0
    for i in range(10):
        (tmp_path / ("s%d" % i)).write_bytes(b"x" * 100)
    _old_mtime(tmp_path)
    quota = store.DirQuota(str(tmp_path), 1000, refresh=60, clock=Clock())
    quota.wait()
    scans, looks = [], []
    real_scandir, real_stat = store.os.scandir, store.os.stat
    monkeypatch.setattr(store.os, "scandir", lambda path: scans.append(path) or real_scandir(path))

    def counting_stat(path, *args, **kwargs):
        if str(path) == str(tmp_path):
            looks.append(path)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(store.os, "stat", counting_stat)
    for _ in range(5):
        assert not quota.allows(1)
        quota.wait()
    assert scans == []
    assert len(looks) >= 1, "the folder was looked at"
    assert quota.counts == 1
    assert quota.used == 1000


class Delivered:
    """The incident of a service (upload.py: UploadFile.complete) goes to the store handler."""
    handler = None

    def __init__(self, name):
        self.name = name

    def report(self):
        Delivered.handler.handle_incident(self)


def arrive(handler, data, prefix="ftp-"):
    """A sample as a service takes it: a temporary file of upload.py, reported, removed."""
    f = upload.UploadFile(prefix, max_size=10 * MIB, download_dir=handler.download_dir, suffix=".tmp")
    f.write(data)
    assert f.complete("the con", "ftp://198.51.100.7/x")
    assert not os.path.exists(f.name)
    return hashlib.md5(data).hexdigest()


def test_quota_does_not_read_a_full_folder_while_samples_arrive(binaries, monkeypatch):
    """At the cap every sample that comes is refused, and smaller ones that still fit are stored. Neither may make
    a refusal read the whole folder again: the temporary file of a sample is made and removed in
    download.dir/.incoming, not in download.dir (that changed its mtime at every sample, so the folder was read
    in full every ten minutes while samples came), and a sample the store adds itself is no change from outside."""
    monkeypatch.setitem(sys.modules, "dionaea.core", types.SimpleNamespace(incident=Delivered))
    for i in range(10):
        (binaries / ("%032x" % i)).write_bytes(b"x" * (100 * 1024))
    # dionaea makes it at the start, before the handlers (src/util.c, incoming_prepare)
    (binaries / ".incoming").mkdir(mode=0o700)
    _old_mtime(binaries)
    handler = make_handler({"max_size": "1"})
    handler.stop()
    Delivered.handler = handler
    Clock.now = 1000.0
    handler.quota = store.DirQuota(str(binaries), handler.max_size, refresh=60, clock=Clock())
    handler.quota.wait()
    assert handler.quota.used == 10 * 100 * 1024
    scans = []
    real_scandir = store.os.scandir
    monkeypatch.setattr(store.os, "scandir", lambda path: scans.append(str(path)) or real_scandir(path))
    stored = []
    for n in range(4):
        # ten minutes apart: the rate limit of the counts at a refusal does not hide a count
        Clock.now = 1000.0 + (n + 1) * (store.RECOUNT_INTERVAL + 1)
        refused = arrive(handler, b"%d big " % n * (20 * 1024))
        assert not (binaries / refused).exists()
        handler.quota.wait()
        stored.append(arrive(handler, b"%d small " % n * 100))
        handler.quota.wait()
    assert all((binaries / md5).exists() for md5 in stored)
    assert scans == [], "the full folder was read at a refusal"
    assert handler.quota.counts == 1
    assert sorted(p.name for p in binaries.iterdir() if p.is_dir()) == [".incoming"]
    assert list((binaries / ".incoming").iterdir()) == []


def test_quota_counts_again_at_a_refusal_at_most_every_ten_minutes(tmp_path):
    Clock.now = 1000.0
    (tmp_path / "a").write_bytes(b"x" * 900)
    _old_mtime(tmp_path)
    quota = store.DirQuota(str(tmp_path), 1000, refresh=60, clock=Clock())
    quota.wait()
    (tmp_path / "a").unlink()
    assert not quota.allows(200)
    quota.wait()
    assert quota.counts == 2
    assert quota.allows(200)
    quota.add(900)
    # another sample comes and goes from outside: the folder changed again
    (tmp_path / "b").write_bytes(b"x")
    (tmp_path / "b").unlink()
    for now in (1001.0, 1300.0, 1599.0):
        Clock.now = now
        assert not quota.allows(200)
        quota.wait()
    assert quota.counts == 2, "no second count within ten minutes of the first"
    Clock.now = 1000.0 + store.RECOUNT_INTERVAL
    assert not quota.allows(200)
    quota.wait()
    assert quota.counts == 3
    assert quota.allows(200)


def test_quota_logs_a_missing_folder_once(tmp_path, caplog):
    """While download.dir is gone a look every refresh found it gone again and logged it every minute."""
    Clock.now = 1000.0
    folder = tmp_path / "binaries"
    folder.mkdir()
    quota = store.DirQuota(str(folder), 1000, refresh=60, clock=Clock())
    quota.wait()
    folder.rmdir()
    with caplog.at_level("WARNING", logger="store"):
        for minute in range(1, 6):
            Clock.now = 1000.0 + 61 * minute
            assert quota.allows(1)
            quota.wait()
        assert len([r for r in caplog.records if "gone" in r.getMessage()]) == 1
        # it is there again: counted
        folder.mkdir()
        (folder / "a").write_bytes(b"x" * 900)
        Clock.now += 61
        quota.allows(1)
        quota.wait()
        assert quota.used == 900
        # and gone again: logged again, once
        (folder / "a").unlink()
        folder.rmdir()
        for _minute in range(1, 4):
            Clock.now += 61
            quota.allows(1)
            quota.wait()
    assert len([r for r in caplog.records if "gone" in r.getMessage()]) == 2
    assert quota.used == 0


# --- the handler: mode ----------------------------------------------------------


def test_stored_sample_has_no_execute_bit(binaries):
    handler = make_handler()
    md5 = store_sample(handler, binaries, b"MZ sample")
    assert stat.S_IMODE((binaries / md5).stat().st_mode) == 0o440
    assert names() == ["dionaea.download.complete.hash", "dionaea.download.complete.unique"]


def test_a_temp_file_that_is_executable_is_stored_without_the_bit(binaries):
    handler = make_handler()
    path = temp_file(binaries, b"#!/bin/sh\nid\n")
    path.chmod(0o755)
    icd = FakeIncident("dionaea.download.complete")
    icd.path, icd.url = str(path), ""
    handler.handle_incident(icd)
    md5 = hashlib.md5(b"#!/bin/sh\nid\n").hexdigest()
    assert stat.S_IMODE((binaries / md5).stat().st_mode) == 0o440


def test_sample_from_another_filesystem_is_copied(binaries, monkeypatch):
    def refuse(src, dst, **kwargs):
        raise OSError(18, "Invalid cross-device link")
    monkeypatch.setattr(store.os, "link", refuse)
    handler = make_handler()
    md5 = store_sample(handler, binaries, b"copied sample")
    assert (binaries / md5).read_bytes() == b"copied sample"
    assert stat.S_IMODE((binaries / md5).stat().st_mode) == 0o440
    assert names() == ["dionaea.download.complete.hash", "dionaea.download.complete.unique"]
    # the copy was made in .incoming and renamed: nothing else is left
    assert sorted(p.name for p in binaries.iterdir()) == [".incoming", md5]
    assert list((binaries / ".incoming").iterdir()) == []


def test_second_upload_of_a_sample_is_again(binaries):
    handler = make_handler()
    store_sample(handler, binaries, b"same")
    FakeIncident.reported.clear()
    store_sample(handler, binaries, b"same")
    assert names() == ["dionaea.download.complete.hash", "dionaea.download.complete.again"]


# --- the handler: cap -----------------------------------------------------------


def test_sample_over_the_cap_is_not_stored(binaries, caplog):
    handler = make_handler({"max_size": 1})
    first = store_sample(handler, binaries, b"a" * (600 * 1024))
    FakeIncident.reported.clear()
    with caplog.at_level("WARNING", logger="store"):
        second = store_sample(handler, binaries, b"b" * (600 * 1024))
    assert (binaries / first).exists()
    assert not (binaries / second).exists()
    # no file is left of the refused sample, also not in .incoming
    assert sorted(os.listdir(binaries)) == sorted([first, ".incoming"])
    assert os.listdir(binaries / ".incoming") == []
    # the md5 stays visible (sqlite and json log it on .hash), nothing is offered for a file that is not there
    assert names() == ["dionaea.download.complete.hash"]
    assert FakeIncident.reported[0][1]["md5hash"] == second
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert second in warnings[0].getMessage()


def test_sample_that_fits_exactly_is_stored(binaries):
    handler = make_handler({"max_size": 1})
    md5 = store_sample(handler, binaries, b"a" * MIB)
    assert (binaries / md5).exists()


def test_known_sample_is_again_over_the_cap(binaries):
    handler = make_handler({"max_size": 1})
    md5 = store_sample(handler, binaries, b"a" * (600 * 1024))
    store_sample(handler, binaries, b"b" * (600 * 1024))
    FakeIncident.reported.clear()
    store_sample(handler, binaries, b"a" * (600 * 1024))
    assert names() == ["dionaea.download.complete.hash", "dionaea.download.complete.again"]
    assert (binaries / md5).exists()


def test_small_sample_still_fits_after_a_refused_one(binaries):
    handler = make_handler({"max_size": 1})
    store_sample(handler, binaries, b"a" * (600 * 1024))
    store_sample(handler, binaries, b"b" * (600 * 1024))
    small = store_sample(handler, binaries, b"c" * 1000)
    assert (binaries / small).exists()


def test_no_cap_by_default(binaries):
    handler = make_handler()
    md5 = store_sample(handler, binaries, b"a" * (3 * MIB))
    assert (binaries / md5).exists()


def test_existing_files_count_for_the_cap(binaries):
    (binaries / ("0" * 32)).write_bytes(b"x" * (900 * 1024))
    handler = make_handler({"max_size": 1})
    md5 = store_sample(handler, binaries, b"b" * (200 * 1024))
    assert not (binaries / md5).exists()


def test_invalid_max_size_is_unlimited_with_a_warning(binaries, caplog):
    with caplog.at_level("WARNING", logger="store"):
        handler = make_handler({"max_size": "lots"})
    assert any("max_size" in r.getMessage() for r in caplog.records)
    md5 = store_sample(handler, binaries, b"a" * (2 * MIB))
    assert (binaries / md5).exists()


def test_a_refused_sample_is_warned_about_once(binaries, caplog):
    handler = make_handler({"max_size": 1})
    store_sample(handler, binaries, b"a" * (600 * 1024))
    with caplog.at_level("WARNING", logger="store"):
        for _ in range(5):
            second = store_sample(handler, binaries, b"b" * (600 * 1024))
        other = store_sample(handler, binaries, b"c" * (600 * 1024))
    messages = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(messages) == 2
    assert second in messages[0] and other in messages[1]


def test_the_memory_of_refused_samples_is_bounded(binaries, caplog):
    handler = make_handler({"max_size": 1})
    store_sample(handler, binaries, b"a" * (900 * 1024))
    for number in range(store.REFUSED_MEMORY + 10):
        store_sample(handler, binaries, b"%d " % number * (50 * 1024))
    assert len(handler._refused) <= store.REFUSED_MEMORY


def test_a_known_sample_with_another_mode_gets_0440(binaries):
    handler = make_handler()
    md5 = store_sample(handler, binaries, b"old sample")
    (binaries / md5).chmod(0o755)
    store_sample(handler, binaries, b"old sample")
    assert stat.S_IMODE((binaries / md5).stat().st_mode) == 0o440
    assert names()[-1] == "dionaea.download.complete.again"


def test_a_failing_chmod_of_a_known_sample_does_not_stop_the_incident(binaries, monkeypatch, caplog):
    handler = make_handler()
    md5 = store_sample(handler, binaries, b"old sample")
    (binaries / md5).chmod(0o644)
    real = store.os.chmod

    def refuse(path, mode, **kwargs):
        if str(path).endswith(md5):
            raise PermissionError(1, "Operation not permitted")
        return real(path, mode, **kwargs)
    monkeypatch.setattr(store.os, "chmod", refuse)
    FakeIncident.reported.clear()
    with caplog.at_level("WARNING", logger="store"):
        store_sample(handler, binaries, b"old sample")
    assert names() == ["dionaea.download.complete.hash", "dionaea.download.complete.again"]
    assert any("Operation not permitted" in r.getMessage() for r in caplog.records)


# --- DIONAEA_STORE_MAX_SIZE -------------------------------------------------------

ENV = "DIONAEA_STORE_MAX_SIZE"


@pytest.mark.parametrize("value, expected", [
    ("0", 0),
    ("1", MIB),
    ("1024", 1024 * MIB),
    ("007", 7 * MIB),
    # the largest config.max_size, 2^40 MiB
    ("1099511627776", 2 ** 40 * MIB),
])
def test_env_max_size_option(value, expected):
    assert store.parse_env_max_size(value) == expected


@pytest.mark.parametrize("value", [
    "", " 2", "2 ", "\t2", "2\n", "+2", "-2", "1.5", "2M", "2MiB", "0x10", "1e3", "inf", "nan", "abc",
    "٣", "２", "1_000", "9" * 400, "9" * 303, "1" + "0" * 303,
    "1099511627777", "99999999999999999999",
])
def test_invalid_env_max_size_is_refused(value):
    with pytest.raises(ValueError):
        store.parse_env_max_size(value)


def test_env_shown_is_printable_and_at_most_64_characters():
    assert store.env_shown("2048 MiB") == "2048 MiB"
    assert store.env_shown("a\nb\tc\x1b[31mä") == "a?b?c?[31m?"
    assert store.env_shown("9" * 100) == "9" * 64
    assert store.env_shown("") == ""


def _infos(caplog):
    return [r.getMessage() for r in caplog.records if r.levelname == "INFO" and r.getMessage().startswith("store: ")]


def test_startup_line_names_the_config(binaries, caplog, monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    with caplog.at_level("INFO", logger="store"):
        handler = make_handler({"max_size": 1})
    assert handler.max_size == MIB
    assert _infos(caplog) == ["store: max_size 1 MiB (from store.yaml)"]


def test_startup_line_without_a_limit(binaries, caplog, monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    with caplog.at_level("INFO", logger="store"):
        make_handler()
    assert _infos(caplog) == ["store: max_size 0 MiB (from store.yaml)"]


def test_startup_line_of_a_fraction_of_the_config(binaries, caplog, monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    with caplog.at_level("INFO", logger="store"):
        make_handler({"max_size": 0.25})
    assert _infos(caplog) == ["store: max_size 0.25 MiB (from store.yaml)"]


def test_env_replaces_the_config(binaries, caplog, monkeypatch):
    monkeypatch.setenv(ENV, "1")
    with caplog.at_level("INFO", logger="store"):
        handler = make_handler({"max_size": 1024})
    assert handler.max_size == MIB
    assert _infos(caplog) == ["store: max_size 1 MiB (from DIONAEA_STORE_MAX_SIZE)"]
    assert not [r for r in caplog.records if r.levelname == "WARNING"]
    # the limit of the variable is the one that holds
    first = store_sample(handler, binaries, b"a" * (600 * 1024))
    second = store_sample(handler, binaries, b"b" * (600 * 1024))
    assert (binaries / first).exists()
    assert not (binaries / second).exists()


def test_env_without_the_option_in_the_config(binaries, caplog, monkeypatch):
    monkeypatch.setenv(ENV, "2")
    with caplog.at_level("INFO", logger="store"):
        handler = make_handler()
    assert handler.max_size == 2 * MIB
    assert _infos(caplog) == ["store: max_size 2 MiB (from DIONAEA_STORE_MAX_SIZE)"]


def test_env_zero_is_no_limit(binaries, caplog, monkeypatch):
    monkeypatch.setenv(ENV, "0")
    with caplog.at_level("INFO", logger="store"):
        handler = make_handler({"max_size": 1})
    assert handler.max_size == 0
    assert _infos(caplog) == ["store: max_size 0 MiB (from DIONAEA_STORE_MAX_SIZE)"]
    md5 = store_sample(handler, binaries, b"a" * (2 * MIB))
    assert (binaries / md5).exists()


def test_env_replaces_an_invalid_config_without_reading_it(binaries, caplog, monkeypatch):
    monkeypatch.setenv(ENV, "3")
    with caplog.at_level("INFO", logger="store"):
        handler = make_handler({"max_size": "lots"})
    assert handler.max_size == 3 * MIB
    assert not [r for r in caplog.records if r.levelname == "WARNING"]


@pytest.mark.parametrize("value", ["2048 MiB", "-1", "+3", " 3", "1.5", "1e3", "abc", "9" * 400, "9" * 303,
                                   "1" + "0" * 303, "1099511627777"])
def test_invalid_env_warns_and_the_config_holds(binaries, caplog, monkeypatch, value):
    monkeypatch.setenv(ENV, value)
    with caplog.at_level("INFO", logger="store"):
        handler = make_handler({"max_size": 1})
    assert handler.max_size == MIB
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    # the value is cut to 64 characters (all of these are printable)
    assert warnings == ["Ignoring DIONAEA_STORE_MAX_SIZE='%s': a whole number of MiB >= 0 (decimal digits) is "
                        "expected, the value of store.yaml holds" % value[:64]]
    assert _infos(caplog) == ["store: max_size 1 MiB (from store.yaml)"]


def test_the_rejected_value_in_the_warning_is_shortened(binaries, caplog, monkeypatch):
    value = "x\n" + "7" * 198
    monkeypatch.setenv(ENV, value)
    with caplog.at_level("WARNING", logger="store"):
        make_handler({"max_size": 1})
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert "='x?%s'" % ("7" * 62) in warnings[0]
    assert "\n" not in warnings[0]


def test_empty_env_counts_as_unset(binaries, caplog, monkeypatch):
    monkeypatch.setenv(ENV, "")
    with caplog.at_level("INFO", logger="store"):
        handler = make_handler({"max_size": 1})
    assert handler.max_size == MIB
    assert not [r for r in caplog.records if r.levelname == "WARNING"]
    assert _infos(caplog) == ["store: max_size 1 MiB (from store.yaml)"]
