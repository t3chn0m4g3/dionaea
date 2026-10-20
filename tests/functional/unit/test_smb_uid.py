# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""smb.py new_uid(): the UIDs of new sessions, counted for the whole process as a Windows server does.
smbd.new_tree(): the TIDs of the trees of a connection, and the share they keep.
smbd.handle_smb1_message(): smb_message is set back to None once a message is handled.

The functions, the counter and the limits are taken from the source with ast (smb.py needs dionaea.core).
"""

import ast
import os
from pathlib import Path


def smb_source():
    """(path, ast) of smb.py"""
    root = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")
    source = root / "smb" / "smb.py"
    return source, ast.parse(source.read_text(), filename=str(source))


def load():
    source, tree = smb_source()
    nodes = [node for node in tree.body
             if (isinstance(node, ast.FunctionDef) and node.name == "new_uid")
             or (isinstance(node, ast.Assign)
                 and any(getattr(t, "id", "").startswith(("_uid", "UID_")) for t in node.targets))]
    namespace = {}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
    return namespace["new_uid"]


def test_the_first_uids_are_steps_of_0x0800():
    new_uid = load()
    assert [new_uid() for _ in range(32)] == [step * 0x0800 for step in range(1, 32)] + [0x0801]


def test_every_uid_but_0_and_0xffff_comes_once_per_round():
    new_uid = load()
    uids = [new_uid() for _ in range(0xffff - 0x0800)]
    assert len(set(uids)) == len(uids)
    assert 0 not in uids and 0xffff not in uids
    assert min(uids) == 0x0800 and max(uids) == 0xfffe
    # the next round starts again
    assert new_uid() == 0x0800


def test_uids_in_use_are_skipped():
    new_uid = load()
    assert new_uid(in_use={0x0800, 0x1000}) == 0x1800


def load_new_tree():
    source, tree = smb_source()
    nodes = [node for node in tree.body
             if isinstance(node, ast.Assign) and any(getattr(t, "id", "").startswith("MAX_") for t in node.targets)]
    smbd = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "smbd")
    nodes += [node for node in smbd.body if isinstance(node, ast.FunctionDef) and node.name == "new_tree"]
    namespace = {}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
    return namespace


class Connection:
    def __init__(self, new_tree):
        self.trees = {}
        self.next_tid = 1
        self.new_tree = new_tree.__get__(self)


def test_a_tree_keeps_at_most_256_characters_of_its_share():
    namespace = load_new_tree()
    con = Connection(namespace["new_tree"])
    tid = con.new_tree("C$")
    assert con.trees[tid] == "C$"
    long = "y" * 300 + "share"
    tid = con.new_tree(long)
    assert con.trees[tid] == long[:256]
    # the trees of a connection hold bounded memory: MAX_TREES shares of at most 256 characters
    for i in range(3 * namespace["MAX_TREES"]):
        con.new_tree("%d" % i + "z" * 100000)
    assert len(con.trees) == namespace["MAX_TREES"]
    assert max(len(share) for share in con.trees.values()) == 256


def load_smb1_message(nbt_session):
    """handle_smb1_message of smbd (and the method it delegates to), with NBTSession of the caller."""
    import struct
    source, tree = smb_source()
    smbd = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "smbd")
    nodes = [node for node in smbd.body
             if isinstance(node, ast.FunctionDef) and node.name in ("handle_smb1_message", "_handle_smb1_message")]
    namespace = {"struct": struct, "NBTSession": nbt_session, "SMB_COM_NEGOTIATE": 0x72,
                 "SMB_COM_SESSION_SETUP_ANDX": 0x73}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
    return {name: namespace[name] for name in ("handle_smb1_message", "_handle_smb1_message") if name in namespace}


class Packet:
    def __init__(self, type_):
        self.TYPE = type_

    def build(self):
        return b"\x82\x00\x00\x00"


class SmbConnection:
    def __init__(self, methods):
        self.sent = []
        self.seen = []
        for name, method in methods.items():
            setattr(self, name, method.__get__(self))

    def send(self, data):
        self.sent.append(data)


def test_smb_message_is_none_once_the_message_is_handled():
    # the SMB message of a request is kept only while it is handled (the requests of a chain)
    def session(data=None, _ctx=None, TYPE=None):
        if _ctx is not None:
            _ctx.seen.append(_ctx.smb_message)
        return Packet(0x81 if TYPE is None else TYPE)
    con = SmbConnection(load_smb1_message(session))
    con.smb_message = None
    message = b"\x81\x00\x00\x04abcd"
    assert con.handle_smb1_message(message) == len(message)
    assert con.seen == [b"abcd"]
    assert con.sent == [b"\x82\x00\x00\x00"]
    assert con.smb_message is None


def test_smb_message_is_none_after_a_message_that_raises():
    def session(data=None, _ctx=None, TYPE=None):
        raise ValueError("cannot dissect")
    con = SmbConnection(load_smb1_message(session))
    con.smb_message = None
    try:
        con.handle_smb1_message(b"\x81\x00\x00\x04abcd")
    except ValueError:
        pass
    else:
        raise AssertionError("ValueError expected")
    assert con.smb_message is None
