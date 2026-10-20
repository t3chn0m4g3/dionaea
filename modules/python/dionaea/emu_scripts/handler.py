# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import re
from bisect import bisect_right
from urllib.parse import urlsplit

logger = logging.getLogger("emu_scripts")


def _as_bytes(data):
    """The downloaded file is read as bytes, the regular expressions are bytes patterns."""
    if isinstance(data, str):
        return data.encode("utf-8", errors="replace")
    return data


def _url_str(url):
    """The URL of a match (bytes, ASCII only: \\w of a bytes pattern) as str for the incident."""
    return url.decode("ascii")


class BaseHandler(object):
    name = ""

    def __init__(self, config=None):
        self._config = {}
        if isinstance(config, dict):
            self._config = config

        self.min_match_count = 0
        self._regex_detect = []

        self._regex_url = re.compile(
            rb"(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)"
        )

    def run(self, data):
        data = _as_bytes(data)
        match_count = 0
        for regex in self._regex_detect:
            m = regex.search(data)
            if m:
                match_count += 1

        if match_count < self.min_match_count:
            logger.info("Match count for %s is %d should at least be %d", self.name, match_count, self.min_match_count)
            return

        logger.info("Looking for URLs '%s'", self.name)
        urls = []
        for m in self._regex_url.finditer(data):
            urls.append(_url_str(m.group("url")))
        return urls


class RawURL(object):
    name = "raw_url"

    def __init__(self, config=None):
        self._config = {}
        if isinstance(config, dict):
            self._config = config

        self._regex_url = re.compile(
            rb"(?P<url>(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?)"
        )

    def run(self, data):
        data = _as_bytes(data)
        urls = []
        for m in self._regex_url.finditer(data):
            urls.append(_url_str(m.group("url")))
        return urls


# Stagers: the calls of a script that fetch a file, and what of their arguments is
# the URL. All patterns are bounded: no quantifier inside another one without a
# length cap, so any file costs linear time. Only the URL is taken
# from a script, nothing of it is run; the URL goes the way of every offer (the
# download handlers check its destination).
MAX_STAGERS = 256    # calls looked at per pattern and file
MAX_URLS = 64        # URLs per file (emu_scripts offers at most max_subdownloads)
MAX_PARTS = 16       # literals of one concatenation
MAX_ARGUMENTS = 16   # arguments of a cmdlet looked at

_URL = re.compile(rb"(?:https?|ftp)://[\w\-.~:/?#@!$&*+=%]{1,2048}", re.I)
# a string literal: '...' or "...", on one line
_LITERAL = re.compile(rb"""[ \t]{0,16}(?:'(?P<single>[^'\r\n]{0,2048})'|"(?P<double>[^"\r\n]{0,2048})")""")
# + (PowerShell) or & (VBScript) between two literals
_CONCAT = re.compile(rb"[ \t]{0,16}[+&]")
_OPEN_PARENS = re.compile(rb"[ \t(]{0,16}")
_PS_VARIABLE = re.compile(rb"[ \t]{0,16}\$(?P<name>[\w:]{1,64})")
_VB_VARIABLE = re.compile(rb"[ \t]{0,16}(?P<name>[A-Za-z_]\w{0,63})")
# an assignment of a literal to a variable: $name = '...' / name = "..."
_PS_ASSIGNMENT = re.compile(rb"\$(?P<name>[\w:]{1,64})[ \t]{0,16}=(?=[ \t]{0,16}['\"])")
_VB_ASSIGNMENT = re.compile(rb"(?<![\w.$])(?P<name>[A-Za-z_]\w{0,63})[ \t]{0,16}=(?=[ \t]{0,16}\")")
MAX_ASSIGNMENTS = 4096
# assignments of a variable looked at before a use, from the last one back (the ones in comments are skipped)
MAX_ASSIGNMENTS_BACK = 8

# Comments: their spans are found in one pass over the file, together with the string
# literals (a "#" or "'" inside a string starts no comment); after MAX_TOKENS strings and
# comments the rest of the file counts as code.
MAX_TOKENS = 16384
_PS_TOKEN = re.compile(rb"""'[^']*'|"[^"]*"|(?P<block><\#)|(?P<line>\#[^\r\n]*)""")
_VB_TOKEN = re.compile(
    rb"""(?im)"[^"\r\n]*"|(?P<line>'[^\r\n]*|(?:^|(?<=:))[ \t]*rem(?![\w])[^\r\n]*)""")

# PowerShell: (New-Object Net.WebClient).DownloadString('...'), .DownloadFile, .DownloadData
_PS_WEBCLIENT = re.compile(rb"\.[ \t]{0,16}Download(?:String|File|Data)(?:Async|TaskAsync)?[ \t]{0,16}\(", re.I)
# PowerShell: Invoke-WebRequest / iwr, Invoke-RestMethod / irm, Start-BitsTransfer
# (the first letter as a class, the look behind after it: the regex module then scans for the
# class, about 5 ms per MiB instead of 27 with the look behind at every position; a look behind
# for the letter then picks its cmdlets, so swr or itart-BitsTransfer are none)
_PS_CMDLET = re.compile(
    rb"[iIsS](?<![\w-][iIsS])(?:(?<=[iI])(?:nvoke-WebRequest|nvoke-RestMethod|wr|rm)|(?<=[sS])tart-BitsTransfer)"
    rb"(?![\w-])", re.I)
_PS_PARAMETER = re.compile(rb"[ \t]{0,64}-[A-Za-z]\w{0,31}:?(?=[ \t\"'$]|$)")
_PS_BARE = re.compile(rb"""[ \t]{0,64}(?P<bare>[^\s'"`;|(){},]{1,2048})""")
_PS_END = re.compile(rb"[ \t]{0,64}(?:[;|)}\r\n]|$)")
# VBScript: CreateObject("MSXML2.XMLHTTP") / ("WinHttp.WinHttpRequest.5.1") ... .Open "GET", url
_VB_OBJECT = re.compile(
    rb"[cC]reateObject[ \t]{0,16}\([ \t]{0,16}[\"'](?:(?:MSXML2|Microsoft)\.(?:Server)?XMLHTTP"
    rb"|WinHttp\.WinHttpRequest|WScript\.Shell)", re.I)
_VB_OPEN = re.compile(rb"\.[ \t]{0,16}Open[ \t]{0,16}\(?[ \t]{0,16}(?:\"GET\"|'GET')[ \t]{0,16},", re.I)


def _url(value):
    """value (bytes) as an URL str if it is one as a whole, else None. The scheme is in lower case."""
    if value is None or _URL.fullmatch(value) is None:
        return None
    url = value.decode("ascii")
    try:
        if not urlsplit(url).hostname:
            return None
    except ValueError:
        return None
    scheme, rest = url.split("://", 1)
    return scheme.lower() + "://" + rest


def _literal_at(data, pos):
    """
    A literal, or a simple concatenation of literals ('a' + 'b', "a" & "b"), at pos.

    :return: (value, end), value None if there is none or the concatenation goes on
        with something else than a literal (code: its value is not known)
    """
    parts = []
    while True:
        m = _LITERAL.match(data, pos)
        if m is None:
            return None, pos
        parts.append(m.group("single") if m.group("single") is not None else m.group("double"))
        pos = m.end()
        concat = _CONCAT.match(data, pos)
        if concat is None:
            return b"".join(parts), pos
        if len(parts) >= MAX_PARTS:
            return None, pos
        pos = concat.end()


class _Comments(object):
    """The comments of a file: (start, end) spans, found on the first question (one pass)."""

    def __init__(self, data, token):
        self._data = data
        self._token = token
        self._starts = None
        self._ends = None

    def _find(self):
        self._starts, self._ends = [], []
        data, pos = self._data, 0
        for _ in range(MAX_TOKENS):
            m = self._token.search(data, pos)
            if m is None:
                return
            pos = m.end()
            if m.groupdict().get("block") is not None:
                # <# ... #>, one not closed runs to the end
                close = data.find(b"#>", pos)
                pos = len(data) if close < 0 else close + 2
                self._starts.append(m.start())
                self._ends.append(pos)
                if close < 0:
                    return
            elif m.group("line") is not None:
                self._starts.append(m.start("line"))
                self._ends.append(m.end())
            if pos == m.start():
                pos += 1

    def inside(self, pos):
        """True if pos is inside a comment."""
        if self._starts is None:
            self._find()
        i = bisect_right(self._starts, pos) - 1
        return i >= 0 and pos < self._ends[i]


class _Assignments(object):
    """The literals assigned to the variables of a file, made on the first lookup (one pass)."""

    def __init__(self, data, pattern, fold_case, comments):
        self._data = data
        self._pattern = pattern
        self._fold = fold_case
        self._comments = comments
        self._index = None
        # value of the assignment whose literal starts at a position
        self._values = {}

    def _key(self, name):
        return name.lower() if self._fold else name

    def value(self, name, before):
        """The value of the last assignment of a literal to name before the position before (None: not known)."""
        if self._index is None:
            self._index = {}
            for count, m in enumerate(self._pattern.finditer(self._data)):
                if count >= MAX_ASSIGNMENTS:
                    break
                starts, ends = self._index.setdefault(self._key(m.group("name")), ([], []))
                starts.append(m.start())
                ends.append(m.end())
        starts, ends = self._index.get(self._key(name), ((), ()))
        last = bisect_right(ends, before)
        for i in range(last - 1, max(last - 1 - MAX_ASSIGNMENTS_BACK, -1), -1):
            if self._comments.inside(starts[i]):
                continue
            pos = ends[i]
            if pos not in self._values:
                self._values[pos] = _literal_at(self._data, pos)[0]
            return self._values[pos]
        return None


class _Urls(object):
    """URLs in the order they were found, each once, at most MAX_URLS."""

    def __init__(self):
        self.urls = {}

    def add(self, url):
        if url is not None and len(self.urls) < MAX_URLS:
            self.urls.setdefault(url, None)

    def list(self):
        return list(self.urls)


def _argument_url(data, pos, variable, assignments):
    """The URL of the first argument of a method call at pos: a literal, a concatenation or a variable."""
    pos = _OPEN_PARENS.match(data, pos).end()
    value, _ = _literal_at(data, pos)
    if value is None:
        m = variable.match(data, pos)
        if m is None:
            return None
        value = assignments.value(m.group("name"), m.start())
    return _url(value)


def _cmdlet_url(data, pos, assignments):
    """The first argument of a cmdlet that is an URL (-Uri / -Source or positional)."""
    for _ in range(MAX_ARGUMENTS):
        if _PS_END.match(data, pos):
            return None
        m = _PS_PARAMETER.match(data, pos)
        if m is not None:
            pos = m.end()
            continue
        start = _OPEN_PARENS.match(data, pos).end()
        value, end = _literal_at(data, start)
        if value is None:
            if _LITERAL.match(data, start):
                # a concatenation with code
                return None
            m = _PS_VARIABLE.match(data, start)
            if m is not None:
                value, end = assignments.value(m.group("name"), m.start()), m.end()
            else:
                m = _PS_BARE.match(data, start)
                if m is None:
                    return None
                value, end = m.group("bare"), m.end()
        url = _url(value)
        if url is not None:
            return url
        pos = end
    return None


class PowerShell(BaseHandler):
    name = "powershell"

    def __init__(self, config=None):
        BaseHandler.__init__(self, config=config)

        # the earlier detection: two of these, then the URLs assigned to variables
        self.min_match_count = 2
        self._regex_detect = [
            re.compile(rb"[nN]ew-Object[ \t]{1,16}(?:System\.)?Net\.WebClient", re.I),
            re.compile(rb"[dD]ownloadFile[ \t]{0,16}\([^,()\r\n]{1,512},", re.I),
            re.compile(rb"[iI]nvoke-Expression[^)\r\n]", re.I),
        ]

        self._regex_url = re.compile(
            # name = "url" (the scan is for the "=", the name only looked at behind it)
            rb"(?<=[\w \t])=[ \t]{0,16}\"[ \t]{0,16}"
            rb"(?P<url>(?:https?|ftp)://[\w\-.~:/?#@!$&*+=%]{1,2048})[ \t]{0,16}\"",
            re.I
        )

    def run(self, data):
        data = _as_bytes(data)
        urls = _Urls()
        comments = _Comments(data, _PS_TOKEN)
        assignments = _Assignments(data, _PS_ASSIGNMENT, True, comments)
        for count, m in enumerate(_PS_WEBCLIENT.finditer(data)):
            if count >= MAX_STAGERS:
                break
            if not comments.inside(m.start()):
                urls.add(_argument_url(data, m.end(), _PS_VARIABLE, assignments))
        for count, m in enumerate(_PS_CMDLET.finditer(data)):
            if count >= MAX_STAGERS:
                break
            if not comments.inside(m.start()):
                urls.add(_cmdlet_url(data, m.end(), assignments))

        detected = sum(1 for regex in self._regex_detect if regex.search(data))
        if detected >= self.min_match_count:
            for count, m in enumerate(self._regex_url.finditer(data)):
                if count >= MAX_STAGERS:
                    break
                if not comments.inside(m.start()):
                    urls.add(_url(m.group("url")))
        elif not urls.urls:
            logger.debug("No stager of %s found", self.name)
            return None
        logger.info("Looking for URLs '%s'", self.name)
        return urls.list()


class VBScript(BaseHandler):
    name = "vbscript"

    def run(self, data):
        data = _as_bytes(data)
        if _VB_OBJECT.search(data) is None:
            logger.debug("No HTTP object of %s found", self.name)
            return None
        urls = _Urls()
        comments = _Comments(data, _VB_TOKEN)
        assignments = _Assignments(data, _VB_ASSIGNMENT, True, comments)
        for count, m in enumerate(_VB_OPEN.finditer(data)):
            if count >= MAX_STAGERS:
                break
            if not comments.inside(m.start()):
                urls.add(_argument_url(data, m.end(), _VB_VARIABLE, assignments))
        logger.info("Looking for URLs '%s'", self.name)
        return urls.list()
