#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wcphunt.py - web cache poisoning detection

The whole vulnerability class is one sentence: a cache stores a response under
a KEY, and anything the application reads that is not in that key is an
unkeyed input. Control an unkeyed input, make the response harmful, and the
cache hands your response to everyone whose request produces the same key.

So the tool never asks "does my input change the response?" -- that question
has a yes for any reflective page, cache or no cache. It asks the only
question that matters:

    does a request that carries NOTHING of mine come back carrying my canary?

If it does, the input is unkeyed AND the response was cached AND the cache
served it to a request that never asked for it. One test, three facts, no
inference. A page that reflects but is never cached answers no, which is
correct: it is not a web cache poisoning finding.

SAFETY. Every request carries a unique cache buster, so the tool works inside
its own cache key and cannot poison an entry a real visitor would receive.
That is a structural property, not a flag: the buster is minted per test unit
and there is no code path that omits it. Before testing a target the tool also
VERIFIES that the buster actually partitions the cache -- a CDN that strips
unknown parameters from the key would silently turn every test into a live
poisoning -- and refuses the target when it does not.

Vectors are opt-in, one --enable-* each:

    --enable-headers     unkeyed request headers (X-Forwarded-Host & co)
    --enable-params      unkeyed query parameters (tracking params)
    --enable-norm        cache key normalization and delimiter discrepancies
    --enable-deception   cache deception: the victim's private response stored
                         under a URL the attacker can fetch
"""

import argparse
import html
import http.client
import ssl
import json
import os
import random
import re
import string
import sys
import threading
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field, asdict

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

VERSION = "1.7.1"

# A page where a quarter of the vocabulary moves between two identical
# requests is not a stable page with noise in it, it is dynamic content.
MAX_VOLATILE_RATIO = 0.25

CANARY_ALPHABET = string.ascii_lowercase + string.digits


# ----------------------------------------------------------------------------
# output
# ----------------------------------------------------------------------------

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"

    @classmethod
    def off(cls):
        for k in list(vars(cls)):
            if k.isupper():
                setattr(cls, k, "")


class Reporter:
    """Verbosity-aware, thread-safe console reporter.

    0 = successes only, 1 = every test performed, 2 = debug (full request,
    exact payload, response status and size, and what was skipped and why).
    """

    def __init__(self, level=0):
        self.level = level
        self.lock = threading.Lock()

    def _emit(self, text):
        with self.lock:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()

    def line(self, text):
        self._emit(text)

    def info(self, msg):
        if self.level >= 1:
            self._emit("%s[*]%s %s" % (Colors.BLUE, Colors.RESET, msg))

    def warn(self, msg):
        self._emit("%s[!]%s %s" % (Colors.YELLOW, Colors.RESET, msg))

    def auth(self, msg):
        self._emit("%s[auth]%s %s" % (Colors.MAGENTA, Colors.RESET, msg))

    def test(self, msg):
        if self.level >= 1:
            self._emit("%s[.]%s %s" % (Colors.GREY, Colors.RESET, msg))

    def dbg(self, msg):
        if self.level >= 2:
            self._emit("%s[d]%s %s" % (Colors.GREY, Colors.RESET, msg))

    def skip(self, msg):
        if self.level >= 2:
            self._emit("%s[-]%s %s" % (Colors.GREY, Colors.RESET, msg))

    def hit(self, f):
        c = Colors
        badge = (" %s%s[CONFIRMED]%s" % (c.CYAN, c.BOLD, c.RESET)
                 if f.confirmed else "")
        # Not every finding is a poisoning. Reading the cache's own key back
        # is information -- valuable, often decisive for the rest of the run,
        # but nobody is compromised by it, and printing it in the same green
        # as a confirmed poisoning would devalue both.
        if f.level == "info":
            # Yellow, and printed at every verbosity like any other finding.
            # This one only ever appeared as a debug line in practice, which
            # made it useless to anyone not running -v 2 -- and it is the
            # piece of information that explains every other result on the
            # page.
            tag, col, badge = "[CACHE KEY]", c.YELLOW, ""
        else:
            tag, col = "[POISONED]", c.GREEN
        lines = [
            "",
            "%s%s%s%s%s %s%s%s"
            % (col, c.BOLD, tag, c.RESET, badge, c.BOLD, f.kind, c.RESET),
            "  %sURL      :%s %s" % (c.CYAN, c.RESET, f.url),
            "  %sVector   :%s %s" % (c.CYAN, c.RESET, f.vector),
            "  %sInput    :%s %s (%s)" % (c.CYAN, c.RESET, f.name, f.location),
            "  %sPayload  :%s %s%s%s"
            % (c.CYAN, c.RESET, c.YELLOW, f.payload, c.RESET),
            "  %sEvidence :%s %s" % (c.CYAN, c.RESET, f.evidence),
        ]
        if f.confirmed:
            if f.proof:
                proof = f.proof
            elif f.vector == "deception":
                proof = ("the victim's own response was served to a request "
                         "with no session, out of the cache")
            elif f.vector == "cache-key":
                proof = ("the cache answered a URL it had never been asked "
                         "for, so the key ignores what the URL says")
            else:
                proof = ("a request carrying none of the above came back "
                         "with the canary, out of the cache")
            lines.append("  %sProof    :%s %s%s%s"
                         % (c.CYAN, c.RESET, c.RED, proof, c.RESET))
        if f.poc:
            lines.append("  %sPoC      :%s %s" % (c.CYAN, c.RESET, f.poc))
        self._emit("\n".join(lines))


class Status:
    """Heartbeat for -l mode. One host needs no queue accounting."""

    def __init__(self, reporter, total, interval=30.0, enabled=True):
        self.rep = reporter
        self.total = total
        self.interval = interval
        self.enabled = enabled
        self.done = 0
        self.counts = {"confirmed": 0, "unkeyed": 0, "observed": 0,
                       "declined": 0}
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
        while not self._stop.wait(self.interval):
            self.emit()

    def url_done(self, n=1):
        with self._lk:
            self.done += n

    def record(self, what):
        with self._lk:
            if what in self.counts:
                self.counts[what] += 1

    def emit(self, label="status"):
        if not self.enabled:
            return
        with self._lk:
            done, c = self.done, dict(self.counts)
        remaining = max(0, self.total - done)
        el = int(time.time() - self._t0)
        self.rep.line(
            "%s  [%s %02d:%02d]  tested %d/%d  remaining %d  |  "
            "confirmed %d  unkeyed %d  declined %d%s"
            % (Colors.CYAN, label, el // 60, el % 60, done, self.total,
               remaining, c["confirmed"], c["unkeyed"], c["declined"],
               Colors.RESET))

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)


# ----------------------------------------------------------------------------
# text: normalisation and similarity
# ----------------------------------------------------------------------------

_TOKEN_FIELDS = re.compile(
    r'(?i)(<input[^>]+(?:csrf|token|nonce|authenticity)[^>]*value=)'
    r'(["\'])(.*?)\2')
# Scripts are NOT stripped here, and that is deliberate.
#
# The SQLi tool this was ported from deletes script elements wholesale, to cut
# noise. Applied to cache poisoning it deletes the finding: a poisoned
# absolute URL lands in a script's src, and a poisoned value lands in the JSON
# blob a page prints inside <script>data = {...}</script>. Both shapes were
# measured on a lab route proven poisonable by hand, and both times the tool
# stayed silent because normalisation had already thrown the canary away --
# first with the tag, then with the body.
#
# Inline scripts really do carry build hashes and per-render state. That is
# what the calibration is for: it learns what THIS page changes on its own and
# masks exactly that, instead of deleting a whole region on the assumption
# that nothing in it could matter.
_NOISE = [
    re.compile(r'(?is)<!--.*?-->'),
    re.compile(r'\s+'),
]


def blank_token_fields(body):
    """Blank the value of the token-shaped inputs a page re-issues per render.

    Structural rather than statistical: these are known to move and known to
    carry no information about what we injected.
    """
    return _TOKEN_FIELDS.sub(lambda m: m.group(1) + m.group(2) + m.group(2),
                             body or "")


def normalize(body):
    out = html.unescape(blank_token_fields(body or ""))
    for rx in _NOISE[:-1]:
        out = rx.sub("", out)
    return _NOISE[-1].sub(" ", out).strip()


def shingles(text, k=5):
    """Overlapping word n-grams.

    Anchored to the text's own words, not to absolute offsets: a fixed-width
    character window desynchronises after any deletion, which makes similarity
    depend on WHERE a difference sits rather than on how big it is.
    """
    words = text.split(" ")
    if len(words) <= k:
        return {text}
    return {" ".join(words[i:i + k]) for i in range(len(words) - k + 1)}


def similarity(a, b):
    """0.0 (nothing in common) .. 1.0 (identical after normalisation)."""
    if a == b:
        return 1.0
    sa, sb = shingles(a), shingles(b)
    if not sa or not sb:
        return 1.0 if sa == sb else 0.0
    return len(sa & sb) / float(len(sa | sb))


class PageNoise:
    """What a page changes on its own, learned from repeated identical requests.

    Every oracle here rests on "same request, same page". That premise is not
    free: a page re-issuing an anti-CSRF token differs from itself, and a tool
    that simply diffs two responses reads that as a finding. Calibration turns
    the premise into a measurement -- the words that differ across two
    IDENTICAL requests carry no information by construction and are dropped
    from every later comparison.

    Uncalibrated this is the identity function: nothing changes for a target
    that was already deterministic.
    """

    def __init__(self):
        self.words = frozenset()
        self.raw_sim = 1.0
        self.self_sim = 1.0
        self.calibrated = False
        self.too_dynamic = False

    def apply(self, norm_text):
        if not self.words:
            return norm_text
        return " ".join(w for w in norm_text.split(" ") if w not in self.words)

    def learn(self, bodies):
        norms = [normalize(b) for b in bodies if b is not None]
        if len(norms) < 2:
            return
        self.calibrated = True
        pairs = [(norms[i], norms[j])
                 for i in range(len(norms)) for j in range(i + 1, len(norms))]
        self.raw_sim = min(similarity(a, b) for a, b in pairs)
        if self.raw_sim >= 1.0:
            self.self_sim = 1.0
            return
        sets = [set(n.split(" ")) for n in norms]
        union = set().union(*sets)
        common = set(sets[0]).intersection(*sets[1:])
        volatile = union - common
        if union and len(volatile) > MAX_VOLATILE_RATIO * len(union):
            self.too_dynamic = True
            self.self_sim = self.raw_sim
            return
        self.words = frozenset(volatile)
        masked = [self.apply(n) for n in norms]
        mp = [(masked[i], masked[j])
              for i in range(len(masked)) for j in range(i + 1, len(masked))]
        self.self_sim = min(similarity(a, b) for a, b in mp)

    def describe(self):
        if not self.calibrated:
            return "page stability: not measured"
        if self.raw_sim >= 1.0:
            return "page stability: identical requests give identical pages"
        if self.too_dynamic:
            return ("page stability: %.3f against itself and too much of it "
                    "moves to mask" % self.raw_sim)
        return ("page stability: %.3f against itself, %d volatile token(s) "
                "masked -> %.3f"
                % (self.raw_sim, len(self.words), self.self_sim))


# ----------------------------------------------------------------------------
# cookies and auth
# ----------------------------------------------------------------------------

def parse_cookie_header(value):
    jar = {}
    for part in (value or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        if k.strip():
            jar[k.strip()] = v.strip()
    return jar


def build_cookie_header(jar):
    return "; ".join("%s=%s" % (k, v) for k, v in jar.items())


class AuthStore:
    """Per-host authentication headers, loaded once and consulted per request.

    Keyed by (host, port) and resolved at request time, so credentials reach
    the host they belong to and no other. In -l mode a session cookie given
    with -H goes to every host in the list, including third parties; this does
    not.

        www.example.com.txt        every port of that host
        www.example.com_8080.txt   that port only, and it wins over the above

    No implicit subdomain inheritance: a file for example.com does NOT
    authenticate app.example.com.
    """

    def __init__(self):
        self.forced = {}
        self.by_key = {}
        self.loaded = []

    @staticmethod
    def _parse(path, rep):
        out = {}
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip().lstrip("﻿")
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    rep.warn("%s:%d: no ':' - line ignored: %s"
                             % (os.path.basename(path), n, line[:60]))
                    continue
                k, _, v = line.partition(":")
                if k.strip():
                    out[k.strip()] = v.strip()
        return out

    @staticmethod
    def _key_from_name(name):
        stem = name[:-4] if name.lower().endswith(".txt") else name
        host, sep, tail = stem.rpartition("_")
        if sep and host and tail.isdigit():
            return host.lower(), int(tail)
        return stem.lower(), None

    @classmethod
    def load(cls, auth_file, auth_dir, rep):
        st = cls()
        if auth_file:
            if not os.path.isfile(auth_file):
                raise ValueError("no such auth file: %s" % auth_file)
            st.forced = cls._parse(auth_file, rep)
            st.loaded.append((auth_file, "every target"))
        elif auth_dir:
            if not os.path.isdir(auth_dir):
                raise ValueError("no such auth directory: %s" % auth_dir)
            for name in sorted(os.listdir(auth_dir)):
                if name.startswith(".") or not name.lower().endswith(".txt"):
                    continue
                path = os.path.join(auth_dir, name)
                if not os.path.isfile(path):
                    continue
                host, port = cls._key_from_name(name)
                st.by_key[(host, port)] = cls._parse(path, rep)
                st.loaded.append(
                    (path, host if port is None else "%s:%d" % (host, port)))
        return st

    def __bool__(self):
        return bool(self.forced or self.by_key)

    def describe(self, rep):
        if not self.loaded:
            return
        rep.auth("%d auth file(s) loaded" % len(self.loaded))
        for path, scope in self.loaded:
            rep.info("  auth %s -> %s" % (os.path.basename(path), scope))

    @staticmethod
    def _key(url):
        p = urllib.parse.urlsplit(url)
        host = (p.hostname or "").lower()
        port = p.port or (443 if p.scheme == "https" else 80)
        return host, port

    def headers_for(self, url):
        if self.forced:
            return dict(self.forced)
        host, port = self._key(url)
        return dict(self.by_key.get((host, port))
                    or self.by_key.get((host, None)) or {})


# ----------------------------------------------------------------------------
# candidate inputs
# ----------------------------------------------------------------------------

# A closed, documented set -- not an open wordlist. These are the headers
# frameworks and reverse proxies are known to read, and discovering that an
# application reads X-Forwarded-Host requires sending it: there is no passive
# way to learn it. Extend with --headers-file for a framework or CDN met in
# the field.
CANDIDATE_HEADERS = [
    # host / URL reconstruction -- the classic
    "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-HTTP-Host-Override",
    "Forwarded", "X-Original-Host", "X-Real-Host",
    # scheme, which flips redirects and absolute links
    "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Forwarded-Protocol",
    "X-Forwarded-Ssl", "Front-End-Https", "X-Url-Scheme",
    # path override -- changes what is served without changing the key
    "X-Original-URL", "X-Rewrite-URL", "X-Override-URL", "X-HTTP-Path-Override",
    # port, which lands in absolute URLs
    "X-Forwarded-Port",
    # client address, often reflected in debug or geo blocks
    "X-Forwarded-For", "X-Real-IP", "True-Client-IP", "CF-Connecting-IP",
    "X-Client-IP", "X-Cluster-Client-IP",
    # content negotiation and CORS
    "Origin", "X-Requested-With", "Accept-Language",
    # framework and CDN specific
    "X-Wap-Profile", "Profile", "X-Amz-Website-Redirect-Location",
    "X-Akamai-Edgescape", "Fastly-Client-IP", "X-Timezone", "X-Country-Code",
    "X-Locale", "X-Tenant", "X-Api-Version",
]

# Parameters CDNs commonly exclude from the cache key to raise the hit rate.
CANDIDATE_PARAMS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "fbclid", "gclid", "msclkid", "mc_cid", "mc_eid", "ref", "referrer",
    "src", "source", "cb", "_", "v", "ts", "t",
]

# Suffixes appended to the PATH. Each models one way a cache and an origin can
# disagree about where the path ends.
NORM_SUFFIXES = [
    (";{p}={c}", "matrix parameter after ';'"),
    ("%3b{p}={c}", "encoded ';'"),
    ("%23{p}={c}", "encoded '#'"),
    ("%3f{p}={c}", "encoded '?'"),
    ("/%2e%2e/{c}", "encoded traversal"),
]

# Extensions a cache may store on sight, whatever the origin said.
DECEPTION_SUFFIXES = [".css", ".js", ".png", ".ico", ".svg", ".woff2"]

CACHE_HINT_HEADERS = ("x-cache", "x-cache-hits", "cf-cache-status", "age",
                      "x-served-by", "x-varnish", "x-drupal-cache",
                      "x-proxy-cache", "cdn-cache", "x-cache-status",
                      "x-iinfo", "x-akamai-request-id", "fastly-debug-digest")


# Observed headers are candidates too, but not these. Host and
# Content-Length would break the request; Cookie has its own vector, which
# tests each cookie separately instead of replacing the session wholesale;
# Authorization is a credential, like the auth-file headers.
NEVER_INJECT = frozenset({
    "host", "content-length", "cookie", "authorization", "connection",
    "transfer-encoding", "content-type",
})


def canary(n=10):
    return "wcp" + "".join(random.choice(CANARY_ALPHABET) for _ in range(n))


@dataclass
class Finding:
    url: str
    vector: str
    kind: str
    name: str
    location: str
    payload: str
    evidence: str = ""
    poc: str = ""
    confirmed: bool = False
    level: str = "poisoned"     # "poisoned" or "info"
    proof: str = ""
    cache_key_url: str = ""

    def ident(self):
        return "%s|%s|%s" % (self.url, self.vector, self.name)


@dataclass
class Response:
    status: int = 0
    body: str = ""
    headers: dict = field(default_factory=dict)
    elapsed: float = 0.0
    error: str = ""

    @property
    def ok(self):
        return self.status > 0 and not self.error

    def header(self, name):
        n = name.lower()
        for k, v in self.headers.items():
            if k.lower() == n:
                return v
        return ""


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------

class Http:
    """One request layer for the whole tool.

    Carries the operator's headers, the per-host auth headers, the proxy and
    the global rate limit. The delay is enforced ACROSS threads, not per
    thread: a 0.2s gap with 5 workers is not a 0.2s gap.
    """

    def __init__(self, args, auth, rep):
        self.args = args
        self.auth = auth
        self.rep = rep
        self.cli_headers = {}
        for h in (args.header or []):
            if ":" in h:
                k, _, v = h.partition(":")
                self.cli_headers[k.strip()] = v.strip()
        self.proxies = ({"http": args.proxy, "https": args.proxy}
                        if args.proxy else None)
        self._gap_lock = threading.Lock()
        self._sent_lock = threading.Lock()
        self._last = 0.0
        self.sent = 0

    def cookie_jar(self, url):
        """Every cookie this URL should carry, and which of them are credentials.

        Merged cookie BY COOKIE rather than header by header: a Cookie given
        with -H must not wipe out the session the auth file supplies, and the
        other way round. Precedence inside the jar is -H over the auth file
        over the captured request, which is the order the rest of the suite
        uses.

        The second return value is the set of cookie names that came from an
        auth file. Those are credentials: injecting into them destroys the
        session and tests nothing, so they are carried and never touched.
        """
        jar, credentials = {}, set()
        for k, v in self.auth.headers_for(url).items():
            if k.lower() == "cookie":
                cj = parse_cookie_header(v)
                jar.update(cj)
                credentials |= {n.lower() for n in cj}
        for k, v in self.cli_headers.items():
            if k.lower() == "cookie":
                jar.update(parse_cookie_header(v))
        return jar, credentials

    def headers_for(self, url, extra=None):
        """Auth file first, then -H, then the per-request extras.

        -H wins over the auth file by design; the extras are the tool's own
        injection and win over both, since that is the point of the test.
        """
        h = {k: v for k, v in self.auth.headers_for(url).items()
             if k.lower() != "cookie"}
        h.update({k: v for k, v in self.cli_headers.items()
                  if k.lower() != "cookie"})
        jar, _ = self.cookie_jar(url)
        if jar:
            h["Cookie"] = build_cookie_header(jar)
        if extra:
            h.update(extra)
        h.setdefault("User-Agent",
                     "Mozilla/5.0 (X11; Linux x86_64) wcphunt/" + VERSION)
        return h

    def _throttle(self):
        if self.args.delay <= 0:
            return
        with self._gap_lock:
            wait = self._last + self.args.delay - time.time()
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()

    def raw_get(self, url, extra=None, no_auth=False):
        """Send the path EXACTLY as written, byte for byte.

        requests normalises the request target, and that is fatal to a test
        whose whole subject IS the spelling of the path. Measured against a
        socket that echoes the request line: requests turns /x%61 into /xa on
        the wire, and turns /x<b> into /x%3Cb%3E. Either rewrite repairs the
        very asymmetry the test is looking for, so this path goes through
        http.client, which sends the target verbatim.

        No proxy support: http.client would have to speak to the proxy itself,
        and a half-working proxy path is worse than an honest refusal.
        """
        if self.args.proxy:
            return Response(error="raw-path request cannot go through -x")
        self._throttle()
        p = urllib.parse.urlsplit(url)
        target = p.path + (("?" + p.query) if p.query else "")
        h = self.headers_for(url, extra)
        if no_auth:
            for k in list(h):
                if k.lower() in ("cookie", "authorization"):
                    del h[k]
        t0 = time.time()
        try:
            if p.scheme == "https":
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(
                    p.hostname, p.port or 443, timeout=self.args.timeout,
                    context=ctx)
            else:
                conn = http.client.HTTPConnection(
                    p.hostname, p.port or 80, timeout=self.args.timeout)
            conn.putrequest("GET", target, skip_accept_encoding=True)
            for k, v in h.items():
                if k.lower() not in ("host", "content-length"):
                    conn.putheader(k, v)
            conn.putheader("Accept-Encoding", "identity")
            conn.endheaders()
            r = conn.getresponse()
            data = r.read()
            resp = Response(status=r.status,
                            body=data.decode("utf-8", "replace"),
                            headers=dict(r.getheaders()),
                            elapsed=time.time() - t0)
            conn.close()
        except Exception as e:
            self.rep.dbg("raw request failed %s : %s" % (url, e))
            return Response(error=str(e), elapsed=time.time() - t0)
        with self._sent_lock:
            self.sent += 1
        self.rep.dbg("GET(raw) %s -> %d, %d bytes"
                     % (target, resp.status, len(resp.body)))
        return resp

    def get(self, url, extra=None, method="GET", body=None, no_auth=False):
        self._throttle()
        h = self.headers_for(url, extra)
        if no_auth:
            for k in list(h):
                if k.lower() in ("cookie", "authorization"):
                    del h[k]
        t0 = time.time()
        try:
            r = requests.request(method, url, headers=h, data=body,
                                 timeout=self.args.timeout, verify=False,
                                 allow_redirects=False, proxies=self.proxies)
        except Exception as e:
            self.rep.dbg("request failed %s : %s" % (url, e))
            return Response(error=str(e), elapsed=time.time() - t0)
        with self._sent_lock:
            self.sent += 1
        resp = Response(status=r.status_code, body=r.text,
                        headers=dict(r.headers), elapsed=time.time() - t0)
        self.rep.dbg("%s %s -> %d, %d bytes%s"
                     % (method, url, resp.status, len(resp.body),
                        (", extra " + repr(extra)) if extra else ""))
        return resp


# ----------------------------------------------------------------------------
# URLs and the cache buster
# ----------------------------------------------------------------------------

def _enc(x):
    return urllib.parse.quote(x, safe="")


def _segments(query, drop=None):
    """The query string as it was WRITTEN, minus one name.

    parse_qsl + urlencode is a round trip, not an identity: '?flag' comes
    back as '?flag=', '%2F' and '+' are respelled, and repeated names are
    reordered. Every one of those rewrites changes the cache key -- so the
    key the tool tests stops being the key the victim produces, which is the
    one thing this tool cannot afford to get wrong.
    """
    out = []
    for seg in query.split("&"):
        if not seg:
            continue
        k = urllib.parse.unquote_plus(seg.split("=", 1)[0])
        if drop is None or k != drop:
            out.append(seg)
    return out


def add_params(url, pairs):
    p = urllib.parse.urlsplit(url)
    q = _segments(p.query) + ["%s=%s" % (_enc(k), _enc(v)) for k, v in pairs]
    return urllib.parse.urlunsplit(
        (p.scheme, p.netloc, p.path, "&".join(q), p.fragment))


def set_param(url, name, value):
    """Set a query parameter, replacing it if it is already there."""
    p = urllib.parse.urlsplit(url)
    q = _segments(p.query, drop=name) + ["%s=%s" % (_enc(name), _enc(value))]
    return urllib.parse.urlunsplit(
        (p.scheme, p.netloc, p.path, "&".join(q), p.fragment))


def payload_for(current, mark, replace):
    """What to send for an input that already holds a value.

    Appending by default is the conservative choice: an application that
    validates its input, looks the value up, or branches on it will throw away
    a payload that replaced the value outright, and the test then measures the
    error path instead of the reflection. Keeping the original and adding to
    it leaves the application on the road it was already on.

    --replace is for the other half of the cases: a value that is echoed
    whole, an allow-list the original value would satisfy and the payload
    would not, or simply a shorter proof for the report.
    """
    if replace or not current:
        return mark
    return current + mark


def path_suffix(url, suffix):
    """Append raw text to the PATH, without letting urlencode touch it.

    The delimiters are the payload here: encoding them would test nothing.
    """
    p = urllib.parse.urlsplit(url)
    base = p.path or "/"
    if suffix.startswith("/") and base.endswith("/"):
        base = base[:-1]          # no accidental // , which some caches fold
    new = base + suffix
    out = "%s://%s%s" % (p.scheme, p.netloc, new)
    if p.query:
        out += "?" + p.query
    return out


class Buster:
    """The safety property, made structural.

    Every request the tool sends carries something unique, so it works inside
    a cache key no real visitor produces. There is no code path that omits it:
    the only way to build a test request is through here.

    Minting alone is not enough, and the usual query parameter is not always
    enough either. A cache that leaves the query string OUT of the key -- a
    real configuration, and the point of a whole class of findings -- makes
    every query buster land on the SAME entry, the live one, and turns each
    test into a genuine poisoning. So a buster is VERIFIED against the target
    before anything is injected, and when the first one does not partition the
    cache the next shape is tried rather than the target being abandoned.
    """

    def __init__(self):
        self._n = 0
        self._lk = threading.Lock()

    def mint(self):
        with self._lk:
            self._n += 1
            n = self._n
        return "%d%s" % (n, "".join(random.choice(CANARY_ALPHABET)
                                    for _ in range(12)))

    # Each shape returns (url, headers). The name is what the report shows,
    # and `excludes` names the input this buster occupies, so the vectors do
    # not inject into the very thing keeping them safe.
    name = "?"
    excludes = frozenset()

    def apply(self, url, token):
        raise NotImplementedError


class QueryBuster(Buster):
    PARAM = "wcpcb"
    name = "query parameter " + PARAM
    excludes = frozenset({PARAM})

    def apply(self, url, token):
        return add_params(url, [(self.PARAM, token)]), {}


class OriginBuster(Buster):
    """Second choice, and the one that saves a target whose query string is
    unkeyed. It works whenever the response varies on Origin, which is common
    on anything that has ever thought about CORS."""

    name = "Origin header"
    excludes = frozenset({"origin"})

    def apply(self, url, token):
        return url, {"Origin": "https://%s.example.net" % token}


class AcceptEncodingBuster(Buster):
    """Last resort. Accept-Encoding is the header caches vary on most often,
    but a server may answer 406 to a coding it does not know, so it is tried
    only after the other two and its verification is the same as theirs."""

    name = "Accept-Encoding header"
    excludes = frozenset({"accept-encoding"})

    def apply(self, url, token):
        return url, {"Accept-Encoding": "gzip, deflate, %s" % token}


BUSTERS = (QueryBuster, OriginBuster, AcceptEncodingBuster)


# Debug headers a cache may answer with the key it computed. Akamai's Pragma
# family is the best known and the labs speak it; Fastly has its own. Asking
# costs one request and replaces a chain of inferences with a reading.
# Sent one shape at a time, not all at once. A Pragma carrying four
# directives matches nothing on an implementation that compares the whole
# header value -- and comparing the whole value is what implementations do.
# Measured against a strict replica: "x-get-cache-key" answers, "x-get-cache-
# key, akamai-x-get-cache-key" does not.
#
# Fastly-Debug and X-Cache-Debug are different header NAMES, so they ride
# along free on the first probe. Only the Pragma value needs a second try,
# which makes the worst case two requests and the usual case one.
KEY_ORACLE_PROBES = [
    {"Pragma": "x-get-cache-key", "Fastly-Debug": "1", "X-Cache-Debug": "1"},
    {"Pragma": "akamai-x-get-cache-key"},
]
KEY_ORACLE_REPLIES = ("x-cache-key", "x-true-cache-key", "x-cache-key-extended",
                      "fastly-debug-path", "x-akamai-session-info")


def echoed_key(resp):
    """The key the cache says it used, and the header it said it in."""
    for k, v in resp.headers.items():
        if k.lower() in KEY_ORACLE_REPLIES and v.strip():
            return v.strip(), k.lower()
    return "", ""


def probe_credit(shape, reply_header):
    """Which request header earned the answer.

    The first probe carries three at once, so the PoC would otherwise tell the
    operator to send all three when one did the work. The REPLY names it: a
    fastly-debug-* answer came from Fastly-Debug, anything else from the
    Pragma.
    """
    if reply_header.startswith("fastly-"):
        return {"Fastly-Debug": shape.get("Fastly-Debug", "1")}
    if "Pragma" in shape:
        return {"Pragma": shape["Pragma"]}
    return dict(shape)


def set_param_raw(url, name, value):
    """Set a parameter WITHOUT encoding its value.

    The delimiters inside the value are the payload: a '?' or an '&' written
    there is what fools a cache that strips parameters from the key with a
    regex instead of parsing them. Encoding them would test nothing.
    """
    p = urllib.parse.urlsplit(url)
    keep = _segments(p.query, drop=name)
    q = "&".join(keep + ["%s=%s" % (_enc(name), value)])
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, q, p.fragment))


def cache_hints(resp):
    return {k.lower(): v for k, v in resp.headers.items()
            if k.lower() in CACHE_HINT_HEADERS}


STATUS_HEADERS = ("X-Cache", "X-Cache-Status", "CF-Cache-Status",
                  "X-Proxy-Cache", "X-Drupal-Cache", "CDN-Cache")
_MISS_WORDS = ("miss", "expired", "bypass", "dynamic", "none", "pass",
               "updating", "revalidated", "ignored", "error", "unknown")


def edge_hop(value):
    """The LAST hop of a multi-hop cache-status header.

    Fastly and Akamai chain shield and edge into one value, in the order the
    request traversed them: "HIT, MISS" is a shield that had the object and
    an edge that did not. Only the edge says whether THIS response came out
    of a cache, and a substring search over the whole chain reads it
    backwards -- "hit" is in "HIT, MISS".
    """
    parts = [p.strip() for p in (value or "").split(",") if p.strip()]
    return parts[-1].lower() if parts else ""


def hit_state(resp):
    """'hit', 'miss' or 'unknown' -- deliberately not a boolean.

    The three are different facts and collapsing 'unknown' into either of the
    others is where false positives come from. A bare Age header is NOT a
    hit: an origin that stamps a frozen Age, a CDN that serves one canonical
    redirect to the whole site, and a shield hit under an edge miss all
    answer "the cache did it" to a boolean, and none of them is evidence
    about the cache key.
    """
    for h in STATUS_HEADERS:
        hop = edge_hop(resp.header(h))
        if not hop:
            continue
        word = hop.split()[0] if hop.split() else hop   # "MISS from cloudfront"
        if "hit" in word:
            return "hit"
        if any(w in word for w in _MISS_WORDS):
            return "miss"
    last = edge_hop(resp.header("X-Cache-Hits"))
    if last.isdigit():
        return "hit" if int(last) > 0 else "miss"
    return "unknown"


def age_of(resp):
    """The Age header as an int, or None when the response carries none."""
    a = resp.header("Age").strip()
    return int(a) if a.isdigit() else None


def looks_hit(resp):
    """Kept for the "is anything cached here at all" question only.

    An Age is a hint that SOMETHING upstream caches. It is not a reading of
    what happened to this request, so nothing that reasons about the cache
    key may call this -- use hit_state().
    """
    if hit_state(resp) == "hit":
        return True
    age = age_of(resp)
    return age is not None and age > 0


# ----------------------------------------------------------------------------
# the hunt
# ----------------------------------------------------------------------------

class Hunter:
    def __init__(self, args, http, rep, buster, status=None):
        self.args = args
        self.http = http
        self.rep = rep
        self.buster = buster
        self.status = status
        self.findings = []
        self._fl = threading.Lock()
        self.declines = Counter()
        self._dl = threading.Lock()
        self._per_url = Counter()       # confirmed findings, per URL
        self._noise = {}
        self._learned = {}              # cookie names seen in Set-Cookie
        self._buster = {}               # the shape that partitions, per URL
        self._key = {}                  # the key the cache echoed, per URL
        self._oracle = {}               # the probe shape that answered
        self._status = {}               # the baseline status, per URL

    # -- bookkeeping ------------------------------------------------------

    def note(self, reason):
        with self._dl:
            self.declines[reason] += 1
        if self.status:
            self.status.record("declined")

    def budget_left(self, url):
        """--confirm-x: once a URL has proven the point N times, stop paying
        for it. Further findings on the same page rarely change the report and
        always cost requests."""
        if self.args.confirm_x <= 0:
            return True
        with self._fl:
            return self._per_url[url] < self.args.confirm_x

    def add(self, f):
        with self._fl:
            self.findings.append(f)
            # Only a poisoning spends the per-URL budget. An informational
            # finding -- the cache echoing its own key -- costs the operator
            # nothing to read and must not push a real one out of the run,
            # which is exactly what it did: three findings on one page and the
            # budget was gone before the last test even started.
            if f.confirmed and f.level != "info":
                self._per_url[f.url] += 1
        self.rep.hit(f)
        if self.status:
            self.status.record("observed" if f.level == "info" else
                               ("confirmed" if f.confirmed else "unkeyed"))

    def why_not(self):
        if not self.declines:
            return
        self.rep.line("")
        self.rep.line("%sdeclined tests, by reason:%s"
                      % (Colors.BOLD, Colors.RESET))
        for reason, n in self.declines.most_common():
            self.rep.line("  %-58s %d" % (reason, n))

    # -- preflight --------------------------------------------------------

    def keyed(self, url):
        """A fresh cache key of our own: (url, headers)."""
        b = self._buster.get(url) or BUSTERS[0]()
        return b.apply(url, b.mint())

    def _partitions(self, url, buster):
        """Does this buster give us a key nobody else produces?

        One question, THREE answers, and the third is the one that was
        missing:

            "miss"     a key nobody else produces. Safe to test.
            "hit"      a token never sent before came out of the cache, so
                       what this buster varies sits outside the key.
            "unknown"  the cache said nothing about this request.

        "unknown" is not "hit". Reading it as one -- which a bare Age header
        made this function do -- turns every origin that stamps a constant
        Age, every globally cached canonical redirect and every shield hit
        under an edge miss into a confirmed finding.
        """
        tok = buster.mint()
        u, h = buster.apply(url, tok)
        extra = dict(h)
        if url in self._oracle:
            extra.update(self._oracle[url])
        r = self.http.get(u, extra=extra)
        if not r.ok:
            return None, r
        key, _ = echoed_key(r)
        # The echoed key describes the URL. A buster that varies a HEADER
        # writes nothing into it, so "tok in key" is false for a buster that
        # works perfectly -- which is why Origin and Accept-Encoding could
        # never be chosen on any target whose cache answers the key oracle.
        # Only ask the key about a buster that writes into the URL.
        if key and isinstance(buster, QueryBuster):
            return ("miss" if tok in key else "hit"), r
        state = hit_state(r)
        if state == "unknown":
            age = age_of(r)
            if not age:
                # No status header, and nothing aged. A response that is not
                # an older shared entry is one our token produced, which is
                # all "the buster partitions" ever meant. Only Age > 0 with
                # no status header stays ambiguous -- and that is the one
                # case this function must not resolve on its own.
                state = "miss"
        return state, r

    def _age_moves(self, url, buster=None):
        """Is that Age a stored object getting older, or a number the origin
        stamps on every response?

        The last resort, for a target that emits Age and no cache status
        header at all: nothing above can read a hit there, and "Age > 0" is
        not one -- it is equally the signature of a misconfigured origin, of
        an Age copied down from a shield that was never consulted for this
        key, and of a CDN serving one canonical redirect to the whole site.

        Two fresh tokens separated by a known gap settle it. One shared entry
        ages by the gap and keeps its validators; a constant Age does not
        move, and a per-response Age resets.
        """
        gap = self.args.age_probe
        if gap <= 0:
            return False, None
        b = buster or QueryBuster()
        u1, h1 = b.apply(url, b.mint())
        r1 = self.http.get(u1, extra=h1)
        a1 = age_of(r1) if r1.ok else None
        if a1 is None or a1 <= 0:
            return False, r1
        t0 = time.time()
        time.sleep(gap)
        u2, h2 = b.apply(url, b.mint())
        r2 = self.http.get(u2, extra=h2)
        a2 = age_of(r2) if r2.ok else None
        if a2 is None:
            return False, r2
        waited = time.time() - t0
        drift = abs((a2 - a1) - waited)
        same = ((r1.header("ETag"), r1.header("Last-Modified"))
                == (r2.header("ETag"), r2.header("Last-Modified")))
        moved = same and a2 >= a1 and drift <= max(1.5, 0.5 * waited)
        self.rep.dbg("  age probe: %d -> %d over %.1fs (drift %.1f), "
                     "validators %s -> %s"
                     % (a1, a2, waited, drift, "match" if same else "differ",
                        "one shared entry" if moved else "not a shared entry"))
        return moved, r2

    def preflight(self, url):
        """Is this target cached, and can we get a key of our own?

        Returns (noise, reason_or_None). Both questions are answered before a
        single payload is sent, because the answer to the second decides
        whether testing is safe at all.
        """
        first = BUSTERS[0]()
        u, h = first.apply(url, first.mint())

        a = self.http.get(u, extra=h)
        if not a.ok:
            return None, "target unreachable (%s)" % (a.error or "no response")
        # A 404 is not a dead end: an error page that echoes the path it was
        # asked for, and that the cache stores, is a poisoning surface like
        # any other -- it is the whole subject of the encoding case below.
        # What genuinely cannot be worked with is a server error or an auth
        # wall, so those keep their refusal.
        if a.status >= 400 and a.status not in (404, 410):
            return None, "target answers HTTP %d" % a.status

        b = self.http.get(u, extra=h)
        if not b.ok:
            return None, "second request failed"

        self._status[url] = a.status

        # The reference measurement, and it costs nothing extra: `a` is the
        # first request ever made for this token, `b` is the same token
        # again. A cache that stores under our key answers miss then hit.
        # Until that transition is seen, every hit/miss reading on this
        # target is uncalibrated -- which is exactly the state the tool used
        # to draw its loudest conclusion from.
        sa, sb = hit_state(a), hit_state(b)

        hints = cache_hints(a) or cache_hints(b)
        if not hints and not looks_hit(b):
            # Without a single cache indicator we cannot verify that a buster
            # partitions anything, and an unverified buster is not a safety
            # property. Refuse rather than inject blind.
            return None, "no cache observed (no cache headers, no Age)"

        # Ask the cache what key it computed. One request, and when it
        # answers, everything below stops being an inference: the buster is
        # verified by reading the token in the key instead of watching
        # HIT/MISS, and the operator gets the key shape in the report.
        if not self.args.no_key_probe:
            key, used = "", {}
            for shape in KEY_ORACLE_PROBES:
                probe_url, probe_h = first.apply(url, first.mint())
                oracle = self.http.get(probe_url, extra=dict(shape, **probe_h))
                key, reply = echoed_key(oracle) if oracle.ok else ("", "")
                if key:
                    used = probe_credit(shape, reply)
                    self._oracle[url] = used
                    break
            if key:
                self._key[url] = key
                self.add(Finding(
                    url=url, vector="cache-key", level="info",
                    kind="the cache echoes its own key",
                    name="(debug header)", location="response header",
                    payload=", ".join("%s: %s" % kv for kv in used.items()),
                    evidence="the cache answered with the key it computed: %s"
                             % key,
                    confirmed=True,
                    proof="read from the cache itself, not inferred from "
                          "HIT and MISS",
                    poc="curl %s %s"
                        % (" ".join("-H '%s: %s'" % kv for kv in used.items()),
                           url)))

        chosen, unkeyed = None, None
        for cls in BUSTERS:
            cand = cls()
            state, probe = self._partitions(url, cand)
            self.rep.dbg("  buster %s: %s" % (cand.name, state))
            if state == "miss":
                chosen = cand
                break
            if state == "hit" and cls is QueryBuster:
                unkeyed = (probe,
                           "a cache status header read %s for a token never "
                           "sent before"
                           % (edge_hop(probe.header("X-Cache"))
                              or edge_hop(probe.header("CF-Cache-Status"))
                              or edge_hop(probe.header("X-Cache-Status"))
                              or "HIT").upper())
                self.rep.info("  query string is unkeyed; trying another "
                              "cache buster so testing stays safe")

        # Age-only target: no status header, so nothing above could read a
        # hit and the loop is about to refuse the target. One measurement
        # recovers the real finding without resurrecting the false one.
        if chosen is None and unkeyed is None and (age_of(a) or age_of(b)):
            moved, probe = self._age_moves(url)
            if moved:
                unkeyed = (probe,
                           "no cache status header, but the Age advanced "
                           "by the wall clock across two different fresh "
                           "tokens with identical validators")

        if unkeyed:
            # Not a poisoning and not reported as one. A query string outside
            # the cache key is a PRECONDITION: it costs nobody anything until
            # some parameter of this page reaches the response, which is what
            # the vectors below are for. Printing it in the same green as a
            # confirmed poisoning inflated every report that contained it,
            # and -- because it was marked confirmed -- it also ate one of
            # the three --confirm-x slots the real tests were going to need.
            probe, how = unkeyed
            self.add(Finding(
                url=url, vector="cache-key", level="info",
                kind="query string not in the cache key",
                name="(whole query string)", location="cache key",
                payload="%s=<fresh token>" % QueryBuster.PARAM,
                evidence="%s, so the cache serves one entry whatever the "
                         "parameters say (baseline: %s then %s)"
                         % (how, sa, sb),
                confirmed=True,
                proof="measured against a token the cache had never seen, "
                      "not inferred from an Age header",
                poc="compare %s against the same URL with no parameters"
                    % u))

        if chosen is None:
            return None, ("no cache buster partitions this key (tried %s) - "
                          "refusing to test"
                          % ", ".join(c.name for c in
                                      [cls() for cls in BUSTERS]))
        self._buster[url] = chosen
        if not isinstance(chosen, QueryBuster):
            self.rep.info("  cache buster: %s" % chosen.name)

        # Cookies the server stamps on a first visit are the ones a scanner
        # would otherwise never know to test: nobody types fehost into a
        # config file, the front end sets it. Harvested here, from the
        # baseline, rather than guessed.
        learned = set()
        for r in (a, b):
            sc = r.header("Set-Cookie")
            for name in parse_cookie_header(sc.split(";")[0] if sc else ""):
                learned.add(name)
        if learned:
            self._learned[url] = learned

        noise = PageNoise()
        noise.learn([a.body, b.body])
        if noise.too_dynamic:
            return None, "page too dynamic to read (%s)" % noise.describe()
        self.rep.info("  %s | cache: %s"
                      % (noise.describe(),
                         ", ".join("%s=%s" % kv for kv in sorted(hints.items()))
                         or "hit observed"))
        return noise, None

    # -- the oracle -------------------------------------------------------

    @staticmethod
    def _searchable(resp):
        """Everything of a response an injected value can land in.

        The body is not the only place, and on the most valuable finding of
        all it is the wrong place: a 302 whose Location an attacker controls
        carries the whole vulnerability in a response header, with an empty
        body underneath. A tool that reads only the body sees a blank page and
        concludes nothing happened.

        The status line is included for the same reason: flipping a 200 into a
        redirect IS the effect, even before the target is chosen.
        """
        heads = " ".join("%s: %s" % (k, v) for k, v in resp.headers.items())
        return "%d %s" % (resp.status, heads), resp.body

    def reflected(self, resp, mark, noise):
        if not resp.ok:
            return False
        head, body = self._searchable(resp)
        if mark.lower() in head.lower():
            return True
        b = noise.apply(normalize(body)) if noise else normalize(body)
        return mark.lower() in b.lower()

    def where(self, resp, mark):
        """Which half of the response carried it -- for the evidence line."""
        head, _ = self._searchable(resp)
        return "response header" if mark.lower() in head.lower() else "body"

    def poison_and_check(self, base_url, vector, name, location, payload_desc,
                         mark, send, kind, clean=None, evidence=None,
                         proof=None):
        """The only test shape in this tool.

        send(url) issues the request carrying the injection. Then a CLEAN
        request goes to the SAME cache key. If the canary survives into a
        request that carried none of it, three things are true at once: the
        input is unkeyed, the response was stored, and the cache served it to
        someone who never asked for it. That is the finding.
        """
        if not self.budget_left(base_url):
            return None
        keyed, bh = self.keyed(base_url)

        r1 = send(keyed, bh)
        if r1 is None or not r1.ok:
            self.note("%s: injected request failed" % vector)
            return None
        noise = self._noise.get(base_url)
        if not self.reflected(r1, mark, noise):
            self.rep.skip("  %s %s: canary not reflected" % (vector, name))
            return None

        self.rep.test("  %s %s: reflected, checking the clean request"
                      % (vector, name))
        # The confirmation is normally "the same key, carrying nothing". One
        # vector needs another shape: when the subject is the SPELLING of the
        # path, the request that proves it is the same path written the way a
        # browser writes it, not the absence of a request.
        r2 = clean(keyed, bh) if clean else self.http.get(keyed, extra=bh)
        if not r2.ok:
            self.note("%s: clean request failed" % vector)
            return None

        if not self.reflected(r2, mark, noise):
            # Reflected but not served back: either not cached, or cached
            # under a key that included our input. Not a poisoning.
            self.note("%s: reflected but the clean request was clean "
                      "(not cached, or the input IS in the key)" % vector)
            return None

        f = Finding(url=base_url, vector=vector, kind=kind, name=name,
                    location=location, payload=payload_desc,
                    # Built by concatenation, never by formatting: a payload
                    # can contain percent signs -- a percent-encoded path is
                    # nothing but percent signs -- and feeding one to a format
                    # string turns the evidence into a crash.
                    evidence=((evidence if evidence else
                               "canary " + mark + " returned in the "
                               + self.where(r2, mark)
                               + " of a request that did not carry it")
                              + " (HTTP %d, X-Cache: %s)"
                              % (r2.status, r2.header("X-Cache") or "n/a")),
                    proof=proof or "",
                    confirmed=True, cache_key_url=keyed,
                    # The PoC has to carry the payload as well as the URL:
                    # for a body parameter or a header the URL alone shows
                    # nothing of what was sent.
                    poc="poison %s  with  %s   then fetch the same URL "
                        "carrying none of it" % (keyed, payload_desc))
        self.add(f)
        return f

    # -- vectors ----------------------------------------------------------

    # -- the generic engine -------------------------------------------

    @staticmethod
    def _ddmin(test, items):
        """The smallest subset of `items` for which test() still holds.

        Delta debugging rather than pair enumeration. Pairs answer "which two"
        and nothing else: a three-header combination is invisible to them, a
        four-header one doubly so, and the cost is a triangle that grows with
        the square of the candidate list. Subtraction asks a different
        question -- "is this one needed?" -- which has the same shape whatever
        the size of the answer.

        Whole blocks are removed first and the granularity only gets finer
        when no block can go, so a set of forty usually collapses in a handful
        of requests instead of forty.
        """
        items = list(items)
        n = 2
        while len(items) >= 2:
            size = max(1, len(items) // n)
            chunks = [items[i:i + size] for i in range(0, len(items), size)]
            reduced = False
            for i in range(len(chunks)):
                comp = [x for j, c in enumerate(chunks) if j != i for x in c]
                if len(comp) < len(items) and test(comp):
                    items = comp
                    n = max(n - 1, 2)
                    reduced = True
                    break
            if not reduced:
                if n >= len(items):
                    break
                n = min(n * 2, len(items))
        return items

    def probe_and_minimize(self, url, vector, kind, location, names, marks,
                           send, describe):
        """One probe over every candidate, then subtraction.

        The probe carries all of them at once, each with its own canary, and
        answers the only question that matters on the vast majority of URLs --
        "does any of this reach the response?" -- in a single request.

        When something does reflect, the canary says which input CARRIES the
        payload. What it does not say is which other inputs had to be there
        for it to work, and that is what the subtraction finds: drop an input,
        ask whether the canary still comes back, and keep it dropped if it
        does. What survives is the minimal set, whether that is one input, two
        or five.

        Nothing here is chunked. Splitting the candidates into groups of ten
        was not just slower, it was wrong: a combination whose two halves fell
        into different groups was never assembled, so the tool's ability to
        find it depended on the order of a hard-coded list. Measured on the
        redirect lab -- found with groups of ten, invisible with groups of
        five, same target, same code.
        """
        noise = self._noise.get(url)
        keyed, bh = self.keyed(url)
        probe = send(keyed, names, bh)
        if probe is None or not probe.ok:
            self.note("%s: probe failed" % vector)
            return []
        # A probe carrying forty headers is a request many servers and
        # most WAFs refuse. Response.ok is true for a 400, so the refusal
        # used to read as "nothing of 40 candidates reflected" and the whole
        # vector was lost in silence on exactly the targets worth testing.
        base = self._status.get(url)
        if (base and probe.status != base
                and probe.status in (400, 403, 413, 414, 431, 502, 503)):
            if len(names) > 4:
                self.rep.info("  %s: the probe carrying %d candidate(s) was "
                              "refused (HTTP %d); splitting"
                              % (vector, len(names), probe.status))
                half = len(names) // 2
                return (self.probe_and_minimize(url, vector, kind, location,
                                                names[:half], marks, send,
                                                describe)
                        + self.probe_and_minimize(url, vector, kind, location,
                                                  names[half:], marks, send,
                                                  describe))
            self.note("%s: probe refused with HTTP %d" % (vector, probe.status))
            return []

        hits = [n for n in names if self.reflected(probe, marks[n], noise)]
        if len(hits) > self.args.max_carriers:
            # A page that echoes its whole request -- a debug route, a
            # verbose error page -- turns one probe into a full subtraction
            # per reflected input. The first few carry the finding; the rest
            # spend the run.
            self.rep.info("  %s: %d inputs reflect, minimising the first %d "
                          "(--max-carriers)" % (vector, len(hits),
                                                self.args.max_carriers))
            hits = hits[:self.args.max_carriers]
        if not hits:
            self.rep.dbg("  %s: nothing of %d candidate(s) reflected"
                         % (vector, len(names)))
            return []

        out = []
        for carrier in hits:
            if not self.budget_left(url):
                break

            def still(subset, _c=carrier):
                k, kh = self.keyed(url)
                r = send(k, list(subset) + [_c], kh)
                return r.ok and self.reflected(r, marks[_c], noise)

            rest = [n for n in names if n != carrier]
            # Cheap first question: does it work on its own? Most of the time
            # it does, and then there is nothing to minimise.
            support = [] if still([]) else self._ddmin(still, rest)
            final = [carrier] + support
            self.rep.test("  %s: %s%s" % (vector, carrier,
                                          (" needs " + ", ".join(support))
                                          if support else " on its own"))
            got = self.poison_and_check(
                url, vector, " + ".join(final),
                location if len(final) == 1 else location + " combination",
                describe(final), marks[carrier],
                lambda u, bh, _f=list(final): send(u, _f, bh),
                kind=kind if len(final) == 1 else kind + " combination")
            if got:
                out.append(got)
        return out

    # -- vectors ----------------------------------------------------------

    def _hv(self, url, name, mark):
        """The value to send for a candidate header, honouring --replace when
        the capture already supplied one."""
        cur = ""
        for k, v in self.http.cli_headers.items():
            if k.lower() == name.lower():
                cur = v
                break
        return header_value(name, mark, cur, self.args.replace)

    def vector_headers(self, url):
        """Unkeyed request headers, and the combinations of them."""
        names = list(CANDIDATE_HEADERS)
        if self.args.headers_file:
            names += load_header_names(self.args.headers_file, self.rep)
        # A header the operator captured or typed is one the application
        # plausibly reads, whether or not it is in anyone's list.
        names += [k for k in self.http.cli_headers
                  if k.lower() not in NEVER_INJECT]
        # Headers from an auth file are NOT candidates. They are
        # credentials -- that is what the file is for -- and overwriting one
        # destroys the session, so the request measures the login page
        # instead of the application. The cookie vector already protects its
        # own credentials this way; this is the same rule, applied where it
        # was missing.
        creds = {k.lower() for k in self.http.auth.headers_for(url)}
        names = [h for h in names if h.lower() not in creds]
        # Whatever is keeping us in our own cache key must not also be a
        # payload: injecting into it would merge our test with the live entry.
        busy = (self._buster.get(url) or BUSTERS[0]()).excludes
        names = [h for h in names if h.lower() not in busy]
        seen, ordered = set(), []
        for n in names:
            if n.lower() not in seen:
                seen.add(n.lower())
                ordered.append(n)

        group = self.args.header_group
        batches = ([ordered] if group <= 0 else
                   [ordered[i:i + group] for i in range(0, len(ordered), group)])

        for batch in batches:
            marks = {h: canary() for h in batch}

            def send(u, subset, bh, _m=marks):
                e = dict(bh)
                e.update({h: self._hv(url, h, _m[h]) for h in subset})
                return self.http.get(u, extra=e)

            found = self.probe_and_minimize(
                url, "headers", "unkeyed request header", "request header",
                batch, marks, send,
                lambda f, _m=marks: " / ".join(
                    "%s: %s" % (h, self._hv(url, h, _m[h])) for h in f))
            if found:
                continue

            # Second shape, one request. A switch header does nothing while it
            # agrees with reality: a scheme header is ignored unless it says
            # something other than the scheme in use. Given a canary-shaped
            # value it happens to disagree, which is why the redirect lab was
            # reachable at all -- but that is luck, not method. Here the
            # switches are given values chosen to make them fire, and only the
            # carriers keep a canary.
            switches = [h for h in batch if is_switch(h)]
            if not switches or len(switches) == len(batch):
                continue

            def send2(u, subset, bh, _m=marks):
                e = dict(bh)
                e.update({h: (trigger_value(h) if is_switch(h)
                              else self._hv(url, h, _m[h])) for h in subset})
                return self.http.get(u, extra=e)

            self.probe_and_minimize(
                url, "headers", "unkeyed request header", "request header",
                batch, marks, send2,
                lambda f, _m=marks: " / ".join(
                    "%s: %s" % (h, trigger_value(h) if is_switch(h)
                                else self._hv(url, h, _m[h])) for h in f))

    def vector_cookies(self, url):
        """Each cookie, and the combinations of them.

        A cookie is a request header, and an application reads it the same
        way -- but the Cookie header can only be tested whole by the header
        vector, which replaces the session along with everything else and
        tests nothing. So the cookies are injected individually, with the
        others left intact, exactly as the rest of the suite does.

        Names come from four places and none of them is a wordlist: -H, the
        captured request, the auth files, and the Set-Cookie the target itself
        returns. That last source is the one that matters: a front-end cookie
        is stamped by the edge, so the server names it for us.

        Cookies from an auth file are carried and never injected. They are
        credentials: replacing one destroys the session and measures nothing.
        """
        jar, credentials = self.http.cookie_jar(url)
        for name in self._learned.get(url, ()):
            jar.setdefault(name, "")
        names = [n for n in jar if n.lower() not in credentials]
        if not names:
            self.note("cookies: %s" % ("every cookie here is a credential from "
                                       "an auth file, none is injected" if jar
                                       else "no cookie on this target"))
            return

        marks = {n: canary() for n in names}

        def payload(n):
            return payload_for(jar.get(n, ""), marks[n], self.args.replace)

        def send(u, subset, bh):
            probe = dict(jar)
            for n in subset:
                probe[n] = payload(n)
            e = dict(bh)
            e["Cookie"] = build_cookie_header(probe)
            return self.http.get(u, extra=e)

        self.probe_and_minimize(
            url, "cookies", "unkeyed cookie", "cookie", names, marks, send,
            lambda f: " / ".join("%s=%s" % (n, payload(n)) for n in f))

    def vector_params(self, url):
        """Query parameters already in the URL, and the combinations of them.

        These are the parameters this application is known to read, so they
        are tested whenever --enable-params is on. The generic tracking list
        is a different question -- what a CDN drops from the key by
        configuration, whether or not the page uses it -- and it has its own
        switch.
        """
        existing = dict(urllib.parse.parse_qsl(
            urllib.parse.urlsplit(url).query, keep_blank_values=True))
        busy = (self._buster.get(url) or BUSTERS[0]()).excludes
        names = [p for p in existing if p not in busy]
        if not names:
            self.note("params: no parameter in the URL")
            return
        self._run_params(url, "params", names, existing)

    def vector_params_common(self, url):
        """The tracking parameters CDNs commonly drop from the cache key."""
        existing = dict(urllib.parse.parse_qsl(
            urllib.parse.urlsplit(url).query, keep_blank_values=True))
        busy = (self._buster.get(url) or BUSTERS[0]()).excludes
        names = [p for p in CANDIDATE_PARAMS
                 if p not in existing and p not in busy]
        if names:
            self._run_params(url, "params-common", names, existing)

    def _run_params(self, url, vector, names, existing):
        marks = {p: canary() for p in names}

        def payload(p):
            return payload_for(existing.get(p, ""), marks[p], self.args.replace)

        def send(u, subset, bh):
            out = u
            for p in subset:
                out = set_param(out, p, payload(p))
            return self.http.get(out, extra=bh)

        self.probe_and_minimize(
            url, vector, "unkeyed query parameter", "query parameter",
            names, marks, send,
            lambda f: " / ".join("%s=%s" % (p, payload(p)) for p in f))

    def vector_fatget(self, url):
        """A GET carrying a request body.

        Frameworks merge the query string and the body into one bag of
        parameters, and most of them let the body win. Caches derive the key
        from the request LINE. Put those two together and a body parameter is
        an unkeyed input that OVERRIDES a keyed one -- the query keeps saying
        what the victim asked for, the body decides what they get.

        The URL is left exactly as it is, on purpose. Touching the query would
        change the cache key and test nothing: the whole point is to reach a
        key the victim already produces, through a channel the key does not
        see.

        Candidates are the parameters the URL already carries, because a body
        parameter the application does not read does nothing. The generic
        tracking names come along only when --enable-params-common is on.
        """
        existing = dict(urllib.parse.parse_qsl(
            urllib.parse.urlsplit(url).query, keep_blank_values=True))
        busy = (self._buster.get(url) or BUSTERS[0]()).excludes
        names = [p for p in existing if p not in busy]
        if self.args.enable_params_common:
            names += [p for p in CANDIDATE_PARAMS
                      if p not in existing and p not in busy]
        if not names:
            self.note("fatget: no parameter to override from the body")
            return

        marks = {p: canary() for p in names}

        def payload(p):
            return payload_for(existing.get(p, ""), marks[p], self.args.replace)

        def send(u, subset, bh):
            body = urllib.parse.urlencode([(p, payload(p)) for p in subset])
            e = dict(bh)
            e["Content-Type"] = "application/x-www-form-urlencoded"
            return self.http.get(u, extra=e, body=body)

        self.probe_and_minimize(
            url, "fatget", "unkeyed request body parameter",
            "GET body parameter", names, marks, send,
            lambda f: "body: " + urllib.parse.urlencode(
                [(p, payload(p)) for p in f]))

    def vector_norm(self, url):
        """Cache key normalization: the cache and the origin disagree about
        where the path ends."""
        for tpl, why in NORM_SUFFIXES:
            m = canary()
            suffix = tpl.format(p="wcp", c=m)
            got = self.poison_and_check(
                url, "norm", why, "path suffix", suffix, m,
                lambda u, bh, _s=suffix: self.http.get(path_suffix(u, _s),
                                                       extra=bh),
                kind="cache key normalization")
            # One spelling is enough -- but only for the DELIMITER family.
            # The encoded variants of ';' describe the same bug, and listing
            # them separately makes one finding look like several. The
            # encoding test below is a different discrepancy entirely, so it
            # runs whatever happened here: a `return` at this point hid it
            # completely on any page that reflects a path suffix.
            if got:
                break
        self._norm_encoding(url)
        self._key_nesting(url)

    def _norm_encoding(self, url):
        """Percent-encoding normalization: two spellings, one cache entry.

        The cache decodes the path before keying, the application does not
        before echoing it. So a path written raw and the same path written
        percent-encoded share an entry, while reaching the application as
        typed -- and whoever writes it raw decides what the other one gets.

        This is the shape behind the reflected-XSS-through-the-cache case: a
        browser always sends the payload encoded, which is why it does not
        fire on its own; it fires because the cache hands it the decoded copy
        somebody else stored.

        The proof needs no cache header. The poison is sent raw, the
        confirmation is sent encoded, and what settles it is that the encoded
        request comes back carrying the RAW spelling -- the one it did not
        send, and could not have produced.
        """
        if self.args.proxy:
            self.note("norm: encoding test needs a raw path, which cannot go "
                      "through -x")
            return
        m = canary()
        raw_sfx = "/" + m + "<b>"
        enc_sfx = "/" + m + "%3Cb%3E"
        self.poison_and_check(
            url, "norm", "percent-encoding normalization", "path spelling",
            raw_sfx, m + "<b>",
            lambda u, bh: self.http.raw_get(path_suffix(u, raw_sfx), extra=bh),
            kind="cache key normalization",
            clean=lambda u, bh: self.http.raw_get(path_suffix(u, enc_sfx),
                                                  extra=bh),
            evidence="the percent-encoded spelling " + enc_sfx
                     + " came back carrying the RAW spelling it never sent",
            proof=("the two spellings share one cache entry: a request that "
                   "wrote the path percent-encoded received the decoded copy "
                   "somebody else stored, which is how a payload a browser "
                   "always encodes ends up executing"))

    def _excluded_params(self, url):
        """Which parameter names the cache leaves OUT of its key.

        With the oracle this is one request and a reading: send them all, see
        which markers are missing from the key it echoes. Without it, fall
        back to the handful of names caches are configured to drop -- a guess,
        and labelled as one in the debug output.
        """
        cands = ["utm_content", "utm_source", "utm_medium", "utm_campaign",
                 "fbclid", "gclid", "ref"]
        if self.args.no_key_probe or url not in self._key:
            self.rep.dbg("  no key oracle: assuming the usual excluded names")
            return cands[:3]
        marks = {c: canary() for c in cands}
        u = url
        for c, m in marks.items():
            u = set_param(u, c, m)
        keyed, bh = self.keyed(u)
        r = self.http.get(keyed, extra=dict(self._oracle.get(url, {}), **bh))
        key, _ = echoed_key(r) if r.ok else ("", "")
        if not key:
            return cands[:3]
        out = [c for c, m in marks.items() if m not in key]
        self.rep.test("  key: %d of %d candidate parameter(s) are excluded "
                      "from the key (%s)"
                      % (len(out), len(cands), ", ".join(out) or "none"))
        return out

    def _key_nesting(self, url):
        """Content that reaches the application but not the cache key.

        A cache that removes a parameter from its key with a REGEX rather than
        by parsing can be fooled: written after a '?' inside another
        parameter's value, the excluded name is stripped from the key while
        the whole string still reaches the application as one value.

        The result is an unkeyed region in the middle of a keyed URL -- the
        attacker steers the response, the victim's plain URL receives it.

        The proof needs no oracle. Two requests differing ONLY inside that
        region: if the second comes back carrying the first one's content,
        the region is outside the key. The oracle, when present, says which
        parameters to try instead of guessing, and explains the finding.
        """
        existing = dict(urllib.parse.parse_qsl(
            urllib.parse.urlsplit(url).query, keep_blank_values=True))
        busy = (self._buster.get(url) or BUSTERS[0]()).excludes
        names = [p for p in existing if p not in busy]
        if not names:
            self.note("key nesting: no parameter in the URL to nest into")
            return
        excluded = self._excluded_params(url)
        if not excluded:
            self.note("key nesting: no parameter is excluded from the key, "
                      "nothing to hide behind")
            return

        for p in names:
            base = existing[p]
            for e in excluded:
                m1, m2 = canary(), canary()
                v1 = "%s?%s=%s" % (base, e, m1)
                v2 = "%s?%s=%s" % (base, e, m2)
                ev = ("two requests differing only after the '?' inside %s "
                      "shared one cache entry" % p)
                if url in self._key:
                    ev += " (the cache's own key: %s)" % self._key[url]
                got = self.poison_and_check(
                    url, "norm", "%s, after '?%s='" % (p, e),
                    "unkeyed region inside a keyed parameter",
                    "%s=%s" % (p, v1), m1,
                    lambda u, bh, _p=p, _v=v1: self.http.get(
                        set_param_raw(u, _p, _v), extra=bh),
                    kind="cache key exclusion fooled",
                    clean=lambda u, bh, _p=p, _v=v2: self.http.get(
                        set_param_raw(u, _p, _v), extra=bh),
                    evidence=ev,
                    proof=("whatever is written there reaches the application "
                           "and stays out of the key, so the victim's plain "
                           "URL receives what the attacker wrote"))
                if got:
                    break

    def vector_deception(self, url):
        """Cache deception: the victim's private response, stored under a URL
        the attacker can fetch.

        The mirror image of the rest of this tool, so it needs its own oracle.
        There is no canary to inject: the secret is the application's own. We
        first learn what the authenticated page says that the anonymous one
        does not, then check whether that content reaches an anonymous request.
        """
        auth = self.http.auth.headers_for(url) or self.http.cli_headers
        if not any(k.lower() in ("cookie", "authorization") for k in auth):
            self.note("deception: no session for this host "
                      "(needs --auth-file/--auth-dir or -H)")
            return

        keyed, bh0 = self.keyed(url)
        authed = self.http.get(keyed, extra=bh0)
        # The signed-in page is fetched TWICE, on two different keys. Anything
        # that is genuinely private is in both; anything that merely changes
        # per render -- a token, a request id, a timestamp -- is in only one
        # and drops out. Without this, a page with fresh randomness in it
        # looks like a page full of secrets, and the noise mask does not help:
        # it holds the specific values seen while calibrating, not a pattern,
        # so a value minted after calibration passes straight through.
        k2, bh2 = self.keyed(url)
        authed2 = self.http.get(k2, extra=bh2)
        k3, bh3 = self.keyed(url)
        anon = self.http.get(k3, extra=bh3, no_auth=True)
        if not (authed.ok and authed2.ok and anon.ok):
            self.note("deception: baseline requests failed")
            return

        noise = self._noise.get(url)
        private = (private_tokens(authed.body, anon.body, noise)
                   & private_tokens(authed2.body, anon.body, noise))
        if len(private) < self.args.deception_min:
            self.note("deception: %d stable token(s) separate the signed-in "
                      "page from the anonymous one, below the %d needed to "
                      "conclude" % (len(private), self.args.deception_min))
            return
        self.rep.test("  deception: %d stable token(s) only the signed-in "
                      "page has" % len(private))

        for ext in DECEPTION_SUFFIXES:
            bait = "/" + canary() + ext
            target, bht = self.keyed(path_suffix(url, bait))

            victim = self.http.get(target, extra=bht)
            if not victim.ok or not has_tokens(victim.body, private, noise):
                self.rep.dbg("  deception %s: signed-in request does not "
                             "reach the private page" % ext)
                continue
            thief = self.http.get(target, extra=bht, no_auth=True)
            if not thief.ok:
                continue
            if has_tokens(thief.body, private, noise):
                if hit_state(thief) != "hit" and not age_of(thief):
                    # The anonymous request got the private content, but
                    # nothing says a cache handed it over. The ordinary
                    # explanation is that this path is simply not
                    # authenticated -- a real bug, and a different one.
                    self.note("deception: private content reached an "
                              "anonymous request, but not out of the cache "
                              "(unauthenticated path, not cache deception)")
                    continue
                self.add(Finding(
                    url=url, vector="deception", kind="cache deception",
                    name=ext, location="path suffix", payload=bait,
                    evidence="%d fragment(s) present only in the signed-in "
                             "response were served to a request carrying no "
                             "session (X-Cache: %s)"
                             % (len(private), thief.header("X-Cache") or "n/a"),
                    confirmed=True, cache_key_url=target,
                    poc="have the victim open %s then fetch it with no cookie"
                        % target))
                return

    # -- driver -----------------------------------------------------------

    def run_url(self, url):
        noise, why = self.preflight(url)
        if why:
            self.rep.test("%s%s%s  skipped: %s"
                          % (Colors.GREY, url, Colors.RESET, why))
            self.note(why.split(" (")[0])
            return
        self._noise[url] = noise
        self.rep.test("%s%s%s" % (Colors.BOLD, url, Colors.RESET))

        before = len(self.findings)
        if self.args.enable_headers:
            self.vector_headers(url)
            self.vector_cookies(url)
        if self.args.enable_params:
            self.vector_params(url)
        if self.args.enable_params_common:
            self.vector_params_common(url)
        if self.args.enable_fatget:
            self.vector_fatget(url)
        if self.args.enable_norm:
            self.vector_norm(url)
        if self.args.enable_deception:
            self.vector_deception(url)
        if len(self.findings) == before:
            self.rep.test("  nothing")


def header_value(name, mark, current="", replace=False):
    """A payload shaped like what the header is supposed to carry.

    A host header holding an IP address is discarded by half the frameworks
    that read it, so the canary is dressed as the right kind of value.
    """
    if current:
        # A header that came from the capture already has a value the
        # application accepted. Keep it unless told otherwise.
        return payload_for(current, mark, replace)
    n = name.lower()
    if "scheme" in n or "proto" in n or n == "front-end-https":
        return mark + "://"
    if n in ("x-forwarded-port",):
        return "1337"
    if "url" in n:
        return "/" + mark
    if "ip" in n or n == "x-forwarded-for":
        return "127.0.0.1, " + mark
    if n == "origin":
        return "https://" + mark + ".example.net"
    return mark + ".example.net"


def is_switch(name):
    """A header that changes the application's behaviour rather than being
    echoed. It carries no canary in the second probe shape: its job is to
    flip the branch the carrier then steers."""
    n = name.lower()
    return ("scheme" in n or "proto" in n or n.endswith("-ssl")
            or n == "front-end-https" or n == "x-forwarded-port")


def trigger_value(name):
    """A value that makes a header DO something rather than carry a canary.

    A scheme header is ignored when it agrees with the scheme in use, so the
    one value that provokes a reaction is any other. Same idea for the rest:
    the point is to flip the application's behaviour, not to be reflected.
    """
    n = name.lower()
    if "scheme" in n or "proto" in n or n == "front-end-https":
        return "nothttps"
    if n.endswith("-ssl"):
        return "off"
    if n == "x-forwarded-port":
        return "1337"
    return "wcp-trigger"


def load_header_names(path, rep):
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    out.append(line.rstrip(":"))
    except OSError as e:
        rep.warn("--headers-file: %s" % e)
    return out


def private_tokens(authed, anon, noise, limit=40):
    """Words the signed-in page has and the anonymous one does not."""
    a = set((noise.apply(normalize(authed)) if noise
             else normalize(authed)).split(" "))
    b = set((noise.apply(normalize(anon)) if noise
             else normalize(anon)).split(" "))
    only = {w for w in (a - b) if len(w) >= 6}
    # Longest first, not alphabetical. Sorting by name selects whatever
    # starts with a digit -- ids, timestamps, build hashes -- which is the
    # part of a signed-in page LEAST likely to be private and most likely to
    # move between renders.
    return set(sorted(only, key=lambda w: (-len(w), w))[:limit])


def has_tokens(body, tokens, noise, need=0.6):
    if not tokens:
        return False
    words = set((noise.apply(normalize(body)) if noise
                 else normalize(body)).split(" "))
    return len(tokens & words) >= max(1, int(need * len(tokens)))


# ----------------------------------------------------------------------------
# targets
# ----------------------------------------------------------------------------

def parse_raw_request(path, force_ssl, rep):
    """A raw HTTP request as Burp or ZAP exports it.

    The method, the headers -- Cookie included -- and the body are replayed.
    The scheme is http unless --force-ssl, or unless an absolute Origin or
    Referer in the file says otherwise.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    raw = raw.replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = [l for l in head.split("\n") if l.strip()]
    if not lines:
        raise ValueError("empty request file")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError("cannot read the request line: %s" % lines[0][:80])
    method, target = parts[0].upper(), parts[1]
    # Burp writes "HTTP/2" for a request it made over TLS: h2 without TLS is
    # not what a browser speaks, so the version alone settles the scheme.
    proto = parts[2].upper() if len(parts) > 2 else ""

    headers = {}
    for l in lines[1:]:
        if ":" in l:
            k, _, v = l.partition(":")
            headers[k.strip()] = v.strip()

    host = headers.get("Host") or headers.get("host") or ""
    scheme = "https" if force_ssl else "http"
    if not force_ssl and proto.startswith("HTTP/2"):
        scheme = "https"
        rep.info("-r: request line says %s, assuming https" % proto)
    if not force_ssl and scheme == "http":
        for h in ("Origin", "Referer"):
            v = headers.get(h, "")
            if v.startswith("https://"):
                scheme = "https"
                break
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        url = "%s://%s%s" % (scheme, host, target)

    if method != "GET":
        rep.warn("-r: the request is %s; caches store GET responses almost "
                 "exclusively, so the GET surface of this URL is what gets "
                 "tested" % method)
    return url, headers, body.strip()


def load_targets(args, rep):
    urls, raw_headers = [], {}
    if args.url:
        urls = [args.url]
    elif args.list:
        with open(args.list, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    urls.append(line)
    elif args.request:
        u, raw_headers, _body = parse_raw_request(args.request,
                                                  args.force_ssl, rep)
        urls = [u]
    out, seen = [], set()
    for u in urls:
        if "://" not in u:
            u = ("https://" if args.force_ssl else "http://") + u
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out, raw_headers


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="wcphunt.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="web cache poisoning detection",
        epilog="""
A finding means one thing only: a request carrying none of the tool's input
came back carrying its canary, out of the cache. Reflection alone is never
reported -- a page that reflects but is never cached is not a cache poisoning
finding, and this tool says so rather than filling a report with it.

Every request carries a unique cache buster, so the tool works inside a cache
key no real visitor produces. The buster is verified against each target
before anything is injected; a target where it does not partition the cache is
refused rather than tested.
""")

    g = p.add_argument_group("targets")
    g.add_argument("-u", dest="url", help="single URL to test")
    g.add_argument("-l", dest="list", help="file containing a list of URLs")
    g.add_argument("-r", dest="request", metavar="FILE",
                   help="raw HTTP request file (Burp/ZAP export): method, "
                        "headers (Cookie...) and body are replayed")
    g.add_argument("--force-ssl", action="store_true",
                   help="force https for a -r request (default: http, "
                        "inferred from Origin/Referer)")

    g = p.add_argument_group("vectors (all opt-in)")
    g.add_argument("--enable-headers", action="store_true",
                   help="unkeyed request headers (X-Forwarded-Host & co)")
    g.add_argument("--enable-params", action="store_true",
                   help="the query parameters already in the URL: the ones "
                        "this application is known to read")
    g.add_argument("--enable-params-common", action="store_true",
                   help="the generic tracking parameters (utm_*, fbclid, "
                        "gclid, ref, t...) that CDNs commonly drop from the "
                        "cache key, whether or not the page uses them. A "
                        "different question from --enable-params, so a "
                        "different switch")
    g.add_argument("--enable-fatget", action="store_true",
                   help="fat GET: a GET carrying a request body, whose "
                        "parameters the application reads and the cache key "
                        "ignores. Overrides a KEYED query parameter through "
                        "an unkeyed channel")
    g.add_argument("--enable-norm", action="store_true",
                   help="cache key normalization and delimiter discrepancies")
    g.add_argument("--enable-deception", action="store_true",
                   help="cache deception: the victim's private response "
                        "stored under a URL the attacker can fetch. Needs a "
                        "session (--auth-file/--auth-dir or -H)")
    g.add_argument("--enable-all", action="store_true",
                   help="every vector above")
    g.add_argument("--headers-file", metavar="FILE",
                   help="extra candidate header names, one per line, '#' for "
                        "comments. Added to the built-in list, never replaces it")
    g.add_argument("--deception-min", type=int, default=3, metavar="N",
                   help="fragments that must separate the signed-in page from "
                        "the anonymous one before cache deception is tested "
                        "(default 3). Below it there is nothing to leak, and "
                        "what little differs is usually per-render noise")
    g.add_argument("--replace", action="store_true",
                   help="overwrite the parameter instead of appending the "
                        "payload to its current value (default: append)")
    g.add_argument("--age-probe", type=float, default=3.0, metavar="SEC",
                   help="on a target that emits Age and no cache status "
                        "header, wait this long between two fresh keys to "
                        "see whether the Age actually advances (default 3). "
                        "An Age that does not move is an origin stamping a "
                        "constant, not a cache serving one entry. 0 disables "
                        "the probe, and the target is then refused rather "
                        "than reported")
    g.add_argument("--no-key-probe", action="store_true",
                   help="do not ask the cache for its key. The probe costs one "
                        "request per target and, when the cache answers, "
                        "replaces the HIT/MISS inference about what is in the "
                        "key with a reading of it")
    g.add_argument("--max-carriers", type=int, default=8, metavar="N",
                   help="at most N reflected inputs get the full subtraction "
                        "pass per probe (default 8). A page that echoes its "
                        "whole request otherwise spends the run proving the "
                        "same thing forty times")
    g.add_argument("--header-group", type=int, default=0, metavar="N",
                   help="split the candidate headers into batches of N "
                        "instead of probing them all at once. Default 0, "
                        "meaning one probe: batching cannot assemble a "
                        "combination whose members fall into different "
                        "batches, so raise this only for a server that "
                        "rejects a request carrying every candidate")

    g = p.add_argument_group("requests")
    g.add_argument("-t", "--threads", type=int, default=5,
                   help="concurrent URLs to scan (default 5)")
    g.add_argument("--timeout", type=float, default=15.0,
                   help="request timeout (s)")
    g.add_argument("-d", "--delay", type=float, default=0.0,
                   help="minimum gap between requests (s), enforced globally "
                        "across all threads")
    g.add_argument("-H", "--header", action="append", metavar="HEADER",
                   help="extra header 'Name: value' (repeatable) - also how "
                        "to set a Cookie or override the User-Agent")
    g.add_argument("-x", "--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")

    g = p.add_argument_group("authentication")
    g.add_argument("--auth-file", metavar="FILE",
                   help="headers to authenticate with, -H syntax, one per "
                        "line, '#' for comments. Applied to EVERY target "
                        "whatever the file is called")
    g.add_argument("--auth-dir", metavar="DIR",
                   help="directory of auth files named after the host they "
                        "authenticate: www.example.com.txt covers every port "
                        "of that host, www.example.com_8080.txt covers that "
                        "port only and wins over it. No subdomain "
                        "inheritance. Mutually exclusive with --auth-file")

    g = p.add_argument_group("output")
    g.add_argument("-v", dest="verbose", type=int, nargs="?", const=1,
                   default=0, choices=[0, 1, 2],
                   help="verbosity: 0 = only successes (default), 1 = every "
                        "test performed, 2 = debug (full request and the "
                        "exact payload sent, response status/size, and what "
                        "was skipped and why)")
    g.add_argument("-o", "--output", help="write JSON report to this file")
    g.add_argument("--status-interval", type=float, default=30.0, metavar="SEC",
                   help="seconds between status lines in -l mode (default 30)")
    g.add_argument("--confirm-x", type=int, default=3, metavar="N",
                   help="stop testing a URL once N findings are confirmed "
                        "(default 3)")
    g.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    g.add_argument("--version", action="version",
                   version="wcphunt " + VERSION)
    return p


def main():
    args = build_parser().parse_args()

    if args.no_color or not sys.stdout.isatty():
        Colors.off()
    rep = Reporter(args.verbose)

    if args.enable_all:
        args.enable_headers = args.enable_params = True
        args.enable_params_common = args.enable_fatget = True
        args.enable_norm = args.enable_deception = True
    vectors = [n for n, on in (("headers", args.enable_headers),
                               ("params", args.enable_params),
                               ("params-common", args.enable_params_common),
                               ("fatget", args.enable_fatget),
                               ("norm", args.enable_norm),
                               ("deception", args.enable_deception)) if on]
    if not vectors:
        rep.warn("no vector enabled. Pick at least one of --enable-headers, "
                 "--enable-params, --enable-params-common, --enable-fatget, "
                 "--enable-norm, --enable-deception, or --enable-all")
        return 2
    if not (args.url or args.list or args.request):
        rep.warn("one of -u, -l or -r is required")
        return 2
    if args.auth_file and args.auth_dir:
        rep.warn("--auth-file and --auth-dir are mutually exclusive")
        return 2

    try:
        auth = AuthStore.load(args.auth_file, args.auth_dir, rep)
    except ValueError as e:
        rep.warn(str(e))
        return 2
    auth.describe(rep)

    try:
        urls, raw_headers = load_targets(args, rep)
    except (OSError, ValueError) as e:
        rep.warn("cannot read targets: %s" % e)
        return 2
    if not urls:
        rep.warn("no target to test")
        return 2

    http = Http(args, auth, rep)
    if raw_headers:
        for k, v in raw_headers.items():
            if k.lower() not in ("host", "content-length", "connection",
                                 "accept-encoding"):
                http.cli_headers.setdefault(k, v)

    rep.line("%s%swcphunt %s%s  |  %d target(s), vectors: %s"
             % (Colors.BOLD, Colors.CYAN, VERSION, Colors.RESET,
                len(urls), ", ".join(vectors)))

    status = Status(rep, len(urls), args.status_interval,
                    enabled=bool(args.list) and len(urls) > 1)
    hunter = Hunter(args, http, rep, None, status)
    status.start()
    t0 = time.time()

    def work(u):
        try:
            hunter.run_url(u)
        except Exception as e:
            rep.warn("%s: %s" % (u, e))
        finally:
            status.url_done()

    if args.threads > 1 and len(urls) > 1:
        from multiprocessing.dummy import Pool
        pool = Pool(args.threads)
        pool.map(work, urls)
        pool.close()
        pool.join()
    else:
        for u in urls:
            work(u)

    status.stop()
    if status.enabled:
        status.emit("final")

    # An informational cache-key reading is not a poisoning and must not be
    # counted as one: a summary saying "3 confirmed" for one poisoning and
    # two observations is how a report gets read as three vulnerabilities.
    poisoned = [f for f in hunter.findings if f.level != "info"]
    observed = len(hunter.findings) - len(poisoned)
    rep.line("")
    rep.line("%s%d poisoning(s) confirmed, %d cache-key observation(s), "
             "%d request(s) in %.1fs%s"
             % (Colors.BOLD, sum(1 for f in poisoned if f.confirmed),
                observed, http.sent, time.time() - t0, Colors.RESET))
    if args.verbose >= 1:
        hunter.why_not()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({"version": VERSION,
                       "targets": urls,
                       "vectors": vectors,
                       "requests": http.sent,
                       "findings": [asdict(f) for f in hunter.findings]},
                      fh, indent=2, ensure_ascii=False)
        rep.line("JSON report written to %s" % args.output)
    # Exit code: 0 unless a poisoning was confirmed. Informational
    # cache-key observations do not fail a pipeline.
    return 1 if any(f.confirmed and f.level != "info"
                    for f in hunter.findings) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        sys.exit(130)
