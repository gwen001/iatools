#!/usr/bin/env python3
"""
sstihunt.py - Server-Side Template Injection test harness.

Detects SSTI by injecting arithmetic template expressions and checking whether
the server *evaluates* them (e.g. {{1234*5678}} coming back as the product,
framed by random markers so a coincidental number is never mistaken for a hit).
When a family fires it fingerprints the engine where it can be told apart
(Jinja2 vs Twig, etc.).

Injection points:
  * GET parameters
  * URL path segments (directories / sub-directories) + one appended segment
  * discovered HTML forms (GET or POST)
  * when a URL has no parameter and no form, common SSTI parameter names

Detection only: it proves the template engine evaluates attacker input (the
prerequisite for RCE) using harmless maths - it does NOT run OS commands. A
confirmed hit in most engines escalates to RCE; that step is engine-specific
and left to manual verification (noted in each finding).

TLS verification is disabled (targets routinely use self-signed/expired certs
or sit behind an intercepting proxy). Stdlib only.

For authorized testing only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.cookiejar
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
from html.parser import HTMLParser

VERSION = "1.0.0"
MAX_BODY = 3 * 1024 * 1024

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# Tried when a URL exposes no query string and no form. Names that commonly
# reach a template (greetings, search echoes, error/preview rendering...).
COMMON_PARAMS = [
    "q", "s", "search", "query", "keyword", "name", "username", "user", "id",
    "page", "view", "template", "tpl", "lang", "locale", "message", "msg",
    "text", "content", "body", "title", "subject", "comment", "data", "input",
    "preview", "format", "redirect", "url", "email", "to", "from", "error",
    "greeting", "hello", "nickname", "profile", "description",
]

INERT_INPUT_TYPES = frozenset({"submit", "button", "image", "reset", "file"})

# Escalation reference for the report (detection tool - RCE steps are left to
# manual verification against this catalogue).
PAYLOADS_ALL_THE_THINGS = ("https://github.com/swisskyrepo/PayloadsAllTheThings/"
                           "tree/master/Server%20Side%20Template%20Injection")

PREFLIGHT_TRIES = 3
PREFLIGHT_BACKOFF = 1.0


# ----------------------------------------------------------------------------
# Template-expression wrappers
# ----------------------------------------------------------------------------
# Each entry: (build(core) -> payload, required_chars, candidate engines, fp).
# `core` is the arithmetic expression, e.g. "1234*5678".
# `fp` == "curly" marks the plain {{ }} family, the only one worth the extra
# Jinja2-vs-Twig fingerprint request; everything else keeps its candidate label.

WRAPPERS = [
    (lambda c: "{{" + c + "}}", "{}", "Jinja2 / Django / Twig / Nunjucks / Handlebars / "
     "Mustache / Hogan / Vue / Blade / Liquid / Tornado / Bottle / Jinjava / Pebble / "
     "Pystache ({{ }})", "jinja_twig"),
    (lambda c: "{{=" + c + "}}", "{}=", "DotJS / Lodash / Underscore / EJS ({{= }})", None),
    (lambda c: "${" + c + "}", "${}", "FreeMarker / Groovy / Mako / Chameleon / Cheetah / "
     "SpEL / JSP-EL / Thymeleaf (${ })", "dollar"),
    (lambda c: "${{" + c + "}}", "${}", "Spring EL / Java (${{ }})", None),
    (lambda c: "#{" + c + "}", "#{}", "Pug / HAML / Slim / SpEL / Thymeleaf / FreeMarker / "
     "Ruby / Codepen (#{ })", None),
    (lambda c: "<%= " + c + " %>", "<%>", "ERB / Erubi / Erubis / EEx / LEEx / HEEx / JSP / "
     "EJS / Underscore (<%= %>)", None),
    (lambda c: "<%- " + c + " %>", "<%>-", "EJS unescaped (<%- %>)", None),
    (lambda c: "<?= " + c + " ?>", "<?>", "Plates / PHP short echo (<?= ?>)", None),
    (lambda c: "{" + c + "}", "{}", "Smarty / Dust / Latte / Tornado ({ })", None),
    (lambda c: "@(" + c + ")", "@()", "Razor (@( ))", None),
    (lambda c: "*{" + c + "}", "*{}", "SpEL / Thymeleaf (*{ })", None),
    (lambda c: "[[${" + c + "}]]", "[]${}", "Thymeleaf inline ([[${ }]])", None),
    (lambda c: "[=" + c + "]", "[]=", "FreeMarker bracket syntax ([= ])", None),
    (lambda c: "#set($ssti=" + c + ")$ssti", "#$()=", "Velocity / VelocityJS (#set)", None),
]


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
        for a in cls._ATTRS:
            setattr(cls, a, "")


# ----------------------------------------------------------------------------
# Status heartbeat (turquoise), list mode only
# ----------------------------------------------------------------------------

class Status:
    def __init__(self, reporter, total, interval=30.0, enabled=True):
        self.rep = reporter
        self.total = total
        self.interval = interval
        self.enabled = enabled
        self.done = 0
        self.confirmed = 0
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

    def record_hit(self):
        with self._lk:
            self.confirmed += 1

    def emit(self, label="status"):
        if not self.enabled:
            return
        with self._lk:
            done, conf = self.done, self.confirmed
        rem = max(0, self.total - done)
        el = int(time.time() - self._t0)
        c = Colors
        self.rep.line(f"{c.CYAN}[{label} {el // 60:02d}:{el % 60:02d}]  "
                      f"tested {done}/{self.total}  remaining {rem}  "
                      f"|  confirmed {conf}{c.RESET}")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------

class Reporter:
    def __init__(self, level=0, logfh=None):
        self.level = level
        self.logfh = logfh
        self.lock = threading.Lock()

    def _emit(self, text, plain=None):
        with self.lock:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
            if self.logfh:
                self.logfh.write((plain if plain is not None else text) + "\n")
                self.logfh.flush()

    def line(self, text):
        # status heartbeat : strip colours for the log
        self._emit(text, plain=re.sub(r"\033\[[0-9;]*m", "", text))

    def hit(self, f: "Finding"):
        c = Colors
        lines = [
            "",
            f"{c.GREEN}{c.BOLD}[VULNERABLE]{c.RESET} {c.BOLD}{f.kind}{c.RESET}",
            f"  {c.CYAN}URL      :{c.RESET} {f.url}",
            f"  {c.CYAN}Method   :{c.RESET} {f.method}",
            f"  {c.CYAN}Parameter:{c.RESET} {f.param} ({f.location})",
            f"  {c.CYAN}Engine   :{c.RESET} {f.engine}",
            f"  {c.CYAN}Payload  :{c.RESET} {c.YELLOW}{f.payload}{c.RESET}",
            f"  {c.CYAN}Evidence :{c.RESET} {f.evidence}",
            f"  {c.CYAN}Confirm  :{c.RESET} {c.YELLOW}{f.confirm}{c.RESET}"
            f"  {c.GREY}(rendu attendu : {f.expected}){c.RESET}",
        ]
        if f.poc:
            lines.append(f"  {c.CYAN}PoC      :{c.RESET} {f.poc}")
        if f.escalation:
            lines.append(f"  {c.CYAN}Escalade :{c.RESET} {f.escalation}")
        lines.append(f"  {c.GREY}note     : SSTI confirmé par exécution (opération évaluée). "
                     f"Escalade RCE spécifique au moteur, à vérifier manuellement.{c.RESET}")
        plain = re.sub(r"\033\[[0-9;]*m", "", "\n".join(lines))
        self._emit("\n".join(lines), plain=plain)

    def maybe(self, f: "Finding"):
        c = Colors
        lines = [
            "",
            f"{c.YELLOW}{c.BOLD}[POTENTIAL]{c.RESET} {c.BOLD}{f.kind}{c.RESET}",
            f"  {c.CYAN}URL      :{c.RESET} {f.url}",
            f"  {c.CYAN}Parameter:{c.RESET} {f.param} ({f.location})",
            f"  {c.CYAN}Evidence :{c.RESET} {f.evidence}",
        ]
        plain = re.sub(r"\033\[[0-9;]*m", "", "\n".join(lines))
        self._emit("\n".join(lines), plain=plain)

    def test(self, msg):
        if self.level >= 1:
            self._emit(f"{Colors.GREY}[test]{Colors.RESET} {msg}",
                       plain=f"[test] {msg}")

    def info(self, msg):
        if self.level >= 1:
            self._emit(f"{Colors.BLUE}[info]{Colors.RESET} {msg}",
                       plain=f"[info] {msg}")

    def debug(self, msg):
        if self.level >= 2:
            self._emit(f"{Colors.MAGENTA}[dbg ]{Colors.RESET} {msg}",
                       plain=f"[dbg ] {msg}")

    def warn(self, msg):
        if self.level >= 1:
            self._emit(f"{Colors.YELLOW}[warn]{Colors.RESET} {msg}",
                       plain=f"[warn] {msg}")

    def skip(self, msg):
        self._emit(f"{Colors.YELLOW}{Colors.BOLD}[skip]{Colors.RESET} {msg}",
                   plain=f"[skip] {msg}")

    def error(self, msg):
        self._emit(f"{Colors.RED}[err ]{Colors.RESET} {msg}",
                   plain=f"[err ] {msg}")

    def banner(self, msg):
        if self.level >= 1:
            self._emit(f"\n{Colors.BOLD}{Colors.BLUE}=== {msg} ==={Colors.RESET}",
                       plain=f"\n=== {msg} ===")


# ----------------------------------------------------------------------------
# Data model
# ----------------------------------------------------------------------------

@dataclass
class Finding:
    kind: str
    url: str
    param: str
    location: str = "query"
    method: str = "GET"
    engine: str = ""
    payload: str = ""          # exact value injected (with random markers)
    evidence: str = ""
    poc: str = ""              # reproducible URL (marker payload)
    confirm: str = ""          # clean copy/paste payload for the report
    expected: str = ""         # expected rendered result of `confirm`
    escalation: str = ""       # reference for RCE escalation
    confidence: str = "confirmed"


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
class Form:
    action: str
    method: str = "GET"
    enctype: str = "application/x-www-form-urlencoded"
    inputs: dict = field(default_factory=dict)
    types: dict = field(default_factory=dict)

    def field_values(self):
        return {k: (v or "test") for k, v in self.inputs.items()}

    def injectable(self):
        names = [n for n, t in self.types.items() if t not in INERT_INPUT_TYPES]
        return names or list(self.inputs.keys())

    def resolved(self, page_url):
        action = urllib.parse.urljoin(page_url, self.action or page_url)
        method = self.method if self.method in ("GET", "POST") else "GET"
        return action, method


# ----------------------------------------------------------------------------
# HTTP layer
# ----------------------------------------------------------------------------

class Requester:
    def __init__(self, timeout=10.0, proxy=None, headers=None, reporter=None):
        self.timeout = timeout
        self.reporter = reporter
        self.proxy = proxy
        self.base_headers = {"User-Agent": DEFAULT_UA,
                             "Accept": "text/html,application/xhtml+xml,"
                                       "application/xml;q=0.9,*/*;q=0.8",
                             "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
                             "Accept-Encoding": "gzip, deflate",
                             "Connection": "close"}
        for h in headers or []:
            if ":" in h:
                k, _, v = h.partition(":")
                self.base_headers[k.strip()] = v.strip()
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

    def request(self, url, method="GET", data=None, extra_headers=None) -> Response:
        headers = dict(self.base_headers)
        if extra_headers:
            headers.update(extra_headers)
        body = None
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, (str, bytes)):
            # raw body (e.g. a JSON body replayed from a -r request); the
            # Content-Type travels in the replayed headers, so nothing is forced
            body = data.encode() if isinstance(data, str) else data
        req = urllib.request.Request(url, data=body, method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        started = time.time()
        with self._count_lock:
            self.count += 1
        try:
            with self._opener().open(req, timeout=self.timeout) as resp:
                raw = resp.read(MAX_BODY)
                cs = resp.headers.get_content_charset() or "utf-8"
                return Response(resp.geturl(), resp.status, dict(resp.headers),
                                raw.decode(cs, errors="replace"), time.time() - started)
        except urllib.error.HTTPError as e:
            try:
                text = e.read(MAX_BODY).decode("utf-8", errors="replace")
            except Exception:
                text = ""
            return Response(url, e.code, dict(e.headers or {}), text,
                            time.time() - started)
        except Exception as e:
            if self.reporter:
                self.reporter.debug(f"request failed {url}: {e}")
            return Response(url, 0, {}, "", time.time() - started, error=str(e))


# ----------------------------------------------------------------------------
# HTML parsing (forms only)
# ----------------------------------------------------------------------------

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[Form] = []
        self._current = None

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

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def parse_page(html):
    p = FormParser()
    try:
        p.feed(html)
        p.close()
    except Exception:
        pass
    return p


# ----------------------------------------------------------------------------
# URL helpers
# ----------------------------------------------------------------------------

def set_query_param(url, param, value):
    parts = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    new, found = [], False
    for k, v in qs:
        if k == param:
            new.append((k, value)); found = True
        else:
            new.append((k, v))
    if not found:
        new.append((param, value))
    query = urllib.parse.urlencode(new, quote_via=urllib.parse.quote)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    query, parts.fragment))


def path_segments(url):
    return [s for s in urllib.parse.urlsplit(url).path.split("/") if s]


def set_path_segment(url, index, value):
    parts = urllib.parse.urlsplit(url)
    segs = [s for s in parts.path.split("/") if s]
    encoded = urllib.parse.quote(value, safe="")
    if index >= len(segs):
        segs.append(encoded); trailing = False
    else:
        segs[index] = encoded; trailing = parts.path.endswith("/")
    path = "/" + "/".join(segs) + ("/" if trailing else "")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path,
                                    parts.query, parts.fragment))


# ----------------------------------------------------------------------------
# Injection point
# ----------------------------------------------------------------------------

@dataclass
class Point:
    url: str
    param: str | None = None
    method: str = "GET"
    data: dict | None = None
    path_index: int | None = None
    # -- raw-request (-r) context --
    inject: str = ""                 # "" (infer) | query | path | body | getform
    headers: dict | None = None      # headers replayed on every probe (Cookie...)
    raw_body: str | None = None      # non-form body (JSON...) replayed as-is

    @property
    def kind(self):
        if self.inject:
            return {"getform": "query"}.get(self.inject, self.inject)
        if self.path_index is not None:
            return "path"
        if self.method == "POST":
            return "body"
        return "query"

    @property
    def name(self):
        if self.path_index is not None:
            return f"path[{self.path_index}]"
        return self.param or "-"

    def label(self):
        if self.path_index is not None:
            n = len(path_segments(self.url))
            return ("path[+] appended segment" if self.path_index >= n
                    else f"path[{self.path_index}] segment")
        return f"{self.param} ({self.kind})"


# ----------------------------------------------------------------------------
# Payload helpers
# ----------------------------------------------------------------------------

def rand_token(n=6):
    return "z" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def rand_operands():
    """Two 4-digit numbers; their product is distinctive enough to avoid FPs."""
    a = random.randint(1000, 9999)
    b = random.randint(1000, 9999)
    return a, b


# ----------------------------------------------------------------------------
# Scanner
# ----------------------------------------------------------------------------

class Scanner:
    def __init__(self, req: Requester, rep: Reporter, args, status: Status = None):
        self.req = req
        self.rep = rep
        self.args = args
        self.status = status
        self.findings: list[Finding] = []
        self.skipped: list[dict] = []
        self.lock = threading.Lock()
        self.tested = 0

    def add(self, f: Finding):
        with self.lock:
            self.findings.append(f)
        if f.confidence == "confirmed":
            if self.status:
                self.status.record_hit()
            self.rep.hit(f)
        else:
            self.rep.maybe(f)

    def bump(self):
        with self.lock:
            self.tested += 1

    # -- request funnel ------------------------------------------------------

    def _inject_kind(self, pt: Point) -> str:
        if pt.inject:
            return pt.inject
        if pt.path_index is not None:
            return "path"
        if pt.method == "POST" and pt.data is not None:
            return "body"
        if pt.data is not None:
            return "getform"
        return "query"

    def base_value(self, pt: Point) -> str:
        if pt.path_index is not None:
            segs = path_segments(pt.url)
            return (urllib.parse.unquote(segs[pt.path_index])
                    if pt.path_index < len(segs) else "")
        inj = self._inject_kind(pt)
        if inj in ("body", "getform"):
            return (pt.data.get(pt.param) or "") if pt.data else ""
        # query: read the parameter's current value from the URL
        for k, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(pt.url).query,
                                           keep_blank_values=True):
            if k == pt.param:
                return v
        return ""

    def compose(self, payload: str, pt: Point) -> str:
        if self.args.replace:
            return payload
        return self.base_value(pt) + payload

    def _place(self, pt: Point, sent: str):
        extra = dict(pt.headers) if pt.headers else None
        inj = self._inject_kind(pt)

        # body replayed on query/path injection so a POST request stays valid
        if pt.method == "POST":
            replay_body = dict(pt.data) if pt.data is not None else pt.raw_body
        else:
            replay_body = None

        if inj == "path":
            return set_path_segment(pt.url, pt.path_index, sent), replay_body, extra
        if inj == "body":
            body = dict(pt.data or {}); body[pt.param] = sent
            return pt.url, body, extra
        if inj == "getform":
            fields = dict(pt.data); fields[pt.param] = sent
            joiner = "&" if "?" in pt.url else "?"
            return pt.url + joiner + urllib.parse.urlencode(fields), None, extra
        # query
        return set_query_param(pt.url, pt.param, sent), replay_body, extra

    def send(self, pt: Point, value: str, label="inject") -> tuple[Response, str]:
        sent = self.compose(value, pt)
        target, body, extra = self._place(pt, sent)
        self.rep.debug(f"{label} | {pt.method} {target}")
        self.rep.debug(f"  payload [{pt.label()}] len={len(sent)}: {sent}")
        if body:
            shown = urllib.parse.urlencode(body) if isinstance(body, dict) else body
            self.rep.debug(f"  body: {shown}")
        resp = self.req.request(target, method=pt.method, data=body, extra_headers=extra)
        self.bump()
        if resp.ok:
            self.rep.debug(f"  -> {resp.status} {len(resp.body)}b {resp.elapsed:.2f}s")
        else:
            self.rep.debug(f"  -> failed: {resp.error}")
        return resp, sent

    def _poc(self, pt: Point, sent: str) -> str:
        # raw-request target: reproducible curl (method + body + cookie)
        if pt.headers is not None:
            target, body, extra = self._place(pt, sent)
            parts = [f"curl -sk -X {pt.method} '{target}'"]
            cookie = next((v for k, v in (extra or {}).items()
                           if k.lower() == "cookie"), None)
            if cookie:
                parts.append(f"-b '{cookie}'")
            if body is not None:
                b = urllib.parse.urlencode(body) if isinstance(body, dict) else body
                parts.append(f"--data '{b}'")
            return " ".join(parts)
        if pt.path_index is not None:
            return set_path_segment(pt.url, pt.path_index, sent)
        if pt.method == "GET" and pt.data is None and pt.param is not None:
            return set_query_param(pt.url, pt.param, sent)
        return ""

    # -- engine fingerprint --------------------------------------------------

    def fingerprint(self, pt: Point, fp_family: str, default_engine: str) -> str:
        """
        Confirm/refine the engine once an injection has fired, by executing a
        second, engine-discriminating expression (7 * '7'):

          {{ }} family : Jinja2/Nunjucks render '7777777' (Python string
                         repetition); Twig renders '49' (numeric coercion).
          ${ } family  : Mako/Groovy render '7777777'; FreeMarker/JSP-EL '49'.

        Marker-framed so the discriminator is read from execution, never from a
        coincidental substring.
        """
        if fp_family not in ("jinja_twig", "dollar"):
            return default_engine
        m1, m2 = rand_token(), rand_token()
        expr = "{{7*'7'}}" if fp_family == "jinja_twig" else "${7*'7'}"
        resp, _ = self.send(pt, m1 + expr + m2, label="fingerprint")
        if resp.ok and resp.body:
            if m1 + "7777777" + m2 in resp.body:
                return ("Jinja2 / Nunjucks (confirmé : 7*'7' -> 7777777)"
                        if fp_family == "jinja_twig" else
                        "Mako / Groovy (confirmé : ${7*'7'} -> 7777777)")
            if m1 + "49" + m2 in resp.body:
                return ("Twig (confirmé : 7*'7' -> 49)" if fp_family == "jinja_twig"
                        else "FreeMarker / JSP-EL (confirmé : ${7*'7'} -> 49)")
        return default_engine

    # -- core per-point test -------------------------------------------------

    def test_point(self, pt: Point, label: str) -> bool:
        """
        Detection is EXECUTION-based, never reflection-based: each wrapper's
        arithmetic (a random NNNN*NNNN) is sent and a hit is declared only when
        the *product* comes back, framed by random markers. A template engine
        processes the delimiters before the output is HTML-escaped, so we never
        gate on whether the raw characters survive in the response - that would
        miss engines whose output is encoded.
        """
        executed = False
        for build, required, engines, fp in WRAPPERS:
            m1, m2 = rand_token(), rand_token()
            a, b = rand_operands()
            product = str(a * b)
            core = f"{a}*{b}"
            payload = m1 + build(core) + m2
            self.rep.test(f"  {pt.method} {pt.name} <- {build(core)}  [{engines}]")
            r, sent = self.send(pt, payload, label="ssti")
            if not r.ok or not r.body:
                continue
            needle = m1 + product + m2
            if needle in r.body:
                executed = True
                engine = self.fingerprint(pt, fp, engines)
                confirm = build("7*7")
                self.add(Finding(
                    kind="Server-Side Template Injection",
                    url=pt.url, param=pt.name, location=pt.kind, method=pt.method,
                    engine=engine,
                    payload=sent,
                    evidence=f"{build(core)} exécuté -> {product} "
                             f"(encadré par marqueurs : {needle})",
                    confirm=confirm, expected="49",
                    escalation=f"{PAYLOADS_ALL_THE_THINGS} (fiche du moteur identifié)",
                    poc=self._poc(pt, sent)))
                return True
            # literal came back but the maths was NOT evaluated -> not SSTI here
            if m1 + build(core) + m2 in r.body:
                self.rep.debug(f"  reflété tel quel, non exécuté : {build(core)}")
        if not executed:
            self.rep.test(f"  {label}: aucune expression de template exécutée")
        return False

    # -- vectors -------------------------------------------------------------

    def test_query_param(self, url, param):
        self.rep.test(f"GET {param} @ {url}")
        self.test_point(Point(url, param=param), param)

    def test_path(self, url):
        segs = path_segments(url)
        indexes = list(range(len(segs)))[-self.args.max_path_segments:]
        indexes.append(len(segs))
        for i in indexes:
            label = f"path[{i}]" if i < len(segs) else "path[+]"
            cur = segs[i] if i < len(segs) else "(new segment)"
            self.rep.test(f"GET {label} @ {url} (current: {cur})")
            self.test_point(Point(url, path_index=i), label)

    def test_form(self, page_url, form: Form):
        action, method = form.resolved(page_url)
        if "multipart" in form.enctype.lower():
            self.rep.warn(f"skipping multipart form {action} (not supported)")
            return
        fields = form.field_values()
        self.rep.info(f"form {method} {action} fields={list(fields)}")
        for name in form.injectable():
            self.rep.test(f"{method} form field {name} @ {action}")
            self.test_point(Point(action, param=name, method=method, data=fields), name)

    # -- orchestration -------------------------------------------------------

    def preflight(self, url):
        last = ""
        for attempt in range(1, PREFLIGHT_TRIES + 1):
            resp = self.req.request(url)
            if resp.ok and not (300 <= resp.status < 400) and resp.status < 500:
                if resp.url != url:
                    self.rep.info(f"{url}: redirected to {resp.url}")
                return resp
            last = resp.error or f"HTTP {resp.status}"
            self.rep.warn(f"{url}: attempt {attempt}/{PREFLIGHT_TRIES} failed ({last})")
            if attempt < PREFLIGHT_TRIES:
                time.sleep(PREFLIGHT_BACKOFF * attempt)
        with self.lock:
            self.skipped.append({"url": url, "reason": last})
        self.rep.skip(f"{url} - no usable response after {PREFLIGHT_TRIES} attempts "
                      f"({last}); skipped")
        return None

    def scan(self, url):
        self.rep.banner(f"Scanning {url}")
        base = self.preflight(url)
        if base is None:
            return
        self.rep.info(f"{base.status} {base.header('Content-Type', '?')} "
                      f"{len(base.body)} bytes ({base.elapsed:.2f}s)")

        query = urllib.parse.urlsplit(url).query
        params = list(dict.fromkeys(
            k for k, _ in urllib.parse.parse_qsl(query, keep_blank_values=True)))
        page = parse_page(base.body)

        if not params and not page.forms and not self.args.no_guess:
            params = COMMON_PARAMS
            self.rep.info(f"no parameters found - trying common SSTI names "
                          f"({len(params)})")

        for p in params:
            self.test_query_param(url, p)
        if not self.args.no_path:
            self.test_path(url)
        if not self.args.no_forms:
            for form in page.forms:
                self.test_form(url, form)

    def scan_request(self, spec: "RequestSpec"):
        """
        Scan a target described by a raw HTTP request (-r): the method, headers
        (Cookie...) and body are replayed on every probe, and the injection
        points are the query parameters, the path segments and the (form) body
        fields — governed by the same --no-path / --no-forms options.
        """
        url = spec.url
        self.rep.banner(f"Scanning (raw request) {spec.method} {url}")

        pre_body = None
        if spec.method == "POST":
            pre_body = dict(spec.body_params) if spec.body_params else spec.raw_body

        base, last = None, ""
        for attempt in range(1, PREFLIGHT_TRIES + 1):
            resp = self.req.request(url, method=spec.method, data=pre_body,
                                    extra_headers=spec.headers)
            if resp.ok and resp.status < 500 and not (300 <= resp.status < 400):
                base = resp
                break
            last = resp.error or f"HTTP {resp.status}"
            self.rep.warn(f"{url}: attempt {attempt}/{PREFLIGHT_TRIES} failed ({last})")
            if attempt < PREFLIGHT_TRIES:
                time.sleep(PREFLIGHT_BACKOFF * attempt)
        if base is None:
            with self.lock:
                self.skipped.append({"url": url, "reason": last})
            self.rep.skip(f"{url} - no usable response after {PREFLIGHT_TRIES} "
                          f"attempts ({last}); skipped")
            return
        self.rep.info(f"{base.status} {base.header('Content-Type', '?')} "
                      f"{len(base.body)} bytes ({base.elapsed:.2f}s)")

        params = list(dict.fromkeys(
            k for k, _ in urllib.parse.parse_qsl(
                urllib.parse.urlsplit(url).query, keep_blank_values=True)))
        if not params and not spec.body_params and not self.args.no_guess:
            params = COMMON_PARAMS
            self.rep.info(f"no parameters in the request - trying common SSTI "
                          f"names ({len(params)})")

        ctx = dict(method=spec.method,
                   data=(dict(spec.body_params) if spec.body_params else None),
                   raw_body=(spec.raw_body if not spec.body_params else None),
                   headers=spec.headers)
        if spec.body_params:
            self.rep.info(f"body {spec.method} fields: {list(spec.body_params)}")

        for p in params:
            self.rep.test(f"{spec.method} query {p} @ {url}")
            self.test_point(Point(url, param=p, inject="query", **ctx), p)
        if not self.args.no_path:
            segs = path_segments(url)
            indexes = list(range(len(segs)))[-self.args.max_path_segments:]
            indexes.append(len(segs))
            for i in indexes:
                label = f"path[{i}]" if i < len(segs) else "path[+]"
                self.rep.test(f"{spec.method} {label} @ {url}")
                self.test_point(Point(url, path_index=i, inject="path", **ctx), label)
        if spec.body_params and not self.args.no_forms:
            for name in spec.body_params:
                self.rep.test(f"{spec.method} body {name} @ {url}")
                self.test_point(Point(url, param=name, inject="body", **ctx), name)


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def normalize(u):
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u


def load_urls(path):
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

# Headers we must not replay verbatim: urllib derives them (Host from the URL,
# Content-Length from the body) or they would break parsing.
_RAW_SKIP_HEADERS = frozenset({
    "host", "content-length", "connection", "proxy-connection", "keep-alive",
    "transfer-encoding", "te",
})


@dataclass
class RequestSpec:
    method: str
    url: str
    headers: dict                                    # replayed on every probe
    body_params: dict = field(default_factory=dict)  # urlencoded body fields
    raw_body: str | None = None                       # non-form body (JSON...)


def _infer_scheme(headers):
    """http by default; https if an Origin/Referer is itself https."""
    for h in ("Origin", "Referer"):
        v = headers.get(h) or headers.get(h.lower())
        if v and v.lower().startswith("https://"):
            return "https"
        if v and v.lower().startswith("http://"):
            return "http"
    return "http"


def parse_raw_request(path, force_ssl=False) -> RequestSpec:
    """
    Parse a raw HTTP request file (Burp/ZAP export, or hand-written): request
    line, headers and body. Query, path and (form) body fields are the injection
    points; method, headers and body are replayed on every probe. Scheme is http
    by default (inferred from Origin/Referer, or forced with --force-ssl) since
    an origin-form request line does not carry one.
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

    headers = {}
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

    # replayed headers: drop hop-by-hop; force identity encoding (this tool does
    # not gunzip) so the template output stays readable
    fwd = {k: v for k, v in headers.items() if k.lower() not in _RAW_SKIP_HEADERS}
    fwd["Accept-Encoding"] = "identity"

    body_params, raw_body = {}, None
    body = body.strip()
    if body:
        ctype = next((v.lower() for k, v in headers.items()
                      if k.lower() == "content-type"), "")
        looks_form = ("urlencoded" in ctype
                      or ("=" in body and not body.lstrip().startswith(("{", "["))))
        if looks_form:
            pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
            if pairs:
                body_params = dict(pairs)
            else:
                raw_body = body
        else:
            raw_body = body       # JSON or other: replayed as-is, not decomposed
    return RequestSpec(method, url, fwd, body_params, raw_body)


def build_parser():
    p = argparse.ArgumentParser(
        prog="sstihunt.py",
        description="Test for Server-Side Template Injection in GET parameters, "
                    "URL paths and forms.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  sstihunt.py -u 'https://target/hello?name=test'
  sstihunt.py -v 1 -u 'https://target/page'
  sstihunt.py -l urls.txt -v 1 -t 10 -o report.txt
  sstihunt.py -r request.txt -v 1
  sstihunt.py -l urls.txt -r request.txt --force-ssl

status line
  In -l mode a turquoise heartbeat prints every 30s (--status-interval) at any
  verbosity: URLs tested / total and remaining. Not shown for a single -u.

Detection only (harmless arithmetic). Use only against authorized systems.""")
    p.add_argument("-v", dest="verbose", type=int, nargs="?", const=1, default=0,
                   choices=[0, 1, 2],
                   help="verbosity: 0 = only successes (default), 1 = every test "
                        "performed, 2 = debug (full request and the exact payload "
                        "sent, response status/size, and payloads that reflected "
                        "without executing)")
    p.add_argument("-u", dest="url", help="single URL to test")
    p.add_argument("-l", dest="list", help="file containing a list of URLs to test")
    p.add_argument("-r", "--request-file", dest="request_file", metavar="FILE",
                   help="target defined by a raw HTTP request file (Burp 'Copy "
                        "to file' / 'Save item' format, or hand-written) -- "
                        "method, headers and body are all reused for every probe, "
                        "and body fields (form) are injected alongside query and "
                        "path. Combines with -u/-l as one more target")
    p.add_argument("--force-ssl", action="store_true",
                   help="force https for a -r request (default: http, inferred "
                        "from Origin/Referer)")
    p.add_argument("-t", "--threads", type=int, default=5,
                   help="concurrent URLs to scan (default 5)")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="extra header 'Name: value' (repeatable) - also how to "
                        "set a Cookie or override the User-Agent")
    p.add_argument("-p", "--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("-o", "--output", help="write text report to this file")
    p.add_argument("--status-interval", type=float, default=30.0, metavar="SEC",
                   help="seconds between status lines in -l mode (default 30)")
    p.add_argument("--timeout", type=float, default=10.0, help="request timeout (s)")
    p.add_argument("--max-path-segments", type=int, default=3,
                   help="how many trailing path segments to inject into "
                        "(default 3, plus one appended segment)")
    p.add_argument("--no-guess", action="store_true",
                   help="don't try common parameter names on parameterless URLs")
    p.add_argument("--no-path", action="store_true",
                   help="skip URL path injection tests")
    p.add_argument("--no-forms", action="store_true", help="skip form tests")
    p.add_argument("--replace", action="store_true",
                   help="overwrite the parameter instead of appending the payload "
                        "to its current value (default: append)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def collect_targets(args):
    urls = []
    if args.url:
        urls.append(normalize(args.url))
    if args.list:
        if not os.path.isfile(args.list):
            print(f"error: no such file: {args.list}", file=sys.stderr)
            return None
        urls.extend(load_urls(args.list))
    return list(dict.fromkeys(urls))


def run_scans(scanner, targets, rep, args, status):
    def one(t):
        try:
            if isinstance(t, RequestSpec):
                scanner.scan_request(t)
            else:
                scanner.scan(t)
        except Exception as e:
            label = t.url if isinstance(t, RequestSpec) else t
            rep.error(f"{label}: {e}")
        finally:
            status.host_done()
    if args.threads > 1 and len(targets) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            list(ex.map(one, targets))
    else:
        for t in targets:
            one(t)


def write_report(path, scanner, req, urls, elapsed):
    c = Colors
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"sstihunt {VERSION} report\n")
        fh.write(f"generated : {time.strftime('%Y-%m-%dT%H:%M:%S')}\n")
        fh.write(f"targets   : {len(urls)}\n")
        fh.write(f"requests  : {req.count}\n")
        fh.write(f"duration  : {elapsed:.1f}s\n")
        confirmed = [f for f in scanner.findings if f.confidence == "confirmed"]
        fh.write(f"confirmed : {len(confirmed)}\n")
        if scanner.skipped:
            fh.write(f"\nskipped ({len(scanner.skipped)}):\n")
            for s in scanner.skipped:
                fh.write(f"  - {s['url']}  [{s['reason']}]\n")
        fh.write("\n=== findings ===\n")
        for f in scanner.findings:
            fh.write(f"\n[{f.confidence.upper()}] {f.kind}\n")
            fh.write(f"  URL      : {f.url}\n")
            fh.write(f"  Method   : {f.method}\n")
            fh.write(f"  Parameter: {f.param} ({f.location})\n")
            fh.write(f"  Engine   : {f.engine}\n")
            fh.write(f"  Payload  : {f.payload}\n")
            fh.write(f"  Evidence : {f.evidence}\n")
            if f.confirm:
                fh.write(f"  Confirm  : {f.confirm}   (rendu attendu : {f.expected})\n")
            if f.poc:
                fh.write(f"  PoC      : {f.poc}\n")
            if f.escalation:
                fh.write(f"  Escalade : {f.escalation}\n")
    print(f"report       : {path}")


def print_summary(scanner, req, urls, elapsed):
    c = Colors
    confirmed = [f for f in scanner.findings if f.confidence == "confirmed"]
    print(f"\n{c.BOLD}--- summary ---{c.RESET}")
    print(f"targets      : {len(urls)}")
    if scanner.skipped:
        print(f"{c.YELLOW}skipped      : {len(scanner.skipped)}{c.RESET}")
        for s in scanner.skipped:
            print(f"               - {s['url']}  [{s['reason']}]")
    print(f"tests sent   : {scanner.tested} (HTTP requests: {req.count})")
    print(f"duration     : {elapsed:.1f}s")
    print(f"{c.GREEN}confirmed SSTI: {len(confirmed)}{c.RESET}")
    return confirmed


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_color or os.environ.get("NO_COLOR"):
        Colors.disable()
    if not args.url and not args.list and not args.request_file:
        build_parser().print_help()
        return 2
    urls = collect_targets(args)
    if urls is None:
        return 2

    # -r adds one more target (combines with -u/-l)
    targets = list(urls)
    if args.request_file:
        if not os.path.isfile(args.request_file):
            print(f"error: no such file: {args.request_file}", file=sys.stderr)
            return 2
        try:
            targets.append(parse_raw_request(args.request_file,
                                             force_ssl=args.force_ssl))
        except Exception as e:
            print(f"error: cannot parse request ({args.request_file}): {e}",
                  file=sys.stderr)
            return 2
    if not targets:
        print("error: no targets", file=sys.stderr)
        return 2

    logfh = open(args.output, "w", encoding="utf-8") if args.output else None
    rep = Reporter(args.verbose, logfh=None)  # -o = report final, pas un tee live
    status = Status(rep, len(targets), interval=args.status_interval,
                    enabled=bool(args.list))
    if args.verbose >= 1:
        rep.info(f"sstihunt {VERSION} - {len(targets)} target(s), {args.threads} thread(s)")

    req = Requester(timeout=args.timeout, proxy=args.proxy, headers=args.header,
                    reporter=rep)
    scanner = Scanner(req, rep, args, status)

    started = time.time()
    status.start()
    try:
        run_scans(scanner, targets, rep, args, status)
    except KeyboardInterrupt:
        rep.error("interrupted by user")
    finally:
        status.stop()
        status.emit(label="final")
    elapsed = time.time() - started

    confirmed = print_summary(scanner, req, targets, elapsed)
    if args.output:
        write_report(args.output, scanner, req, targets, elapsed)
    if logfh:
        logfh.close()
    return 1 if confirmed else 0


if __name__ == "__main__":
    sys.exit(main())
