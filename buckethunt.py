#!/usr/bin/env python3
"""
buckethunt — cloud object-storage permission tester.

Three phases:
  1. DETECT   is this bucket-backed, which provider, and what is the bucket
              actually called
  2. ASSESS   which permissions anonymous callers hold: READ, LIST, ACL/IAM
              read, WRITE, DELETE
  3. COLLECT  bounded inventory of what LIST exposes, flagging the object names
              that matter

Supports Google Cloud Storage, Amazon S3 and Azure Blob Storage, including
buckets fronted by a custom domain (the common case for SPA hosting, where the
hostname gives no hint that object storage is behind it).

The WRITE test writes exactly one file whose content is the current date and
nothing else, then verifies it and deletes it. That is the whole write
capability: the filename and body are hardcoded, there is no flag to supply
content, and nothing else is ever written. A dated file is enough for a company
to confirm the finding and is harmless if cleanup fails.

For authorized testing only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import re
import sys
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] pip install requests")

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

CRIT, HIGH, MED, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
_SEV_ORDER = {CRIT: 0, HIGH: 1, MED: 2, LOW: 3, INFO: 4}

GCS, S3, AZURE = "gcs", "s3", "azure"

# Object names that change the severity of a LIST finding.
SENSITIVE_RX = re.compile(
    r"\.(env|pem|key|p12|pfx|jks|kdbx|sql|bak|dump|tar|tgz|zip|7z|rar|"
    r"log|cfg|conf|config|ini|yml|yaml|json|xls[xm]?|csv|docx?|pdf)$|"
    r"(secret|credential|password|passwd|token|apikey|api_key|private|"
    r"backup|dump|id_rsa|\.git/|\.aws/|\.ssh/|serviceaccount|service-account)",
    re.I)


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
    """v=0 prints confirmed findings only. v=1 prints every test."""

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
            print(f"  {paint('Target    :', 'head')} {f.target}")
            print(f"  {paint('Provider  :', 'head')} {f.provider}")
            print(f"  {paint('Bucket    :', 'head')} {paint(f.bucket, 'b')}")
            print(f"  {paint('Permission:', 'head')} {paint(f.permission, f.sev)}")
            if f.evidence:
                for ln in f.evidence.splitlines():
                    print(f"  {paint('Evidence  :', 'head')} {ln}")
            if f.curl:
                print(f"  {paint('PoC       :', 'head')} {paint(f.curl, 'warn')}")
            sys.stdout.flush()

    def test(self, target, name, result, extra=""):
        if self.level < 1:
            return
        self.line(f"  {paint('·', 'dim')}  {paint(target, 'dim')}  "
                  f"{name:<40} {paint(f'{result:<5}', status_key(result))} "
                  f"{paint(extra, 'dim')}")

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
    target: str
    provider: str
    bucket: str
    permission: str
    sev: str = HIGH
    evidence: str = ""
    curl: str = ""
    when: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Resp:
    status: int
    body: str
    headers: dict
    error: str = ""

    @property
    def ok(self):
        return not self.error

    @property
    def length(self):
        return len(self.body)


@dataclass
class Bucket:
    provider: str
    name: str
    base: str          # API base for object operations
    origin: str        # the URL we were given
    via_custom_domain: bool = False


# ----------------------------------------------------------------------------
# http
# ----------------------------------------------------------------------------

class Http:
    def __init__(self, console, timeout=20.0, delay=0.0, proxy=None, verify=False):
        self.con = console
        self.timeout = timeout
        self.verify = verify
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
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
            s.headers.update({"User-Agent": UA})
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

    def req(self, method, url, data=None, headers=None) -> Resp:
        self._throttle()
        with self._cnt_lk:
            self.count += 1
        try:
            r = self._session().request(method, url, data=data, headers=headers,
                                        timeout=self.timeout, verify=self.verify,
                                        proxies=self.proxies,
                                        allow_redirects=False)
            body = r.text if len(r.content) < 2_000_000 else r.text[:2_000_000]
            return Resp(r.status_code, body, dict(r.headers))
        except requests.RequestException as e:
            return Resp(0, "", {}, error=str(e))

    def get(self, url, **kw):
        return self.req("GET", url, **kw)


# ----------------------------------------------------------------------------
# detection
# ----------------------------------------------------------------------------

class Detector:
    """
    Works out whether a URL is backed by object storage, and what the bucket is
    called.

    Custom-domain hosting is the interesting case: the hostname reveals nothing,
    so the provider has to be inferred from response headers, and the bucket name
    guessed from the hostname (for GCS and S3 website hosting the bucket is
    conventionally named after the domain it serves).
    """

    def __init__(self, http: Http, con: Console):
        self.http = http
        self.con = con

    @staticmethod
    def _provider_from_headers(h: dict) -> str | None:
        low = {k.lower(): v for k, v in h.items()}
        server = low.get("server", "").lower()
        if any(k.startswith("x-goog-") for k in low) or server == "uploadserver":
            return GCS
        if any(k.startswith("x-amz-") for k in low) or "amazons3" in server:
            return S3
        if any(k.startswith("x-ms-") for k in low) or "blob" in server:
            return AZURE
        return None

    def candidates(self, url: str) -> list[Bucket]:
        u = urlsplit(url if "://" in url else "https://" + url)
        # netloc keeps the port; hostname is only for matching provider domains.
        # Stripping the port here (and assuming https) silently broke every
        # target not on 443.
        netloc = u.netloc
        host = netloc.split(":")[0]
        scheme = u.scheme or "https"
        origin = f"{scheme}://{netloc}"
        path = u.path.strip("/")
        out: list[Bucket] = []

        # explicit provider URLs
        if host in ("storage.googleapis.com", "storage.cloud.google.com"):
            name = path.split("/")[0] if path else ""
            if name:
                out.append(Bucket(GCS, name, f"https://storage.googleapis.com/{name}", url))
            return out
        m = re.match(r"^(.+?)\.storage\.googleapis\.com$", host)
        if m:
            out.append(Bucket(GCS, m.group(1),
                              f"https://storage.googleapis.com/{m.group(1)}", url))
            return out
        m = re.match(r"^(.+?)\.s3[.-][\w-]*\.?amazonaws\.com$", host)
        if m:
            out.append(Bucket(S3, m.group(1), f"https://{host}", url))
            return out
        if host.endswith(".amazonaws.com") and path:
            name = path.split("/")[0]
            out.append(Bucket(S3, name, f"https://{host}/{name}", url))
            return out
        m = re.match(r"^(.+?)\.blob\.core\.windows\.net$", host)
        if m:
            container = path.split("/")[0] if path else "$root"
            out.append(Bucket(AZURE, f"{m.group(1)}/{container}",
                              f"https://{host}/{container}", url))
            return out

        # custom domain (or any other host): probe it and infer from headers
        r = self.http.get(origin + "/" + (path.split("/")[0] if path else ""))
        prov = self._provider_from_headers(r.headers) if r.ok else None
        self.con.test(url, "storage probe", r.status if r.ok else "err",
                      f"provider={prov or 'unknown'}")
        if not prov:
            return out

        # path-style on an arbitrary host: first path segment is the bucket
        if path:
            first = path.split("/")[0]
            out.append(Bucket(prov, first, f"{origin}/{first}", url,
                              via_custom_domain=True))

        # virtual-host style: the bucket is conventionally named after the domain
        names = [host]
        if host.startswith("www."):
            names.append(host[4:])
        names.append(host.replace(".", "-"))
        for n in dict.fromkeys(names):
            if prov == GCS:
                out.append(Bucket(GCS, n, f"https://storage.googleapis.com/{n}",
                                  url, via_custom_domain=True))
            elif prov == S3:
                out.append(Bucket(S3, n, f"https://{n}.s3.amazonaws.com", url,
                                  via_custom_domain=True))
        if not path:
            # the served domain itself is an operable base for READ/WRITE tests
            out.append(Bucket(prov, f"(via {host})", origin, url,
                              via_custom_domain=True))
        return out


# ----------------------------------------------------------------------------
# permission tests
# ----------------------------------------------------------------------------

class BucketHunter:
    # The write PoC. Filename identifies the test; the body is the date and
    # nothing else, exactly as specified for the client's proof of concept.
    POC_PREFIX = "buckethunt-poc-"

    def __init__(self, http: Http, con: Console, args, status: Status = None):
        self.http = http
        self.con = con
        self.args = args
        self.status = status
        self.det = Detector(http, con)
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

    # -- listing

    @staticmethod
    def _list_url(b: Bucket) -> str:
        if b.provider == GCS:
            return b.base + "?max-keys=100"
        if b.provider == S3:
            return b.base + "?list-type=2&max-keys=100"
        return b.base + "?restype=container&comp=list"

    @staticmethod
    def _parse_keys(body: str) -> list[str]:
        keys = []
        try:
            root = ET.fromstring(body)
            for el in root.iter():
                tag = el.tag.split("}")[-1]
                if tag in ("Key", "Name") and el.text and "/" not in el.text[:1]:
                    keys.append(el.text)
        except ET.ParseError:
            keys = re.findall(r"<Key>([^<]+)</Key>", body)
        return keys

    def test_list(self, b: Bucket) -> list[str]:
        url = self._list_url(b)
        r = self.http.get(url)
        self.bump()
        listable = (r.ok and r.status == 200
                    and ("<ListBucketResult" in r.body or "<EnumerationResults" in r.body))
        self.con.test(b.origin, f"LIST {b.name}", r.status if r.ok else "err",
                      "listable" if listable else "denied")
        if not listable:
            return []
        keys = self._parse_keys(r.body)
        sens = [k for k in keys if SENSITIVE_RX.search(k)]
        sev = HIGH if sens else MED
        self.add(Finding(
            title="Bucket contents listable by anonymous users",
            target=b.origin, provider=b.provider, bucket=b.name,
            permission="LIST (storage.objects.list)", sev=sev,
            evidence=f"{len(keys)} object(s) enumerated"
                     + (f"\n{len(sens)} with sensitive-looking names, e.g. "
                        f"{', '.join(sens[:3])}" if sens else ""),
            curl=f"curl -sk '{url}'"))
        return keys

    # -- acl / iam

    # A response only counts as an ACL/policy if it IS one. Each entry is the
    # document's own structural signature, not a keyword that might appear in
    # prose. Checked against the parsed document, never the raw page.
    ACL_SIGNATURES = {
        "s3 bucket ACL": re.compile(
            r"<AccessControlPolicy|<AccessControlList|<Grantee|<Owner>"),
        "s3 bucket policy": re.compile(
            r'"Statement"\s*:|"Effect"\s*:\s*"(?:Allow|Deny)"'),
        "gcs IAM policy": re.compile(
            r'"kind"\s*:\s*"storage#policy"|"bindings"\s*:\s*\['),
        "gcs bucket ACL": re.compile(
            r'"kind"\s*:\s*"storage#(?:bucketAccessControls?|objectAccessControls?)"'),
        "gcs bucket metadata": re.compile(r'"kind"\s*:\s*"storage#bucket"'),
    }

    @staticmethod
    def _is_document(resp: Resp) -> bool:
        """Content-Type must be XML or JSON. An HTML page is never an ACL."""
        ct = ""
        for k, v in resp.headers.items():
            if k.lower() == "content-type":
                ct = v.lower()
                break
        if "html" in ct or "text/plain" in ct:
            return False
        if not any(t in ct for t in ("xml", "json")):
            # some endpoints omit or mislabel it; fall back to the body shape
            head = resp.body.lstrip()[:1]
            return head in ("<", "{", "[") and not resp.body.lstrip()[:14].lower().startswith("<!doctype html")
        return True

    def test_acl(self, b: Bucket):
        """
        Read the bucket ACL / IAM policy.

        Three independent gates, because `?acl` and `?policy` are ordinary query
        parameters that any web server happily ignores while returning its
        homepage -- 200, plenty of bytes, and previously reported as a finding:

          1. Content-Type must be XML or JSON, never text/html
          2. the body must match the structural signature of the document type
             actually requested
          3. the body must DIFFER from the same URL without the query string;
             if they match, the parameter was ignored and nothing was disclosed
        """
        urls = []
        if b.provider == GCS and not b.name.startswith("("):
            urls = [(f"https://storage.googleapis.com/storage/v1/b/{b.name}/iam",
                     "gcs IAM policy", None),
                    (f"https://storage.googleapis.com/storage/v1/b/{b.name}/acl",
                     "gcs bucket ACL", None),
                    (f"https://storage.googleapis.com/storage/v1/b/{b.name}",
                     "gcs bucket metadata", None)]
        elif b.provider == S3:
            urls = [(b.base + "?acl", "s3 bucket ACL", b.base),
                    (b.base + "?policy", "s3 bucket policy", b.base)]

        for url, label, plain in urls:
            r = self.http.get(url)
            self.bump()
            if not (r.ok and r.status == 200 and len(r.body) > 20):
                self.con.test(b.origin, f"ACL {label}",
                              r.status if r.ok else "err", "denied")
                continue

            # gate 1 — document, not a web page
            if not self._is_document(r):
                self.con.test(b.origin, f"ACL {label}", r.status,
                              "rejected: HTML page, not a policy document")
                continue

            # gate 2 — the right kind of document
            sig = self.ACL_SIGNATURES.get(label)
            if sig and not sig.search(r.body):
                self.con.test(b.origin, f"ACL {label}", r.status,
                              "rejected: no policy structure in body")
                continue

            # gate 3 — the query parameter actually changed something
            if plain:
                base_r = self.http.get(plain)
                self.bump()
                if base_r.ok and base_r.body[:2000] == r.body[:2000]:
                    self.con.test(b.origin, f"ACL {label}", r.status,
                                  "rejected: identical to plain URL, param ignored")
                    continue

            self.con.test(b.origin, f"ACL {label}", r.status, "readable")
            public = re.findall(r"allUsers|allAuthenticatedUsers|AllUsers|"
                                r"AuthenticatedUsers", r.body)
            sev = CRIT if public else MED
            self.add(Finding(
                title=f"{label.capitalize()} readable by anonymous users",
                target=b.origin, provider=b.provider, bucket=b.name,
                permission=f"READ {label}", sev=sev,
                evidence=(f"public principals present: {sorted(set(public))}"
                          if public else "policy disclosed to anonymous callers")
                         + f"\n{r.body[:200]}",
                curl=f"curl -sk '{url}'"))

    # -- read

    def test_read(self, b: Bucket, keys: list[str]):
        target = keys[0] if keys else None
        if not target:
            r = self.http.get(b.base + "/index.html")
            self.bump()
            ok = r.ok and r.status == 200
            self.con.test(b.origin, "READ index.html",
                          r.status if r.ok else "err", "readable" if ok else "denied")
            return
        url = f"{b.base}/{target}"
        r = self.http.get(url)
        self.bump()
        ok = r.ok and r.status == 200
        self.con.test(b.origin, f"READ {target[:28]}", r.status if r.ok else "err",
                      f"{r.length}b" if ok else "denied")
        if ok and SENSITIVE_RX.search(target):
            self.add(Finding(
                title="Sensitive object readable by anonymous users",
                target=b.origin, provider=b.provider, bucket=b.name,
                permission="READ (storage.objects.get)", sev=HIGH,
                evidence=f"{target} — {r.length} bytes",
                curl=f"curl -sk '{url}'"))

    # -- write (the PoC)

    def test_write(self, b: Bucket):
        """
        Write exactly one file whose body is the current date, verify it, delete
        it, then confirm the deletion.

        Opt-in via --allow-write. The name and the body are fixed here; there is
        no way to write anything else with this tool.
        """
        stamp = datetime.now(timezone.utc)
        fname = f"{self.POC_PREFIX}{stamp.strftime('%Y%m%d-%H%M%S')}.txt"
        body = stamp.strftime("%Y-%m-%d") + "\n"   # the current date, nothing else
        url = f"{b.base}/{fname}"

        r = self.http.req("PUT", url, data=body.encode(),
                          headers={"Content-Type": "text/plain"})
        self.bump()
        wrote = r.ok and r.status in (200, 201, 204)
        self.con.test(b.origin, f"WRITE {fname[:28]}", r.status if r.ok else "err",
                      "accepted" if wrote else "denied")
        if not wrote:
            return False

        # a 2xx on PUT is not proof: read it back
        v = self.http.get(url)
        self.bump()
        confirmed = v.ok and v.status == 200 and body.strip() in v.body
        self.con.test(b.origin, "WRITE verify (read back)",
                      v.status if v.ok else "err",
                      "confirmed" if confirmed else "not present")
        if not confirmed:
            self.con.debug("  PUT returned 2xx but the object is not readable "
                           "— not treating as writable")
            return False

        self.add(Finding(
            title="Bucket is WRITABLE by anonymous users",
            target=b.origin, provider=b.provider, bucket=b.name,
            permission="WRITE (storage.objects.create)", sev=CRIT,
            evidence=f"uploaded {fname} containing only the date "
                     f"{body.strip()}, read it back, now deleting it\n"
                     f"A bucket that serves a website and accepts anonymous "
                     f"writes allows replacing site content.",
            curl=f"curl -sk -X PUT '{url}' --data '{body.strip()}'"))
        self._cleanup(b, url, fname)
        return True

    def _cleanup(self, b: Bucket, url: str, fname: str):
        d = self.http.req("DELETE", url)
        self.bump()
        v = self.http.get(url)
        self.bump()
        gone = v.status in (403, 404) or not v.ok
        self.con.line(paint(
            f"    cleanup {fname} -> DELETE {d.status}, re-read {v.status} "
            + ("(removed)" if gone else "(STILL PRESENT — remove manually)"),
            "ok" if gone else "bad"))
        if not gone:
            self.add(Finding(
                title="Cleanup failed — test artifact left in bucket",
                target=b.origin, provider=b.provider, bucket=b.name,
                permission="DELETE denied", sev=HIGH,
                evidence=f"{fname} could not be deleted. Remove it manually and "
                         f"disclose it in the report.",
                curl=f"curl -sk -X DELETE '{url}'"))

    # -- driver

    def run_target(self, url: str):
        self.con.banner(f"Testing {url}")
        buckets = self.det.candidates(url)
        if not buckets:
            with self._lk:
                self.skipped.append({"url": url, "reason": "no object storage detected"})
            self.con.skip(f"{url} — no object storage detected")
            return

        self.con.info(f"{len(buckets)} bucket candidate(s): "
                      f"{', '.join(b.name for b in buckets)}")
        for b in buckets:
            self.con.info(f"testing {b.provider} bucket '{b.name}' at {b.base}")
            keys = self.test_list(b)
            self.test_acl(b)
            self.test_read(b, keys)
            if self.args.allow_write:
                self.test_write(b)


# ----------------------------------------------------------------------------
# cli
# ----------------------------------------------------------------------------

BANNER = r"""
  buckethunt — cloud storage permission tester
  authorized testing only
"""

EPILOG = """
providers
  Google Cloud Storage, Amazon S3, Azure Blob. Buckets fronted by a custom
  domain are detected from response headers (x-goog-*, x-amz-*, x-ms-*,
  Server: UploadServer) and the bucket name guessed from the hostname.

permissions tested
  LIST   anonymous object enumeration
  ACL    bucket ACL / IAM policy readable, and whether allUsers appears in it
  READ   object retrieval
  WRITE  opt-in, see below
  DELETE only ever used to remove this tool's own test file

the write test
  Off unless --allow-write. It writes ONE file named buckethunt-poc-<timestamp>
  whose entire content is the current date, reads it back to confirm (a 2xx on
  PUT alone is not proof), then deletes it and verifies the deletion. Filename
  and body are hardcoded -- there is no option to write anything else. If
  cleanup fails that is reported as a finding so it is not left silently behind.

safety
  Every target you supply is requested. There is no allowlist -- feed it a
  pre-filtered, in-scope list.

colour
  On by default. Disable with --no-color or NO_COLOR=1.

status line
  In -l mode a heartbeat prints every 30s (--status-interval) at any verbosity.
  Not shown for -u.

examples
  buckethunt.py -u https://blueberry.example.com
  buckethunt.py -u https://storage.googleapis.com/my-bucket -v 1
  buckethunt.py -l hosts-scope.txt
  buckethunt.py -u https://assets.example.com --allow-write
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="buckethunt.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", type=int, default=0, choices=[0, 1, 2], dest="verbosity",
                   help="0 = confirmed findings only (default), 1 = every test, "
                        "2 = debug")
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
    p.add_argument("--timeout", type=float, default=20.0, help="request timeout")
    p.add_argument("-p", "--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--allow-write", action="store_true",
                   help="WRITE PoC: upload one dated file, verify, delete "
                        "(mutates the bucket)")
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
    print(f"  write PoC "
          f"{paint('ON (one dated file)', 'bad') if args.allow_write else paint('off', 'ok')}"
          + (f"        status every {args.status_interval:.0f}s"
             if status.enabled else ""))
    print()

    http = Http(con, timeout=args.timeout, delay=args.delay, proxy=args.proxy)
    hunter = BucketHunter(http, con, args, status)

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
    print(f"\n  {paint(str(len(hunter.findings)), 'b')} finding(s) from "
          f"{http.count} requests in {elapsed:.0f}s")
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
