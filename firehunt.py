#!/usr/bin/env python3
"""
firehunt — Firebase security-rules tester.

Three phases:
  1. DETECT   find the Firebase config (it ships in client JS by design) and
              derive the Realtime Database, Firestore and Storage endpoints
  2. ASSESS   what anonymous callers may READ and WRITE, and -- separately --
              what a self-registered account may read and write
  3. COLLECT  bounded sample of exposed data, flagging the field names that
              decide severity

Two things this tool is built around:

  * The Firebase apiKey is NOT a secret. It is a project identifier meant to be
    public, and reporting it as a leaked credential is a classic invalid
    submission. Security comes entirely from the rules, so the finding is always
    what the rules permit -- never the key itself.

  * `allow read, write: if request.auth != null` reads like "logged-in users
    only" but means *any* Firebase identity. Where the project permits anonymous
    or self-service signup, an attacker mints their own token and the rule is
    equivalent to open. That case is tested on every run, because it is the one
    that actually shows up in the wild -- an anonymous-only scan reports such a
    project as secure.

The WRITE test writes one node named firehunt-poc-<timestamp> whose value is the
current date, verifies it, deletes it and confirms the deletion. Name and value
are hardcoded; there is no option to write anything else.

For authorized testing only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
import threading
import time
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

IDENTITY = "https://identitytoolkit.googleapis.com/v1"
FIRESTORE = "https://firestore.googleapis.com/v1"
FBSTORAGE = "https://firebasestorage.googleapis.com/v0"

# Collections/paths worth guessing: Firestore has no root listing, so blind
# enumeration is the only way in without knowing the schema.
COMMON_COLLECTIONS = [
    "users", "user", "accounts", "profiles", "profile", "customers", "members",
    "orders", "carts", "payments", "invoices", "transactions", "messages",
    "chats", "chat", "notifications", "posts", "comments", "reviews",
    "products", "items", "inventory", "stores", "config", "settings",
    "admin", "admins", "roles", "permissions", "tokens", "sessions",
    "logs", "events", "analytics", "feedback", "contacts", "subscriptions",
]

# Field names that decide whether exposed data is a Medium or a Critical.
SENSITIVE_FIELDS = re.compile(
    r"(email|e_?mail|phone|mobile|address|postcode|zip|iban|bic|card|"
    r"pan|cvv|ssn|nino|passport|dob|birth|password|passwd|hash|salt|"
    r"token|secret|api_?key|private|credential|auth|role|is_?admin|"
    r"permission|salary|invoice|order|payment|balance|firstname|lastname|"
    r"surname|fullname|nom|prenom|adresse|telephone)", re.I)


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
            print(f"  {paint('Project   :', 'head')} {paint(f.project, 'b')}")
            print(f"  {paint('Service   :', 'head')} {f.service}")
            print(f"  {paint('Access as :', 'head')} {f.identity}")
            print(f"  {paint('Permission:', 'head')} {paint(f.permission, f.sev)}")
            for ln in (f.evidence or "").splitlines():
                print(f"  {paint('Evidence  :', 'head')} {ln}")
            if f.curl:
                print(f"  {paint('PoC       :', 'head')} {paint(f.curl, 'warn')}")
            sys.stdout.flush()

    def test(self, target, name, result, extra=""):
        if self.level < 1:
            return
        self.line(f"  {paint('·', 'dim')}  {paint(target, 'dim')}  "
                  f"{name:<44} {paint(f'{result:<5}', status_key(result))} "
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

    def alert(self, title: str, lines: list[str], good=False):
        """
        Loud, always-shown operator notice — never suppressed by verbosity.

        Reserved for the tool changing the target's state. The operator has a
        disclosure obligation for anything left behind, so this must not be
        something you can miss by running at -v 0.
        """
        key = "ok" if good else "bad"
        bar = "!" * 66
        with self._lk:
            print(f"\n{paint(bar, key)}")
            print(f"{paint('[TARGET MODIFIED]', key)} {paint(title, 'b')}")
            for ln in lines:
                print(f"  {ln}")
            print(paint(bar, key))
            sys.stdout.flush()

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
    project: str
    service: str
    permission: str
    identity: str = "anonymous (no token)"
    sev: str = HIGH
    evidence: str = ""
    curl: str = ""
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

    def json(self):
        try:
            return json.loads(self.body)
        except Exception:
            return None


@dataclass
class FbConfig:
    project: str = ""
    api_key: str = ""
    auth_domain: str = ""
    database_url: str = ""
    storage_bucket: str = ""
    app_id: str = ""
    source: str = ""

    def rtdb_urls(self) -> list[str]:
        """Every plausible RTDB origin for this project."""
        out = []
        if self.database_url:
            out.append(self.database_url.rstrip("/"))
        if self.project:
            out.append(f"https://{self.project}.firebaseio.com")
            out.append(f"https://{self.project}-default-rtdb.firebaseio.com")
            for region in ("europe-west1", "asia-southeast1", "us-central1"):
                out.append(f"https://{self.project}-default-rtdb."
                           f"{region}.firebasedatabase.app")
        return list(dict.fromkeys(out))


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
                                        proxies=self.proxies, allow_redirects=False)
            return Resp(r.status_code, r.text[:1_000_000], dict(r.headers))
        except requests.RequestException as e:
            return Resp(0, "", {}, error=str(e))

    def get(self, url, **kw):
        return self.req("GET", url, **kw)


# ----------------------------------------------------------------------------
# detection
# ----------------------------------------------------------------------------

class Detector:
    """
    Recovers the Firebase config from a web app.

    The config object is public by design, so this is discovery, not a finding.
    A project is only confirmed when a projectId or databaseURL is present -- an
    apiKey alone means nothing, and plenty of non-Firebase SDKs use that name.
    """

    CFG_KEYS = ("apiKey", "authDomain", "databaseURL", "projectId",
                "storageBucket", "appId", "messagingSenderId")

    def __init__(self, http: Http, con: Console):
        self.http = http
        self.con = con

    @staticmethod
    def _direct(url: str) -> FbConfig | None:
        """The URL may already be a Firebase endpoint."""
        h = urlsplit(url if "://" in url else "https://" + url).netloc
        m = re.match(r"^([\w-]+?)(?:-default-rtdb)?\.(?:firebaseio\.com|"
                     r"[\w-]+\.firebasedatabase\.app)$", h)
        if m:
            return FbConfig(project=m.group(1),
                            database_url=f"https://{h}", source="URL")
        m = re.match(r"^([\w-]+)\.(?:firebaseapp\.com|web\.app)$", h)
        if m:
            return FbConfig(project=m.group(1), source="URL")
        return None

    def _scrape(self, text: str, where: str) -> FbConfig | None:
        vals = {}
        for k in self.CFG_KEYS:
            m = re.search(rf'["\']?{k}["\']?\s*[:=]\s*["\']([^"\']{{4,120}})["\']', text)
            if m:
                vals[k] = m.group(1)
        if not (vals.get("projectId") or vals.get("databaseURL")):
            return None       # apiKey alone is not a Firebase project
        proj = vals.get("projectId", "")
        if not proj and vals.get("databaseURL"):
            mm = re.match(r"https?://([\w-]+?)(?:-default-rtdb)?\.",
                          vals["databaseURL"])
            proj = mm.group(1) if mm else ""
        return FbConfig(project=proj, api_key=vals.get("apiKey", ""),
                        auth_domain=vals.get("authDomain", ""),
                        database_url=vals.get("databaseURL", ""),
                        storage_bucket=vals.get("storageBucket", ""),
                        app_id=vals.get("appId", ""), source=where)

    def find(self, url: str) -> FbConfig | None:
        direct = self._direct(url)
        if direct:
            self.con.test(url, "direct firebase endpoint", "ok",
                          f"project={direct.project}")
            return direct

        r = self.http.get(url)
        self.con.test(url, "fetch app", r.status if r.ok else "err")
        if not r.ok:
            return None
        cfg = self._scrape(r.body, "html")
        if cfg:
            return cfg

        # walk the JS bundles the page references
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.body)
        base = url.rstrip("/")
        origin = "{0.scheme}://{0.netloc}".format(urlsplit(
            url if "://" in url else "https://" + url))
        for s in scripts[:12]:
            full = s if s.startswith("http") else (
                origin + s if s.startswith("/") else base + "/" + s)
            js = self.http.get(full)
            if not js.ok:
                continue
            cfg = self._scrape(js.body, full.split("/")[-1])
            self.con.test(url, f"scan {full.split('/')[-1][:30]}", js.status,
                          "config found" if cfg else "")
            if cfg:
                return cfg
        return None


# ----------------------------------------------------------------------------
# scanner
# ----------------------------------------------------------------------------

class FireHunter:
    POC_PREFIX = "firehunt-poc-"

    def __init__(self, http: Http, con: Console, args, status: Status = None):
        self.http = http
        self.con = con
        self.args = args
        self.status = status
        self.det = Detector(http, con)
        self.findings: list[Finding] = []
        self.skipped: list[dict] = []
        # Accounts this tool created in target projects. Anything still in here
        # at the end could not be deleted and must be disclosed.
        self.accounts: list[dict] = []
        self._lk = threading.Lock()

    def add(self, f: Finding):
        with self._lk:
            self.findings.append(f)
        if self.status:
            self.status.record(f.sev)
        self.con.finding(f)

    # -- helpers

    @staticmethod
    def _auth_q(token: str | None) -> str:
        return f"?auth={token}" if token else ""

    @staticmethod
    def _sev_for(sample: str) -> str:
        return CRIT if SENSITIVE_FIELDS.search(sample or "") else MED

    def _ident(self, token) -> str:
        return "self-registered account" if token else "anonymous (no token)"

    # -- anonymous signup: the request.auth != null test

    def anon_token(self, cfg: FbConfig) -> str | None:
        """
        Mint a self-service identity.

        This is what turns `if request.auth != null` from a control into a
        formality, so it runs on every project as a standard test rather than an
        opt-in extra. It needs the apiKey recovered during detection.

        Note that accounts:signUp creates a user record in the project's auth
        backend -- a persistent change to the target. Disclose it in the report.
        """
        if not cfg.api_key:
            self.con.debug("  no apiKey recovered — cannot test self-registration")
            return None
        r = self.http.req("POST", f"{IDENTITY}/accounts:signUp?key={cfg.api_key}",
                          data=json.dumps({"returnSecureToken": True}),
                          headers={"Content-Type": "application/json"})
        j = r.json() or {}
        tok = j.get("idToken")
        uid = j.get("localId", "")
        self.con.test(cfg.project, "anonymous signUp", r.status,
                      "token issued" if tok else (j.get("error", {}) or {}).get("message", ""))
        if tok:
            with self._lk:
                self.accounts.append({"project": cfg.project, "uid": uid,
                                      "api_key": cfg.api_key, "id_token": tok,
                                      "created": datetime.now(timezone.utc).isoformat(),
                                      "deleted": False})
            self.con.alert(
                f"user record created in project '{cfg.project}'",
                [f"uid          : {paint(uid or 'unknown', 'b')}",
                 f"provider     : anonymous (accounts:signUp)",
                 f"why          : required to test `if request.auth != null` rules",
                 f"cleanup      : this tool will attempt accounts:delete when the "
                 f"project's tests finish",
                 f"if that fails: report the uid above so the client can remove it"])
            self.add(Finding(
                title="Anonymous authentication is enabled",
                target=cfg.project, project=cfg.project, service="Identity Toolkit",
                permission="accounts:signUp (anonymous)", sev=MED,
                identity="anonymous (no token)",
                evidence="Any caller can mint a valid idToken. Rules written as "
                         "`if request.auth != null` therefore grant public access.",
                curl=f"curl -s -X POST '{IDENTITY}/accounts:signUp?key={cfg.api_key}' "
                     f"-d '{{\"returnSecureToken\":true}}'"))
        return tok

    def delete_account(self, cfg: FbConfig, token: str):
        """
        Remove the account created for the auth test, and say plainly whether it
        worked. A tool that mutates a target has to close the loop.
        """
        r = self.http.req("POST", f"{IDENTITY}/accounts:delete?key={cfg.api_key}",
                          data=json.dumps({"idToken": token}),
                          headers={"Content-Type": "application/json"})
        ok = r.ok and r.status == 200
        uid = ""
        with self._lk:
            for a in self.accounts:
                if a["id_token"] == token:
                    a["deleted"] = ok
                    uid = a["uid"]
                    break
        self.con.test(cfg.project, "accounts:delete (cleanup)",
                      r.status if r.ok else "err", "removed" if ok else "FAILED")
        if ok:
            self.con.alert(f"user record removed from project '{cfg.project}'",
                           [f"uid : {uid or 'unknown'}",
                            "state: deleted — nothing left behind"], good=True)
        else:
            err = ((r.json() or {}).get("error", {}) or {}).get("message", r.status)
            self.con.alert(
                f"COULD NOT DELETE the account created in '{cfg.project}'",
                [f"uid   : {paint(uid or 'unknown', 'b')}",
                 f"error : {err}",
                 "action: disclose this uid in the report so the client removes it"])
            self.add(Finding(
                title="Test account could not be removed",
                target=cfg.project, project=cfg.project,
                service="Identity Toolkit", permission="accounts:delete denied",
                sev=HIGH, identity="self-registered account",
                evidence=f"uid {uid or 'unknown'} remains in the project's auth "
                         f"backend. Disclose it so the client can delete it.",
                curl=f"curl -s -X POST '{IDENTITY}/accounts:delete?key={cfg.api_key}' "
                     f"-d '{{\"idToken\":\"<token>\"}}'"))

    # -- realtime database

    def test_rtdb(self, cfg: FbConfig, token: str | None):
        for base in cfg.rtdb_urls():
            q = self._auth_q(token)
            r = self.http.get(f"{base}/.json{q or '?'}&shallow=true"
                              if q else f"{base}/.json?shallow=true")
            exists = r.ok and r.status != 404 and "Not Found" not in r.body[:80]
            self.con.test(cfg.project, f"RTDB {base.split('//')[1][:34]}",
                          r.status if r.ok else "err",
                          "open" if r.status == 200 else
                          ("exists, denied" if exists else "no such db"))
            if not exists:
                continue

            if r.status == 200 and r.body.strip() not in ("null", ""):
                # Severity depends on the FIELD names, but the probe above is
                # shallow=true and returns only top-level keys. Judging severity
                # from that under-rates a database full of PII as Medium, so
                # take one small non-shallow sample purely to classify it.
                sample = self.http.get(f"{base}/.json?limitToFirst=3"
                                       f"&orderBy=%22%24key%22{q}")
                probe = sample.body if (sample.ok and sample.status == 200) else ""
                if not probe:
                    # some rules reject ordered queries; fall back to one node
                    first = next(iter(r.json() or {}), None)
                    if first:
                        s2 = self.http.get(f"{base}/{first}.json{q}")
                        probe = s2.body if s2.ok else ""
                sev = self._sev_for(probe)
                hits = sorted(set(m.group(0).lower() for m in
                                  SENSITIVE_FIELDS.finditer(probe or "")))[:6]
                self.add(Finding(
                    title="Realtime Database readable",
                    target=base, project=cfg.project, service="Realtime Database",
                    permission="READ (.read: true)", sev=sev,
                    identity=self._ident(token),
                    evidence=f"root readable; top-level keys: "
                             f"{', '.join(list((r.json() or {}))[:8]) if isinstance(r.json(), dict) else 'n/a'}"
                             + (f"\nsensitive field names in sampled records: "
                                f"{', '.join(hits)}" if hits else
                                "\nno obviously sensitive field names in the sample"),
                    curl=f"curl -s '{base}/.json?print=pretty{q}'"))
                self.collect_rtdb(base, cfg, token)

            # rules file is normally admin-only; readable means total exposure
            rr = self.http.get(f"{base}/.settings/rules.json{q}")
            if rr.ok and rr.status == 200 and "rules" in rr.body:
                self.add(Finding(
                    title="Database rules readable",
                    target=base, project=cfg.project, service="Realtime Database",
                    permission="READ /.settings/rules.json", sev=HIGH,
                    identity=self._ident(token),
                    evidence=rr.body[:200],
                    curl=f"curl -s '{base}/.settings/rules.json{q}'"))

            if self.args.allow_write:
                self.write_rtdb(base, cfg, token)

    def write_rtdb(self, base: str, cfg: FbConfig, token: str | None):
        """One dated node, verified, then deleted and re-checked."""
        stamp = datetime.now(timezone.utc)
        node = f"{self.POC_PREFIX}{stamp.strftime('%Y%m%d-%H%M%S')}"
        value = stamp.strftime("%Y-%m-%d")      # the current date, nothing else
        q = self._auth_q(token)
        url = f"{base}/{node}.json{q}"

        w = self.http.req("PUT", url, data=json.dumps(value),
                          headers={"Content-Type": "application/json"})
        wrote = w.ok and w.status == 200
        self.con.test(cfg.project, f"RTDB WRITE {node[:26]}",
                      w.status if w.ok else "err", "accepted" if wrote else "denied")
        if not wrote:
            return
        v = self.http.get(url)
        confirmed = v.ok and value in v.body
        self.con.test(cfg.project, "RTDB WRITE verify", v.status,
                      "confirmed" if confirmed else "not present")
        if not confirmed:
            self.con.debug("  PUT returned 200 but the node is not readable back "
                           "— not treating as writable")
            return
        self.add(Finding(
            title="Realtime Database is WRITABLE",
            target=base, project=cfg.project, service="Realtime Database",
            permission="WRITE (.write: true)", sev=CRIT,
            identity=self._ident(token),
            evidence=f"wrote /{node} containing only the date {value}, read it "
                     f"back, now deleting it\nAnyone can create, alter or destroy "
                     f"records in this database.",
            curl=f"curl -s -X PUT '{url}' -d '\"{value}\"'"))
        self._cleanup(base, node, url, cfg)

    def _cleanup(self, base, node, url, cfg):
        self.http.req("DELETE", url)
        v = self.http.get(url)
        gone = (not v.ok) or v.body.strip() in ("null", "")
        self.con.line(paint(
            f"    cleanup /{node} -> re-read {v.status} "
            + ("(removed)" if gone else "(STILL PRESENT — remove manually)"),
            "ok" if gone else "bad"))
        if not gone:
            self.add(Finding(
                title="Cleanup failed — test node left in database",
                target=base, project=cfg.project, service="Realtime Database",
                permission="DELETE denied", sev=HIGH,
                evidence=f"/{node} could not be removed. Delete it manually and "
                         f"disclose it in the report.",
                curl=f"curl -s -X DELETE '{url}'"))

    def collect_rtdb(self, base, cfg, token):
        """Bounded sample — enough to size the exposure, not a copy of the data."""
        q = self._auth_q(token)
        r = self.http.get(f"{base}/.json?shallow=true{q}")
        j = r.json() if r.ok else None
        if not isinstance(j, dict):
            return
        keys = list(j)[: self.args.max_nodes]
        rows = 0
        hits = []
        for k in keys:
            rr = self.http.get(f"{base}/{k}.json?shallow=true{q}")
            jj = rr.json() if rr.ok else None
            n = len(jj) if isinstance(jj, dict) else (1 if jj is not None else 0)
            rows += n
            if SENSITIVE_FIELDS.search(k):
                hits.append(k)
            self.con.test(cfg.project, f"enumerate /{k[:30]}", rr.status, f"{n} child(ren)")
        self.add(Finding(
            title="Exposure sized", target=base, project=cfg.project,
            service="Realtime Database", permission="READ", sev=INFO,
            identity=self._ident(token),
            evidence=f"{len(keys)} top-level node(s), ~{rows} record(s) reachable"
                     + (f"; sensitive-looking nodes: {', '.join(hits[:6])}" if hits else "")))

    # -- firestore

    def test_firestore(self, cfg: FbConfig, token: str | None):
        if not cfg.project:
            return
        hdr = {"Authorization": f"Bearer {token}"} if token else None
        root = f"{FIRESTORE}/projects/{cfg.project}/databases/(default)/documents"
        for coll in COMMON_COLLECTIONS[: self.args.max_collections]:
            r = self.http.get(f"{root}/{coll}?pageSize=5", headers=hdr)
            has = r.ok and r.status == 200 and '"documents"' in r.body
            self.con.test(cfg.project, f"Firestore /{coll}",
                          r.status if r.ok else "err",
                          "readable" if has else ("empty/denied" if r.ok else ""))
            if not has:
                continue
            self.add(Finding(
                title=f"Firestore collection '{coll}' readable",
                target=f"{root}/{coll}", project=cfg.project, service="Firestore",
                permission="READ (allow read)", sev=self._sev_for(r.body),
                identity=self._ident(token),
                evidence=f"{r.body.count('\"name\"')} document(s) in first page; "
                         f"{len(r.body)} bytes",
                curl=f"curl -s '{root}/{coll}?pageSize=5'"
                     + (f" -H 'Authorization: Bearer <token>'" if token else "")))
            if self.args.allow_write:
                self.write_firestore(root, coll, cfg, token, hdr)
                break     # one write PoC per project is enough

    def write_firestore(self, root, coll, cfg, token, hdr):
        stamp = datetime.now(timezone.utc)
        doc = f"{self.POC_PREFIX}{stamp.strftime('%Y%m%d-%H%M%S')}"
        value = stamp.strftime("%Y-%m-%d")
        body = json.dumps({"fields": {"date": {"stringValue": value}}})
        h = dict(hdr or {}); h["Content-Type"] = "application/json"
        url = f"{root}/{coll}?documentId={doc}"
        w = self.http.req("POST", url, data=body, headers=h)
        wrote = w.ok and w.status == 200
        self.con.test(cfg.project, f"Firestore WRITE /{coll}/{doc[:20]}",
                      w.status if w.ok else "err", "accepted" if wrote else "denied")
        if not wrote:
            return
        docurl = f"{root}/{coll}/{doc}"
        v = self.http.get(docurl, headers=hdr)
        if not (v.ok and value in v.body):
            self.con.debug("  POST returned 200 but the document is not readable "
                           "— not treating as writable")
            return
        self.add(Finding(
            title="Firestore is WRITABLE",
            target=docurl, project=cfg.project, service="Firestore",
            permission="WRITE (allow write)", sev=CRIT,
            identity=self._ident(token),
            evidence=f"created {coll}/{doc} containing only the date {value}, "
                     f"read it back, now deleting it",
            curl=f"curl -s -X POST '{url}' -d '{body}'"))
        self.http.req("DELETE", docurl, headers=hdr)
        chk = self.http.get(docurl, headers=hdr)
        gone = chk.status in (403, 404) or not chk.ok
        self.con.line(paint(f"    cleanup {coll}/{doc} -> re-read {chk.status} "
                            + ("(removed)" if gone else "(STILL PRESENT)"),
                            "ok" if gone else "bad"))

    # -- storage

    def test_storage(self, cfg: FbConfig, token: str | None):
        bucket = cfg.storage_bucket or (f"{cfg.project}.appspot.com"
                                        if cfg.project else "")
        if not bucket:
            return
        hdr = {"Authorization": f"Bearer {token}"} if token else None
        url = f"{FBSTORAGE}/b/{bucket}/o?maxResults=20"
        r = self.http.get(url, headers=hdr)
        listable = r.ok and r.status == 200 and '"items"' in r.body
        self.con.test(cfg.project, f"Storage {bucket[:32]}",
                      r.status if r.ok else "err",
                      "listable" if listable else "denied")
        if listable:
            self.add(Finding(
                title="Firebase Storage bucket listable",
                target=url, project=cfg.project, service="Firebase Storage",
                permission="LIST", sev=self._sev_for(r.body),
                identity=self._ident(token),
                evidence=f"{r.body.count('\"name\"')} object(s) listed",
                curl=f"curl -s '{url}'"))

    # -- driver

    def run_target(self, url: str):
        self.con.banner(f"Testing {url}")
        cfg = self.det.find(url)
        if not cfg:
            with self._lk:
                self.skipped.append({"url": url, "reason": "no Firebase config found"})
            self.con.skip(f"{url} — no Firebase config found")
            return

        self.con.info(f"project={cfg.project} apiKey={'yes' if cfg.api_key else 'no'} "
                      f"rtdb={cfg.database_url or 'derived'} "
                      f"bucket={cfg.storage_bucket or 'derived'} (from {cfg.source})")
        # Say where the config actually came from. For a direct *.firebaseio.com
        # or *.firebaseapp.com target nothing is scraped at all -- the project
        # name is simply the hostname -- and claiming otherwise misleads anyone
        # trying to reproduce the step by hand.
        if cfg.source == "URL":
            how = ("Project name taken from the hostname; no client code was "
                   "read and no apiKey is available. Supply the web app URL "
                   "instead if you need the apiKey (it enables the "
                   "self-registration test).")
        else:
            how = (f"Config recovered from client code ({cfg.source}). This is "
                   f"public by design and is NOT itself a finding — the findings "
                   f"are what the rules below permit.")
        self.add(Finding(
            title="Firebase project identified", target=url, project=cfg.project,
            service="config discovery", permission="n/a", sev=INFO,
            evidence=how))

        # anonymous first, then as a self-registered identity
        self.test_rtdb(cfg, None)
        self.test_firestore(cfg, None)
        self.test_storage(cfg, None)

        tok = self.anon_token(cfg)
        if tok:
            self.con.info("re-testing as a self-registered account "
                          "(this is what `request.auth != null` actually allows)")
            self.test_rtdb(cfg, tok)
            self.test_firestore(cfg, tok)
            self.test_storage(cfg, tok)
            # only now is the token no longer needed
            self.delete_account(cfg, tok)


# ----------------------------------------------------------------------------
# cli
# ----------------------------------------------------------------------------

BANNER = r"""
  firehunt — Firebase security-rules tester
  authorized testing only
"""

EPILOG = """
what it tests
  Realtime Database, Cloud Firestore and Firebase Storage, each tested twice:
  once as an anonymous caller, then again as a self-registered identity.

the apiKey is not a secret
  Firebase config ships in client JS by design. This tool reports it as INFO,
  never as a finding. Submitting "leaked Firebase API key" is a classic invalid
  report; the finding is always what the rules permit.

the request.auth != null trap
  `allow read, write: if request.auth != null` reads like "logged-in users only"
  but means any Firebase identity. The tool always mints its own token via
  accounts:signUp and repeats every read/write test with it -- that
  configuration is invisible to an anonymous-only scan, so it is a standard test
  rather than an option. Findings state which identity reached the data.

the write test
  Off unless --allow-write. Writes ONE node/document named firehunt-poc-<ts>
  whose value is the current date, reads it back to confirm (a 200 alone is not
  proof), then deletes it and verifies removal. Name and value are hardcoded --
  there is no option to write anything else. Failed cleanup is reported.

safety
  Every target you supply is requested. There is no allowlist -- feed it a
  pre-filtered, in-scope list.

  The self-registration test calls accounts:signUp, which creates a user record
  in the project's auth backend. That happens on every run and should be
  disclosed in the report.

colour
  On by default. Disable with --no-color or NO_COLOR=1.

status line
  In -l mode a heartbeat prints every 30s (--status-interval) at any verbosity.
  Not shown for -u.

examples
  firehunt.py -u https://app.example.com
  firehunt.py -u https://myproject.firebaseio.com -v 1
  firehunt.py -l hosts-scope.txt
  firehunt.py -u https://app.example.com --allow-write
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="firehunt.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", type=int, default=0, choices=[0, 1, 2], dest="verbosity",
                   help="0 = confirmed findings only (default), 1 = every test, "
                        "2 = debug")
    p.add_argument("-u", "--url", help="single target: an app URL or a Firebase endpoint")
    p.add_argument("-l", "--list", help="file of targets, one per line")
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
                   help="WRITE PoC: one dated node, verified, then deleted")
    p.add_argument("--max-collections", type=int, default=36, metavar="N",
                   help="Firestore collection names to guess (default 36)")
    p.add_argument("--max-nodes", type=int, default=25, metavar="N",
                   help="RTDB top-level nodes to enumerate (default 25)")
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
          f"{paint('ON (one dated node)', 'bad') if args.allow_write else paint('off', 'ok')}"
          f"      self-registration test {paint('always on', 'warn')}"
          + (f"      status every {args.status_interval:.0f}s"
             if status.enabled else ""))
    print()

    http = Http(con, timeout=args.timeout, delay=args.delay, proxy=args.proxy)
    hunter = FireHunter(http, con, args, status)

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
    real = [f for f in hunter.findings if f.sev != INFO]
    print(f"\n  {paint(str(len(real)), 'b')} finding(s) "
          f"({len(hunter.findings)} incl. info) from {http.count} requests "
          f"in {elapsed:.0f}s")
    for sev in (CRIT, HIGH, MED, LOW):
        n = sum(1 for f in hunter.findings if f.sev == sev)
        if n:
            print(f"    {paint(sev, sev):<20} {n}")
    if hunter.skipped:
        print(f"  {paint('skipped', 'warn')}: {len(hunter.skipped)}")
        for s in hunter.skipped[:10]:
            print(f"    - {s['url']}  [{s['reason']}]")

    # Accounting for every account this run created. Printed unconditionally --
    # the operator has to be able to tell the client exactly what was left.
    if hunter.accounts:
        created = len(hunter.accounts)
        left = [a for a in hunter.accounts if not a["deleted"]]
        print(f"\n  {paint('--- accounts created by this run ---', 'b')}")
        print(f"    created: {created}    deleted: {created - len(left)}    "
              f"remaining: {paint(str(len(left)), 'bad' if left else 'ok')}")
        for a in hunter.accounts:
            state = paint("deleted", "ok") if a["deleted"] else paint("REMAINS", "bad")
            print(f"    {state}  project={a['project']}  uid={a['uid'] or 'unknown'}")
        if left:
            print(f"    {paint('Disclose the uid(s) above in the report so the '
                              'client can remove them.', 'bad')}")
    return 1 if real else 0


if __name__ == "__main__":
    sys.exit(main())
