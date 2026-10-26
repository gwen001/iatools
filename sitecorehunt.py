#!/usr/bin/env python3
"""
sitecorehunt — Sitecore XP/XM assessment tool for authorized testing.

Same three-phase shape as aemhunt:
  1. DETECT    is this Sitecore, which version/tier
  2. ASSESS    run checks, confirm each against a control where possible
  3. COLLECT   gather bounded evidence for whatever was confirmed

Default run is read-only. The only state it touches is a login attempt with a
tiny list of vendor defaults (--no-login to skip). No item creation, no upload,
no SPE script execution. Read the safety notes in --help before use.
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
from urllib.parse import quote, urlparse

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
    if not _COLOR:
        return s
    return f"{ANSI.get(key, '')}{s}{ANSI['x']}"


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


# ---------------------------------------------------------------- status

class Status:
    """Periodic heartbeat for list mode (-l), same as aemhunt."""

    def __init__(self, console, total, interval=30.0, enabled=True):
        self.con, self.total, self.interval, self.enabled = console, total, interval, enabled
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
        with self._lk:
            print(msg)
            sys.stdout.flush()

    def finding(self, target, sev, title, detail=""):
        with self._lk:
            print(f"{paint('['+sev+']', sev)} {paint(target, 'b')}  {paint(title, sev)}")
            if detail:
                for ln in detail.splitlines():
                    print(f"        {paint(ln, 'dim')}")
            sys.stdout.flush()

    def probe(self, target, name, result, extra=""):
        if self.level < 1:
            return
        with self._lk:
            print(f"  {paint('·', 'dim')}  {paint(target, 'dim')}  "
                  f"{name:<36} {paint(str(result), status_key(result))} "
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
    def __init__(self, console, timeout=15, rate=8.0, verify=False, proxy=None):
        self.con, self.timeout, self.verify = console, timeout, verify
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

    def req(self, method, url, host=None, **kw):
        headers = dict(kw.pop("headers", {}))
        if host:
            headers["Host"] = host
        self._throttle()
        try:
            return self.s.request(method, url, headers=headers, timeout=self.timeout,
                                  verify=self.verify, allow_redirects=False,
                                  proxies=self.proxies, **kw)
        except requests.RequestException:
            return None

    def get(self, url, **kw):
        return self.req("GET", url, **kw)

    def post(self, url, **kw):
        return self.req("POST", url, **kw)


# ---------------------------------------------------------------- model

class Finding:
    def __init__(self, target, sev, title, detail="", evidence=None):
        self.target, self.sev, self.title = target, sev, title
        self.detail, self.evidence = detail, evidence or {}
        self.when = datetime.now(timezone.utc).isoformat()

    def as_dict(self):
        return {"target": self.target, "severity": self.sev, "title": self.title,
                "detail": self.detail, "evidence": self.evidence, "timestamp": self.when}


# ---------------------------------------------------------------- payloads

# Admin / debug pages: (path, label, severity, signature-word). A locked page
# 302-redirects to login; a 200 that also contains the signature is exposed.
ADMIN_PAGES = [
    ("/sitecore/admin/showconfig.aspx", "showconfig (config dump)", HIGH, "<sitecore"),
    ("/sitecore/admin/dbbrowser.aspx", "Database Browser", HIGH, "Database Browser"),
    ("/sitecore/admin/unlock_admin.aspx", "Unlock Admin", HIGH, "Unlock"),
    ("/sitecore/admin/serialization.aspx", "Serialization", HIGH, "Serialization"),
    ("/sitecore/admin/LinqScratchPad.aspx", "Linq ScratchPad", HIGH, "ScratchPad"),
    ("/sitecore/admin/cache.aspx", "Cache admin", MED, "Cache"),
    ("/sitecore/admin/logs.aspx", "Log viewer", MED, "log"),
    ("/sitecore/admin/jobs.aspx", "Jobs viewer", MED, "Jobs"),
    ("/sitecore/admin/pipelines.aspx", "Pipelines profiler", MED, "Pipeline"),
    ("/sitecore/admin/stats.aspx", "Stats", LOW, "Statistics"),
    ("/sitecore/admin/WhoIsOnline.aspx", "Who Is Online", LOW, "Online"),
]

# SPE (PowerShell Extensions) surfaces - upload/exec stage of the 2025 chain.
SPE_PATHS = [
    ("/sitecore/shell/client/Applications/PowerShell/PowerShellConsole", "SPE console", HIGH, "PowerShell"),
    ("/sitecore%20modules/Shell/PowerShell/PowerShellConsole.aspx", "SPE console (aspx)", HIGH, "PowerShell"),
    ("/-/script/v2/master/-", "SPE web API", HIGH, "PowerShell"),
    ("/sitecore%20modules/PowerShell/Services/RemoteAutomation.asmx", "SPE remoting asmx", HIGH, "RemoteAutomation"),
]

# Read APIs that are often reachable without a valid key by misconfiguration.
READ_APIS = [
    ("/sitecore/api/ssc/item/%7B11111111-1111-1111-1111-111111111111%7D",
     "ItemService (root item)", MED),
    ("/sitecore/api/graph/items/master", "GraphQL items endpoint", MED),
    ("/sitecore/api/layout/render/jss?item=/&sc_lang=en", "Layout Service (JSS)", MED),
    ("/-/item/v1/?sc_itemid=%7B11111111-1111-1111-1111-111111111111%7D",
     "Item Web API", MED),
]

# Small fixed list of vendor defaults. admin/b is the classic Sitecore default;
# the bare "b" account is the hardcoded internal user from the 2025 chain.
DEFAULT_CREDS = [
    ("admin", "b"),
    ("admin", "password"),
    ("admin", "admin"),
    ("sitecore\\admin", "b"),
    ("b", "b"),
]

_SECRET_PATTERNS = [
    (r'validationKey="([0-9A-Fa-f]{8,})"', "machineKey validationKey"),
    (r'decryptionKey="([0-9A-Fa-f]{8,})"', "machineKey decryptionKey"),
    (r'(Data Source=[^"<;]+)', "SQL connection string"),
    (r'(User ID=[^"<;]+)', "SQL user"),
    (r'[Pp]assword=([^"<;&]+)', "embedded password"),
]


# ---------------------------------------------------------------- version / CVE

def parse_version(text):
    """Pull a version like '10.3' (and build/rev if present) from version.xml."""
    major = re.search(r"<major>(\d+)</major>", text)
    minor = re.search(r"<minor>(\d+)</minor>", text)
    build = re.search(r"<build>([^<]+)</build>", text)
    rev = re.search(r"<revision>([^<]+)</revision>", text)
    if not major:
        return None
    v = major.group(1) + (f".{minor.group(1)}" if minor else "")
    if build:
        v += f" (build {build.group(1)}"
        v += f", rev {rev.group(1)})" if rev else ")"
    return v


def cve_notes(version):
    """Version-based advisory context - NOT a confirmed vuln. Conservative INFO."""
    notes = []
    notes.append("Recent Sitecore XP CVEs to verify against patch level: "
                 "CVE-2025-53690 (ViewState deserialization via sample machine "
                 "keys, pre-auth RCE), CVE-2025-34509 (hardcoded 'b' user), "
                 "CVE-2025-34510/34511 (SPE upload -> RCE chain).")
    return notes


# ---------------------------------------------------------------- scanner

class SitecoreHunter:
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

    def detect(self, base):
        markers = 0
        sig = {"version": None, "tier": "unknown"}

        root = self.h.get(base + "/")
        if root is not None:
            sc = root.headers.get("Set-Cookie", "")
            sig["server"] = root.headers.get("Server", "")
            if "SC_ANALYTICS_GLOBAL_COOKIE" in sc:
                markers += 2
                sig["analytics_cookie"] = True
            self.con.probe(base, "root", root.status_code)

        login = self.h.get(base + "/sitecore/login/default.aspx")
        if login is None:
            login = self.h.get(base + "/sitecore/login")
        if login is not None and login.status_code == 200 and "Sitecore" in login.text \
                and re.search(r"(UserName|Password|sc_lang)", login.text):
            markers += 3
            sig["login"] = "/sitecore/login/default.aspx"
            sig["tier"] = "author/CM"
        self.con.probe(base, "login page",
                       login.status_code if login is not None else "err")

        ka = self.h.get(base + "/sitecore/service/keepalive.aspx")
        if ka is not None and ka.status_code == 200 and ka.text.strip().upper().startswith("OK"):
            markers += 2
            sig["keepalive"] = True

        ver = self.h.get(base + "/sitecore/shell/sitecore.version.xml")
        if ver is not None and ver.status_code == 200 and "<major>" in ver.text:
            markers += 2
            sig["version"] = parse_version(ver.text)
        self.con.probe(base, "version.xml",
                       ver.status_code if ver is not None else "err",
                       f"({sig['version']})" if sig.get("version") else "")

        sig["is_sitecore"] = markers >= 3
        self.con.probe(base, "detect Sitecore",
                       "YES" if sig["is_sitecore"] else "no", f"(score {markers})")
        if sig["is_sitecore"]:
            bits = [f"tier={sig['tier']}"]
            if sig.get("version"):
                bits.append(f"version={sig['version']}")
            if sig.get("server"):
                bits.append(f"server={sig['server']}")
            self.add(Finding(base, INFO, "Sitecore detected", " ".join(bits), sig))
            self.add(Finding(base, INFO, "Version / CVE context",
                             "\n".join(cve_notes(sig.get("version"))),
                             {"version": sig.get("version")}))
        return sig if sig["is_sitecore"] else None

    # ---------- phase 2: checks

    def check_admin_pages(self, base):
        opened = []
        for path, label, sev, sigword in ADMIN_PAGES:
            r = self.h.get(base + path)
            if r is None:
                continue
            hit = (r.status_code == 200 and sigword.lower() in r.text.lower()
                   and len(r.content) > 200)
            self.con.probe(base, f"admin {label}", r.status_code, f"({len(r.content)}b)")
            if not hit:
                continue
            opened.append(path)
            if "showconfig" in path:
                self._report_showconfig(base, path, r)
            else:
                self.add(Finding(base, sev, f"Admin page exposed: {label}",
                                 f"{path} -> 200 ({len(r.content)} bytes), unauthenticated.",
                                 {"path": path, "len": len(r.content)}))
        return opened

    def _report_showconfig(self, base, path, r):
        """showconfig.aspx dumps merged config; escalate if it leaks secrets."""
        leaks = []
        for rx, label in _SECRET_PATTERNS:
            if re.search(rx, r.text):
                leaks.append(label)
        if leaks:
            self.add(Finding(
                base, CRIT, "Config disclosure with secrets: showconfig.aspx",
                f"{path} -> 200 ({len(r.content)} bytes). Leaks: "
                + ", ".join(sorted(set(leaks)))
                + "\nSecret values withheld from console; saved to evidence only "
                  "with --collect. Confirm and rotate.",
                {"path": path, "leaks": sorted(set(leaks)), "len": len(r.content)}))
        else:
            self.add(Finding(
                base, HIGH, "Config dump exposed: showconfig.aspx",
                f"{path} -> 200 ({len(r.content)} bytes), unauthenticated merged "
                f"config. No obvious secrets matched, but review manually.",
                {"path": path, "len": len(r.content)}))

    def check_spe(self, base):
        for path, label, sev, sigword in SPE_PATHS:
            r = self.h.get(base + path)
            if r is None:
                continue
            hit = r.status_code == 200 and sigword.lower() in r.text.lower()
            self.con.probe(base, f"spe {label}", r.status_code, f"({len(r.content)}b)")
            if hit:
                self.add(Finding(
                    base, sev, f"Sitecore PowerShell Extensions exposed: {label}",
                    f"{path} -> 200. SPE reachable unauthenticated is a strong RCE "
                    f"vector (2025 chain). Confirm execution manually within scope.",
                    {"path": path}))

    def check_read_apis(self, base):
        for path, label, sev in READ_APIS:
            r = self.h.get(base + path)
            if r is None:
                continue
            ct = r.headers.get("Content-Type", "")
            hit = (r.status_code == 200 and "json" in ct
                   and r.text.strip()[:1] in "{[" and len(r.content) > 20)
            self.con.probe(base, f"api {label}", r.status_code, f"({len(r.content)}b)")
            if hit:
                self.add(Finding(
                    base, sev, f"Unauthenticated read API: {label}",
                    f"{path} -> 200 JSON ({len(r.content)} bytes). Repository data "
                    f"readable without a valid API key.",
                    {"path": path, "len": len(r.content)}))

    def check_default_login(self, base, login_path):
        """
        Default creds via the WebForms login. Fetch the page for the ASP.NET
        tokens, then POST them with each default pair. VERSION-DEPENDENT: the
        username/password field names vary; a null result on a confirmed
        Sitecore host may just mean the field names differ.
        """
        page = self.h.get(base + login_path)
        if page is None or page.status_code != 200:
            self.con.probe(base, "login tokens", "unavailable")
            return
        def hidden(name):
            m = re.search(name + r'"[^>]*value="([^"]*)"', page.text)
            return m.group(1) if m else ""
        vs, vg, ev = hidden("__VIEWSTATE"), hidden("__VIEWSTATEGENERATOR"), hidden("__EVENTVALIDATION")

        for user, pw in DEFAULT_CREDS:
            data = {"__VIEWSTATE": vs, "__VIEWSTATEGENERATOR": vg,
                    "__EVENTVALIDATION": ev, "__EVENTTARGET": "", "__EVENTARGUMENT": "",
                    "UserName": user, "Password": pw, "Login": "Login"}
            r = self.h.post(base + login_path, data=data,
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
            if r is None:
                continue
            loc = r.headers.get("Location", "")
            setc = r.headers.get("Set-Cookie", "")
            body = r.text or ""
            success = (("sitecore/shell" in loc.lower()) or (".ASPXAUTH" in setc)
                       or ("sitecore_userticket" in setc.lower()))
            rejected = re.search(r"incorrect|invalid|not been able to log", body, re.I)
            self.con.probe(base, f"login {user}:{pw}", r.status_code,
                           "(accepted)" if success and not rejected else "(rejected)")
            if success and not rejected:
                self.add(Finding(
                    base, CRIT, f"Default credentials accepted: {user}:{pw}",
                    "Authenticated session established with a vendor default.",
                    {"user": user}))
                return

    # ---------- phase 3: bounded evidence

    def collect(self, base, sig, opened, outdir):
        if not outdir:
            return
        os.makedirs(outdir, exist_ok=True)
        tag = re.sub(r"\W+", "_", urlparse(base).hostname or "target")
        saved = []
        if "/sitecore/admin/showconfig.aspx" in opened:
            r = self.h.get(base + "/sitecore/admin/showconfig.aspx")
            if r is not None and r.status_code == 200:
                fn = os.path.join(outdir, f"{tag}_showconfig.xml")
                with open(fn, "w", encoding="utf-8") as fh:
                    fh.write(r.text)
                saved.append(fn)
        summary = {"target": base, "version": sig.get("version"),
                   "tier": sig.get("tier"), "opened_admin_pages": opened}
        fn = os.path.join(outdir, f"{tag}_summary.json")
        with open(fn, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        saved.append(fn)
        if saved:
            self.add(Finding(base, INFO, "Evidence collected",
                             "\n".join(saved), {"files": saved}))

    # ---------- driver

    def run(self, base):
        base = base.rstrip("/")
        if not urlparse(base).scheme:
            base = "https://" + base

        sig = self.detect(base)
        if not sig:
            self.con.probe(base, "summary", "not Sitecore — skipping")
            return

        opened = self.check_admin_pages(base)
        self.check_spe(base)
        self.check_read_apis(base)
        if sig.get("login") and not self.args.no_login:
            self.check_default_login(base, sig["login"])
        if self.args.collect:
            self.collect(base, sig, opened, self.args.outdir)


# ---------------------------------------------------------------- cli

BANNER = r"""
  sitecorehunt — Sitecore XP/XM assessment
  authorized testing only
"""

EPILOG = """
safety
  Every target you supply is requested. There is no allowlist, so the target
  list is the only thing keeping this in scope -- feed it a pre-filtered file.

  The default run is read-only apart from a login attempt with a tiny list of
  vendor defaults (admin/b, etc.). Disable that with --no-login. No item is
  created, nothing is uploaded, and no SPE script is executed.

  A confirmed default-credentials or exposed-SPE finding is high-impact; verify
  the follow-on impact manually and within scope before reporting it.

notes
  The default-login check depends on the login form field names, which vary by
  Sitecore version. A null result on a confirmed host may just mean the field
  names differ -- adjust DEFAULT_CREDS / field names for the target.

examples
  sitecorehunt.py -u https://target.example.com -v 1
  sitecorehunt.py -l hosts-scope.txt --collect --outdir evidence/
  sitecorehunt.py -u https://target.example.com --no-login -o findings.json
"""


def main():
    ap = argparse.ArgumentParser(prog="sitecorehunt.py", description=BANNER, epilog=EPILOG,
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
    ap.add_argument("--timeout", type=int, default=15, help="per-request timeout (default 15)")
    ap.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080 for Burp/Caido")
    ap.add_argument("--verify-tls", action="store_true", help="verify certificates (default off)")
    ap.add_argument("--no-login", action="store_true",
                    help="skip the default-credentials login attempt (fully read-only)")
    ap.add_argument("--collect", action="store_true", help="phase 3: save bounded evidence")
    ap.add_argument("--outdir", default="sitecorehunt-evidence", help="evidence directory")
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
    status = Status(con, len(targets), interval=args.status_interval, enabled=bool(args.list))

    print(paint(BANNER, "head"))
    print(f"  targets {paint(str(len(targets)), 'b')}   threads {args.threads}   rate {args.rate}/s")
    print(f"  login   {paint('off', 'ok') if args.no_login else paint('ON (vendor defaults)', 'warn')}"
          + (f"        status every {args.status_interval:.0f}s" if status.enabled else ""))
    print()

    http = Http(con, timeout=args.timeout, rate=args.rate, verify=args.verify_tls, proxy=args.proxy)
    hunter = SitecoreHunter(http, con, args, status)
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
                       sorted(hunter.findings, key=lambda x: _SEV_ORDER[x.sev])], fh, indent=2)
        print(f"\n  findings -> {args.json}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\ninterrupted")
