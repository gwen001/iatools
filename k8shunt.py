#!/usr/bin/env python3
"""
k8shunt.py - Detect exposed / unauthenticated Kubernetes surfaces (read-only):
kube-apiserver, kubelet, and etcd.

Part of the *hunt bug-bounty tooling suite.

AUTHORIZED USE ONLY. Run this only against hosts that are in scope for a bug
bounty program or covered by a signed engagement / rules of engagement.

The tool is strictly READ-ONLY (GET only). It never creates, patches, deletes,
or execs. Per host it probes the k8s ports and, per component, gathers minimum
proof of exposure:
  - apiserver : GET /version, then GET /api/v1/namespaces (anonymous cluster
                read?) and whether /api/v1/secrets is listable. Secret NAMES /
                types only with --poc-value; secret DATA is never read.
  - kubelet   : GET /pods (anonymous node access?), pod/namespace inventory.
  - etcd      : GET /version + /health, v2 key listing (GET /v2/keys), and v3
                detection (the v3 gRPC-gateway range read is not issued here).

Unlike the single-service *hunt tools there is NO stop-at-first-port: every k8s
port is probed so all exposed components on a host are reported.

Pass --poc-value to list up to --poc-keys resource identifiers (pod, namespace,
secret name+type, etcd key), each truncated to --poc-bytes. Off by default.

Targets:
  host                     -> the common k8s ports (per-port http/https)
  host:port                -> that port (TLS auto by port unless scheme/--force-tls)
  http://host:port / https://host:port  -> forces that scheme
  (any user:pass@ prefix is stripped and ignored - this tool does not auth)
"""

import argparse
import http.client
import json
import re
import socket
import ssl
import sys
import threading
import time
from queue import Queue, Empty
from urllib.parse import quote

# --------------------------------------------------------------------------- #
# Colours
# --------------------------------------------------------------------------- #

class C:
    reset = "\033[0m"
    bold = "\033[1m"
    dim = "\033[2m"
    red = "\033[31m"
    green = "\033[32m"
    yellow = "\033[33m"
    blue = "\033[34m"
    magenta = "\033[35m"
    cyan = "\033[36m"
    turquoise = "\033[38;5;44m"
    white = "\033[97m"
    grey = "\033[90m"

    enabled = True

    @classmethod
    def disable(cls):
        cls.enabled = False
        for name in ("reset", "bold", "dim", "red", "green", "yellow",
                     "blue", "magenta", "cyan", "turquoise", "white", "grey"):
            setattr(cls, name, "")


def c(text, colour):
    if not C.enabled:
        return text
    return f"{colour}{text}{C.reset}"


# --------------------------------------------------------------------------- #
# Global rate limiter
# --------------------------------------------------------------------------- #

class Limiter:
    def __init__(self, min_interval):
        self.min_interval = max(0.0, min_interval)
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            sleep = self._next - now if now < self._next else 0.0
            self._next = max(now, self._next) + self.min_interval
        if sleep > 0:
            time.sleep(sleep)


# --------------------------------------------------------------------------- #
# HTTP (read-only GET, optional proxy)
# --------------------------------------------------------------------------- #

MAX_BODY = 5_000_000


def _ssl_ctx(verify, cert=None, key=None):
    cx = ssl.create_default_context()
    if not verify:
        cx.check_hostname = False
        cx.verify_mode = ssl.CERT_NONE
    if cert:                                          # client cert for mTLS targets
        cx.load_cert_chain(cert, key or None)
    return cx


def _is_mtls(exc):
    """True when the server rejected the handshake for lack of a client cert."""
    s = str(exc).lower()
    return "certificate required" in s or "certificate_required" in s


def _tls_reason(exc):
    """Readable reason for a TLS transport failure, or None if not TLS-specific."""
    s = str(exc)
    if "UNEXPECTED_EOF" in s or "EOF occurred" in s:
        return "handshake dropped (likely a plaintext service on a TLS port)"
    if "WRONG_VERSION_NUMBER" in s:
        return "not TLS (wrong version number) - plaintext service?"
    if "INTERNAL_ERROR" in s:
        return "TLS internal error (mTLS / SNI mismatch?)"
    if "certificate required" in s.lower():
        return "client certificate required (mTLS enforced)"
    return None


def _split_proxy(proxy):
    p = proxy
    for pre in ("http://", "https://"):
        if p.startswith(pre):
            p = p[len(pre):]
            break
    if "@" in p:
        p = p.split("@", 1)[1]
    p = p.rstrip("/")
    ph, _, pp = p.partition(":")
    return ph, int(pp or "8080")


def http_get(host, port, tls, path, timeout, verify, proxy=None, cert=None, key=None):
    if proxy:
        ph, pp = _split_proxy(proxy)
        if tls:
            conn = http.client.HTTPSConnection(ph, pp, timeout=timeout,
                                               context=_ssl_ctx(verify, cert, key))
            conn.set_tunnel(host, port)
            req_path = path
        else:
            conn = http.client.HTTPConnection(ph, pp, timeout=timeout)
            req_path = f"http://{host}:{port}{path}"
    else:
        if tls:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=_ssl_ctx(verify, cert, key))
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        req_path = path
    try:
        conn.request("GET", req_path, headers={
            "User-Agent": "k8shunt", "Accept": "application/json", "Connection": "close"})
        resp = conn.getresponse()
        body = resp.read(MAX_BODY)
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, hdrs, body
    finally:
        try:
            conn.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Target parsing
# --------------------------------------------------------------------------- #

_SCHEME_RE = re.compile(r'^([a-zA-Z][a-zA-Z0-9+.\-]*)://')


def parse_target(raw):
    """Return (host, port_or_None, scheme) where scheme is True (https),
    False (http), or None (no scheme -> decide TLS per port)."""
    raw = raw.strip()
    scheme = None
    m = _SCHEME_RE.match(raw)
    if m:
        s = m.group(1).lower()
        if s == "https":
            scheme = True
        elif s == "http":
            scheme = False
        raw = raw[m.end():]
    if "@" in raw:
        raw = raw.split("@", 1)[1]
    for sep in ("/", "?", "#"):
        if sep in raw:
            raw = raw.split(sep, 1)[0]
    raw = raw.strip().rstrip("/")
    if raw.startswith("["):
        host, _, tail = raw[1:].partition("]")
        tail = tail.lstrip(":")
        port = int(tail) if tail.isdigit() else None
    elif raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        host, p = raw.rsplit(":", 1)
        port = int(p)
    else:
        host, port = raw, None
    return host, port, scheme


# --------------------------------------------------------------------------- #
# Scan context
# --------------------------------------------------------------------------- #

class Ctx:
    def __init__(self, args, limiter):
        self.args = args
        self.limiter = limiter
        self.v = args.v
        self.print_lock = threading.Lock()
        self.out_fh = open(args.output, "a", encoding="utf-8") if args.output else None
        self.found = 0
        self.done = 0
        self.total = 0
        self.show_status = False

    def emit(self, line=""):
        with self.print_lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def status(self):
        if not self.show_status:
            return
        with self.print_lock:
            pct = int(self.done * 100 / self.total) if self.total else 100
            sys.stderr.write(c("scanned: %d/%d  (%d%%)\r"
                               % (self.done, self.total, pct), C.white))
            sys.stderr.flush()

    def debug(self, host, port, msg):
        if self.v >= 2:
            self.emit(c(f"      [debug {host}:{port}] {msg}", C.grey))

    def write_finding(self, text):
        if self.out_fh:
            with self.print_lock:
                self.out_fh.write(text + "\n")
                self.out_fh.flush()

    def close(self):
        if self.out_fh:
            self.out_fh.close()


# --------------------------------------------------------------------------- #
# Probing (read-only) - one component per port
# --------------------------------------------------------------------------- #

def _trunc(s, nbytes):
    s = str(s)
    return s if len(s) <= nbytes else s[:nbytes] + "...[truncated]"


def _make_get(host, port, tls, ctx, r):
    a = ctx.args
    st = {"tls": tls, "fb": False}

    def get(path):
        ctx.limiter.wait()
        try:
            status, hdrs, body = http_get(host, port, st["tls"], path, a.timeout,
                                          a.verify_tls, a.proxy,
                                          a.client_cert, a.client_key)
        except Exception as e:
            if st["tls"] and not st["fb"] and isinstance(e, ssl.SSLError) and not _is_mtls(e):
                ctx.debug(host, port, f"TLS failed ({e}); retrying plaintext")
                st["tls"] = False
                st["fb"] = True
                r["tls"] = False
                status, hdrs, body = http_get(host, port, False, path, a.timeout,
                                              a.verify_tls, a.proxy)
            else:
                raise
        if ctx.v >= 2:
            ctx.debug(host, port, f"GET {path} -> {status} ({len(body)}b)")
        try:
            data = json.loads(body) if body else None
        except Exception:
            data = None
        return status, hdrs, body, data
    return get


def _p_apiserver(get, r, ctx):
    a = ctx.args
    r["data"]["component"] = "apiserver"
    status, _, body, data = get("/version")
    if status in (401, 403):
        r["status"] = "AUTH"
        r["detail"] = f"apiserver: HTTP {status} on /version"
        return r
    gv = data.get("gitVersion") if isinstance(data, dict) else None
    if not (isinstance(data, dict) and (gv or ("major" in data and "minor" in data))):
        r["status"] = "NOT-K8S"
        r["detail"] = f"apiserver: HTTP {status}, no /version banner"
        return r
    r["data"]["version"] = gv or f"{data.get('major')}.{data.get('minor')}"

    st, _, _, ns = get("/api/v1/namespaces?limit=200")
    if st == 200 and isinstance(ns, dict) and "items" in ns:
        names = [i.get("metadata", {}).get("name") for i in ns.get("items", [])]
        r["data"]["namespaces"] = [n for n in names if n]
        r["data"]["anon_read"] = True
        ss, _, _, sec = get("/api/v1/secrets?limit=1")
        if ss == 200 and isinstance(sec, dict) and "items" in sec:
            r["data"]["secrets_readable"] = True
        r["status"] = "OPEN"
    elif st in (401, 403):
        r["status"] = "AUTH"
        r["detail"] = f"apiserver v{r['data']['version']}: RBAC enforced (namespaces {st})"
    else:
        r["status"] = "OPEN-EMPTY"
        r["detail"] = f"apiserver v{r['data']['version']} reachable (no anon list)"

    if a.poc_value and r["data"].get("anon_read"):
        poc = []
        _, _, _, pods = get(f"/api/v1/pods?limit={a.poc_keys}")
        if isinstance(pods, dict):
            for it in pods.get("items", [])[:a.poc_keys]:
                m = it.get("metadata", {})
                poc.append(("pod", f"{m.get('namespace')}/{m.get('name')}"))
        _, _, _, secd = get(f"/api/v1/secrets?limit={a.poc_keys}")
        if isinstance(secd, dict):
            for it in secd.get("items", [])[:a.poc_keys]:
                m = it.get("metadata", {})
                poc.append(("secret",
                            f"{m.get('namespace')}/{m.get('name')} (type {it.get('type')})"))
        if poc:
            r["data"]["poc"] = [(t, _trunc(v, a.poc_bytes)) for t, v in poc]
    return r


def _p_kubelet(get, r, ctx):
    a = ctx.args
    r["data"]["component"] = "kubelet"
    status, _, body, data = get("/pods")
    if status in (401, 403):
        r["status"] = "AUTH"
        r["detail"] = f"kubelet: /pods {status} (auth required)"
        return r
    if not (isinstance(data, dict) and "items" in data):
        s2, _, b2, _ = get("/healthz")
        if s2 == 200 and b2.strip() == b"ok":
            r["status"] = "OPEN-EMPTY"
            r["detail"] = "kubelet healthz ok, /pods not readable"
            return r
        r["status"] = "NOT-K8S"
        r["detail"] = f"kubelet: /pods {status}, no pod list"
        return r
    pods = data.get("items", [])
    ns = set()
    for it in pods:
        ns.add((it.get("metadata", {}) or {}).get("namespace"))
    r["data"]["pods"] = len(pods)
    r["data"]["namespaces_n"] = len([x for x in ns if x])
    r["status"] = "OPEN" if pods else "OPEN-EMPTY"
    if a.poc_value and pods:
        poc = []
        for it in pods[:a.poc_keys]:
            m = it.get("metadata", {}) or {}
            poc.append(("pod", f"{m.get('namespace')}/{m.get('name')}"))
        r["data"]["poc"] = [(t, _trunc(v, a.poc_bytes)) for t, v in poc]
    return r


def _p_etcd(get, r, ctx):
    a = ctx.args
    r["data"]["component"] = "etcd"
    status, _, body, data = get("/version")
    if status in (401, 403):
        r["status"] = "AUTH"
        r["detail"] = f"etcd: /version {status}"
        return r
    es = data.get("etcdserver") if isinstance(data, dict) else None
    if es is None and b"etcdserver" not in body and b"etcdcluster" not in body:
        r["status"] = "NOT-K8S"
        r["detail"] = f"etcd: no version banner (HTTP {status})"
        return r
    r["data"]["version"] = es or "?"
    api = "v3" if str(es or "").startswith("3") else ("v2" if str(es or "").startswith("2") else "?")
    r["data"]["api"] = api

    _, _, _, hd = get("/health")
    if isinstance(hd, dict):
        r["data"]["health"] = hd.get("health")

    sk, _, _, kd = get("/v2/keys/?recursive=false")
    if sk == 200 and isinstance(kd, dict) and "node" in kd:
        nodes = (kd.get("node", {}) or {}).get("nodes", []) or []
        keys = [n.get("key") for n in nodes if n.get("key")]
        r["data"]["v2_keys"] = len(keys)
        r["data"]["anon_read"] = True
        r["status"] = "OPEN"
        if a.poc_value and keys:
            r["data"]["poc"] = [("key", _trunc(k, a.poc_bytes)) for k in keys[:a.poc_keys]]
    elif sk in (401, 403):
        r["status"] = "AUTH"
        r["detail"] = f"etcd {api}: v2 keys {sk}"
    elif api == "v3":
        r["status"] = "OPEN-EMPTY"
        r["detail"] = ("etcd v3 detected - v2 API disabled; gRPC-gateway range "
                       "read not issued (detection only)")
    else:
        r["status"] = "OPEN-EMPTY"
        r["detail"] = "etcd reachable, v2 keys not listable"
    return r


def _p_component(get, r, ctx, label):
    r["data"]["component"] = label
    status, _, body, _ = get("/healthz")
    if status in (401, 403):
        r["status"] = "AUTH"
        r["detail"] = f"{label}: /healthz {status}"
        return r
    if status == 200:
        r["status"] = "OPEN"
        r["detail"] = f"{label}: /healthz ok"
        sm, _, mb, _ = get("/metrics")
        if sm == 200 and mb[:1] in (b"#", b"k"):
            r["data"]["metrics"] = True
        return r
    s2, _, b2, _ = get("/")
    if b"cadvisor" in b2.lower():
        r["data"]["component"] = "cadvisor"
        r["status"] = "OPEN"
        r["detail"] = "cadvisor UI exposed"
        return r
    r["status"] = "NOT-K8S"
    r["detail"] = f"{label}: HTTP {status}"
    return r


_DISPATCH = {
    "apiserver": lambda g, r, ctx: _p_apiserver(g, r, ctx),
    "kubelet": lambda g, r, ctx: _p_kubelet(g, r, ctx),
    "etcd": lambda g, r, ctx: _p_etcd(g, r, ctx),
    "cadvisor": lambda g, r, ctx: _p_component(g, r, ctx, "cadvisor"),
    "component": lambda g, r, ctx: _p_component(g, r, ctx, "k8s-component"),
}
_AUTO_ORDER = ("apiserver", "etcd", "kubelet", "component")


def probe(host, port, tls, kind, ctx):
    order = [kind] if kind in _DISPATCH else list(_AUTO_ORDER)
    last = None
    for k in order:
        r = {"host": host, "port": port, "tls": tls, "status": "ERROR",
             "detail": "", "data": {}, "suspect": []}
        r["data"]["component"] = k if k != "component" else "k8s-component"
        get = _make_get(host, port, tls, ctx, r)
        try:
            rr = _DISPATCH[k](get, r, ctx)
        except Exception as e:
            rr = r
            if _is_mtls(e):
                rr["status"] = "MTLS"
                rr["detail"] = "client certificate required (mTLS enforced)"
            else:
                rr["status"] = "ERROR"
                rr["detail"] = _tls_reason(e) or f"{type(e).__name__}: {e}"
        if rr["status"] != "NOT-K8S":
            return rr
        last = rr
    return last


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _ver(v):
    v = str(v)
    return v if v.startswith("v") or v == "?" else "v" + v


def _summary(comp, d):
    if comp == "apiserver":
        s = _ver(d.get("version", "?"))
        if "namespaces" in d:
            s += f"  namespaces={len(d['namespaces'])}"
        if d.get("secrets_readable"):
            s += "  secrets=READABLE"
        return s
    if comp == "kubelet":
        return f"pods={d.get('pods','?')}  namespaces={d.get('namespaces_n','?')}"
    if comp == "etcd":
        s = f"{d.get('api','?')} {_ver(d.get('version','?'))}  health={d.get('health','?')}"
        if "v2_keys" in d:
            s += f"  v2keys={d['v2_keys']}"
        return s
    extra = "  metrics=exposed" if d.get("metrics") else ""
    return (d.get("version", "") or "") + extra


_CRIT = {
    "apiserver": lambda d: ("anonymous secrets readable"
                            if d.get("secrets_readable") else
                            ("anonymous cluster read" if d.get("anon_read") else None)),
    "kubelet": lambda d: ("anonymous kubelet: pod inventory readable"
                          if d.get("pods") else None),
    "etcd": lambda d: ("anonymous etcd: keyspace readable" if d.get("anon_read") else None),
}


def render(r, ctx):
    tls = " TLS" if r["tls"] else ""
    tgt = f"{r['host']}:{r['port']}{tls}"
    st = r["status"]
    d = r["data"]
    comp = d.get("component", "?")

    if st in ("OPEN", "OPEN-EMPTY"):
        tag = c("[OPEN]", C.bold + C.green)
        ctx.emit(f"{tag} {c(tgt, C.green)}  {c(comp, C.bold+C.cyan)}  {_summary(comp, d)}")
        crit = _CRIT.get(comp, lambda _d: None)(d)
        if crit:
            ctx.emit(c(f"      !! {crit}", C.bold + C.red))
        elif r.get("detail"):
            ctx.emit(c(f"      {r['detail']}", C.dim))
        for i, (t, val) in enumerate(d.get("poc", []), 1):
            ctx.emit(c(f"      PoC {t}[{i}]: {val}", C.yellow))
        if r["suspect"]:
            ctx.emit(c("      ! possible honeypot: " + "; ".join(r["suspect"]), C.yellow))

        rec = f"{tgt} component={comp} status={st} {_summary(comp, d).strip()}"
        if crit:
            rec += f" critical={crit!r}"
        for i, (t, val) in enumerate(d.get("poc", []), 1):
            rec += f" poc_{t}[{i}]={val!r}"
        ctx.write_finding(rec)
        return

    if st == "MTLS":                                   # informative: locked with mTLS
        if ctx.v >= 1:
            ctx.emit(f"{c('[MTLS]', C.magenta)} {c(tgt, C.magenta)}  {comp}: {r['detail']}")
        return

    if ctx.v < 1:
        return
    if st == "AUTH":
        ctx.emit(f"{c('[AUTH]', C.yellow)} {c(tgt, C.yellow)}  {comp}: {r['detail']}")
    elif st == "NOT-K8S":
        ctx.emit(f"{c('[----]', C.grey)} {c(tgt, C.grey)}  {r['detail']}")
    else:
        ctx.emit(f"{c('[ERR ]', C.red)} {c(tgt, C.dim)}  {r['detail']}")


# --------------------------------------------------------------------------- #
# Status / worker pool  (NO stop-at-first-port: every k8s port is reported)
# --------------------------------------------------------------------------- #

def fmt_elapsed(sec):
    sec = int(sec)
    h, m, s = sec // 3600, (sec % 3600) // 60, sec % 60
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


# port -> (component kind, default TLS when no scheme/--force-tls)
PORT_TABLE = {
    6443: ("apiserver", True), 8080: ("apiserver", False),
    10250: ("kubelet", True), 10255: ("kubelet", False),
    2379: ("etcd", True),
    6444: ("apiserver", True), 8443: ("apiserver", True), 2380: ("etcd", True),
    4194: ("cadvisor", False), 10256: ("component", False),
    10257: ("component", True), 10259: ("component", True), 9099: ("component", False),
}


def worker(q, ctx):
    while True:
        try:
            job = q.get_nowait()
        except Empty:
            return
        host, forced_tls, ports = job
        try:
            for port in ports:
                kind, dtls = PORT_TABLE.get(port, ("auto", False))
                tls = forced_tls if forced_tls is not None else dtls
                try:
                    r = probe(host, port, tls, kind, ctx)
                except Exception as e:
                    r = {"host": host, "port": port, "tls": tls, "status": "ERROR",
                         "detail": f"internal: {e}", "data": {}, "suspect": []}
                render(r, ctx)
                if r["status"] in ("OPEN", "OPEN-EMPTY"):
                    with ctx.print_lock:
                        ctx.found += 1
        finally:
            with ctx.print_lock:
                ctx.done += 1
            ctx.status()
            q.task_done()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

# Common k8s ports, always tested.
COMMON_PORTS = [6443, 8080, 10250, 10255, 2379]
# Uncommon extra ports (control-plane components, peer, cAdvisor, calico),
# only added with --extra-ports.
EXTRA_PORTS = [6444, 8443, 2380, 4194, 10256, 10257, 10259, 9099]


def parse_ports(spec):
    out = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part.lstrip("-"):
            a, _, b = part.partition("-")
            a, b = int(a), int(b)
            step = 1 if b >= a else -1
            out.extend(range(a, b + step, step))
        else:
            out.append(int(part))
    return out


def build_parser():
    epilog = (
        "components: apiserver (6443/8080), kubelet (10250/10255), etcd (2379).\n"
        "ports:   an explicit port in the target is tried alone; -p PORTS is an\n"
        "         exclusive list; otherwise the common ports (6443,8080,10250,10255,\n"
        "         2379) are always tried and --extra-ports adds control-plane /\n"
        "         cAdvisor ports. Every port is probed - components are NOT skipped.\n"
        "         TLS is chosen per port (https for 6443/2379/10250/... , http for\n"
        "         8080/10255/...), overridden by a target scheme or --force-tls.\n"
        "read-only: GET only. Namespaces/pods/keys are listed; secret DATA is never\n"
        "         read (only name+type with --poc-value). No write/exec is ever sent.\n"
        "AUTHORIZED SCOPE ONLY."
    )
    p = argparse.ArgumentParser(
        prog="k8shunt.py",
        description="Detect exposed / unauthenticated Kubernetes (apiserver/kubelet/etcd).",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-v", type=int, choices=[0, 1, 2], nargs="?", const=1, default=0,
                   help="verbosity: 0 = only successes (default), 1 = every test "
                        "performed, 2 = debug (each GET and its status/size)")
    p.add_argument("-u", dest="url", help="single target to test")
    p.add_argument("-l", dest="list", help="file containing a list of targets to test")
    p.add_argument("-p", "--port", dest="port", default=None, metavar="PORTS",
                   help="exclusive port(s) to test for targets without an explicit port: "
                        "comma list, ranges like 6443-6444 allowed")
    p.add_argument("--extra-ports", dest="extra_ports", action="store_true",
                   help="also test uncommon ports (6444,8443,2380,4194,10256,10257,"
                        "10259,9099) on top of the common set")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured output (colour is on by default)")
    p.add_argument("-t", "--threads", type=int, default=4,
                   help="concurrent targets (default 4)")
    p.add_argument("-d", "--delay", type=float, default=0.0,
                   help="minimum gap between requests (s), enforced globally across all threads")
    p.add_argument("--rate", type=float, default=8.0, help="max requests/sec (default 8)")
    p.add_argument("--timeout", type=float, default=20.0, help="per-request timeout (default 20)")
    p.add_argument("-x", "--proxy", dest="proxy", default=None,
                   help="proxy URL, e.g. http://127.0.0.1:8080 (HTTP proxy; CONNECT for HTTPS)")
    p.add_argument("--force-tls", dest="force_tls", action="store_true",
                   help="use HTTPS for all ports (default off; TLS is otherwise per-port)")
    p.add_argument("--verify-tls", dest="verify_tls", action="store_true",
                   help="verify certificates (default off)")
    p.add_argument("--client-cert", dest="client_cert", default=None, metavar="FILE",
                   help="client certificate (PEM) to present for mTLS targets (e.g. etcd)")
    p.add_argument("--client-key", dest="client_key", default=None, metavar="FILE",
                   help="private key for --client-cert (if not bundled in the cert file)")
    p.add_argument("--poc-value", dest="poc_value", action="store_true",
                   help="list resource identifiers as PoC (off by default; see "
                        "--poc-keys/--poc-bytes). Secret DATA is never read.")
    p.add_argument("--poc-keys", dest="poc_keys", type=int, default=5, metavar="N",
                   help="number of identifiers to list per component for the PoC "
                        "when --poc-value is set (default 5)")
    p.add_argument("--poc-bytes", dest="poc_bytes", type=int, default=120, metavar="N",
                   help="truncate each PoC identifier to N bytes (default 120)")
    p.add_argument("-o", "--output", metavar="TXT", help="write findings to TEXT file")
    return p


def load_targets(args):
    targets = []
    if args.url:
        targets.append(args.url.strip())
    if args.list:
        with open(args.list, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    return targets


def build_jobs(targets, args):
    ports_p = parse_ports(args.port) if args.port else None
    jobs = []
    for raw in targets:
        host, exp_port, scheme = parse_target(raw)
        if args.force_tls:
            forced = True
        elif scheme is True:
            forced = True
        elif scheme is False:
            forced = False
        else:
            forced = None
        if exp_port is not None:
            ports = [exp_port]
        elif ports_p is not None:
            ports = ports_p
        else:
            ports = list(COMMON_PORTS)
            if args.extra_ports:
                ports += EXTRA_PORTS
        seen = set()
        ports = [p for p in ports if not (p in seen or seen.add(p))]
        jobs.append((host, forced, ports))
    return jobs


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.no_color or not sys.stdout.isatty():
        C.disable()
    if not args.url and not args.list:
        build_parser().error("provide a target with -u or a list with -l")

    targets = load_targets(args)
    if not targets:
        build_parser().error("no targets loaded")

    jobs = build_jobs(targets, args)
    min_interval = max(args.delay, (1.0 / args.rate) if args.rate > 0 else 0.0)
    ctx = Ctx(args, Limiter(min_interval))
    ctx.total = len(jobs)

    sys.stderr.write(c(f"\n\tk8shunt: {ctx.total} target(s), {args.threads} thread(s), "
                       f"min gap {min_interval:.3f}s\n\n", C.turquoise))
    sys.stderr.flush()

    q = Queue()
    for j in jobs:
        q.put(j)

    ctx.show_status = bool(args.list) and ctx.total > 1
    start = time.monotonic()

    n = max(1, min(args.threads, ctx.total))
    threads = [threading.Thread(target=worker, args=(q, ctx), daemon=True) for _ in range(n)]
    for th in threads:
        th.start()
    try:
        for th in threads:
            th.join()
    except KeyboardInterrupt:
        sys.stderr.write(c("\n[!] interrupted\n", C.red))
    finally:
        ctx.close()

    el = fmt_elapsed(time.monotonic() - start)
    sys.stderr.write(c(f"\n[done {el}] scanned {ctx.done}/{ctx.total} host(s)  "
                       f"exposed components {ctx.found}\n", C.bold + C.turquoise))
    sys.stderr.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
