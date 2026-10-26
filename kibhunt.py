#!/usr/bin/env python3
"""
kibhunt.py - Detect exposed / unauthenticated Kibana instances (read-only).

Part of the *hunt bug-bounty tooling suite.

AUTHORIZED USE ONLY. Run this only against hosts that are in scope for a bug
bounty program or covered by a signed engagement / rules of engagement.

The tool is strictly READ-ONLY. It only issues GET requests. On a reachable
instance it collects the minimum proof of exposure:
  - version / status state / node name   (GET /api/status)
  - whether saved objects are readable    (GET /api/saved_objects/_find)
    without authentication -> distinguishes OPEN (data readable) from a
    login-gated instance (AUTH), plus index-pattern / dashboard counts.

Pass --poc-value to additionally list up to --poc-keys saved object titles
(index patterns, dashboards, searches, visualizations), each truncated to
--poc-bytes. Off by default.

Targets:
  host                     -> http://host:5601
  host:port                -> http on that port
  http://host:port         -> plaintext
  https://host:port        -> TLS (see --force-tls / --verify-tls)
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
# Global rate limiter (min gap between requests, across all threads)
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
            "User-Agent": "kibhunt", "Accept": "application/json",
            "kbn-xsrf": "kibhunt", "Connection": "close"})
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
    raw = raw.strip()
    tls = False
    m = _SCHEME_RE.match(raw)
    if m:
        if m.group(1).lower() == "https":
            tls = True
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
    return host, port, tls


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
# Kibana probing (read-only)
# --------------------------------------------------------------------------- #

_KIB_SIG = (b"kbn-", b"kibana", b"/app/kibana", b"bootstraptemplate", b"kbnbundles")
_POC_TYPES = ("index-pattern", "dashboard", "search", "visualization")


def _trunc(s, nbytes):
    s = str(s)
    return s if len(s) <= nbytes else s[:nbytes] + "...[truncated]"


def probe(host, port, tls, ctx):
    r = {"host": host, "port": port, "tls": tls, "status": "ERROR",
         "detail": "", "data": {}, "suspect": []}
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

    # 1) /api/status
    try:
        status, hdrs, body, data = get("/api/status")
    except Exception as e:
        if _is_mtls(e):
            r["status"] = "MTLS"
            r["detail"] = "client certificate required (mTLS enforced)"
        else:
            r["detail"] = _tls_reason(e) or f"{type(e).__name__}: {e}"
        return r

    if status in (401, 403):
        r["status"] = "AUTH"
        r["detail"] = f"HTTP {status} on /api/status - authentication required"
        return r

    version, state, name = "?", "?", ""
    kib = False
    if isinstance(data, dict) and ("version" in data or "status" in data):
        kib = True
        ver = data.get("version", {})
        version = ver.get("number", "?") if isinstance(ver, dict) else "?"
        name = data.get("name", "") or ""
        st = data.get("status", {})
        if isinstance(st, dict):
            overall = st.get("overall", {}) or {}
            state = overall.get("state") or overall.get("level") or "?"

    if not kib:                                        # fallback: HTML signature on /
        try:
            _, _, body2, _ = get("/")
        except Exception:
            body2 = b""
        low = body2.lower()
        if any(sig in low for sig in _KIB_SIG):
            kib = True
        if not kib:
            r["status"] = "NOT-KIBANA"
            r["detail"] = f"HTTP {status}, no Kibana signature"
            return r

    r["data"]["version"] = version
    r["data"]["state"] = state
    r["data"]["name"] = name
    if version != "?" and not re.match(r"^\d+\.\d+", str(version)):
        r["suspect"].append(f"implausible version '{version}'")

    # 2) unauthenticated saved-objects access (OPEN vs login-gated)
    def so_total(t):
        try:
            st, _, _, d = get(f"/api/saved_objects/_find?type={t}&per_page=1")
        except Exception:
            return None, "err"
        if st in (401, 403):
            return None, "auth"
        if isinstance(d, dict) and "total" in d:
            return d.get("total"), "ok"
        return None, "na"

    ip_total, s1 = so_total("index-pattern")
    dash_total, s2 = so_total("dashboard")

    if s1 == "auth" and s2 == "auth":
        r["status"] = "AUTH"
        r["detail"] = f"Kibana v{version} present; saved_objects require login"
        return r

    r["data"]["index_patterns"] = ip_total if ip_total is not None else "?"
    r["data"]["dashboards"] = dash_total if dash_total is not None else "?"

    if a.poc_value:
        types = "".join(f"type={t}&" for t in _POC_TYPES)
        try:
            _, _, _, d = get(f"/api/saved_objects/_find?{types}per_page={a.poc_keys}")
        except Exception:
            d = None
        objs = (d or {}).get("saved_objects", []) if isinstance(d, dict) else []
        poc = []
        for o in objs[:a.poc_keys]:
            if not isinstance(o, dict):
                continue
            t = o.get("type", "?")
            title = (o.get("attributes", {}) or {}).get("title") or o.get("id", "?")
            poc.append((t, _trunc(title, a.poc_bytes)))
        if poc:
            r["data"]["saved_objects"] = poc

    counts = [x for x in (ip_total, dash_total) if isinstance(x, int)]
    r["status"] = "OPEN" if any(x > 0 for x in counts) else "OPEN-EMPTY"
    return r


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def render(r, ctx):
    tls = " (TLS)" if r["tls"] else ""
    tgt = f"{r['host']}:{r['port']}{tls}"
    st = r["status"]
    d = r["data"]

    if st in ("OPEN", "OPEN-EMPTY"):
        namepart = f"  name={d['name']}" if d.get("name") else ""
        ctx.emit(f"{c('[OPEN]', C.bold + C.green)} {c(tgt, C.green)}  "
                 f"Kibana v{d.get('version','?')}  state={d.get('state','?')}"
                 f"{namepart}  index-patterns={d.get('index_patterns','?')}  "
                 f"dashboards={d.get('dashboards','?')}")
        for i, (t, title) in enumerate(d.get("saved_objects", []), 1):
            ctx.emit(c(f"      PoC obj[{i}]: {t} = {title!r}", C.yellow))
        if r["suspect"]:
            ctx.emit(c("      ! possible honeypot: " + "; ".join(r["suspect"]), C.yellow))

        rec = (f"{tgt} status={st} version={d.get('version','?')} "
               f"state={d.get('state','?')} name={d.get('name','')!r} "
               f"index_patterns={d.get('index_patterns','?')} "
               f"dashboards={d.get('dashboards','?')}")
        for i, (t, title) in enumerate(d.get("saved_objects", []), 1):
            rec += f" obj[{i}]={t}:{title!r}"
        if r["suspect"]:
            rec += " honeypot?=" + ";".join(r["suspect"])
        ctx.write_finding(rec)
        return

    if st == "MTLS":
        if ctx.v >= 1:
            ctx.emit(f"{c('[MTLS]', C.magenta)} {c(tgt, C.magenta)}  {r['detail']}")
        return

    if ctx.v < 1:
        return
    if st == "AUTH":
        ctx.emit(f"{c('[AUTH]', C.yellow)} {c(tgt, C.yellow)}  {r['detail']}")
    elif st == "NOT-KIBANA":
        ctx.emit(f"{c('[----]', C.grey)} {c(tgt, C.grey)}  not kibana: {r['detail']}")
    else:
        ctx.emit(f"{c('[ERR ]', C.red)} {c(tgt, C.dim)}  {r['detail']}")


# --------------------------------------------------------------------------- #
# Status / worker pool
# --------------------------------------------------------------------------- #

def fmt_elapsed(sec):
    sec = int(sec)
    h, m, s = sec // 3600, (sec % 3600) // 60, sec % 60
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


# A Kibana instance is "found" (stop scanning this host's other ports) whether
# it is open, open-but-empty, or login-gated.
FOUND_STATUSES = ("OPEN", "OPEN-EMPTY", "AUTH", "MTLS")


def worker(q, ctx):
    while True:
        try:
            job = q.get_nowait()
        except Empty:
            return
        host, tls, ports = job
        found = None
        try:
            for port in ports:
                try:
                    r = probe(host, port, tls, ctx)
                except Exception as e:
                    r = {"host": host, "port": port, "tls": tls,
                         "status": "ERROR", "detail": f"internal: {e}",
                         "data": {}, "suspect": []}
                if ctx.v >= 1:
                    render(r, ctx)
                if r["status"] in FOUND_STATUSES:
                    found = r
                    break
        finally:
            with ctx.print_lock:
                ctx.done += 1
                if found and found["status"] in ("OPEN", "OPEN-EMPTY"):
                    ctx.found += 1
            if ctx.v < 1 and found and found["status"] in ("OPEN", "OPEN-EMPTY"):
                render(found, ctx)
            ctx.status()
            q.task_done()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

# Common Kibana ports, always tested.
COMMON_PORTS = [5601, 5602]
# Uncommon extra ports, only added with --extra-ports.
EXTRA_PORTS = [5603, 5604, 5605, 443, 8443]


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
        "targets: host | host:port | http://host:port | https://host:port (TLS) -\n"
        "         any other scheme is stripped; no scheme means http.\n"
        "ports:   an explicit port in the target is tried alone; -p PORTS is an\n"
        "         exclusive list; otherwise the common ports (5601,5602) are always\n"
        "         tried, and --extra-ports adds a few uncommon ones. A host stops at\n"
        "         the first port where Kibana answers.\n"
        "read-only: only GET /api/status and GET /api/saved_objects/_find are sent.\n"
        "         No write is ever sent.\n"
        "AUTHORIZED SCOPE ONLY."
    )
    p = argparse.ArgumentParser(
        prog="kibhunt.py",
        description="Detect exposed / unauthenticated Kibana instances (read-only).",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-v", type=int, choices=[0, 1, 2], nargs="?", const=1, default=0,
                   help="verbosity: 0 = only successes (default), 1 = every test "
                        "performed, 2 = debug (each GET and its status/size)")
    p.add_argument("-u", dest="url", help="single target to test")
    p.add_argument("-l", dest="list", help="file containing a list of targets to test")
    p.add_argument("-p", "--port", dest="port", default=None, metavar="PORTS",
                   help="port(s) to test for targets without an explicit port: comma "
                        "list, ranges like 5601-5602 allowed (only these are tested)")
    p.add_argument("--extra-ports", dest="extra_ports", action="store_true",
                   help="also test uncommon ports (5603-5605,443,8443) on top of the "
                        "common set (5601,5602)")
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
                   help="use HTTPS for all targets (default off)")
    p.add_argument("--verify-tls", dest="verify_tls", action="store_true",
                   help="verify certificates (default off)")
    p.add_argument("--client-cert", dest="client_cert", default=None, metavar="FILE",
                   help="client certificate (PEM) to present for mTLS targets")
    p.add_argument("--client-key", dest="client_key", default=None, metavar="FILE",
                   help="private key for --client-cert (if not bundled in the cert file)")
    p.add_argument("--poc-value", dest="poc_value", action="store_true",
                   help="list saved object title(s) as PoC (off by default; see --poc-keys/--poc-bytes)")
    p.add_argument("--poc-keys", dest="poc_keys", type=int, default=5, metavar="N",
                   help="number of saved objects to list for the PoC when --poc-value "
                        "is set (default 5)")
    p.add_argument("--poc-bytes", dest="poc_bytes", type=int, default=120, metavar="N",
                   help="truncate each PoC title to N bytes (default 120)")
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
        host, exp_port, scheme_tls = parse_target(raw)
        tls = scheme_tls or args.force_tls
        if exp_port is not None:                       # explicit port: only that
            ports = [exp_port]
        elif ports_p is not None:                      # -p: exclusive list
            ports = ports_p
        else:                                          # common ports always;
            ports = list(COMMON_PORTS)                 # --extra-ports adds more
            if args.extra_ports:
                ports += EXTRA_PORTS
        seen = set()
        ports = [p for p in ports if not (p in seen or seen.add(p))]
        jobs.append((host, tls, ports))
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

    sys.stderr.write(c(f"\n\tkibhunt: {ctx.total} target(s), {args.threads} thread(s), "
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
    sys.stderr.write(c(f"\n[done {el}] scanned {ctx.done}/{ctx.total}  open {ctx.found}\n",
                       C.bold + C.turquoise))
    sys.stderr.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
