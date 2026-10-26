#!/usr/bin/env python3
"""
redishunt.py - Detect exposed / unauthenticated Redis instances (read-only).

Part of the *hunt bug-bounty tooling suite.

AUTHORIZED USE ONLY. Run this only against hosts that are in scope for a bug
bounty program or covered by a signed engagement / rules of engagement.

The tool is strictly READ-ONLY. It never issues write, delete or config-change
commands (no SET / DEL / FLUSH* / CONFIG SET / SLAVEOF / MODULE ...). On an
unauthenticated instance it collects the minimum proof of exposure:
  - server version / mode / os               (INFO server)
  - key-space volume, i.e. number of keys    (INFO keyspace, DBSIZE)
  - one sample key NAME and its TYPE          (RANDOMKEY + TYPE)  -- never a value

Pass --poc-value to additionally read ONE key value (truncated/redacted) for a
client that explicitly requires a value as proof. Off by default.

Targets:
  host                 -> host:6379, plaintext
  host:port            -> plaintext on port
  redis://host:port    -> plaintext
  rediss://host:port   -> TLS (see --verify-tls)
  (any user:pass@ prefix is stripped and ignored - this tool does not AUTH)
"""

import argparse
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
# Global rate limiter (min gap between requests, enforced across all threads)
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
# RESP protocol
# --------------------------------------------------------------------------- #

def resp_encode(*args):
    out = [b"*" + str(len(args)).encode() + b"\r\n"]
    for a in args:
        if isinstance(a, str):
            a = a.encode()
        out.append(b"$" + str(len(a)).encode() + b"\r\n" + a + b"\r\n")
    return b"".join(out)


class RespReader:
    """Minimal RESP2 reply reader over a blocking socket."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("connection closed by peer")
        self.buf += chunk

    def _read_line(self):
        while b"\r\n" not in self.buf:
            self._fill()
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def _read_n(self, n):
        while len(self.buf) < n + 2:
            self._fill()
        data = self.buf[:n]
        self.buf = self.buf[n + 2:]  # drop trailing CRLF
        return data

    def read_reply(self, _depth=0):
        if _depth > 32:
            raise ValueError("RESP nesting too deep")
        line = self._read_line()
        if not line:
            raise ValueError("empty RESP line")
        t, rest = line[:1], line[1:]
        if t == b"+":
            return ("status", rest.decode("utf-8", "replace"))
        if t == b"-":
            return ("error", rest.decode("utf-8", "replace"))
        if t == b":":
            return ("int", int(rest))
        if t == b"$":
            n = int(rest)
            if n < 0:
                return ("bulk", None)
            return ("bulk", self._read_n(n).decode("utf-8", "replace"))
        if t == b"*":
            n = int(rest)
            if n < 0:
                return ("array", None)
            return ("array", [self.read_reply(_depth + 1) for _ in range(n)])
        raise ValueError(f"not a RESP reply (byte {t!r}) - probably not Redis")


# --------------------------------------------------------------------------- #
# Connection (optional HTTP CONNECT proxy, optional TLS)
# --------------------------------------------------------------------------- #

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


def open_connection(host, port, tls, verify, timeout, cert=None, key=None):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    if tls:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if cert:                                       # client cert for mTLS targets
            ctx.load_cert_chain(cert, key or None)
        s = ctx.wrap_socket(s, server_hostname=(host if verify else None))
    return s


# --------------------------------------------------------------------------- #
# Target parsing
# --------------------------------------------------------------------------- #

_SCHEME_RE = re.compile(r'^([a-zA-Z][a-zA-Z0-9+.\-]*)://')


def parse_target(raw):
    raw = raw.strip()
    tls = False
    # strip any scheme:// prefix (http://, https://, ftp://, redis://, ...);
    # only rediss:// carries a meaning we keep (TLS). Everything else is
    # dropped and the target treated as plaintext Redis.
    m = _SCHEME_RE.match(raw)
    if m:
        if m.group(1).lower() == "rediss":
            tls = True
        raw = raw[m.end():]
    if "@" in raw:                      # strip user:pass@ credentials
        raw = raw.split("@", 1)[1]
    for sep in ("/", "?", "#"):         # drop any path / query / fragment
        if sep in raw:
            raw = raw.split(sep, 1)[0]
    raw = raw.strip().rstrip("/")
    if raw.startswith("["):             # [ipv6] or [ipv6]:port
        host, _, tail = raw[1:].partition("]")
        tail = tail.lstrip(":")
        port = int(tail) if tail.isdigit() else None
    elif raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        host, p = raw.rsplit(":", 1)
        port = int(p)
    else:
        host, port = raw, None
    return host, port, tls           # port is None when the target carried none


# --------------------------------------------------------------------------- #
# Scan context (shared state / logging)
# --------------------------------------------------------------------------- #

class Ctx:
    def __init__(self, args, limiter):
        self.args = args
        self.limiter = limiter
        self.v = args.v
        self.print_lock = threading.Lock()
        self.out_fh = None
        if args.output:
            self.out_fh = open(args.output, "a", encoding="utf-8")
        self.found = 0
        self.done = 0
        self.total = 0
        self.show_status = False

    def emit(self, line=""):
        with self.print_lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def status(self):
        """Live one-line progress, rewritten in place on every completion."""
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
# Redis probing (read-only)
# --------------------------------------------------------------------------- #

def _cmd(sock, reader, ctx, host, port, *args):
    ctx.limiter.wait()
    payload = resp_encode(*args)
    ctx.debug(host, port, f"SEND {' '.join(args)}  raw={payload!r}")
    sock.sendall(payload)
    rep = reader.read_reply()
    ctx.debug(host, port, f"RECV kind={rep[0]} "
                          f"size={len(str(rep[1])) if rep[1] is not None else 0} "
                          f"value={_short(rep[1])}")
    return rep


def _short(v, n=80):
    s = str(v)
    return s if len(s) <= n else s[:n] + "..."


def _parse_info(blob):
    d = {}
    for line in blob.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, _, val = line.partition(":")
        d[k.strip()] = val.strip()
    return d


def _keyspace_total(blob):
    total = 0
    dbs = 0
    for line in blob.splitlines():
        line = line.strip()
        if line.startswith("db") and "keys=" in line:
            dbs += 1
            try:
                kv = dict(p.split("=", 1) for p in line.split(":", 1)[1].split(","))
                total += int(kv.get("keys", "0"))
            except Exception:
                pass
    return total, dbs


def _sample_keys(sock, reader, ctx, host, port, want):
    """Collect up to `want` distinct key names, read-only and bounded.
    Follows the SCAN cursor across pages (a single page can be partial or even
    empty with a non-zero cursor); falls back to repeated RANDOMKEY for
    Redis < 2.8 or if SCAN yields nothing."""
    keys = []
    count_hint = 20 if want <= 1 else 100
    cursor = "0"
    pages = 0
    try:
        while True:
            rep = _cmd(sock, reader, ctx, host, port,
                       "SCAN", cursor, "COUNT", str(count_hint))
            if rep[0] != "array" or not rep[1] or len(rep[1]) != 2:
                raise ValueError("unexpected SCAN reply")
            cur_rep, keys_rep = rep[1]
            cursor = cur_rep[1] if cur_rep[0] in ("bulk", "status") else "0"
            if keys_rep[0] == "array" and keys_rep[1]:
                keys.extend(x[1] for x in keys_rep[1]
                            if x[0] == "bulk" and x[1] is not None)
            pages += 1
            if cursor == "0" or len(keys) >= want or pages >= 100:
                break
    except Exception as e:
        ctx.debug(host, port, f"SCAN failed ({e}) - falling back to RANDOMKEY")
        keys = []
    if not keys:                                     # fallback: RANDOMKEY loop
        seen = set()
        for _ in range(max(want * 2, 8)):
            try:
                rep = _cmd(sock, reader, ctx, host, port, "RANDOMKEY")
            except Exception:
                break
            if rep[0] == "bulk" and rep[1] is not None and rep[1] not in seen:
                seen.add(rep[1])
                keys.append(rep[1])
            if len(keys) >= want:
                break
    return keys[:want]


def probe(host, port, tls, ctx):
    r = {"host": host, "port": port, "tls": tls,
         "status": "ERROR", "detail": "", "data": {}, "suspect": []}
    a = ctx.args
    try:
        sock = open_connection(host, port, tls, a.verify_tls, a.timeout,
                               a.client_cert, a.client_key)
    except Exception as e:
        if tls and isinstance(e, ssl.SSLError) and not _is_mtls(e):
            ctx.debug(host, port, f"TLS failed ({e}); retrying plaintext")
            try:                                       # TLS→plaintext fallback
                sock = open_connection(host, port, False, a.verify_tls, a.timeout)
                tls = False
                r["tls"] = False
            except Exception as e2:
                r["detail"] = _tls_reason(e) or f"{type(e2).__name__}: {e2}"
                return r
        elif _is_mtls(e):
            r["status"] = "MTLS"
            r["detail"] = "client certificate required (mTLS enforced)"
            return r
        else:
            r["detail"] = _tls_reason(e) or f"{type(e).__name__}: {e}"
            return r

    try:
        reader = RespReader(sock)

        # 1) liveness / auth discrimination
        try:
            rep = _cmd(sock, reader, ctx, host, port, "PING")
        except (ValueError, ConnectionError) as e:
            r["status"] = "NOT-REDIS"
            r["detail"] = str(e)
            return r

        if rep[0] == "status" and rep[1].upper() == "PONG":
            pass  # open, unauthenticated
        elif rep[0] == "error":
            err = rep[1].upper()
            if "NOAUTH" in err or "AUTHENTICATION" in err:
                r["status"] = "AUTH"
                r["detail"] = "NOAUTH - authentication required"
            elif "WRONGPASS" in err:
                r["status"] = "AUTH"
                r["detail"] = "password-protected"
            else:
                r["status"] = "AUTH"
                r["detail"] = f"reachable, restricted: {rep[1]}"
            return r
        else:
            r["status"] = "NOT-REDIS"
            r["detail"] = f"unexpected PING reply: {rep!r}"
            return r

        # 2) INFO server (version / mode / os)
        info = {}
        try:
            rep = _cmd(sock, reader, ctx, host, port, "INFO", "server")
            if rep[0] == "bulk" and rep[1]:
                info = _parse_info(rep[1])
            elif rep[0] == "error" and ("NOAUTH" in rep[1].upper()):
                # PONG without auth but INFO gated -> odd, treat as auth
                r["status"] = "AUTH"
                r["detail"] = "PING open but INFO requires auth"
                return r
        except Exception as e:
            ctx.debug(host, port, f"INFO server failed: {e}")

        r["data"]["version"] = info.get("redis_version", "?")
        r["data"]["mode"] = info.get("redis_mode", "?")
        r["data"]["os"] = info.get("os", "?")
        r["data"]["run_id"] = info.get("run_id", "")

        # honeypot heuristics (light)
        ver = r["data"]["version"]
        if ver in ("", "?"):
            r["suspect"].append("no redis_version in INFO")
        else:
            head = ver.split(".")[0]
            if not head.isdigit() or int(head) > 20:
                r["suspect"].append(f"implausible version '{ver}'")
        if not r["data"]["run_id"]:
            r["suspect"].append("no run_id in INFO")

        # 3) key-space volume
        keys, dbs = 0, 0
        try:
            rep = _cmd(sock, reader, ctx, host, port, "INFO", "keyspace")
            if rep[0] == "bulk" and rep[1]:
                keys, dbs = _keyspace_total(rep[1])
        except Exception as e:
            ctx.debug(host, port, f"INFO keyspace failed: {e}")
        if keys == 0:
            try:
                rep = _cmd(sock, reader, ctx, host, port, "DBSIZE")
                if rep[0] == "int":
                    keys = rep[1]
            except Exception as e:
                ctx.debug(host, port, f"DBSIZE failed: {e}")
        r["data"]["keys"] = keys
        r["data"]["dbs"] = dbs

        # 4) minimal PoC: sample key NAME(s) + TYPE (no value by default).
        #    With --poc-value, read up to --poc-keys string values (truncated
        #    to --poc-bytes). All read-only (SCAN / RANDOMKEY / TYPE / GET).
        if keys > 0:
            # gather more candidates than poc_keys: non-string keys are filtered
            # out below, so we need headroom to still find poc_keys strings.
            want = max(a.poc_keys * 20, 100) if a.poc_value else 1
            try:
                cand = _sample_keys(sock, reader, ctx, host, port, want)
            except Exception as e:
                ctx.debug(host, port, f"key sampling failed: {e}")
                cand = []

            type_cache = {}

            def type_of(k):
                if k in type_cache:
                    return type_cache[k]
                t = "?"
                try:
                    rt = _cmd(sock, reader, ctx, host, port, "TYPE", k)
                    if rt[0] == "status":
                        t = rt[1]
                except Exception:
                    pass
                type_cache[k] = t
                return t

            if cand:
                r["data"]["sample_key"] = cand[0]
                r["data"]["sample_type"] = type_of(cand[0])

            if a.poc_value:
                collected = []
                for k in cand:
                    if len(collected) >= a.poc_keys:
                        break
                    if type_of(k) != "string":
                        continue
                    try:
                        rv = _cmd(sock, reader, ctx, host, port, "GET", k)
                    except Exception:
                        continue
                    if rv[0] == "bulk" and rv[1] is not None:
                        val = rv[1]
                        if len(val) > a.poc_bytes:
                            val = val[:a.poc_bytes] + "...[truncated]"
                        collected.append((k, val))
                if collected:
                    r["data"]["poc_values"] = collected
            r["status"] = "OPEN"
        else:
            r["status"] = "OPEN-EMPTY"

        return r
    finally:
        try:
            sock.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def render(r, ctx):
    host, port = r["host"], r["port"]
    tls = " (TLS)" if r["tls"] else ""
    tgt = f"{host}:{port}{tls}"
    st = r["status"]

    if st in ("OPEN", "OPEN-EMPTY"):
        d = r["data"]
        tag = c("[OPEN]", C.bold + C.green)
        line = (f"{tag} {c(tgt, C.green)}  "
                f"v{d.get('version','?')} mode={d.get('mode','?')} "
                f"os={d.get('os','?')}  keys={d.get('keys',0)} dbs={d.get('dbs',0)}")
        ctx.emit(line)
        if d.get("sample_key") is not None:
            ctx.emit(c(f"      PoC: sample key = {d['sample_key']!r} "
                       f"type={d.get('sample_type','?')}", C.yellow))
        for i, (k, v) in enumerate(d.get("poc_values", []), 1):
            ctx.emit(c(f"      PoC value[{i}]: {k!r} = {v!r}", C.yellow))
        if r["suspect"]:
            ctx.emit(c("      ! possible honeypot: " + "; ".join(r["suspect"]), C.yellow))
        # findings file
        rec = (f"{tgt} status={st} version={d.get('version','?')} "
               f"mode={d.get('mode','?')} os={d.get('os','?')} "
               f"keys={d.get('keys',0)} dbs={d.get('dbs',0)}")
        if d.get("sample_key") is not None:
            rec += f" sample_key={d['sample_key']!r} type={d.get('sample_type','?')}"
        for i, (k, v) in enumerate(d.get("poc_values", []), 1):
            rec += f" poc_value[{i}]={k!r}:{v!r}"
        if r["suspect"]:
            rec += f" honeypot?={';'.join(r['suspect'])}"
        ctx.write_finding(rec)
        return

    if st == "MTLS":
        if ctx.v >= 1:
            ctx.emit(f"{c('[MTLS]', C.magenta)} {c(tgt, C.magenta)}  {r['detail']}")
        return

    # non-successes only shown at -v >= 1
    if ctx.v < 1:
        return
    if st == "AUTH":
        ctx.emit(f"{c('[AUTH]', C.yellow)} {c(tgt, C.yellow)}  {r['detail']}")
    elif st == "NOT-REDIS":
        ctx.emit(f"{c('[----]', C.grey)} {c(tgt, C.grey)}  not redis: {r['detail']}")
    else:  # ERROR
        ctx.emit(f"{c('[ERR ]', C.red)} {c(tgt, C.dim)}  {r['detail']}")


# --------------------------------------------------------------------------- #
# Status reporter
# --------------------------------------------------------------------------- #

def fmt_elapsed(sec):
    sec = int(sec)
    h, m, s = sec // 3600, (sec % 3600) // 60, sec % 60
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


# --------------------------------------------------------------------------- #
# Worker pool
# --------------------------------------------------------------------------- #

# A Redis instance is considered "found" (stop scanning this host's other
# ports) whether it is open, open-but-empty, or password-protected.
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
                except Exception as e:               # never let a thread die
                    r = {"host": host, "port": port, "tls": tls,
                         "status": "ERROR", "detail": f"internal: {e}",
                         "data": {}, "suspect": []}
                if ctx.v >= 1:                        # -v1/-v2: show every test
                    render(r, ctx)
                if r["status"] in FOUND_STATUSES:
                    found = r
                    break                             # skip the remaining ports
        finally:
            with ctx.print_lock:
                ctx.done += 1
                if found and found["status"] in ("OPEN", "OPEN-EMPTY"):
                    ctx.found += 1
            if ctx.v < 1 and found and found["status"] in ("OPEN", "OPEN-EMPTY"):
                render(found, ctx)                    # -v0: only successes
            ctx.status()
            q.task_done()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser():
    epilog = (
        "targets: host | host:port | redis://host | rediss://host (TLS) - any\n"
        "         other scheme (http://, ftp://, ...) is stripped.\n"
        "ports:   a target with an explicit port is tried on that port only; else\n"
        "         the ports from -p and/or --extra-ports are tried in order (default\n"
        "         6379), and a host stops at the first port where Redis answers.\n"
        "read-only: no SET/DEL/FLUSH/CONFIG/SLAVEOF/MODULE is ever sent.\n"
        "AUTHORIZED SCOPE ONLY."
    )
    p = argparse.ArgumentParser(
        prog="redishunt.py",
        description="Detect exposed / unauthenticated Redis instances (read-only).",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-v", type=int, choices=[0, 1, 2], nargs="?", const=1, default=0,
                   help="verbosity: 0 = only successes (default), 1 = every test "
                        "performed, 2 = debug (full request and the exact payload "
                        "sent, response status/size, and payloads skipped as filtered)")
    p.add_argument("-u", dest="url", help="single target to test")
    p.add_argument("-l", dest="list", help="file containing a list of targets to test")
    p.add_argument("-p", "--port", dest="port", default=None, metavar="PORTS",
                   help="port(s) to test for targets without an explicit port: comma "
                        "list, ranges like 7000-7005 allowed (only these are tested)")
    p.add_argument("--extra-ports", dest="extra_ports", action="store_true",
                   help="test the common Redis/Sentinel/cluster port set "
                        "(6379,6380,6381,6382,6399,6400,7000-7005,16379,26379)")
    p.add_argument("--no-color", action="store_true", help="disable coloured output (colour is on by default)")
    p.add_argument("-t", "--threads", type=int, default=4,
                   help="concurrent targets (default 4)")
    p.add_argument("-d", "--delay", type=float, default=0.0,
                   help="minimum gap between requests (s), enforced globally across all threads")
    p.add_argument("--rate", type=float, default=8.0, help="max requests/sec (default 8)")
    p.add_argument("--timeout", type=float, default=20.0, help="per-request timeout (default 20)")
    p.add_argument("--force-tls", dest="force_tls", action="store_true",
                   help="use TLS for all targets (default off)")
    p.add_argument("--verify-tls", dest="verify_tls", action="store_true",
                   help="verify certificates (default off)")
    p.add_argument("--client-cert", dest="client_cert", default=None, metavar="FILE",
                   help="client certificate (PEM) to present for mTLS targets")
    p.add_argument("--client-key", dest="client_key", default=None, metavar="FILE",
                   help="private key for --client-cert (if not bundled in the cert file)")
    p.add_argument("--poc-value", dest="poc_value", action="store_true",
                   help="read string value(s) as PoC (off by default; see --poc-keys/--poc-bytes)")
    p.add_argument("--poc-keys", dest="poc_keys", type=int, default=5, metavar="N",
                   help="number of string values to read for the PoC when --poc-value "
                        "is set (default 5)")
    p.add_argument("--poc-bytes", dest="poc_bytes", type=int, default=120, metavar="N",
                   help="truncate each PoC value to N bytes (default 120)")
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


# Common Redis / Sentinel / cluster ports, used by --extra-ports.
EXTRA_PORTS = [6379, 6380, 6381, 6382, 6399, 6400,
               7000, 7001, 7002, 7003, 7004, 7005, 16379, 26379]


def parse_ports(spec):
    """Parse '6379,6380,7000-7005' into an ordered list of ints (ranges ok)."""
    out = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part.lstrip("-"):          # a range like 7000-7005
            a, _, b = part.partition("-")
            a, b = int(a), int(b)
            step = 1 if b >= a else -1
            out.extend(range(a, b + step, step))
        else:
            out.append(int(part))
    return out


def build_jobs(targets, args):
    """One job per target line: (host, tls, ordered_ports).
    Explicit port in the target -> that port only. Otherwise the ports come
    from -p (a comma list / ranges) and/or --extra-ports (the preset set);
    with neither, the default 6379. De-duplicated, order preserved."""
    ports_p = parse_ports(args.port) if args.port else []
    ports_extra = list(EXTRA_PORTS) if args.extra_ports else []
    jobs = []
    for raw in targets:
        host, exp_port, scheme_tls = parse_target(raw)
        tls = scheme_tls or args.force_tls
        if exp_port is not None:
            ports = [exp_port]
        else:
            ports = ports_p + ports_extra
            seen = set()
            ports = [p for p in ports if not (p in seen or seen.add(p))]
            if not ports:                    # neither -p nor --extra-ports
                ports = [6379]
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
    limiter = Limiter(min_interval)
    ctx = Ctx(args, limiter)
    ctx.total = len(jobs)

    sys.stderr.write(c(f"\n\tredishunt: {ctx.total} target(s), {args.threads} thread(s), "
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
