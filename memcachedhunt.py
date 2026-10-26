#!/usr/bin/env python3
"""
memcachedhunt.py - Detect exposed / unauthenticated Memcached instances (read-only).

Part of the *hunt bug-bounty tooling suite.

AUTHORIZED USE ONLY. Run this only against hosts that are in scope for a bug
bounty program or covered by a signed engagement / rules of engagement.

The tool is strictly READ-ONLY. It never issues set/add/replace/delete/flush.
On an unauthenticated instance it collects the minimum proof of exposure:
  - server version                     (version)
  - cache volume: item count, bytes    (stats)
  - a sample key NAME                   (stats items + stats cachedump)  -- name only

It also sends ONE UDP `stats` datagram per port: if the server answers over UDP
it is usable as a DDoS amplification reflector, reported as a distinct finding
(disable with --no-udp). A single packet is sent; no amplification is generated.

Pass --poc-value to additionally read up to --poc-keys values (each truncated to
--poc-bytes) via `get`. Off by default.

Targets:
  host                    -> host:11211
  host:port               -> that port
  memcached://host:port   -> that port
  (any other scheme is stripped; any user:pass@ prefix is stripped and ignored)
"""

import argparse
import re
import socket
import struct
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
# Memcached text protocol
# --------------------------------------------------------------------------- #

class McError(Exception):
    pass


class LineReader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("connection closed by peer")
        self.buf += chunk

    def read_line(self):
        while b"\r\n" not in self.buf:
            self._fill()
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def read_bytes(self, n):
        while len(self.buf) < n:
            self._fill()
        data = self.buf[:n]
        self.buf = self.buf[n:]
        return data


_ERR_PREFIXES = (b"ERROR", b"CLIENT_ERROR", b"SERVER_ERROR")


def _send(sock, ctx, host, port, text):
    ctx.limiter.wait()
    if ctx.v >= 2:
        ctx.debug(host, port, f"SEND {text!r}")
    sock.sendall(text.encode())


def _read_until_end(reader):
    """Read text-protocol lines until END; raise McError on an error line."""
    lines = []
    while True:
        line = reader.read_line()
        if line == b"END":
            break
        if line.startswith(_ERR_PREFIXES):
            raise McError(line.decode("utf-8", "replace"))
        lines.append(line)
        if len(lines) > 20000:                       # runaway guard
            break
    return lines


def _stats_kv(sock, reader, ctx, host, port):
    _send(sock, ctx, host, port, "stats\r\n")
    d = {}
    for line in _read_until_end(reader):
        if line.startswith(b"STAT "):
            parts = line.split(b" ", 2)
            if len(parts) == 3:
                d[parts[1].decode("utf-8", "replace")] = parts[2].decode("utf-8", "replace")
    if ctx.v >= 2:
        ctx.debug(host, port, f"RECV stats: {len(d)} STAT lines")
    return d


def _sample_keys(sock, reader, ctx, host, port, want):
    """Read-only key sampling via `stats items` + `stats cachedump` (bounded).
    cachedump is deprecated/limited on newer memcached - it simply yields nothing
    there, which we handle gracefully."""
    try:
        _send(sock, ctx, host, port, "stats items\r\n")
        lines = _read_until_end(reader)
    except Exception:
        return []
    slabs = []
    for line in lines:
        if line.startswith(b"STAT items:") and b":number " in line:
            try:
                name, val = line[5:].split(b" ", 1)   # items:<slab>:number , count
                if int(val) > 0:
                    slabs.append(name.split(b":")[1].decode("ascii", "replace"))
            except Exception:
                pass
    keys = []
    for slab in slabs:
        try:
            _send(sock, ctx, host, port,
                  f"stats cachedump {slab} {min(want, 100)}\r\n")
            lines = _read_until_end(reader)
        except McError:
            continue
        except Exception:
            break
        for line in lines:
            if line.startswith(b"ITEM "):
                keys.append(line[5:].split(b" ", 1)[0].decode("utf-8", "replace"))
                if len(keys) >= want:
                    break
        if len(keys) >= want:
            break
    return keys[:want]


def _get(sock, reader, ctx, host, port, key):
    """Read one value via `get` (read-only). Returns bytes or None."""
    _send(sock, ctx, host, port, f"get {key}\r\n")
    line = reader.read_line()
    if not line.startswith(b"VALUE "):
        return None
    parts = line.split(b" ")
    try:
        nbytes = int(parts[3])
    except (IndexError, ValueError):
        return None
    data = reader.read_bytes(nbytes)
    reader.read_line()                                # trailing CRLF after data
    while True:                                        # consume until END
        tail = reader.read_line()
        if tail == b"END" or tail.startswith(_ERR_PREFIXES):
            break
    return data


# --------------------------------------------------------------------------- #
# UDP amplification check (single read-only datagram)
# --------------------------------------------------------------------------- #

# memcached UDP frame header: request id, sequence, total datagrams, reserved.
_UDP_REQUEST = struct.pack(">HHHH", 0x0539, 0, 1, 0) + b"stats\r\n"


def udp_stats_bytes(host, port, ctx):
    """Send one UDP `stats` datagram. Return response size in bytes if the
    server answers (=> amplification reflector), else None. Never floods."""
    ctx.limiter.wait()
    s = None
    try:
        info = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)[0]
        s = socket.socket(info[0], socket.SOCK_DGRAM)
        s.settimeout(ctx.args.timeout)
        s.sendto(_UDP_REQUEST, info[4])
        data, _ = s.recvfrom(65535)
        return len(data)
    except Exception:
        return None
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Connection
# --------------------------------------------------------------------------- #

def open_connection(host, port, timeout):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


# --------------------------------------------------------------------------- #
# Target parsing
# --------------------------------------------------------------------------- #

_SCHEME_RE = re.compile(r'^([a-zA-Z][a-zA-Z0-9+.\-]*)://')


def parse_target(raw):
    raw = raw.strip()
    m = _SCHEME_RE.match(raw)
    if m:
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
    return host, port


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
# Probing (read-only)
# --------------------------------------------------------------------------- #

_UDP_REQ_LEN = len(_UDP_REQUEST)


def _hsize(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return str(n)
    for u in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return f"{n:.0f}{u}"
        n /= 1024
    return f"{n:.0f}P"


def probe(host, port, ctx):
    r = {"host": host, "port": port, "status": "ERROR",
         "detail": "", "data": {}, "suspect": []}
    a = ctx.args

    # UDP amplification check first (one datagram)
    if not a.no_udp:
        ub = udp_stats_bytes(host, port, ctx)
        if ub:
            r["data"]["udp_bytes"] = ub
            r["data"]["udp_factor"] = round(ub / _UDP_REQ_LEN, 1)

    # TCP text protocol
    try:
        sock = open_connection(host, port, a.timeout)
    except Exception as e:
        if r["data"].get("udp_bytes"):
            r["status"] = "UDP"
            r["detail"] = f"TCP {type(e).__name__}; UDP stats replied"
        else:
            r["detail"] = f"{type(e).__name__}: {e}"
        return r

    try:
        reader = LineReader(sock)
        try:
            _send(sock, ctx, host, port, "version\r\n")
            line = reader.read_line()
        except Exception as e:
            r["status"] = "UDP" if r["data"].get("udp_bytes") else "NOT-MEMCACHED"
            r["detail"] = str(e)
            return r

        if not line.startswith(b"VERSION"):
            if line.startswith(_ERR_PREFIXES):        # e.g. SASL required
                r["status"] = "AUTH"
                r["detail"] = f"version rejected: {line.decode('utf-8', 'replace')}"
            else:
                r["status"] = "UDP" if r["data"].get("udp_bytes") else "NOT-MEMCACHED"
                r["detail"] = f"unexpected version reply: {line[:40]!r}"
            return r

        r["data"]["version"] = (line.split(b" ", 1)[1].decode("utf-8", "replace").strip()
                                if b" " in line else "?")

        try:
            stats = _stats_kv(sock, reader, ctx, host, port)
        except McError as e:
            r["status"] = "AUTH"
            r["detail"] = f"stats rejected: {e}"
            return r

        r["data"]["items"] = int(stats.get("curr_items", "0") or 0)
        r["data"]["bytes"] = int(stats.get("bytes", "0") or 0)
        r["data"]["conns"] = stats.get("curr_connections", "?")

        ver = r["data"]["version"]
        if not re.match(r"^\d+\.\d+", ver):
            r["suspect"].append(f"implausible version '{ver}'")

        if r["data"]["items"] > 0:
            want = max(a.poc_keys * 20, 100) if a.poc_value else 1
            try:
                cand = _sample_keys(sock, reader, ctx, host, port, want)
            except Exception as e:
                ctx.debug(host, port, f"key sampling failed: {e}")
                cand = []
            if cand:
                r["data"]["sample_key"] = cand[0]
            if a.poc_value and cand:
                collected = []
                for k in cand:
                    if len(collected) >= a.poc_keys:
                        break
                    try:
                        val = _get(sock, reader, ctx, host, port, k)
                    except Exception:
                        continue
                    if val is not None:
                        if len(val) > a.poc_bytes:
                            val = val[:a.poc_bytes] + b"...[truncated]"
                        collected.append((k, val.decode("utf-8", "replace")))
                if collected:
                    r["data"]["poc_values"] = collected

        r["status"] = "OPEN" if r["data"]["items"] > 0 else "OPEN-EMPTY"
        return r
    finally:
        try:
            sock.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _udp_line(d):
    return (f"UDP amplification: stats replied {d['udp_bytes']} bytes "
            f"(~{d['udp_factor']}x)")


def render(r, ctx):
    tgt = f"{r['host']}:{r['port']}"
    st = r["status"]
    d = r["data"]

    if st in ("OPEN", "OPEN-EMPTY"):
        ctx.emit(f"{c('[OPEN]', C.bold + C.green)} {c(tgt, C.green)}  "
                 f"v{d.get('version','?')}  items={d.get('items',0)}  "
                 f"bytes={_hsize(d.get('bytes',0))}  conns={d.get('conns','?')}")
        if "sample_key" in d:
            ctx.emit(c(f"      PoC: sample key = {d['sample_key']!r}", C.yellow))
        for i, (k, v) in enumerate(d.get("poc_values", []), 1):
            ctx.emit(c(f"      PoC value[{i}]: {k!r} = {v!r}", C.yellow))
        if "udp_bytes" in d:
            ctx.emit(c(f"      ! {_udp_line(d)}", C.bold + C.red))
        if r["suspect"]:
            ctx.emit(c("      ! possible honeypot: " + "; ".join(r["suspect"]), C.yellow))

        rec = (f"{tgt} status={st} version={d.get('version','?')} "
               f"items={d.get('items',0)} bytes={d.get('bytes',0)} "
               f"conns={d.get('conns','?')}")
        if "sample_key" in d:
            rec += f" sample_key={d['sample_key']!r}"
        for i, (k, v) in enumerate(d.get("poc_values", []), 1):
            rec += f" poc_value[{i}]={k!r}:{v!r}"
        if "udp_bytes" in d:
            rec += f" udp_amplification={d['udp_bytes']}b:{d['udp_factor']}x"
        if r["suspect"]:
            rec += " honeypot?=" + ";".join(r["suspect"])
        ctx.write_finding(rec)
        return

    if st == "UDP":                                    # TCP not memcached, UDP replied
        ctx.emit(f"{c('[UDP ]', C.bold + C.red)} {c(tgt, C.red)}  {_udp_line(d)}")
        ctx.write_finding(f"{tgt} status=UDP "
                          f"udp_amplification={d['udp_bytes']}b:{d['udp_factor']}x")
        return

    if ctx.v < 1:
        return
    if st == "AUTH":
        ctx.emit(f"{c('[AUTH]', C.yellow)} {c(tgt, C.yellow)}  {r['detail']}")
    elif st == "NOT-MEMCACHED":
        ctx.emit(f"{c('[----]', C.grey)} {c(tgt, C.grey)}  not memcached: {r['detail']}")
    else:
        ctx.emit(f"{c('[ERR ]', C.red)} {c(tgt, C.dim)}  {r['detail']}")


# --------------------------------------------------------------------------- #
# Status / worker pool
# --------------------------------------------------------------------------- #

def fmt_elapsed(sec):
    sec = int(sec)
    h, m, s = sec // 3600, (sec % 3600) // 60, sec % 60
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


# A memcached instance is "found" (stop scanning this host's other ports) when
# it answers over TCP (open/empty/auth) or reflects over UDP.
FOUND_STATUSES = ("OPEN", "OPEN-EMPTY", "AUTH", "UDP")


def worker(q, ctx):
    while True:
        try:
            job = q.get_nowait()
        except Empty:
            return
        host, ports = job
        found = None
        try:
            for port in ports:
                try:
                    r = probe(host, port, ctx)
                except Exception as e:
                    r = {"host": host, "port": port, "status": "ERROR",
                         "detail": f"internal: {e}", "data": {}, "suspect": []}
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
            if ctx.v < 1 and found and found["status"] in ("OPEN", "OPEN-EMPTY", "UDP"):
                render(found, ctx)
            ctx.status()
            q.task_done()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

# Common memcached ports (default + stacked instances).
EXTRA_PORTS = [11211, 11212, 11213, 11214]


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
        "targets: host | host:port | memcached://host:port - any other scheme\n"
        "         (http://, ...) is stripped.\n"
        "ports:   a target with an explicit port is tried on that port only; else\n"
        "         the ports from -p and/or --extra-ports are tried in order (default\n"
        "         11211), and a host stops at the first port where memcached answers.\n"
        "read-only: only version / stats / stats items / stats cachedump / get are\n"
        "         sent (get only with --poc-value). No set/delete/flush is ever sent.\n"
        "udp:     one UDP `stats` datagram per port checks for DDoS amplification\n"
        "         exposure (disable with --no-udp); no amplification is generated.\n"
        "AUTHORIZED SCOPE ONLY."
    )
    p = argparse.ArgumentParser(
        prog="memcachedhunt.py",
        description="Detect exposed / unauthenticated Memcached instances (read-only).",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-v", type=int, choices=[0, 1, 2], nargs="?", const=1, default=0,
                   help="verbosity: 0 = only successes (default), 1 = every test "
                        "performed, 2 = debug (commands sent/received)")
    p.add_argument("-u", dest="url", help="single target to test")
    p.add_argument("-l", dest="list", help="file containing a list of targets to test")
    p.add_argument("-p", "--port", dest="port", default=None, metavar="PORTS",
                   help="port(s) to test for targets without an explicit port: comma "
                        "list, ranges like 11211-11214 allowed (only these are tested)")
    p.add_argument("--extra-ports", dest="extra_ports", action="store_true",
                   help="test the common memcached port set (11211,11212,11213,11214)")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured output (colour is on by default)")
    p.add_argument("-t", "--threads", type=int, default=4,
                   help="concurrent targets (default 4)")
    p.add_argument("-d", "--delay", type=float, default=0.0,
                   help="minimum gap between requests (s), enforced globally across all threads")
    p.add_argument("--rate", type=float, default=8.0, help="max requests/sec (default 8)")
    p.add_argument("--timeout", type=float, default=20.0, help="per-request timeout (default 20)")
    p.add_argument("--no-udp", dest="no_udp", action="store_true",
                   help="skip the UDP amplification check (TCP only)")
    p.add_argument("--poc-value", dest="poc_value", action="store_true",
                   help="read value(s) as PoC (off by default; see --poc-keys/--poc-bytes)")
    p.add_argument("--poc-keys", dest="poc_keys", type=int, default=5, metavar="N",
                   help="number of values to read for the PoC when --poc-value is set "
                        "(default 5)")
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


def build_jobs(targets, args):
    ports_p = parse_ports(args.port) if args.port else []
    ports_extra = list(EXTRA_PORTS) if args.extra_ports else []
    jobs = []
    for raw in targets:
        host, exp_port = parse_target(raw)
        if exp_port is not None:
            ports = [exp_port]
        else:
            ports = ports_p + ports_extra
            seen = set()
            ports = [p for p in ports if not (p in seen or seen.add(p))]
            if not ports:
                ports = [11211]
        jobs.append((host, ports))
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

    sys.stderr.write(c(f"\n\tmemcachedhunt: {ctx.total} target(s), {args.threads} thread(s), "
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
