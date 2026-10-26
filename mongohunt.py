#!/usr/bin/env python3
"""
mongohunt.py - Detect exposed / unauthenticated MongoDB instances (read-only).

Part of the *hunt bug-bounty tooling suite.

AUTHORIZED USE ONLY. Run this only against hosts that are in scope for a bug
bounty program or covered by a signed engagement / rules of engagement.

The tool is strictly READ-ONLY. It never issues insert/update/delete or any
admin write. On an unauthenticated instance it collects the minimum proof of
exposure:
  - server version + topology         (isMaster / buildInfo)
  - database list + sizes             (listDatabases)
  - collection names + document count (listCollections, count)  -- volume only

Pass --poc-value to additionally read ONE document from up to --poc-keys
collections (preview truncated to --poc-bytes). Off by default.

Targets:
  host                    -> host:27017, plaintext
  host:port               -> plaintext on port
  mongodb://host:port     -> plaintext
  mongodb+srv://host      -> TLS hint (see --force-tls)
  (any user:pass@ prefix is stripped and ignored - this tool does not auth)
"""

import argparse
import json
import re
import socket
import ssl
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
# Minimal BSON (only what commands and replies need)
# --------------------------------------------------------------------------- #

def _enc_cstr(s):
    return s.encode("utf-8") + b"\x00"


def _enc_value(v):
    if isinstance(v, bool):
        return 0x08, (b"\x01" if v else b"\x00")
    if isinstance(v, int):
        if -2**31 <= v < 2**31:
            return 0x10, struct.pack("<i", v)
        return 0x12, struct.pack("<q", v)
    if isinstance(v, float):
        return 0x01, struct.pack("<d", v)
    if isinstance(v, str):
        b = v.encode("utf-8") + b"\x00"
        return 0x02, struct.pack("<i", len(b)) + b
    if isinstance(v, dict):
        return 0x03, _enc_doc(v)
    if isinstance(v, list):
        return 0x04, _enc_doc({str(i): x for i, x in enumerate(v)})
    if v is None:
        return 0x0A, b""
    raise TypeError(f"cannot BSON-encode {type(v)}")


def _enc_doc(d):
    body = b""
    for k, v in d.items():
        t, payload = _enc_value(v)
        body += bytes([t]) + _enc_cstr(k) + payload
    body += b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _dec_doc(buf, off):
    length = struct.unpack_from("<i", buf, off)[0]
    end = off + length
    off += 4
    out = {}
    while off < end - 1:
        t = buf[off]
        off += 1
        nend = buf.index(0, off)
        name = buf[off:nend].decode("utf-8", "replace")
        off = nend + 1
        v, off = _dec_value(buf, off, t)
        out[name] = v
    return out, end


def _dec_value(buf, off, t):
    if t == 0x01:
        return struct.unpack_from("<d", buf, off)[0], off + 8
    if t == 0x02 or t == 0x0D or t == 0x0E:          # string / code / symbol
        ln = struct.unpack_from("<i", buf, off)[0]
        off += 4
        return buf[off:off + ln - 1].decode("utf-8", "replace"), off + ln
    if t == 0x03:
        return _dec_doc(buf, off)
    if t == 0x04:
        d, end = _dec_doc(buf, off)
        try:
            return [d[k] for k in sorted(d, key=lambda x: int(x))], end
        except ValueError:
            return list(d.values()), end
    if t == 0x05:                                    # binary
        ln = struct.unpack_from("<i", buf, off)[0]
        off += 4
        sub = buf[off]
        off += 1
        return {"$binary": f"<{ln} bytes, subtype {sub}>"}, off + ln
    if t == 0x06:                                    # undefined (deprecated)
        return None, off
    if t == 0x07:                                    # ObjectId
        return {"$oid": buf[off:off + 12].hex()}, off + 12
    if t == 0x08:
        return (buf[off] != 0), off + 1
    if t == 0x09:                                    # UTC datetime
        return {"$date": struct.unpack_from("<q", buf, off)[0]}, off + 8
    if t == 0x0A:
        return None, off
    if t == 0x0B:                                    # regex: 2 cstrings
        e1 = buf.index(0, off)
        e2 = buf.index(0, e1 + 1)
        return {"$regex": buf[off:e1].decode("utf-8", "replace")}, e2 + 1
    if t == 0x10:
        return struct.unpack_from("<i", buf, off)[0], off + 4
    if t == 0x11:                                    # timestamp
        return {"$timestamp": struct.unpack_from("<Q", buf, off)[0]}, off + 8
    if t == 0x12:
        return struct.unpack_from("<q", buf, off)[0], off + 8
    if t == 0x13:                                    # decimal128
        return {"$decimal128": buf[off:off + 16].hex()}, off + 16
    if t == 0xFF:
        return {"$minKey": 1}, off
    if t == 0x7F:
        return {"$maxKey": 1}, off
    raise ValueError(f"unknown BSON type 0x{t:02x}")


# --------------------------------------------------------------------------- #
# MongoDB wire protocol (OP_MSG 2013, with OP_QUERY 2004 fallback)
# --------------------------------------------------------------------------- #

MAX_MSG = 48_000_000


def _recv_n(sock, n):
    if n < 0 or n > MAX_MSG:
        raise ValueError("implausible length - not MongoDB wire protocol")
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed by peer")
        buf += chunk
    return buf


def _recv_msg(sock):
    hdr = _recv_n(sock, 16)
    mlen, _req, _resp, opcode = struct.unpack("<iiii", hdr)
    if mlen < 16 or mlen > MAX_MSG:
        raise ValueError("implausible message length - not MongoDB wire protocol")
    return opcode, _recv_n(sock, mlen - 16)


def _frame(opcode, body, req_id):
    return struct.pack("<iiii", 16 + len(body), req_id, 0, opcode) + body


def _op_msg_body(command):
    return struct.pack("<I", 0) + b"\x00" + _enc_doc(command)   # flags + kind0 doc


def _op_query_body(db, command):
    return (struct.pack("<i", 0) + _enc_cstr(db + ".$cmd")
            + struct.pack("<ii", 0, -1) + _enc_doc(command))


def _parse_op_msg(body):
    off = 4                                           # flagBits
    kind = body[off]
    off += 1
    if kind != 0:
        raise ValueError(f"unexpected OP_MSG section kind {kind}")
    doc, _ = _dec_doc(body, off)
    return doc


def _parse_op_reply(body):
    off = 4 + 8 + 4 + 4                                # flags+cursorId+from+count
    doc, _ = _dec_doc(body, off)
    return doc


def mongo_command(sock, req_id, command, use_query=False, db="admin"):
    if use_query:
        cmd = {k: v for k, v in command.items() if k != "$db"}
        sock.sendall(_frame(2004, _op_query_body(db, cmd), req_id))
    else:
        sock.sendall(_frame(2013, _op_msg_body(command), req_id))
    opcode, body = _recv_msg(sock)
    if opcode == 2013:
        return _parse_op_msg(body)
    if opcode == 1:                                   # OP_REPLY
        return _parse_op_reply(body)
    raise ValueError(f"unexpected wire opcode {opcode}")


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
    m = _SCHEME_RE.match(raw)
    if m:
        if m.group(1).lower() in ("mongodb+srv", "mongodbs"):
            tls = True                                # SRV connections imply TLS
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
# MongoDB probing (read-only)
# --------------------------------------------------------------------------- #

SYS_DBS = {"admin", "local", "config"}


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


def _preview(doc, nbytes):
    try:
        s = json.dumps(doc, default=str, ensure_ascii=False)
    except Exception:
        s = str(doc)
    if len(s) > nbytes:
        s = s[:nbytes] + "...[truncated]"
    return s


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

    state = {"req": 0, "query": False}

    def cmd(doc, db="admin"):
        ctx.limiter.wait()
        state["req"] += 1
        if ctx.v >= 2:
            ctx.debug(host, port, f"SEND {'OP_QUERY' if state['query'] else 'OP_MSG'} {doc}")
        rep = mongo_command(sock, state["req"], doc, use_query=state["query"], db=db)
        if ctx.v >= 2:
            ctx.debug(host, port, f"RECV ok={rep.get('ok')} keys={list(rep)[:6]}")
        return rep

    try:
        # 1) handshake: OP_MSG isMaster, fall back to OP_QUERY for old servers
        try:
            hello = cmd({"isMaster": 1, "$db": "admin"})
        except Exception as e:
            try:
                sock.close()
                sock = open_connection(host, port, tls, a.verify_tls, a.timeout,
                                       a.client_cert, a.client_key)
                state["query"] = True
                hello = cmd({"isMaster": 1, "$db": "admin"})
            except Exception as e2:
                r["status"] = "NOT-MONGO"
                r["detail"] = f"{type(e).__name__}/{type(e2).__name__}: {e2}"
                return r

        if not isinstance(hello, dict) or not any(
                k in hello for k in ("maxWireVersion", "ismaster",
                                     "isWritablePrimary", "ok")):
            r["status"] = "NOT-MONGO"
            r["detail"] = "no isMaster fields in reply"
            return r

        topo = []
        if hello.get("setName"):
            topo.append("rs:" + str(hello["setName"]))
        if hello.get("msg") == "isdbgrid":
            topo.append("mongos")
        if hello.get("ismaster") or hello.get("isWritablePrimary"):
            topo.append("primary")
        r["data"]["topology"] = ",".join(topo) or "standalone"
        r["data"]["wire"] = hello.get("maxWireVersion", "?")

        try:
            bi = cmd({"buildInfo": 1, "$db": "admin"})
            r["data"]["version"] = bi.get("version", "?")
        except Exception:
            r["data"]["version"] = "?"

        ver = r["data"]["version"]
        if ver == "?" and r["data"]["wire"] == "?":
            r["suspect"].append("no version/wire info")
        elif ver != "?" and not re.match(r"^\d+\.\d+", str(ver)):
            r["suspect"].append(f"implausible version '{ver}'")

        # 2) auth discrimination
        try:
            ld = cmd({"listDatabases": 1, "$db": "admin"})
        except Exception as e:
            r["status"] = "AUTH"
            r["detail"] = f"reachable, listDatabases failed: {e}"
            return r

        if not (ld.get("ok") == 1 and "databases" in ld):
            code = ld.get("code")
            msg = str(ld.get("errmsg", "") or code)
            r["status"] = "AUTH"
            low = msg.lower()
            if code == 13 or "auth" in low or "not authorized" in low:
                r["detail"] = f"auth required ({msg})"
            else:
                r["detail"] = f"restricted ({msg})"
            return r

        dbs = [(d.get("name"), d.get("sizeOnDisk")) for d in ld["databases"]]
        r["data"]["dbs"] = dbs
        r["data"]["total_dbs"] = len(dbs)

        # 3) read-only sampling (volume; documents only with --poc-value)
        nondata = [n for n, _ in dbs if n not in SYS_DBS]
        want = a.poc_keys if a.poc_value else 1
        coll_budget = max(want * 5, 20)
        seen_colls = 0
        poc_docs = []
        for dbname in nondata:
            if seen_colls >= coll_budget:
                break
            try:
                lc = cmd({"listCollections": 1, "nameOnly": True, "$db": dbname},
                         db=dbname)
            except Exception as e:
                ctx.debug(host, port, f"listCollections {dbname} failed: {e}")
                continue
            colls = [x.get("name") for x in
                     lc.get("cursor", {}).get("firstBatch", [])]
            for coll in colls:
                if not coll or coll.startswith("system."):
                    continue
                seen_colls += 1
                ns = f"{dbname}.{coll}"
                if "sample" not in r["data"]:
                    try:
                        cnt = cmd({"count": coll, "$db": dbname}, db=dbname)
                        n = cnt.get("n", "?")
                    except Exception:
                        n = "?"
                    r["data"]["sample"] = (ns, n)
                if a.poc_value and len(poc_docs) < want:
                    try:
                        fr = cmd({"find": coll, "limit": 1, "singleBatch": True,
                                  "$db": dbname}, db=dbname)
                        batch = fr.get("cursor", {}).get("firstBatch", [])
                        if batch:
                            poc_docs.append((ns, _preview(batch[0], a.poc_bytes)))
                    except Exception:
                        pass
                stop = (not a.poc_value and "sample" in r["data"]) or \
                       (a.poc_value and len(poc_docs) >= want)
                if stop or seen_colls >= coll_budget:
                    break
            if (not a.poc_value and "sample" in r["data"]) or \
               (a.poc_value and len(poc_docs) >= want):
                break

        if poc_docs:
            r["data"]["poc_docs"] = poc_docs
        r["status"] = "OPEN" if nondata else "OPEN-EMPTY"
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
    tls = " (TLS)" if r["tls"] else ""
    tgt = f"{r['host']}:{r['port']}{tls}"
    st = r["status"]

    if st in ("OPEN", "OPEN-EMPTY"):
        d = r["data"]
        ctx.emit(f"{c('[OPEN]', C.bold + C.green)} {c(tgt, C.green)}  "
                 f"v{d.get('version','?')} {d.get('topology','?')}  "
                 f"wire={d.get('wire','?')}  dbs={d.get('total_dbs',0)}")
        names = [f"{n}({_hsize(s)})" for n, s in d.get("dbs", []) if n not in SYS_DBS]
        if names:
            shown = ", ".join(names[:8]) + (" ..." if len(names) > 8 else "")
            ctx.emit(c(f"      user dbs: {shown}", C.cyan))
        if "sample" in d:
            ns, n = d["sample"]
            ctx.emit(c(f"      PoC: {ns} ~{n} docs", C.yellow))
        for i, (ns, prev) in enumerate(d.get("poc_docs", []), 1):
            ctx.emit(c(f"      PoC doc[{i}]: {ns} = {prev}", C.yellow))
        if r["suspect"]:
            ctx.emit(c("      ! possible honeypot: " + "; ".join(r["suspect"]), C.yellow))

        rec = (f"{tgt} status={st} version={d.get('version','?')} "
               f"topology={d.get('topology','?')} wire={d.get('wire','?')} "
               f"dbs={d.get('total_dbs',0)}")
        if names:
            rec += " user_dbs=" + "|".join(names)
        if "sample" in d:
            rec += f" sample={d['sample'][0]}:{d['sample'][1]}"
        for i, (ns, prev) in enumerate(d.get("poc_docs", []), 1):
            rec += f" poc_doc[{i}]={ns}:{prev!r}"
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
    elif st == "NOT-MONGO":
        ctx.emit(f"{c('[----]', C.grey)} {c(tgt, C.grey)}  not mongodb: {r['detail']}")
    else:
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

# A MongoDB instance is "found" (stop scanning this host's other ports) whether
# it is open, open-but-empty, or access-controlled.
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

# Common MongoDB ports (mongod / shard / config server / extra mongos).
EXTRA_PORTS = [27017, 27018, 27019, 27020]


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
        "targets: host | host:port | mongodb://host | mongodb+srv://host (TLS) -\n"
        "         any other scheme (http://, ftp://, ...) is stripped.\n"
        "ports:   a target with an explicit port is tried on that port only; else\n"
        "         the ports from -p and/or --extra-ports are tried in order (default\n"
        "         27017), and a host stops at the first port where MongoDB answers.\n"
        "read-only: only isMaster/buildInfo/listDatabases/listCollections/count are\n"
        "         sent, plus find(limit:1) with --poc-value. No write is ever sent.\n"
        "AUTHORIZED SCOPE ONLY."
    )
    p = argparse.ArgumentParser(
        prog="mongohunt.py",
        description="Detect exposed / unauthenticated MongoDB instances (read-only).",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-v", type=int, choices=[0, 1, 2], nargs="?", const=1, default=0,
                   help="verbosity: 0 = only successes (default), 1 = every test "
                        "performed, 2 = debug (full command sent, response ok/keys, "
                        "and steps skipped as filtered)")
    p.add_argument("-u", dest="url", help="single target to test")
    p.add_argument("-l", dest="list", help="file containing a list of targets to test")
    p.add_argument("-p", "--port", dest="port", default=None, metavar="PORTS",
                   help="port(s) to test for targets without an explicit port: comma "
                        "list, ranges like 27017-27020 allowed (only these are tested)")
    p.add_argument("--extra-ports", dest="extra_ports", action="store_true",
                   help="test the common MongoDB port set (27017,27018,27019,27020)")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured output (colour is on by default)")
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
                   help="read document(s) as PoC (off by default; see --poc-keys/--poc-bytes)")
    p.add_argument("--poc-keys", dest="poc_keys", type=int, default=5, metavar="N",
                   help="number of documents (one per collection) to read for the PoC "
                        "when --poc-value is set (default 5)")
    p.add_argument("--poc-bytes", dest="poc_bytes", type=int, default=120, metavar="N",
                   help="truncate each PoC document preview to N bytes (default 120)")
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
        host, exp_port, scheme_tls = parse_target(raw)
        tls = scheme_tls or args.force_tls
        if exp_port is not None:
            ports = [exp_port]
        else:
            ports = ports_p + ports_extra
            seen = set()
            ports = [p for p in ports if not (p in seen or seen.add(p))]
            if not ports:
                ports = [27017]
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

    sys.stderr.write(c(f"\n\tmongohunt: {ctx.total} target(s), {args.threads} thread(s), "
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
