#!/usr/bin/env python3
"""
epfinder.py - Endpoint discovery orchestrator.

Aggregates several already-installed tools into one deduplicated, in-scope list
of endpoints for a host:

  * Passive  (ALWAYS ON)  : gau / gauplus + waybackurls  (archives, no traffic
                            to the target beyond what the archives hold)
  * Crawl    (--no-crawl) : katana  (same-origin spider, JS-aware)
  * JS       (--no-js)    : jsluice  (endpoints extracted from discovered .js)

No brute force. The passive stage cannot be disabled.

Everything is time-boxed: each tool gets --timeout-per-tool, and the whole scan
of one host is capped by --max-time; independent tools run in parallel, and a
tool that overruns is killed while keeping whatever it already printed.

Output: unique, normalised, in-scope URLs (stdout and/or -o). Feed it straight
to your scanners with -l.

Requires the tools on PATH (missing ones are skipped with a warning). Python
stdlib only for the orchestration itself.

For authorized testing only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser  # noqa: F401 (kept for future HTML parsing)

VERSION = "1.0.0"

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

STATIC_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".mp4", ".webm", ".mp3", ".wav", ".avi", ".mov", ".pdf",
}

JS_FETCH_CAP = 40          # max .js files handed to jsluice
MAX_BODY = 3 * 1024 * 1024


# ----------------------------------------------------------------------------
# Colour / status / output
# ----------------------------------------------------------------------------

class Colors:
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; GREY = "\033[90m"
    BOLD = "\033[1m"; RESET = "\033[0m"
    _A = ("RED", "GREEN", "YELLOW", "BLUE", "CYAN", "GREY", "BOLD", "RESET")

    @classmethod
    def disable(cls):
        for a in cls._A:
            setattr(cls, a, "")


class Reporter:
    def __init__(self, level=0):
        self.level = level
        self.lock = threading.Lock()

    def _emit(self, s):
        with self.lock:
            sys.stderr.write(s + "\n")
            sys.stderr.flush()

    def line(self, s):
        self._emit(s)

    def info(self, s):
        if self.level >= 1:
            self._emit(f"{Colors.BLUE}[info]{Colors.RESET} {s}")

    def debug(self, s):
        if self.level >= 2:
            self._emit(f"{Colors.GREY}[dbg ]{Colors.RESET} {s}")

    def warn(self, s):
        self._emit(f"{Colors.YELLOW}[warn]{Colors.RESET} {s}")

    def error(self, s):
        self._emit(f"{Colors.RED}[err ]{Colors.RESET} {s}")

    def banner(self, s):
        if self.level >= 1:
            self._emit(f"{Colors.BOLD}{Colors.BLUE}=== {s} ==={Colors.RESET}")


class Status:
    """Turquoise heartbeat, list mode only."""
    def __init__(self, reporter, total, interval=30.0, enabled=True):
        self.rep = reporter; self.total = total; self.interval = interval
        self.enabled = enabled; self.done = 0; self.found = 0
        self._lk = threading.Lock(); self._stop = threading.Event()
        self._thread = None; self._t0 = 0.0

    def start(self):
        if not self.enabled:
            return
        self._t0 = time.time()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.wait(self.interval):
            self.emit()

    def host_done(self, found=0):
        with self._lk:
            self.done += 1; self.found += found

    def emit(self, label="status"):
        if not self.enabled:
            return
        with self._lk:
            done, found = self.done, self.found
        rem = max(0, self.total - done)
        el = int(time.time() - self._t0)
        c = Colors
        self.rep.line(f"{c.CYAN}[{label} {el // 60:02d}:{el % 60:02d}]  "
                      f"tested {done}/{self.total}  remaining {rem}  "
                      f"|  endpoints {found}{c.RESET}")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)


# ----------------------------------------------------------------------------
# Subprocess helper (time-boxed, keeps partial output on timeout)
# ----------------------------------------------------------------------------

def run_tool(cmd, rep, timeout, stdin_text=None, env_extra=None):
    """Run cmd, return stdout (partial if it had to be killed on timeout)."""
    if timeout <= 0:
        rep.debug(f"skip (no time budget left): {' '.join(cmd)}")
        return ""
    rep.debug(f"run ({timeout:.0f}s): {' '.join(cmd)}")
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    # start_new_session=True puts the tool in its own process group, so on a
    # timeout we can kill the WHOLE group - the tool plus any child it spawned.
    # Killing only the direct process leaves grandchildren holding the stdout
    # pipe open, which makes the follow-up communicate() block until they exit.
    try:
        p = subprocess.Popen(
            cmd, stdin=subprocess.PIPE if stdin_text is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env,
            start_new_session=True)
    except (OSError, ValueError) as e:
        rep.warn(f"cannot launch {cmd[0]}: {e}")
        return ""
    try:
        out, _ = p.communicate(input=stdin_text, timeout=timeout)
        return out or ""
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            p.kill()
        try:
            out, _ = p.communicate(timeout=5)
        except Exception:
            out = ""
        rep.debug(f"  timed out, killed {cmd[0]} (kept partial output)")
        return out or ""


# ----------------------------------------------------------------------------
# URL helpers
# ----------------------------------------------------------------------------

def normalize(u):
    u = (u or "").strip().strip('"').strip("'")
    if not u:
        return None
    if u.startswith("//"):
        u = "https:" + u
    if not re.match(r"https?://", u, re.I):
        return None
    try:
        p = urllib.parse.urlsplit(u)
    except ValueError:
        return None
    if not p.netloc:
        return None
    path = p.path or "/"
    return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), path,
                                    p.query, ""))  # drop fragment


def host_of(u):
    return urllib.parse.urlsplit(u).netloc.split("@")[-1].split(":")[0].lower()


def in_scope(u, roots, include_subs):
    h = host_of(u)
    for r in roots:
        if h == r or (include_subs and h.endswith("." + r)):
            return True
    return False


def is_static(u):
    path = urllib.parse.urlsplit(u).path.lower()
    ext = os.path.splitext(path)[1]
    return ext in STATIC_EXT


def dedupe_params(urls):
    """Collapse URLs sharing (path, set of param names) to one representative."""
    seen, out = set(), []
    for u in urls:
        p = urllib.parse.urlsplit(u)
        keys = tuple(sorted(k for k, _ in
                            urllib.parse.parse_qsl(p.query, keep_blank_values=True)))
        key = (p.scheme, p.netloc, p.path, keys)
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out


# ----------------------------------------------------------------------------
# HTTP (for fetching JS before jsluice) - TLS verification disabled
# ----------------------------------------------------------------------------

def make_opener(proxy):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(*handlers)


def fetch(opener, url, headers, timeout):
    req = urllib.request.Request(url)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.read(MAX_BODY).decode("utf-8", errors="replace")
    except Exception:
        return ""


# ----------------------------------------------------------------------------
# Tool stages
# ----------------------------------------------------------------------------

class Discoverer:
    def __init__(self, args, rep):
        self.args = args
        self.rep = rep
        self.headers = {"User-Agent": DEFAULT_UA}
        for h in args.header or []:
            if ":" in h:
                k, _, v = h.partition(":")
                self.headers[k.strip()] = v.strip()
        self.have = {t: shutil.which(t) for t in
                     ("gau", "gauplus", "waybackurls", "katana", "hakrawler", "jsluice")}
        self.gau_bin = "gau" if self.have["gau"] else ("gauplus" if self.have["gauplus"] else None)

    # -- individual tools ----------------------------------------------------

    def _gau(self, domain, timeout):
        cmd = [self.gau_bin, "--threads", str(self.args.threads)]
        if self.args.include_subdomains:
            cmd.append("--subs")
        if self.args.proxy:
            cmd += ["--proxy", self.args.proxy]
        cmd.append(domain)
        return run_tool(cmd, self.rep, timeout)

    def _waybackurls(self, domain, timeout):
        return run_tool(["waybackurls"], self.rep, timeout, stdin_text=domain + "\n")

    def _katana(self, url, timeout):
        ct = max(5, int(min(timeout, self.args.timeout_per_tool)))
        cmd = ["katana", "-u", url, "-silent", "-jc",
               "-d", str(self.args.depth), "-ct", str(ct),
               "-timeout", "10"]
        # rdn = whole registered domain (lets it roam sub-domains); fqdn = strict
        # same host. Our in_scope() filter is authoritative either way.
        cmd += ["-fs", "rdn" if self.args.include_subdomains else "fqdn"]
        if self.args.proxy:
            cmd += ["-proxy", self.args.proxy]
        for h in self.args.header or []:
            cmd += ["-H", h]
        return run_tool(cmd, self.rep, timeout)

    def _hakrawler(self, url, timeout):
        cmd = ["hakrawler", "-u", "-d", str(self.args.depth),
               "-t", str(self.args.threads), "-insecure"]
        if self.args.include_subdomains:
            cmd.append("-subs")
        if self.args.header:
            # hakrawler takes all custom headers in one -h, joined by ';;'
            cmd += ["-h", ";;".join(self.args.header)]
        return run_tool(cmd, self.rep, timeout, stdin_text=url + "\n")

    def _jsluice(self, js_file, timeout):
        return run_tool(["jsluice", "urls", js_file], self.rep, timeout)

    # -- parsing -------------------------------------------------------------

    @staticmethod
    def _lines_to_urls(text):
        for ln in text.splitlines():
            ln = ln.strip()
            if ln:
                yield ln

    def _parse_jsluice(self, text, base):
        """jsluice urls emits one JSON object per line with a 'url' field."""
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
                u = obj.get("url") or obj.get("URL")
            except (ValueError, AttributeError):
                u = ln
            if not u:
                continue
            yield urllib.parse.urljoin(base, u)

    # -- orchestration for one host -----------------------------------------

    def discover(self, url, deadline):
        roots = [host_of(url)]
        domain = roots[0]
        found = set()
        rep = self.rep

        def remaining():
            return max(0.0, deadline - time.time())

        def add(raw_urls):
            for u in raw_urls:
                n = normalize(u)
                if n and in_scope(n, roots, self.args.include_subdomains):
                    found.add(n)

        # -- wave 1 : passive (always) + crawl (optional), in parallel -------
        jobs = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            if self.gau_bin:
                jobs[ex.submit(self._gau, domain,
                               min(self.args.timeout_per_tool, remaining()))] = "gau"
            else:
                rep.warn("gau/gauplus not found - passive (gau) skipped")
            if self.have["waybackurls"]:
                jobs[ex.submit(self._waybackurls, domain,
                               min(self.args.timeout_per_tool, remaining()))] = "wayback"
            else:
                rep.warn("waybackurls not found - passive (wayback) skipped")
            if not self.args.no_crawl:
                if self.have["katana"]:
                    jobs[ex.submit(self._katana, url,
                                   min(self.args.timeout_per_tool, remaining()))] = "katana"
                else:
                    rep.warn("katana not found - crawl (katana) skipped")
                if self.have["hakrawler"]:
                    jobs[ex.submit(self._hakrawler, url,
                                   min(self.args.timeout_per_tool, remaining()))] = "hakrawler"
                else:
                    rep.warn("hakrawler not found - crawl (hakrawler) skipped")

            for fut in concurrent.futures.as_completed(jobs):
                name = jobs[fut]
                try:
                    text = fut.result()
                except Exception as e:
                    rep.warn(f"{name} failed: {e}")
                    continue
                before = len(found)
                add(self._lines_to_urls(text))
                rep.info(f"  {name}: +{len(found) - before} in-scope "
                         f"(total {len(found)})")

        # -- wave 2 : JS extraction with jsluice (optional) ------------------
        if not self.args.no_js and self.have["jsluice"] and remaining() > 0:
            js_urls = [u for u in found if urllib.parse.urlsplit(u).path.lower()
                       .endswith(".js")][:JS_FETCH_CAP]
            if js_urls:
                rep.info(f"  js: {len(js_urls)} script(s) -> jsluice")
                opener = make_opener(self.args.proxy)
                import tempfile
                before = len(found)
                with concurrent.futures.ThreadPoolExecutor(
                        max_workers=self.args.threads) as ex:
                    def do_js(ju):
                        if remaining() <= 0:
                            return
                        body = fetch(opener, ju, self.headers, 10)
                        if not body:
                            return
                        with tempfile.NamedTemporaryFile("w", suffix=".js",
                                                         delete=False) as tf:
                            tf.write(body); path = tf.name
                        try:
                            out = self._jsluice(path, min(20, remaining()))
                        finally:
                            try:
                                os.unlink(path)
                            except OSError:
                                pass
                        add(self._parse_jsluice(out, ju))
                    list(ex.map(do_js, js_urls))
                rep.info(f"  js: +{len(found) - before} in-scope (total {len(found)})")
        elif not self.args.no_js and not self.have["jsluice"]:
            rep.warn("jsluice not found - JS extraction skipped")

        return found


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def normalize_target(u):
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u


def load_lines(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [normalize_target(l.strip()) for l in fh
                if l.strip() and not l.startswith("#")]


def build_parser():
    p = argparse.ArgumentParser(
        prog="epfinder.py",
        description="Endpoint discovery orchestrator (passive always on, "
                    "no brute force).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  epfinder.py -u https://target                 # writes target.txt
  epfinder.py -u https://target --no-js --max-time 120
  epfinder.py -l hosts.txt                      # one <host>.txt per host
  epfinder.py -l hosts.txt -o all.txt -t 10     # everything in one file
  epfinder.py -u https://target -o - --dedupe | tee urls.txt   # stdout -> scanner

Passive (gau + waybackurls) always runs and cannot be disabled.
Scope: endpoints are kept only for the tested host; --include-subdomains also
keeps its sub-domains. Use only against authorized targets.""")
    p.add_argument("-v", dest="verbose", type=int, nargs="?", const=1, default=0,
                   choices=[0, 1, 2], help="verbosity (0/1/2)")
    p.add_argument("-u", dest="url", help="single host/URL")
    p.add_argument("-l", dest="list", help="file of hosts/URLs, one per line")
    p.add_argument("-o", "--output",
                   help="write ALL hosts' endpoints to this single file "
                        "('-' = stdout). Default: one file per host, <host>.txt")
    p.add_argument("-t", "--threads", type=int, default=5,
                   help="concurrency for hosts and JS fetch (default 5)")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="extra header 'Name: value' (repeatable, passed to katana "
                        "and JS fetch)")
    p.add_argument("-p", "--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--no-crawl", action="store_true", help="skip katana crawl")
    p.add_argument("--no-js", action="store_true", help="skip jsluice JS extraction")
    p.add_argument("--timeout-per-tool", type=float, default=120.0, metavar="SEC",
                   help="max seconds for each tool (default 120)")
    p.add_argument("--max-time", type=float, default=300.0, metavar="SEC",
                   help="max seconds spent per host, all stages (default 300)")
    p.add_argument("--depth", type=int, default=2,
                   help="katana crawl depth (default 2)")
    p.add_argument("--include-subdomains", action="store_true",
                   help="keep endpoints on sub-domains of the target too")
    p.add_argument("--no-static", action="store_true",
                   help="strip static assets (css/img/fonts/media); kept by default")
    p.add_argument("--dedupe", action="store_true",
                   help="collapse URLs sharing the same path + parameter names")
    p.add_argument("--status-interval", type=float, default=30.0, metavar="SEC",
                   help="seconds between status lines in -l mode (default 30)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_color or os.environ.get("NO_COLOR"):
        Colors.disable()
    if not args.url and not args.list:
        build_parser().print_help()
        return 2

    targets = []
    if args.url:
        targets.append(normalize_target(args.url))
    if args.list:
        if not os.path.isfile(args.list):
            print(f"error: no such file: {args.list}", file=sys.stderr)
            return 2
        targets.extend(load_lines(args.list))
    targets = list(dict.fromkeys(targets))
    if not targets:
        print("error: no targets", file=sys.stderr)
        return 2

    rep = Reporter(args.verbose)
    disc = Discoverer(args, rep)
    present = [t for t, path in disc.have.items() if path]
    rep.info(f"epfinder {VERSION} - tools present: {', '.join(present) or 'none'}")
    if not disc.gau_bin and not disc.have["waybackurls"]:
        rep.warn("no passive tool available (gau/gauplus/waybackurls) - results "
                 "will be limited to crawl/js")

    status = Status(rep, len(targets), interval=args.status_interval,
                    enabled=bool(args.list))

    host_results = {}          # host -> set of endpoints
    all_lock = threading.Lock()

    def one(t):
        rep.banner(f"{t}")
        deadline = time.time() + args.max_time
        try:
            urls = disc.discover(t, deadline)
        except Exception as e:
            rep.error(f"{t}: {e}")
            urls = set()
        with all_lock:
            host_results.setdefault(host_of(t), set()).update(urls)
        status.host_done(found=len(urls))
        return len(urls)

    started = time.time()
    status.start()
    try:
        if args.threads > 1 and len(targets) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
                list(ex.map(one, targets))
        else:
            for t in targets:
                one(t)
    except KeyboardInterrupt:
        rep.error("interrupted by user")
    finally:
        status.stop()
        status.emit(label="final")

    # -- post-processing + output -------------------------------------------
    def finalize(s):
        urls = sorted(s)
        if args.no_static:
            urls = [u for u in urls if not is_static(u)]
        if args.dedupe:
            urls = dedupe_params(urls)
        return urls

    def safe_name(host):
        return re.sub(r"[^A-Za-z0-9._-]", "_", host) or "host"

    total = 0
    if args.output == "-":                       # everything to stdout
        union = set().union(*host_results.values()) if host_results else set()
        for u in finalize(union):
            print(u); total += 1
    elif args.output:                            # everything to one file
        union = set().union(*host_results.values()) if host_results else set()
        urls = finalize(union)
        total = len(urls)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write("\n".join(urls) + ("\n" if urls else ""))
        rep.line(f"{Colors.GREY}  -> {args.output} ({total}){Colors.RESET}")
    else:                                         # one file per host (default)
        for host in sorted(host_results):
            urls = finalize(host_results[host])
            total += len(urls)
            fname = safe_name(host) + ".txt"
            with open(fname, "w", encoding="utf-8") as fh:
                fh.write("\n".join(urls) + ("\n" if urls else ""))
            rep.line(f"{Colors.GREY}  -> {fname} ({len(urls)}){Colors.RESET}")

    rep.line(f"{Colors.GREEN}{Colors.BOLD}[done]{Colors.RESET} "
             f"{total} endpoints from {len(targets)} target(s) in "
             f"{time.time() - started:.1f}s")
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())
