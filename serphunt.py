#!/usr/bin/env python3
"""
serphunt — search engine querying for recon.

Runs one query across several engines and collects the result URLs. Engines
disagree about what they index, so the union of a handful is materially larger
than any one of them; that is the whole reason this queries more than one.

The thing that makes a scraper like this worth trusting is knowing when it
FAILED rather than when it found nothing. A CAPTCHA page, a consent wall or a
429 all parse to zero results, and a tool that reports "0 results" for those is
lying to you. Every engine here is checked for block signatures, and a blocked
engine is reported as blocked -- loudly, and separately from a genuine empty
result set.

Engine reliability, honestly stated (see --list-engines):
  reliable    duckduckgo, mojeek, marginalia, brave, ecosia
  flaky       bing, yahoo, qwant, startpage
  usually blocked   google  -- serves a consent wall or /sorry/ to
                    non-browser clients; kept because it occasionally works
                    from a residential IP, not because it is dependable

For authorized use. Respect robots, terms and rate limits of the services you
query; the default delay exists for that reason.
"""

from __future__ import annotations

import argparse
import html as htmllib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import (quote_plus, urlsplit, parse_qs, unquote, urljoin)

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] pip install requests")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

ACCEPT_HTML = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,*/*;q=0.8")


# ----------------------------------------------------------------------------
# colour
# ----------------------------------------------------------------------------

ANSI = {
    "ok": "\033[1;92m", "warn": "\033[0;93m", "bad": "\033[0;91m",
    "dim": "\033[0;90m", "b": "\033[1m", "head": "\033[1;36m",
    "url": "\033[0;96m", "x": "\033[0m",
}
_COLOR = True


def set_color(enabled):
    global _COLOR
    _COLOR = enabled


def paint(s, key):
    return s if not _COLOR else f"{ANSI.get(key, '')}{s}{ANSI['x']}"


# ----------------------------------------------------------------------------
# console
# ----------------------------------------------------------------------------

class Console:
    """
    Verbosity is exactly as specified:
      0  URLs only -- nothing else on stdout, so the output pipes cleanly
      1  + which engine is being queried, and its outcome
      2  + every HTTP request performed
    """

    def __init__(self, verbosity=0):
        self.v = verbosity

    def url(self, u):
        print(paint(u, "url"), flush=True)

    def engine(self, s):
        if self.v >= 1:
            print(paint(f"[engine] {s}", "head"), file=sys.stderr, flush=True)

    def request(self, s):
        if self.v >= 2:
            print(paint(f"  [req] {s}", "dim"), file=sys.stderr, flush=True)

    def note(self, s):
        if self.v >= 1:
            print(paint(f"  {s}", "dim"), file=sys.stderr, flush=True)

    def warn(self, s):
        # A blocked engine is never silent: it changes what the results mean.
        print(paint(f"  [!] {s}", "warn"), file=sys.stderr, flush=True)

    def error(self, s):
        print(paint(f"  [err] {s}", "bad"), file=sys.stderr, flush=True)


# ----------------------------------------------------------------------------
# engines
# ----------------------------------------------------------------------------

# Hosts that are never a real result: the engine's own furniture, plus the
# usual redirectors and social chrome.
JUNK_HOSTS = re.compile(
    r"(?:^|\.)(?:google\.[a-z.]+|gstatic\.com|googleusercontent\.com|"
    r"bing\.com|microsoft\.com|msn\.com|yahoo\.com|yimg\.com|"
    r"duckduckgo\.com|qwant\.com|brave\.com|mojeek\.com|ecosia\.org|"
    r"startpage\.com|marginalia\.nu|marginalia-search\.com|searx\.be|"
    r"w3\.org|schema\.org)$",
    re.I)

BLOCK_SIGNS = re.compile(
    r"(?i)(unusual traffic|/sorry/index|captcha|are you a robot|"
    r"verify you are human|challenge-platform|consent\.(?:google|yahoo)|"
    r"before you continue|enable javascript to continue|"
    r"access denied|too many requests|rate ?limit)")


@dataclass
class EngineResult:
    name: str
    urls: list = field(default_factory=list)
    blocked: bool = False
    error: str = ""
    pages: int = 0
    # 200 OK, no block signature, and still nothing extractable. Distinct from
    # blocked and from a genuinely empty result set: it means the page was
    # served but could not be read -- JS rendering or a layout change.
    unparsed: bool = False


class Engine:
    name = "base"
    reliable = "reliable"
    json_api = False
    # Hosts that are this engine's own page furniture: nav, footer, licence
    # and "about" links. They are not results, and an engine whose result set
    # is empty otherwise emits nothing but these -- which is exactly how a
    # scraper ends up reporting a footer as a finding.
    chrome: tuple = ()

    def page_url(self, query: str, page: int) -> str:
        raise NotImplementedError

    def headers(self) -> dict:
        return {}

    def extract(self, body: str) -> list:
        raise NotImplementedError

    def _not_chrome(self, u: str) -> bool:
        host = urlsplit(u).netloc.split("@")[-1].split(":")[0].lower()
        return not any(host == c or host.endswith("." + c) for c in self.chrome)

    def _generic(self, body: str) -> list:
        """Fallback extraction: every external href that is not furniture."""
        return [u for u in (self._clean(h) for h in self._hrefs(body))
                if self._keep(u) and self._not_chrome(u)]

    # -- helpers shared by the HTML engines

    @staticmethod
    def _clean(u: str) -> str:
        u = htmllib.unescape(u or "").strip()
        if u.startswith("//"):
            u = "https:" + u
        # Unescaping turns a trailing &quot; into a literal quote inside the
        # URL, producing junk like "https://host/\"" that looks like a distinct
        # result and is not one. The percent-encoded form does the same.
        u = u.rstrip("\"'")
        while u.endswith(("%22", "%27")):
            u = u[:-3]
        return u.rstrip("\"'")

    @staticmethod
    def _keep(u: str) -> bool:
        if not u.startswith(("http://", "https://")):
            return False
        # A well-formed URL never contains raw quotes, angle brackets or
        # whitespace: anything that does is a parsing artefact, not a result.
        if re.search(r"[\"'<>\s]", u):
            return False
        host = urlsplit(u).netloc.split("@")[-1].split(":")[0]
        if not host or "." not in host:
            return False
        return not JUNK_HOSTS.search(host)

    @classmethod
    def _hrefs(cls, body: str) -> list:
        return re.findall(r'href="([^"]+)"', body or "", re.I)


class Google(Engine):
    name = "google"
    # Measured, not assumed: the /search response is a 200 of ~90KB whose only
    # external href is support.google.com. Results are rendered client-side, so
    # there is nothing to scrape even when it does not challenge you.
    reliable = "js-rendered, unscrapeable"

    def page_url(self, q, page):
        return (f"https://www.google.com/search?q={quote_plus(q)}"
                f"&num=20&start={page * 20}&hl=en")

    def extract(self, body):
        out = []
        # classic redirector, still emitted in the no-JS layout
        for m in re.findall(r'/url\?q=([^&"]+)', body or ""):
            u = self._clean(unquote(m))
            if self._keep(u):
                out.append(u)
        if out:
            return out
        for h in self._hrefs(body):
            u = self._clean(h)
            if self._keep(u):
                out.append(u)
        return out


class Bing(Engine):
    name = "bing"
    reliable = "flaky"

    def page_url(self, q, page):
        return (f"https://www.bing.com/search?q={quote_plus(q)}"
                f"&count=30&first={page * 30 + 1}&setlang=en")

    def extract(self, body):
        out = []
        for h in self._hrefs(body):
            u = self._clean(h)
            # bing wraps results: /ck/a?...&u=a1<base64url>
            if "bing.com/ck/a" in u or u.startswith("/ck/a"):
                qs = parse_qs(urlsplit(u).query)
                raw = (qs.get("u") or [""])[0]
                if raw.startswith("a1"):
                    import base64
                    s = raw[2:]
                    try:
                        u = base64.urlsafe_b64decode(
                            s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
                    except Exception:
                        continue
                else:
                    continue
            if self._keep(u):
                out.append(u)
        return out


class Yahoo(Engine):
    name = "yahoo"
    reliable = "flaky"

    def page_url(self, q, page):
        return (f"https://search.yahoo.com/search?p={quote_plus(q)}"
                f"&n=30&b={page * 30 + 1}")

    def extract(self, body):
        out = []
        for h in self._hrefs(body):
            u = self._clean(h)
            # yahoo wraps in r.search.yahoo.com/...;_ylu=.../RU=<enc>/RK=...
            m = re.search(r"/RU=([^/]+)/", u)
            if m:
                u = self._clean(unquote(m.group(1)))
            if self._keep(u):
                out.append(u)
        return out


class DuckDuckGo(Engine):
    name = "duckduckgo"
    reliable = "reliable"

    def page_url(self, q, page):
        # the html endpoint is the scrape-friendly one; s= is the offset
        return (f"https://html.duckduckgo.com/html/?q={quote_plus(q)}"
                f"&s={page * 30}")

    def extract(self, body):
        out = []
        for h in self._hrefs(body):
            u = self._clean(h)
            if "duckduckgo.com/l/" in u or u.startswith("/l/"):
                qs = parse_qs(urlsplit(u).query)
                raw = (qs.get("uddg") or [""])[0]
                if not raw:
                    continue
                u = self._clean(unquote(raw))
            if self._keep(u):
                out.append(u)
        return out


class Qwant(Engine):
    name = "qwant"
    reliable = "flaky"
    json_api = True

    def page_url(self, q, page):
        return (f"https://api.qwant.com/v3/search/web?q={quote_plus(q)}"
                f"&count=10&locale=en_GB&offset={page * 10}"
                f"&device=desktop&safesearch=0")

    def headers(self):
        return {"Accept": "application/json"}

    def extract(self, body):
        out = []
        try:
            data = json.loads(body)
        except Exception:
            return out

        def walk(node):
            if isinstance(node, dict):
                u = node.get("url")
                if isinstance(u, str) and self._keep(u):
                    out.append(u)
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
        walk(data)
        return out


class Brave(Engine):
    name = "brave"
    reliable = "reliable"

    def page_url(self, q, page):
        return (f"https://search.brave.com/search?q={quote_plus(q)}"
                f"&offset={page}")

    def extract(self, body):
        return self._generic(body)


class Mojeek(Engine):
    name = "mojeek"
    reliable = "reliable"

    def page_url(self, q, page):
        return (f"https://www.mojeek.com/search?q={quote_plus(q)}"
                f"&s={page * 10}")

    def extract(self, body):
        return self._generic(body)


class Ecosia(Engine):
    name = "ecosia"
    reliable = "reliable"

    def page_url(self, q, page):
        return (f"https://www.ecosia.org/search?q={quote_plus(q)}"
                f"&p={page}")

    def extract(self, body):
        return self._generic(body)


class Startpage(Engine):
    name = "startpage"
    reliable = "flaky"

    def page_url(self, q, page):
        return (f"https://www.startpage.com/sp/search?query={quote_plus(q)}"
                f"&page={page + 1}")

    def extract(self, body):
        return self._generic(body)


class Marginalia(Engine):
    name = "marginalia"
    reliable = "reliable"
    chrome = ("marginalia-search.com", "marginalia.nu", "github.com",
              "creativecommons.org", "lite.ip2location.com")

    def page_url(self, q, page):
        return (f"https://marginalia-search.com/search?query={quote_plus(q)}"
                f"&index=0&page={page + 1}")

    def extract(self, body):
        return self._generic(body)


class Searx(Engine):

    """Public SearXNG instance -- itself a metasearch, so it is a useful
    backstop when the direct engines are blocking."""
    name = "searx"
    reliable = "flaky"

    def page_url(self, q, page):
        return (f"https://searx.be/search?q={quote_plus(q)}"
                f"&pageno={page + 1}")

    def extract(self, body):
        return self._generic(body)


ENGINES = {e.name: e for e in (
    Google, Bing, Yahoo, DuckDuckGo, Qwant, Brave, Mojeek, Ecosia,
    Startpage, Marginalia, Searx)}


# ----------------------------------------------------------------------------
# runner
# ----------------------------------------------------------------------------

class Serp:
    def __init__(self, con: Console, args):
        self.con = con
        self.args = args
        self.session = requests.Session()
        self.proxies = ({"http": args.proxy, "https": args.proxy}
                        if args.proxy else None)
        self.extra = {}
        for h in args.header or []:
            if ":" in h:
                k, _, v = h.partition(":")
                self.extra[k.strip()] = v.strip()
        self.seen = set()
        self.results: list[EngineResult] = []

    def fetch(self, url, engine: Engine):
        h = {"User-Agent": self.args.user_agent or UA,
             "Accept": ACCEPT_HTML,
             "Accept-Language": "en-US,en;q=0.9"}
        h.update(engine.headers())
        h.update(self.extra)
        self.con.request(f"GET {url}")
        try:
            r = self.session.get(url, headers=h, timeout=self.args.timeout,
                                 proxies=self.proxies, verify=False,
                                 allow_redirects=True)
            return r.status_code, r.text
        except requests.RequestException as e:
            return 0, f"__error__{e}"

    def run_engine(self, cls) -> EngineResult:
        eng = cls()
        res = EngineResult(name=eng.name)
        self.con.engine(f"{eng.name}  ({eng.reliable})")
        for page in range(self.args.pages):
            if page:
                time.sleep(self.args.delay)
            url = eng.page_url(self.args.query, page)
            status, body = self.fetch(url, eng)

            if body.startswith("__error__"):
                res.error = body[9:][:80]
                self.con.error(f"{eng.name}: {res.error}")
                break
            # scan the WHOLE body: consent walls and challenge scripts often
            # sit well past the first few KB, and truncating the scan turns a
            # block into a silent "0 results"
            # 202 is not a success here: DuckDuckGo returns "202 Accepted" with
            # an empty result shell as its soft rate-limit, and treating it as
            # a normal response reports a throttle as "no results".
            if status in (202, 401, 403, 429) or BLOCK_SIGNS.search(body):
                res.blocked = True
                self.con.warn(f"{eng.name}: blocked (HTTP {status}) — results "
                              f"from this engine are missing, not empty")
                break
            if status >= 400:
                res.error = f"HTTP {status}"
                self.con.error(f"{eng.name}: HTTP {status}")
                break

            found = eng.extract(body)
            res.pages += 1
            new = 0
            for u in found:
                u = u.split("#")[0].rstrip("/")
                if u in self.seen:
                    continue
                self.seen.add(u)
                res.urls.append(u)
                new += 1
                self.con.url(u)
            self.con.note(f"page {page + 1}: {len(found)} link(s), {new} new")
            if not found:
                # Nothing extractable from a page that was served normally.
                # Saying "0 results" here would be a guess presented as a fact.
                if page == 0:
                    res.unparsed = True
                    self.con.warn(
                        f"{eng.name}: HTTP {status}, no block signature, but "
                        f"nothing parseable — JS-rendered, layout changed, or "
                        f"genuinely no matches. Treat as UNKNOWN, not zero.")
                break
            time.sleep(self.args.delay)
        if not (res.blocked or res.error or res.unparsed):
            self.con.note(f"{eng.name}: {len(res.urls)} unique URL(s)")
        return res

    def run(self):
        for cls in self.selected():
            self.results.append(self.run_engine(cls))
        return self.results

    def selected(self):
        if self.args.engine.lower() == "all":
            return list(ENGINES.values())
        out = []
        for n in self.args.engine.split(","):
            n = n.strip().lower()
            if not n:
                continue
            if n not in ENGINES:
                self.con.error(f"unknown engine: {n}  "
                               f"(see --list-engines)")
                continue
            out.append(ENGINES[n])
        return out


# ----------------------------------------------------------------------------
# cli
# ----------------------------------------------------------------------------

BANNER = r"""
  serphunt — multi-engine search collection
"""

EPILOG = """
verbosity
  -v 0   URLs only, one per line, nothing else on stdout (default)
  -v 1   + which engine is running and what it returned
  -v 2   + every HTTP request performed

  Diagnostics go to stderr, results to stdout, so `-v 2 > urls.txt` still
  yields a clean file.

blocked is not empty
  A CAPTCHA, a consent wall and a 429 all parse to zero results. Reporting
  those as "no results" would be a lie, so every engine response is checked for
  block signatures and a blocked engine is called out explicitly. If half your
  engines were blocked, the union you got is not the union you asked for.

engines
  Reliability varies and is stated up front (--list-engines). Google in
  particular serves a consent wall or /sorry/ to non-browser clients and will
  usually contribute nothing; it is included because it occasionally works from
  a residential IP, not because it can be relied on.

  Results are deduplicated across engines, so querying all of them costs
  requests but never duplicates output.

politeness
  --delay (default 2s) applies between every request, including between pages
  of the same engine. Lowering it raises the odds of being blocked, which
  reduces results rather than increasing them.

examples
  serphunt.py -q 'site:sephora.fr inurl:admin'
  serphunt.py -q 'site:*.sephora.fr ext:pdf' -e duckduckgo,mojeek -o pdfs.txt
  serphunt.py -q 'intitle:"index of" sephora' -v 1 --pages 3
  serphunt.py -q 'site:sephora.fr' --no-banner -v 0 -o urls.txt
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="serphunt.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", type=int, default=0, choices=[0, 1, 2],
                   dest="verbosity",
                   help="0 = URLs only (default), 1 = engine in use, "
                        "2 = requests performed")
    p.add_argument("-q", "--query", help="search query")
    p.add_argument("-o", "--output", help="write unique URLs to this file")
    p.add_argument("-e", "--engine", default="all", metavar="LIST",
                   help="comma-separated engines, or 'all' (default): "
                        + ", ".join(ENGINES))
    p.add_argument("--list-engines", action="store_true",
                   help="show engines and their reliability, then exit")
    p.add_argument("--no-banner", action="store_true",
                   help="suppress the banner and option summary")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured output (colour is on by default)")
    p.add_argument("--pages", type=int, default=2, metavar="N",
                   help="result pages per engine (default 2)")
    p.add_argument("-d", "--delay", type=float, default=2.0,
                   help="seconds between requests (default 2)")
    p.add_argument("--timeout", type=float, default=20.0,
                   help="request timeout (default 20)")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="extra header 'Name: value' (repeatable)")
    p.add_argument("--proxy", help="proxy URL, e.g. socks5h://127.0.0.1:1337")
    p.add_argument("--user-agent", help="override the User-Agent")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color or os.environ.get("NO_COLOR"):
        set_color(False)

    if args.list_engines:
        print(paint("  engines", "b"))
        for n, cls in ENGINES.items():
            key = {"reliable": "ok", "flaky": "warn",
                   "usually blocked": "bad"}.get(cls.reliable, "dim")
            print(f"    {n:<12} {paint(cls.reliable, key)}")
        return 0

    if not args.query:
        print("error: -q/--query is required", file=sys.stderr)
        return 2

    con = Console(args.verbosity)

    if not args.no_banner:
        print(paint(BANNER, "head"), file=sys.stderr)
        print(f"  query   {paint(args.query, 'b')}", file=sys.stderr)
        print(f"  engines {args.engine}      pages {args.pages}      "
              f"delay {args.delay}s", file=sys.stderr)
        if args.output:
            print(f"  output  {args.output}", file=sys.stderr)
        print(file=sys.stderr)

    serp = Serp(con, args)
    started = time.time()
    try:
        results = serp.run()
    except KeyboardInterrupt:
        con.error("interrupted by user")
        results = serp.results

    urls = sorted(serp.seen)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write("\n".join(urls) + ("\n" if urls else ""))
        except OSError as e:
            con.error(f"could not write {args.output}: {e}")

    # Summary to stderr so -v 0 stdout stays a clean URL list.
    if not args.no_banner or args.verbosity >= 1:
        el = time.time() - started
        print(f"\n  {paint(str(len(urls)), 'b')} unique URL(s) "
              f"in {el:.0f}s", file=sys.stderr)
        blocked = [r.name for r in results if r.blocked]
        unparsed = [r.name for r in results if r.unparsed]
        errored = [f"{r.name} ({r.error})" for r in results if r.error]
        for r in results:
            if r.blocked or r.error or r.unparsed:
                continue
            print(f"    {r.name:<12} {len(r.urls)}", file=sys.stderr)
        if blocked:
            print(f"  {paint('blocked', 'warn')}: {', '.join(blocked)}"
                  f"  — their results are missing, not absent",
                  file=sys.stderr)
        if unparsed:
            print(f"  {paint('unparsed', 'warn')}: {', '.join(unparsed)}"
                  f"  — served a page but nothing extractable (UNKNOWN, "
                  f"not zero)", file=sys.stderr)
        if errored:
            print(f"  {paint('errors', 'bad')}: {', '.join(errored)}",
                  file=sys.stderr)
        contributing = len(results) - len(blocked) - len(unparsed) - len(errored)
        if contributing < len(results):
            print(f"  {paint('coverage', 'warn')}: {contributing}/"
                  f"{len(results)} engine(s) actually contributed",
                  file=sys.stderr)
        if args.output and urls:
            print(f"  written to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
