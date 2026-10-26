#!/usr/bin/env python3
"""
githunt — GitHub code search for recon.

Two backends, because GitHub offers two different searches and they do not
return the same thing:

  api   /search/code via api.github.com. Needs a personal access token.
        Documented and stable, but the legacy code index is narrower than the
        web one and its rate limit is brutal: 10 requests/minute, even
        authenticated. Supports multiple tokens to spread that limit.

  web   github.com/search?type=code. Needs a logged-in session cookie.
        This is the modern (Blackbird) index -- materially better coverage
        than the API -- but it is an undocumented surface: results live in an
        embedded JSON blob whose shape GitHub changes without notice. Treat a
        web-backend failure as "GitHub changed the page", not "no results".

Either can be disabled (--no-api / --no-web). Running both and merging is the
default because their indexes genuinely differ.

Findings are extracted from result content, not just listed: given -t DOMAIN
the tool pulls URLs on that domain and subdomains of it out of every match,
deduplicates across backends, and prints those. Subdomains come from two
places -- a dedicated subdomain-shaped query, and extraction from the URLs
found by every other query.

Rate limiting and auth failures are reported explicitly. A search that returned
nothing because the token was exhausted is not a search that found nothing, and
this never conflates the two.

For authorized reconnaissance. You are searching other people's public code:
stay within GitHub's terms and your engagement scope.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] pip install requests")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

API = "https://api.github.com"
WEB = "https://github.com"


# ----------------------------------------------------------------------------
# colour
# ----------------------------------------------------------------------------

ANSI = {
    "ok": "\033[1;92m", "warn": "\033[0;93m", "bad": "\033[0;91m",
    "dim": "\033[0;90m", "b": "\033[1m", "head": "\033[1;36m",
    "sub": "\033[1;95m", "url": "\033[0;96m", "x": "\033[0m",
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
      0  findings only -- stdout stays a clean, pipeable list
      1  + the search currently running and its outcome
      2  + every HTTP request performed
    Everything that is not a finding goes to stderr.
    """

    def __init__(self, verbosity=0):
        self.v = verbosity

    def finding(self, value, kind, source=""):
        print(paint(value, "sub" if kind == "sub" else "url"), flush=True)
        if self.v >= 1 and source:
            print(paint(f"      ^ {source}", "dim"), file=sys.stderr, flush=True)

    def search(self, s):
        if self.v >= 1:
            print(paint(f"[search] {s}", "head"), file=sys.stderr, flush=True)

    def request(self, s):
        if self.v >= 2:
            print(paint(f"  [req] {s}", "dim"), file=sys.stderr, flush=True)

    def note(self, s):
        if self.v >= 1:
            print(paint(f"  {s}", "dim"), file=sys.stderr, flush=True)

    def warn(self, s):
        # never suppressed: it changes what an empty result set means
        print(paint(f"  [!] {s}", "warn"), file=sys.stderr, flush=True)

    def error(self, s):
        print(paint(f"  [err] {s}", "bad"), file=sys.stderr, flush=True)


# ----------------------------------------------------------------------------
# extraction
# ----------------------------------------------------------------------------

# Hosts that carry a target string but are never the target's own asset.
NOT_TARGET = re.compile(
    r"(?:^|\.)(?:github\.com|githubusercontent\.com|githubassets\.com|"
    r"w3\.org|schema\.org|example\.(?:com|org|net)|localhost)$", re.I)

URL_RE = re.compile(r"""https?://[^\s"'`<>\\)\]}(,;]+""", re.I)

# A /pattern/ term anywhere in the query means Blackbird regex syntax, which
# only the web backend understands.
REGEX_Q = re.compile(r"(?:^|\s)/(?:[^/\\]|\\.)+/(?:\s|$)")


def sub_re(domain: str) -> re.Pattern:
    """
    A label chain ending in the target domain.

    Both boundaries matter and for different reasons. The leading one stops
    "notsephora.fr" matching target "sephora.fr". The trailing one must also
    reject a FOLLOWING label, or "cdn.sephora.fr.attacker.com" yields a
    fictitious "cdn.sephora.fr" -- a lookalike domain laundered into the
    recon list as if it were the client's. A trailing dot is tolerated only
    when nothing follows it, so "Visit api.sephora.fr." still matches.
    """
    return re.compile(
        r"(?<![A-Za-z0-9.-])((?:[A-Za-z0-9_-]+\.)+" + re.escape(domain) + r")"
        r"(?!\.?[A-Za-z0-9-])", re.I)


def host_of(u: str) -> str:
    try:
        return urlsplit(u).netloc.split("@")[-1].split(":")[0].lower()
    except ValueError:
        return ""


def in_scope(host: str, domain: str) -> bool:
    if not host or NOT_TARGET.search(host):
        return False
    return host == domain.lower() or host.endswith("." + domain.lower())


@dataclass
class Extract:
    subs: set = field(default_factory=set)
    urls: set = field(default_factory=set)


def extract(text: str, domain: str) -> Extract:
    """Pull in-scope URLs and subdomains out of a blob of code."""
    got = Extract()
    if not text:
        return got
    for m in URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;:'\"")
        h = host_of(u)
        if in_scope(h, domain):
            got.urls.add(u)
            if h != domain.lower():
                got.subs.add(h)
    # subdomains that appear as bare hostnames, not inside a URL
    for m in sub_re(domain).finditer(text):
        h = m.group(1).lower().strip(".")
        if not NOT_TARGET.search(h):
            got.subs.add(h)
    return got


# ----------------------------------------------------------------------------
# backends
# ----------------------------------------------------------------------------

@dataclass
class BackendResult:
    name: str
    matches: int = 0
    pages: int = 0
    rate_limited: bool = False
    auth_failed: bool = False
    unparsed: bool = False
    error: str = ""


class GitHunt:
    def __init__(self, con: Console, args):
        self.con = con
        self.args = args
        self.s = requests.Session()
        self.proxies = ({"http": args.proxy, "https": args.proxy}
                        if args.proxy else None)
        self.tokens = self._load_tokens()
        self.tok_i = 0
        self.cookie = self._load_cookie()
        self.subs: set = set()
        self.urls: set = set()
        self.sources: dict = {}
        self.results: list[BackendResult] = []

    # -- credentials

    def _load_tokens(self) -> list:
        toks = []
        if self.args.token:
            toks += [t.strip() for t in self.args.token.split(",") if t.strip()]
        if self.args.token_file and os.path.isfile(self.args.token_file):
            with open(self.args.token_file, encoding="utf-8") as fh:
                toks += [l.strip() for l in fh
                         if l.strip() and not l.startswith("#")]
        env = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if env and not toks:
            toks.append(env.strip())
        return list(dict.fromkeys(toks))

    @staticmethod
    def _norm_cookie(raw: str) -> str:
        """
        Accept either a bare cookie string or a full header line. A file saved
        straight from a browser's "copy as cURL" keeps the "Cookie: " prefix,
        and passing that through unchanged builds "Cookie: Cookie: ..." -- a
        malformed header that GitHub answers with a login page, which looks
        exactly like an expired session.
        """
        raw = (raw or "").strip().strip('"').strip("'")
        raw = re.sub(r"^\s*cookie\s*:\s*", "", raw, flags=re.I)
        return " ".join(raw.split())

    def _load_cookie(self) -> str:
        if self.args.cookie:
            return self._norm_cookie(self.args.cookie)
        if self.args.cookie_file and os.path.isfile(self.args.cookie_file):
            with open(self.args.cookie_file, encoding="utf-8") as fh:
                return self._norm_cookie(fh.read())
        return self._norm_cookie(os.environ.get("GITHUB_COOKIE") or "")

    def _token(self) -> str:
        if not self.tokens:
            return ""
        return self.tokens[self.tok_i % len(self.tokens)]

    def _rotate(self):
        if len(self.tokens) > 1:
            self.tok_i += 1
            self.con.note(f"rotated to token {self.tok_i % len(self.tokens) + 1}"
                          f"/{len(self.tokens)}")

    # -- http

    def _get(self, url, headers=None):
        self.con.request(f"GET {url}")
        try:
            r = self.s.get(url, headers=headers, timeout=self.args.timeout,
                           proxies=self.proxies, verify=False,
                           allow_redirects=True)
            return r
        except requests.RequestException as e:
            self.con.error(str(e)[:90])
            return None

    # -- record

    def record(self, ex: Extract, source: str):
        new = 0
        for h in ex.subs:
            if h not in self.subs:
                self.subs.add(h)
                self.sources.setdefault(h, source)
                new += 1
                self.con.finding(h, "sub", source)
        if not self.args.only_subs:
            for u in ex.urls:
                if u not in self.urls:
                    self.urls.add(u)
                    self.sources.setdefault(u, source)
                    new += 1
                    self.con.finding(u, "url", source)
        return new

    # ---------------- API backend ----------------

    def run_api(self, query: str) -> BackendResult:
        res = BackendResult(name="api")
        if not self.tokens:
            res.auth_failed = True
            self.con.warn("api: no token (--token/--token-file/GITHUB_TOKEN) — "
                          "GitHub code search requires authentication, so this "
                          "backend contributed NOTHING (not 'no results')")
            return res

        for page in range(1, self.args.pages + 1):
            url = (f"{API}/search/code?q={quote(query)}"
                   f"&per_page=100&page={page}")
            h = {"Accept": "application/vnd.github.text-match+json",
                 "Authorization": f"Bearer {self._token()}",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": UA}
            r = self._get(url, h)
            if r is None:
                res.error = "request failed"
                break

            if r.status_code == 401:
                res.auth_failed = True
                self.con.warn("api: 401 — token rejected (bad or expired)")
                break
            remaining = r.headers.get("X-RateLimit-Remaining")
            if r.status_code in (403, 429) or remaining == "0":
                reset = r.headers.get("X-RateLimit-Reset")
                wait = 0
                try:
                    wait = max(0, int(reset) - int(time.time()))
                except (TypeError, ValueError):
                    pass
                if len(self.tokens) > 1:
                    self._rotate()
                    continue
                res.rate_limited = True
                self.con.warn(f"api: rate limited (HTTP {r.status_code}), "
                              f"resets in {wait}s — results are INCOMPLETE. "
                              f"Code search allows 10 req/min; use "
                              f"--token-file with several tokens.")
                break
            if r.status_code >= 400:
                res.error = f"HTTP {r.status_code}"
                self.con.error(f"api: HTTP {r.status_code} {r.text[:120]}")
                break

            try:
                data = r.json()
            except ValueError:
                res.unparsed = True
                self.con.warn("api: response was not JSON")
                break

            items = data.get("items") or []
            res.pages += 1
            res.matches += len(items)
            for it in items:
                repo = (it.get("repository") or {}).get("full_name", "?")
                path = it.get("path", "?")
                src = f"{repo}:{path}"
                blob = "\n".join(
                    frag.get("fragment", "")
                    for frag in (it.get("text_matches") or []))
                self.record(extract(blob, self.args.target), src)
                if self.args.fetch_raw:
                    self._raw(it, src)
            self.con.note(f"api page {page}: {len(items)} match(es) "
                          f"of {data.get('total_count', '?')} total")
            if len(items) < 100:
                break
            time.sleep(self.args.delay)
        return res

    def _raw(self, item, src):
        """Fetch the whole file. Off by default: it multiplies requests."""
        u = item.get("html_url", "")
        raw = (u.replace("https://github.com/", "https://raw.githubusercontent.com/")
                .replace("/blob/", "/"))
        r = self._get(raw, {"User-Agent": UA})
        if r is not None and r.status_code == 200:
            self.record(extract(r.text[:400000], self.args.target), src)

    # ---------------- web backend ----------------

    # The search page ships several application/json blobs; only one carries
    # the results. Matching on data-target is fragile -- the page uses both
    # react-app.embeddedData and react-partial.embeddedData, and their order
    # and attribute order both vary -- so select by CONTENT instead: the blob
    # whose parsed JSON has payload.results.
    JSON_TAG = re.compile(
        r'<script[^>]*type="application/json"[^>]*>(.*?)</script>', re.S)

    def run_web(self, query: str) -> BackendResult:
        res = BackendResult(name="web")
        if not self.cookie:
            res.auth_failed = True
            self.con.warn("web: no session cookie (--cookie/--cookie-file/"
                          "GITHUB_COOKIE) — github.com code search requires a "
                          "logged-in session, so this backend contributed "
                          "NOTHING (not 'no results')")
            return res

        for page in range(1, self.args.pages + 1):
            url = (f"{WEB}/search?q={quote(query)}&type=code&p={page}")
            h = {"User-Agent": UA,
                 "Accept": "text/html,application/xhtml+xml,application/xml;"
                           "q=0.9,*/*;q=0.8",
                 "Accept-Language": "en-US,en;q=0.9",
                 "Cookie": self.cookie}
            r = self._get(url, h)
            if r is None:
                res.error = "request failed"
                break
            if r.status_code in (401, 403):
                res.auth_failed = True
                self.con.warn(f"web: HTTP {r.status_code} — session cookie "
                              f"rejected or expired")
                break
            if r.status_code == 429:
                res.rate_limited = True
                self.con.warn("web: 429 rate limited — results INCOMPLETE")
                break
            if r.status_code >= 400:
                res.error = f"HTTP {r.status_code}"
                self.con.error(f"web: HTTP {r.status_code}")
                break

            # A login page means the cookie did not take. Check the FINAL url
            # (requests follows the redirect, so the original path is gone) and
            # scan the whole body: GitHub's <title> sits behind a long block of
            # preload/meta tags and routinely lands past any short prefix.
            final = (r.url or "").lower()
            if ("/login" in final or "/session" in final
                    or "sign in to github" in r.text.lower()):
                res.auth_failed = True
                self.con.warn(
                    f"web: redirected to the login page ({r.url[:60]}...) — "
                    f"the session cookie is expired or was not accepted. "
                    f"Re-export it from a logged-in browser; _gh_sess rotates "
                    f"and invalidates the old value.")
                break

            payload = self._web_payload(r.text)
            if payload is None:
                res.unparsed = True
                self.con.warn("web: no search payload in the page at all. "
                              "GitHub changed the page shape — this is a "
                              "PARSER failure, not an empty result set.")
                break

            # The decisive check. When the session is not accepted GitHub does
            # NOT redirect to login: it serves a normal 200 search page with
            # logged_in=false and result_count=0. Without this, an unauthorised
            # session is indistinguishable from a query that matched nothing,
            # and every search silently reports zero.
            if payload.get("logged_in") is False:
                res.auth_failed = True
                self.con.warn(
                    "web: GitHub reports logged_in=false — the session cookie "
                    "was not accepted. It serves a normal 200 with zero "
                    "results in this state, so this is an AUTH failure, not "
                    "an empty result set. Re-export the cookie (needs "
                    "user_session and _gh_sess from a logged-in browser).")
                break

            if payload.get("warn_limited_results"):
                self.con.warn("web: GitHub flagged the result set as limited — "
                              "results are truncated, not complete")

            found = self._web_items(payload)
            res.pages += 1
            res.matches += len(found)
            for it in found:
                self.record(extract(it.get("_text", ""), self.args.target),
                            it.get("_src", "?"))
            total = payload.get("result_count")
            self.con.note(f"web page {page}: {len(found)} match(es)"
                          + (f" of {total} total" if total is not None else ""))
            if not found:
                # authenticated, payload present, genuinely nothing matched
                if page == 1:
                    self.con.note("web: authenticated and parsed cleanly — "
                                  "this query genuinely has no matches")
                break
            time.sleep(self.args.delay)
        return res

    def _web_payload(self, html: str):
        """The search payload dict, or None if the page carries none at all."""
        for blob in self.JSON_TAG.findall(html):
            try:
                data = json.loads(blob)
            except ValueError:
                continue
            payload = data.get("payload")
            if isinstance(payload, dict) and "results" in payload:
                return payload
        return None

    @staticmethod
    def _web_items(payload: dict) -> list:
        """
        Flatten result entries to {_src,_text}.

        The text is the entry serialised whole rather than specific snippet
        fields: we are mining domain strings, so shape-agnostic beats precise
        here, and it keeps working when GitHub renames a field.
        """
        out = []
        for r in payload.get("results") or []:
            if not isinstance(r, dict):
                continue
            repo = r.get("repo_nwo") or r.get("repoNwo") or r.get("repository") or ""
            if isinstance(repo, dict):
                repo = repo.get("nwo") or repo.get("name") or ""
            path = r.get("path") or r.get("file_path") or "?"
            out.append({"_src": f"{repo}:{path}" if repo else str(path),
                        "_text": json.dumps(r)})
        return out

    # ---------------- driver ----------------

    def queries(self) -> list:
        qs = []
        if self.args.query:
            qs.append(self.args.query)
        elif self.args.target:
            # dedicated searches: the bare domain, then a subdomain-shaped one
            qs.append(f'"{self.args.target}"')
            qs.append(f'"*.{self.args.target}"')
            qs.append(f'"//{self.args.target}"')
        return qs

    def run(self):
        # A credential does not repair itself between queries: once a backend
        # has failed auth, retrying it per query only repeats the same warning
        # and wastes requests. Rate limiting is different -- that one is worth
        # retrying, since a rotated token or elapsed window can clear it.
        dead: set = set()
        for q in self.queries():
            regex = bool(REGEX_Q.search(q))
            for backend, disabled in (("api", self.args.no_api),
                                      ("web", self.args.no_web)):
                if disabled or backend in dead:
                    continue
                # /pattern/ is a Blackbird (web) feature. The legacy code
                # search API has no regex support: it would treat the slashes
                # as literals and quietly return unrelated matches, which is
                # worse than not running at all.
                if regex and backend == "api":
                    self.con.warn("api: query uses /regex/, which the code "
                                  "search API does not support — skipping this "
                                  "backend for this query (web only)")
                    continue
                self.con.search(f"{backend}: {q}")
                r = (self.run_api(q) if backend == "api" else self.run_web(q))
                r.name = backend
                self.results.append(r)
                if r.auth_failed:
                    dead.add(backend)
                    self.con.note(f"{backend}: disabled for the remaining "
                                  f"searches (credential will not change)")
                time.sleep(self.args.delay)


# ----------------------------------------------------------------------------
# cli
# ----------------------------------------------------------------------------

BANNER = r"""
  githunt — GitHub code search for recon
"""

EPILOG = """
the two backends
  api  needs a personal access token. GitHub code search is authenticated-only
       and capped at 10 requests per MINUTE, which is the real constraint --
       not the 5000/hour headline limit. --token-file with several tokens
       rotates through them when one is exhausted.

  web  needs a logged-in session cookie (the `user_session` cookie from a
       browser). This reaches the modern Blackbird index, whose coverage is
       materially better than the legacy API index, but the result payload is
       undocumented JSON embedded in the page. When GitHub changes it, this
       reports a PARSER failure rather than pretending there were no results.

  Both run by default and their findings are merged, because the two indexes
  genuinely differ. --no-api / --no-web disable either.

credentials
  --token / --token-file / $GITHUB_TOKEN
  --cookie / --cookie-file / $GITHUB_COOKIE
  A backend with no credential is reported as "contributed NOTHING", never as
  "no results". Those are different claims and only one of them is honest.

findings
  -t DOMAIN drives extraction. Every match is scanned for URLs whose host is
  the domain or a subdomain of it, and for bare subdomain-shaped hostnames.
  Both are printed by default; --only-subs narrows output to subdomains.

  Subdomains come from two sources: the dedicated subdomain-shaped queries
  (used when -q is omitted) and extraction from URLs found by any query.

  Matching is boundary-anchored, so target "sephora.fr" does not match
  "notsephora.fr", and github.com/githubusercontent.com are never reported.

  By default only the search-result snippets are scanned. --fetch-raw pulls
  each whole file, which finds more and costs one extra request per match.

verbosity
  -v 0   findings only, one per line on stdout (default)
  -v 1   + which search is running, its outcome, and each finding's source
  -v 2   + every HTTP request

examples
  githunt.py -t sephora.fr --token ghp_xxx
  githunt.py -t sephora.fr --only-subs --token-file tokens.txt -o subs.txt
  githunt.py -q 'org:sephora filename:.env' --token ghp_xxx -v 1
  githunt.py -t sephora.fr --no-api --cookie 'user_session=...' -v 1
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="githunt.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", type=int, default=0, choices=[0, 1, 2],
                   dest="verbosity",
                   help="0 = findings only (default), 1 = current search, "
                        "2 = all requests")
    p.add_argument("-q", "--query", help="raw GitHub search query")
    p.add_argument("-t", "--target", help="target domain; findings are URLs "
                                          "and subdomains belonging to it")
    p.add_argument("--only-subs", action="store_true",
                   help="print only subdomains, not endpoints/URLs")
    p.add_argument("-o", "--output", help="write unique findings to this file")
    p.add_argument("--no-banner", action="store_true",
                   help="suppress the banner and option summary")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured output (colour is on by default)")
    p.add_argument("--no-api", action="store_true",
                   help="disable the token-based API backend")
    p.add_argument("--no-web", action="store_true",
                   help="disable the cookie-based web backend")
    p.add_argument("--token", help="GitHub token(s), comma-separated")
    p.add_argument("--token-file", help="file of tokens, one per line")
    p.add_argument("--cookie", help="github.com session cookie header value")
    p.add_argument("--cookie-file", help="file containing the cookie header")
    p.add_argument("--fetch-raw", action="store_true",
                   help="fetch each matched file in full (more findings, "
                        "one extra request per match)")
    p.add_argument("--pages", type=int, default=3, metavar="N",
                   help="result pages per search (default 3)")
    p.add_argument("-d", "--delay", type=float, default=2.0,
                   help="seconds between requests (default 2)")
    p.add_argument("--timeout", type=float, default=25.0,
                   help="request timeout (default 25)")
    p.add_argument("--proxy", help="proxy URL, e.g. socks5h://127.0.0.1:1337")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.no_color or os.environ.get("NO_COLOR"):
        set_color(False)

    if not args.query and not args.target:
        print("error: give -q QUERY or -t DOMAIN (or both)", file=sys.stderr)
        return 2
    if args.no_api and args.no_web:
        print("error: --no-api and --no-web together disable both backends; "
              "there would be nothing to search", file=sys.stderr)
        return 2
    if args.only_subs and not args.target:
        print("error: --only-subs needs -t DOMAIN to know what a subdomain is",
              file=sys.stderr)
        return 2

    con = Console(args.verbosity)
    hunt = GitHunt(con, args)

    if not args.no_banner:
        print(paint(BANNER, "head"), file=sys.stderr)
        print(f"  target  {paint(args.target or '-', 'b')}"
              f"      query {args.query or '(auto)'}", file=sys.stderr)
        backends = []
        if not args.no_api:
            backends.append(f"api({len(hunt.tokens)} token"
                            f"{'s' if len(hunt.tokens) != 1 else ''})")
        if not args.no_web:
            backends.append(f"web({'cookie' if hunt.cookie else 'NO COOKIE'})")
        print(f"  backends {' + '.join(backends)}      pages {args.pages}"
              f"      delay {args.delay}s", file=sys.stderr)
        print(f"  output  {args.output or '-'}"
              f"      mode {'subdomains only' if args.only_subs else 'urls + subdomains'}",
              file=sys.stderr)
        print(file=sys.stderr)

    started = time.time()
    try:
        hunt.run()
    except KeyboardInterrupt:
        con.error("interrupted by user")

    findings = sorted(hunt.subs) + ([] if args.only_subs else sorted(hunt.urls))
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write("\n".join(findings) + ("\n" if findings else ""))
        except OSError as e:
            con.error(f"could not write {args.output}: {e}")

    if not args.no_banner or args.verbosity >= 1:
        el = time.time() - started
        print(f"\n  {paint(str(len(hunt.subs)), 'b')} subdomain(s)"
              + ("" if args.only_subs
                 else f", {paint(str(len(hunt.urls)), 'b')} URL(s)")
              + f" in {el:.0f}s", file=sys.stderr)
        # aggregate per backend: one line each, not one line per query
        by_backend: dict = {}
        for r in hunt.results:
            a = by_backend.setdefault(r.name, BackendResult(name=r.name))
            a.matches += r.matches
            a.pages += r.pages
            a.rate_limited |= r.rate_limited
            a.auth_failed |= r.auth_failed
            a.unparsed |= r.unparsed
            a.error = a.error or r.error
        for name, r in by_backend.items():
            if r.auth_failed:
                state = paint("NO CREDENTIAL / AUTH FAILED", "bad")
            elif r.rate_limited:
                state = paint(f"RATE LIMITED after {r.matches} match(es) "
                              f"— incomplete", "warn")
            elif r.unparsed:
                state = paint("PARSER FAILED", "warn")
            elif r.error:
                state = paint(r.error, "bad")
            else:
                state = f"{r.matches} match(es) over {r.pages} page(s)"
            print(f"    {name:<5} {state}", file=sys.stderr)
        degraded = [n for n, r in by_backend.items()
                    if r.auth_failed or r.rate_limited or r.unparsed or r.error]
        if degraded:
            print(f"  {paint('incomplete', 'warn')}: "
                  f"{', '.join(sorted(set(degraded)))} did not fully run — "
                  f"absence of findings here proves nothing", file=sys.stderr)
        if args.output and findings:
            print(f"  written to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
