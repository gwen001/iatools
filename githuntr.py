#!/usr/bin/env python3
"""
githuntr — GitHub code search hunter.

Prints the matching FILES, with their matching lines. Where githunt.py mines a
target domain out of results, this one hands you the raw matches: repo, path,
permalink and the snippet that matched, filtered by an optional regexp.

Two backends, because GitHub runs two different code searches and they do not
return the same thing:

  api   /search/code via api.github.com. Needs a personal access token. Well
        documented and stable, but the legacy index is narrower than the web
        one and the rate limit is brutal: 10 requests/minute even
        authenticated. Several tokens can be supplied and are rotated when one
        is exhausted.

  web   github.com/search?type=code. Needs a logged-in session cookie. This is
        the modern (Blackbird) index -- materially better coverage -- but it is
        an undocumented surface whose JSON shape GitHub changes without notice.
        A web failure means "GitHub changed the payload", not "no results".

Either can be disabled (--no-api / --no-web). Both run by default and their
findings are merged and de-duplicated on (repo, path); a file both backends
found is tagged [api+web].

Matching is case-insensitive throughout: the -r filter, the highlighting, and
the de-duplication key. Secrets and hostnames do not have a canonical case, and
a filter that misses AKIA because the file said akia is a filter that lies.

Credentials that are missing or rejected are reported as such, never as an
empty result set. Those are different claims and only one of them is honest.

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

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] pip install requests")

VERSION = "1.1"

API_URL = "https://api.github.com/search/code"
WEB_URL = "https://github.com/search"

# The search API refuses to page past 1000 results whatever you ask for.
API_MAX_RESULTS = 1000

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")


# ----------------------------------------------------------------------------
# colour
# ----------------------------------------------------------------------------

ANSI = {
    "ok": "\033[1;92m", "warn": "\033[0;93m", "bad": "\033[0;91m",
    "dim": "\033[0;90m", "b": "\033[1m", "head": "\033[1;36m",
    "repo": "\033[1;36m", "path": "\033[0;93m", "url": "\033[0;90m",
    "hit": "\033[1;30;43m", "x": "\033[0m",
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
    Everything that is not a finding goes to stderr, so redirecting stdout
    gives you the findings alone. The -o copy is never coloured.
    """

    def __init__(self, verbosity=0, outfile=None):
        self.v = verbosity
        self.fh = None
        if outfile:
            self.fh = open(outfile, "a", encoding="utf-8", errors="replace")

    def finding(self, coloured, plain):
        print(coloured, flush=True)
        if self.fh:
            self.fh.write(plain + "\n")
            self.fh.flush()

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

    def close(self):
        if self.fh:
            self.fh.close()
            self.fh = None


# ----------------------------------------------------------------------------
# model
# ----------------------------------------------------------------------------

@dataclass
class Finding:
    """One matching file. `snippets` holds (line number or None, text)."""

    repo: str
    path: str
    url: str
    snippets: list = field(default_factory=list)
    sources: list = field(default_factory=list)

    @property
    def key(self) -> tuple:
        return (self.repo.lower(), self.path.lower())

    def merge(self, other: "Finding"):
        for src in other.sources:
            if src not in self.sources:
                self.sources.append(src)
        seen = {t.strip() for _, t in self.snippets}
        for ln, txt in other.snippets:
            if txt.strip() not in seen:
                self.snippets.append((ln, txt))
                seen.add(txt.strip())
        self.url = self.url or other.url

    def lines(self):
        """Flatten snippets to (line number or None, single line of text)."""
        for ln, txt in self.snippets:
            for off, raw in enumerate(txt.splitlines() or [txt]):
                body = raw.strip()
                if body:
                    yield (ln + off if isinstance(ln, int) else None), body

    def matches(self, rx) -> bool:
        if rx.search(self.repo) or rx.search(self.path):
            return True
        return any(rx.search(txt) for _, txt in self.snippets)

    def as_dict(self) -> dict:
        return {
            "repo": self.repo,
            "path": self.path,
            "url": self.url,
            "sources": self.sources,
            "snippets": [{"line": ln, "text": txt} for ln, txt in self.snippets],
        }


@dataclass
class BackendResult:
    """Why a backend stopped. An empty run is not the same as a failed one."""

    name: str
    matches: int = 0
    pages: int = 0
    rate_limited: bool = False
    auth_failed: bool = False
    unparsed: bool = False
    error: str = ""

    @property
    def degraded(self) -> bool:
        return bool(self.rate_limited or self.auth_failed
                    or self.unparsed or self.error)


# ----------------------------------------------------------------------------
# rendering
# ----------------------------------------------------------------------------

# Query words that are search operators rather than content to highlight.
QUALIFIER = re.compile(
    r"^(?:repo|user|org|language|path|filename|extension|size|fork|in|created|"
    r"pushed|stars|forks|topic|is|archived|license|mirror):", re.I)


def query_terms(query: str) -> list:
    """The bare (non-qualifier) words of a query, used for highlighting."""
    terms = []
    for tok in re.findall(r'"[^"]+"|\S+', query):
        tok = tok.strip('"')
        if tok and not QUALIFIER.match(tok) and tok.upper() not in ("AND", "OR", "NOT"):
            terms.append(tok)
    return terms


def make_highlighter(rx, terms):
    """
    f(text) -> text with matches highlighted.

    The -r filter doubles as the highlighter when given, so you see exactly
    what kept the line. Otherwise the query's own words are highlighted.
    """
    if not _COLOR:
        return lambda t: t
    if rx is None:
        if not terms:
            return lambda t: t
        rx = re.compile("|".join(re.escape(t) for t in terms), re.I)

    def hl(text):
        return rx.sub(lambda m: paint(m.group(0), "hit") if m.group(0) else "", text)
    return hl


def render(f: Finding, highlight, max_lines: int, width: int) -> tuple:
    """Return (coloured, plain) renderings of one finding."""
    src = "+".join(f.sources)
    coloured = [f"{paint('[' + src + ']', 'ok')} "
                f"{paint(f.repo, 'repo')}:{paint(f.path, 'path')}",
                "    " + paint(f.url, "url")]
    plain = [f"[{src}] {f.repo}:{f.path}", "    " + f.url]

    for i, (ln, body) in enumerate(f.lines()):
        if max_lines and i >= max_lines:
            break
        if width and len(body) > width:
            body = body[:width] + "..."
        prefix = f"{ln if ln else '':>5}| "
        coloured.append("    " + paint(prefix, "dim") + highlight(body))
        plain.append("    " + prefix + body)
    return "\n".join(coloured) + "\n", "\n".join(plain)


# ----------------------------------------------------------------------------
# backends
# ----------------------------------------------------------------------------

class Backend:
    """Common HTTP plumbing. Subclasses implement search() as a generator."""

    name = "base"

    def __init__(self, con: Console, args):
        self.con = con
        self.args = args
        self.res = BackendResult(name=self.name)
        self.s = requests.Session()
        self.s.proxies = ({"http": args.proxy, "https": args.proxy}
                          if args.proxy else {})
        self.s.verify = not args.insecure

    def _get(self, url, params=None, headers=None, redirects=True):
        self.con.request(f"GET {url} {params or ''}")
        try:
            r = self.s.get(url, params=params, headers=headers,
                           timeout=self.args.timeout,
                           allow_redirects=redirects)
        except requests.RequestException as e:
            self.res.error = "request failed"
            self.con.error(f"{self.name}: {str(e)[:90]}")
            return None
        self.con.request(f"  <- {r.status_code} {r.reason} ({len(r.content)} bytes)")
        return r


class ApiBackend(Backend):
    """REST /search/code. Rotates tokens when one hits its rate limit."""

    name = "api"

    def __init__(self, con, args, tokens):
        super().__init__(con, args)
        self.tokens = tokens
        self.i = 0

    def _headers(self) -> dict:
        return {
            "Accept": "application/vnd.github.text-match+json",
            "Authorization": f"Bearer {self.tokens[self.i % len(self.tokens)]}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"githuntr/{VERSION}",
        }

    def _rotate(self) -> bool:
        if len(self.tokens) <= 1:
            return False
        self.i += 1
        self.con.note(f"rotated to token {self.i % len(self.tokens) + 1}"
                      f"/{len(self.tokens)}")
        return True

    def _cooldown(self, r) -> bool:
        """Rotate if we can, else sleep. False means give up on this backend."""
        if self._rotate():
            return True
        wait = 60
        if r.headers.get("Retry-After", "").isdigit():
            wait = int(r.headers["Retry-After"]) + 1
        elif r.headers.get("X-RateLimit-Reset", "").isdigit():
            wait = max(1, int(r.headers["X-RateLimit-Reset"]) - int(time.time()) + 2)
        if wait > self.args.max_wait:
            self.res.rate_limited = True
            self.con.warn(f"api: rate limited for {wait}s, over --max-wait "
                          f"({self.args.max_wait}s) — results are INCOMPLETE. "
                          f"Code search allows 10 req/min; pass several tokens "
                          f"to rotate through them.")
            return False
        self.con.note(f"api: rate limited, sleeping {wait}s")
        time.sleep(wait)
        return True

    def search(self, query: str):
        per_page = min(self.args.per_page, 100)
        max_pages = min(self.args.pages, max(1, API_MAX_RESULTS // per_page))
        page = 1
        while page <= max_pages:
            self.con.note(f"api page {page}/{max_pages}")
            r = self._get(API_URL, {"q": query, "per_page": per_page, "page": page},
                          self._headers())
            if r is None:
                return

            if r.status_code == 401:
                self.res.auth_failed = True
                self.con.warn("api: 401 — token rejected (bad or expired), so "
                              "this backend contributed NOTHING, not 'no results'")
                return
            if r.status_code in (403, 429) or r.headers.get("X-RateLimit-Remaining") == "0":
                body = r.text[:150].replace("\n", " ")
                if r.status_code in (403, 429) and "rate limit" not in body.lower() \
                        and r.headers.get("X-RateLimit-Remaining") != "0":
                    self.res.error = f"HTTP {r.status_code}"
                    self.con.error(f"api: HTTP {r.status_code} {body}")
                    return
                if not self._cooldown(r):
                    return
                if r.status_code in (403, 429):
                    continue        # the page was refused; fetch it again
            if r.status_code == 422:
                self.res.error = "query rejected"
                self.con.error(f"api: 422 — GitHub rejected the query: "
                               f"{r.text[:200]}")
                return
            if r.status_code >= 400:
                self.res.error = f"HTTP {r.status_code}"
                self.con.error(f"api: HTTP {r.status_code}")
                return

            try:
                data = r.json()
            except ValueError:
                self.res.unparsed = True
                self.con.warn("api: response was not JSON — PARSER failure, "
                              "not an empty result set")
                return

            items = data.get("items") or []
            self.res.pages += 1
            self.res.matches += len(items)
            if page == 1:
                self.con.note(f"api: {data.get('total_count', '?')} total match(es)")
            for it in items:
                yield self._finding(it)

            if len(items) < per_page:
                return
            page += 1
            if page <= max_pages:
                time.sleep(self.args.delay)

    @staticmethod
    def _finding(item: dict) -> Finding:
        repo = (item.get("repository") or {}).get("full_name", "?")
        path = item.get("path", "?")
        url = item.get("html_url") or f"https://github.com/{repo}/blob/HEAD/{path}"
        snippets = [(None, tm["fragment"])
                    for tm in item.get("text_matches") or []
                    if tm.get("fragment")]
        return Finding(repo, path, url, snippets, ["api"])


class WebBackend(Backend):
    """
    github.com/search?type=code, the Blackbird index.

    Asking for JSON gets the same payload the page's own JS consumes. When
    GitHub answers with HTML anyway, the payload is still in there as an
    embedded blob, so fall back to digging it out rather than reporting zero.
    """

    name = "web"

    # Select the blob by CONTENT (it has payload.results), not by attribute:
    # the page uses several application/json scripts and their order varies.
    JSON_TAG = re.compile(
        r'<script[^>]*type="application/json"[^>]*>(.*?)</script>', re.S)

    def __init__(self, con, args, cookie):
        super().__init__(con, args)
        self.cookie = cookie

    def _headers(self) -> dict:
        return {
            "Accept": "application/json",
            "User-Agent": UA,
            "Cookie": self.cookie,
            "Referer": WEB_URL,
            "X-Requested-With": "XMLHttpRequest",
            "GitHub-Verified-Fetch": "true",
            "Accept-Language": "en-US,en;q=0.9",
        }

    def search(self, query: str):
        page = 1
        while page <= self.args.pages:
            self.con.note(f"web page {page}/{self.args.pages}")
            r = self._get(WEB_URL, {"q": query, "type": "code", "p": page},
                          self._headers(), redirects=False)
            if r is None:
                return

            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "?")
                self.res.auth_failed = True
                self.con.warn(f"web: redirected to {loc[:60]} — the session "
                              f"cookie is expired or was not accepted. Re-export "
                              f"it from a logged-in browser.")
                return
            if r.status_code in (401, 403):
                self.res.auth_failed = True
                self.con.warn(f"web: HTTP {r.status_code} — session cookie "
                              f"rejected")
                return
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 30) or 30)
                if wait > self.args.max_wait:
                    self.res.rate_limited = True
                    self.con.warn(f"web: 429 rate limited for {wait}s, over "
                                  f"--max-wait — results INCOMPLETE")
                    return
                self.con.note(f"web: rate limited, sleeping {wait}s")
                time.sleep(wait)
                continue
            if r.status_code == 422:
                self.res.error = "query rejected"
                self.con.error(f"web: 422 — query rejected: {r.text[:200]}")
                return
            if r.status_code >= 400:
                self.res.error = f"HTTP {r.status_code}"
                self.con.error(f"web: HTTP {r.status_code}")
                return

            payload = self._payload(r)
            if payload is None:
                self.res.unparsed = True
                self.con.warn("web: no search payload in the response. GitHub "
                              "changed the shape — this is a PARSER failure, "
                              "not an empty result set.")
                return

            # The decisive check. With a bad cookie GitHub does NOT redirect: it
            # serves a normal 200 carrying logged_in=false and zero results.
            # Without this, an unauthenticated session is indistinguishable
            # from a query that genuinely matched nothing.
            if payload.get("logged_in") is False:
                self.res.auth_failed = True
                self.con.warn("web: GitHub reports logged_in=false — the cookie "
                              "was not accepted. It returns 200 with zero "
                              "results in this state, so this is an AUTH "
                              "failure, not an empty result set. Re-export "
                              "user_session (and _gh_sess) from a browser.")
                return

            for msg in payload.get("errors") or []:
                self.con.warn(f"web: {msg}")
            if payload.get("warn_limited_results"):
                self.con.warn("web: GitHub flagged the result set as limited — "
                              "results are truncated, not complete")

            results = self._results(payload)
            self.res.pages += 1
            self.res.matches += len(results)
            if page == 1:
                total = payload.get("result_count")
                self.con.note(f"web: {total if total is not None else '?'} "
                              f"total match(es)")
            for item in results:
                f = self._finding(item)
                if f:
                    yield f

            if not results:
                if page == 1:
                    self.con.note("web: authenticated and parsed cleanly — this "
                                  "query genuinely has no matches")
                return
            pages_total = payload.get("page_count")
            if isinstance(pages_total, int) and page >= pages_total:
                return
            page += 1
            if page <= self.args.pages:
                time.sleep(max(self.args.delay, 1.0))

    # -- payload plumbing

    def _payload(self, r):
        """The search payload dict, from JSON or embedded in HTML."""
        if "json" in r.headers.get("Content-Type", ""):
            try:
                data = r.json()
            except ValueError:
                return None
            if isinstance(data, dict):
                inner = data.get("payload")
                return inner if isinstance(inner, dict) else data
            return None
        for blob in self.JSON_TAG.findall(r.text):
            try:
                data = json.loads(blob)
            except ValueError:
                continue
            inner = data.get("payload") if isinstance(data, dict) else None
            if isinstance(inner, dict) and "results" in inner:
                return inner
        return None

    @staticmethod
    def _results(payload: dict) -> list:
        for key in ("results", "code_results", "items"):
            val = payload.get(key)
            if isinstance(val, list):
                return val
        return []

    @staticmethod
    def _repo(res: dict) -> str:
        nwo = res.get("repo_nwo") or res.get("repoNwo") or res.get("repository_nwo")
        if nwo:
            return nwo
        node = res.get("repository")
        while isinstance(node, dict):
            if node.get("nwo"):
                return node["nwo"]
            owner = node.get("owner_login") or node.get("owner")
            if isinstance(owner, dict):
                owner = owner.get("login")
            if owner and node.get("name"):
                return f"{owner}/{node['name']}"
            node = node.get("repository")
        return "?"

    def _finding(self, res) -> Finding | None:
        if not isinstance(res, dict):
            return None
        path = res.get("path") or res.get("file_path") or res.get("blob_path")
        if not path:
            return None
        repo = self._repo(res)
        sha = res.get("commit_sha") or res.get("ref") or "HEAD"

        snippets = []
        for sn in res.get("snippets") or []:
            if not isinstance(sn, dict):
                continue
            text = sn.get("lines") or sn.get("snippet") or ""
            if text:
                snippets.append((sn.get("starting_line_number"), text))
        if not snippets:
            for key in ("line_text", "fragment", "content"):
                if res.get(key):
                    snippets.append((res.get("line_number"), res[key]))
                    break
        return Finding(repo, path, f"https://github.com/{repo}/blob/{sha}/{path}",
                       snippets, ["web"])


# ----------------------------------------------------------------------------
# hunt
# ----------------------------------------------------------------------------

class GitHuntr:
    def __init__(self, con: Console, args, backends, rx):
        self.con = con
        self.args = args
        self.backends = backends
        self.rx = rx
        self.highlight = make_highlighter(rx, query_terms(args.query))
        self.seen: dict = {}

    def emit(self, f: Finding):
        if self.args.json:
            line = json.dumps(f.as_dict(), ensure_ascii=False)
            self.con.finding(line, line)
        else:
            self.con.finding(*render(f, self.highlight,
                                     self.args.snippets, self.args.width))

    def run(self) -> int:
        """Search every enabled backend. Returns the count of unique findings."""
        for backend in self.backends:
            self.con.search(f"{backend.name}: {self.args.query}")
            for f in backend.search(self.args.query):
                if f is None or (self.rx and not f.matches(self.rx)):
                    continue
                known = self.seen.get(f.key)
                if known is not None:
                    known.merge(f)      # same file from the other backend
                    continue
                self.seen[f.key] = f
                self.emit(f)
        return len(self.seen)


# ----------------------------------------------------------------------------
# cli
# ----------------------------------------------------------------------------

BANNER = r"""
        _ _   _                 _
  __ _ (_) |_| |__ _  _ _ _ _ _| |_ _ _
 / _` || |  _| '_ \ || | ' \  _|  _| '_|
 \__, ||_|\__|_.__/\_,_|_||_\__|\__|_|
 |___/ github code search hunter  v%s
""" % VERSION

EPILOG = """
the two backends
  api  needs a personal access token. GitHub code search is authenticated-only
       and capped at 10 requests per MINUTE, which is the real constraint, not
       the 5000/hour headline. Pass several tokens (comma separated or @file)
       to rotate through them when one is exhausted.

  web  needs a logged-in session cookie (user_session, plus _gh_sess). This is
       the Blackbird index, whose coverage beats the API's, but its payload is
       undocumented. When GitHub changes it this reports a PARSER failure
       rather than pretending there were no results.

  Both run by default and their findings are merged, because the indexes
  genuinely differ. --no-api / --no-web disable either.

credentials
  -t/--token   token, comma separated tokens, or @file    ($GITHUB_TOKEN)
  -c/--cookie  full Cookie header value, or @file         ($GITHUB_COOKIE)
  A backend with no credential contributed NOTHING; that is reported, never
  silently folded into "no results".

matching
  -r RE keeps only files whose repo, path or snippet matches RE, and doubles as
  the highlighter so you can see what kept each line. Without -r the query's
  own words are highlighted. All matching is CASE-INSENSITIVE.

output
  Findings go to stdout, everything else to stderr, so `> hits.txt` gives you
  the findings alone. Colour turns itself off when stdout is not a terminal,
  and the -o copy is never coloured. --json emits one JSON object per finding.

verbosity
  -v 0   findings only (default)
  -v 1   + the search running, page counts and outcomes
  -v 2   + every HTTP request

exit status
  0 findings   1 none   2 bad invocation   130 interrupted

examples
  githuntr.py -q 'org:desjardins password'
  githuntr.py -q '"desjardins.com" AWS_SECRET' -r 'AKIA[0-9A-Z]{16}' -o loot.txt
  githuntr.py -q 'desjardins api_key' --no-web -v 1
  githuntr.py -q 'desjardins' --no-api -c @cookie.txt -v 2
"""


def load_secrets(value, env_name) -> list:
    """A literal value, a comma separated list, an @file, or an env var."""
    raw = value or os.environ.get(env_name, "")
    if raw.startswith("@"):
        path = os.path.expanduser(raw[1:])
        try:
            with open(path, encoding="utf-8") as fh:
                raw = ",".join(l.strip() for l in fh
                               if l.strip() and not l.startswith("#"))
        except OSError as e:
            print(f"[!] cannot read {path}: {e}", file=sys.stderr)
            return []
    # A cookie header copied from a browser keeps its "Cookie: " prefix, and
    # passing that through builds "Cookie: Cookie: ..." -- a malformed header
    # GitHub answers with a login page, which looks exactly like expiry.
    raw = re.sub(r"^\s*cookie\s*:\s*", "", raw.strip().strip('"').strip("'"),
                 flags=re.I)
    return [p.strip() for p in raw.split(",") if p.strip()]


def build_parser():
    p = argparse.ArgumentParser(
        prog="githuntr.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-q", "--query", required=True,
                   help="GitHub search query [required]")
    p.add_argument("-v", type=int, nargs="?", const=1, default=0,
                   choices=[0, 1, 2], dest="verbosity", metavar="LEVEL",
                   help="0 = findings only (default), 1 = current search, "
                        "2 = all requests")
    p.add_argument("-r", "--regexp", metavar="RE",
                   help="keep only results whose repo, path or snippet matches "
                        "RE (always case-insensitive)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="append findings to FILE (never coloured)")
    p.add_argument("--json", action="store_true",
                   help="emit one JSON object per finding instead of text")
    p.add_argument("--no-banner", action="store_true",
                   help="suppress the banner and option summary")
    p.add_argument("--no-color", "--no-colour", action="store_true",
                   dest="no_color",
                   help="disable coloured output (colour is on by default)")

    b = p.add_argument_group("backends")
    b.add_argument("-t", "--token", metavar="TOK",
                   help="token, comma separated tokens, or @file")
    b.add_argument("-c", "--cookie", metavar="COOKIE",
                   help="session Cookie header value, or @file")
    b.add_argument("--no-api", action="store_true",
                   help="disable the token-based API backend")
    b.add_argument("--no-web", action="store_true",
                   help="disable the cookie-based web backend")

    t = p.add_argument_group("tuning")
    t.add_argument("-p", "--pages", type=int, default=10, metavar="N",
                   help="max result pages per backend (default 10)")
    t.add_argument("--per-page", type=int, default=100, metavar="N",
                   help="results per page, max 100 (default 100)")
    t.add_argument("-d", "--delay", type=float, default=2.0, metavar="S",
                   help="seconds between pages (default 2)")
    t.add_argument("--max-wait", type=int, default=300, metavar="S",
                   help="give up rather than sleep longer than this on a rate "
                        "limit (default 300)")
    t.add_argument("--timeout", type=float, default=30.0, metavar="S",
                   help="request timeout (default 30)")
    t.add_argument("--snippets", type=int, default=5, metavar="N",
                   help="max matching lines shown per file (default 5, 0 = all)")
    t.add_argument("--width", type=int, default=200, metavar="N",
                   help="truncate shown lines to N chars (default 200, 0 = off)")
    t.add_argument("--proxy", metavar="URL",
                   help="proxy URL, e.g. http://127.0.0.1:8080")
    t.add_argument("-k", "--insecure", action="store_true",
                   help="skip TLS verification")
    t.add_argument("-V", "--version", action="version",
                   version=f"githuntr {VERSION}")
    return p


def show_banner(args, con, backends):
    print(paint(BANNER, "head"), file=sys.stderr)
    live = " + ".join(b.name for b in backends) or "none"
    off = [n for n, d in (("api", args.no_api), ("web", args.no_web)) if d]
    if off:
        live += paint(f"   ({', '.join(off)} disabled)", "dim")
    rows = [("query", args.query),
            ("regexp", f"{args.regexp}  (case-insensitive)" if args.regexp else "-"),
            ("backends", live),
            ("pages", f"{args.pages} x {min(args.per_page, 100)} per page"),
            ("output", args.output or "-")]
    for k, v in rows:
        print(f"  {paint(k.ljust(9), 'b')} {v}", file=sys.stderr)
    print(file=sys.stderr)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    # Colour is on by default, but never into a pipe or a JSON stream.
    if args.no_color or args.json or os.environ.get("NO_COLOR") \
            or not sys.stdout.isatty():
        set_color(False)

    con = Console(args.verbosity, args.output)

    rx = None
    if args.regexp:
        try:
            rx = re.compile(args.regexp, re.IGNORECASE)
        except re.error as e:
            con.error(f"invalid regexp: {e}")
            con.close()
            return 2

    tokens = load_secrets(args.token, "GITHUB_TOKEN")
    cookie = "; ".join(load_secrets(args.cookie, "GITHUB_COOKIE"))

    backends = []
    if not args.no_api:
        if tokens:
            backends.append(ApiBackend(con, args, tokens))
        else:
            con.warn("api: no token (-t / $GITHUB_TOKEN) — GitHub code search "
                     "requires authentication, so this backend is disabled and "
                     "contributed NOTHING (not 'no results')")
    if not args.no_web:
        if cookie:
            backends.append(WebBackend(con, args, cookie))
        else:
            con.warn("web: no session cookie (-c / $GITHUB_COOKIE) — "
                     "github.com code search requires a logged-in session, so "
                     "this backend is disabled and contributed NOTHING")
    if not backends:
        con.error("no usable backend: supply -t and/or -c, and do not disable "
                  "both with --no-api --no-web")
        con.close()
        return 2

    if not args.no_banner:
        show_banner(args, con, backends)

    hunt = GitHuntr(con, args, backends, rx)
    interrupted = False
    try:
        found = hunt.run()
    except KeyboardInterrupt:
        interrupted = True
        found = len(hunt.seen)
        con.error("interrupted by user")
    finally:
        con.close()

    con.note(f"{found} unique finding(s)" + (" so far" if interrupted else ""))
    # A backend that never really ran makes an empty result set meaningless;
    # say so whatever the verbosity.
    degraded = [b.res.name for b in backends if b.res.degraded]
    if degraded:
        con.warn(f"{', '.join(degraded)} did not fully run — absence of "
                 f"findings there proves nothing")
    if interrupted:
        return 130
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
