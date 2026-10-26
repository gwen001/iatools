#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
brokhunt - hunt broken external resources (second-order / broken-link hijacking)

For every target page, brokhunt extracts every outbound resource reference
(href, src, srcset, data-src, poster, action, CSS url()/@import, inline-JS
string literals, ...), then checks each unique resource for being *dead* and,
more importantly, *claimable by a third party*.

Severity is derived from the kind of element that references the dead resource,
not from the mere fact it is dead:

    <script src>         -> code executed in the page origin   (worst case)
    <link stylesheet>    -> CSS injection / data exfiltration
    <iframe>/<object>    -> framed phishing, clickjacking
    form action / fetch  -> credential or data redirection
    <img>/<video>/icon   -> cosmetic, phishing support
    <a href>             -> broken link hijacking

A dead resource on a *registered* domain is only a broken link (INFO).
A dead resource on an *unregistered* domain, or on a third-party service with an
open namespace, is what actually gets claimed.
"""

__version__ = "0.1.0"

import argparse
import json
import os
import re
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
import urllib3

# SSL/TLS verification is disabled by design, everywhere, always.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import tldextract
    try:
        _TLD = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)
    except TypeError:                                    # very old tldextract
        _TLD = tldextract.TLDExtract(suffix_list_urls=None)
except ImportError:                                      # graceful degradation
    tldextract = None
    _TLD = None


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/140.0.0.0 Safari/537.36")

BODY_SNIPPET = 16384          # bytes read from a resource, for fingerprinting
PAGE_MAX_BYTES = 8 * 1024 * 1024

# headers never forwarded to a host other than the one they were meant for
SENSITIVE_HEADERS = {"cookie", "authorization", "proxy-authorization",
                     "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token"}

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SEV_IDX = {s: i for i, s in enumerate(SEVERITIES)}
SEV_STYLE = {"CRITICAL": ("bold", "bred"), "HIGH": ("red",), "MEDIUM": ("yellow",),
             "LOW": ("cyan",), "INFO": ("grey",)}

# resource classes, ordered by blast radius
CLS_EXEC, CLS_STYLE, CLS_FRAME, CLS_FETCH, CLS_MEDIA, CLS_NAV = \
    "exec", "style", "frame", "fetch", "media", "nav"
ALL_CLASSES = (CLS_EXEC, CLS_STYLE, CLS_FRAME, CLS_FETCH, CLS_MEDIA, CLS_NAV)

CLASS_IMPACT = {
    CLS_EXEC:  "arbitrary script executed in the page origin",
    CLS_STYLE: "CSS injection / data exfiltration in the page origin",
    CLS_FRAME: "attacker-controlled framed content",
    CLS_FETCH: "request / data flow redirected to the attacker",
    CLS_MEDIA: "attacker-controlled media shown in the page",
    CLS_NAV:   "broken link hijacking (user navigated to attacker)",
}

# severity base, per situation x resource class
# Severity depends only on the ROLE the broken reference plays in the page.
# Claimability is evaluated and reported next to the finding, but never changes
# the severity: whether a third party can really take the resource over depends
# on registrar state and on provider policies that shift over time (several
# services no longer allow a released name to be re-registered), so it is
# evidence for the analyst, not a multiplier.
# A confirmed broken reference is always reported. INFO is reserved for what
# could not be established as broken at all (timeout, connection failure, 5xx,
# unreliable DNS).
CLASS_SEVERITY = {
    CLS_EXEC:  "HIGH",      # a hijacked script runs in the page origin
    CLS_STYLE: "MEDIUM",    # css injection, exfiltration through selectors
    CLS_FRAME: "MEDIUM",    # framed phishing, clickjacking
    CLS_FETCH: "MEDIUM",    # credentials or data sent to the wrong place
    CLS_MEDIA: "LOW",       # defacement, phishing support
    CLS_NAV:   "LOW",       # broken link hijacking
}

# distinctive third-party takeover error pages only - generic "404 Not Found"
# style bodies are deliberately absent, they produce nothing but false positives
TAKEOVER_SIGNATURES = (
    ("AWS S3",          ("<Code>NoSuchBucket</Code>", "The specified bucket does not exist")),
    ("AWS S3 website",  ("NoSuchWebsiteConfiguration",)),
    ("GitHub Pages",    ("There isn't a GitHub Pages site here",)),
    ("Heroku",          ("herokucdn.com/error-pages/no-such-app.html", "No such app</")),
    ("Vercel",          ("DEPLOYMENT_NOT_FOUND", "The deployment could not be found")),
    ("Netlify",         ("Not Found - Request ID",)),
    ("Shopify",         ("Sorry, this shop is currently unavailable",)),
    ("Fastly",          ("Fastly error: unknown domain",)),
    ("Bitbucket",       ("Repository not found",)),
    ("Azure Web Apps",  ("404 Web Site not found", "Error 404 - Web app not found")),
    ("Firebase",        ("Site Not Found</h1>",)),
    ("Pantheon",        ("The gods are wise", "404 error unknown site")),
    ("Read the Docs",   ("unknown to Read the Docs",)),
    ("Tumblr",          ("Whatever you were looking for doesn't currently exist at this address",)),
    ("Ghost",           ("The thing you were looking for is no longer here",)),
    ("Surge.sh",        ("project not found",)),
    ("Zendesk",         ("Help Center Closed",)),
    ("Statuspage",      ("Status page not found",)),
    ("Webflow",         ("The page you are looking for doesn't exist or has been moved",)),
    ("Agile CRM",       ("Sorry, this page is no longer available",)),
    ("Help Scout",      ("No settings were found for this company",)),
    ("Cargo",           ("If you're moving your domain away from Cargo",)),
    ("Kinsta",          ("No Site For Domain",)),
    ("LaunchRock",      ("It looks like you may have taken a wrong turn somewhere",)),
)

# hosts whose 404 means "this name/path is free to take"
CLAIMABLE_NAMESPACES = (
    "s3.amazonaws.com", "s3.us-east-1.amazonaws.com", "amazonaws.com",
    "blob.core.windows.net", "azurewebsites.net", "cloudapp.net", "trafficmanager.net",
    "storage.googleapis.com", "appspot.com", "web.app", "firebaseapp.com",
    "github.io", "gitlab.io", "bitbucket.io",
    "herokuapp.com", "netlify.app", "vercel.app", "pages.dev", "surge.sh",
    "glitch.me", "repl.co", "readthedocs.io", "fly.dev", "onrender.com",
    "unpkg.com", "cdn.jsdelivr.net", "esm.sh", "skypack.dev",
    "myshopify.com", "zendesk.com", "statuspage.io", "helpscoutdocs.com",
)

PARKING_SIGNATURES = (
    "this domain is for sale", "buy this domain", "domain is parked",
    "parkingcrew", "sedoparking", "hugedomains", "afternic", "dan.com",
    "domain name is for sale", "ce nom de domaine est en vente",
    "this web page is parked", "godaddy.com/domainsearch",
)

# verdict labels
V_OK = "ok"
V_NXDOMAIN = "NXDOMAIN"
V_NO_ADDRESS = "NO-ADDRESS"
V_DNS_ERROR = "DNS-ERROR"
V_TIMEOUT = "TIMEOUT"
V_REFUSED = "REFUSED"
V_TLS = "TLS-ERROR"
V_NETERR = "NET-ERROR"
V_PARKED = "PARKED"
V_TAKEOVER = "TAKEOVER"

DEAD_STATUSES = (404, 410)


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

class Palette(object):
    CODES = {"reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
             "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
             "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
             "grey": "\033[90m", "bred": "\033[91m", "bgreen": "\033[92m",
             "byellow": "\033[93m", "bcyan": "\033[96m"}

    def __init__(self, enabled=True):
        self.enabled = enabled

    def __call__(self, text, *styles):
        if not self.enabled or not styles:
            return text
        pre = "".join(self.CODES.get(s, "") for s in styles)
        return (pre + text + self.CODES["reset"]) if pre else text


def render(segments, pal):
    """segments = [(text, (styles,)), ...] -> (plain, styled)"""
    plain = "".join(t for t, _ in segments)
    styled = "".join(pal(t, *s) for t, s in segments)
    return plain, styled


def sev_down(sev, n=1):
    return SEVERITIES[max(0, SEV_IDX[sev] - n)]


def fmt_elapsed(seconds):
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return "%02d:%02d:%02d" % (h, m, s) if h else "%02d:%02d" % (m, s)


def split_host_port(netloc):
    host = netloc
    port = None
    if host.startswith("["):                             # IPv6 literal
        end = host.find("]")
        if end != -1:
            port_part = host[end + 1:]
            host = host[1:end]
            if port_part.startswith(":"):
                port = port_part[1:]
    elif ":" in host:
        host, _, port = host.rpartition(":")
    return host.lower(), port


def registrable(host, strict=False):
    """Registrable domain (apex) of a host, '' for IP literals.

    strict=True returns '' when the public suffix is not in the PSL snapshot -
    used before asking a registrar about a domain, where a guess is worthless.
    Otherwise the last two labels are used as a fallback, so --ignore-host /
    --ignore-domain can never silently degrade into a no-op on an internal or
    recently created TLD missing from the snapshot.
    """
    if not host:
        return ""
    if re.match(r"^[\d.]+$", host) or ":" in host:       # IPv4 / IPv6
        return ""
    if _TLD is not None:
        ext = _TLD(host)
        if ext.domain and ext.suffix:
            return (ext.domain + "." + ext.suffix).lower()
        if strict:
            return ""
    parts = host.split(".")                              # fallback
    return ".".join(parts[-2:]).lower() if len(parts) >= 2 else host.lower()


def origin_identity(*urls):
    """Hosts and apexes that count as 'the origin' for the ignore filters.

    Both the requested URL and the URL actually reached are included: a page
    that redirects to another domain must not make the originally requested
    domain look like a third party.
    """
    hosts, apexes = set(), set()
    for url in urls:
        if not url:
            continue
        host = split_host_port(urlsplit(url).netloc)[0]
        if not host:
            continue
        hosts.add(host)
        apex = registrable(host)
        if apex:
            apexes.add(apex)
    return {"hosts": hosts, "apexes": apexes}


def in_namespace(host):
    for ns in CLAIMABLE_NAMESPACES:
        if host == ns or host.endswith("." + ns):
            return ns
    return None


BAD_HOST_CHARS = set('*,%{}$()<>"\'` \t\\|^!?=;#')


def plausible_host(host):
    """A host extracted from markup must look like a hostname.

    Policy values carry things that merely start with https:// - CSP sources,
    trusted-types allow lists, comma-joined wildcard lists, templating
    placeholders. None of them is a resource the browser fetches, and resolving
    them produces pure noise such as '*.public.onecdn.static.microsoft,https'.
    """
    if not host or len(host) > 253:
        return False
    if any(c in BAD_HOST_CHARS for c in host):
        return False
    if ":" in host:                                      # IPv6 literal
        return bool(re.match(r"^[0-9a-f:.]+$", host))
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):      # IPv4
        return True
    stripped = host.strip(".")
    if "." not in stripped:
        return False                                     # single label, not a public host
    for label in stripped.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return False
    return True


def normalise(raw, base):
    """Absolute, fragment-free http(s) URL, or None if not interesting."""
    if not raw:
        return None
    raw = raw.strip().replace("\n", "").replace("\r", "").replace("\t", "")
    if not raw or raw.startswith("#"):
        return None
    low = raw.lower()
    for bad in ("javascript:", "data:", "mailto:", "tel:", "about:", "blob:",
                "ftp:", "file:", "sms:", "callto:", "ws:", "wss:", "chrome-extension:"):
        if low.startswith(bad):
            return None
    try:
        absolute = urljoin(base, raw)
    except ValueError:
        return None
    parts = urlsplit(absolute)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    host, port = split_host_port(parts.netloc)
    if not plausible_host(host):
        return None
    if port and ((parts.scheme == "http" and port == "80") or
                 (parts.scheme == "https" and port == "443")):
        port = None
    netloc = ("[%s]" % host) if ":" in host else host
    if port:
        netloc += ":" + port
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))


def normalise_ignore_entry(item):
    """Accept whatever shape the entry is pasted in: example.com, .example.com,
    *.example.com, https://example.com/path, example.com:8443."""
    item = (item or "").strip().lower()
    if not item:
        return None
    if "://" in item:
        item = item.split("://", 1)[1]
    item = item.split("/")[0]
    if item.startswith("*."):
        item = item[2:]
    item = item.lstrip(".")
    host = split_host_port(item)[0] if item else ""
    return host or None


def parse_ignore_list(items):
    out = []
    for item in items or ():
        for part in item.split(","):
            entry = normalise_ignore_entry(part)
            if entry and entry not in out:
                out.append(entry)
    return out


def host_ignored(host, patterns):
    """Label-aligned suffix match: 'brokt.com' covers cdn.brokt.com but never
    notbrokt.com."""
    for pat in patterns:
        if host == pat or host.endswith("." + pat):
            return True
    return False


def parse_srcset(value):
    out = []
    for part in value.split(","):
        part = part.strip()
        if part:
            out.append(part.split()[0])
    return out


# ---------------------------------------------------------------------------
# HTML / CSS / JS reference extraction
# ---------------------------------------------------------------------------

CSS_URL_RE = re.compile(r"""url\(\s*['"]?([^'")\s]+)""", re.I)
CSS_IMPORT_RE = re.compile(r"""@import\s+(?:url\(\s*)?['"]([^'"]+)['"]""", re.I)
CSS_IMPORT_STRIP_RE = re.compile(r"@import[^;}]*;?", re.I)
JS_URL_RE = re.compile(r"""['"](https?://[^'"\s<>\\]{6,})['"]""")
META_REFRESH_RE = re.compile(r"""url\s*=\s*['"]?([^'";\s]+)""", re.I)

SIMPLE_MAP = {
    ("img", "src"): CLS_MEDIA, ("img", "data-src"): CLS_MEDIA,
    ("img", "data-original"): CLS_MEDIA, ("img", "longdesc"): CLS_MEDIA,
    ("image", "href"): CLS_MEDIA, ("use", "href"): CLS_MEDIA,
    ("input", "src"): CLS_MEDIA, ("track", "src"): CLS_MEDIA,
    ("video", "src"): CLS_MEDIA, ("video", "poster"): CLS_MEDIA,
    ("audio", "src"): CLS_MEDIA, ("source", "src"): CLS_MEDIA,
    ("script", "src"): CLS_EXEC,
    ("iframe", "src"): CLS_FRAME, ("frame", "src"): CLS_FRAME,
    ("embed", "src"): CLS_FRAME, ("object", "data"): CLS_FRAME,
    ("applet", "code"): CLS_FRAME, ("applet", "codebase"): CLS_FRAME,
    ("portal", "src"): CLS_FRAME,
    ("form", "action"): CLS_FETCH, ("input", "formaction"): CLS_FETCH,
    ("button", "formaction"): CLS_FETCH,
    ("a", "href"): CLS_NAV, ("area", "href"): CLS_NAV,
    ("blockquote", "cite"): CLS_NAV, ("q", "cite"): CLS_NAV,
}
# meta names/properties whose content really is a URL the browser fetches or
# follows. Anything else (CSP, trusted types, verification tokens, app ids) is
# policy or metadata, never a resource, whatever it looks like.
META_URL_KEYS = {
    "og:image", "og:image:url", "og:image:secure_url", "og:url",
    "og:video", "og:video:url", "og:video:secure_url",
    "og:audio", "og:audio:url", "og:audio:secure_url",
    "twitter:image", "twitter:image:src", "twitter:player",
    "twitter:player:stream", "twitter:url",
    "msapplication-tileimage", "msapplication-config",
    "vk:image", "thumbnail", "thumbnailurl", "image", "canonical",
    "sailthru.image.full", "sailthru.image.thumb", "shareaholic:image",
}
META_MEDIA_RE = re.compile(r"image|video|audio|tile|logo|icon|thumbnail", re.I)

SRCSET_TAGS = ("img", "source")
PRELOAD_AS = {"script": CLS_EXEC, "worker": CLS_EXEC, "style": CLS_STYLE,
              "font": CLS_MEDIA, "image": CLS_MEDIA, "video": CLS_MEDIA,
              "audio": CLS_MEDIA, "document": CLS_FRAME}

# SIMPLE_MAP indexed by tag, so a tag costs one lookup instead of a full scan
TAG_ATTRS = {}
for (_t, _a), _c in SIMPLE_MAP.items():
    TAG_ATTRS.setdefault(_t, []).append((_a, _c))


class ReferenceExtractor(HTMLParser):
    """Real tag/attribute parsing - no regex over raw HTML."""

    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.refs = []            # (raw_url, resource_class, tag, attr, element, integrity)
        self.base_href = None
        self._in_style = False
        self._in_script = False

    # -- plumbing ----------------------------------------------------------
    def _add(self, raw, cls, tag, attr, element, integrity=None):
        if raw:
            self.refs.append((raw, cls, tag, attr, element, integrity))

    @staticmethod
    def _element(tag, attrs, limit=180):
        out = "<" + tag
        for k, v in attrs:
            out += " " + k if v is None else ' %s="%s"' % (k, v)
            if len(out) > limit:
                return out[:limit] + '..."'
        return out + ">"

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        adict = {}
        for k, v in attrs:
            k = k.lower()
            if k == "xlink:href":
                k = "href"
            if k not in adict:
                adict[k] = v or ""
        element = self._element(tag, attrs)
        integrity = adict.get("integrity") or None

        if tag == "style":
            self._in_style = True
        elif tag == "script":
            self._in_script = "src" not in adict

        if tag == "base" and adict.get("href"):
            self.base_href = adict["href"]

        # inline style="... url(...) ..." - url() loads an image, a font or a
        # cursor, never executable CSS, so it is media and not CLS_STYLE
        if adict.get("style"):
            for m in CSS_URL_RE.findall(adict["style"]):
                self._add(m, CLS_MEDIA, tag, "style:url()", element)

        # <link>: meaning depends on rel
        if tag == "link":
            rel = (adict.get("rel") or "").lower().split()
            href = adict.get("href")
            if href:
                if "preconnect" in rel or "dns-prefetch" in rel:
                    pass                                 # no resource is fetched
                else:
                    if "stylesheet" in rel:
                        cls = CLS_STYLE
                    elif "modulepreload" in rel:
                        cls = CLS_EXEC
                    elif "preload" in rel:
                        cls = PRELOAD_AS.get((adict.get("as") or "").lower(), CLS_FETCH)
                    elif "manifest" in rel:
                        cls = CLS_FETCH
                    elif ("icon" in rel or "apple-touch-icon" in rel
                          or "mask-icon" in rel or "shortcut" in rel):
                        cls = CLS_MEDIA
                    elif "prefetch" in rel or "prerender" in rel:
                        cls = CLS_FETCH
                    else:
                        cls = CLS_NAV
                    self._add(href, cls, "link", "rel=%s" % (rel[0] if rel else "?"),
                              element, integrity)

        # <meta content="...">
        if tag == "meta":
            content = adict.get("content") or ""
            key = (adict.get("property") or adict.get("name")
                   or adict.get("itemprop") or "").lower()
            if (adict.get("http-equiv") or "").lower() == "refresh":
                m = META_REFRESH_RE.search(content)
                if m:
                    self._add(m.group(1), CLS_NAV, "meta", "refresh", element)
            elif key in META_URL_KEYS and re.match(r"^\s*(https?:)?//", content):
                cls = CLS_MEDIA if META_MEDIA_RE.search(key) else CLS_NAV
                self._add(content, cls, "meta", key, element)

        # srcset
        if tag in SRCSET_TAGS:
            for key in ("srcset", "data-srcset"):
                if adict.get(key):
                    for cand in parse_srcset(adict[key]):
                        self._add(cand, CLS_MEDIA, tag, key, element)

        # plain attribute map
        for attr, cls in TAG_ATTRS.get(tag, ()):
            if adict.get(attr):
                self._add(adict[attr], cls, tag, attr, element, integrity)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "style":
            self._in_style = False
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_style:
            # @import pulls in real CSS -> CLS_STYLE. A bare url() pulls in an
            # image, a font, a cursor or a mask -> CLS_MEDIA. Conflating the two
            # inflated every dead font into a "CSS injection" finding.
            for m in CSS_IMPORT_RE.findall(data):
                self._add(m, CLS_STYLE, "style", "@import", "<style> @import")
            for m in CSS_URL_RE.findall(CSS_IMPORT_STRIP_RE.sub("", data)):
                self._add(m, CLS_MEDIA, "style", "url()", "<style> url()")
        elif self._in_script and len(data) < 2_000_000:
            for m in JS_URL_RE.findall(data):
                self._add(m, CLS_FETCH, "script", "inline-js", "<script> string literal")


def extract_references(html_text, page_url):
    parser = ReferenceExtractor()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception:
        pass                                             # keep whatever was parsed
    base = page_url
    if parser.base_href:
        try:
            base = urljoin(page_url, parser.base_href.strip())
        except ValueError:
            pass
    out = []
    for raw, cls, tag, attr, element, integrity in parser.refs:
        url = normalise(raw, base)
        if url:
            out.append({"url": url, "class": cls, "tag": tag, "attr": attr,
                        "element": element, "integrity": integrity})
    return out


# ---------------------------------------------------------------------------
# rate limiting, DNS cache, registrar lookup
# ---------------------------------------------------------------------------

class RateLimiter(object):
    """Minimum gap between any two requests, enforced globally."""

    def __init__(self, delay):
        self.delay = float(delay or 0)
        self.lock = threading.Lock()
        self.last = 0.0

    def wait(self):
        if self.delay <= 0:
            return
        with self.lock:
            now = time.monotonic()
            gap = self.last + self.delay - now
            if gap > 0:
                time.sleep(gap)
                now = self.last + self.delay
            self.last = now


class DnsCache(object):
    """Resolution with bounded concurrency, confirmation of negative answers,
    and no caching of transient failures.

    A local resolver under heavy concurrency (systemd-resolved, dnsmasq, a
    rate-limiting upstream) returns EAI_NONAME for names that resolve perfectly
    well a moment later. Trusting a single lookup and caching it for the whole
    run turns a live domain into a reported NXDOMAIN, so a negative is accepted
    only when several consecutive lookups agree, and lookups are throttled so
    the resolver is not the thing that breaks first.
    """

    NXDOMAIN_ERRNOS = {getattr(socket, "EAI_NONAME", -2)}
    NODATA_ERRNOS = {getattr(socket, "EAI_NODATA", -5)}
    TRANSIENT_ERRNOS = {getattr(socket, "EAI_AGAIN", -3),      # temporary failure
                        getattr(socket, "EAI_FAIL", -4),       # SERVFAIL
                        getattr(socket, "EAI_SYSTEM", -11),
                        getattr(socket, "EAI_MEMORY", -10)}

    MAX_CONCURRENT = 8
    NEGATIVE_ATTEMPTS = 3
    RETRY_BACKOFF = 0.3

    def __init__(self, max_concurrent=None):
        self.cache = {}
        self.lock = threading.Lock()
        self.gate = threading.Semaphore(max_concurrent or self.MAX_CONCURRENT)
        self.counts = {"hosts": 0, "negative": 0, "rescued": 0, "unreliable": 0}

    def _lookup(self, host):
        try:
            with self.gate:
                # SOCK_STREAM avoids the duplicate entries getaddrinfo returns
                # once per socket type
                socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM)
            return "ok"
        except socket.gaierror as exc:
            msg = str(exc).lower()
            if exc.errno in self.TRANSIENT_ERRNOS or "temporary failure" in msg:
                return V_DNS_ERROR
            if exc.errno in self.NODATA_ERRNOS or "no address associated" in msg:
                return V_NO_ADDRESS
            if exc.errno in self.NXDOMAIN_ERRNOS or "not known" in msg or "no such host" in msg:
                return V_NXDOMAIN
            return V_DNS_ERROR
        except UnicodeError:
            return V_NXDOMAIN                    # invalid IDN / oversized label
        except Exception:
            return V_DNS_ERROR

    def resolve(self, host):
        """-> 'ok' | V_NXDOMAIN | V_NO_ADDRESS | V_DNS_ERROR"""
        with self.lock:
            if host in self.cache:
                return self.cache[host]

        tries = [self._lookup(host)]
        while tries[-1] != "ok" and len(tries) < self.NEGATIVE_ATTEMPTS:
            time.sleep(self.RETRY_BACKOFF * len(tries))
            tries.append(self._lookup(host))

        if "ok" in tries:
            verdict = "ok"
        elif all(v == tries[0] for v in tries):
            verdict = tries[0]                   # every attempt agreed
        else:
            verdict = V_DNS_ERROR                # attempts disagreed: unreliable

        with self.lock:
            self.counts["hosts"] += 1
            if verdict == "ok" and len(tries) > 1:
                self.counts["rescued"] += 1
            elif verdict in (V_NXDOMAIN, V_NO_ADDRESS):
                self.counts["negative"] += 1
            elif verdict == V_DNS_ERROR:
                self.counts["unreliable"] += 1
            # a transient failure is never cached: the next reference retries
            if verdict != V_DNS_ERROR:
                self.cache[host] = verdict
        return verdict


class GandiChecker(object):
    """Domain availability through the Gandi v5 API. GANDI_KEY required.

    Every outcome is either an answer or a stated reason. An inconclusive
    lookup is never reported as "unverified, run --check-domains": the caller
    gets the reason so the finding can say what actually happened.
    """

    ENDPOINT = "https://api.gandi.net/v5/domain/check"
    MAX_ATTEMPTS = 4
    TAKEN_STATUSES = ("reserved", "pending", "error_eoi", "error_premium",
                      "error_forbidden", "error_unknown_tld_status")

    def __init__(self, key, timeout, proxies, reporter, gap=1.0):
        self.key = key
        self.timeout = timeout
        self.proxies = proxies
        self.reporter = reporter
        self.scheme = "Apikey"
        self.scheme_locked = False
        self.cache = {}
        self.reasons = {}
        self.lock = threading.Lock()
        self.limiter = RateLimiter(gap)
        self.base_gap = gap
        self.ok_streak = 0
        self.disabled = False
        self.counts = {"queries": 0, "available": 0, "taken": 0, "inconclusive": 0}
        self.first_failure = None
        self.session = requests.Session()
        self.session.trust_env = False       # -x is the only proxy control

    # -- public ------------------------------------------------------------
    def available(self, domain):
        """True / False / None. On None, reason_for(domain) says why."""
        if not domain:
            return None
        if self.disabled:
            with self.lock:
                self.reasons.setdefault(domain, "registrar checks disabled after an auth error")
            return None
        with self.lock:
            if domain in self.cache:
                return self.cache[domain]

        verdict, reason = self._query(domain)

        if verdict is not None:
            self._speed_up()

        with self.lock:
            self.cache[domain] = verdict
            self.counts["queries"] += 1
            if verdict is True:
                self.counts["available"] += 1
            elif verdict is False:
                self.counts["taken"] += 1
            else:
                self.counts["inconclusive"] += 1
                self.reasons[domain] = reason or "no answer"
                if self.first_failure is None:
                    self.first_failure = "%s: %s" % (domain, reason or "no answer")
        return verdict

    def reason_for(self, domain):
        with self.lock:
            return self.reasons.get(domain)

    # -- internals ---------------------------------------------------------
    @staticmethod
    def _retry_after(resp, attempt):
        header = resp.headers.get("Retry-After")
        if header:
            try:
                return max(0.5, min(float(header), 30.0))
            except ValueError:
                pass
        return min(0.8 * (2 ** (attempt - 1)), 10.0)

    def _slow_down(self):
        """A rate limit means the whole run is too fast, not just this call."""
        with self.lock:
            self.ok_streak = 0
            self.limiter.delay = min(max(self.limiter.delay, 0.5) * 2, 5.0)
            return self.limiter.delay

    def _speed_up(self):
        """Decay back towards the configured gap, so one burst of 429s does not
        penalise every remaining lookup of the run."""
        with self.lock:
            self.ok_streak += 1
            if self.ok_streak >= 5 and self.limiter.delay > self.base_gap:
                self.ok_streak = 0
                self.limiter.delay = max(self.base_gap, self.limiter.delay / 2)

    def _query(self, domain):
        """-> (True|False|None, reason or None)"""
        flipped = False
        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            self.limiter.wait()
            try:
                resp = self.session.get(
                    self.ENDPOINT, params={"name": domain},
                    headers={"Authorization": "%s %s" % (self.scheme, self.key),
                             "Accept": "application/json"},
                    timeout=self.timeout, verify=False, proxies=self.proxies)
            except Exception as exc:
                if attempt == self.MAX_ATTEMPTS:
                    return None, "request to the registrar failed: %s" % type(exc).__name__
                self.reporter.debug("gandi: %s -> %s, retrying" % (domain, exc))
                time.sleep(0.5 * attempt)
                continue

            code = resp.status_code
            self.reporter.debug("gandi: %s -> HTTP %d (attempt %d, %s)"
                                % (domain, code, attempt, self.scheme))

            # the key may be a legacy API key or a personal access token: try
            # the other scheme once, without spending the retry budget
            if code in (401, 403) and not flipped and not self.scheme_locked:
                flipped = True
                with self.lock:
                    self.scheme = "Bearer" if self.scheme == "Apikey" else "Apikey"
                self.reporter.debug("gandi: retrying with Authorization: %s" % self.scheme)
                continue
            if code in (401, 403):
                self.disabled = True
                self.reporter.warn("[!] the registrar rejected GANDI_KEY (HTTP %d) - "
                                   "availability checks are now disabled" % code)
                return None, "GANDI_KEY rejected (HTTP %d)" % code

            if code == 429 or code >= 500:
                wait = self._retry_after(resp, attempt)
                if code == 429:
                    wait = max(wait, self._slow_down())
                if attempt == self.MAX_ATTEMPTS:
                    return None, ("registrar answered HTTP %d on %d attempts - rate limit "
                                  "or outage" % (code, attempt))
                self.reporter.trace("[.] registrar HTTP %d on %s, waiting %.1fs"
                                    % (code, domain, wait))
                time.sleep(wait)
                continue

            if code != 200:
                return None, "registrar answered HTTP %d: %s" % (
                    code, " ".join(resp.text[:120].split()))

            if not flipped:
                self.scheme_locked = True        # this scheme works, stop probing

            try:
                data = resp.json()
            except ValueError:
                return None, "registrar returned a non-JSON response"

            products = data.get("products") or []
            if not products:
                return None, "registrar returned no product for this TLD"

            statuses = []
            for product in products:
                status = (product.get("status") or "").lower()
                statuses.append(status or "?")
                if status.startswith("available"):
                    return True, None
                if status.startswith("unavailable") or status in self.TAKEN_STATUSES:
                    return False, None
            return None, "registrar status not understood: %s" % ",".join(statuses)

        return None, "no answer from the registrar after %d attempts" % self.MAX_ATTEMPTS


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

class Reporter(object):
    def __init__(self, palette, verbosity, text_path):
        self.pal = palette
        self.verbosity = verbosity
        self.lock = threading.Lock()
        self.fh = open(text_path, "w", encoding="utf-8") if text_path else None

    def emit(self, segments):
        self.emit_block([segments])

    def emit_block(self, lines):
        """Write several lines as one atomic unit, so concurrent findings never
        interleave in the middle of a block."""
        plains, styleds = [], []
        for segments in lines:
            plain, styled = render(segments, self.pal)
            plains.append(plain)
            styleds.append(styled)
        with self.lock:
            sys.stdout.write("\n".join(styleds) + "\n")
            sys.stdout.flush()
            if self.fh:
                self.fh.write("\n".join(plains) + "\n")
                self.fh.flush()

    def plain(self, text, *styles):
        self.emit([(text, styles)])

    def warn(self, text):
        if self.verbosity >= 0:
            self.emit([(text, ("byellow",))])

    def trace(self, text):
        if self.verbosity >= 1:
            self.emit([(text, ("grey",))])

    def debug(self, text):
        if self.verbosity >= 2:
            self.emit([(text, ("dim", "grey"))])

    def status(self, text):
        sys.stderr.write(text + "\n")
        sys.stderr.flush()

    def close(self):
        if self.fh:
            self.fh.close()
            self.fh = None


# ---------------------------------------------------------------------------
# assessment
# ---------------------------------------------------------------------------

def assess(res, origin):
    """Fill res['severity'], res['notes'] and the claimability fields.

    Severity comes from the role of the broken reference. Claimability is
    reported separately and deliberately has no weight: provider policies on
    reusing a released name change over time, so a namespace error page is a
    lead to verify, not a severity multiplier.
    """
    cls = res["class"]
    verdict = res["verdict"]
    status = res.get("status")
    host = res["host"]
    apex = res["registrable"]
    if apex:
        same_apex = apex in origin["apexes"]
    else:                                                # IP literal
        same_apex = host in origin["hosts"]

    notes = []
    broken = False

    # ---- is the reference broken? this is what decides the severity -------
    if verdict == V_TAKEOVER:
        broken = True
        notes.append("dead: the third-party service answered with a namespace error page")
    elif verdict == V_NXDOMAIN:
        broken = True
        notes.append("dead: %s does not resolve" % host)
    elif verdict == V_NO_ADDRESS:
        broken = True
        notes.append("dead: %s exists in DNS but has no address record" % host)
    elif verdict == V_PARKED:
        broken = True
        notes.append("dead: the domain answers with a parking / for-sale page")
    elif status in DEAD_STATUSES:
        broken = True
        notes.append("dead: HTTP %d" % status)
    elif verdict in (V_TIMEOUT, V_REFUSED, V_TLS, V_NETERR, V_DNS_ERROR):
        notes.append("undetermined: %s - transport failure, not established as broken"
                     % verdict)
    elif status and status >= 500:
        notes.append("undetermined: HTTP %d - server error, not established as broken" % status)
    elif status and status >= 400:
        notes.append("undetermined: HTTP %d - the resource answers, not established as broken"
                     % status)

    severity = CLASS_SEVERITY[cls] if broken else "INFO"

    if broken:
        notes.append("if a third party can serve it: %s" % CLASS_IMPACT[cls])

    if res.get("integrity") and cls in (CLS_EXEC, CLS_STYLE):
        severity = sev_down(severity, 2)
        notes.append("subresource integrity present - hijacking is neutralised unless the "
                     "hash is controlled too")

    # ---- claimability: reported, never weighed ---------------------------
    claim, claim_note = "n/a", None
    if verdict == V_TAKEOVER:
        # checked before same_apex on purpose: a namespace error page on a host
        # inside the target's own domain is the classic subdomain takeover, and
        # the provider name is the whole point of the finding
        claim = "service"
        claim_note = ("%s namespace error page - verify by hand whether this provider still "
                      "lets a released name be re-registered" % res.get("takeover_service"))
        if same_apex:
            claim_note += "; host is in the target's own domain, so look for a dangling CNAME"
    elif same_apex:
        claim_note = ("host sits inside the target's own registrable domain, so the name "
                      "cannot be registered by a third party - check the CNAME target by hand")
    elif verdict == V_PARKED:
        claim = "parked"
        claim_note = "the domain has most likely already expired and changed hands"
    elif verdict in (V_NXDOMAIN, V_NO_ADDRESS):
        avail = res.get("domain_available")
        if avail is True:
            claim = "confirmed"
            claim_note = "%s is unregistered and available at the registrar" % apex
        elif avail is False:
            claim = "registered"
            claim_note = "%s is registered, only this host is dead" % apex
        elif res.get("apex_dns") in (V_NXDOMAIN, V_NO_ADDRESS):
            claim = "likely"
            if res.get("domain_check_error"):
                claim_note = ("%s does not resolve either - the registrar lookup was "
                              "inconclusive (%s)" % (apex, res["domain_check_error"]))
            elif res.get("domain_check"):
                claim_note = ("%s does not resolve either - the registrar gave no verdict"
                              % apex)
            else:
                claim_note = ("%s does not resolve either - registration unverified, run "
                              "--check-domains to confirm" % apex)
        else:
            claim = "registered"
            claim_note = ("%s resolves, only this host is dead - verify the CNAME target "
                          "by hand" % apex)
    elif broken and res.get("namespace"):
        claim = "namespace"
        claim_note = ("inside %s, an open namespace - verify by hand whether the bucket / "
                      "app / package name can be re-registered" % res["namespace"])
    elif broken:
        claim = "registered"
        claim_note = "%s is registered - broken reference, nothing obvious to claim" % (
            apex or host)

    res["broken"] = broken
    res["situation"] = "broken" if broken else "undetermined"
    res["claimability"] = claim
    res["claim_note"] = claim_note
    res["severity"] = severity
    res["notes"] = notes
    return severity


# ---------------------------------------------------------------------------
# the scanner
# ---------------------------------------------------------------------------

class Target(object):
    def __init__(self, url, method="GET", headers=None, body=None):
        self.url = url
        self.method = method
        self.headers = headers or {}
        self.body = body


class Brokhunt(object):
    def __init__(self, args, reporter, palette):
        self.args = args
        self.rep = reporter
        self.pal = palette
        self.limiter = RateLimiter(args.delay)
        self.dns = DnsCache(max_concurrent=max(8, args.threads))
        self.local = threading.local()
        self.proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

        self.extra_headers = parse_header_list(args.header or [])
        self.ignore_list = parse_ignore_list(args.ignore)
        self.auth_global = {}
        self.auth_by_host = {}
        if args.auth_file:
            self.auth_global = load_header_file(args.auth_file)
        if args.auth_dir:
            self.auth_by_host = load_auth_dir(args.auth_dir, self.rep)

        self.gandi = None
        if args.check_domains:
            self.gandi = GandiChecker(os.environ["GANDI_KEY"], args.timeout,
                                      self.proxies, self.rep)

        self.target_hosts = set()
        self.seen_lock = threading.Lock()
        self.stat_lock = threading.Lock()
        self.seen = {}                                   # url -> finding dict or None
        self.findings = []
        self.stats = {"pages_done": 0, "pages_failed": 0, "refs": 0,
                      "checked": 0, "findings": 0, "ignored": 0, "offsite": 0}
        self.sev_counts = {s: 0 for s in SEVERITIES}
        self.started = time.time()
        self.stop = threading.Event()
        self.total_pages = 0

    def bump(self, key, amount=1):
        with self.stat_lock:
            self.stats[key] += amount

    def bump_sev(self, severity):
        with self.stat_lock:
            self.sev_counts[severity] += 1

    # -- http --------------------------------------------------------------
    @property
    def session(self):
        sess = getattr(self.local, "sess", None)
        if sess is None:
            sess = requests.Session()
            sess.trust_env = False
            sess.max_redirects = 10
            self.local.sess = sess
        return sess

    def headers_for(self, url, base=None, cross_host=False):
        host, port = split_host_port(urlsplit(url).netloc)
        scheme = urlsplit(url).scheme
        port = port or ("443" if scheme == "https" else "80")

        hdrs = {"User-Agent": DEFAULT_UA, "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        if base:
            hdrs.update(base)
        # -H is global, but credentials are never leaked off-host
        for k, v in self.extra_headers.items():
            if cross_host and k.lower() in SENSITIVE_HEADERS:
                continue
            hdrs[k] = v
        if self.auth_global and (not cross_host or host in self.target_hosts):
            hdrs.update(self.auth_global)
        for key in ("%s_%s" % (host, port), host):
            if key in self.auth_by_host:
                hdrs.update(self.auth_by_host[key])
                break
        return hdrs

    def log_request(self, method, url, headers, body=None):
        if self.args.verbose < 2:
            return
        lines = ["    > %s %s" % (method, url)]
        lines += ["    > %s: %s" % (k, v) for k, v in headers.items()]
        if body:
            lines.append("    > ")
            lines.append("    > %s" % (body[:500] if isinstance(body, str)
                                       else body[:500].decode("utf-8", "replace")))
        self.rep.debug("\n".join(lines))

    def log_response(self, resp):
        if self.args.verbose < 2 or resp is None:
            return
        lines = ["    < HTTP %d %s" % (resp.status_code, resp.reason or "")]
        lines += ["    < %s: %s" % (k, v) for k, v in resp.headers.items()]
        self.rep.debug("\n".join(lines))

    # -- page --------------------------------------------------------------
    def fetch_page(self, target):
        hdrs = self.headers_for(target.url, base=target.headers, cross_host=False)
        # a page fetch asks for HTML, unless the user or the raw request said otherwise
        explicit = {k.lower() for k in (target.headers or {})} | \
                   {k.lower() for k in self.extra_headers}
        if "accept" not in explicit:
            hdrs["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        body = target.body
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.limiter.wait()
        self.log_request(target.method, target.url, hdrs, body)
        resp = self.session.request(target.method, target.url, headers=hdrs, data=body,
                                    timeout=self.args.timeout, verify=False,
                                    allow_redirects=True, proxies=self.proxies, stream=True)
        try:
            chunks, size = [], 0
            for chunk in resp.iter_content(65536):
                chunks.append(chunk)
                size += len(chunk)
                if size >= PAGE_MAX_BYTES:
                    break
            raw = b"".join(chunks)
            encoding = resp.encoding or resp.apparent_encoding or "utf-8"
            text = raw.decode(encoding, "replace")
            self.log_response(resp)
            return resp, text
        finally:
            resp.close()

    def scan_page(self, target):
        if self.stop.is_set():
            return
        try:
            resp, html_text = self.fetch_page(target)
        except Exception as exc:
            self.bump("pages_failed")
            self.rep.trace("[-] %s -> %s" % (target.url, type(exc).__name__))
            self.bump("pages_done")
            return

        ctype = (resp.headers.get("Content-Type") or "").lower()
        if ("html" not in ctype and "xml" not in ctype
                and "<" not in html_text[:512]):
            self.rep.trace("[.] %s -> %s, nothing to parse" % (target.url, ctype or "?"))
            self.bump("pages_done")
            return

        page_url = resp.url or target.url

        # requests follows redirects, so a target can land on a domain that was
        # never in the list. Parsing that page would pull in every reference of
        # a third party and scan it - out of scope by accident.
        req_host = split_host_port(urlsplit(target.url).netloc)[0]
        fin_host = split_host_port(urlsplit(page_url).netloc)[0]
        if (registrable(fin_host) or fin_host) != (registrable(req_host) or req_host):
            if not self.args.allow_offsite:
                self.rep.warn("[!] %s redirected off-domain to %s - page not parsed "
                              "(--allow-offsite to follow)" % (target.url, page_url))
                self.bump("offsite")
                self.bump("pages_done")
                return
            self.rep.trace("[.] %s redirected off-domain to %s - following (--allow-offsite)"
                           % (target.url, page_url))
            self.bump("offsite")

        refs = extract_references(html_text, page_url)
        self.bump("refs", len(refs))
        self.rep.trace("[*] %s -> HTTP %d, %d references"
                       % (page_url, resp.status_code, len(refs)))

        origin = origin_identity(target.url, page_url)
        self.rep.debug("    origin identity: hosts=%s apexes=%s"
                       % (sorted(origin["hosts"]), sorted(origin["apexes"])))

        todo = self.filter_refs(refs, page_url, origin)
        if todo:
            futures = [LINK_POOL.submit(self.check_reference, ref, target.url, page_url,
                                        origin) for ref in todo]
            for fut in futures:
                try:
                    fut.result()
                except Exception as exc:
                    self.rep.debug("check failed: %s" % exc)
        self.bump("pages_done")

    def filter_refs(self, refs, page_url, origin):
        out, local_seen = [], set()
        for ref in refs:
            url = ref["url"]
            if url == page_url:
                continue
            host = split_host_port(urlsplit(url).netloc)[0]
            if self.ignore_list and host_ignored(host, self.ignore_list):
                self.rep.debug("ignore list skipping: %s" % url)
                self.bump("ignored")
                continue
            if self.args.ignore_host and host in origin["hosts"]:
                self.rep.debug("skip same host: %s" % url)
                continue
            if self.args.ignore_domain:
                res_apex = registrable(host)
                # an IP literal has no registrable domain: same IP counts as same
                # domain, so the flag is never a silent no-op
                same = (res_apex in origin["apexes"]) if res_apex \
                    else (host in origin["hosts"])
                if same:
                    self.rep.debug("skip same domain: %s" % url)
                    continue
            if url in local_seen:
                continue
            local_seen.add(url)
            out.append(ref)
        return out

    # -- resource ----------------------------------------------------------
    def check_reference(self, ref, origin_url, final_url, origin):
        if self.stop.is_set():
            return
        url = ref["url"]
        with self.seen_lock:
            if url in self.seen:
                known = self.seen[url]
                if known is not None and origin_url not in known["origins"]:
                    known["origins"].append(origin_url)
                    if final_url and final_url != origin_url:
                        known["origin_redirects"][origin_url] = final_url
                return
            self.seen[url] = None

        res = self.probe(url)
        res.update({"class": ref["class"], "tag": ref["tag"], "attr": ref["attr"],
                    "element": ref["element"], "integrity": ref["integrity"],
                    "origins": [origin_url],
                    "origin_redirects": ({origin_url: final_url}
                                         if final_url and final_url != origin_url else {})})
        self.bump("checked")

        if res["verdict"] == V_NXDOMAIN and res["registrable"]:
            res["apex_dns"] = (self.dns.resolve(res["registrable"])
                               if res["registrable"] != res["host"] else V_NXDOMAIN)
            if self.gandi and res["apex_dns"] in (V_NXDOMAIN, V_NO_ADDRESS):
                # only ask a registrar about a PSL-confirmed apex, never a guess
                apex = registrable(res["host"], strict=True)
                if apex:
                    res["domain_check"] = True
                    res["domain_available"] = self.gandi.available(apex)
                    if res["domain_available"] is None:
                        res["domain_check_error"] = self.gandi.reason_for(apex)
                else:
                    res["domain_check_error"] = (
                        "no public suffix for %s, a registrar lookup would be a guess"
                        % res["host"])

        severity = assess(res, origin)
        self.bump_sev(severity)

        if severity == "INFO":
            self.report_test(res)
            with self.seen_lock:
                self.seen[url] = res
            return

        with self.seen_lock:
            self.seen[url] = res
            self.findings.append(res)
        self.bump("findings")
        self.report_finding(res)

    def probe(self, url):
        parts = urlsplit(url)
        host = split_host_port(parts.netloc)[0]
        res = {"url": url, "host": host, "registrable": registrable(host),
               "namespace": in_namespace(host), "status": None, "verdict": V_OK,
               "final_url": None, "length": None, "content_type": None,
               "takeover_service": None, "apex_dns": None, "domain_available": None,
               "domain_check": False, "domain_check_error": None}

        dns_verdict = self.dns.resolve(host) if res["registrable"] or host else "ok"
        if dns_verdict != "ok":
            res["verdict"] = dns_verdict
            return res

        # credentials follow the target host only, never a third-party domain
        hdrs = self.headers_for(url, cross_host=(host not in self.target_hosts))
        try:
            self.limiter.wait()
            self.log_request("GET", url, hdrs)
            resp = self.session.get(url, headers=hdrs, timeout=self.args.timeout,
                                    verify=False, allow_redirects=True,
                                    proxies=self.proxies, stream=True)
        except requests.exceptions.SSLError:
            res["verdict"] = V_TLS
            return res
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
            res["verdict"] = V_TIMEOUT
            return res
        except requests.exceptions.ConnectionError as exc:
            msg = str(exc).lower()
            res["verdict"] = V_REFUSED if ("refused" in msg or "reset" in msg) else V_NETERR
            return res
        except Exception:
            res["verdict"] = V_NETERR
            return res

        try:
            chunks, size = [], 0
            for chunk in resp.iter_content(8192):
                chunks.append(chunk)
                size += len(chunk)
                if size >= BODY_SNIPPET:
                    break
            snippet = b"".join(chunks).decode(resp.encoding or "utf-8", "replace")
            res["status"] = resp.status_code
            res["final_url"] = resp.url
            res["length"] = int(resp.headers.get("Content-Length") or size)
            res["content_type"] = (resp.headers.get("Content-Type") or "-").split(";")[0]
            self.log_response(resp)
        finally:
            resp.close()

        low = snippet.lower()
        server = (resp.headers.get("Server") or "").lower()
        for service, needles in TAKEOVER_SIGNATURES:
            for needle in needles:
                if needle.lower() in low:
                    res["verdict"] = V_TAKEOVER
                    res["takeover_service"] = service
                    return res
        for needle in PARKING_SIGNATURES:
            if needle in low or needle in server:
                res["verdict"] = V_PARKED
                return res
        res["verdict"] = V_OK if res["status"] < 400 else "HTTP-%d" % res["status"]
        return res

    # -- output ------------------------------------------------------------
    def report_test(self, res):
        if self.args.verbose < 1:
            return
        verdict = res["verdict"] if res["verdict"] != V_OK else str(res.get("status") or "-")
        if verdict.startswith("HTTP-"):
            verdict = verdict[5:]
        self.rep.emit([("[%-8s] " % "ok", ("grey",)),
                       ("%-12s " % verdict, ("grey",)),
                       ("%-22s " % ("%s[%s]" % (res["tag"], res["attr"]))[:22], ("grey",)),
                       (res["url"], ("grey",))])

    def report_finding(self, res):
        sev = res["severity"]
        style = SEV_STYLE[sev]
        verdict = res["verdict"]
        if verdict.startswith("HTTP-"):
            verdict = verdict[5:]
        tagref = ("%s[%s]" % (res["tag"], res["attr"]))[:22]
        requested = res["origins"][0]

        def label(name):
            return ("           %-11s " % name, ("grey",))

        block = [[("[%-8s] " % sev, style),
                  ("%-12s " % verdict, style),
                  ("%-22s " % tagref, ("bcyan",)),
                  (res["url"], ("bold",))],
                 [label("origin"), (requested, ())]]
        # the page the reference was really read from, when a redirect moved it
        landed = (res.get("origin_redirects") or {}).get(requested)
        if landed:
            block.append([label("redirection"), (landed, ("byellow",))])
        if res.get("element"):
            block.append([label("element"), (res["element"], ("dim",))])
        if res.get("status"):
            meta = "HTTP %s  %s  %s bytes" % (res["status"], res.get("content_type") or "-",
                                              res.get("length"))
            block.append([label("response"), (meta, ("grey",))])
        if res.get("claim_note"):
            block.append([label("claim"),
                          ("%-10s " % res.get("claimability", "n/a"), ("magenta",)),
                          (res["claim_note"], ())])
        for note in res.get("notes", []):
            block.append([label("why"), (note, ())])
        self.rep.emit_block(block)

    def status_line(self):
        done = self.stats["pages_done"]
        total = self.total_pages
        self.rep.status("[status %s]  tested %d/%d  remaining %d  findings %d"
                        % (fmt_elapsed(time.time() - self.started), done, total,
                           max(total - done, 0), self.stats["findings"]))

    def summary(self):
        counts = ", ".join("%s %d" % (s, self.sev_counts[s])
                           for s in reversed(SEVERITIES) if self.sev_counts[s] and s != "INFO")
        self.rep.plain("")
        self.rep.plain("[+] done in %s  pages %d/%d (%d failed)  references %d  "
                       "unique checked %d  findings %d%s"
                       % (fmt_elapsed(time.time() - self.started), self.stats["pages_done"],
                          self.total_pages, self.stats["pages_failed"], self.stats["refs"],
                          self.stats["checked"], self.stats["findings"],
                          ("  [%s]" % counts) if counts else ""), "bgreen")

        if self.gandi:
            g = self.gandi.counts
            self.rep.plain("[+] registrar: %d domain(s) checked, %d available, %d taken, "
                           "%d inconclusive" % (g["queries"], g["available"], g["taken"],
                                                g["inconclusive"]), "grey")
            if g["inconclusive"]:
                self.rep.warn("[!] %d registrar lookup(s) gave no verdict, first one - %s"
                              % (g["inconclusive"], self.gandi.first_failure))

        if self.stats["ignored"]:
            self.rep.plain("[+] %d reference(s) skipped by -i/--ignore"
                           % self.stats["ignored"], "grey")
        if self.stats["offsite"]:
            self.rep.plain("[+] %d target(s) redirected off-domain (%s)"
                           % (self.stats["offsite"],
                              "followed" if self.args.allow_offsite else "not parsed"), "grey")

        dns = self.dns.counts
        if dns["rescued"] or dns["unreliable"]:
            self.rep.plain("[+] dns: %d host(s), %d negative, %d rescued by retry, "
                           "%d unreliable (not reported)"
                           % (dns["hosts"], dns["negative"], dns["rescued"],
                              dns["unreliable"]), "grey")
        if dns["hosts"] >= 25 and dns["negative"] > dns["hosts"] * 0.5:
            self.rep.warn("[!] %d of %d hosts came back as not resolving - your resolver is "
                          "probably rate-limiting. Re-check the NXDOMAIN findings with a "
                          "lower -t or a -d delay before trusting them."
                          % (dns["negative"], dns["hosts"]))

    # -- run ---------------------------------------------------------------
    def run(self, targets):
        self.total_pages = len(targets)
        self.target_hosts = {split_host_port(urlsplit(t.url).netloc)[0] for t in targets}

        ticker = None
        if self.total_pages > 1 and self.args.status_interval > 0:
            ticker = threading.Thread(target=self._ticker, daemon=True)
            ticker.start()

        pool = ThreadPoolExecutor(max_workers=max(1, self.args.threads))
        try:
            futures = [pool.submit(self.scan_page, t) for t in targets]
            for fut in futures:
                fut.result()
        except KeyboardInterrupt:
            self.stop.set()
            raise
        finally:
            self.stop.set()
            try:
                pool.shutdown(wait=False, cancel_futures=True)
            except TypeError:                            # python < 3.9
                pool.shutdown(wait=False)
        if ticker:
            ticker.join(timeout=1)

    def _ticker(self):
        while not self.stop.wait(self.args.status_interval):
            self.status_line()


LINK_POOL = None          # shared, bounded: avoids the threads^2 explosion


# ---------------------------------------------------------------------------
# inputs: headers, auth files, raw requests, target lists
# ---------------------------------------------------------------------------

def parse_header_list(items):
    out = {}
    for item in items:
        if ":" not in item:
            raise SystemExit("[-] bad header (expected 'Name: value'): %r" % item)
        name, _, value = item.partition(":")
        out[name.strip()] = value.strip()
    return out


def load_header_file(path):
    out = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or ":" not in line:
                    continue
                name, _, value = line.partition(":")
                out[name.strip()] = value.strip()
    except OSError as exc:
        raise SystemExit("[-] cannot read %s: %s" % (path, exc))
    return out


def load_auth_dir(path, reporter):
    """host.txt -> every port of that host ; host_8080.txt -> that port only."""
    if not os.path.isdir(path):
        raise SystemExit("[-] not a directory: %s" % path)
    table = {}
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        if not os.path.isfile(full):
            continue
        key = name[:-4] if name.lower().endswith(".txt") else name
        headers = load_header_file(full)
        if headers:
            table[key.lower()] = headers
            reporter.trace("[+] auth for %s: %d header(s)" % (key, len(headers)))
    if not table:
        reporter.warn("[!] no usable auth file found in %s" % path)
    return table


def parse_raw_request(path, force_ssl):
    """Burp / ZAP raw request export -> Target."""
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError as exc:
        raise SystemExit("[-] cannot read %s: %s" % (path, exc))

    blob = blob.replace(b"\r\n", b"\n")
    head, _, body = blob.partition(b"\n\n")
    lines = head.decode("utf-8", "replace").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        raise SystemExit("[-] %s is empty" % path)

    bits = lines[0].split()
    if len(bits) < 2:
        raise SystemExit("[-] %s: cannot parse the request line %r" % (path, lines[0]))
    method, path_part = bits[0].upper(), bits[1]

    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip()] = value.strip()

    host = None
    for name, value in headers.items():
        if name.lower() == "host":
            host = value.strip()
            break

    scheme = "http"
    if force_ssl:
        scheme = "https"
    else:
        for name in ("Origin", "Referer"):
            for hname, value in headers.items():
                if hname.lower() == name.lower() and value.lower().startswith("https://"):
                    scheme = "https"
    if path_part.lower().startswith(("http://", "https://")):      # absolute-form
        url = path_part
        if force_ssl:
            url = "https://" + url.split("://", 1)[1]
    else:
        if not host:
            raise SystemExit("[-] %s: no Host header and no absolute URL" % path)
        url = "%s://%s%s" % (scheme, host, path_part if path_part.startswith("/")
                             else "/" + path_part)

    for drop in [k for k in headers
                 if k.lower() in ("content-length", "transfer-encoding", "connection",
                                  "accept-encoding", "if-none-match", "if-modified-since")]:
        headers.pop(drop)

    text_body = body.decode("utf-8", "replace") if body.strip() else None
    return Target(url, method=method, headers=headers, body=text_body)


def load_targets(args):
    if args.raw:
        return [parse_raw_request(args.raw, args.force_ssl)]

    raw_list = []
    if args.url:
        raw_list = [args.url]
    else:
        try:
            with open(args.list, encoding="utf-8", errors="replace") as fh:
                raw_list = [line.strip() for line in fh]
        except OSError as exc:
            raise SystemExit("[-] cannot read %s: %s" % (args.list, exc))

    targets, seen = [], set()
    for item in raw_list:
        if not item or item.startswith("#"):
            continue
        if not re.match(r"^https?://", item, re.I):
            item = ("https://" if args.force_ssl else "http://") + item
        url = normalise(item, item)
        if url and url not in seen:
            seen.add(url)
            targets.append(Target(url))
    if not targets:
        raise SystemExit("[-] no usable target")
    return targets


# ---------------------------------------------------------------------------
# json report
# ---------------------------------------------------------------------------

def write_json(path, scanner, args):
    payload = {
        "tool": "brokhunt",
        "version": __version__,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(scanner.started)),
        "finished": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "duration_seconds": round(time.time() - scanner.started, 2),
        "options": {"threads": args.threads, "timeout": args.timeout, "delay": args.delay,
                    "ignore_host": args.ignore_host, "ignore_domain": args.ignore_domain,
                    "ignore": scanner.ignore_list,
                    "check_domains": args.check_domains, "proxy": args.proxy},
        "stats": dict(scanner.stats, severities={s: scanner.sev_counts[s] for s in SEVERITIES}),
        "findings": [],
    }
    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    for res in sorted(scanner.findings, key=lambda r: order[r["severity"]]):
        payload["findings"].append({
            "severity": res["severity"],
            "situation": res["situation"],
            "broken": res.get("broken"),
            "claimability": res.get("claimability"),
            "claimability_note": res.get("claim_note"),
            "verdict": res["verdict"],
            "http_status": res.get("status"),
            "url": res["url"],
            "final_url": res.get("final_url"),
            "host": res["host"],
            "registrable_domain": res["registrable"],
            "domain_available": res.get("domain_available"),
            "domain_check_error": res.get("domain_check_error"),
            "apex_dns": res.get("apex_dns"),
            "takeover_service": res.get("takeover_service"),
            "claimable_namespace": res.get("namespace"),
            "resource_class": res["class"],
            "tag": res["tag"],
            "attribute": res["attr"],
            "element": res.get("element"),
            "subresource_integrity": res.get("integrity"),
            "content_type": res.get("content_type"),
            "content_length": res.get("length"),
            "origins": res["origins"],
            "origin_redirects": res.get("origin_redirects") or {},
            "notes": res.get("notes", []),
        })
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    except OSError as exc:
        sys.stderr.write("[-] cannot write %s: %s\n" % (path, exc))


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

EPILOG = """\
severity model
  severity comes from the ROLE the broken reference plays in the page, and from
  nothing else:
    HIGH    script[src], modulepreload, worker   runs in the page origin
    MEDIUM  link stylesheet, @import             css injection / exfiltration
    MEDIUM  iframe, object, embed                framed phishing, clickjacking
    MEDIUM  form action, formaction, preload     data sent to the wrong place
    LOW     img, video, font, icon, url(), meta  defacement, phishing support
    LOW     a href                               broken link hijacking
  subresource integrity on a script or a stylesheet drops it two levels.
  a bare url() in CSS loads an image, a font or a cursor, never executable css,
  so it is LOW - only @import and link rel=stylesheet are style.
  INFO is reserved for what could not be established as broken at all (timeout,
  connection failure, 403, 5xx, unreliable DNS).

claimability
  reported on its own "claim" line and in the JSON, never folded into the
  severity, because whether a released name can really be taken over depends on
  registrar state and on provider policy, and several services no longer allow
  a name to be re-registered. Treat it as a lead to verify:
    confirmed   the registrar says the domain is available (--check-domains)
    likely      the registrable domain does not resolve, registration unverified
    service     a third-party namespace error page, provider named
    namespace   404 inside an open namespace (bucket, app, package)
    parked      the domain answers with a parking / for-sale page
    registered  the name is taken, nothing obvious to claim
    n/a         the host is inside the target's own registrable domain

notes
  - a target that redirects to another registrable domain is NOT parsed, so a
    webmail redirecting to a cloud provider never drags that provider's whole
    page into the scan. --allow-offsite opts in.
  - -i/--ignore is the noise filter: -i gouv.fr,cdn.jsdelivr.net drops every
    reference on those domains and their subdomains, whatever the origin.
    --ignore-host / --ignore-domain are relative to the page being scanned.
  - TLS verification is disabled for every request, always.
  - -H is applied to every request, but Cookie / Authorization style headers are
    never forwarded to a host other than the target, to avoid leaking a session
    to third-party domains.
  - -r replays the request as-is (method, cookies, body) so authenticated pages
    can be fetched; brokhunt injects nothing.
  - -t is the number of concurrent pages; resource checks run in a separate
    bounded pool (max(10, 5*threads)) so concurrency never explodes.
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="brokhunt.py",
        description="hunt broken external resources (second-order / broken-link hijacking)",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG)
    p.add_argument("-v", "--verbose", type=int, choices=(0, 1, 2), default=0,
                   help="verbosity: 0 = only successes (default), 1 = every test performed, "
                        "2 = debug (full request)")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-u", dest="url", metavar="URL", help="single URL to test")
    src.add_argument("-l", dest="list", metavar="LIST",
                     help="file containing a list of URLs to test")
    src.add_argument("-r", dest="raw", metavar="FILE",
                     help="raw HTTP request file (Burp/ZAP export): method, headers "
                          "(Cookie...) and body are replayed as-is")
    p.add_argument("--allow-offsite", action="store_true",
                   help="parse a target that redirected to another registrable domain. Off by "
                        "default: following such a redirect scans a third party that was never "
                        "in your list")
    p.add_argument("--force-ssl", action="store_true",
                   help="force https for a -r request (default: http, derived from "
                        "Origin/Referer); also forces https on bare hostnames from -u/-l")
    p.add_argument("-t", "--threads", type=int, default=5,
                   help="concurrent URLs to scan (default 5)")
    p.add_argument("--timeout", type=float, default=7, help="request timeout (s)")
    p.add_argument("-d", "--delay", type=float, default=0,
                   help="minimum gap between requests (s), enforced globally across all threads")
    p.add_argument("-H", "--header", action="append", metavar="HEADER",
                   help="extra header 'Name: value' (repeatable) - also how to set a Cookie "
                        "or override the User-Agent")
    p.add_argument("-x", "--proxy", metavar="PROXY",
                   help="proxy URL, e.g. http://127.0.0.1:8080")
    auth = p.add_mutually_exclusive_group()
    auth.add_argument("--auth-file", metavar="FILE",
                      help="headers to authenticate with, -H syntax, one per line, "
                           "'#' for comments. Applied to EVERY target whatever the file "
                           "is called")
    auth.add_argument("--auth-dir", metavar="DIR",
                      help="directory of auth files named after the host they authenticate: "
                           "www.example.com.txt covers every port of that host, "
                           "www.example.com_8080.txt covers that port only and wins over it. "
                           "No subdomain inheritance")
    p.add_argument("-o", "--output", metavar="OUTPUT",
                   help="write TEXT report to this file (identical to standard output)")
    p.add_argument("--json", "--output-json", dest="json_out", metavar="OUTPUT",
                   help="write JSON report to this file (only findings)")
    p.add_argument("--status-interval", type=float, default=30, metavar="SEC",
                   help="seconds between status lines in -l mode (default 30)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("-i", "--ignore", action="append", metavar="DOMAIN|HOST",
                   help="comma separated domains/hosts whose links and resources are never "
                        "tested (repeatable). Label-aligned suffix match, so 'gouv.fr' also "
                        "covers every *.gouv.fr and 'cdn.example.com' covers its subdomains. "
                        "Accepts example.com, .example.com, *.example.com, "
                        "https://example.com/, example.com:8443")
    p.add_argument("--ignore-host", action="store_true",
                   help="ignore links/resources on the same host (subdomain) as the origin URL")
    p.add_argument("--ignore-domain", action="store_true",
                   help="ignore links/resources on the same domain as the origin URL")
    p.add_argument("--check-domains", action="store_true",
                   help="check domain availability via Gandi (requires GANDI_KEY)")
    p.add_argument("--version", action="version", version="brokhunt %s" % __version__)
    return p


def main(argv=None):
    global LINK_POOL
    args = build_parser().parse_args(argv)

    if args.check_domains and not os.environ.get("GANDI_KEY"):
        raise SystemExit("[-] --check-domains needs the GANDI_KEY environment variable")
    if args.threads < 1:
        raise SystemExit("[-] --threads must be >= 1")

    palette = Palette(enabled=not args.no_color and not os.environ.get("NO_COLOR"))
    reporter = Reporter(palette, args.verbose, args.output)

    if tldextract is None:
        reporter.warn("[!] tldextract is not installed, falling back to a naive "
                      "two-label domain split (pip install tldextract)")

    exit_code = 0
    try:
        targets = load_targets(args)
        scanner = Brokhunt(args, reporter, palette)
        LINK_POOL = ThreadPoolExecutor(max_workers=max(10, args.threads * 5))

        reporter.plain("[+] brokhunt %s - %d target(s), %d thread(s)%s"
                       % (__version__, len(targets), args.threads,
                          ", gandi availability check on" if args.check_domains else ""), "bgreen")
        if scanner.ignore_list:
            reporter.plain("[+] ignoring %d domain/host pattern(s): %s"
                           % (len(scanner.ignore_list), ", ".join(scanner.ignore_list)), "grey")
        if args.verbose >= 1:
            reporter.plain("[+] legend: [SEVERITY] verdict tag[attr] resource-url", "grey")

        try:
            scanner.run(targets)
        except KeyboardInterrupt:
            reporter.plain("")
            reporter.warn("[!] interrupted, reporting what was found so far")
            exit_code = 130
        finally:
            LINK_POOL.shutdown(wait=False)

        scanner.summary()
        if args.json_out:
            write_json(args.json_out, scanner, args)
            reporter.plain("[+] json report: %s" % args.json_out, "grey")
        if args.output:
            reporter.plain("[+] text report: %s" % args.output, "grey")
        if scanner.stats["findings"]:
            exit_code = exit_code or 1
    finally:
        reporter.close()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
