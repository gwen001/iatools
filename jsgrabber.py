#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
js_grabber.py — Récupère les fichiers JavaScript inclus dans une ou plusieurs pages.

Pour chaque URL source : télécharge le HTML, extrait les <script src=...> (plus
les <link rel=preload/modulepreload as=script>), résout les URLs (absolue,
relative à la racine, ou relative au dossier courant) et enregistre chaque JS
sous <output-dir>/<host source>/<nom_fichier>.

Affichage (une ligne par JS, aussi écrite dans le fichier de log --output) :
    <url du js> [host de l'url source] [status] [content length]
Couleur du status : 2xx vert, 3xx bleu, autre rouge.

En mode liste (-l), une ligne de statut s'affiche à intervalle régulier :
    [status 01:00]  downloaded 12/27614  remaining 27602

Outil de recon défensif : à n'utiliser que sur des cibles autorisées (ROE).

Dépendances : requests  (pip install requests)
              jsbeautifier  (optionnel, pour --beautify : pip install jsbeautifier)
"""

import argparse
import os
import re
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse, unquote
from html.parser import HTMLParser

try:
    import requests
except ImportError:
    sys.stderr.write("[X] Module 'requests' manquant : pip install requests\n")
    sys.exit(2)

HTTP_TIMEOUT = 20
# User-Agent navigateur réaliste : certains WAF/edge servent une page allégée
# ou un challenge (donc sans scripts) aux UA non-navigateur.
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
# En-têtes navigateur par défaut. Accept-Encoding limité à ce que requests sait
# toujours décoder (gzip/deflate) pour éviter un corps brotli/zstd non décodé
# qui rendrait le HTML illisible et masquerait les scripts.
DEFAULT_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate",
}

# --- couleurs ---
GREEN, BLUE, RED, CYAN, RESET = "\033[92m", "\033[94m", "\033[91m", "\033[96m", "\033[0m"
COLOR = True

# --- état global ---
WRITE_LOCK = threading.Lock()   # réservation de nom + écriture fichier
EMIT_LOCK = threading.Lock()    # sortie stdout + log non entrelacés
LOG_FH = None                   # fichier de log (--output)
_beautify_warned = False

DONE = 0                        # nb d'URLs sources traitées
DONE_LOCK = threading.Lock()
TOTAL = 0                       # nb d'URLs sources en entrée
START_TS = 0.0


# ----------------------------------------------------------------------------- sortie (tee)
def emit(plain, colored=None):
    """Écrit sur stdout (coloré si activé) ET dans le log (toujours en clair)."""
    with EMIT_LOCK:
        sys.stdout.write((colored if (COLOR and colored) else plain) + "\n")
        sys.stdout.flush()
        if LOG_FH:
            LOG_FH.write(plain + "\n")
            LOG_FH.flush()


def color_status(code):
    s = f"[{code}]"
    if not COLOR:
        return s
    if isinstance(code, int) and 200 <= code < 300:
        return GREEN + s + RESET
    if isinstance(code, int) and 300 <= code < 400:
        return BLUE + s + RESET
    return RED + s + RESET


def fmt_elapsed():
    m, s = divmod(int(time.time() - START_TS), 60)
    return f"{m:02d}:{s:02d}"


def status_line():
    with DONE_LOCK:
        done = DONE
    txt = f"[status {fmt_elapsed()}]  downloaded {done}/{TOTAL}  remaining {TOTAL - done}"
    emit(txt, CYAN + txt + RESET)


# ----------------------------------------------------------------------------- parsing HTML
class ScriptExtractor(HTMLParser):
    """Collecte <script src>, <link rel=preload/modulepreload as=script>."""
    def __init__(self):
        super().__init__()
        self.srcs = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.srcs.append(a["src"].strip())
        elif tag == "link":
            rel = (a.get("rel") or "").lower()
            as_ = (a.get("as") or "").lower()
            href = a.get("href")
            if href and ("modulepreload" in rel or (rel == "preload" and as_ == "script")):
                self.srcs.append(href.strip())


def resolve(src, base_url):
    """
    Reconstruit l'URL absolue d'un script.
      - commence par http/https  -> absolue, telle quelle
      - commence par //           -> relative au schéma (protocol-relative)
      - commence par /            -> relative à la RACINE du site courant
      - sinon                     -> relative au DOSSIER courant de la page
    urljoin() applique exactement cette résolution (RFC 3986) à partir de base_url.
    """
    return urljoin(base_url, src)


def extract_js_urls(html, base_url):
    p = ScriptExtractor()
    try:
        p.feed(html)
    except Exception:
        pass
    seen, out = set(), []
    for s in p.srcs:
        if not s or s.startswith(("data:", "javascript:", "blob:")):
            continue
        full = resolve(s, base_url)
        if urlparse(full).scheme not in ("http", "https"):
            continue
        if full not in seen:
            seen.add(full)
            out.append(full)
    return out


# ----------------------------------------------------------------------------- nommage fichier
def safe_filename(js_url):
    name = unquote(os.path.basename(urlparse(js_url).path))
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("._") or "script"
    if not os.path.splitext(name)[1]:
        name += ".js"
    return name


def reserve_path(dirpath, name):
    """Réserve un chemin unique (sous verrou). main.js -> main.1.js -> main.2.js ..."""
    root, ext = os.path.splitext(name)
    with WRITE_LOCK:
        os.makedirs(dirpath, exist_ok=True)
        candidate = os.path.join(dirpath, name)
        i = 1
        while True:
            try:
                fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                os.close(fd)
                return candidate
            except FileExistsError:
                candidate = os.path.join(dirpath, f"{root}.{i}{ext}")
                i += 1


# ----------------------------------------------------------------------------- beautify
def maybe_beautify(data):
    global _beautify_warned
    try:
        import jsbeautifier
    except ImportError:
        if not _beautify_warned:
            _beautify_warned = True
            sys.stderr.write("[!] --beautify demandé mais 'jsbeautifier' absent "
                             "(pip install jsbeautifier) — JS enregistré brut.\n")
        return data
    try:
        return jsbeautifier.beautify(data.decode("utf-8", "replace")).encode("utf-8")
    except Exception:
        return data


# ----------------------------------------------------------------------------- worker
def process_source(url, session, outdir, beautify, follow=True, verify=True):
    global DONE
    try:
        host = urlparse(url).netloc or url
        host_dir = re.sub(r"[^A-Za-z0-9._:-]", "_", host).replace(":", "_")
        lines = []  # (plain, colored)

        try:
            r = session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=follow, verify=verify)
        except requests.RequestException as e:
            emit(f"[X] source {url} : {e}")
            return

        js_urls = extract_js_urls(r.text, r.url)
        if not js_urls:
            ct = r.headers.get("Content-Type", "?")
            ce = r.headers.get("Content-Encoding", "-")
            emit(f"[-] {url} : aucun script externe trouvé "
                 f"(HTTP {r.status_code}, {ct}, enc={ce}, {len(r.content)} octets)")
            return

        for ju in js_urls:
            try:
                jr = session.get(ju, timeout=HTTP_TIMEOUT, allow_redirects=follow, verify=verify)
                data = jr.content
                status, length = jr.status_code, len(data)
                if beautify:
                    data = maybe_beautify(data)
                dest = reserve_path(os.path.join(outdir, host_dir), safe_filename(ju))
                with open(dest, "wb") as f:
                    f.write(data)
                plain = f"[{host}] {ju} [{status}] [{length}]"
                colored = f"[{host}] {ju} {color_status(status)} [{length}]"
                lines.append((plain, colored))
            except requests.RequestException as e:
                plain = f"[{host}] {ju} [ERR] [-]  ({e.__class__.__name__})"
                colored = f"[{host}] {ju} {color_status('ERR')} [-]  ({e.__class__.__name__})"
                lines.append((plain, colored))

        # flush groupé (une source = un bloc)
        with EMIT_LOCK:
            for plain, colored in lines:
                sys.stdout.write((colored if COLOR else plain) + "\n")
                if LOG_FH:
                    LOG_FH.write(plain + "\n")
            sys.stdout.flush()
            if LOG_FH:
                LOG_FH.flush()
    finally:
        with DONE_LOCK:
            DONE += 1


# ----------------------------------------------------------------------------- statut périodique
def status_worker(stop_event, interval):
    while not stop_event.wait(interval):
        with DONE_LOCK:
            if DONE >= TOTAL:
                return
        status_line()


# ----------------------------------------------------------------------------- CLI
def parse_headers(items):
    hdrs = {}
    for h in items:
        if ":" not in h:
            sys.stderr.write(f"[X] en-tête invalide (format 'Name: value') : {h!r}\n")
            sys.exit(2)
        name, value = h.split(":", 1)
        name = name.strip()
        if not name:
            sys.stderr.write(f"[X] nom d'en-tête vide : {h!r}\n")
            sys.exit(2)
        hdrs[name] = value.strip()
    return hdrs


def load_lines(path):
    with open(path, encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def normalize(u):
    return u if urlparse(u).scheme else "https://" + u


def main():
    global COLOR, LOG_FH, TOTAL, START_TS

    ap = argparse.ArgumentParser(
        description="Récupère les JS inclus dans des pages — usage autorisé uniquement.")
    ap.add_argument("-u", "--url", help="single url")
    ap.add_argument("-l", "--list", help="file of url, one per line")
    ap.add_argument("-t", "--threads", type=int, default=5,
                    help="concurrent targets (default 5)")
    ap.add_argument("-H", "--header", action="append", default=[], metavar="HEADER",
                    help="extra header 'Name: value' (repeatable)")
    ap.add_argument("--output-dir", default="js",
                    help="dossier de stockage des JS (défaut: js)")
    ap.add_argument("--output", default="js.txt",
                    help="fichier de log = copie de la sortie standard (défaut: js.txt)")
    ap.add_argument("--status-interval", type=int, default=30, metavar="SEC",
                    help="seconds between status lines in -l mode (default 30)")
    ap.add_argument("--beautify", action="store_true",
                    help="beautify downloaded js (défaut: off)")
    ap.add_argument("--no-color", action="store_true",
                    help="disable coloured output (colour is on by default)")
    ap.add_argument("--no-follow-redirects", action="store_true",
                    help="do not follow HTTP redirects (followed by default)")
    args = ap.parse_args()

    if not args.url and not args.list:
        ap.error("fournir une URL avec -u, ou un fichier avec -l")
    if args.threads < 1:
        ap.error("--threads doit être >= 1")
    if args.status_interval < 1:
        ap.error("--status-interval doit être >= 1")

    COLOR = not args.no_color

    urls = []
    if args.url:
        urls.append(normalize(args.url))
    if args.list:
        try:
            urls.extend(normalize(u) for u in load_lines(args.list))
        except OSError as e:
            sys.stderr.write(f"[X] Lecture de {args.list} impossible : {e}\n")
            sys.exit(2)
    if not urls:
        sys.stderr.write("[X] Aucune URL à traiter.\n")
        sys.exit(2)

    try:
        LOG_FH = open(args.output, "w", encoding="utf-8")
    except OSError as e:
        sys.stderr.write(f"[X] Ouverture du log {args.output} impossible : {e}\n")
        sys.exit(2)

    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    session.headers.update(parse_headers(args.header))  # -H peut surcharger les défauts
    # Vérification TLS TOUJOURS désactivée (verify=False passé explicitement à
    # chaque requête, fiable même si un CA bundle est imposé par l'environnement).
    verify = False
    try:
        requests.packages.urllib3.disable_warnings()
    except Exception:
        pass
    follow = not args.no_follow_redirects

    TOTAL = len(urls)
    START_TS = time.time()

    # Thread de statut : uniquement en mode liste (-l).
    stop_event = threading.Event()
    status_thread = None
    if args.list:
        status_thread = threading.Thread(
            target=status_worker, args=(stop_event, args.status_interval), daemon=True)
        status_thread.start()

    workers = min(args.threads, len(urls))
    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for u in urls:
                ex.submit(process_source, u, session, args.output_dir, args.beautify, follow, verify)
    finally:
        stop_event.set()
        if status_thread:
            status_thread.join(timeout=2)
            status_line()  # ligne de statut finale (100%)
        if LOG_FH:
            LOG_FH.close()


if __name__ == "__main__":
    main()
