#!/usr/bin/env python3
"""
gigya_audit.py — Audit de configuration SAP Customer Data Cloud (Gigya)

Teste, pour une ou plusieurs apiKey, l'exposition côté client de méthodes
sensibles de l'API CDC. Outil d'audit défensif : à n'utiliser QUE sur des
tenants pour lesquels tu disposes d'une autorisation écrite (ROE).

Tests réalisés :
  - accounts.getSchema      -> ROUGE si succès (errorCode 0). Affiche errorMessage.
  - accounts.getPolicies    -> ROUGE si succès (errorCode 0). Affiche errorMessage.
  - accounts.search         -> ROUGE si totalCount > 0.        Affiche total.
  - accounts.otp.sendCode   -> ROUGE si autorisé.              Affiche message.

Note importante sur otp.sendCode : le script N'ENVOIE PAS d'OTP réel.
Il appelle la méthode SANS destinataire et lit l'errorCode :
  * 403xxx  -> refusé par l'ACL           => non exploitable (pas de finding)
  * 0 / 400xxx (param manquant/invalide)  -> la porte d'ACL est franchie
                                             => exploitable (finding), zéro envoi.

Domaine d'API : avec -d, on teste ce domaine uniquement. Sans -d, on teste
toutes les régions connues (prod + staging) et on lance les tests partout où
la clé est reconnue.

Dépendance : requests  (pip install requests)
"""

import argparse
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

try:
    import requests
except ImportError:
    sys.stderr.write("[X] Module 'requests' manquant : pip install requests\n")
    sys.exit(2)

# Domaines d'API CDC testés par défaut (prod + staging, toutes régions).
API_DOMAINS = [
    "accounts.au1-st1.gigya.com",
    "accounts.au1-st2.gigya.com",
    "accounts.au1-st4.gigya.com",
    "accounts.au1.gigya.com",
    "accounts.eu1-st1.gigya.com",
    "accounts.eu1-st2.gigya.com",
    "accounts.eu1-st4.gigya.com",
    "accounts.eu1.gigya.com",
    "accounts.gigya.com",
    "accounts.us1-st1.gigya.com",
    "accounts.us1-st2.gigya.com",
    "accounts.us1-st4.gigya.com",
    "accounts.us1.gigya.com",
]

# errorCodes indiquant que la clé n'existe PAS sur ce domaine (mauvaise région).
WRONG_KEY_CODES = {400093, 301001}
WRONG_KEY_HINTS = ("api key does not exist", "invalid apikey", "wrong data center", "data center")

HTTP_TIMEOUT = 15
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"


# ----------------------------------------------------------------------------- couleurs
class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    enabled = True

    @classmethod
    def wrap(cls, s, color):
        if not cls.enabled:
            return s
        return f"{color}{s}{cls.RESET}"


# ----------------------------------------------------------------------------- verbosité / sortie
VERBOSITY = 0  # 0 findings only, 1 every test, 2 debug

# Buffer de sortie propre au thread : chaque clé écrit dans son propre buffer,
# flushé en un bloc sous verrou pour ne pas entrelacer les threads.
_tls = threading.local()
PRINT_LOCK = threading.Lock()


def log(level, msg):
    if VERBOSITY >= level:
        buf = getattr(_tls, "buf", None)
        if buf is None:
            print(msg)
        else:
            buf.append(msg)


# ----------------------------------------------------------------------------- HTTP
def call(domain, method, params, session):
    """Appelle une méthode CDC sur un domaine. Renvoie (json_dict | None, info)."""
    url = f"https://{domain}/{method}"
    p = dict(params)
    p["format"] = "json"
    try:
        r = session.get(url, params=p, timeout=HTTP_TIMEOUT)
    except requests.RequestException as e:
        return None, f"ERREUR RÉSEAU: {e}"
    try:
        return r.json(), r.text
    except ValueError:
        return None, f"HTTP {r.status_code} (réponse non-JSON, {len(r.text)} octets)"


def err_code(j):
    try:
        return int(j.get("errorCode"))
    except (TypeError, ValueError, AttributeError):
        return None


def is_wrong_key(j):
    """True si la réponse indique que la clé n'existe pas sur ce domaine."""
    code = err_code(j)
    msg = str(j.get("errorMessage", "")).lower()
    return code in WRONG_KEY_CODES or any(h in msg for h in WRONG_KEY_HINTS)


# ----------------------------------------------------------------------------- affichage tests
def finding_line(method, detail):
    return "  " + C.wrap(f"[!] {method:<24} {detail}", C.RED)


def refused_line(method, detail):
    # v1 : trace des tests refusés, en gris neutre (pas de vert).
    return "  " + C.wrap(f"[-] {method:<24} {detail}", C.DIM)


# ----------------------------------------------------------------------------- tests
def eval_simple(method, j):
    """getSchema / getPolicies : finding si errorCode == 0. Utilise un JSON déjà obtenu."""
    if j is None:
        log(1, refused_line(method, "pas de réponse JSON exploitable"))
        return False
    code = err_code(j)
    msg = j.get("errorMessage", "")
    if code == 0:
        log(0, finding_line(method, f"SUCCÈS  errorMessage=\"{msg}\""))
        return True
    log(2, C.wrap(f"      [debug] {method}: rejeté errorCode={code} '{msg}'", C.DIM))
    log(1, refused_line(method, f"refusé  errorMessage=\"{msg}\" (errorCode={code})"))
    return False


def test_simple_success(domain, method, apikey, session):
    j, raw = call(domain, method, {"apiKey": apikey}, session)
    if j is None:
        log(2, C.wrap(f"      [debug] {method}: {raw}", C.DIM))
    return eval_simple(method, j)


def test_search(domain, apikey, session):
    """accounts.search count(*) : finding si totalCount > 0."""
    method = "accounts.search"
    j, raw = call(domain, method, {"apiKey": apikey, "query": "SELECT count(*) FROM accounts"}, session)
    if j is None:
        log(2, C.wrap(f"      [debug] {method}: {raw}", C.DIM))
        log(1, refused_line(method, "pas de réponse JSON exploitable"))
        return False
    code = err_code(j)
    msg = j.get("errorMessage", "")
    total = j.get("totalCount")
    if code == 0 and isinstance(total, int) and total > 0:
        log(0, finding_line(method, f"total={total}  (base interrogeable sans auth)"))
        return True
    if code == 0:
        log(2, C.wrap(f"      [debug] {method}: errorCode=0 mais totalCount={total}", C.DIM))
        log(1, refused_line(method, f"autorisé mais total={total}"))
        return False
    log(2, C.wrap(f"      [debug] {method}: rejeté errorCode={code} '{msg}'", C.DIM))
    log(1, refused_line(method, f"refusé  errorMessage=\"{msg}\" (errorCode={code})"))
    return False


def test_otp(domain, apikey, session):
    """
    accounts.otp.sendCode : finding si l'ACL est franchie. NON DESTRUCTIF
    (aucun destinataire -> aucun OTP envoyé).
      403xxx      -> refusé (pas de finding)
      0 / 400xxx  -> autorisé (finding), requête non aboutie faute de params.
    """
    method = "accounts.otp.sendCode"
    j, raw = call(domain, method, {"apiKey": apikey}, session)
    if j is None:
        log(2, C.wrap(f"      [debug] {method}: {raw}", C.DIM))
        log(1, refused_line(method, "pas de réponse JSON exploitable"))
        return False
    code = err_code(j)
    msg = j.get("errorMessage", "")
    # Garde-fou : une clé invalide sur ce domaine n'est jamais un finding.
    if is_wrong_key(j):
        log(2, C.wrap(f"      [debug] {method}: clé invalide ici (errorCode={code})", C.DIM))
        return False
    denied = code is not None and 403000 <= code <= 403999
    if not denied:
        state = "envoyé" if code == 0 else "autorisé (porte d'ACL franchie, 0 envoi)"
        log(0, finding_line(method, f"{state}  message=\"{msg}\" (errorCode={code})"))
        return True
    log(2, C.wrap(f"      [debug] {method}: refusé errorCode={code} '{msg}'", C.DIM))
    log(1, refused_line(method, f"refusé  message=\"{msg}\" (errorCode={code})"))
    return False


# ----------------------------------------------------------------------------- pilotage
def run_all(domain, apikey, session, schema_json):
    """Lance les 4 tests sur un domaine, renvoie le nombre de findings."""
    n = 0
    n += 1 if eval_simple("accounts.getSchema", schema_json) else 0
    n += 1 if test_simple_success(domain, "accounts.getPolicies", apikey, session) else 0
    n += 1 if test_search(domain, apikey, session) else 0
    n += 1 if test_otp(domain, apikey, session) else 0
    return n


def audit_key(apikey, domains, session):
    """Teste une clé sur les domaines fournis. Renvoie la liste des lignes à afficher."""
    key_out = []
    _tls.buf = key_out
    try:
        apikey = apikey.strip()
        if not apikey:
            return key_out
        seen_valid = False

        for domain in domains:
            # Sonde de validité (réutilisée comme test getSchema).
            schema_json, raw = call(domain, "accounts.getSchema", {"apiKey": apikey}, session)
            if schema_json is None:
                log(2, C.wrap(f"      [debug] {domain}: {raw}", C.DIM))
                continue
            if is_wrong_key(schema_json):
                log(2, C.wrap(f"      [debug] {domain}: clé absente ici "
                              f"(errorCode={err_code(schema_json)})", C.DIM))
                continue

            seen_valid = True
            header = f"[*] {apikey}   (domain: {domain})"

            # Tests dans un buffer de domaine, pour décider ensuite d'afficher l'en-tête.
            domain_buf = []
            _tls.buf = domain_buf
            n = run_all(domain, apikey, session, schema_json)
            _tls.buf = key_out

            if VERBOSITY >= 1 or n > 0:
                key_out.append(C.wrap(header, C.BOLD))
                key_out.extend(domain_buf)

        if not seen_valid:
            log(0, C.wrap(f"[X] {apikey} : clé reconnue sur aucun domaine testé "
                          f"(clé invalide, région absente de la liste, ou WAF ?)", C.YELLOW))
    finally:
        _tls.buf = None
    return key_out


def load_keys(path):
    keys = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                keys.append(line)
    return keys


def main():
    ap = argparse.ArgumentParser(
        description="Audit d'exposition d'API SAP CDC (Gigya) — usage autorisé uniquement.")
    ap.add_argument("-v", type=int, choices=[0, 1, 2], default=0,
                    help="0 = confirmed findings only (default), 1 = every test, "
                         "2 = debug (shows why candidates were rejected)")
    ap.add_argument("-k", "--key", help="single key")
    ap.add_argument("-l", "--list", help="file of keys, one per line")
    ap.add_argument("-d", "--domain",
                    help="api domain to test (e.g. accounts.eu1.gigya.com); "
                         "default: test all known regions")
    ap.add_argument("-t", "--threads", type=int, default=5,
                    help="concurrent targets (default 5)")
    ap.add_argument("-H", "--header", action="append", default=[], metavar="HEADER",
                    help="extra header 'Name: value' (repeatable)")
    ap.add_argument("--no-color", action="store_true",
                    help="disable coloured output (colour is on by default)")
    args = ap.parse_args()

    global VERBOSITY
    VERBOSITY = args.v
    C.enabled = not args.no_color

    if not args.key and not args.list:
        ap.error("fournir une clé avec -k, ou un fichier avec -l")
    if args.threads < 1:
        ap.error("--threads doit être >= 1")

    extra_headers = {}
    for h in args.header:
        if ":" not in h:
            ap.error(f"en-tête invalide (format attendu 'Name: value') : {h!r}")
        name, value = h.split(":", 1)
        name = name.strip()
        if not name:
            ap.error(f"nom d'en-tête vide : {h!r}")
        extra_headers[name] = value.strip()

    keys = []
    if args.key:
        keys.append(args.key)
    if args.list:
        try:
            keys.extend(load_keys(args.list))
        except OSError as e:
            sys.stderr.write(f"[X] Lecture de {args.list} impossible : {e}\n")
            sys.exit(2)

    if not keys:
        sys.stderr.write("[X] Aucune clé à tester.\n")
        sys.exit(2)

    domains = [args.domain] if args.domain else API_DOMAINS

    session = requests.Session()
    session.headers.update({"User-Agent": UA})
    session.headers.update(extra_headers)  # -H : peut surcharger l'UA si besoin

    workers = min(args.threads, len(keys))
    log(1, C.wrap(f"# {len(keys)} clé(s) x {len(domains)} domaine(s) — "
                  f"{workers} thread(s) — verbosité {VERBOSITY}", C.DIM))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        # ex.map préserve l'ordre des clés ; chaque bloc est flushé en entier
        # sous verrou pour éviter tout entrelacement entre threads.
        for key_out in ex.map(lambda k: audit_key(k, domains, session), keys):
            if key_out:
                with PRINT_LOCK:
                    for line in key_out:
                        print(line)


if __name__ == "__main__":
    main()
