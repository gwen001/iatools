#!/usr/bin/env python3
"""
filter_pentest.py
-----------------
Filtre les résultats de fuzzing web en éliminant les réponses "baseline"
(hosts qui retournent toujours la même chose quoiqu'il arrive).

Format d'entrée attendu :
  url [code] [content-length] [content-type] [title optionnel]

Usage :
  python3 filter_pentest.py <input_file> [output_file] [--seuil N] [--verbose]

Exemples :
  python3 filter_pentest.py results.txt
  python3 filter_pentest.py results.txt filtered.txt
  python3 filter_pentest.py results.txt filtered.txt --seuil 3 --verbose
"""

import sys
import os
import argparse
from collections import Counter, defaultdict
from urllib.parse import urlparse


# ─── PARSING ─────────────────────────────────────────────────────────────────

def parse_line(line: str, line_num: int) -> dict | None:
    """
    Parse une ligne du fichier de résultats.
    Retourne None si la ligne est invalide (vide, commentaire, trop courte).

    Format :  url code content-length content-type [title...]
    Le title est optionnel et peut contenir des espaces.
    """
    raw = line.rstrip("\n")
    stripped = raw.strip()

    # Ignorer les lignes vides et les commentaires
    if not stripped or stripped.startswith("#"):
        return None

    parts = stripped.split()

    # Minimum : url + code + content-length + content-type = 4 champs
    if len(parts) < 4:
        return None

    url         = parts[0]
    code        = parts[1]
    cl          = parts[2]
    ctype       = parts[3]
    # Title = tout ce qui reste après les 4 premiers champs (peut être absent)
    title       = " ".join(parts[4:]) if len(parts) > 4 else ""

    # Extraire le host depuis l'URL
    try:
        parsed = urlparse(url)
        host = parsed.netloc or url
    except Exception:
        host = url

    return {
        "raw":    raw,          # ligne originale intacte (pas de strip)
        "url":    url,
        "code":   code,
        "cl":     cl,
        "ctype":  ctype,
        "title":  title,
        "host":   host,
        "line":   line_num,
    }


def load_file(filepath: str) -> tuple[list[dict], list[str]]:
    """
    Charge et parse le fichier.
    Retourne (entries valides, lignes rejetées avec raison).
    """
    entries  = []
    rejected = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for num, line in enumerate(f, start=1):
                entry = parse_line(line, num)
                if entry is not None:
                    entries.append(entry)
                else:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        rejected.append(f"  Ligne {num} ignorée (format invalide) : {line.rstrip()}")
    except FileNotFoundError:
        print(f"[!] Fichier introuvable : {filepath}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[!] Permissions insuffisantes pour lire : {filepath}", file=sys.stderr)
        sys.exit(1)

    return entries, rejected


# ─── DÉTECTION DES BASELINES ─────────────────────────────────────────────────

def compute_baselines(entries: list[dict], seuil: int) -> dict[str, set]:
    """
    Pour chaque host, identifie les combinaisons (code, cl, ctype) qui
    apparaissent au moins `seuil` fois → considérées comme "baseline" (bruit).

    Retourne un dict : host -> set of (code, cl, ctype)
    """
    # Compteur par (host, code, cl, ctype)
    counter: Counter = Counter()
    for e in entries:
        key = (e["host"], e["code"], e["cl"], e["ctype"])
        counter[key] += 1

    # Construire le set de baselines par host
    baselines: dict[str, set] = defaultdict(set)
    for (host, code, cl, ctype), count in counter.items():
        if count > seuil:
            baselines[host].add((code, cl, ctype))

    return dict(baselines)


def is_noise(entry: dict, baselines: dict[str, set]) -> bool:
    """Retourne True si l'entrée correspond à une baseline (bruit)."""
    host_baselines = baselines.get(entry["host"], set())
    sig = (entry["code"], entry["cl"], entry["ctype"])
    return sig in host_baselines


# ─── FILTRAGE ET TRI ─────────────────────────────────────────────────────────

def filter_and_sort(entries: list[dict], baselines: dict[str, set]) -> tuple[list[dict], list[dict]]:
    """
    Sépare les entrées en (résultats valides, bruit).
    Les résultats valides sont triés par : host → code → url.
    Les lignes originales ne sont PAS modifiées.
    """
    valid = []
    noise = []

    for e in entries:
        if is_noise(e, baselines):
            noise.append(e)
        else:
            valid.append(e)

    # Tri stable : host alphabétique, puis code HTTP, puis URL
    valid.sort(key=lambda e: (e["host"], e["code"], e["url"]))

    return valid, noise


# ─── ÉCRITURE DE LA SORTIE ───────────────────────────────────────────────────

def write_output(valid: list[dict], filepath: str) -> None:
    """Écrit les lignes originales (intactes) dans le fichier de sortie."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            for e in valid:
                f.write(e["raw"] + "\n")
    except PermissionError:
        print(f"[!] Permissions insuffisantes pour écrire : {filepath}", file=sys.stderr)
        sys.exit(1)


# ─── RAPPORT ─────────────────────────────────────────────────────────────────

def print_report(
    entries:   list[dict],
    valid:     list[dict],
    noise:     list[dict],
    baselines: dict[str, set],
    rejected:  list[str],
    seuil:     int,
    verbose:   bool,
    output:    str,
) -> None:
    """Affiche un rapport lisible sur stderr."""

    total   = len(entries)
    n_valid = len(valid)
    n_noise = len(noise)
    pct     = (n_noise / total * 100) if total else 0

    print(file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print("  RAPPORT DE FILTRAGE", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Lignes parsées       : {total}", file=sys.stderr)
    print(f"  Lignes filtrées      : {n_noise} ({pct:.1f}% de bruit)", file=sys.stderr)
    print(f"  Résultats conservés  : {n_valid}", file=sys.stderr)
    print(f"  Seuil utilisé        : {seuil} occurrences", file=sys.stderr)
    print(f"  Fichier de sortie    : {output}", file=sys.stderr)

    if rejected:
        print(f"\n  Lignes ignorées (format invalide) : {len(rejected)}", file=sys.stderr)
        if verbose:
            for r in rejected:
                print(r, file=sys.stderr)

    if baselines:
        print(f"\n  Baselines détectées ({len(baselines)} host(s)) :", file=sys.stderr)
        for host in sorted(baselines):
            sigs = baselines[host]
            print(f"\n    [{host}]", file=sys.stderr)
            for (code, cl, ctype) in sorted(sigs):
                count = sum(
                    1 for e in noise
                    if e["host"] == host
                    and e["code"] == code
                    and e["cl"] == cl
                    and e["ctype"] == ctype
                )
                print(f"      code={code}  cl={cl}  type={ctype}  → {count} ligne(s) filtrée(s)", file=sys.stderr)
    else:
        print("\n  Aucune baseline détectée — aucun filtrage appliqué.", file=sys.stderr)

    if verbose and valid:
        print(f"\n  Résultats conservés :", file=sys.stderr)
        for e in valid:
            title_part = f"  title={e['title']!r}" if e["title"] else "  (no title)"
            print(f"    [{e['code']}] {e['url']}  cl={e['cl']}{title_part}", file=sys.stderr)

    print("=" * 60, file=sys.stderr)
    print(file=sys.stderr)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def build_output_path(input_path: str) -> str:
    """Génère un nom de fichier de sortie à partir du nom d'entrée."""
    base, ext = os.path.splitext(input_path)
    return f"{base}.filtered{ext or '.txt'}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Filtre les résultats de fuzzing web en éliminant les réponses baseline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("input",
        help="Fichier de résultats à filtrer")
    parser.add_argument("output", nargs="?", default=None,
        help="Fichier de sortie (défaut : <input>.filtered)")
    parser.add_argument("--seuil", type=int, default=5, metavar="N",
        help="Nombre d'occurrences identiques pour considérer une réponse comme bruit (défaut : 5)")
    parser.add_argument("--verbose", "-v", action="store_true",
        help="Affiche le détail des résultats conservés dans le rapport")

    args = parser.parse_args()

    # Résoudre le chemin de sortie
    output_path = args.output or build_output_path(args.input)

    # Charger
    entries, rejected = load_file(args.input)

    if not entries:
        print("[!] Aucune entrée valide trouvée dans le fichier.", file=sys.stderr)
        sys.exit(1)

    # Calculer les baselines
    baselines = compute_baselines(entries, args.seuil)

    # Filtrer et trier
    valid, noise = filter_and_sort(entries, baselines)

    # Écrire la sortie
    write_output(valid, output_path)

    # Rapport
    print_report(
        entries, valid, noise, baselines, rejected,
        args.seuil, args.verbose, output_path
    )


if __name__ == "__main__":
    main()


