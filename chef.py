#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chef.py - Orchestrateur général (démon) pour une suite d'outils.

Surveille en boucle le dossier queue/ d'un répertoire "orchestre" :

    orchestre/
      queue/       fichiers sources (listes d'endpoints, format -l) à traiter
      running/     fichier en cours de traitement
      finished/    fichiers traités
      logs/        un log dédié par fichier : <timestamp>.<nom>.log
      chef.log     journal global du chef (append) - aussi affiché à l'écran

Cycle pour chaque fichier détecté dans queue/ :
  1. déplacé dans running/
  2. traité par les étapes du pipeline ; le chef devine si le fichier est une
     liste d'URLs (option -l) ou une requête HTTP brute (option -r)
  3. déplacé dans finished/

Les étapes sont déclarées dans build_stages() : en ajouter une = ajouter une
entrée. La sortie de chaque étape est concaténée dans son log dédié ; chaque
opération du chef est affichée ET concaténée dans chef.log.

Arrêt propre par Ctrl-C / SIGTERM (l'étape en cours se termine).

Usage :
  python3 chef.py --script-path ./monoutil.py            # démon, surveille ./orchestre
  python3 chef.py --script-path ./monoutil.py --dir /opt/orchestre --interval 5
  python3 chef.py --script-path ./monoutil.py --once     # traite la file puis quitte
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime

# --- couleurs (écran uniquement) ---
CYAN = "\033[96m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"
GREY = "\033[90m"; BOLD = "\033[1m"; RESET = "\033[0m"
COLOR = True

# fichiers à ignorer dans queue/ (en cours d'écriture / temporaires)
IGNORE_SUFFIX = (".tmp", ".part", ".swp", ".crdownload", "~")

_STOP = False


def _handle_signal(signum, frame):
    global _STOP
    _STOP = True


# ----------------------------------------------------------------------------
# Journalisation
# ----------------------------------------------------------------------------

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def fname_ts():
    """Timestamp compatible nom de fichier (sans ':' ni espace)."""
    return datetime.now().strftime("%Y%m%d-%H%M%S")


# méthodes HTTP reconnues en tête d'une ligne de requête (RFC 7231 + WebDAV)
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
                "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
                "MOVE", "LOCK", "UNLOCK"}


def detect_input_mode(path):
    """
    Devine le type du fichier pris en charge et l'option à passer à l'outil :
      '-r' si la 1re ligne non vide est une ligne de requête HTTP
           ("MÉTHODE cible HTTP/x.y", ex. 'POST /x?y=1 HTTP/1.1')
      '-l' sinon (fichier considéré comme une liste d'URLs)
    """
    first = ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    first = line.strip()
                    break
    except OSError:
        return "-l"
    parts = first.split()
    if (len(parts) == 3 and parts[0].upper() in HTTP_METHODS
            and parts[2].upper().startswith("HTTP/")):
        return "-r"
    return "-l"


class Chef:
    def __init__(self, base, args):
        self.base = base
        self.args = args
        self.queue = os.path.join(base, "queue")
        self.running = os.path.join(base, "running")
        self.finished = os.path.join(base, "finished")
        self.logs = os.path.join(base, "logs")
        self.chef_log = os.path.join(base, "chef.log")
        for d in (self.queue, self.running, self.finished, self.logs):
            os.makedirs(d, exist_ok=True)

    # -- logs ---------------------------------------------------------------

    def log(self, msg, level="INFO", color=None):
        line = f"[{ts()}] [{level}] {msg}"
        # écran (coloré)
        if COLOR and color:
            print(f"{color}{line}{RESET}", flush=True)
        else:
            print(line, flush=True)
        # chef.log (append, sans couleur)
        try:
            with open(self.chef_log, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as e:
            print(f"[{ts()}] [ERR ] écriture chef.log impossible: {e}", flush=True)

    # -- sélection des fichiers ---------------------------------------------

    def next_files(self):
        """Fichiers de queue/ prêts (stables), triés du plus ancien au plus récent."""
        try:
            names = sorted(os.listdir(self.queue))
        except OSError:
            return []
        ready = []
        now = time.time()
        for n in names:
            if n.startswith(".") or n.endswith(IGNORE_SUFFIX):
                continue
            p = os.path.join(self.queue, n)
            if not os.path.isfile(p):
                continue
            # évite d'attraper un fichier encore en cours d'écriture/copie
            try:
                if now - os.path.getmtime(p) < self.args.min_age:
                    continue
            except OSError:
                continue
            ready.append(n)
        return ready

    @staticmethod
    def _safe_move(src, dstdir):
        base = os.path.basename(src)
        dst = os.path.join(dstdir, base)
        if os.path.exists(dst):
            dst = os.path.join(dstdir, f"{base}.{int(time.time())}")
        shutil.move(src, dst)
        return dst

    # -- exécution d'une étape ----------------------------------------------

    def run_stage(self, stage, input_path, logpath, mode_flag):
        """Lance une étape, concatène sa sortie dans le log dédié du fichier."""
        argv = [self.args.python, stage["script"]]
        for a in stage["args"]:
            argv.append(a.replace("{input}", input_path)
                         .replace("{mode_flag}", mode_flag))
        logname = os.path.basename(logpath)

        self.log(f"étape '{stage['name']}' -> {os.path.basename(input_path)} "
                 f"| cmd: {' '.join(argv)}", color=CYAN)

        if not os.path.isfile(stage["script"]):
            self.log(f"étape '{stage['name']}' ignorée : script introuvable "
                     f"({stage['script']})", level="WARN", color=YELLOW)
            return False

        started = time.time()
        header = (f"\n{'='*70}\n"
                  f"# stage={stage['name']} file={os.path.basename(input_path)} "
                  f"start={ts()}\n# cmd: {' '.join(argv)}\n{'='*70}\n")
        try:
            with open(logpath, "a", encoding="utf-8") as lf:
                lf.write(header)
                lf.flush()
                # sortie de l'étape concaténée directement dans son log
                proc = subprocess.run(argv, stdout=lf, stderr=subprocess.STDOUT)
                lf.write(f"\n# stage={stage['name']} end={ts()} "
                         f"exit={proc.returncode} "
                         f"duration={time.time() - started:.1f}s\n")
            ok = proc.returncode in (0, 1)  # convention: 1 = findings, pas une erreur
            lvl, col = ("INFO", GREEN) if ok else ("WARN", YELLOW)
            self.log(f"étape '{stage['name']}' terminée (exit={proc.returncode}, "
                     f"{time.time() - started:.1f}s) -> logs/{logname}",
                     level=lvl, color=col)
            return True
        except Exception as e:
            self.log(f"étape '{stage['name']}' en échec: {e}", level="ERR", color=RED)
            return False

    # -- traitement d'un fichier --------------------------------------------

    def process(self, name, stages):
        qpath = os.path.join(self.queue, name)
        self.log(f"nouveau fichier détecté: {name}", color=BOLD)
        try:
            rpath = self._safe_move(qpath, self.running)
        except Exception as e:
            self.log(f"déplacement vers running/ impossible ({name}): {e}",
                     level="ERR", color=RED)
            return
        self.log(f"{name} -> running/ ({os.path.basename(rpath)})", color=GREY)

        # un log dédié par fichier pris en charge : logs/<timestamp>.<nom>.log
        logpath = os.path.join(self.logs, f"{fname_ts()}.{name}.log")

        # devine le type du fichier -> option à passer à l'outil (-l ou -r)
        mode_flag = detect_input_mode(rpath)
        kind = "requête HTTP" if mode_flag == "-r" else "liste d'URLs"
        self.log(f"{name} détecté comme {kind} -> option {mode_flag}", color=CYAN)

        t0 = time.time()
        for stage in stages:
            if _STOP:
                self.log("arrêt demandé - étapes restantes non lancées pour "
                         f"{name}", level="WARN", color=YELLOW)
                break
            self.run_stage(stage, rpath, logpath, mode_flag)

        try:
            fpath = self._safe_move(rpath, self.finished)
            self.log(f"{name} -> finished/ ({os.path.basename(fpath)}) "
                     f"[total {time.time() - t0:.1f}s]", level="INFO", color=GREEN)
        except Exception as e:
            self.log(f"déplacement vers finished/ impossible ({name}): {e}",
                     level="ERR", color=RED)

    # -- boucle principale --------------------------------------------------

    def loop(self, stages):
        self.log(f"chef démarré | base={self.base} | interval={self.args.interval}s "
                 f"| étapes: {', '.join(s['name'] for s in stages)}",
                 color=BOLD)
        idle = False
        while not _STOP:
            files = self.next_files()
            if not files:
                if self.args.once:
                    self.log("file vide - fin (--once)", color=GREY)
                    return
                if not idle:
                    self.log("file vide - en attente…", level="INFO", color=GREY)
                    idle = True
                # sommeil fractionné pour réagir vite à l'arrêt
                for _ in range(max(1, int(self.args.interval))):
                    if _STOP:
                        break
                    time.sleep(1)
                continue
            idle = False
            for name in files:
                if _STOP:
                    break
                self.process(name, stages)
            if self.args.once:
                self.log("file traitée - fin (--once)", color=GREY)
                return
        self.log("arrêt du chef (signal reçu)", level="WARN", color=YELLOW)


# ----------------------------------------------------------------------------
# Pipeline
# ----------------------------------------------------------------------------

def build_stages(args):
    """
    Étapes du pipeline. Pour ajouter un outil plus tard, ajoute une entrée :
      {"name": "ssti", "script": args.ssti_path,
       "args": ["{mode_flag}", "{input}", "--no-color"]}
    Placeholders remplacés au moment de l'exécution :
      '{input}'     -> chemin du fichier dans running/
      '{mode_flag}' -> '-l' (liste d'URLs) ou '-r' (requête HTTP), deviné par
                       le chef selon le contenu du fichier.
    La sortie de toutes les étapes d'un même fichier est concaténée dans son
    log dédié logs/<timestamp>.<nom>.log (nommage géré par le chef).
    """
    if args.script_args:
        script_args = args.script_args.split()
    else:
        script_args = []
    script_args += ["{mode_flag}", "{input}", "--no-color"]
    # if args.script_args:
    #     script_args += args.script_args.split()
    return [
        {"name": "script", "script": args.script_path, "args": script_args},
    ]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(
        prog="chef.py",
        description="Orchestrateur démon : surveille queue/, lance les scanners, "
                    "déplace running/ -> finished/.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=os.path.join(here, "orchestre"),
                    help="dossier orchestre (défaut: ./orchestre à côté du script)")
    ap.add_argument("--interval", type=float, default=5.0,
                    help="intervalle de surveillance de queue/ en secondes (défaut 5)")
    ap.add_argument("--min-age", type=float, default=5.0,
                    help="âge minimal d'un fichier avant prise en charge, pour "
                         "éviter d'attraper une copie en cours (défaut 5s)")
    ap.add_argument("--python", default=sys.executable,
                    help="interpréteur Python pour lancer l'outil")
    ap.add_argument("--script-path", required=True,
                    help="chemin de l'outil à lancer sur chaque fichier de queue/")
    ap.add_argument("--script-args", default="",
                    help="arguments supplémentaires passés à l'outil "
                         "(ex: \"-t 10 --no-color\")")
    ap.add_argument("--once", action="store_true",
                    help="traite la file actuelle puis quitte (pas de démon)")
    ap.add_argument("--no-color", action="store_true", help="désactive les couleurs")
    args = ap.parse_args()

    global COLOR
    COLOR = not args.no_color and not os.environ.get("NO_COLOR")

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    base = os.path.abspath(args.dir)
    os.makedirs(base, exist_ok=True)
    chef = Chef(base, args)
    stages = build_stages(args)
    try:
        chef.loop(stages)
    except KeyboardInterrupt:
        chef.log("interruption clavier", level="WARN", color=YELLOW)
    return 0


if __name__ == "__main__":
    sys.exit(main())
