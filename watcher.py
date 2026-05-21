#!/usr/bin/env python3
"""
watcher.py — Surveille les fichiers du projet et déclenche git-autopush.sh
Usage  : python3 watcher.py &
Arrêt  : kill %1   ou   pkill -f watcher.py
"""
import subprocess
import sys
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

PROJECT_DIR  = Path(__file__).parent.resolve()
AUTOPUSH     = PROJECT_DIR / "git-autopush.sh"
WATCH_EXTS   = {".py", ".html", ".css"}
DEBOUNCE_SEC = 8          # délai minimum entre deux pushs
IGNORE_DIRS  = {".git", "__pycache__", "venv", "node_modules", ".idea"}


class AutoPushHandler(FileSystemEventHandler):
    def __init__(self):
        self._last_push = 0.0

    def on_modified(self, event):
        self._trigger(event.src_path)

    def on_created(self, event):
        self._trigger(event.src_path)

    def _trigger(self, src_path: str):
        path = Path(src_path)

        # Ignorer les dossiers, fichiers hors extensions, dossiers exclus
        if path.is_dir():
            return
        if path.suffix not in WATCH_EXTS:
            return
        if any(part in IGNORE_DIRS for part in path.parts):
            return

        now = time.time()
        if now - self._last_push < DEBOUNCE_SEC:
            return          # debounce

        self._last_push = now
        print(f"[watcher] {path.name} modifié — lancement autopush...", flush=True)
        try:
            subprocess.run(["bash", str(AUTOPUSH)], cwd=PROJECT_DIR, check=False)
        except Exception as e:
            print(f"[watcher] Erreur : {e}", flush=True)


if __name__ == "__main__":
    observer = Observer()
    handler  = AutoPushHandler()
    observer.schedule(handler, str(PROJECT_DIR), recursive=True)
    observer.start()
    print(f"[watcher] Surveillance de {PROJECT_DIR}")
    print(f"[watcher] Extensions : {', '.join(sorted(WATCH_EXTS))}")
    print(f"[watcher] Debounce   : {DEBOUNCE_SEC}s  |  Ctrl+C pour arrêter\n", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    observer.stop()
    observer.join()
    print("[watcher] Arrêté.")
    sys.exit(0)
