#!/bin/bash
# ──────────────────────────────────────────────────────────────
# git-autopush.sh — commit + push automatique
# Déclenché par watcher.py dès qu'un .py/.html/.css est sauvegardé
# ──────────────────────────────────────────────────────────────
set -e

cd "/Users/yoan/Desktop/dev wcomply"

# Rien à committer → sortir silencieusement
if git diff --quiet && git diff --staged --quiet; then
    echo "[autopush] $(date '+%H:%M:%S') — aucun changement, push ignoré."
    exit 0
fi

git add .
git commit -m "auto: $(date '+%Y-%m-%d %H:%M')"
git push origin main
echo "[autopush] $(date '+%H:%M:%S') — push OK ✓"
