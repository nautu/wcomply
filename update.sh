#!/bin/bash
# ==============================================================
# VulnTrack — Script de mise à jour (Docker)
# Usage : bash /opt/vulntrack/update.sh
# ==============================================================
set -e

APP_DIR="/opt/vulntrack"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   VulnTrack — Mise à jour (Docker)   ║"
echo "╚══════════════════════════════════════╝"

# ── 1. Récupérer le code ───────────────────────────────────────
echo "▶ 1/3 git pull..."
git -C "$APP_DIR" pull
echo "  ✓ Code à jour"

# ── 2. Tirer les images distantes (optionnel) ─────────────────
echo ""
echo "▶ 2/3 docker-compose pull..."
docker compose -f "$APP_DIR/docker-compose.yml" pull --ignore-buildable 2>/dev/null || true
echo "  ✓ Images à jour"

# ── 3. Rebuild et redémarrage ─────────────────────────────────
echo ""
echo "▶ 3/3 docker-compose up -d --build..."
docker compose -f "$APP_DIR/docker-compose.yml" up -d --build
sleep 4

# Vérification
if docker compose -f "$APP_DIR/docker-compose.yml" ps | grep -q "running\|Up"; then
    echo "  ✓ Services actifs"
else
    echo "  ✗ Problème détecté — vérifiez :"
    docker compose -f "$APP_DIR/docker-compose.yml" logs --tail=30
fi

echo ""
echo "  Logs : docker compose -f $APP_DIR/docker-compose.yml logs -f app"
echo ""
