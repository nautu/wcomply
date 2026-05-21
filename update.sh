#!/bin/bash
# ==============================================================
# WComply — Script de mise à jour (Docker)
# Usage : bash /opt/wcomply/update.sh
# ==============================================================
set -e

APP_DIR="/opt/wcomply"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   WComply — Mise à jour (Docker)     ║"
echo "╚══════════════════════════════════════╝"

# ── 1. Récupérer le code ───────────────────────────────────────
echo "▶ 1/3 git pull..."
git -C "$APP_DIR" pull
echo "  ✓ Code à jour"

# ── 2. Reconstruire et redémarrer les conteneurs ───────────────
echo ""
echo "▶ 2/3 Rebuild de l'image app..."
docker compose -f "$APP_DIR/docker-compose.yml" build app
echo "  ✓ Image reconstruite"

echo ""
echo "▶ 3/3 Redémarrage des services..."
docker compose -f "$APP_DIR/docker-compose.yml" up -d
sleep 3

# Vérification
if docker compose -f "$APP_DIR/docker-compose.yml" ps | grep -q "running"; then
    echo "  ✓ Services actifs"
else
    echo "  ✗ Problème détecté — vérifiez :"
    docker compose -f "$APP_DIR/docker-compose.yml" logs --tail=30
fi

echo ""
echo "  Logs : docker compose -f $APP_DIR/docker-compose.yml logs -f app"
echo ""
