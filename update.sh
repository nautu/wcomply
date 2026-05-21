#!/bin/bash
# ==============================================================
# WComply — Script de mise à jour (à relancer après chaque push)
# Usage : bash /opt/wcomply/update.sh
# ==============================================================
set -e

APP_DIR="/opt/wcomply"
SERVICE_NAME="wcomply"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   WComply — Mise à jour              ║"
echo "╚══════════════════════════════════════╝"

# ── 1. Récupérer le code ───────────────────────────────────────
echo "▶ 1/3 git pull..."
git -C "$APP_DIR" pull
echo "  ✓ Code à jour"

# ── 2. Mettre à jour les dépendances ──────────────────────────
echo ""
echo "▶ 2/3 pip install (nouvelles dépendances éventuelles)..."
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
echo "  ✓ Dépendances à jour"

# ── 3. Redémarrer le service ───────────────────────────────────
echo ""
echo "▶ 3/3 Redémarrage du service $SERVICE_NAME..."
sudo systemctl restart "$SERVICE_NAME"
sleep 2
systemctl is-active --quiet "$SERVICE_NAME" && \
    echo "  ✓ Service redémarré avec succès" || \
    echo "  ✗ Échec — vérifiez : journalctl -u $SERVICE_NAME -n 30"

echo ""
echo "  Logs en direct : journalctl -u $SERVICE_NAME -f"
echo ""
