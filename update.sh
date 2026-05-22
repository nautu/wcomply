#!/bin/bash
# ==============================================================
# VulnTrack — Script de mise à jour (systemd + venv)
# Usage : bash /opt/vulntrack/update.sh
# ==============================================================
set -e

APP_DIR="/opt/vulntrack"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   VulnTrack — Mise à jour            ║"
echo "╚══════════════════════════════════════╝"

echo "▶ 1/3 git pull..."
git -C "$APP_DIR" pull
echo "  ✓ Code à jour"

echo ""
echo "▶ 2/3 pip install..."
source "$APP_DIR/venv/bin/activate" && pip install -r "$APP_DIR/requirements.txt" -q
echo "  ✓ Dépendances à jour"

echo ""
echo "▶ 3/3 Redémarrage du service..."
sudo systemctl restart vulntrack
echo "  ✓ Service redémarré"

echo ""
echo "  Logs : sudo journalctl -u vulntrack -f"
echo ""
