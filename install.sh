#!/bin/bash
# ==============================================================
# WComply — Script d'installation (première fois sur la VM EC2)
# Usage : sudo bash install.sh
# ==============================================================
set -e

# ── À MODIFIER avant de lancer ─────────────────────────────────
REPO_URL="https://github.com/TON_USERNAME/wcomply.git"
# ───────────────────────────────────────────────────────────────

APP_DIR="/opt/wcomply"
SERVICE_NAME="wcomply"
PORT=8000

# Détecter l'utilisateur qui a lancé sudo (pour le service systemd)
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    APP_USER="$SUDO_USER"
else
    APP_USER="$(whoami)"
fi

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   WComply — Installation EC2         ║"
echo "╚══════════════════════════════════════╝"
echo "  Répertoire : $APP_DIR"
echo "  Utilisateur : $APP_USER"
echo "  Port : $PORT"
echo ""

# ── 1. Dépendances système ─────────────────────────────────────
echo "▶ 1/5 Installation des dépendances système..."
if command -v apt-get &>/dev/null; then
    apt-get update -y -q
    apt-get install -y -q python3 python3-pip python3-venv git
elif command -v dnf &>/dev/null; then
    dnf update -y -q
    dnf install -y -q python3 python3-pip git
elif command -v yum &>/dev/null; then
    yum update -y -q
    yum install -y -q python3 python3-pip git
else
    echo "ERREUR : aucun gestionnaire de paquets reconnu (apt/dnf/yum)."
    exit 1
fi
echo "  ✓ Python3, pip, git installés"

# ── 2. Cloner le dépôt ────────────────────────────────────────
echo ""
echo "▶ 2/5 Clonage du dépôt GitHub..."
if [ -d "$APP_DIR/.git" ]; then
    echo "  Dépôt déjà présent — git pull..."
    git -C "$APP_DIR" pull
else
    git clone "$REPO_URL" "$APP_DIR"
fi
echo "  ✓ Code récupéré dans $APP_DIR"

# ── 3. Virtualenv & dépendances Python ────────────────────────
echo ""
echo "▶ 3/5 Création du virtualenv et installation des dépendances..."
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip -q
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt" -q
echo "  ✓ Dépendances installées"

# ── 4. Permissions ────────────────────────────────────────────
chown -R "$APP_USER":"$APP_USER" "$APP_DIR"

# ── 5. Service systemd ────────────────────────────────────────
echo ""
echo "▶ 4/5 Configuration du service systemd..."

cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=WComply — SAP Vulnerability Tracker
After=network.target

[Service]
Type=simple
User=${APP_USER}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/venv/bin/uvicorn main:app --host 0.0.0.0 --port ${PORT} --workers 2
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
echo "  ✓ Service $SERVICE_NAME activé et démarré"

# ── Résumé ────────────────────────────────────────────────────
echo ""
echo "▶ 5/5 Vérification..."
sleep 2
systemctl is-active --quiet "$SERVICE_NAME" && \
    echo "  ✓ Service actif" || \
    echo "  ✗ Service inactif — vérifiez : journalctl -u $SERVICE_NAME -n 50"

PUBLIC_IP=$(curl -s --max-time 3 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "VOTRE_IP_EC2")

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ✓ Installation terminée !                          ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  App     : http://${PUBLIC_IP}:${PORT}"
echo "║  Status  : systemctl status $SERVICE_NAME"
echo "║  Logs    : journalctl -u $SERVICE_NAME -f"
echo "║  Update  : bash $APP_DIR/update.sh"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
