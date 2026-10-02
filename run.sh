#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "VEAS RÉSEAUX - Demarrage"

# Vérifier le venv
if [ ! -d "venv" ]; then
    echo "❌ Environnement virtuel non trouvé"
    echo "Exécutez d'abord: ./install.sh"
    exit 1
fi

# Capture and ARP discovery need elevated network capabilities.
if [ "$EUID" -ne 0 ]; then
    echo "Demarrage avec les droits administrateur..."
    exec sudo -E "$SCRIPT_DIR/run.sh" "$@"
fi

# Gunicorn keeps the dashboard server separate from the development server.
echo "Demarrage de VEAS RÉSEAUX..."
exec ./venv/bin/gunicorn \
    --worker-class gthread \
    --threads 100 \
    --workers 1 \
    --bind "${HOST:-127.0.0.1}:${PORT:-5000}" \
    veas.wsgi:app
