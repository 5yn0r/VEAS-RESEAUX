#!/bin/bash

echo "VEAS RÉSEAUX - Installation"
echo "================================"

# Vérifier Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 n'est pas installé"
    exit 1
fi

echo "✓ Python3 détecté"

# Créer venv si nécessaire
if [ ! -d "venv" ]; then
    echo "📦 Création de l'environnement virtuel..."
    python3 -m venv venv
fi

# Activer venv
echo "🔧 Activation de l'environnement..."
source venv/bin/activate

# Installer les dépendances
echo "📥 Installation des dépendances..."
pip install --upgrade pip
pip install -r requirements.txt

# Vérifier arp-scan
if ! command -v arp-scan &> /dev/null; then
    echo ""
    echo "⚠️  arp-scan n'est pas installé"
    echo "Installation manuelle requise:"
    echo "  - Ubuntu/Debian: sudo apt-get install arp-scan"
    echo "  - macOS: brew install arp-scan"
    echo "  - Fedora: sudo dnf install arp-scan"
    echo ""
fi

echo ""
echo "✨ Installation terminée!"
echo ""
echo "Pour démarrer l'application:"
echo "  sudo ./run.sh"
echo ""
echo "Puis accédez à: http://localhost:5000"
