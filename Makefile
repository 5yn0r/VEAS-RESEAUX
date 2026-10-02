.PHONY: help install run dev test hash-password clean requirements

help:
	@echo "VEAS RÉSEAUX"
	@echo "================="
	@echo ""
	@echo "Commandes disponibles:"
	@echo "  make install         - Installer les dépendances"
	@echo "  make run             - Lancer l'app en production"
	@echo "  make dev             - Lancer en mode développement"
	@echo "  make test            - Lancer les tests"
	@echo "  make hash-password   - Generer AUTH_PASSWORD_HASH"
	@echo "  make clean           - Nettoyer les fichiers générés"
	@echo "  make requirements    - Générer requirements.txt"
	@echo ""

install:
	@chmod +x install.sh run.sh
	@./install.sh

run:
	@chmod +x run.sh
	@./run.sh

dev:
	@DEBUG=true ./venv/bin/python app.py

test:
	@./venv/bin/python -m unittest discover -s tests -t . -v

hash-password:
	@./venv/bin/python -m veas.auth

clean:
	@echo "🧹 Nettoyage..."
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@echo "✓ Nettoyage terminé"

requirements:
	@./venv/bin/pip freeze > requirements.txt
	@echo "✓ requirements.txt généré"
