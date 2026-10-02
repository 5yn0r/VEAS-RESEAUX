FROM python:3.11-slim

WORKDIR /app

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    arp-scan \
    libpcap-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers
COPY requirements.txt .
COPY app.py .
COPY config.py .
COPY moniwifi/ moniwifi/
COPY templates/ templates/

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Historique SQLite (monte en volume par docker-compose)
RUN mkdir -p /app/data
ENV DB_PATH=/app/data/wifi_guardian.db

# Exposer le port
EXPOSE 5000

# /api/health renvoie 503 si un composant est degrade
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.getenv(\"PORT\", \"5000\")}/api/health', timeout=4)"

# Commande de démarrage
CMD ["sh", "-c", "exec gunicorn --worker-class gthread --threads 100 --workers 1 --bind ${HOST:-127.0.0.1}:${PORT:-5000} moniwifi.wsgi:app"]
