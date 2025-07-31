# Utiliser une image Python officielle et légère
FROM python:3.10-slim

# Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Copier le fichier des dépendances
COPY requirements.txt .

# Installer les dépendances
# L'option --pre autorise l'installation de versions bêta (pré-versions).
# L'option --no-cache-dir réduit la taille de l'image.
RUN pip install --pre --no-cache-dir -r requirements.txt

# Copier le reste du code de l'application
COPY . .

# Exposer le port que Gunicorn utilisera. Render le définit dynamiquement.
EXPOSE 8000

# Commande pour lancer l'application avec Gunicorn
# On utilise "sh -c" pour que la variable d'environnement ${PORT} soit correctement interprétée.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} app:app"]
