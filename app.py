import os
import re
import logging
import httpx
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import Unauthorized
from svix import Webhook, WebhookVerificationError

# --- INITIALISATION ---
load_dotenv()
app = Flask(__name__)

# --- CONFIGURATION & LOGGING ---
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# --- GESTION DES FICHIERS UPLOADÉS ---
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- CORS ---
# Pour le développement, autoriser toutes les origines est acceptable.
# Pour la production, il faudra restreindre à l'URL de votre frontend.
CORS(app, origins=["*"], supports_credentials=True, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], allow_headers=["Authorization", "Content-Type"])

# --- CONFIGURATION DE CLERK ---
CLERK_SECRET_KEY = os.environ.get("CLERK_SECRET_KEY")
CLERK_API_BASE_URL = "https://api.clerk.dev/v1" # URL standard de l'API Clerk
CLERK_WEBHOOK_SECRET = os.environ.get("CLERK_WEBHOOK_SECRET")

if not CLERK_SECRET_KEY:
    raise RuntimeError("CLERK_SECRET_KEY n'est pas définie dans les variables d'environnement.")
if not CLERK_WEBHOOK_SECRET:
    raise RuntimeError("CLERK_WEBHOOK_SECRET n'est pas définie. Récupérez-la depuis votre dashboard Clerk.")

# --- DÉCORATEUR D'AUTHENTIFICATION (AMÉLIORÉ) ---
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        app.logger.info("--- [AUTH] Vérification du token ---")
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            app.logger.error("[AUTH] ÉCHEC: Header 'Authorization' manquant ou mal formaté.")
            raise Unauthorized("Header 'Authorization' manquant ou mal formaté")
        
        token = auth_header.split(' ')[1]
        app.logger.info(f"[AUTH] Token trouvé. Appel de l'API Clerk pour vérification.")
        app.logger.info(f"[AUTH] Utilisation de la clé secrète commençant par: {CLERK_SECRET_KEY[:10]}")

        try:
            headers = {"Authorization": f"Bearer {CLERK_SECRET_KEY}"}
            introspect_url = f"{CLERK_API_BASE_URL}/tokens/introspect"
            
            with httpx.Client() as client:
                response = client.post(introspect_url, headers=headers, data={"token": token})
            
            app.logger.info(f"[AUTH] Réponse de l'API Clerk: Statut {response.status_code}")

            if response.status_code == 200:
                response_data = response.json()
                if response_data.get("active"):
                    # Stocker les informations de l'utilisateur dans la requête pour un accès facile
                    request.claims = response_data.get("claims", {})
                    app.logger.info("[AUTH] SUCCÈS: Token valide et actif.")
                else:
                    app.logger.error("[AUTH] ÉCHEC: Token inactif.")
                    raise Unauthorized("Token inactif")
            else:
                # Cette erreur 404 est souvent due à une mauvaise clé secrète
                app.logger.error(f"[AUTH] ÉCHEC: La vérification du token a échoué. Réponse de Clerk: {response.text}")
                raise Unauthorized("Token invalide")
        except Exception as e:
            app.logger.error(f"[AUTH] ÉCHEC: Une exception est survenue: {e}")
            raise Unauthorized("Token invalide")
        
        return f(*args, **kwargs)
    return decorated

# --- CONFIGURATION DE LA BASE DE DONNÉES ---
database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise RuntimeError("DATABASE_URL n'est pas définie dans le fichier .env.")

# SQLAlchemy requiert 'postgresql' au lieu de 'postgres'
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- MODÈLES DE BASE DE DONNÉES (UNIFIÉS) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    clerk_id = db.Column(db.String(120), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(80), nullable=True)
    last_name = db.Column(db.String(80), nullable=True)

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    clerk_org_id = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    logo_url = db.Column(db.Text, nullable=True)
    primary_color = db.Column(db.String(7), default='#D69E2E')
    google_link = db.Column(db.Text, nullable=True)
    tripadvisor_link = db.Column(db.Text, nullable=True)

# Création des tables si elles n'existent pas
with app.app_context():
    db.create_all()

# --- FONCTIONS UTILITAIRES ---
def slugify(text):
    text = text.lower()
    return re.sub(r'[\s\W]+', '-', text).strip('-')

def get_restaurant_from_claims():
    claims = getattr(request, 'claims', {})
    org_id = claims.get('org_id')
    if not org_id:
        return None, ('ID de l\'organisation non trouvé dans le token', 401)
    restaurant = Restaurant.query.filter_by(clerk_org_id=org_id).first()
    if not restaurant:
        return None, ('Restaurant non trouvé pour cette organisation.', 404)
    return restaurant, None

def is_admin():
    claims = getattr(request, 'claims', {})
    # Le rôle standard d'administrateur dans Clerk est 'org:admin'
    return claims.get('org_role') == 'org:admin'

# --- ROUTE WEBHOOK CLERK ---
@app.route("/api/clerk-webhook", methods=["POST"])
def clerk_webhook():
    try:
        headers = request.headers
        payload = request.get_data(as_text=True)
        wh = Webhook(CLERK_WEBHOOK_SECRET)
        event = wh.verify(payload, headers)
    except WebhookVerificationError as e:
        app.logger.warning(f"La vérification du webhook a échoué: {e}")
        return jsonify(status="error", message="Signature invalide"), 400

    event_type = event.get("type")
    data = event.get("data")
    app.logger.info(f"Webhook reçu: {event_type}")

    try:
        if event_type == "user.created":
            email = data.get("email_addresses")[0].get("email_address")
            new_user = User(
                clerk_id=data.get("id"),
                email=email,
                first_name=data.get("first_name"),
                last_name=data.get("last_name"),
            )
            db.session.add(new_user)
            db.session.commit()
            app.logger.info(f"Utilisateur {new_user.clerk_id} créé dans la BDD.")

        elif event_type == "organization.created":
            new_restaurant = Restaurant(
                clerk_org_id=data.get("id"),
                name=data.get("name"),
                slug=data.get("slug") or slugify(data.get("name"))
            )
            db.session.add(new_restaurant)
            db.session.commit()
            app.logger.info(f"Restaurant {new_restaurant.name} créé pour l'org {new_restaurant.clerk_org_id}.")

        # Ajoutez ici la logique pour user.updated, organization.updated, etc.

    except IntegrityError:
        db.session.rollback()
        app.logger.warning(f"Erreur d'intégrité pour l'événement {event_type}: l'entrée existe probablement déjà.")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors du traitement du webhook {event_type}: {e}")
        return jsonify(status="error", message="Erreur interne du serveur"), 500

    return jsonify(status="success"), 200

# --- ROUTE POUR SERVIR LES FICHIERS UPLOADÉS ---
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- ROUTES PROTÉGÉES DE L'API ---
@app.route('/api/v1/restaurant/settings', methods=['GET', 'PUT'])
@requires_auth
def restaurant_settings():
    restaurant, error = get_restaurant_from_claims()
    if error:
        return jsonify({"error": error[0]}), error[1]

    if not is_admin():
        return jsonify({"error": "Action non autorisée. Rôle administrateur requis."}), 403

    if request.method == 'GET':
        # Préfixe l'URL du logo avec /uploads/ pour que le frontend sache où le trouver
        logo_url_full = f"/uploads/{restaurant.logo_url}" if restaurant.logo_url else None
        return jsonify({
            "name": restaurant.name,
            "slug": restaurant.slug,
            "logoUrl": logo_url_full,
            "primaryColor": restaurant.primary_color,
            "googleLink": restaurant.google_link,
            "tripadvisorLink": restaurant.tripadvisor_link,
        })

    if request.method == 'PUT':
        # Mise à jour des champs texte
        restaurant.name = request.form.get('name', restaurant.name)
        restaurant.primary_color = request.form.get('primaryColor', restaurant.primary_color)
        restaurant.google_link = request.form.get('googleLink', restaurant.google_link)
        restaurant.tripadvisor_link = request.form.get('tripadvisorLink', restaurant.tripadvisor_link)

        # Gestion de l'upload du logo
        if 'logo' in request.files:
            file = request.files['logo']
            if file and file.filename != '' and allowed_file(file.filename):
                # Crée un nom de fichier sécurisé et unique
                filename = secure_filename(f"{restaurant.clerk_org_id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                restaurant.logo_url = filename
        
        try:
            db.session.commit()
            logo_url_full = f"/uploads/{restaurant.logo_url}" if restaurant.logo_url else None
            return jsonify({"message": "Paramètres mis à jour.", "logoUrl": logo_url_full}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de la mise à jour des paramètres: {e}")
            return jsonify({"error": "Échec de la mise à jour"}), 500
            
    return jsonify({"error": "Méthode non autorisée"}), 405

# --- POINT D'ENTRÉE POUR L'EXÉCUTION ---
if __name__ == '__main__':
    # Le port est géré par Flask/Gunicorn, 5000 par défaut pour le dev
    app.run(debug=True)
