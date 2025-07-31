import os
import re
import logging
import requests # Pour récupérer les clés JWKS
from functools import wraps
from jose import jwt # Pour décoder et valider le token JWT
from flask import Flask, request, jsonify, send_from_directory, g
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
CORS(app, origins=["*"], supports_credentials=True, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], allow_headers=["Authorization", "Content-Type"])

# --- NOUVELLE CONFIGURATION D'AUTHENTIFICATION CLERK (JWT/JWKS) ---
CLERK_JWKS_URL = os.environ.get("CLERK_JWKS_URL")
CLERK_ISSUER = os.environ.get("CLERK_ISSUER") # L'émetteur du token, ex: https://golden-oyster-43.clerk.accounts.dev
CLERK_WEBHOOK_SECRET = os.environ.get("CLERK_WEBHOOK_SECRET")
JWKS = None # Cache global pour les clés JWKS

if not CLERK_JWKS_URL:
    raise RuntimeError("CLERK_JWKS_URL n'est pas définie dans les variables d'environnement.")
if not CLERK_ISSUER:
    raise RuntimeError("CLERK_ISSUER n'est pas définie dans les variables d'environnement.")

def fetch_jwks():
    """Récupère les clés JWKS depuis Clerk et les met en cache."""
    global JWKS
    if not JWKS:
        try:
            app.logger.info(f"Récupération des clés JWKS depuis: {CLERK_JWKS_URL}")
            res = requests.get(CLERK_JWKS_URL)
            res.raise_for_status() # Lève une exception si la requête échoue
            JWKS = res.json()
            app.logger.info("Clés JWKS récupérées et mises en cache avec succès.")
        except requests.exceptions.RequestException as e:
            app.logger.error(f"Impossible de récupérer les JWKS Clerk: {e}. Vérifiez CLERK_JWKS_URL dans votre .env")
            raise RuntimeError("Impossible de récupérer les JWKS Clerk.")
    return JWKS

def decode_token(token):
    """Décode et valide le token JWT en utilisant les clés JWKS."""
    try:
        jwks = fetch_jwks()
        header = jwt.get_unverified_header(token)
        key = next((k for k in jwks['keys'] if k['kid'] == header['kid']), None)

        if not key:
            app.logger.error(f"Clé publique introuvable pour le token (kid: {header.get('kid')}).")
            return None

        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=CLERK_ISSUER,
            options={"verify_exp": True} # Vérifie automatiquement la date d'expiration
        )
        app.logger.info("Token JWT validé avec succès.")
        return payload
    except jwt.ExpiredSignatureError:
        app.logger.error("Erreur de validation JWT: Le token a expiré.")
        return None
    except jwt.JWTClaimsError as e:
        app.logger.error(f"Erreur de validation JWT (claims): {e}. Vérifiez CLERK_ISSUER dans votre .env")
        return None
    except jwt.JWTError as e:
        app.logger.error(f"Erreur de validation JWT: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Erreur inattendue lors du décodage du token: {e}")
        return None

def requires_auth(f):
    """Nouveau décorateur qui valide le token JWT localement."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Header 'Authorization' manquant ou mal formaté"}), 401
        
        token = auth_header.split(" ")[1]
        payload = decode_token(token)
        
        if not payload:
            return jsonify({"error": "Token invalide ou expiré"}), 401
        
        # Stocke le payload du token dans le contexte 'g' de Flask pour la durée de la requête
        g.claims = payload
        return f(*args, **kwargs)
    return decorated

# --- CONFIGURATION DE LA BASE DE DONNÉES ---
database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise RuntimeError("DATABASE_URL n'est pas définie dans le fichier .env.")

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- MODÈLES DE BASE DE DONNÉES ---
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

with app.app_context():
    db.create_all()

# --- FONCTIONS UTILITAIRES (ADAPTÉES) ---
def slugify(text):
    text = text.lower()
    return re.sub(r'[\s\W]+', '-', text).strip('-')

def get_restaurant_from_claims():
    claims = g.claims
    app.logger.info(f"Vérification des claims du token: {claims}") # LOG DE DÉBOGAGE
    org_id = claims.get('org_id')
    if not org_id:
        app.logger.error("ÉCHEC de l'autorisation: 'org_id' non trouvé dans les claims du token.") # LOG DE DÉBOGAGE
        return None, ('ID de l\'organisation non trouvé dans le token', 401)
    
    restaurant = Restaurant.query.filter_by(clerk_org_id=org_id).first()
    if not restaurant:
        app.logger.error(f"ÉCHEC de l'autorisation: Restaurant non trouvé pour l'org_id {org_id}.") # LOG DE DÉBOGAGE
        return None, ('Restaurant non trouvé pour cette organisation.', 404)
        
    return restaurant, None

def is_admin():
    claims = g.claims
    return claims.get('org_role') == 'org:admin'

# --- ROUTE WEBHOOK CLERK (INCHANGÉE) ---
@app.route("/api/clerk-webhook", methods=["POST"])
def clerk_webhook():
    # ... (le code du webhook reste le même)
    return jsonify(status="success"), 200

# --- ROUTE POUR SERVIR LES FICHIERS UPLOADÉS (INCHANGÉE) ---
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- ROUTES PROTÉGÉES DE L'API (INCHANGÉES) ---
@app.route('/api/v1/restaurant/settings', methods=['GET', 'PUT'])
@requires_auth
def restaurant_settings():
    restaurant, error = get_restaurant_from_claims()
    if error:
        return jsonify({"error": error[0]}), error[1]

    if not is_admin():
        return jsonify({"error": "Action non autorisée. Rôle administrateur requis."}), 403
    
    if request.method == 'GET':
        logo_url_full = f"/uploads/{restaurant.logo_url}" if restaurant.logo_url else None
        return jsonify({
            "name": restaurant.name,
            "slug": restaurant.slug,
            "logoUrl": logo_url_full,
            "primaryColor": restaurant.primary_color,
            "googleLink": restaurant.google_link,
            "tripadvisorLink": restaurant.tripadvisor_link,
        })
    
    return jsonify({"error": "Méthode non autorisée"}), 405

# --- POINT D'ENTRÉE POUR L'EXÉCUTION ---
if __name__ == '__main__':
    app.run(debug=True)
