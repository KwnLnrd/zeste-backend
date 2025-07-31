import os
import re
import json
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

# --- INITIAL CONFIGURATION ---
load_dotenv()
app = Flask(__name__)

# --- UPLOAD FOLDER CONFIGURATION ---
UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), 'uploads'))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- LOGGING ---
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# --- CORS ---
CORS(app, origins=["*"], supports_credentials=True, allow_headers=["Authorization", "Content-Type"])

# --- CLERK AUTHENTICATION VIA REST API ---
CLERK_SECRET_KEY = os.environ.get("CLERK_SECRET_KEY")
CLERK_API_BASE_URL = "https://api.clerk.com/v1"

if not CLERK_SECRET_KEY:
    raise RuntimeError("CLERK_SECRET_KEY is not set in environment variables.")

# --- DÉCORATEUR D'AUTHENTIFICATION VIA L'API REST ---
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            raise Unauthorized("Missing Authorization Header")
        
        try:
            token = auth_header.split(' ')[1]
            
            # Utiliser l'API de Clerk pour vérifier le token
            headers = {"Authorization": f"Bearer {CLERK_SECRET_KEY}"}
            # L'endpoint /sessions/{session_id}/verify est plus direct
            # Pour cela, il nous faut le session_id. Le plus simple est de vérifier le token via l'endpoint /me
            # qui valide le token et retourne l'utilisateur.
            # Cependant, pour obtenir les claims de la session (org_role etc.), il faut vérifier la session.
            # Le token JWT contient le session ID (sid).
            
            # La méthode la plus simple et officielle est d'utiliser l'endpoint /sessions/verify
            # qui prend le token JWT du frontend.
            verify_url = f"{CLERK_API_BASE_URL}/sessions/verify"
            response = httpx.post(verify_url, headers=headers, json={"token": token})
            
            if response.status_code == 200:
                # Attacher les claims à la requête pour un accès facile
                request.claims = response.json()
            else:
                app.logger.error(f"Clerk token verification failed: {response.status_code} {response.text}")
                raise Unauthorized("Invalid Token")

        except Exception as e:
            app.logger.error(f"Token verification failed: {e}")
            raise Unauthorized("Invalid Token")
        
        return f(*args, **kwargs)
    return decorated

# --- DATABASE CONFIGURATION ---
database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise RuntimeError("DATABASE_URL is not set in .env file.")

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
elif database_url.startswith("postgresql://") and "+psycopg" not in database_url:
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- DATABASE MODELS ---
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
    enabled_languages = db.Column(db.JSON, default=['fr', 'en'])
    servers = db.relationship('Server', back_populates='restaurant', cascade="all, delete-orphan")
    dishes = db.relationship('Dish', back_populates='restaurant', cascade="all, delete-orphan")

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    avatar_url = db.Column(db.Text, nullable=True)
    restaurant = db.relationship('Restaurant', back_populates='servers')
    user = db.relationship('User')

class Dish(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)

# Correction: Utiliser app.app_context() pour les opérations de base de données
with app.app_context():
    db.create_all()

# --- HELPER FUNCTIONS ---
def get_restaurant_from_claims():
    claims = request.claims
    org_id = claims.get('org_id')
    if not org_id:
        return None, ('Organization ID not found in token', 401)
    
    restaurant = Restaurant.query.filter_by(clerk_org_id=org_id).first()
    if not restaurant:
        return None, ('Restaurant not found for this organization', 404)
    
    return restaurant, None

def is_admin():
    claims = request.claims
    # Le rôle dans les claims de l'API est 'admin' et non 'org:admin'
    return claims.get('org_role') == 'admin'

# --- CLERK WEBHOOK ---
@app.route("/api/clerk-webhook", methods=["POST"])
def clerk_webhook():
    payload = request.json
    event_type = payload.get("type")
    data = payload.get("data")

    if event_type == "user.created":
        try:
            new_user = User(
                clerk_id=data.get("id"),
                email=data.get("email_addresses")[0].get("email_address"),
                first_name=data.get("first_name"),
                last_name=data.get("last_name"),
            )
            db.session.add(new_user)
            db.session.commit()
            app.logger.info(f"User {new_user.clerk_id} created in local DB.")
        except IntegrityError:
            db.session.rollback()
            app.logger.warning(f"User with clerk_id {data.get('id')} already exists.")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating user from webhook: {e}")
            return jsonify(status="error", message=str(e)), 500

    # ... (les autres handlers de webhook restent les mêmes)

    return jsonify(status="success"), 200

# --- PROTECTED ROUTES ---
@app.route('/api/v1/dashboard/stats', methods=['GET'])
@requires_auth
def get_dashboard_stats():
    restaurant, error = get_restaurant_from_claims()
    if error:
        return jsonify({"error": error[0]}), error[1]

    if is_admin():
        stats = {"totalReviews": 128, "averageRating": 4.8, "serverOfTheMonth": "Clara"}
        return jsonify(stats)
    else:
        claims = request.claims
        user = User.query.filter_by(clerk_id=claims.get('sub')).first()
        if not user:
            return jsonify({"error": "User not found in local DB"}), 404
        stats = {"myReviews": 32, "myAverageRating": 4.9}
        return jsonify(stats)

# ... (les autres routes protégées restent les mêmes)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)), debug=True)
