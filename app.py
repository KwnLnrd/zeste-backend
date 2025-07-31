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
# We define an absolute path to ensure it works correctly on any system (like Render).
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- LOGGING ---
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# --- CORS ---
# Allow all origins for now, but you might want to restrict this to your frontend's URL in production.
CORS(app, origins=["*"], supports_credentials=True, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], allow_headers=["Authorization", "Content-Type"])

# --- CLERK AUTHENTICATION VIA REST API ---
CLERK_SECRET_KEY = os.environ.get("CLERK_SECRET_KEY")
CLERK_API_BASE_URL = "https://api.clerk.com/v1"

if not CLERK_SECRET_KEY:
    raise RuntimeError("CLERK_SECRET_KEY is not set in environment variables.")

# --- AUTHENTICATION DECORATOR ---
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            raise Unauthorized("Missing Authorization Header")
        
        try:
            token = auth_header.split(' ')[1]
            # Use Clerk's API to verify the token
            headers = {"Authorization": f"Bearer {CLERK_SECRET_KEY}"}
            # The /users/me endpoint is a good way to validate the token and get user info
            # For session claims (like org_role), you might need to use /sessions/{session_id}/verify
            # but for simplicity and broader use, we can use the introspect endpoint.
            introspect_url = f"{CLERK_API_BASE_URL}/tokens/introspect"
            response = httpx.post(introspect_url, headers=headers, data={"token": token})
            
            if response.status_code == 200:
                # Attach claims to the request for easy access in routes
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
# Note: These models are defined here. The models.py file seems to have a different structure.
# For this fix, we are using the models defined directly in app.py.
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
    restaurant = db.relationship('Restaurant', back_populates='dishes') # Added back_populates

with app.app_context():
    db.create_all()

# --- HELPER FUNCTIONS ---
def get_restaurant_from_claims():
    claims = getattr(request, 'claims', {})
    # In Clerk's token introspection, active organization details are in `active_org_id`
    org_id = claims.get('active_org_id')
    if not org_id:
        return None, ('Organization ID not found in token', 401)
    
    restaurant = Restaurant.query.filter_by(clerk_org_id=org_id).first()
    if not restaurant:
        return None, ('Restaurant not found for this organization', 404)
    
    return restaurant, None

def is_admin():
    claims = getattr(request, 'claims', {})
    # The role is in `active_org_role`
    return claims.get('active_org_role') == 'org:admin'

# --- CLERK WEBHOOK ---
@app.route("/api/clerk-webhook", methods=["POST"])
def clerk_webhook():
    # ... (Your existing webhook logic remains here)
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

    # Add other webhook handlers here (organization.created, etc.)

    return jsonify(status="success"), 200

# --- STATIC FILE ROUTE (NEW) ---
# This route is necessary to serve the uploaded logos to the frontend.
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- PROTECTED ROUTES ---

@app.route('/api/v1/restaurant/settings', methods=['GET', 'PUT'])
@requires_auth
def restaurant_settings():
    restaurant, error = get_restaurant_from_claims()
    if error:
        return jsonify({"error": error[0]}), error[1]

    # Only admins can change settings
    if not is_admin():
        return jsonify({"error": "Forbidden: You must be an admin to perform this action."}), 403

    if request.method == 'GET':
        # Construct the full URL for the logo if it exists
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
        # Handle form data from the multipart request
        restaurant.name = request.form.get('name', restaurant.name)
        restaurant.primary_color = request.form.get('primaryColor', restaurant.primary_color)
        restaurant.google_link = request.form.get('googleLink', restaurant.google_link)
        restaurant.tripadvisor_link = request.form.get('tripadvisorLink', restaurant.tripadvisor_link)

        # Handle file upload
        logo_url_full = None
        if 'logo' in request.files:
            file = request.files['logo']
            if file and file.filename != '' and allowed_file(file.filename):
                # Create a secure, unique filename to avoid conflicts
                filename = secure_filename(f"{restaurant.clerk_org_id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                restaurant.logo_url = filename  # Store just the filename in the DB
        
        try:
            db.session.commit()
            # The frontend expects the logoUrl in the response to update the preview
            logo_url_full = f"/uploads/{restaurant.logo_url}" if restaurant.logo_url else None
            return jsonify({
                "message": "Settings updated successfully.",
                "logoUrl": logo_url_full
            }), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating settings: {e}")
            return jsonify({"error": "Failed to update settings"}), 500
            
    # This should not be reached if methods are GET or PUT
    return jsonify({"error": "Method not allowed"}), 405


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
        claims = getattr(request, 'claims', {})
        user = User.query.filter_by(clerk_id=claims.get('sub')).first()
        if not user:
            return jsonify({"error": "User not found in local DB"}), 404
        stats = {"myReviews": 32, "myAverageRating": 4.9}
        return jsonify(stats)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=True)
