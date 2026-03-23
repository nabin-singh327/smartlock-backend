"""
SmartLock Backend - Flask API with SQLAlchemy ORM
Raspberry Pi Smart Lock System
"""

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime
import os

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Allow requests from the React frontend (port 3000)

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "smart_lock.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# ==================== DATABASE MODELS ====================

class User(db.Model):
    """User account model - stores app user login info"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=True)
    pi_id = db.Column(db.String(17), nullable=True)  # MAC address of connected Pi
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    pi = db.relationship('RaspberryPi', uselist=False, backref='owner')
    
    def set_password(self, password):
        """Hash the password and store it"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify the provided password against the hash"""
        return check_password_hash(self.password_hash, password)
    
    def generate_token(self):
        """Generate a unique token for this user"""
        self.token = secrets.token_urlsafe(32)
        return self.token


class RaspberryPi(db.Model):
    """Raspberry Pi hardware registry model"""
    __tablename__ = 'raspberry_pis'
    
    id = db.Column(db.Integer, primary_key=True)
    unique_id = db.Column(db.String(17), unique=True, nullable=False)  # MAC address (AA:BB:CC:DD:EE:FF)
    stream_url = db.Column(db.String(255), nullable=True)  # Live video feed URL
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    logs = db.relationship('Log', backref='pi', lazy=True, cascade='all, delete-orphan')
    pi_users = db.relationship('PiUser', backref='pi', lazy=True, cascade='all, delete-orphan')


class Log(db.Model):
    """Access log model - records door access attempts"""
    __tablename__ = 'logs'
    
    id = db.Column(db.Integer, primary_key=True)
    pi_unique_id = db.Column(db.String(17), db.ForeignKey('raspberry_pis.unique_id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)  # Who tried to open
    timestamp = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False)  # "Success" or "Failed"
    method = db.Column(db.String(50), nullable=True)  # "fingerprint", "faceid", "keypad", etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PiUser(db.Model):
    """Biometric user registry - stores users saved on the Pi"""
    __tablename__ = 'pi_users'
    
    id = db.Column(db.Integer, primary_key=True)
    pi_unique_id = db.Column(db.String(17), db.ForeignKey('raspberry_pis.unique_id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    has_fingerprint = db.Column(db.Boolean, default=False)
    has_faceid = db.Column(db.Boolean, default=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)


# ==================== UTILITY FUNCTIONS ====================

def verify_token(token):
    """Verify the user token and return the user object"""
    if not token:
        return None
    user = User.query.filter_by(token=token).first()
    return user


# ==================== API ENDPOINTS ====================

# 0. Root Endpoint - API Info
@app.route('/', methods=['GET'])
def root():
    """Root endpoint - shows API information"""
    return jsonify({
        "name": "SmartLock Backend API",
        "version": "1.0.0",
        "description": "Raspberry Pi Smart Lock System - Flask API",
        "status": "running",
        "endpoints": {
            "authentication": {
                "register": "POST /auth/register",
                "login": "POST /auth/login"
            },
            "user_operations": {
                "connect_pi": "POST /user/connect_pi",
                "get_logs": "POST /user/get_logs",
                "get_stream_url": "POST /user/get_stream_url",
                "get_pi_users": "POST /user/get_pi_users"
            },
            "raspberry_pi_operations": {
                "update_stream": "POST /pi/update_stream",
                "add_log": "POST /pi/add_log",
                "add_biometric_user": "POST /pi/add_biometric_user"
            },
            "utility": {
                "health": "GET /health",
                "debug_all_data": "GET /debug/all_data"
            }
        },
        "documentation": "See README.md or TESTING_GUIDE.md for complete documentation"
    }), 200


# ---------- AUTHENTICATION ENDPOINTS ----------

# 1. User Registration
@app.route('/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.json
    
    # Validate input
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({"message": "Missing username, email, or password"}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Username already exists"}), 409
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Email already exists"}), 409
    
    # Create new user
    user = User(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    user.generate_token()
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({
        "message": "User registered successfully",
        "user_id": user.id,
        "username": user.username,
        "token": user.token
    }), 201


# 2. User Login
@app.route('/auth/login', methods=['POST'])
def login():
    """Login a user and return token"""
    data = request.json
    
    # Validate input
    if not data or not (data.get('username') or data.get('email')) or not data.get('password'):
        return jsonify({"message": "Missing credentials"}), 400
    
    # Find user by username or email
    user = User.query.filter(
        (User.username == data.get('username')) | (User.email == data.get('email'))
    ).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({"message": "Invalid credentials"}), 401
    
    # Generate new token
    user.generate_token()
    db.session.commit()
    
    return jsonify({
        "message": "Login successful",
        "token": user.token,
        "username": user.username,
        "pi_id": user.pi_id
    }), 200


# ---------- USER API ENDPOINTS ----------

# 3. User Connect Pi (Add Pi to account)
@app.route('/user/connect_pi', methods=['POST'])
def connect_pi():
    """User adds their Raspberry Pi by MAC address"""
    data = request.json
    
    # Validate token
    user = verify_token(data.get('token'))
    if not user:
        return jsonify({"message": "Unauthorized"}), 401
    
    # Validate Pi unique ID
    if not data.get('pi_unique_id'):
        return jsonify({"message": "Missing pi_unique_id"}), 400
    
    pi_unique_id = data['pi_unique_id'].upper()
    
    # Check if Pi exists
    pi = RaspberryPi.query.filter_by(unique_id=pi_unique_id).first()
    if not pi:
        # Create new Pi entry if it doesn't exist
        pi = RaspberryPi(unique_id=pi_unique_id)
        db.session.add(pi)
    
    # Assign Pi to user
    user.pi_id = pi_unique_id
    pi.owner_id = user.id
    
    db.session.commit()
    
    return jsonify({
        "message": "Pi connected successfully",
        "pi_unique_id": pi_unique_id
    }), 200


# 4. User Get Logs
@app.route('/user/get_logs', methods=['POST'])
def get_logs():
    """Get all access logs for user's connected Pi"""
    data = request.json
    
    # Validate token
    user = verify_token(data.get('token'))
    if not user or not user.pi_id:
        return jsonify({"message": "Unauthorized or no Pi connected"}), 401
    
    # Fetch logs for user's Pi
    logs = Log.query.filter_by(pi_unique_id=user.pi_id).order_by(Log.timestamp.desc()).all()
    
    log_list = []
    for log in logs:
        log_list.append({
            "id": log.id,
            "name": log.name,
            "timestamp": log.timestamp.isoformat(),
            "status": log.status,
            "method": log.method
        })
    
    return jsonify({
        "pi_unique_id": user.pi_id,
        "total_logs": len(log_list),
        "logs": log_list
    }), 200


# 5. User Get Live Feed URL
@app.route('/user/get_stream_url', methods=['POST'])
def get_stream_url():
    """Get the live video feed URL for user's connected Pi"""
    data = request.json
    
    # Validate token
    user = verify_token(data.get('token'))
    if not user or not user.pi_id:
        return jsonify({"message": "Unauthorized or no Pi connected"}), 401
    
    # Fetch Pi and get stream URL
    pi = RaspberryPi.query.filter_by(unique_id=user.pi_id).first()
    if not pi or not pi.stream_url:
        return jsonify({"message": "Stream URL not available"}), 404
    
    return jsonify({
        "pi_unique_id": user.pi_id,
        "stream_url": pi.stream_url
    }), 200


# 6. User Get all registered users on Pi (Biometric registry)
@app.route('/user/get_pi_users', methods=['POST'])
def get_pi_users():
    """Get all users registered inside the Pi hardware"""
    data = request.json
    
    # Validate token
    user = verify_token(data.get('token'))
    if not user or not user.pi_id:
        return jsonify({"message": "Unauthorized or no Pi connected"}), 401
    
    # Fetch all residents/users registered on that specific Pi
    pi_internal_users = PiUser.query.filter_by(pi_unique_id=user.pi_id).all()
    
    user_list = []
    for u in pi_internal_users:
        user_list.append({
            "name": u.name,
            "fingerprint_exists": u.has_fingerprint,
            "faceid_exists": u.has_faceid,
            "added_at": u.added_at.isoformat()
        })
    
    return jsonify({
        "pi_unique_id": user.pi_id,
        "total_users": len(user_list),
        "pi_users": user_list
    }), 200


# ---------- RASPBERRY PI API ENDPOINTS ----------

# 7. Pi Update Stream URL
@app.route('/pi/update_stream', methods=['POST'])
def update_stream():
    """Pi updates its live stream URL"""
    data = request.json
    
    # Validate Pi unique ID
    if not data or not data.get('unique_id') or not data.get('stream_url'):
        return jsonify({"message": "Missing unique_id or stream_url"}), 400
    
    pi_unique_id = data['unique_id'].upper()
    
    # Find or create Pi
    pi = RaspberryPi.query.filter_by(unique_id=pi_unique_id).first()
    if not pi:
        pi = RaspberryPi(unique_id=pi_unique_id)
        db.session.add(pi)
    
    # Update stream URL and last seen time
    pi.stream_url = data['stream_url']
    pi.last_seen = datetime.utcnow()
    
    db.session.commit()
    
    return jsonify({
        "message": "Stream URL updated successfully",
        "pi_unique_id": pi_unique_id,
        "stream_url": data['stream_url']
    }), 200


# 8. Pi Add Log Entry
@app.route('/pi/add_log', methods=['POST'])
def add_log():
    """Pi adds a new log entry (door access attempt)"""
    data = request.json
    
    # Validate input
    if not data or not data.get('unique_id') or not data.get('name') or not data.get('timestamp') or not data.get('status'):
        return jsonify({"message": "Missing required fields: unique_id, name, timestamp, status"}), 400
    
    pi_unique_id = data['unique_id'].upper()
    
    # Verify Pi exists
    pi = RaspberryPi.query.filter_by(unique_id=pi_unique_id).first()
    if not pi:
        return jsonify({"message": "Pi not found"}), 404
    
    # Parse timestamp
    try:
        log_timestamp = datetime.fromisoformat(data['timestamp'])
    except ValueError:
        return jsonify({"message": "Invalid timestamp format. Use ISO format (YYYY-MM-DD HH:MM:SS)"}), 400
    
    # Create log entry
    log_entry = Log(
        pi_unique_id=pi_unique_id,
        name=data['name'],
        timestamp=log_timestamp,
        status=data['status'],
        method=data.get('method', 'unknown')
    )
    
    db.session.add(log_entry)
    db.session.commit()
    
    return jsonify({
        "message": "Log entry created successfully",
        "log_id": log_entry.id,
        "pi_unique_id": pi_unique_id,
        "status": data['status']
    }), 201


# 9. Pi Add/Update Biometric User
@app.route('/pi/add_biometric_user', methods=['POST'])
def add_biometric_user():
    """Pi adds a user with biometric info to registry"""
    data = request.json
    
    # Validate input
    if not data or not data.get('unique_id') or not data.get('name'):
        return jsonify({"message": "Missing unique_id or name"}), 400
    
    pi_unique_id = data['unique_id'].upper()
    
    # Verify Pi exists
    pi = RaspberryPi.query.filter_by(unique_id=pi_unique_id).first()
    if not pi:
        return jsonify({"message": "Pi not found"}), 404
    
    # Check if user already exists
    pi_user = PiUser.query.filter_by(
        pi_unique_id=pi_unique_id,
        name=data['name']
    ).first()
    
    if pi_user:
        # Update existing user
        pi_user.has_fingerprint = data.get('has_fingerprint', pi_user.has_fingerprint)
        pi_user.has_faceid = data.get('has_faceid', pi_user.has_faceid)
    else:
        # Create new user
        pi_user = PiUser(
            pi_unique_id=pi_unique_id,
            name=data['name'],
            has_fingerprint=data.get('has_fingerprint', False),
            has_faceid=data.get('has_faceid', False)
        )
        db.session.add(pi_user)
    
    db.session.commit()
    
    return jsonify({
        "message": "Biometric user added/updated successfully",
        "pi_unique_id": pi_unique_id,
        "name": data['name'],
        "has_fingerprint": pi_user.has_fingerprint,
        "has_faceid": pi_user.has_faceid
    }), 201


# ---------- HEALTH CHECK & DEBUG ----------

# 10. Health Check
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok", "message": "SmartLock Backend is running"}), 200


# 11. Debug Get All Data (for testing only)
@app.route('/debug/all_data', methods=['GET'])
def debug_all_data():
    """Get all data in database (for testing/debugging)"""
    users = User.query.all()
    pis = RaspberryPi.query.all()
    logs = Log.query.all()
    pi_users = PiUser.query.all()
    
    return jsonify({
        "users": [{
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "token": u.token,
            "pi_id": u.pi_id
        } for u in users],
        "pis": [{
            "id": p.id,
            "unique_id": p.unique_id,
            "stream_url": p.stream_url,
            "owner_id": p.owner_id,
            "last_seen": p.last_seen.isoformat()
        } for p in pis],
        "logs": [{
            "id": l.id,
            "pi_unique_id": l.pi_unique_id,
            "name": l.name,
            "timestamp": l.timestamp.isoformat(),
            "status": l.status,
            "method": l.method
        } for l in logs],
        "pi_users": [{
            "id": u.id,
            "pi_unique_id": u.pi_unique_id,
            "name": u.name,
            "has_fingerprint": u.has_fingerprint,
            "has_faceid": u.has_faceid,
            "added_at": u.added_at.isoformat()
        } for u in pi_users]
    }), 200


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({"message": "Endpoint not found"}), 404


@app.errorhandler(400)
def bad_request(error):
    """Handle 400 errors"""
    return jsonify({"message": "Bad request"}), 400


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    return jsonify({"message": "Internal server error"}), 500


# ==================== MAIN ====================

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
        print("✓ Database initialized")
    
    # Run the Flask app
print("🚀 SmartLock Backend starting on http://192.168.18.8:5000")
app.run(debug=True, host='0.0.0.0', port=5000)
