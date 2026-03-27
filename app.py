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
CORS(app)

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "smart_lock.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Firebase Admin (only if key file exists)
try:
    import firebase_admin
    from firebase_admin import credentials, messaging
    key_path = os.path.join(basedir, 'firebase-key.json')
    if os.path.exists(key_path):
        cred = credentials.Certificate(key_path)
        firebase_admin.initialize_app(cred)
        print("✓ Firebase initialized")
    else:
        print("⚠ firebase-key.json not found, push notifications disabled")
except Exception as e:
    print(f"⚠ Firebase init failed: {e}")

def send_push_notification(title, body):
    """Send push notification to all registered devices"""
    try:
        import firebase_admin
        from firebase_admin import messaging
        fcm_tokens = [u.fcm_token for u in User.query.all() if u.fcm_token]
        if not fcm_tokens:
            print("No FCM tokens registered")
            return
        message = messaging.MulticastMessage(
            notification=messaging.Notification(title=title, body=body),
            tokens=fcm_tokens,
        )
        messaging.send_each_for_multicast(message)
        print(f"✓ Push notification sent: {title}")
    except Exception as e:
        print(f"Push notification failed: {e}")


# ==================== DATABASE MODELS ====================

class User(db.Model):
    """User account model - stores app user login info"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=True)
    fcm_token = db.Column(db.String(255), nullable=True)
    pi_id = db.Column(db.String(17), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    pi = db.relationship('RaspberryPi', uselist=False, backref='owner')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_token(self):
        self.token = secrets.token_urlsafe(32)
        return self.token


class RaspberryPi(db.Model):
    """Raspberry Pi hardware registry model"""
    __tablename__ = 'raspberry_pis'

    id = db.Column(db.Integer, primary_key=True)
    unique_id = db.Column(db.String(17), unique=True, nullable=False)
    stream_url = db.Column(db.String(255), nullable=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    logs = db.relationship('Log', backref='pi', lazy=True, cascade='all, delete-orphan')
    pi_users = db.relationship('PiUser', backref='pi', lazy=True, cascade='all, delete-orphan')


class Log(db.Model):
    """Access log model - records door access attempts"""
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    pi_unique_id = db.Column(db.String(17), db.ForeignKey('raspberry_pis.unique_id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False)
    method = db.Column(db.String(50), nullable=True)
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
    if not token:
        return None
    return User.query.filter_by(token=token).first()


# ==================== API ENDPOINTS ====================

@app.route('/', methods=['GET'])
def root():
    return jsonify({
        "name": "SmartLock Backend API",
        "version": "1.0.0",
        "status": "running"
    }), 200


# ---------- AUTHENTICATION ----------

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({"message": "Missing username, email, or password"}), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Username already exists"}), 409
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Email already exists"}), 409
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


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    if not data or not (data.get('username') or data.get('email')) or not data.get('password'):
        return jsonify({"message": "Missing credentials"}), 400
    user = User.query.filter(
        (User.username == data.get('username')) | (User.email == data.get('email'))
    ).first()
    if not user or not user.check_password(data['password']):
        return jsonify({"message": "Invalid credentials"}), 401
    user.generate_token()
    db.session.commit()
    return jsonify({
        "message": "Login successful",
        "token": user.token,
        "username": user.username,
        "pi_id": user.pi_id
    }), 200


# ---------- USER ENDPOINTS ----------

@app.route('/user/save_fcm_token', methods=['POST'])
def save_fcm_token():
    """Save FCM token for push notifications"""
    data = request.json
    user = verify_token(data.get('token'))
    if not user:
        return jsonify({"message": "Unauthorized"}), 401
    user.fcm_token = data.get('fcm_token')
    db.session.commit()
    return jsonify({"message": "FCM token saved"}), 200


@app.route('/user/connect_pi', methods=['POST'])
def connect_pi():
    data = request.json
    user = verify_token(data.get('token'))
    if not user:
        return jsonify({"message": "Unauthorized"}), 401
    if not data.get('pi_unique_id'):
        return jsonify({"message": "Missing pi_unique_id"}), 400
    pi_unique_id = data['pi_unique_id'].upper()
    pi = RaspberryPi.query.filter_by(unique_id=pi_unique_id).first()
    if not pi:
        pi = RaspberryPi(unique_id=pi_unique_id)
        db.session.add(pi)
    user.pi_id = pi_unique_id
    pi.owner_id = user.id
    db.session.commit()
    return jsonify({"message": "Pi connected successfully", "pi_unique_id": pi_unique_id}), 200


@app.route('/user/get_logs', methods=['POST'])
def get_logs():
    data = request.json
    user = verify_token(data.get('token'))
    if not user or not user.pi_id:
        return jsonify({"message": "Unauthorized or no Pi connected"}), 401
    logs = Log.query.filter_by(pi_unique_id=user.pi_id).order_by(Log.timestamp.desc()).all()
    return jsonify({
        "pi_unique_id": user.pi_id,
        "total_logs": len(logs),
        "logs": [{
            "id": l.id,
            "name": l.name,
            "timestamp": l.timestamp.isoformat(),
            "status": l.status,
            "method": l.method
        } for l in logs]
    }), 200


@app.route('/user/get_stream_url', methods=['POST'])
def get_stream_url():
    data = request.json
    user = verify_token(data.get('token'))
    if not user or not user.pi_id:
        return jsonify({"message": "Unauthorized or no Pi connected"}), 401
    pi = RaspberryPi.query.filter_by(unique_id=user.pi_id).first()
    if not pi or not pi.stream_url:
        return jsonify({"message": "Stream URL not available"}), 404
    return jsonify({"pi_unique_id": user.pi_id, "stream_url": pi.stream_url}), 200


@app.route('/user/get_pi_users', methods=['POST'])
def get_pi_users():
    data = request.json
    user = verify_token(data.get('token'))
    if not user or not user.pi_id:
        return jsonify({"message": "Unauthorized or no Pi connected"}), 401
    pi_internal_users = PiUser.query.filter_by(pi_unique_id=user.pi_id).all()
    return jsonify({
        "pi_unique_id": user.pi_id,
        "total_users": len(pi_internal_users),
        "pi_users": [{
            "name": u.name,
            "fingerprint_exists": u.has_fingerprint,
            "faceid_exists": u.has_faceid,
            "added_at": u.added_at.isoformat()
        } for u in pi_internal_users]
    }), 200


# ---------- RASPBERRY PI ENDPOINTS ----------

@app.route('/pi/update_stream', methods=['POST'])
def update_stream():
    data = request.json
    if not data or not data.get('unique_id') or not data.get('stream_url'):
        return jsonify({"message": "Missing unique_id or stream_url"}), 400
    pi_unique_id = data['unique_id'].upper()
    pi = RaspberryPi.query.filter_by(unique_id=pi_unique_id).first()
    if not pi:
        pi = RaspberryPi(unique_id=pi_unique_id)
        db.session.add(pi)
    pi.stream_url = data['stream_url']
    pi.last_seen = datetime.utcnow()
    db.session.commit()
    return jsonify({"message": "Stream URL updated successfully", "pi_unique_id": pi_unique_id}), 200


@app.route('/pi/add_log', methods=['POST'])
def add_log():
    data = request.json
    if not data or not data.get('unique_id') or not data.get('name') or not data.get('timestamp') or not data.get('status'):
        return jsonify({"message": "Missing required fields"}), 400
    pi_unique_id = data['unique_id'].upper()
    pi = RaspberryPi.query.filter_by(unique_id=pi_unique_id).first()
    if not pi:
        return jsonify({"message": "Pi not found"}), 404
    try:
        log_timestamp = datetime.fromisoformat(data['timestamp'])
    except ValueError:
        return jsonify({"message": "Invalid timestamp format"}), 400
    log_entry = Log(
        pi_unique_id=pi_unique_id,
        name=data['name'],
        timestamp=log_timestamp,
        status=data['status'],
        method=data.get('method', 'unknown')
    )
    db.session.add(log_entry)
    db.session.commit()

    # Send push notification
    status_emoji = "✅" if data['status'] == 'Success' else "❌"
    send_push_notification(
        title=f"{status_emoji} Door Access — {data['status']}",
        body=f"{data['name']} used {data.get('method', 'unknown')} at {data['timestamp']}"
    )

    return jsonify({
        "message": "Log entry created successfully",
        "log_id": log_entry.id,
        "pi_unique_id": pi_unique_id,
        "status": data['status']
    }), 201


@app.route('/pi/add_biometric_user', methods=['POST'])
def add_biometric_user():
    data = request.json
    if not data or not data.get('unique_id') or not data.get('name'):
        return jsonify({"message": "Missing unique_id or name"}), 400
    pi_unique_id = data['unique_id'].upper()
    pi = RaspberryPi.query.filter_by(unique_id=pi_unique_id).first()
    if not pi:
        return jsonify({"message": "Pi not found"}), 404
    pi_user = PiUser.query.filter_by(pi_unique_id=pi_unique_id, name=data['name']).first()
    if pi_user:
        pi_user.has_fingerprint = data.get('has_fingerprint', pi_user.has_fingerprint)
        pi_user.has_faceid = data.get('has_faceid', pi_user.has_faceid)
    else:
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


# ---------- HEALTH & DEBUG ----------

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "message": "SmartLock Backend is running"}), 200


@app.route('/debug/all_data', methods=['GET'])
def debug_all_data():
    users = User.query.all()
    pis = RaspberryPi.query.all()
    logs = Log.query.all()
    pi_users = PiUser.query.all()
    return jsonify({
        "users": [{"id": u.id, "username": u.username, "email": u.email, "token": u.token, "pi_id": u.pi_id} for u in users],
        "pis": [{"id": p.id, "unique_id": p.unique_id, "stream_url": p.stream_url, "owner_id": p.owner_id, "last_seen": p.last_seen.isoformat()} for p in pis],
        "logs": [{"id": l.id, "pi_unique_id": l.pi_unique_id, "name": l.name, "timestamp": l.timestamp.isoformat(), "status": l.status, "method": l.method} for l in logs],
        "pi_users": [{"id": u.id, "pi_unique_id": u.pi_unique_id, "name": u.name, "has_fingerprint": u.has_fingerprint, "has_faceid": u.has_faceid, "added_at": u.added_at.isoformat()} for u in pi_users]
    }), 200


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"message": "Endpoint not found"}), 404

@app.errorhandler(400)
def bad_request(error):
    return jsonify({"message": "Bad request"}), 400

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({"message": "Internal server error"}), 500


# ==================== MAIN ====================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✓ Database initialized")
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 SmartLock Backend starting on port {port}")
    app.run(debug=False, host='0.0.0.0', port=port)

    @app.route('/admin/reset_db', methods=['GET'])
def reset_db():
    """Temporarily reset database - remove after use"""
    db.drop_all()
    db.create_all()
    return jsonify({"message": "Database reset successfully"}), 200