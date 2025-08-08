# flask_auth_backend/app.py

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import psycopg2
from psycopg2.pool import SimpleConnectionPool
import jwt
import datetime
import os

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)

# Secret used for signing JWTs (set in Render env vars)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key')

# --------------------------------------------------
# Database: prefer DATABASE_URL; otherwise compose DSN
# --------------------------------------------------
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    DB_NAME = os.environ.get('DB_NAME')
    DB_USER = os.environ.get('DB_USER')
    DB_PASSWORD = os.environ.get('DB_PASSWORD')
    DB_HOST = os.environ.get('DB_HOST')
    DB_PORT = os.environ.get('DB_PORT', '5432')
    if not all([DB_NAME, DB_USER, DB_PASSWORD, DB_HOST]):
        raise RuntimeError("Database environment variables are not fully set. Provide DATABASE_URL or DB_* vars.")
    DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Render Postgres typically requires SSL
DATABASE_URL += ("?sslmode=require" if "sslmode=" not in DATABASE_URL else "")

# Create a small connection pool (avoid a single long-lived connection)
pool = SimpleConnectionPool(minconn=1, maxconn=5, dsn=DATABASE_URL)


def db_execute(query, params=None, fetchone=False, fetchall=False, commit=False):
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(query, params or ())
            if commit:
                conn.commit()
            if fetchone:
                return cur.fetchone()
            if fetchall:
                return cur.fetchall()
    finally:
        pool.putconn(conn)


@app.route('/health', methods=['GET'])
def health():
    # Basic health check and DB check
    try:
        row = db_execute("SELECT 1", fetchone=True)
        ok = (row and row[0] == 1)
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500
    return jsonify({"status": "ok", "db": ok})


@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not name or not email or not password:
        return jsonify({"error": "name, email, and password are required"}), 400

    # Check if email exists
    existing = db_execute("SELECT id FROM users WHERE email = %s", (email,), fetchone=True)
    if existing:
        return jsonify({"error": "Email already registered"}), 409

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    db_execute(
        "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
        (name, email, hashed_pw), commit=True
    )
    return jsonify({"message": "User created successfully"}), 201


@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    user = db_execute("SELECT id, name, email, password FROM users WHERE email = %s", (email,), fetchone=True)
    if not user:
        return jsonify({"error": "Invalid email or password"}), 401

    user_id, name, email, hashed = user
    if not bcrypt.check_password_hash(hashed, password):
        return jsonify({"error": "Invalid email or password"}), 401

    token = jwt.encode(
        {
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        },
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )

    return jsonify({"token": token, "user": {"id": user_id, "name": name, "email": email}}), 200


if __name__ == '__main__':
    # For local testing only; Render uses gunicorn start command
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
