import os
import json
import logging
import joblib
import jwt
import datetime
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask App
app = Flask(__name__)

# Secret key for JWT authentication
SECRET_KEY = "supersecretkey"
app.config["SECRET_KEY"] = SECRET_KEY

# Load trained model and scaler
model = joblib.load("model/intrusion_model.pkl")
scaler = joblib.load("model/scaler.pkl")
feature_names = joblib.load("model/feature_names.pkl")

# Configure Rate Limiting (File-based storage)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://"  # Use "filesystem://rate_limit_storage" for persistence
)

# Setup logging for intrusion detection
LOG_FILE = "intrusion_logs.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# Dummy user for authentication
USER_DATA = {
    "user": generate_password_hash("majorproject")  # Username: admin, Password: password123
}

# ----------------------------- #
#         ROUTES
# ----------------------------- #

# ✅ Homepage Route
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Welcome to AI-Powered Cybersecurity API!"})


# ✅ User Login (Generates JWT Token)
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username in USER_DATA and check_password_hash(USER_DATA[username], password):
        token = jwt.encode(
            {"user": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config["SECRET_KEY"], algorithm="HS256"
        )
        return jsonify({"token": token})
    return jsonify({"message": "Invalid credentials"}), 401


# ✅ Predict Intrusion (JWT Required)
@app.route("/predict", methods=["POST"])
@limiter.limit("5 per minute")  # Limit requests to prevent abuse
def predict():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing!"}), 401

    try:
        jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expired!"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token!"}), 401

    try:
        data = request.json
        input_features = [data.get(feature, 0) for feature in feature_names]
        input_scaled = scaler.transform([input_features])
        prediction = model.predict(input_scaled)[0]
        
        intrusion_detected = bool(prediction)
        logging.info(f"Intrusion Detected: {intrusion_detected}, Data: {data}")

        return jsonify({"intrusion_detected": intrusion_detected})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Run Flask App (Local)
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # Default to 10000
    app.run(host="0.0.0.0", port=port)
