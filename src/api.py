import os
import json
import logging
import joblib
import datetime
import jwt as pyjwt  # ✅ Fix for JWT encoding error
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
try:
    model = joblib.load("model/intrusion_model.pkl")
    scaler = joblib.load("model/scaler.pkl")
    feature_names = joblib.load("model/feature_names.pkl")
except Exception as e:
    print(f"⚠️ Model loading error: {e}")

# Configure Rate Limiting (Using in-memory storage)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://"  # Use "filesystem://rate_limit_storage" for persistent storage
)

# Setup logging for intrusion detection
LOG_FILE = "intrusion_logs.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# Dummy user for authentication
USER_DATA = {
    "admin": generate_password_hash("password123")  # Username: admin, Password: password123
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
    try:
        data = request.json
        if not data:
            return jsonify({"message": "Missing JSON body"}), 400

        username = data.get("username")
        password = data.get("password")

        if username in USER_DATA and check_password_hash(USER_DATA[username], password):
            token = pyjwt.encode(
                {"user": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                app.config["SECRET_KEY"], algorithm="HS256"
            )
            return jsonify({"token": token})
        return jsonify({"message": "Invalid credentials"}), 401
    
    except Exception as e:
        logging.error(f"Error in login: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500


# ✅ Predict Intrusion (JWT Required)
@app.route("/predict", methods=["POST"])
@limiter.limit("5 per minute")  # ✅ Prevent abuse by limiting requests
def predict():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token is missing!"}), 401

    try:
        pyjwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        return jsonify({"message": "Token expired!"}), 401
    except pyjwt.InvalidTokenError:
        return jsonify({"message": "Invalid token!"}), 401

    try:
        data = request.json
        if not data:
            return jsonify({"message": "Missing JSON body"}), 400

        input_features = [data.get(feature, 0) for feature in feature_names]
        input_scaled = scaler.transform([input_features])
        prediction = model.predict(input_scaled)[0]
        
        intrusion_detected = bool(prediction)
        logging.info(f"Intrusion Detected: {intrusion_detected}, Data: {data}")

        return jsonify({"intrusion_detected": intrusion_detected})
    except Exception as e:
        logging.error(f"Prediction error: {str(e)}")
        return jsonify({"error": "Prediction failed"}), 400


# Run Flask App (Local or Render Deployment)
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # ✅ Render assigns a dynamic port
    app.run(host="0.0.0.0", port=port)
