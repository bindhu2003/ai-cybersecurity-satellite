from flask import Flask, request, jsonify
import joblib
import numpy as np
import jwt
import datetime
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

# Initialize Flask App
app = Flask(__name__)

# Secret key for JWT authentication
app.config["SECRET_KEY"] = "your_secret_key"

# Initialize Rate Limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])

# Load trained model and scaler
model = joblib.load("model/intrusion_model.pkl")
scaler = joblib.load("model/scaler.pkl")
feature_names = joblib.load("model/feature_names.pkl")

# Setup logging
logging.basicConfig(filename="intrusion_logs.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# ✅ **Homepage Route**
@app.route("/")
def home():
    return jsonify({"message": "Welcome to AI Cybersecurity API! Use /predict to make requests."})


# ✅ **JWT Authentication Decorator**
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("x-access-token")
        if not token:
            return jsonify({"error": "Token is missing!"}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token!"}), 401

        return f(*args, **kwargs)

    return decorated


# ✅ **Generate JWT Token**
@app.route("/login", methods=["POST"])
def login():
    auth = request.json
    if auth and auth.get("username") == "admin" and auth.get("password") == "password":
        token = jwt.encode(
            {"user": auth["username"], "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config["SECRET_KEY"],
            algorithm="HS256",
        )
        return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401


# ✅ **Intrusion Detection Prediction Route**
@app.route("/predict", methods=["POST"])
@token_required
@limiter.limit("5 per minute")
def predict():
    try:
        data = request.json
        input_data = np.array([data[feature] for feature in feature_names]).reshape(1, -1)
        input_scaled = scaler.transform(input_data)
        prediction = model.predict(input_scaled)[0]
        
        # Log Intrusion Events
        logging.info(f"Intrusion Detected: {bool(prediction)}, Data: {data}")

        return jsonify({"intrusion_detected": bool(prediction)})

    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ✅ **Run Flask App**
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
