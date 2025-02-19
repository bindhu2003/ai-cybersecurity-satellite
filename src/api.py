from flask import Flask, request, jsonify
import joblib
import numpy as np
import jwt
import datetime
import logging
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize Flask App
app = Flask(__name__)

# 🔹 Secret Key for JWT Authentication (Change this in production)
SECRET_KEY = "your_secret_key_here"
app.config['SECRET_KEY'] = SECRET_KEY

# ✅ Use In-Memory Rate Limiting (No Redis/SQLite Needed)
limiter = Limiter(get_remote_address, app=app)

# Load trained model and scaler
model = joblib.load("model/intrusion_model.pkl")
scaler = joblib.load("model/scaler.pkl")
feature_names = joblib.load("model/feature_names.pkl")

# ✅ Separate Intrusion Logs
intrusion_logger = logging.getLogger("intrusion_logger")
intrusion_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("intrusion_logs.txt")
file_handler.setFormatter(logging.Formatter("%(asctime)s - Intrusion Detected: %(message)s"))
intrusion_logger.addHandler(file_handler)

# ❌ Disable Flask Debug Logging in `intrusion_logs.txt`
app_logger = logging.getLogger("werkzeug")
app_logger.setLevel(logging.WARNING)  # Only show warnings & errors in console
flask_file_handler = logging.FileHandler("flask_logs.txt")
app_logger.addHandler(flask_file_handler)

# 🔹 Authentication Decorator (Protects Routes)
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token is missing!"}), 403
        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid token!"}), 403
        return f(*args, **kwargs)
    return decorated

# 🔹 Login Route (Generates JWT Token)
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")  # Limits login attempts
def login():
    auth = request.json
    if auth and auth.get("username") == "admin" and auth.get("password") == "password":
        token = jwt.encode(
            {"exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401

# 🔹 Intrusion Detection API (Protected Route)
@app.route("/predict", methods=["POST"])
@token_required
@limiter.limit("10 per minute")  # Limits intrusion checks
def predict():
    data = request.json
    try:
        # Ensure all required features are in the request
        missing_features = [feature for feature in feature_names if feature not in data]
        if missing_features:
            return jsonify({"error": f"Missing features: {missing_features}"}), 400

        # Convert input to NumPy array
        input_data = np.array([data[feature] for feature in feature_names]).reshape(1, -1)
        input_data = scaler.transform(input_data)

        # Predict intrusion
        prediction = model.predict(input_data)[0]
        intrusion_status = bool(prediction)

        # ✅ Log only real intrusions, not server logs
        intrusion_logger.info(f"{intrusion_status}, Data: {data}")

        return jsonify({"intrusion_detected": intrusion_status})

    except Exception as e:
        intrusion_logger.error(f"Error: {str(e)}, Data: {data}")
        return jsonify({"error": str(e)}), 400

# ✅ Run the API
if __name__ == "__main__":
    app.run(debug=True)
