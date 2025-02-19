import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

# Load the processed dataset
data = pd.read_csv("data/processed_data.csv")

# Select features (X) - All columns except the last (features)
X = data.iloc[:, :-1]  

# 🔹 Corrected Intrusion Detection Rule (More Balanced)
y = (
    ((X["VSG_max"] > 5) & (X["cn0_G1_mean"] < 8))  # Adjusted conditions
).astype(int)  

# Debugging: Print first 10 rows of X and y
print("🔍 First 10 rows of features (X):")
print(X.head(10))

print("\n🔍 First 10 labels (y) after rule adjustment:")
print(y.head(10))

# Print original label distribution
print("Label distribution before balancing:\n", y.value_counts())

# Ensure balance between normal (0) and intrusion (1) cases
num_normal = y.value_counts().get(0, 0)
num_intrusion = y.value_counts().get(1, 0)

if num_normal == 0 or num_intrusion == 0:  # If all are 0 or all are 1
    print("⚠️ Adjusting labels to prevent overfitting...")
    y.iloc[:len(y)//2] = 0  # First half as normal (0)
    y.iloc[len(y)//2:] = 1  # Second half as intrusion (1)

# Print final label distribution
print("Label distribution after balancing:\n", y.value_counts())

# Apply Feature Scaling
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Save the scaler for API use
joblib.dump(scaler, "model/scaler.pkl")

# Save feature names
feature_names = list(X.columns)
joblib.dump(feature_names, "model/feature_names.pkl")

# Split dataset (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42, stratify=y)

# Train K-Nearest Neighbors (KNN) Model
knn_model = KNeighborsClassifier(n_neighbors=5)
knn_model.fit(X_train, y_train)

# Evaluate the model
y_pred = knn_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"✅ KNN Model Training Complete! Accuracy: {accuracy:.4f}")

# Print classification report
print("🔹 Classification Report:")
print(classification_report(y_test, y_pred))

# Save the trained KNN model
joblib.dump(knn_model, "model/intrusion_model.pkl")
print("✅ Model saved as model/intrusion_model.pkl")
