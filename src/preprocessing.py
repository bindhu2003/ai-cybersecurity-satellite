import pandas as pd
import json
import os

# Path to data directory
DATA_DIR = "data"

# Load JSON files
def load_json_file(filename, selected_keys):
    with open(os.path.join(DATA_DIR, filename), 'r') as file:
        data = json.load(file)
        extracted_data = {key: data[key] for key in selected_keys if key in data}
        return pd.DataFrame(extracted_data)

# Features to extract
observation_features = ["VSG", "VSE", "VSB", "VSQ", "VSR", "cn0_G1", "cn0_G2", "numSvs"]
satellite_features = ["cno_G", "cno_E", "cno_B", "cno_Q", "cno_R", "elev_G", "elev_E", "elev_B", "elev_Q", "elev_R"]

# Load data from JSON files
df_observations = load_json_file("observation0.json", observation_features)
df_satellite = load_json_file("satelliteInfomation0.json", satellite_features)

# Function to compute `_mean`, `_max`, `_min` for list-based features
def compute_statistics(df):
    for column in df.columns:
        df[column + "_mean"] = df[column].apply(lambda x: sum(x)/len(x) if isinstance(x, list) else x)
        df[column + "_max"] = df[column].apply(lambda x: max(x) if isinstance(x, list) else x)
        df[column + "_min"] = df[column].apply(lambda x: min(x) if isinstance(x, list) else x)
    return df

# Apply feature extraction
df_observations = compute_statistics(df_observations)
df_satellite = compute_statistics(df_satellite)

# Select only the newly created statistical features
df_observations = df_observations.filter(like="_mean").join(df_observations.filter(like="_max")).join(df_observations.filter(like="_min"))
df_satellite = df_satellite.filter(like="_mean").join(df_satellite.filter(like="_max")).join(df_satellite.filter(like="_min"))

# Merge the processed datasets
df_final = pd.concat([df_observations, df_satellite], axis=1)

# Save the final processed dataset
df_final.to_csv("data/processed_data.csv", index=False)
print("✅ Preprocessing complete! Data saved to data/processed_data.csv")
