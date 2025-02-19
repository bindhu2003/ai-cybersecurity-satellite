import pandas as pd
import matplotlib.pyplot as plt
import re

# File path
LOG_FILE = "intrusion_logs.txt"

# Read and parse log file
def parse_logs(file_path):
    logs = []
    with open(file_path, "r") as file:
        for line in file:
            match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3} - Intrusion Detected: (\w+), Data:", line)
            if match:
                timestamp, status = match.groups()
                logs.append({"timestamp": timestamp, "intrusion_detected": status == "True"})
    
    return pd.DataFrame(logs)

# Load logs into DataFrame
df = parse_logs(LOG_FILE)

# ✅ Check if logs were extracted correctly
if df.empty:
    print("⚠️ No valid intrusion logs found! Check `intrusion_logs.txt` format.")
else:
    # Convert timestamp column to datetime format
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # ✅ Show summary statistics
    print(df["intrusion_detected"].value_counts())

    # 📊 Plot Intrusions Over Time
    plt.figure(figsize=(10, 5))
    df.set_index("timestamp")["intrusion_detected"].resample("1T").sum().plot(kind="line", color="red", marker="o")
    plt.title("Intrusion Attempts Over Time")
    plt.xlabel("Time")
    plt.ylabel("Intrusions Detected")
    plt.grid()
    plt.show()
