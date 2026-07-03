import os
import pandas as pd

DATA_PATH = "data/processed/processed_auth_logs.csv"
OUTPUT_PATH = "reports/ml_evaluation_results.csv"

df = pd.read_csv(DATA_PATH)

required_columns = [
    "ml_anomaly_label",
    "is_ml_anomaly",
    "ml_raw_score",
    "ml_anomaly_score"
]

for col in required_columns:
    if col not in df.columns:
        raise ValueError(f"Missing required column: {col}")

total_logs = len(df)
normal_events = int((df["is_ml_anomaly"] == 0).sum())
ml_anomalies = int((df["is_ml_anomaly"] == 1).sum())
contamination_rate = round((ml_anomalies / total_logs) * 100, 2)
avg_ml_score = round(df["ml_anomaly_score"].mean(), 2)
min_ml_score = round(df["ml_anomaly_score"].min(), 2)
max_ml_score = round(df["ml_anomaly_score"].max(), 2)

label_distribution = df["ml_anomaly_label"].value_counts().to_dict()
prediction_distribution = df["is_ml_anomaly"].value_counts().to_dict()

results = {
    "Total Authentication Logs": total_logs,
    "Normal Events": normal_events,
    "ML Anomalies Detected": ml_anomalies,
    "Contamination Rate (%)": contamination_rate,
    "Average ML Anomaly Score": avg_ml_score,
    "Minimum ML Anomaly Score": min_ml_score,
    "Maximum ML Anomaly Score": max_ml_score,
    "Isolation Forest Normal Label Count": int(label_distribution.get(1, 0)),
    "Isolation Forest Anomaly Label Count": int(label_distribution.get(-1, 0)),
    "Model": "Isolation Forest",
    "Number of Estimators": 100,
    "Configured Contamination": "0.08",
    "Random State": 42
}

os.makedirs("reports", exist_ok=True)
results_df = pd.DataFrame([results])
results_df.to_csv(OUTPUT_PATH, index=False)

print("\nML Anomaly Detection Output Summary")
print("-----------------------------------")
for key, value in results.items():
    print(f"{key}: {value}")

print(f"\nResults saved to: {OUTPUT_PATH}")