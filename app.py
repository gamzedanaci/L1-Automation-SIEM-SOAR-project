import shutil
import os
from src.parser.load_data import df
from src.parser.preprocessing import (
    preprocess_data,
    create_time_features
)

from src.features.auth_features import (
    failed_login_features,
    privileged_account_feature,
    device_change_feature,
    rapid_attempts_feature
)

from src.scoring.risk_score import calculate_risk_score
from src.incidents.incident_generator import generate_incident
from src.actions.action_executor import execute_action
from src.detection.anomaly_model import add_anomaly_scores
from src.tickets.ticket_generator import generate_ticket
from src.explainability.timeline_generator import generate_timeline

import pandas as pd

df = preprocess_data(df)

df = create_time_features(df)

df = failed_login_features(df)

df = privileged_account_feature(df)

df = device_change_feature(df)

df = rapid_attempts_feature(df)

df = add_anomaly_scores(df)
print(df.head())
print(df.columns)

df.to_csv(
    "data/processed/processed_auth_logs.csv",
    index=False
)

if os.path.exists("reports/tickets"):
    shutil.rmtree("reports/tickets")

os.makedirs("reports/tickets", exist_ok=True)

import shutil
import os

if os.path.exists("reports/timelines"):
    shutil.rmtree("reports/timelines")

os.makedirs("reports/timelines", exist_ok=True)

incidents = []

for _, row in df.iterrows():
    risk_score, severity, reasons = calculate_risk_score(row)

    if severity == "HIGH" or (
    severity == "MEDIUM" and risk_score >= 55
):

        incident = generate_incident(row, risk_score, severity, reasons)
        action_result = execute_action(incident)
        incident["action_executed"] = action_result["executed"]
        incident["action_type"] = action_result["action_type"]
        incident["action_details"] = action_result["details"]
        incident["action_timestamp"] = action_result["timestamp"]
        if severity=="HIGH":

            ticket_result = generate_ticket(incident)
            incident["ticket_generated"] = ticket_result["ticket_generated"]
            incident["ticket_id"] = ticket_result["ticket_id"]
            incident["ticket_path"] = ticket_result["ticket_path"]
        else:
            incident["ticket_generated"] = False   
            incident["ticket_id"] = None
            incident["ticket_path"] = None

        incident["timeline"]=generate_timeline(incident)
        if len(incidents) < 20:
            incident["timeline"] = generate_timeline(incident)
        else:
            incident["timeline"] = []

        incidents.append(incident)
       

print(f"Generated incidents: {len(incidents)}")

for incident in incidents[:5]:
    print(incident)



incidents_df = pd.DataFrame(incidents)
print(df[['timestamp','login_hour']].head(20))

incidents_df.to_csv(
    "reports/generated_incidents.csv",
    index=False
)
print("Incidents saved to reports/generated_incidents.csv")
print(incidents_df['incident_type'].value_counts())

print("ML anomaly count:")
print(df["is_ml_anomaly"].value_counts())

print("Average ML anomaly score:")
print(df["ml_anomaly_score"].mean())

print("Incident severity distribution:")
print(incidents_df["severity"].value_counts())
print("Ticket generated count:")
print(incidents_df["ticket_generated"].value_counts())