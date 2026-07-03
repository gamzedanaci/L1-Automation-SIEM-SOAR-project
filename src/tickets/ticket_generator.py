from datetime import datetime, timezone
import os
import uuid



def generate_ticket(incident):
    os.makedirs("reports/tickets", exist_ok=True)

    ticket_id = create_ticket_id(incident)

    ticket_text = f"""
SOC INCIDENT TICKET: #{ticket_id}

Ticket Title:
[ESCALATION] [{incident.get("severity")}] {incident.get("incident_type")} - User [{incident.get("username")}] via [{incident.get("ip_address")}]

Priority:
{incident.get("severity")}

Assigned Group:
L2 SOC Incident Response Team

Detection Source:
SOC-AI Autonomous L1 Engine

Detection Method:
Hybrid Rule-Based + ML Behavioral Analysis

Overall Incident Risk:
{incident.get("risk_score", "N/A")}/100

AI Behavioral Anomaly Score:
{incident.get("ml_anomaly_score", "N/A")}/100

ML Anomaly Flag:
{incident.get("is_ml_anomaly", "N/A")}


Incident Description:
At {incident.get("timestamp")}, the SOC-AI platform detected a suspicious authentication event originating from IP address {incident.get("ip_address")} and associated with user account {incident.get("username")}.

The event was classified as "{incident.get("incident_type")}" based on rule-based SOC logic, behavioral anomaly scoring, and contextual authentication indicators. The incident received a risk score of {incident.get("risk_score")} and severity level {incident.get("severity")}.

Indicators of Compromise (IoCs):
- Source IP: {incident.get("ip_address")}
- Location: {incident.get("location")}
- Affected User: {incident.get("username")}
- Incident Type: {incident.get("incident_type")}
- ML Anomaly Score: {incident.get("ml_anomaly_score")}
- ML Anomaly Flag: {incident.get("is_ml_anomaly")}


SIEM Correlation Evidence:
- Authentication event timestamp: {incident.get("timestamp")}
- Rule-based reasoning: {incident.get("reasons")}
- Recommended action: {incident.get("recommended_action")}


Automated First Response Actions Executed:
- Action Executed: {incident.get("action_executed")}
- Action Type: {incident.get("action_type")}
- Action Details: {incident.get("action_details")}
- Action Timestamp: {incident.get("action_timestamp")}


L2 Escalation Request:
Please review the affected user account, source IP address, authentication history, and any post-authentication activity. If additional compromise indicators are found, proceed with endpoint investigation, session review, and account containment.


Audit Trail:
1. Raw authentication log ingested
2. Log normalized and parsed
3. Features extracted
4. Rule-based SOC reasoning applied
5. ML anomaly score calculated
6. Incident risk score assigned
7. Automated first response action executed
8. L2 escalation ticket generated


Generated At:
{datetime.now(timezone.utc).isoformat()}
"""

    file_path = f"reports/tickets/{ticket_id}.txt"

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(ticket_text)

    return {
        "ticket_id": ticket_id,
        "ticket_path": file_path,
        "ticket_generated": True
    }



def create_ticket_id(incident):
    username = str(incident.get("username", "unknown")).replace(" ", "_")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    short_uuid = str(uuid.uuid4())[:8]
    return f"SOC-AI-{timestamp}-{username}-{short_uuid}"