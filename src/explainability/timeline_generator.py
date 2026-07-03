import os
from datetime import datetime, timezone


def generate_timeline(incident):
    timeline = []

    timeline.append("1. Raw authentication log ingested")
    timeline.append("2. Log normalized and parsed")
    timeline.append("3. Features extracted")

    for reason in incident.get("reasons", []):
        timeline.append(f"4. SOC reasoning: {reason}")

    timeline.append(
        f"5. ML anomaly score calculated: {incident.get('ml_anomaly_score')}"
    )

    timeline.append(
        f"6. Final hybrid risk score assigned: {incident.get('risk_score')}"
    )

    timeline.append(
        f"7. Automated action executed: {incident.get('action_type')}"
    )

    if incident.get("ticket_generated"):
        timeline.append(
            f"8. L2 escalation ticket generated: {incident.get('ticket_id')}"
        )
    else:
        timeline.append("8. L2 escalation ticket not required")

    save_timeline(incident, timeline)

    return timeline


def save_timeline(incident, timeline):
    os.makedirs("reports/timelines", exist_ok=True)

    username = str(incident.get("username", "unknown")).replace(" ", "_")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    file_path = f"reports/timelines/timeline_{timestamp}_{username}.txt"

    with open(file_path, "w", encoding="utf-8") as f:
        f.write("SOC-AI INCIDENT WORKFLOW TIMELINE\n")
        f.write("=" * 40 + "\n\n")

        f.write(f"Incident Type: {incident.get('incident_type')}\n")
        f.write(f"Severity: {incident.get('severity')}\n")
        f.write(f"Risk Score: {incident.get('risk_score')}/100\n")
        f.write(f"User: {incident.get('username')}\n")
        f.write(f"Source IP: {incident.get('ip_address')}\n\n")

        f.write("Workflow Steps:\n")
        for step in timeline:
            f.write(f"- {step}\n")