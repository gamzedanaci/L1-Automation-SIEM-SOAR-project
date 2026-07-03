from datetime import datetime, timezone
import os
import json

def execute_action(incident):
    incident_type = incident.get("incident_type")
    username = incident.get("username")
    ip_address = incident.get("ip_address")
    severity = incident.get("severity")

    action_result = {
        "executed": False,
        "action_type": "No action",
        "details": "No automated action was executed.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    if incident_type == "Brute Force Attempt":
        action_result = block_ip(ip_address, reason="Brute force attempt detected")

    elif incident_type == "Possible Brute Force Success":
        action_result = force_password_reset(username, reason="Successful login after repeated failed attempts")

    elif incident_type == "Possible Session Hijacking":
        action_result = revoke_session(username, reason="Device or browser change after authentication")

    elif incident_type == "Potential MFA Bypass":
        action_result = enforce_mfa(username, reason="MFA risk detected")

    elif incident_type == "Expired Session Abuse":
        action_result = revoke_session(username, reason="Expired token abuse detected")

    elif incident_type == "Geo Risk Authentication":
        action_result = require_step_up_auth(username, reason="Geo-risk authentication detected")

    elif severity == "HIGH":
        action_result = escalate_high_risk(incident)

    return action_result


def block_ip(ip_address, reason):
    os.makedirs("reports/actions", exist_ok=True)

    with open("reports/actions/blocked_ips.txt", "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | BLOCK_IP | {ip_address} | {reason}\n")

    return {
        "executed": True,
        "action_type": "Temporary IP Block",
        "details": f"Source IP {ip_address} was added to simulated block list.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def force_password_reset(username, reason):
    os.makedirs("reports/actions", exist_ok=True)

    with open("reports/actions/account_actions.txt", "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | FORCE_PASSWORD_RESET | {username} | {reason}\n")

    return {
        "executed": True,
        "action_type": "Force Password Reset",
        "details": f"Password reset was simulated for user {username}.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def revoke_session(username, reason):
    os.makedirs("reports/actions", exist_ok=True)

    with open("reports/actions/session_actions.txt", "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | REVOKE_SESSION | {username} | {reason}\n")

    return {
        "executed": True,
        "action_type": "Session Revocation",
        "details": f"Active session revocation was simulated for user {username}.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def enforce_mfa(username, reason):
    os.makedirs("reports/actions", exist_ok=True)

    with open("reports/actions/mfa_actions.txt", "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | ENFORCE_MFA | {username} | {reason}\n")

    return {
        "executed": True,
        "action_type": "MFA Enforcement",
        "details": f"MFA re-authentication was simulated for user {username}.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def require_step_up_auth(username, reason):
    os.makedirs("reports/actions", exist_ok=True)

    with open("reports/actions/step_up_auth.txt", "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | STEP_UP_AUTH | {username} | {reason}\n")

    return {
        "executed": True,
        "action_type": "Step-Up Authentication",
        "details": f"Additional authentication challenge was simulated for user {username}.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def escalate_high_risk(incident):
    os.makedirs("reports/actions", exist_ok=True)

    with open("reports/actions/escalations.txt", "a") as f:
        f.write(json.dumps(incident, default=str) + "\n")

    return {
        "executed": True,
        "action_type": "High-Risk Escalation",
        "details": "Incident was escalated to L2 queue.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }