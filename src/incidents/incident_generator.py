def generate_incident(row,risk_score,severity,reasons):


    incident_type="Authentication Anomaly"


    # Brute Force
    if row['failed_attempts']>=5 and row['success']==False:
        incident_type="Brute Force Attempt"


    # Brute Force Success
    elif row['failed_attempts']>=5 and row['success']==True:
        incident_type="Possible Brute Force Success"


    # Password Spraying
    elif row['failed_attempts']==1 and row['rapid_attempts']==1:
        incident_type="Password Spraying"


    # Session Hijack
    elif row['device_change']==1:
        incident_type="Possible Session Hijacking"


    # Suspicious Admin Access
    elif row['privileged_account']==1 and row['unusual_hour']==1:
        incident_type="Suspicious Privileged Login"


    # MFA bypass risk
    elif row['mfa_enabled']==False and row['success']==True:
        incident_type="Potential MFA Bypass"


    # Token misuse
    elif row['token_expired']==True:
        incident_type="Expired Session Abuse"


    # Geo anomaly
    elif row['threat_level']>=7 and row['location']:
        incident_type="Geo Risk Authentication"

    return {
        "timestamp": row.get("timestamp"),
        "username": row.get("username"),
        "ip_address": row.get("ip_address"),
        "location": row.get("location"),
        "incident_type": incident_type,
        "risk_score": risk_score,
        "severity": severity,
        "ml_anomaly_score": row.get("ml_anomaly_score"),
        "is_ml_anomaly": row.get("is_ml_anomaly"),
        "reasons": reasons,
        "recommended_action": recommend_action(incident_type,severity),
        "decision_method": "Adaptive Hybrid Scoring (Rule-Based SOC Logic + ML Behavioral Anomaly)"

    }


def recommend_action(incident_type,severity):

    actions={

        "Brute Force Attempt":
        "Temporarily block source IP for 15 minutes and enforce CAPTCHA or account lockout.",


        "Possible Brute Force Success":
        "Force password reset, terminate active sessions, and escalate to L2 analyst.",


        "Possible Session Hijacking":
        "Terminate suspicious session, revoke session tokens, and request MFA re-authentication.",


        "Potential MFA Bypass":
        "Force MFA re-enrollment and verify user identity.",


        "Expired Session Abuse":
        "Invalidate expired tokens and investigate token reuse attempts.",


        "Geo Risk Authentication":
        "Trigger additional authentication challenge and verify login origin.",


        "Password Spraying":
        "Temporarily block source IP and monitor authentication attempts across users.",


        "Suspicious Privileged Login":
        "Escalate immediately and review privileged account activity.",


        "Authentication Anomaly":
        "Generate SOC ticket and continue monitoring user behavior."
    }

    return actions.get(
        incident_type,
        "Escalate to analyst for manual review"
    )