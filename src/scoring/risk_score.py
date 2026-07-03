def calculate_risk_score(row):
    rule_score = 0
    reasons = []

    # Rule-based SOC reasoning
    if row.get("failed_attempts", 0) >= 5:
        rule_score += 20
        reasons.append("High number of failed login attempts")

    if row.get("unusual_hour", 0) == 1:
        rule_score += 10
        reasons.append("Login attempt occurred during unusual hours")

    if row.get("privileged_account", 0) == 1:
        rule_score += 20
        reasons.append("Privileged account involved")

    if row.get("device_change", 0) == 1:
        rule_score += 10
        reasons.append("Device change detected")

    if row.get("mfa_enabled", True) == False:
        rule_score += 15
        reasons.append("MFA is disabled")

    if row.get("token_expired", False) == True:
        rule_score += 10
        reasons.append("Expired token usage detected")

    if row.get("suspicious_activity", False) == True:
        rule_score += 15
        reasons.append("Suspicious activity flag detected")

    if row.get("threat_level", 0) >= 7:
        rule_score += 20
        reasons.append("High threat level detected")

    if row.get("blocked", False) == True:
        rule_score += 10
        reasons.append("Blocked authentication attempt")

    rule_score = min(rule_score, 100)

    ml_score = row.get("ml_anomaly_score", 0)
    is_ml_anomaly = row.get("is_ml_anomaly", 0)


    if is_ml_anomaly == 1:
        final_score = (rule_score * 0.6) + (ml_score * 0.4)
        reasons.append("ML anomaly model confirmed abnormal authentication behavior")
    else:
        final_score = (rule_score * 0.9) + (ml_score * 0.1)
        reasons.append("ML anomaly model did not strongly confirm behavioral abnormality")

    final_score = round(min(final_score, 100), 2)

    if final_score >= 75:
        severity = "HIGH"
    elif final_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return final_score, severity, reasons