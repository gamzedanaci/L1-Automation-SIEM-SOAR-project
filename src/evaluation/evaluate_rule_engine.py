import pandas as pd

df = pd.read_csv("data/processed/processed_auth_logs.csv")


def safe_sum(column_name, condition):
    if column_name in df.columns:
        return condition.sum()
    return "Kolon Bulunamadı!"

results = {
    "High Failed Login Attempts": safe_sum("failed_attempts", df["failed_attempts"] >= 5) if "failed_attempts" in df.columns else (safe_sum("failed_login_count", df["failed_login_count"] >= 5) if "failed_login_count" in df.columns else 0),
    "Unusual Login Hour": safe_sum("unusual_hour", df["unusual_hour"] == 1),
    "Privileged Account Login": safe_sum("privileged_account", df["privileged_account"] == 1),
    "Device Change": safe_sum("device_change", df["device_change"] == 1),
 
    "MFA Disabled": safe_sum("mfa_enabled", df["mfa_enabled"].astype(str).str.lower() == 'false') if "mfa_enabled" in df.columns else 0,
    "Expired Token Usage": safe_sum("token_expired", df["token_expired"].astype(str).str.lower() == 'true') if "token_expired" in df.columns else 0,
    "Suspicious Activity": safe_sum("suspicious_activity", df["suspicious_activity"].astype(str).str.lower() == 'true') if "suspicious_activity" in df.columns else 0,
    "High Threat Level": safe_sum("threat_level", df["threat_level"] >= 7) if "threat_level" in df.columns else 0,
    "Blocked Authentication": safe_sum("blocked", df["blocked"].astype(str).str.lower() == 'true') if "blocked" in df.columns else 0
}

print("\nRule Trigger Statistics")
print("-" * 45)

for rule, count in results.items():
    print(f"{rule:<30} {count}")