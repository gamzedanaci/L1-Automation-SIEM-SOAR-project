# SOC-AI 🛡️
### An Explainable Autonomous L1 Security Operations Center Analyst Platform


---

## Overview

SOC-AI is an AI-supported **Security Operations Center (SOC) Level-1 automation framework** that combines rule-based security logic with machine learning to automate repetitive analyst tasks. The system ingests authentication logs, extracts behavioral features, detects anomalies with Isolation Forest, computes a hybrid risk score, and autonomously handles the full incident lifecycle — from triage to escalation ticket — without human intervention at the L1 stage.

---

## Features

- 🔍 Authentication log preprocessing and normalization
- ⚙️ 10 security-specific behavioral features per event
- 🤖 Unsupervised anomaly detection (Isolation Forest, contamination 8%)
- 📋 Weighted rule-based SOC threat detection
- 📊 Hybrid risk scoring — `RiskFinal = RiskRule + BonusML`
- 🚨 Automatic incident generation and severity classification
- ⚡ Automated first-response actions (IP block, password reset, MFA enforce, session termination)
- 🎫 Investigation ticket generation for high-severity incidents
- 🕐 Chronological audit timeline per incident
- 🖥️ Interactive Streamlit SOC dashboard (Main Channel · Investigation · Closed Alerts)

---

## Pipeline

```
Auth Logs → Cleaning → Feature Engineering → Rule Engine ─┐
                                                           ├─→ Hybrid Risk Score → Incident Classification
                                           Isolation Forest┘         │
                                                             Automated Response → Ticket → Timeline → Dashboard
```

---

## Tech Stack
- Python
- Streamlit
- Pandas
- NumPy
- Scikit-learn
- Isolation Forest
- Machine Learning
- Rule-Based Detection
- Feature Engineering
- Authentication Log Analysis
- Incident Response Automation
- Data Visualization

---

## Dataset

Evaluated on the [Authentication and Authorization Failures Dataset](https://www.kaggle.com/datasets/mirzayasirabdullah07/authentication-and-authorization-failures-dataset) (Kaggle, 2025) — 50,000 simulated enterprise authentication records.

| Metric | Value |
|---|---|
| Total Records | 50,000 |
| ML-Detected Anomalies | 4,000 (8%) |
| Generated Incidents | 13,099 |
| High Severity + Auto-Tickets | 1,779 |

---

## Limitations

- Authentication telemetry only — no endpoint, network, or cloud log support
- No real-time SIEM integration
- Single unsupervised ML algorithm (Isolation Forest)
- Evaluated on simulated dataset, not live enterprise data

---

## License

Developed for academic research and educational purposes as part of a Software Engineering Graduation Project at Haliç University.

---

<p align="center"><sub>SOC-AI · Haliç University, Software Engineering · June 2026</sub></p>
