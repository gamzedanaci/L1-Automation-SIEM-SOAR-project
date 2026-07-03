import ast
from pathlib import Path

import pandas as pd
import streamlit as st # type: ignore


# =========================
# Page Config
# =========================

st.set_page_config(
    page_title="SOC-AI L1 Automation Console",
    layout="wide"
)


# =========================
# Data Loading
# =========================

@st.cache_data
def load_data():
    raw_logs_path = Path("data/processed/processed_auth_logs.csv")
    incidents_path = Path("reports/generated_incidents.csv")

    if not raw_logs_path.exists():
        st.error("data/processed/processed_auth_logs.csv not found. Run `python app.py` first.")
        st.stop()

    raw_logs = pd.read_csv(raw_logs_path)
    raw_logs["log_id"] = raw_logs.index.astype(str)

    if incidents_path.exists():
        incidents = pd.read_csv(incidents_path)
    else:
        incidents = pd.DataFrame()

    if not incidents.empty:
        incidents["incident_id"] = incidents.index.astype(str)

        merged = raw_logs.merge(
            incidents,
            on=["timestamp", "username", "ip_address", "location"],
            how="left",
            suffixes=("_raw", "")
        )
    else:
        merged = raw_logs.copy()

    # Default values for logs that did not generate incidents
    merged["incident_generated"] = merged["incident_type"].notna()
    merged["severity"] = merged["severity"].fillna("LOW")
    merged["incident_type"] = merged["incident_type"].fillna("No Incident")
    merged["risk_score"] = merged["risk_score"].fillna(0)
    merged["ml_anomaly_score"] = merged["ml_anomaly_score"].fillna(0)
    merged["is_ml_anomaly"] = merged["is_ml_anomaly"].fillna(0)
    merged["action_type"] = merged["action_type"].fillna("No Action")
    merged["action_executed"] = merged["action_executed"].fillna(False)
    merged["action_details"] = merged["action_details"].fillna("No automated action executed.")
    merged["ticket_generated"] = merged["ticket_generated"].fillna(False)
    merged["ticket_id"] = merged["ticket_id"].fillna("")
    merged["ticket_path"] = merged["ticket_path"].fillna("")
    merged["reasons"] = merged["reasons"].fillna("[]")
    merged["decision_method"] = merged["decision_method"].fillna("No incident decision required")

    return merged


# =========================
# Session State
# =========================

def initialize_state():
    if "selected_log_id" not in st.session_state:
        st.session_state.selected_log_id = None

    if "closed_log_ids" not in st.session_state:
        st.session_state.closed_log_ids = []


# =========================
# Helper Functions
# =========================

def parse_reasons(value):
    try:
        return ast.literal_eval(value)
    except Exception:
        return [str(value)]


def show_overview(open_logs, closed_logs):
    total = len(open_logs)
    high = len(open_logs[open_logs["severity"] == "HIGH"])
    medium = len(open_logs[open_logs["severity"] == "MEDIUM"])
    low = len(open_logs[open_logs["severity"] == "LOW"])
    closed = len(closed_logs)

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Open Logs", total)
    col2.metric("High Severity", high)
    col3.metric("Medium Severity", medium)
    col4.metric("Low / No Incident", low)
    col5.metric("Closed Alerts", closed)


def show_main_channel(open_logs):
    st.subheader("Main Channel — Raw Authentication Logs")

    st.caption(
        "This channel displays all processed authentication logs. "
        "Only MEDIUM and HIGH risk logs generate incidents; LOW logs remain under normal monitoring."
    )

    if open_logs.empty:
        st.success("No open logs. All alerts are closed.")
        return

    filter_col1, filter_col2, filter_col3 = st.columns([1, 1.4, 1.2])

    with filter_col1:
        severity_choice = st.selectbox(
            "Severity",
            ["ALL"] + sorted(open_logs["severity"].dropna().unique().tolist())
        )

    with filter_col2:
        incident_type_choice = st.selectbox(
            "Incident Type",
            ["ALL"] + sorted(open_logs["incident_type"].dropna().unique().tolist())
        )

    with filter_col3:
        search_query = st.text_input("Search username or IP")

    filtered = open_logs.copy()

    if severity_choice != "ALL":
        filtered = filtered[filtered["severity"] == severity_choice]

    if incident_type_choice != "ALL":
        filtered = filtered[filtered["incident_type"] == incident_type_choice]

    if search_query:
        filtered = filtered[
            filtered["username"].astype(str).str.contains(search_query, case=False, na=False)
            | filtered["ip_address"].astype(str).str.contains(search_query, case=False, na=False)
        ]

    if filtered.empty:
        st.warning("No logs match selected filters.")
        return

    display_cols = [
        "log_id",
        "severity",
        "timestamp",
        "username",
        "ip_address",
        "location",
        "success",
        "failed_attempts",
        "mfa_enabled",
        "threat_level",
        "incident_type",
        "risk_score",
        "action_type",
        "ticket_generated",
    ]

    event = st.dataframe(
        filtered[display_cols],
        use_container_width=True,
        height=560,
        hide_index=True,
        selection_mode="single-row",
        on_select="rerun"
    )

    selected_rows = event.selection.rows

    if selected_rows:
        selected_row_position = selected_rows[0]
        selected_log_id = filtered.iloc[selected_row_position]["log_id"]
        st.session_state.selected_log_id = selected_log_id

        st.success(
            "Log selected. Open the Investigation Channel to view SOC-AI analysis."
        )
    else:
        st.info("No log selected. Investigation Channel will remain empty.")


def show_investigation_channel(all_logs):
    st.subheader("Investigation Channel")

    selected_id = st.session_state.selected_log_id

    if selected_id is None:
        st.info("No log selected. Go to Main Channel and select a raw log first.")
        return

    selected_df = all_logs[all_logs["log_id"].astype(str) == str(selected_id)]

    if selected_df.empty:
        st.warning("Selected log could not be found.")
        return

    selected = selected_df.iloc[0]

    st.markdown("### Selected Raw Log")

    raw_col1, raw_col2 = st.columns(2)

    with raw_col1:
        st.write("**Timestamp:**", selected["timestamp"])
        st.write("**User:**", selected["username"])
        st.write("**Source IP:**", selected["ip_address"])
        st.write("**Location:**", selected["location"])
        st.write("**Device Type:**", selected.get("device_type", "N/A"))
        st.write("**OS Type:**", selected.get("os_type", "N/A"))
        st.write("**Browser:**", selected.get("browser", "N/A"))

    with raw_col2:
        st.write("**Login Success:**", selected.get("success", "N/A"))
        st.write("**Failed Attempts:**", selected.get("failed_attempts", "N/A"))
        st.write("**MFA Enabled:**", selected.get("mfa_enabled", "N/A"))
        st.write("**Token Expired:**", selected.get("token_expired", "N/A"))
        st.write("**Privilege Level:**", selected.get("privilege_level", "N/A"))
        st.write("**Threat Level:**", selected.get("threat_level", "N/A"))
        st.write("**System Component:**", selected.get("system_component", "N/A"))

    st.divider()

    if not bool(selected["incident_generated"]):
        st.info(
            "No incident was generated for this log. "
            "SOC-AI classified it as LOW / normal monitoring."
        )

        st.markdown("### Monitoring Result")
        st.write("**Severity:** LOW")
        st.write("**Incident Type:** No Incident")
        st.write("**Action:** No automated action required")
        return

    st.markdown("### SOC-AI Analysis")

    analysis_col1, analysis_col2 = st.columns(2)

    with analysis_col1:
        st.write("**Incident Type:**", selected["incident_type"])
        st.write("**Severity:**", selected["severity"])
        st.write("**Overall Incident Risk:**", f"{selected['risk_score']}/100")
        st.write("**AI Behavioral Anomaly Score:**", f"{selected['ml_anomaly_score']}/100")
        st.write("**ML Anomaly Flag:**", selected["is_ml_anomaly"])

    with analysis_col2:
        st.write("**Decision Method:**", selected["decision_method"])
        st.write("**Incident Generated:**", selected["incident_generated"])
        st.write("**Ticket Generated:**", selected["ticket_generated"])
        st.write("**Action Executed:**", selected["action_executed"])

    st.divider()

    st.markdown("### SOC Reasoning")

    reasons = parse_reasons(selected["reasons"])
    for reason in reasons:
        st.write("✓", reason)

    st.divider()

    st.markdown("### Automated First Response")

    st.write("**Action Type:**", selected["action_type"])
    st.write("**Action Details:**", selected["action_details"])

    if "action_timestamp" in selected:
        st.write("**Action Timestamp:**", selected.get("action_timestamp", "N/A"))

    st.divider()

    st.markdown("### SOC Analyst Workflow Timeline")

    timeline_steps = [
        "Raw authentication log selected",
        "Log parsed and normalized",
        "Security features extracted",
        "Rule-based SOC reasoning applied",
        "ML anomaly score calculated",
        "Adaptive hybrid risk score assigned",
        f"Incident classified as: {selected['incident_type']}",
        f"Automated action executed: {selected['action_type']}",
    ]

    if bool(selected["ticket_generated"]):
        timeline_steps.append(f"L2 escalation ticket generated: {selected['ticket_id']}")
    else:
        timeline_steps.append("L2 escalation ticket not required")

    for step in timeline_steps:
        st.write("✅", step)

    st.divider()

    st.markdown("### L2 Escalation Ticket")

    if bool(selected["ticket_generated"]):
        st.success("L2 escalation ticket generated.")
        st.write("**Ticket ID:**", selected["ticket_id"])
        st.write("**Ticket Path:**", selected["ticket_path"])

        ticket_path = Path(str(selected["ticket_path"]))

        if ticket_path.exists():
            with open(ticket_path, "r", encoding="utf-8") as f:
                ticket_text = f.read()

            with st.expander("View Generated Ticket"):
                st.text(ticket_text)
        else:
            st.warning("Ticket file path exists in CSV, but file could not be found locally.")
    else:
        st.info("L2 ticket not required for this incident.")

    st.divider()

    if st.button("Mark this incident as completed", type="primary"):
        if selected_id not in st.session_state.closed_log_ids:
            st.session_state.closed_log_ids.append(selected_id)

        st.session_state.selected_log_id = None
        st.success("Incident moved to Closed Alerts.")
        st.rerun()


def show_closed_alerts(all_logs):
    st.subheader("Closed Alerts")

    closed_ids = st.session_state.closed_log_ids

    if not closed_ids:
        st.info("No closed alerts yet.")
        return

    closed = all_logs[all_logs["log_id"].astype(str).isin([str(x) for x in closed_ids])]

    display_cols = [
        "log_id",
        "severity",
        "timestamp",
        "username",
        "ip_address",
        "incident_type",
        "risk_score",
        "action_type",
        "ticket_generated",
    ]

    st.dataframe(
        closed[display_cols],
        use_container_width=True,
        height=520,
        hide_index=True
    )


def show_analytics(all_logs):
    st.divider()
    st.subheader("SOC Analytics")

    col1, col2 = st.columns(2)

    with col1:
        st.write("**Incident Type Distribution**")
        st.bar_chart(all_logs["incident_type"].value_counts())

    with col2:
        st.write("**Severity Distribution**")
        st.bar_chart(all_logs["severity"].value_counts())


# =========================
# Main App
# =========================

all_logs = load_data()
initialize_state()

closed_ids = st.session_state.closed_log_ids

closed_logs = all_logs[
    all_logs["log_id"].astype(str).isin([str(x) for x in closed_ids])
]

open_logs = all_logs[
    ~all_logs["log_id"].astype(str).isin([str(x) for x in closed_ids])
]

st.title("SOC-AI L1 Automation Console")

st.caption(
    "Main Channel → Investigation Channel → Closed Alerts workflow for autonomous SOC L1 operations."
)

show_overview(open_logs, closed_logs)

st.divider()

main_tab, investigation_tab, closed_tab = st.tabs(
    ["MAIN CHANNEL", "INVESTIGATION CHANNEL", "CLOSED ALERTS"]
)

with main_tab:
    show_main_channel(open_logs)

with investigation_tab:
    show_investigation_channel(all_logs)

with closed_tab:
    show_closed_alerts(all_logs)

show_analytics(all_logs)