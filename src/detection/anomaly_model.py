import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


NUMERIC_FEATURES = [
    "failed_attempts",
    "session_duration",
    "password_age_days",
    "privilege_level",
    "threat_level",
    "login_hour",
    "weekend_login",
    "unusual_hour",
    "device_change",
    "rapid_attempts"
]


def add_anomaly_scores(df):


    missing_features = [col for col in NUMERIC_FEATURES if col not in df.columns]

    if missing_features:
        raise ValueError(f"Missing required features: {missing_features}")

    model_df = df[NUMERIC_FEATURES].copy()

    model_df = model_df.fillna(0)

    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(model_df)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.08,
        random_state=42
    )

    model.fit(scaled_features)

    predictions = model.predict(scaled_features)

    anomaly_scores = model.decision_function(scaled_features)

    df["ml_anomaly_label"] = predictions

    df["is_ml_anomaly"] = (df["ml_anomaly_label"] == -1).astype(int)

    df["ml_raw_score"] = anomaly_scores

    df["ml_anomaly_score"] = normalize_anomaly_score(anomaly_scores)

    return df


def normalize_anomaly_score(scores):

    scores = pd.Series(scores)

    inverted = scores.max() - scores

    normalized = 100 * (inverted - inverted.min()) / (inverted.max() - inverted.min())

    return normalized.round(2)