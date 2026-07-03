import pandas as pd

def preprocess_data(df):

    df['timestamp'] = pd.to_datetime(df['timestamp'])

    return df


def create_time_features(df):

    df['login_hour'] = df['timestamp'].dt.hour

    df['day_of_week'] = df['timestamp'].dt.dayofweek

    df['weekend_login'] = df['day_of_week'].apply(
        lambda x: 1 if x >= 5 else 0
    )

    df['unusual_hour'] = df['login_hour'].apply(
        lambda x: 1 if x < 6 or x > 22 else 0
    )

    return df