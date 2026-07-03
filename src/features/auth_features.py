def failed_login_features(df):

    df['failed_login_count'] = df.groupby(
        ['username']
    )['success'].transform(
        lambda x: (~x).cumsum()
    )

    return df


def privileged_account_feature(df):

    df['privileged_account'] = df['privilege_level'].apply(
        lambda x: 1 if x in ['high', 'admin'] else 0
    )

    return df


def device_change_feature(df):

    df['previous_device'] = df.groupby(
        'username'
    )['device_type'].shift(1)

    df['device_change'] = (
    (df['device_type'] != df['previous_device']) &
    (df['previous_device'].notna())
).astype(int)
    
    return df



def rapid_attempts_feature(df):

    df = df.sort_values(by='timestamp')

    df['rapid_attempts'] = df.groupby(
        'ip_address'
    )['timestamp'].diff().dt.seconds

    df['rapid_attempts'] = df['rapid_attempts'].apply(
        lambda x: 1 if x is not None and x < 30 else 0
    )

    return df




