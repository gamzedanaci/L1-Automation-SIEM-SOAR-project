import pandas as pd

df = pd.read_csv("data/raw_logs/auth_dataset.csv")

print(df.head())
print(df.info())
print(df.isnull().sum())