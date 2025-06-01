import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

# Load dataset
file_path =  r"C:\Users\nandu\Downloads\02-14-2018.csv\raw.csv"
df = pd.read_csv(file_path)

# Strip spaces from column names
df.columns = df.columns.str.strip()

# Drop identifier fields (adjust as needed)
identifier_columns = ["Flow ID", " Source IP", " Destination IP", " Timestamp"]
df = df.drop(columns=[col for col in identifier_columns if col in df.columns], errors='ignore')

# Handle missing values: fill NaN with median or drop if excessive
df = df.fillna(df.median(numeric_only=True))

# Handle infinity values
df = df.replace([np.inf, -np.inf], np.nan).dropna()

# Encode 'Label' column (Binary: Benign vs Attack)
if 'Label' in df.columns:
    df['Label'] = df['Label'].apply(lambda x: 1 if x.lower() != "benign" else 0)  # 1 = Attack, 0 = Benign
else:
    print("Warning: 'Label' column not found!")

# Normalize numerical features (Optional)
numerical_cols = df.select_dtypes(include=['int64', 'float64']).columns
scaler = MinMaxScaler()
df[numerical_cols] = scaler.fit_transform(df[numerical_cols])

# Save cleaned dataset
cleaned_file_path = "cleaned_data.csv"
df.to_csv(cleaned_file_path, index=False)

print(f"✅ Data cleaning complete! Cleaned dataset saved as '{cleaned_file_path}'.")