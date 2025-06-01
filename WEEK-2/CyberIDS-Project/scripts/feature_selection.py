import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.feature_selection import VarianceThreshold, RFE
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Load cleaned dataset
file_path = r"C:\Users\nandu\OneDrive\Desktop\cleaned_data.csv"
df = pd.read_csv(file_path)

# Drop non-numeric columns before feature selection
df_numeric = df.select_dtypes(include=['number'])  # Keep only numerical features

# Remove low-variance features
selector = VarianceThreshold(threshold=0.01)
df_reduced = pd.DataFrame(selector.fit_transform(df_numeric), columns=df_numeric.columns[selector.get_support()])

# Remove highly correlated features
corr_matrix = df_reduced.corr().abs()
upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
to_drop = [column for column in upper.columns if any(upper[column] > 0.95)]
df_reduced.drop(columns=to_drop, inplace=True)

# Apply Recursive Feature Elimination (RFE)
X = df_reduced.drop(columns=['Label'])
y = df_reduced['Label']
model = RandomForestClassifier()
rfe = RFE(model, n_features_to_select=20)
X_selected = rfe.fit_transform(X, y)

# Convert selected features back to a DataFrame
selected_features = X.columns[rfe.get_support()]
df_selected = pd.DataFrame(X_selected, columns=selected_features)
df_selected['Label'] = y.values  # Add label column back

# Compute feature importance using Random Forest
model.fit(X_selected, y)
importance = pd.Series(model.feature_importances_, index=selected_features)
importance.nlargest(20).plot(kind='barh')
plt.title("Top 20 Feature Importance (Random Forest)")
plt.savefig("feature_importance.png")
plt.show()

# Normalize numerical features (Optional)
scaler = StandardScaler()
df_selected[selected_features] = scaler.fit_transform(df_selected[selected_features])

# Save processed dataset
df_selected.to_csv("processed_data.csv", index=False)
print(" Feature selection complete! Saved as 'processed_data.csv'.")