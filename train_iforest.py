import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

print("Loading dataset...")
df = pd.read_csv('vulnex_dataset.csv')

# Drop both the label and simulated_cvss so only the 12 binary features remain
columns_to_drop = ['risk_category', 'simulated_cvss']
X = df.drop(columns=columns_to_drop)

print(f"Training on features: {X.columns.tolist()}")
print(f"Total features: {X.shape[1]}") # Should print 12

print("\nTraining Isolation Forest...")
iso_forest = IsolationForest(
    n_estimators=100, 
    contamination=0.05, 
    random_state=42
)
iso_forest.fit(X)

print("Saving model...")
joblib.dump(iso_forest, 'isolation_forest.pkl')
print("✅ isolation_forest.pkl successfully created!")