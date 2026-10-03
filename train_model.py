import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

print("[VULNEX AI] Loading dataset from CSV...")

# 1. Load the CSV file you got from Claude
df = pd.read_csv('vulnex_dataset (2).csv')

# 2. Separate Features (Inputs) and Target (Output)
# We drop the cvss score and risk category so the AI only looks at the 12 binary flags
X = df.drop(columns=['simulated_cvss', 'risk_category'])
y = df['risk_category']

# 3. Split the data (80% for training, 20% for testing)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=1)

# 4. Train the Random Forest Model
print("[VULNEX AI] Training the Machine Learning model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 5. Evaluate the Model's accuracy
print("\n[VU    LNEX AI] Model Performance Report:")
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred, target_names=['Low', 'Medium', 'High', 'Critical']))

# 6. Save the trained model for Celery to use
joblib.dump(model, 'vulnex_model.pkl')
print("\n[VULNEX AI] Success! Model saved as 'vulnex_model.pkl'.")