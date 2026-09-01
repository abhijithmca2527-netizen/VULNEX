import os
import joblib
import numpy as np

# Dynamically find the .pkl files in the root folder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RF_MODEL_PATH = os.path.join(BASE_DIR, 'vulnex_model.pkl')
IFOREST_MODEL_PATH = os.path.join(BASE_DIR, 'isolation_forest.pkl')

class VulnexAIEngine:
    def __init__(self):
        # 1. Load Random Forest Model (Risk Severity)
        if os.path.exists(RF_MODEL_PATH):
            self.rf_model = joblib.load(RF_MODEL_PATH)
        else:
            self.rf_model = None
            print(f"[ERROR] Random Forest Model not found at {RF_MODEL_PATH}")

        # 2. Load Isolation Forest Model (Anomaly Detection)
        if os.path.exists(IFOREST_MODEL_PATH):
            self.iforest_model = joblib.load(IFOREST_MODEL_PATH)
        else:
            self.iforest_model = None
            print(f"[ERROR] Isolation Forest Model not found at {IFOREST_MODEL_PATH}")

    def predict_risk(self, feature_vector):
        if not self.rf_model:
            return {
                "risk_level": "Unknown",
                "security_score": 0,
                "confidence": 0.0,
                "is_anomaly": False
            }

        input_data = np.array(feature_vector).reshape(1, -1)

        # 1. Raw Prediction & Class Mapping
        predicted_class = self.rf_model.predict(input_data)[0]
        probabilities = self.rf_model.predict_proba(input_data)[0]
        classes = list(self.rf_model.classes_)

        # Normalize predicted label
        if isinstance(predicted_class, (int, np.integer)):
            risk_map = {0: "Low", 1: "Medium", 2: "High"}
            predicted_risk = risk_map.get(predicted_class, "Low")
        else:
            predicted_risk = str(predicted_class)

        # 2. Compute 0-100 Dynamic Security Score
        # Safe score is directly tied to the probability of 'Low' risk (or 0)
        low_target = 0 if 0 in classes else 'Low'
        if low_target in classes:
            low_idx = classes.index(low_target)
            safe_prob = probabilities[low_idx]
        else:
            safe_prob = 1.0 - (np.sum(feature_vector) / len(feature_vector))

        security_score = round(float(safe_prob * 100), 2)
        confidence = round(float(np.max(probabilities) * 100), 2)

        # 3. Isolation Forest Anomaly Prediction
        is_anomaly = False
        if self.iforest_model:
            try:
                iforest_prediction = self.iforest_model.predict(input_data)[0]
                is_anomaly = True if iforest_prediction == -1 else False
            except Exception as e:
                print(f"[WARNING] Isolation Forest error: {e}")

        return {
            "risk_level": predicted_risk,
            "security_score": security_score,
            "confidence": confidence,
            "is_anomaly": is_anomaly
        }