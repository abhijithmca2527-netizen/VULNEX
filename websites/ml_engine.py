import os
import joblib
import numpy as np

# Dynamically find the .pkl file in the root folder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'vulnex_model.pkl')

class VulnexAIEngine:
    def __init__(self):
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
        else:
            self.model = None
            print(f"[ERROR] AI Model not found at {MODEL_PATH}")

    def predict_risk(self, feature_vector):
        if not self.model:
            return {"risk_level": "Unknown", "confidence": 0.0}

        # Format the 8-bit list into a numpy array for scikit-learn
        input_data = np.array(feature_vector).reshape(1, -1)
        
        # Get AI Prediction & Confidence
        prediction_class = self.model.predict(input_data)[0]
        probabilities = self.model.predict_proba(input_data)[0]
        
        risk_labels = {0: "Low", 1: "Medium", 2: "High"}
        
        return {
            "risk_level": risk_labels.get(prediction_class, "Unknown"),
            "confidence": round(float(np.max(probabilities) * 100), 2),
        }