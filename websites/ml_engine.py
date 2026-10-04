import os
import joblib
import numpy as np
import warnings


# ============================================================
# RANDOM FOREST MODEL PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

RF_MODEL_PATH = os.path.join(
    BASE_DIR,
    "vulnex_model.pkl"
)


# ============================================================
# VULNEX RANDOM FOREST ENGINE
# ============================================================

class VulnexAIEngine:

    def __init__(self):

        if os.path.exists(RF_MODEL_PATH):

            self.rf_model = joblib.load(
                RF_MODEL_PATH
            )

            print(
                "[VULNEX] Random Forest model loaded."
            )

        else:

            self.rf_model = None

            print(
                "[VULNEX ERROR] Random Forest model "
                f"not found at: {RF_MODEL_PATH}"
            )


    # ========================================================
    # RANDOM FOREST RISK PREDICTION
    # ========================================================

    def predict_risk(self, feature_vector):

        if self.rf_model is None:

            return {
                "risk_level": "Unknown",
                "security_score": 0,
                "confidence": 0.0,
                "source": "Random Forest Classifier"
            }

        # ----------------------------------------------------
        # Validate input
        # ----------------------------------------------------

        if len(feature_vector) != 12:

            raise ValueError(
                "Random Forest expected 12 features, "
                f"but received {len(feature_vector)}."
            )

        input_data = np.array(
            feature_vector,
            dtype=int
        ).reshape(1, -1)


        # ----------------------------------------------------
        # Prediction
        # ----------------------------------------------------

        with warnings.catch_warnings():

            warnings.filterwarnings(
                "ignore",
                message="X does not have valid feature names"
            )

            predicted_class = (
                self.rf_model.predict(
                    input_data
                )[0]
            )

            probabilities = (
                self.rf_model.predict_proba(
                    input_data
                )[0]
            )


        # ----------------------------------------------------
        # Convert model class into risk label
        # ----------------------------------------------------

        if isinstance(
            predicted_class,
            (int, np.integer)
        ):

            risk_map = {
                0: "Low",
                1: "Medium",
                2: "High"
            }

            predicted_risk = risk_map.get(
                int(predicted_class),
                "Low"
            )

        else:

            predicted_risk = str(
                predicted_class
            ).strip().title()


        # ----------------------------------------------------
        # Prediction confidence
        # ----------------------------------------------------

        confidence = round(
            float(
                np.max(probabilities) * 100
            ),
            2
        )


        # ----------------------------------------------------
        # Model-based score
        #
        # This is returned for reference.
        # Main VulnEx score is calculated in tasks.py.
        # ----------------------------------------------------

        classes = list(
            self.rf_model.classes_
        )

        low_targets = [
            0,
            "Low",
            "low"
        ]

        low_index = None

        for target in low_targets:

            if target in classes:

                low_index = classes.index(
                    target
                )

                break


        if low_index is not None:

            safe_probability = float(
                probabilities[low_index]
            )

        else:

            safe_probability = max(
                0.0,
                1.0 - (
                    sum(feature_vector)
                    / len(feature_vector)
                )
            )


        model_security_score = round(
            safe_probability * 100,
            2
        )


        return {
            "risk_level": predicted_risk,
            "security_score": model_security_score,
            "confidence": confidence,
            "source": "Random Forest Classifier"
        }