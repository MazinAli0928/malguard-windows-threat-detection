import json
from pathlib import Path

import joblib
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]

MODEL_FILE = (
    ROOT
    / "saved_models"
    / "windows"
    / "windows_random_forest.pkl"
)

FEATURE_FILE = (
    ROOT
    / "saved_models"
    / "windows"
    / "windows_feature_names.json"
)


class MalwarePredictor:

    def __init__(self):

        if not MODEL_FILE.exists():
            raise FileNotFoundError(
                f"Model not found: {MODEL_FILE}"
            )

        if not FEATURE_FILE.exists():
            raise FileNotFoundError(
                f"Feature file not found: {FEATURE_FILE}"
            )

        self.model = joblib.load(MODEL_FILE)

        with open(
            FEATURE_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            self.feature_names = json.load(file)

    def predict(self, features):

        X = pd.DataFrame(
            [[
                features[name]
                for name in self.feature_names
            ]],
            columns=self.feature_names
        )

        probabilities = self.model.predict_proba(X)[0]

        benign_probability = float(probabilities[0])
        malicious_probability = float(probabilities[1])

        return {
            "raw_prediction": int(
                malicious_probability >= 0.50
            ),
            "benign_probability": benign_probability,
            "malicious_probability": malicious_probability,
        }