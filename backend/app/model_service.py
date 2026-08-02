from pathlib import Path

import joblib
import numpy as np
import pandas as pd


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = (
    ROOT
    / "saved_models"
    / "baseline_random_forest.pkl"
)

FEATURES_PATH = (
    ROOT
    / "saved_models"
    / "baseline_features.pkl"
)


# ============================================================
# LOAD MODEL
# ============================================================

print("Loading malware detection model...")

model = joblib.load(MODEL_PATH)
feature_names = joblib.load(FEATURES_PATH)

print("✓ Model loaded")
print(f"✓ Expected features: {len(feature_names)}")


# ============================================================
# CLASS INFORMATION
# ============================================================

CLASS_NAMES = {
    1: "Adware",
    2: "Banking Malware",
    3: "SMS Malware",
    4: "Riskware",
    5: "Benign",
}


# ============================================================
# BEHAVIOR DESCRIPTIONS
# ============================================================

BEHAVIOR_DESCRIPTIONS = {
    "getDeviceId": "Accessed the unique device identifier",
    "getSubscriberId": "Accessed subscriber identity information",
    "getActivePhoneType": "Queried mobile network/phone information",
    "ACCESS_PERSONAL_INFO___": "Accessed privacy-sensitive personal information",

    "open": "Opened files or system resources",
    "read": "Read data from files or system resources",
    "write": "Wrote data to files or system resources",
    "mkdir": "Created a directory",
    "unlink": "Deleted or removed a file",
    "rename": "Renamed a file or resource",

    "socket": "Created a network socket",
    "connect": "Established a network connection",
    "sendto": "Transmitted data over a network",
    "sendmsg": "Sent a network message",
    "recvfrom": "Received network data",
    "recvmsg": "Received a network message",

    "execve": "Executed another program or process",
    "fork": "Created a new process",
    "vfork": "Created a child process",
    "clone": "Created a new process or thread",
    "ptrace": "Performed process tracing/debugging activity",

    "mprotect": "Modified memory protection settings",
    "mmap2": "Mapped memory into the process",
    "munmap": "Released mapped memory",

    "getPackageInfo": "Queried installed application information",
    "getApplicationInfo": "Queried Android application information",
    "getInstallerPackageName": "Queried the application's installer",
}


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(predicted_class, confidence):

    if predicted_class == 5:
        return "SAFE"

    if confidence >= 0.90:
        return "CRITICAL"

    if confidence >= 0.75:
        return "HIGH"

    if confidence >= 0.55:
        return "MEDIUM"

    return "LOW"


# ============================================================
# SUSPICIOUS FEATURES
# ============================================================

def get_suspicious_features(input_data, limit=10):

    suspicious = []

    for feature in feature_names:

        value = input_data.get(feature, 0)

        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 0

        if value > 0:

            suspicious.append({
                "feature": feature,
                "value": value,
                "description": BEHAVIOR_DESCRIPTIONS.get(
                    feature,
                    "Observed application behavioral activity"
                )
            })

    suspicious.sort(
        key=lambda item: item["value"],
        reverse=True
    )

    return suspicious[:limit]


# ============================================================
# PREDICTION
# ============================================================

def predict_behavior(input_data):

    row = []

    for feature in feature_names:

        value = input_data.get(feature, 0)

        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 0

        row.append(value)

    input_df = pd.DataFrame(
        [row],
        columns=feature_names
    )

    predicted_class = int(
        model.predict(input_df)[0]
    )

    probabilities = model.predict_proba(
        input_df
    )[0]

    probability_map = {}

    for class_id, probability in zip(
        model.classes_,
        probabilities
    ):

        probability_map[
            CLASS_NAMES[int(class_id)]
        ] = round(
            float(probability) * 100,
            2
        )

    confidence = float(
        np.max(probabilities)
    )

    classification = CLASS_NAMES[
        predicted_class
    ]

    is_malicious = predicted_class != 5

    status = (
        "MALICIOUS"
        if is_malicious
        else "BENIGN"
    )

    risk_level = get_risk_level(
        predicted_class,
        confidence
    )

    suspicious_features = (
        get_suspicious_features(
            input_data
        )
    )

    return {
        "status": status,
        "classification": classification,
        "class_id": predicted_class,

        "confidence": round(
            confidence * 100,
            2
        ),

        "risk_level": risk_level,
        "is_malicious": is_malicious,

        "probabilities": probability_map,

        "active_behaviors": suspicious_features,

        "model": "Random Forest",
        "model_accuracy": 94.57
    }