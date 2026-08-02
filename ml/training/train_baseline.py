from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
from sklearn.model_selection import train_test_split


# --------------------------------------------------
# PATHS
# --------------------------------------------------

ROOT = Path(__file__).resolve().parents[2]

DATASET = (
    ROOT
    / "dataset"
    / "raw"
    / "feature_vectors_syscallsbinders_frequency_5_Cat.csv"
)

MODEL_DIR = ROOT / "saved_models"
RESULTS_DIR = ROOT / "results"

MODEL_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)


# --------------------------------------------------
# LOAD DATASET
# --------------------------------------------------

print("=" * 70)
print("BEHAVIOR-BASED MALWARE DETECTION")
print("BASELINE MODEL TRAINING")
print("=" * 70)

print("\nLoading dataset...")

df = pd.read_csv(DATASET)

print("Dataset loaded successfully.")
print("Shape:", df.shape)


# --------------------------------------------------
# PREPARE FEATURES
# --------------------------------------------------

X = df.drop(columns=["Class"])
y = df["Class"].astype(int)

print("\nNumber of behavioral features:", X.shape[1])

print("\nClass distribution:")
print(y.value_counts().sort_index())


# --------------------------------------------------
# TRAIN / TEST SPLIT
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples :", len(X_test))


# --------------------------------------------------
# MODEL
# --------------------------------------------------

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

print("Training complete.")


# --------------------------------------------------
# PREDICTION
# --------------------------------------------------

print("\nEvaluating model...")

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

print(f"\nAccuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        digits=4
    )
)

print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))


# --------------------------------------------------
# FEATURE IMPORTANCE
# --------------------------------------------------

importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": model.feature_importances_
})

importance = importance.sort_values(
    "Importance",
    ascending=False
)

importance.to_csv(
    RESULTS_DIR / "baseline_feature_importance.csv",
    index=False
)

print("\nTop 20 behavioral features:")

print(
    importance.head(20).to_string(index=False)
)


# --------------------------------------------------
# SAVE MODEL
# --------------------------------------------------

joblib.dump(
    model,
    MODEL_DIR / "baseline_random_forest.pkl"
)

joblib.dump(
    list(X.columns),
    MODEL_DIR / "baseline_features.pkl"
)


# --------------------------------------------------
# SAVE REPORT
# --------------------------------------------------

report = classification_report(
    y_test,
    predictions,
    digits=4
)

with open(
    RESULTS_DIR / "baseline_report.txt",
    "w",
    encoding="utf-8"
) as file:

    file.write(
        "Behavior-Based Malware Detection\n"
    )

    file.write(
        "Random Forest Baseline\n\n"
    )

    file.write(
        f"Accuracy: {accuracy:.4f}\n\n"
    )

    file.write(report)


print("\nModel saved:")
print(
    MODEL_DIR
    / "baseline_random_forest.pkl"
)

print("\nFeature importance saved:")
print(
    RESULTS_DIR
    / "baseline_feature_importance.csv"
)

print("\n✓ BASELINE TRAINING COMPLETE")