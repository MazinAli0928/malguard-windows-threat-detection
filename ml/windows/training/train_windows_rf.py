from pathlib import Path
import json

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    balanced_accuracy_score,
)


ROOT = Path(__file__).resolve().parents[3]

DATASET = (
    ROOT
    / "dataset"
    / "windows"
    / "processed"
    / "windows_behavior_features.csv"
)

MODEL_DIR = ROOT / "saved_models" / "windows"
RESULTS_DIR = ROOT / "results" / "windows"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = MODEL_DIR / "windows_random_forest.pkl"
FEATURE_PATH = MODEL_DIR / "windows_feature_names.json"
IMPORTANCE_PATH = RESULTS_DIR / "windows_rf_feature_importance.csv"
REPORT_PATH = RESULTS_DIR / "windows_rf_report.txt"


print("=" * 72)
print("MALGUARD WINDOWS RANDOM FOREST")
print("=" * 72)

print("\nLoading feature dataset...")

df = pd.read_csv(DATASET)

print(f"Samples : {len(df):,}")
print(f"Features: {len(df.columns) - 1}")

print("\nClass distribution:")
print(df["class"].value_counts().sort_index())


# -------------------------------------------------------------------
# FEATURES / TARGET
# -------------------------------------------------------------------

X = df.drop(columns=["class"])
y = df["class"]

feature_names = list(X.columns)

print("\nFeature count:", len(feature_names))


# -------------------------------------------------------------------
# TRAIN / TEST SPLIT
# -------------------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print("\nTraining samples:", len(X_train))
print("Testing samples :", len(X_test))

print("\nTraining distribution:")
print(y_train.value_counts().sort_index())

print("\nTesting distribution:")
print(y_test.value_counts().sort_index())


# -------------------------------------------------------------------
# MODEL
# -------------------------------------------------------------------

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=500,
    max_depth=None,
    min_samples_split=4,
    min_samples_leaf=2,

    # Important because the dataset is imbalanced
    class_weight="balanced",

    random_state=42,
    n_jobs=-1,
)

model.fit(X_train, y_train)

print("Training complete.")


# -------------------------------------------------------------------
# EVALUATION
# -------------------------------------------------------------------

print("\nEvaluating model...")

predictions = model.predict(X_test)

probabilities = model.predict_proba(X_test)[:, 1]

accuracy = accuracy_score(
    y_test,
    predictions
)

balanced_accuracy = balanced_accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)

matrix = confusion_matrix(
    y_test,
    predictions
)

report = classification_report(
    y_test,
    predictions,
    target_names=[
        "Benign",
        "Malicious"
    ],
    digits=4,
    zero_division=0
)


print("\n" + "=" * 72)
print("RESULTS")
print("=" * 72)

print(f"\nAccuracy          : {accuracy * 100:.2f}%")
print(f"Balanced Accuracy : {balanced_accuracy * 100:.2f}%")
print(f"Malware Precision : {precision * 100:.2f}%")
print(f"Malware Recall    : {recall * 100:.2f}%")
print(f"Malware F1-score  : {f1 * 100:.2f}%")

print("\nClassification Report:\n")
print(report)

print("Confusion Matrix:")
print(matrix)


# -------------------------------------------------------------------
# FEATURE IMPORTANCE
# -------------------------------------------------------------------

importance_df = pd.DataFrame({
    "Feature": feature_names,
    "Importance": model.feature_importances_,
})

importance_df = importance_df.sort_values(
    "Importance",
    ascending=False
)

importance_df.to_csv(
    IMPORTANCE_PATH,
    index=False
)

print("\nTop 15 features:\n")

print(
    importance_df
    .head(15)
    .to_string(index=False)
)


# -------------------------------------------------------------------
# SAVE MODEL
# -------------------------------------------------------------------

joblib.dump(
    model,
    MODEL_PATH
)

with open(
    FEATURE_PATH,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        feature_names,
        file,
        indent=4
    )


# -------------------------------------------------------------------
# SAVE REPORT
# -------------------------------------------------------------------

with open(
    REPORT_PATH,
    "w",
    encoding="utf-8"
) as file:

    file.write(
        "MALGUARD WINDOWS RANDOM FOREST\n"
    )

    file.write("=" * 72 + "\n\n")

    file.write(
        f"Accuracy: {accuracy:.6f}\n"
    )

    file.write(
        f"Balanced Accuracy: {balanced_accuracy:.6f}\n"
    )

    file.write(
        f"Malware Precision: {precision:.6f}\n"
    )

    file.write(
        f"Malware Recall: {recall:.6f}\n"
    )

    file.write(
        f"Malware F1: {f1:.6f}\n\n"
    )

    file.write(
        "Classification Report\n"
    )

    file.write(
        report
    )

    file.write(
        "\n\nConfusion Matrix\n"
    )

    file.write(
        str(matrix)
    )


print("\n" + "=" * 72)

print("MODEL SAVED:")
print(MODEL_PATH)

print("\nFEATURE NAMES SAVED:")
print(FEATURE_PATH)

print("\nFEATURE IMPORTANCE SAVED:")
print(IMPORTANCE_PATH)

print("\nREPORT SAVED:")
print(REPORT_PATH)

print("\n✓ WINDOWS RANDOM FOREST TRAINING COMPLETE")