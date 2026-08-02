from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd
import tensorflow as tf

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

from tensorflow.keras.layers import (
    Input,
    Dense,
    Dropout,
    BatchNormalization,
    Multiply,
    Activation
)

from tensorflow.keras.models import Model
from tensorflow.keras.callbacks import (
    EarlyStopping,
    ReduceLROnPlateau
)


# ============================================================
# SETTINGS
# ============================================================

SEED = 42

np.random.seed(SEED)
tf.random.set_seed(SEED)


# ============================================================
# PATHS
# ============================================================

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


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 70)
print("ATTENTION-BASED MALWARE DETECTION")
print("=" * 70)

print("\nLoading dataset...")

df = pd.read_csv(DATASET)

print("Dataset shape:", df.shape)


# ============================================================
# FEATURES / LABELS
# ============================================================

X = df.drop(columns=["Class"]).astype("float32")
y = df["Class"].astype(int)


# Convert labels:
# 1,2,3,4,5  ->  0,1,2,3,4

y = y - 1

print("\nFeatures:", X.shape[1])

print("\nClass distribution:")
print(pd.Series(y).value_counts().sort_index())


# ============================================================
# TRAIN / VALIDATION / TEST
# ============================================================

X_train, X_temp, y_train, y_temp = train_test_split(
    X,
    y,
    test_size=0.30,
    random_state=SEED,
    stratify=y
)

X_val, X_test, y_val, y_test = train_test_split(
    X_temp,
    y_temp,
    test_size=0.50,
    random_state=SEED,
    stratify=y_temp
)

print("\nTraining samples  :", len(X_train))
print("Validation samples:", len(X_val))
print("Testing samples   :", len(X_test))


# ============================================================
# SCALING
# ============================================================

print("\nScaling features...")

scaler = StandardScaler()

X_train = scaler.fit_transform(X_train)
X_val = scaler.transform(X_val)
X_test = scaler.transform(X_test)

joblib.dump(
    scaler,
    MODEL_DIR / "attention_scaler.pkl"
)

joblib.dump(
    list(X.columns),
    MODEL_DIR / "attention_features.pkl"
)


# ============================================================
# MODEL
# ============================================================

number_of_features = X_train.shape[1]

inputs = Input(
    shape=(number_of_features,),
    name="behavior_input"
)


# ------------------------------------------------------------
# Feature representation
# ------------------------------------------------------------

x = Dense(
    256,
    activation="relu",
    name="feature_representation"
)(inputs)

x = BatchNormalization()(x)

x = Dropout(0.30)(x)


# ------------------------------------------------------------
# ATTENTION MECHANISM
# ------------------------------------------------------------

attention_scores = Dense(
    256,
    name="attention_scores"
)(x)

attention_weights = Activation(
    "softmax",
    name="attention_weights"
)(attention_scores)

attention_output = Multiply(
    name="attention_output"
)([
    x,
    attention_weights
])


# ------------------------------------------------------------
# Classification layers
# ------------------------------------------------------------

x = Dense(
    128,
    activation="relu"
)(attention_output)

x = BatchNormalization()(x)

x = Dropout(0.30)(x)


x = Dense(
    64,
    activation="relu"
)(x)

x = Dropout(0.20)(x)


outputs = Dense(
    5,
    activation="softmax",
    name="malware_class"
)(x)


model = Model(
    inputs=inputs,
    outputs=outputs
)


# ============================================================
# COMPILE
# ============================================================

model.compile(
    optimizer=tf.keras.optimizers.Adam(
        learning_rate=0.001
    ),
    loss="sparse_categorical_crossentropy",
    metrics=["accuracy"]
)


print("\n")
model.summary()


# ============================================================
# CALLBACKS
# ============================================================

early_stop = EarlyStopping(
    monitor="val_loss",
    patience=8,
    restore_best_weights=True,
    verbose=1
)

reduce_lr = ReduceLROnPlateau(
    monitor="val_loss",
    factor=0.5,
    patience=3,
    min_lr=0.00001,
    verbose=1
)


# ============================================================
# TRAIN
# ============================================================

print("\nStarting training...\n")

history = model.fit(
    X_train,
    y_train,
    validation_data=(X_val, y_val),

    epochs=50,
    batch_size=64,

    callbacks=[
        early_stop,
        reduce_lr
    ],

    verbose=1
)


# ============================================================
# EVALUATION
# ============================================================

print("\nEvaluating model...")

test_loss, test_accuracy = model.evaluate(
    X_test,
    y_test,
    verbose=0
)

probabilities = model.predict(
    X_test,
    verbose=0
)

predictions = np.argmax(
    probabilities,
    axis=1
)


print("\n" + "=" * 70)
print("ATTENTION MODEL RESULTS")
print("=" * 70)

print(
    f"\nTest Accuracy: "
    f"{test_accuracy * 100:.2f}%"
)


# ============================================================
# CLASSIFICATION REPORT
# ============================================================

report = classification_report(
    y_test,
    predictions,
    digits=4
)

print("\nClassification Report:\n")
print(report)


# ============================================================
# CONFUSION MATRIX
# ============================================================

cm = confusion_matrix(
    y_test,
    predictions
)

print("\nConfusion Matrix:")
print(cm)


# ============================================================
# SAVE MODEL
# ============================================================

model.save(
    MODEL_DIR / "attention_malware_model.keras"
)


# ============================================================
# SAVE TRAINING HISTORY
# ============================================================

history_df = pd.DataFrame(
    history.history
)

history_df.to_csv(
    RESULTS_DIR / "attention_training_history.csv",
    index=False
)


# ============================================================
# SAVE REPORT
# ============================================================

with open(
    RESULTS_DIR / "attention_report.txt",
    "w",
    encoding="utf-8"
) as file:

    file.write(
        "Attention-Based Malware Detection\n\n"
    )

    file.write(
        f"Test Accuracy: "
        f"{test_accuracy:.4f}\n\n"
    )

    file.write(report)

    file.write(
        "\n\nConfusion Matrix:\n"
    )

    file.write(
        np.array2string(cm)
    )


print("\n" + "=" * 70)

print("MODEL SAVED:")
print(
    MODEL_DIR
    / "attention_malware_model.keras"
)

print("\nSCALER SAVED:")
print(
    MODEL_DIR
    / "attention_scaler.pkl"
)

print("\nTRAINING HISTORY SAVED:")
print(
    RESULTS_DIR
    / "attention_training_history.csv"
)

print("\n✓ ATTENTION MODEL TRAINING COMPLETE")

print("=" * 70)