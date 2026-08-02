from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[2]

RESULTS = ROOT / "results"
PLOTS = RESULTS / "plots"

PLOTS.mkdir(parents=True, exist_ok=True)


# ==========================================================
# 1. TRAINING ACCURACY GRAPH
# ==========================================================

history = pd.read_csv(
    RESULTS / "attention_training_history.csv"
)

plt.figure(figsize=(9, 6))

plt.plot(
    history["accuracy"],
    label="Training Accuracy"
)

plt.plot(
    history["val_accuracy"],
    label="Validation Accuracy"
)

plt.xlabel("Epoch")
plt.ylabel("Accuracy")

plt.title(
    "Attention Model - Training and Validation Accuracy"
)

plt.legend()
plt.grid(alpha=0.3)

plt.tight_layout()

plt.savefig(
    PLOTS / "attention_accuracy.png",
    dpi=300
)

plt.close()


# ==========================================================
# 2. TRAINING LOSS GRAPH
# ==========================================================

plt.figure(figsize=(9, 6))

plt.plot(
    history["loss"],
    label="Training Loss"
)

plt.plot(
    history["val_loss"],
    label="Validation Loss"
)

plt.xlabel("Epoch")
plt.ylabel("Loss")

plt.title(
    "Attention Model - Training and Validation Loss"
)

plt.legend()
plt.grid(alpha=0.3)

plt.tight_layout()

plt.savefig(
    PLOTS / "attention_loss.png",
    dpi=300
)

plt.close()


# ==========================================================
# 3. MODEL COMPARISON
# ==========================================================

models = [
    "Random Forest",
    "Attention Network"
]

accuracy = [
    94.57,
    85.69
]

plt.figure(figsize=(8, 6))

bars = plt.bar(
    models,
    accuracy
)

plt.ylabel("Test Accuracy (%)")

plt.title(
    "Malware Detection Model Comparison"
)

plt.ylim(0, 100)

plt.grid(
    axis="y",
    alpha=0.3
)

for bar, value in zip(bars, accuracy):

    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 1,
        f"{value:.2f}%",
        ha="center",
        fontweight="bold"
    )

plt.tight_layout()

plt.savefig(
    PLOTS / "model_comparison.png",
    dpi=300
)

plt.close()


# ==========================================================
# 4. CLASS PERFORMANCE
# ==========================================================

classes = [
    "Class 1",
    "Class 2",
    "Class 3",
    "Class 4",
    "Class 5"
]

f1_scores = [
    0.7521,
    0.8344,
    0.9359,
    0.8527,
    0.7857
]

plt.figure(figsize=(9, 6))

bars = plt.bar(
    classes,
    f1_scores
)

plt.xlabel("Malware Category")
plt.ylabel("F1 Score")

plt.title(
    "Attention Model - Class-wise F1 Score"
)

plt.ylim(0, 1)

plt.grid(
    axis="y",
    alpha=0.3
)

for bar, value in zip(bars, f1_scores):

    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 0.015,
        f"{value:.3f}",
        ha="center"
    )

plt.tight_layout()

plt.savefig(
    PLOTS / "class_f1_scores.png",
    dpi=300
)

plt.close()


print("=" * 60)
print("RESULT VISUALIZATIONS GENERATED")
print("=" * 60)

print("\nCreated:")

for file in sorted(PLOTS.glob("*.png")):
    print("✓", file.name)