from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[3]

INPUT_FILE = (
    ROOT
    / "dataset"
    / "windows"
    / "raw"
    / "fasttext-all-nofamily.csv"
)

OUTPUT_FILE = (
    ROOT
    / "dataset"
    / "windows"
    / "processed"
    / "windows_behavior_features.csv"
)

# Events available in BOTH SILRAD and our live Sysmon configuration
EVENT_IDS = [1, 3, 5, 11, 12, 13, 22]

# Number of consecutive events used to form one training sample
WINDOW_SIZE = 50


def create_features(window):
    total = len(window)

    features = {}

    # Raw counts
    for event_id in EVENT_IDS:
        count = int((window["event.code"] == event_id).sum())
        features[f"event_{event_id}_count"] = count

    # Total events
    features["total_events"] = total

    # Normalized frequencies
    for event_id in EVENT_IDS:
        count = features[f"event_{event_id}_count"]

        features[f"event_{event_id}_ratio"] = (
            count / total if total else 0.0
        )

    # Broader behavioral categories
    features["process_activity"] = (
        features["event_1_count"]
        + features["event_5_count"]
    )

    features["network_activity"] = (
        features["event_3_count"]
        + features["event_22_count"]
    )

    features["file_activity"] = (
        features["event_11_count"]
    )

    features["registry_activity"] = (
        features["event_12_count"]
        + features["event_13_count"]
    )

    # Category ratios
    features["process_ratio"] = (
        features["process_activity"] / total
        if total else 0.0
    )

    features["network_ratio"] = (
        features["network_activity"] / total
        if total else 0.0
    )

    features["file_ratio"] = (
        features["file_activity"] / total
        if total else 0.0
    )

    features["registry_ratio"] = (
        features["registry_activity"] / total
        if total else 0.0
    )

    return features


def main():

    print("=" * 70)
    print("MALGUARD WINDOWS FEATURE BUILDER")
    print("=" * 70)

    print("\nLoading SILRAD...")

    df = pd.read_csv(
        INPUT_FILE,
        usecols=["event.code", "class"]
    )

    print(f"Events loaded: {len(df):,}")

    # Keep only events our live collector can reproduce
    df = df[df["event.code"].isin(EVENT_IDS)].copy()

    print(f"Compatible events: {len(df):,}")

    samples = []

    print("\nCreating behavioral windows...")

    # IMPORTANT:
    # Build windows independently for each class.
    # This prevents a window from mixing benign and malicious labels.
    for label in sorted(df["class"].unique()):

        class_df = df[df["class"] == label].reset_index(drop=True)

        print(
            f"Class {label}: "
            f"{len(class_df):,} compatible events"
        )

        for start in range(
            0,
            len(class_df) - WINDOW_SIZE + 1,
            WINDOW_SIZE
        ):

            window = class_df.iloc[
                start:start + WINDOW_SIZE
            ]

            features = create_features(window)

            features["class"] = int(label)

            samples.append(features)

    features_df = pd.DataFrame(samples)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    features_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\n" + "=" * 70)
    print("FEATURE DATASET CREATED")
    print("=" * 70)

    print(f"\nSamples: {len(features_df):,}")
    print(f"Features: {len(features_df.columns) - 1}")

    print("\nClass distribution:")
    print(features_df["class"].value_counts().sort_index())

    print("\nColumns:")

    for column in features_df.columns:
        print(f" - {column}")

    print(f"\nSaved to:\n{OUTPUT_FILE}")

    print("\nFirst 5 samples:")
    print(features_df.head().to_string(index=False))


if __name__ == "__main__":
    main()