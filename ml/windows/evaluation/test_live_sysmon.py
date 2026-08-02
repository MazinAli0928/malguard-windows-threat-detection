from pathlib import Path
import json

import joblib
import pandas as pd


ROOT = Path(__file__).resolve().parents[3]

LOG_FILE = (
    ROOT
    / "dataset"
    / "windows"
    / "raw"
    / "live_sysmon_events.jsonl"
)

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

EVENT_IDS = [1, 3, 5, 11, 12, 13, 22]

WINDOW_SIZE = 50


def load_events():

    events = []

    if not LOG_FILE.exists():
        raise FileNotFoundError(
            f"Live Sysmon log not found:\n{LOG_FILE}"
        )

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)

                event_id = event.get("event_id")

                if event_id in EVENT_IDS:
                    events.append(event)

            except json.JSONDecodeError:
                continue

    return events


def create_features(events):

    total = len(events)

    counts = {
        event_id: 0
        for event_id in EVENT_IDS
    }

    for event in events:

        event_id = event.get("event_id")

        if event_id in counts:
            counts[event_id] += 1

    features = {}

    # Event counts
    for event_id in EVENT_IDS:
        features[f"event_{event_id}_count"] = counts[event_id]

    features["total_events"] = total

    # Event ratios
    for event_id in EVENT_IDS:

        features[f"event_{event_id}_ratio"] = (
            counts[event_id] / total
            if total
            else 0.0
        )

    # Activity categories
    features["process_activity"] = (
        counts[1] + counts[5]
    )

    features["network_activity"] = (
        counts[3] + counts[22]
    )

    features["file_activity"] = (
        counts[11]
    )

    features["registry_activity"] = (
        counts[12] + counts[13]
    )

    # Category ratios
    features["process_ratio"] = (
        features["process_activity"] / total
        if total
        else 0.0
    )

    features["network_ratio"] = (
        features["network_activity"] / total
        if total
        else 0.0
    )

    features["file_ratio"] = (
        features["file_activity"] / total
        if total
        else 0.0
    )

    features["registry_ratio"] = (
        features["registry_activity"] / total
        if total
        else 0.0
    )

    return features


def main():

    print("=" * 72)
    print("MALGUARD - LIVE WINDOWS SYSMON TEST")
    print("=" * 72)

    print("\nLoading model...")

    model = joblib.load(MODEL_FILE)

    with open(
        FEATURE_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        feature_names = json.load(file)

    print("Model loaded.")

    print("\nLoading real Sysmon events...")

    events = load_events()

    print(
        f"Compatible events found: {len(events):,}"
    )

    if len(events) < WINDOW_SIZE:

        print(
            f"\nNot enough events."
        )

        print(
            f"Need at least {WINDOW_SIZE}, "
            f"found {len(events)}."
        )

        print(
            "\nRun the collector and generate "
            "more Windows activity first."
        )

        return

    # Use most recent compatible events
    window = events[-WINDOW_SIZE:]

    features = create_features(window)

    print("\n" + "-" * 72)
    print("LIVE FEATURE VECTOR")
    print("-" * 72)

    for key, value in features.items():
        print(f"{key:<25} {value}")

    # Exact same feature ordering as training
    X_live = pd.DataFrame(
        [[features[name] for name in feature_names]],
        columns=feature_names
    )

    prediction = int(
        model.predict(X_live)[0]
    )

    probabilities = model.predict_proba(
        X_live
    )[0]

    benign_probability = float(
        probabilities[0]
    )

    malicious_probability = float(
        probabilities[1]
    )

    print("\n" + "=" * 72)
    print("LIVE PREDICTION")
    print("=" * 72)

    if prediction == 1:

        print("\nSTATUS: MALICIOUS")

    else:

        print("\nSTATUS: BENIGN")

    print(
        f"\nBenign probability   : "
        f"{benign_probability * 100:.2f}%"
    )

    print(
        f"Malicious probability: "
        f"{malicious_probability * 100:.2f}%"
    )

    print("\nEvent distribution:")

    for event_id in EVENT_IDS:

        print(
            f"Event {event_id:<2}: "
            f"{features[f'event_{event_id}_count']}"
        )

    print("\n" + "=" * 72)


if __name__ == "__main__":
    main()