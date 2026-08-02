import json
import time
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime
from pathlib import Path

import joblib
import pandas as pd
import win32evtlog


# ============================================================
# CONFIGURATION
# ============================================================

ROOT = Path(__file__).resolve().parents[1]

CHANNEL = "Microsoft-Windows-Sysmon/Operational"

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

OUTPUT_DIR = (
    ROOT
    / "dataset"
    / "windows"
    / "test"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

PREDICTION_FILE = (
    OUTPUT_DIR
    / "realtime_predictions.jsonl"
)


# Sysmon events used during training
EVENT_IDS = [
    1,   # Process Create
    3,   # Network Connection
    5,   # Process Terminate
    11,  # File Create
    12,  # Registry Create/Delete
    13,  # Registry Value Set
    22,  # DNS Query
]


EVENT_NAMES = {
    1: "PROCESS_CREATE",
    3: "NETWORK_CONNECTION",
    5: "PROCESS_TERMINATE",
    11: "FILE_CREATE",
    12: "REGISTRY_CREATE_DELETE",
    13: "REGISTRY_VALUE_SET",
    22: "DNS_QUERY",
}


# Number of events used for each prediction
WINDOW_SIZE = 50

# Run prediction every N compatible events
STEP_SIZE = 10


# ============================================================
# LOAD MODEL
# ============================================================

print("=" * 75)
print("MALGUARD REAL-TIME WINDOWS DETECTOR")
print("=" * 75)

print("\nLoading Random Forest model...")

model = joblib.load(
    MODEL_FILE
)

with open(
    FEATURE_FILE,
    "r",
    encoding="utf-8"
) as file:

    feature_names = json.load(file)

print("Model loaded successfully.")

print(
    f"Features expected: "
    f"{len(feature_names)}"
)


# ============================================================
# EVENT PARSER
# ============================================================

def parse_event(raw_event):

    xml = win32evtlog.EvtRender(
        raw_event,
        win32evtlog.EvtRenderEventXml
    )

    root = ET.fromstring(xml)

    namespace = {
        "e":
        "http://schemas.microsoft.com/win/2004/08/events/event"
    }

    system = root.find(
        "e:System",
        namespace
    )

    event_id = int(
        system.find(
            "e:EventID",
            namespace
        ).text
    )

    record_node = system.find(
        "e:EventRecordID",
        namespace
    )

    record_id = (
        int(record_node.text)
        if record_node is not None
        else None
    )

    time_node = system.find(
        "e:TimeCreated",
        namespace
    )

    timestamp = (
        time_node.attrib.get(
            "SystemTime"
        )
        if time_node is not None
        else None
    )

    data = {}

    event_data = root.find(
        "e:EventData",
        namespace
    )

    if event_data is not None:

        for item in event_data:

            name = item.attrib.get(
                "Name",
                "unknown"
            )

            data[name] = (
                item.text or ""
            )

    return {
        "record_id": record_id,
        "timestamp": timestamp,
        "event_id": event_id,
        "event_type": EVENT_NAMES.get(
            event_id,
            f"EVENT_{event_id}"
        ),
        "data": data,
    }


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def create_features(events):

    total = len(events)

    counts = {
        event_id: 0
        for event_id in EVENT_IDS
    }

    for event in events:

        event_id = event["event_id"]

        if event_id in counts:
            counts[event_id] += 1

    features = {}

    # ---------------- EVENT COUNTS ----------------

    for event_id in EVENT_IDS:

        features[
            f"event_{event_id}_count"
        ] = counts[event_id]

    features["total_events"] = total

    # ---------------- EVENT RATIOS ----------------

    for event_id in EVENT_IDS:

        features[
            f"event_{event_id}_ratio"
        ] = (
            counts[event_id] / total
            if total
            else 0.0
        )

    # ---------------- ACTIVITY GROUPS ----------------

    features["process_activity"] = (
        counts[1]
        + counts[5]
    )

    features["network_activity"] = (
        counts[3]
        + counts[22]
    )

    features["file_activity"] = (
        counts[11]
    )

    features["registry_activity"] = (
        counts[12]
        + counts[13]
    )

    # ---------------- ACTIVITY RATIOS ----------------

    features["process_ratio"] = (
        features["process_activity"]
        / total
        if total
        else 0.0
    )

    features["network_ratio"] = (
        features["network_activity"]
        / total
        if total
        else 0.0
    )

    features["file_ratio"] = (
        features["file_activity"]
        / total
        if total
        else 0.0
    )

    features["registry_ratio"] = (
        features["registry_activity"]
        / total
        if total
        else 0.0
    )

    return features


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(
    malicious_probability
):

    probability = (
        malicious_probability * 100
    )

    if probability < 30:
        return "LOW"

    elif probability < 50:
        return "ELEVATED"

    elif probability < 70:
        return "SUSPICIOUS"

    else:
        return "HIGH_RISK"


# ============================================================
# PREDICTION
# ============================================================

def predict_window(events):

    features = create_features(
        events
    )

    X = pd.DataFrame(
        [[
            features[name]
            for name in feature_names
        ]],
        columns=feature_names
    )

    probabilities = (
        model.predict_proba(X)[0]
    )

    benign_probability = float(
        probabilities[0]
    )

    malicious_probability = float(
        probabilities[1]
    )

    prediction = int(
        malicious_probability >= 0.50
    )

    risk_level = get_risk_level(
        malicious_probability
    )

    return {
        "timestamp":
            datetime.now().isoformat(),

        "prediction":
            prediction,

        "status":
            (
                "MALICIOUS"
                if prediction == 1
                else "BENIGN"
            ),

        "risk_level":
            risk_level,

        "benign_probability":
            benign_probability,

        "malicious_probability":
            malicious_probability,

        "features":
            features,
    }


# ============================================================
# DISPLAY
# ============================================================

def display_prediction(result):

    probability = (
        result[
            "malicious_probability"
        ]
        * 100
    )

    print("\n")
    print("=" * 75)
    print("MALGUARD LIVE ANALYSIS")
    print("=" * 75)

    print(
        f"Status              : "
        f"{result['status']}"
    )

    print(
        f"Risk Level          : "
        f"{result['risk_level']}"
    )

    print(
        f"Malicious Probability: "
        f"{probability:.2f}%"
    )

    print(
        f"Benign Probability   : "
        f"{result['benign_probability'] * 100:.2f}%"
    )

    print("\nBehavior Window")
    print("-" * 40)

    features = result["features"]

    print(
        f"Process activity : "
        f"{features['process_activity']}"
    )

    print(
        f"Network activity : "
        f"{features['network_activity']}"
    )

    print(
        f"File activity    : "
        f"{features['file_activity']}"
    )

    print(
        f"Registry activity: "
        f"{features['registry_activity']}"
    )

    print(
        f"DNS queries      : "
        f"{features['event_22_count']}"
    )

    print("=" * 75)


# ============================================================
# SAVE PREDICTION
# ============================================================

def save_prediction(result):

    with open(
        PREDICTION_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(
                result,
                ensure_ascii=False
            )
            + "\n"
        )


# ============================================================
# GET CURRENT RECORD ID
# ============================================================

def get_latest_record_id():

    flags = (
        win32evtlog.EvtQueryChannelPath
        |
        win32evtlog.EvtQueryReverseDirection
    )

    handle = win32evtlog.EvtQuery(
        CHANNEL,
        flags,
        "*"
    )

    events = win32evtlog.EvtNext(
        handle,
        1
    )

    if not events:
        return None

    event = parse_event(
        events[0]
    )

    return event["record_id"]


# ============================================================
# MAIN REAL-TIME LOOP
# ============================================================

def main():

    print("\nSysmon channel:")
    print(CHANNEL)

    print(
        f"\nWindow size : "
        f"{WINDOW_SIZE} events"
    )

    print(
        f"Step size   : "
        f"{STEP_SIZE} events"
    )

    print(
        "\nWaiting for new "
        "Windows activity..."
    )

    print(
        "Press CTRL+C to stop.\n"
    )

    event_buffer = deque(
        maxlen=WINDOW_SIZE
    )

    events_since_prediction = 0

    last_record_id = (
        get_latest_record_id()
    )

    try:

        while True:

            flags = (
                win32evtlog.EvtQueryChannelPath
                |
                win32evtlog.EvtQueryForwardDirection
            )

            if last_record_id is None:

                query = "*"

            else:

                query = (
                    "*[System["
                    f"EventRecordID>{last_record_id}"
                    "]]"
                )

            handle = win32evtlog.EvtQuery(
                CHANNEL,
                flags,
                query
            )

            raw_events = (
                win32evtlog.EvtNext(
                    handle,
                    200
                )
            )

            for raw_event in raw_events:

                event = parse_event(
                    raw_event
                )

                if (
                    event["record_id"]
                    is not None
                ):

                    last_record_id = (
                        event["record_id"]
                    )

                # Ignore events not used
                # by the ML model
                if (
                    event["event_id"]
                    not in EVENT_IDS
                ):
                    continue

                event_buffer.append(
                    event
                )

                events_since_prediction += 1

                print(
                    f"[{event['event_type']:<24}] "
                    f"Buffer: "
                    f"{len(event_buffer):02}/{WINDOW_SIZE}"
                )

                # Wait until first complete window
                if (
                    len(event_buffer)
                    < WINDOW_SIZE
                ):
                    continue

                # Sliding window
                if (
                    events_since_prediction
                    < STEP_SIZE
                ):
                    continue

                events_since_prediction = 0

                result = predict_window(
                    list(event_buffer)
                )

                display_prediction(
                    result
                )

                save_prediction(
                    result
                )

            time.sleep(1)

    except KeyboardInterrupt:

        print(
            "\n\nMALGUARD "
            "real-time detector stopped."
        )

        print(
            "\nPredictions saved to:"
        )

        print(
            PREDICTION_FILE
        )


if __name__ == "__main__":
    main()