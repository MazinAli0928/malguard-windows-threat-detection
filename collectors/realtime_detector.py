import json
import sys
import time
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime
from pathlib import Path

import win32evtlog


# ============================================================
# PROJECT IMPORTS
# ============================================================

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.detector import (
    EVENT_IDS,
    EVENT_NAMES,
    MalwarePredictor,
    RiskEngine,
    DetectorState,
    create_features,
    calculate_behavior_diversity,
)


# ============================================================
# CONFIGURATION
# ============================================================

CHANNEL = "Microsoft-Windows-Sysmon/Operational"

WINDOW_SIZE = 50
STEP_SIZE = 10

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


# ============================================================
# DETECTOR COMPONENTS
# ============================================================

predictor = MalwarePredictor()

risk_engine = RiskEngine(
    confirmation_windows=3
)

detector_state = DetectorState(
    history_size=100,
    event_size=100
)


# ============================================================
# SYSMON EVENT PARSER
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
# GET LATEST RECORD ID
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
# ANALYZE WINDOW
# ============================================================

def analyze_window(events):

    # --------------------------------------------
    # FEATURE EXTRACTION
    # --------------------------------------------

    features = create_features(
        events
    )

    diversity = (
        calculate_behavior_diversity(
            features
        )
    )

    # --------------------------------------------
    # MACHINE LEARNING
    # --------------------------------------------

    ml_result = predictor.predict(
        features
    )

    # --------------------------------------------
    # RISK ENGINE
    # --------------------------------------------

    risk_result = risk_engine.evaluate(
        ml_result[
            "malicious_probability"
        ],
        features,
        diversity
    )

    # --------------------------------------------
    # COMPLETE RESULT
    # --------------------------------------------

    result = {
        "timestamp":
            datetime.now().isoformat(),

        "raw_prediction":
            ml_result[
                "raw_prediction"
            ],

        "benign_probability":
            ml_result[
                "benign_probability"
            ],

        "malicious_probability":
            ml_result[
                "malicious_probability"
            ],

        "model_risk":
            risk_result[
                "model_risk"
            ],

        "status":
            risk_result[
                "final_status"
            ],

        "risk_level":
            risk_result[
                "final_risk"
            ],

        "confirmed_threat":
            risk_result[
                "confirmed_threat"
            ],

        "behavior_diversity":
            risk_result[
                "behavior_diversity"
            ],

        "registry_only":
            risk_result[
                "registry_only"
            ],

        "reason":
            risk_result[
                "reason"
            ],

        "features":
            features,
    }

    return result


# ============================================================
# DISPLAY RESULT
# ============================================================

def display_prediction(result):

    malicious = (
        result[
            "malicious_probability"
        ]
        * 100
    )

    benign = (
        result[
            "benign_probability"
        ]
        * 100
    )

    features = result["features"]

    print("\n")
    print("=" * 75)
    print("MALGUARD LIVE ANALYSIS")
    print("=" * 75)

    print(
        f"Status               : "
        f"{result['status']}"
    )

    print(
        f"Risk Level           : "
        f"{result['risk_level']}"
    )

    print(
        f"Model Risk           : "
        f"{result['model_risk']}"
    )

    print(
        f"Confirmed Threat     : "
        f"{result['confirmed_threat']}"
    )

    print(
        f"Behavior Diversity   : "
        f"{result['behavior_diversity']}/5"
    )

    print(
        f"Malicious Probability: "
        f"{malicious:.2f}%"
    )

    print(
        f"Benign Probability   : "
        f"{benign:.2f}%"
    )

    print("\nBehavior Window")
    print("-" * 45)

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

    print("\nAnalysis")
    print("-" * 45)

    print(
        result["reason"]
    )

    print("=" * 75)


# ============================================================
# SAVE RESULT
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
# MAIN
# ============================================================

def main():

    print("=" * 75)
    print("MALGUARD REAL-TIME WINDOWS DETECTOR")
    print("=" * 75)

    print("\nArchitecture:")
    print(
        "Sysmon -> Features -> Random Forest "
        "-> Risk Engine -> Final Status"
    )

    print(f"\nChannel     : {CHANNEL}")
    print(f"Window size : {WINDOW_SIZE}")
    print(f"Step size   : {STEP_SIZE}")

    print(
        "\nWaiting for NEW Sysmon events..."
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

    detector_state.start()

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

                # Ignore events outside
                # the trained feature space
                if (
                    event["event_id"]
                    not in EVENT_IDS
                ):
                    continue

                # Store for FastAPI
                detector_state.add_event(
                    event
                )

                # Sliding window
                event_buffer.append(
                    event
                )

                events_since_prediction += 1

                print(
                    f"[{event['event_type']:<24}] "
                    f"Buffer: "
                    f"{len(event_buffer):02}/{WINDOW_SIZE}"
                )

                # Need full initial window
                if (
                    len(event_buffer)
                    < WINDOW_SIZE
                ):
                    continue

                # Prediction every STEP_SIZE events
                if (
                    events_since_prediction
                    < STEP_SIZE
                ):
                    continue

                events_since_prediction = 0

                result = analyze_window(
                    list(event_buffer)
                )

                # Store prediction in shared state
                detector_state.update_prediction(
                    result
                )

                display_prediction(
                    result
                )

                save_prediction(
                    result
                )

            time.sleep(1)

    except KeyboardInterrupt:

        detector_state.stop()

        print(
            "\n\nMALGUARD real-time "
            "detector stopped."
        )

        print("\nSession statistics")
        print("-" * 40)

        status = (
            detector_state.get_status()
        )

        print(
            f"Events analyzed     : "
            f"{status['total_events']}"
        )

        print(
            f"Predictions made    : "
            f"{status['total_predictions']}"
        )

        print(
            f"Confirmed alerts    : "
            f"{status['total_alerts']}"
        )

        print(
            "\nPredictions saved to:"
        )

        print(PREDICTION_FILE)


if __name__ == "__main__":
    main()