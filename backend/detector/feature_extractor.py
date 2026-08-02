EVENT_IDS = [1, 3, 5, 11, 12, 13, 22]

EVENT_NAMES = {
    1: "PROCESS_CREATE",
    3: "NETWORK_CONNECTION",
    5: "PROCESS_TERMINATE",
    11: "FILE_CREATE",
    12: "REGISTRY_CREATE_DELETE",
    13: "REGISTRY_VALUE_SET",
    22: "DNS_QUERY",
}


def create_features(events):
    total = len(events)

    counts = {event_id: 0 for event_id in EVENT_IDS}

    for event in events:
        event_id = event.get("event_id")

        if event_id in counts:
            counts[event_id] += 1

    features = {}

    # Individual event counts
    for event_id in EVENT_IDS:
        features[f"event_{event_id}_count"] = counts[event_id]

    features["total_events"] = total

    # Individual event ratios
    for event_id in EVENT_IDS:
        features[f"event_{event_id}_ratio"] = (
            counts[event_id] / total
            if total > 0
            else 0.0
        )

    # Broader behavioral categories
    features["process_activity"] = counts[1] + counts[5]
    features["network_activity"] = counts[3] + counts[22]
    features["file_activity"] = counts[11]
    features["registry_activity"] = counts[12] + counts[13]

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


def calculate_behavior_diversity(features):
    """
    Number of behavioral categories active in the current window.

    Categories:
        Process
        Network
        File
        Registry
        DNS
    """

    active = 0

    if features["process_activity"] > 0:
        active += 1

    if features["network_activity"] > 0:
        active += 1

    if features["file_activity"] > 0:
        active += 1

    if features["registry_activity"] > 0:
        active += 1

    if features["event_22_count"] > 0:
        active += 1

    return active