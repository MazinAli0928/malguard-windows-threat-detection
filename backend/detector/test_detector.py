from backend.detector import (
    MalwarePredictor,
    RiskEngine,
    create_features,
    calculate_behavior_diversity,
)


def main():

    print("=" * 70)
    print("MALGUARD DETECTOR MODULE TEST")
    print("=" * 70)

    # Simulated normal behavioral window
    events = []

    event_distribution = {
        1: 4,
        3: 15,
        5: 0,
        11: 17,
        12: 7,
        13: 4,
        22: 3,
    }

    for event_id, count in event_distribution.items():

        for _ in range(count):

            events.append({
                "event_id": event_id
            })

    print(
        f"\nEvents generated: "
        f"{len(events)}"
    )

    features = create_features(events)

    print("\nFeature extraction: OK")

    diversity = (
        calculate_behavior_diversity(
            features
        )
    )

    print(
        f"Behavior diversity: "
        f"{diversity}"
    )

    predictor = MalwarePredictor()

    print("Model loading: OK")

    prediction = predictor.predict(
        features
    )

    print(
        "\nMalicious probability: "
        f"{prediction['malicious_probability'] * 100:.2f}%"
    )

    risk_engine = RiskEngine()

    risk = risk_engine.evaluate(
        prediction[
            "malicious_probability"
        ],
        features,
        diversity
    )

    print(
        f"Final status: "
        f"{risk['final_status']}"
    )

    print(
        f"Final risk: "
        f"{risk['final_risk']}"
    )

    print(
        f"Reason: "
        f"{risk['reason']}"
    )

    print("\n✓ MODULE TEST COMPLETE")


if __name__ == "__main__":
    main()