from collections import deque


class RiskEngine:

    def __init__(
        self,
        confirmation_windows=3
    ):
        self.confirmation_windows = confirmation_windows

        self.recent_high_risk = deque(
            maxlen=confirmation_windows
        )

    def evaluate(
        self,
        malicious_probability,
        features,
        diversity
    ):

        probability = malicious_probability * 100

        # --------------------------------------------------
        # BASE ML RISK LEVEL
        # --------------------------------------------------

        if probability < 30:
            model_risk = "LOW"

        elif probability < 50:
            model_risk = "ELEVATED"

        elif probability < 75:
            model_risk = "SUSPICIOUS"

        else:
            model_risk = "HIGH_RISK"

        # --------------------------------------------------
        # BEHAVIORAL CONTEXT
        # --------------------------------------------------

        registry_only = (
            features["registry_activity"] > 0
            and features["process_activity"] == 0
            and features["network_activity"] == 0
            and features["file_activity"] == 0
        )

        low_diversity = diversity <= 1

        # --------------------------------------------------
        # HIGH-RISK CONFIRMATION
        # --------------------------------------------------

        high_candidate = (
            probability >= 75
            and diversity >= 2
            and not registry_only
        )

        self.recent_high_risk.append(
            high_candidate
        )

        confirmed = (
            len(self.recent_high_risk)
            == self.confirmation_windows
            and all(self.recent_high_risk)
        )

        # --------------------------------------------------
        # FINAL APPLICATION STATUS
        # --------------------------------------------------

        if confirmed:

            final_status = "MALICIOUS"
            final_risk = "HIGH_RISK"

            reason = (
                "Repeated high-risk behavior detected "
                "across multiple behavioral categories."
            )

        elif probability >= 75 and registry_only:

            final_status = "ANOMALOUS"
            final_risk = "ELEVATED"

            reason = (
                "High model probability caused by a "
                "registry-dominated activity burst. "
                "Additional malicious behavior has not "
                "been confirmed."
            )

        elif probability >= 75 and low_diversity:

            final_status = "ANOMALOUS"
            final_risk = "ELEVATED"

            reason = (
                "High model probability detected, but "
                "behavioral diversity is too low for "
                "malware confirmation."
            )

        elif probability >= 50:

            final_status = "SUSPICIOUS"
            final_risk = "SUSPICIOUS"

            reason = (
                "Elevated malicious probability detected. "
                "Monitoring for additional evidence."
            )

        elif probability >= 30:

            final_status = "BENIGN"
            final_risk = "ELEVATED"

            reason = (
                "Some unusual activity detected, but "
                "malicious behavior is not confirmed."
            )

        else:

            final_status = "BENIGN"
            final_risk = "LOW"

            reason = (
                "Current behavior is consistent with "
                "normal system activity."
            )

        return {
            "model_risk": model_risk,
            "final_status": final_status,
            "final_risk": final_risk,
            "confirmed_threat": confirmed,
            "behavior_diversity": diversity,
            "registry_only": registry_only,
            "reason": reason,
        }