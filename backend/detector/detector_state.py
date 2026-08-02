from collections import deque
from datetime import datetime
from threading import Lock


class DetectorState:

    def __init__(
        self,
        history_size=100,
        event_size=100
    ):

        self.lock = Lock()

        self.running = False

        self.started_at = None

        self.latest_prediction = None

        self.prediction_history = deque(
            maxlen=history_size
        )

        self.recent_events = deque(
            maxlen=event_size
        )

        self.total_events = 0
        self.total_predictions = 0
        self.total_alerts = 0

    def start(self):

        with self.lock:

            self.running = True
            self.started_at = datetime.now().isoformat()

    def stop(self):

        with self.lock:
            self.running = False

    def add_event(self, event):

        with self.lock:

            self.recent_events.append(event)

            self.total_events += 1

    def update_prediction(self, prediction):

        with self.lock:

            self.latest_prediction = prediction

            self.prediction_history.append(
                prediction
            )

            self.total_predictions += 1

            if prediction.get(
                "confirmed_threat",
                False
            ):
                self.total_alerts += 1

    def get_status(self):

        with self.lock:

            return {
                "running": self.running,
                "started_at": self.started_at,
                "total_events": self.total_events,
                "total_predictions": self.total_predictions,
                "total_alerts": self.total_alerts,
                "latest_prediction":
                    self.latest_prediction,
            }

    def get_events(self):

        with self.lock:
            return list(
                self.recent_events
            )

    def get_history(self):

        with self.lock:
            return list(
                self.prediction_history
            )

    def reset(self):

        with self.lock:

            self.latest_prediction = None

            self.prediction_history.clear()
            self.recent_events.clear()

            self.total_events = 0
            self.total_predictions = 0
            self.total_alerts = 0