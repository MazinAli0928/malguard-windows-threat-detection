import threading
import time
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime

import win32evtlog

from .feature_extractor import (
    EVENT_IDS,
    EVENT_NAMES,
    create_features,
    calculate_behavior_diversity,
)
from .predictor import MalwarePredictor
from .risk_engine import RiskEngine
from .detector_state import DetectorState


CHANNEL = "Microsoft-Windows-Sysmon/Operational"

WINDOW_SIZE = 50
STEP_SIZE = 10


class DetectorService:

    def __init__(self):

        self.predictor = MalwarePredictor()

        self.risk_engine = RiskEngine(
            confirmation_windows=3
        )

        self.state = DetectorState(
            history_size=200,
            event_size=200
        )

        self.event_buffer = deque(
            maxlen=WINDOW_SIZE
        )

        self.events_since_prediction = 0

        self.thread = None

        self.stop_event = threading.Event()

        self.last_record_id = None

        self.service_lock = threading.Lock()

    # ========================================================
    # EVENT PARSER
    # ========================================================

    def parse_event(self, raw_event):

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

    # ========================================================
    # LATEST SYSMON RECORD
    # ========================================================

    def get_latest_record_id(self):

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

        event = self.parse_event(
            events[0]
        )

        return event["record_id"]

    # ========================================================
    # WINDOW ANALYSIS
    # ========================================================

    def analyze_window(self):

        features = create_features(
            list(self.event_buffer)
        )

        diversity = (
            calculate_behavior_diversity(
                features
            )
        )

        ml_result = self.predictor.predict(
            features
        )

        risk_result = (
            self.risk_engine.evaluate(
                ml_result[
                    "malicious_probability"
                ],
                features,
                diversity
            )
        )

        return {
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

    # ========================================================
    # MONITOR LOOP
    # ========================================================

    def monitor(self):

        try:

            self.last_record_id = (
                self.get_latest_record_id()
            )

            while not self.stop_event.is_set():

                flags = (
                    win32evtlog.EvtQueryChannelPath
                    |
                    win32evtlog.EvtQueryForwardDirection
                )

                if self.last_record_id is None:

                    query = "*"

                else:

                    query = (
                        "*[System["
                        f"EventRecordID>{self.last_record_id}"
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

                    if self.stop_event.is_set():
                        break

                    event = self.parse_event(
                        raw_event
                    )

                    if (
                        event["record_id"]
                        is not None
                    ):
                        self.last_record_id = (
                            event["record_id"]
                        )

                    if (
                        event["event_id"]
                        not in EVENT_IDS
                    ):
                        continue

                    self.state.add_event(
                        event
                    )

                    self.event_buffer.append(
                        event
                    )

                    self.events_since_prediction += 1

                    if (
                        len(self.event_buffer)
                        < WINDOW_SIZE
                    ):
                        continue

                    if (
                        self.events_since_prediction
                        < STEP_SIZE
                    ):
                        continue

                    self.events_since_prediction = 0

                    result = (
                        self.analyze_window()
                    )

                    self.state.update_prediction(
                        result
                    )

                self.stop_event.wait(1)

        except Exception as error:

            err_msg = str(error)
            if "Access is denied" in err_msg or (hasattr(error, 'winerror') and error.winerror == 5):
                err_msg = "Access is denied. Please run MALGUARD Backend as Administrator to read Sysmon event log."

            print(
                "Detector service error:",
                err_msg
            )

            self.state.set_error(err_msg)

        finally:

            self.state.stop()

    # ========================================================
    # START
    # ========================================================

    def start(self):

        with self.service_lock:

            if (
                self.thread is not None
                and self.thread.is_alive()
            ):
                return False

            self.stop_event.clear()

            self.event_buffer.clear()

            self.events_since_prediction = 0

            self.risk_engine = RiskEngine(
                confirmation_windows=3
            )

            self.state.start()

            self.thread = threading.Thread(
                target=self.monitor,
                daemon=True,
                name="MALGUARD-Sysmon-Detector"
            )

            self.thread.start()

            return True

    # ========================================================
    # STOP
    # ========================================================

    def stop(self):

        with self.service_lock:

            if (
                self.thread is None
                or not self.thread.is_alive()
            ):
                self.state.stop()
                return False

            self.stop_event.set()

            self.thread.join(
                timeout=3
            )

            self.state.stop()

            return True

    # ========================================================
    # PUBLIC METHODS FOR FASTAPI
    # ========================================================

    def get_status(self):
        return self.state.get_status()

    def get_events(self):
        return self.state.get_events()

    def get_history(self):
        return self.state.get_history()