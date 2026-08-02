from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.detector import DetectorService


app = FastAPI(
    title="MALGUARD API",
    description=(
        "Real-time Windows behavioral "
        "malware detection API"
    ),
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DETECTOR
# ============================================================

detector = DetectorService()


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "name": "MALGUARD",
        "version": "1.0.0",
        "platform": "Windows",
        "status": "API online",
    }


# ============================================================
# STATUS
# ============================================================

@app.get("/api/status")
def get_status():

    return detector.get_status()


# ============================================================
# EVENTS
# ============================================================

@app.get("/api/events")
def get_events(
    limit: int = 50
):

    events = detector.get_events()

    limit = max(
        1,
        min(limit, 200)
    )

    return {
        "count": min(
            len(events),
            limit
        ),
        "events": events[-limit:],
    }


# ============================================================
# HISTORY
# ============================================================

@app.get("/api/history")
def get_history(
    limit: int = 50
):

    history = (
        detector.get_history()
    )

    limit = max(
        1,
        min(limit, 200)
    )

    return {
        "count": min(
            len(history),
            limit
        ),
        "history":
            history[-limit:],
    }


# ============================================================
# STATISTICS
# ============================================================

@app.get("/api/stats")
def get_stats():

    status = detector.get_status()

    history = detector.get_history()

    benign = 0
    suspicious = 0
    anomalous = 0
    malicious = 0

    for item in history:

        item_status = item.get(
            "status"
        )

        if item_status == "BENIGN":
            benign += 1

        elif item_status == "SUSPICIOUS":
            suspicious += 1

        elif item_status == "ANOMALOUS":
            anomalous += 1

        elif item_status == "MALICIOUS":
            malicious += 1

    return {
        "running":
            status["running"],

        "total_events":
            status["total_events"],

        "total_predictions":
            status[
                "total_predictions"
            ],

        "confirmed_alerts":
            status["total_alerts"],

        "classification_counts": {
            "benign": benign,
            "suspicious": suspicious,
            "anomalous": anomalous,
            "malicious": malicious,
        },
    }


# ============================================================
# START
# ============================================================

@app.post("/api/start")
def start_detector():

    started = detector.start()

    if not started:

        return {
            "success": False,
            "message":
                "Detector is already running."
        }

    return {
        "success": True,
        "message":
            "MALGUARD monitoring started."
    }


# ============================================================
# STOP
# ============================================================

@app.post("/api/stop")
def stop_detector():

    stopped = detector.stop()

    if not stopped:

        return {
            "success": False,
            "message":
                "Detector is not running."
        }

    return {
        "success": True,
        "message":
            "MALGUARD monitoring stopped."
    }