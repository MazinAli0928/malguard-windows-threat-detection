MALGUARD

Real-Time Windows Behavioral Malware & Spyware Detection System

MALGUARD is a real-time Windows endpoint threat-detection prototype thatmonitors live system activity using Microsoft Sysmon, converts telemetryinto behavioral feature windows, evaluates those windows using a trainedRandom Forest model, and applies a contextual risk engine beforepresenting the results through a FastAPI backend and React dashboard.

Unlike a simple offline malware classifier, MALGUARD demonstrates anend-to-end monitoring pipeline:

Windows → Sysmon → Event Collection → Behavioral Feature Extraction →Random Forest → Risk Engine → FastAPI → React Dashboard

Key Features

Real-time Windows Sysmon telemetry collection

Behavioral rather than signature-only detection

50-event behavioral analysis windows

Random Forest malware probability prediction

Context-aware risk engine

Behavioral diversity analysis

Live process, network, file, registry, and DNS monitoring

Multiple threat states instead of only benign/malicious

Real-time React security dashboard

Live Events view with filtering and search

Threat investigation interface

Detection history

REST API powered by FastAPI

Safe threat-behavior simulation for demonstrations

Detection Architecture

Windows Endpoint
      |
      v
Microsoft Sysmon
      |
      v
Sysmon Event Collector
      |
      v
Behavior Window (50 Events)
      |
      v
Feature Extractor
      |
      v
Random Forest Model
      |
      v
Malicious Probability
      |
      v
Context + Behavioral Diversity
      |
      v
Risk Engine
      |
      v
Final Threat Assessment
      |
      v
FastAPI Backend
      |
      v
React Dashboard

The Random Forest prediction is not treated as the final securitydecision by itself. MALGUARD also evaluates behavioral context anddiversity before assigning the final threat status.

Monitored Sysmon Events

MALGUARD currently focuses on the following Sysmon event categories:

Event ID   Activity

1          Process Creation3          Network Connection5          Process Termination11         File Creation12         Registry Object Activity13         Registry Value Activity22         DNS Query

These events are grouped into behavioral windows and transformed intomachine-learning features.

Machine Learning Features

The current Windows behavioral dataset contains 23 model features.

Event Counts

event_1_count
event_3_count
event_5_count
event_11_count
event_12_count
event_13_count
event_22_count
total_events

Event Ratios

event_1_ratio
event_3_ratio
event_5_ratio
event_11_ratio
event_12_ratio
event_13_ratio
event_22_ratio

Behavioral Activity

process_activity
network_activity
file_activity
registry_activity

Behavioral Ratios

process_ratio
network_ratio
file_ratio
registry_ratio

Model

The current implementation uses a Random Forest classifier trainedon Windows behavioral features derived from the SILRAD dataset.

A recorded training run produced:

Metric                Result

Accuracy              92.46%Balanced Accuracy     91.11%Malware Precision     59.00%Malware Recall        89.39%Malware F1 Score      71.08%

Confusion matrix from that run:

[[530  41]
 [  7  59]]

These metrics describe the recorded experimental run and should not beinterpreted as a guarantee of detection performance on arbitraryreal-world malware.

Risk Engine

MALGUARD separates model probability from the final threatassessment.

For example, a behavioral window may have an elevated maliciousprobability while containing only one category of behavior. Instead ofautomatically declaring malware, the risk engine can retain the resultas suspicious while waiting for additional behavioral evidence.

Typical states include:

BENIGN
ELEVATED
SUSPICIOUS
CONFIRMED THREAT

The system also tracks behavioral diversity across categories such asprocess, network, file, registry, and DNS activity.

Dashboard

The React frontend contains four main areas.

Dashboard

Provides an overview of:

events analyzed

prediction count

confirmed alerts

detector status

current threat probability

current risk assessment

behavioral activity

threat probability history

Live Events

Displays recent Sysmon telemetry with:

Event ID

event category

event type

timestamp

record ID

search

event filtering

pause/resume feed

Threats

Displays elevated and suspicious detections and separates suspiciousmodel predictions from confirmed threats.

A detection can be opened to inspect:

malicious probability

risk level

model risk

behavioral diversity

confirmed-threat state

reason for classification

process activity

network activity

file activity

registry activity

DNS activity

total events

Detection History

Shows historical behavioral predictions including:

timestamp

status

risk

benign probability

malicious probability

behavioral diversity

activity counts

classification reason

Technology Stack

Backend

Python

FastAPI

Uvicorn

scikit-learn

pandas

NumPy

PyWin32 / Windows Event Log access

Machine Learning

Random Forest

behavioral feature engineering

SILRAD-derived Windows dataset

Telemetry

Microsoft Sysmon

Windows Event Log

Frontend

React

Vite

JavaScript

CSS

React Router

Lucide React

Recharts

Project Structure

A typical project structure is:

malware-spyware-detection/
|
|-- backend/
|   |-- app/
|   |-- detector/
|       |-- detector_state.py
|       |-- feature_extractor.py
|       |-- predictor.py
|       |-- risk_engine.py
|
|-- collectors/
|   |-- sysmon_collector.py
|
|-- dataset/
|   |-- processed/
|   |-- raw/
|   |-- windows/
|       |-- processed/
|       |-- raw/
|           |-- live_sysmon_events.jsonl
|
|-- frontend/
|   |-- public/
|   |-- src/
|       |-- components/
|       |-- pages/
|       |-- App.jsx
|       |-- App.css
|       |-- index.css
|       |-- main.jsx
|
|-- ml/
|   |-- evaluation/
|   |-- models/
|   |-- notebooks/
|   |-- preprocessing/
|   |-- training/
|
|-- results/
|   |-- windows/
|
|-- saved_models/
|   |-- windows/
|       |-- windows_random_forest.pkl
|       |-- windows_feature_names.json
|
|-- tests/
|   |-- simulate_suspicious_activity.ps1
|
|-- venv/
|
|-- sysmonconfig.xml
|-- requirements.txt
|-- START_MALGUARD.bat
|-- README.md

The exact folders may vary as development continues.

Prerequisites

Before running MALGUARD, install:

Windows 10/11

Python

Node.js and npm

Microsoft Sysmon

Required Python packages

Frontend npm dependencies

Because MALGUARD reads the Sysmon Operational event channel, the backendmay require an Administrator terminal.

Python Environment

From the project root:

python -m venv venv

Activate it:

.\venv\Scripts\Activate.ps1

Install dependencies:

pip install -r requirements.txt

Frontend Installation

Open the frontend directory:

cd frontend

Install packages:

npm install

Return to the project root when required:

cd ..

Sysmon Setup

Confirm Sysmon is installed:

where.exe Sysmon64.exe

Apply the MALGUARD Sysmon configuration from an Administrator terminal:

C:\Windows\System32\Sysmon64.exe -c ".\sysmonconfig.xml"

If Sysmon is installed elsewhere, use the path returned by where.exe.

Check the active configuration:

C:\Windows\System32\Sysmon64.exe -c

MALGUARD expects the Sysmon Operational channel:

Microsoft-Windows-Sysmon/Operational

Starting the Backend

Open an Administrator PowerShell/terminal at the project root.

Activate the virtual environment:

.\venv\Scripts\Activate.ps1

Start FastAPI:

python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

Backend address:

http://127.0.0.1:8000

Swagger documentation:

http://127.0.0.1:8000/docs

Starting the Frontend

Open another terminal:

cd frontend
npm run dev

The dashboard normally runs at:

http://localhost:5173

Keep both backend and frontend terminals running.

One-Click Launcher

The project can include:

START_MALGUARD.bat

Run the launcher as Administrator so that the backend can accessSysmon telemetry.

The launcher can start:

FastAPI backend

React/Vite frontend

MALGUARD dashboard in the browser

If the launcher does not start the frontend, verify manually:

cd frontend
npm run dev

API

The FastAPI backend exposes endpoints used by the frontend.

Examples currently used by the dashboard include:

GET /api/status
GET /api/events
GET /api/history

Example:

GET /api/history?limit=5

A history record can contain:

{
  "timestamp": "2026-08-02T17:51:28.109245",
  "raw_prediction": 1,
  "benign_probability": 0.32726908574758146,
  "malicious_probability": 0.6727309142524185,
  "model_risk": "SUSPICIOUS",
  "status": "SUSPICIOUS",
  "risk_level": "SUSPICIOUS",
  "confirmed_threat": false,
  "behavior_diversity": 1,
  "registry_only": true,
  "reason": "Elevated malicious probability detected. Monitoring for additional evidence."
}

Notice that status: SUSPICIOUS does not automatically implyconfirmed_threat: true.

Safe Testing

Do not run real malware on your development or demonstration laptop.

MALGUARD can be tested by generating harmless Windows activity thatproduces the types of telemetry monitored by the system.

The project can use:

tests/simulate_suspicious_activity.ps1

The simulator can safely generate combinations of:

process activity

file activity

registry activity

DNS activity

network activity

Run it only as a controlled telemetry test.

Example:

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\tests\simulate_suspicious_activity.ps1

Then observe:

Live Events
    ↓
Detection History
    ↓
Threats

A simulator run is not guaranteed to produce a confirmed threat. TheML model and risk engine determine the result from the generatedbehavioral window.

Dataset

The Windows model was built using the SILRAD dataset after convertingcompatible telemetry into MALGUARD behavioral windows.

A recorded preprocessing run contained:

Events loaded:       196,840
Compatible events:   159,258
Behavior samples:      3,185

Class 0 / Benign:       2,855
Class 1 / Malicious:      330

The processed feature dataset is stored under the Windows datasetdirectory.

Why MALGUARD Is Different

Many malware-detection projects focus on:

Android malware

static permissions

API-call sequences

network traffic alone

PE-file classification

offline datasets

computationally heavier deep-learning architectures

MALGUARD's current implementation focuses on real-time Windowsendpoint behavioral monitoring.

Its main distinguishing characteristics are:

live Windows Sysmon telemetry

multi-category behavioral monitoring

behavioral-window feature extraction

Random Forest probability estimation

contextual risk assessment

behavioral diversity

multiple threat states

real-time FastAPI integration

interactive React dashboard

complete collection-to-visualization pipeline

Project Scope

MALGUARD is an academic/research prototype for demonstratingbehavior-based malware and spyware detection.

It should not be treated as a replacement for a production EndpointDetection and Response (EDR) product, antivirus platform, or enterprisesecurity control.

The current model is limited by its training data, selected Sysmonevents, feature representation, and experimental evaluation environment.

Current Methodology Note

The original project synopsis proposed sequence-learning andattention-based techniques such as LSTM/GRU and attention mechanisms.

The implemented MALGUARD prototype has evolved into:

Windows Sysmon
      ↓
Behavioral Feature Engineering
      ↓
Random Forest
      ↓
Risk Engine
      ↓
FastAPI
      ↓
React Dashboard

Final project documentation should describe the implemented architectureaccurately unless a sequence-learning component is subsequently added.

Future Enhancements

Potential improvements include:

sequence-learning models for temporal behavior

LSTM/GRU/Transformer experiments

richer Sysmon event coverage

process-tree analysis

executable metadata analysis

persistence-behavior detection

improved false-positive reduction

explainable threat scoring

alert export and reporting

configurable detection rules

longer-term event storage

model comparison and cross-validation

isolated malware-lab validation

packaging MALGUARD as a Windows application

Disclaimer

MALGUARD is intended for educational, academic, research, and authorizedsecurity-testing purposes.

Do not intentionally execute real malware, visit maliciousinfrastructure, or perform unsafe testing on personal, production,college, or demonstration systems.

Use isolated virtual machines and controlled laboratory environments forany future validation involving real malicious samples.