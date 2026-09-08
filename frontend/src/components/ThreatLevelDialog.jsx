import { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Info,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";

const THREAT_LEVELS = [
  {
    level: "CONFIRMED",
    cardClass: "tlc-confirmed",
    title: "Confirmed Threat",
    badgeClass: "badge-high",
    badgeLabel: "CONFIRMED / MALICIOUS",
    probability: "Sustained High Risk (≥ 75% + Multi-window)",
    icon: ShieldAlert,
    description:
      "Active malware or spyware threat confirmed by the risk correlation engine.",
    details:
      "Triggered when high-risk malicious probability (≥ 75%) persists across 3 consecutive 50-event evaluation windows with behavioral diversity (≥ 2 event types across process, network, file, or registry).",
    action:
      "Immediate action required: Isolate host, terminate malicious process IDs, and perform full incident response.",
  },
  {
    level: "HIGH_RISK",
    cardClass: "tlc-high",
    title: "High Risk",
    badgeClass: "badge-high",
    badgeLabel: "HIGH RISK",
    probability: "Malicious Probability ≥ 75%",
    icon: AlertTriangle,
    description:
      "Severe anomalous behavior pattern identified by the Random Forest model.",
    details:
      "High ML model confidence based on combined telemetry features (process creation, suspicious network connection, file modifications, or registry changes).",
    action:
      "High priority investigation: Examine process tree, network endpoints, and system event history.",
  },
  {
    level: "SUSPICIOUS",
    cardClass: "tlc-suspicious",
    title: "Suspicious",
    badgeClass: "badge-suspicious",
    badgeLabel: "SUSPICIOUS",
    probability: "Malicious Probability 50% – 74%",
    icon: AlertTriangle,
    description:
      "Elevated threat indicators deviating from expected normal system baseline.",
    details:
      "The classifier detects potential malware behavior, but multi-window confirmation or vector diversity threshold is not yet fulfilled.",
    action:
      "Moderate priority: Continuously monitor upcoming behavioral windows for threat escalation.",
  },
  {
    level: "ELEVATED",
    cardClass: "tlc-elevated",
    title: "Elevated",
    badgeClass: "badge-elevated",
    badgeLabel: "ELEVATED",
    probability: "Probability 30% – 49% or Vector Spikes",
    icon: Info,
    description:
      "Minor behavioral anomalies or isolated single-vector activity bursts.",
    details:
      "Assigned when malicious probability is slightly elevated or when single-category activity (such as a registry write burst) occurs without supporting process/network indicators.",
    action:
      "Low priority: Logged for baseline anomaly analysis. No immediate intervention needed unless elevated sustained.",
  },
  {
    level: "LOW",
    cardClass: "tlc-low",
    title: "Low Risk / Benign",
    badgeClass: "badge-low",
    badgeLabel: "LOW / BENIGN",
    probability: "Malicious Probability < 30%",
    icon: CheckCircle2,
    description:
      "Normal system operations aligned with standard Windows baseline behavior.",
    details:
      "Standard operating system background processes, routine file I/O, benign network traffic, and trusted application executions.",
    action:
      "Safe: Continuous automated background monitoring remains active.",
  },
];

export default function ThreatLevelDialog({
  isOpen: externalIsOpen,
  onClose: externalOnClose,
  showTriggerButton = true,
  triggerText = "Threat Level Guide",
}) {
  const [internalIsOpen, setInternalIsOpen] = useState(false);

  const isControlled = externalIsOpen !== undefined;
  const isOpen = isControlled ? externalIsOpen : internalIsOpen;

  const handleOpen = () => {
    if (!isControlled) setInternalIsOpen(true);
  };

  const handleClose = () => {
    if (isControlled && externalOnClose) {
      externalOnClose();
    } else {
      setInternalIsOpen(false);
    }
  };

  return (
    <>
      {showTriggerButton && !isControlled && (
        <button
          type="button"
          className="threat-level-guide-btn"
          onClick={handleOpen}
          title="View threat level explanations"
        >
          <HelpCircle size={16} />
          <span>{triggerText}</span>
        </button>
      )}

      {isOpen && (
        <div
          className="threat-modal-backdrop"
          onClick={handleClose}
          role="dialog"
          aria-modal="true"
          aria-labelledby="threat-dialog-title"
        >
          <div
            className="threat-modal threat-levels-dialog"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="threat-modal-header">
              <div>
                <span>MALGUARD CLASSIFICATION SYSTEM</span>
                <h2 id="threat-dialog-title">Threat Level Explanations</h2>
              </div>
              <button
                type="button"
                onClick={handleClose}
                aria-label="Close dialog"
              >
                <X size={19} />
              </button>
            </div>

            {/* Intro */}
            <div className="threat-dialog-intro">
              <ShieldCheck size={20} className="intro-icon" />
              <div>
                <strong>How Threat Scoring Works</strong>
                <p>
                  MALGUARD analyzes Windows Sysmon telemetry in 50-event windows
                  using a Random Forest model combined with a rule-based Risk
                  Engine. Risk levels are calculated based on malicious
                  probability, behavioral diversity across 4 activity vectors
                  (Process, Network, File, Registry), and multi-window
                  correlation.
                </p>
              </div>
            </div>

            {/* Level cards */}
            <div className="threat-levels-list">
              {THREAT_LEVELS.map((item) => {
                const Icon = item.icon;
                return (
                  <div
                    key={item.level}
                    className={`threat-level-card ${item.cardClass}`}
                  >
                    <div className="threat-level-card-header">
                      <div className="threat-level-title-wrap">
                        <Icon size={18} className="tlc-icon" />
                        <h3>{item.title}</h3>
                      </div>
                      <span className={`risk-table-badge ${item.badgeClass}`}>
                        {item.badgeLabel}
                      </span>
                    </div>

                    <div className="threat-level-criteria">
                      <strong>Threshold:</strong> {item.probability}
                    </div>

                    <p className="threat-level-desc">{item.description}</p>
                    {item.details && (
                      <p className="threat-level-details">{item.details}</p>
                    )}

                    <div className="threat-level-action">
                      <span>RECOMMENDED ACTION</span>
                      <p>{item.action}</p>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Footer */}
            <div className="threat-dialog-footer">
              <button
                type="button"
                className="threat-dialog-close-btn"
                onClick={handleClose}
              >
                Close Guide
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
