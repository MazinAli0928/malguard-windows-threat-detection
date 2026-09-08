import { useEffect, useMemo, useState } from "react";

import ThreatLevelDialog from "../components/ThreatLevelDialog";

import {
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";

const API = "http://127.0.0.1:8000";

function Threats() {
  const [history, setHistory] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);

  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("ALL");

  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState(false);

  const fetchThreats = async () => {
    try {
      const response = await fetch(
        `${API}/api/history?limit=500`
      );

      if (!response.ok) {
        throw new Error("Unable to retrieve threat history");
      }

      const data = await response.json();

      setHistory(data.history || []);
      setApiError(false);
    } catch (error) {
      console.error("Threat fetch error:", error);
      setApiError(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();

    const interval = setInterval(fetchThreats, 3000);

    return () => clearInterval(interval);
  }, []);

  /*
   * Threat page intentionally excludes LOW benign activity.
   *
   * ELEVATED = unusual behavior
   * SUSPICIOUS = model detected suspicious behavior
   * HIGH_RISK = severe detection
   * confirmed_threat = confirmed by risk engine
   */
  const threats = useMemo(() => {
    return history
      .filter((item) => {
        return (
          item.risk_level === "ELEVATED" ||
          item.risk_level === "SUSPICIOUS" ||
          item.risk_level === "HIGH_RISK" ||
          item.confirmed_threat === true
        );
      })
      .filter((item) => {
        if (
          filter !== "ALL" &&
          item.risk_level !== filter
        ) {
          return false;
        }

        if (!search.trim()) {
          return true;
        }

        const query = search.toLowerCase();

        return (
          String(item.status || "")
            .toLowerCase()
            .includes(query) ||
          String(item.risk_level || "")
            .toLowerCase()
            .includes(query) ||
          String(item.reason || "")
            .toLowerCase()
            .includes(query)
        );
      })
      .reverse();
  }, [history, filter, search]);

  const confirmedCount = history.filter(
    (item) => item.confirmed_threat === true
  ).length;

  const suspiciousCount = history.filter(
    (item) => item.risk_level === "SUSPICIOUS"
  ).length;

  const elevatedCount = history.filter(
    (item) => item.risk_level === "ELEVATED"
  ).length;

  const highRiskCount = history.filter(
    (item) => item.risk_level === "HIGH_RISK"
  ).length;

  return (
    <main className="main">
      <header className="header">
        <div>
          <h2>Threat Intelligence</h2>

          <p>
            Investigate suspicious behavioral
            detections identified by MALGUARD
          </p>
        </div>

        <div className="header-actions">
          <ThreatLevelDialog />

          <button
            className="refresh-button"
            onClick={fetchThreats}
            title="Refresh threats"
          >
            <RefreshCw size={17} />
          </button>
        </div>
      </header>

      {apiError && (
        <div className="api-error">
          <AlertTriangle size={19} />

          Unable to retrieve threat intelligence
          from the MALGUARD API.
        </div>
      )}

      <section className="threat-summary-grid">
        <ThreatSummary
          title="Confirmed Threats"
          value={confirmedCount}
          type="confirmed"
        />

        <ThreatSummary
          title="High Risk"
          value={highRiskCount}
          type="high"
        />

        <ThreatSummary
          title="Suspicious"
          value={suspiciousCount}
          type="suspicious"
        />

        <ThreatSummary
          title="Elevated"
          value={elevatedCount}
          type="elevated"
        />
      </section>

      <section className="panel">
        <div className="live-events-toolbar">
          <div>
            <h3>Detection Queue</h3>

            <p>
              Elevated and suspicious behavioral
              windows requiring investigation
            </p>
          </div>

          <div className="feed-status">
            <span className="feed-dot" />
            LIVE
          </div>
        </div>

        <div className="event-filters">
          <div className="event-search">
            <Search size={15} />

            <input
              value={search}
              onChange={(e) =>
                setSearch(e.target.value)
              }
              placeholder="Search detections..."
            />
          </div>

          <select
            value={filter}
            onChange={(e) =>
              setFilter(e.target.value)
            }
          >
            <option value="ALL">
              All Threat Levels
            </option>

            <option value="ELEVATED">
              Elevated
            </option>

            <option value="SUSPICIOUS">
              Suspicious
            </option>

            <option value="HIGH_RISK">
              High Risk
            </option>
          </select>
        </div>

        <div className="event-table-wrapper live-table">
          <table>
            <thead>
              <tr>
                <th>TIME</th>
                <th>STATUS</th>
                <th>RISK</th>
                <th>THREAT PROBABILITY</th>
                <th>DIVERSITY</th>
                <th>CONFIRMED</th>
                <th>REASON</th>
              </tr>
            </thead>

            <tbody>
              {threats.map((threat, index) => (
                <tr
                  key={`${threat.timestamp}-${index}`}
                  className="clickable-row"
                  onClick={() =>
                    setSelectedThreat(threat)
                  }
                >
                  <td>
                    {formatDate(threat.timestamp)}
                  </td>

                  <td>
                    <span
                      className={`risk-table-badge ${getRiskBadgeClass(
                        threat.status
                      )}`}
                    >
                      {threat.status}
                    </span>
                  </td>

                  <td>
                    <span
                      className={`risk-table-badge ${getRiskBadgeClass(
                        threat.risk_level
                      )}`}
                    >
                      {threat.risk_level}
                    </span>
                  </td>

                  <td>
                    <ProbabilityBar
                      value={
                        threat.malicious_probability *
                        100
                      }
                    />
                  </td>

                  <td>
                    {threat.behavior_diversity}/5
                  </td>

                  <td>
                    {threat.confirmed_threat ? (
                      <span className="confirmed-yes">
                        <CheckCircle2 size={14} />
                        YES
                      </span>
                    ) : (
                      <span className="confirmed-no">
                        NO
                      </span>
                    )}
                  </td>

                  <td className="reason-cell">
                    {threat.reason}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {!loading && threats.length === 0 && (
            <div className="empty-events">
              No elevated or suspicious detections
              found.
            </div>
          )}

          {loading && (
            <div className="empty-events">
              Loading threat intelligence...
            </div>
          )}
        </div>

        <div className="event-footer">
          <span>
            {threats.length} detections displayed
          </span>

          <span>
            Click a detection to investigate
          </span>
        </div>
      </section>

      {selectedThreat && (
        <ThreatModal
          threat={selectedThreat}
          onClose={() =>
            setSelectedThreat(null)
          }
        />
      )}
    </main>
  );
}

function ThreatSummary({
  title,
  value,
  type,
}) {
  return (
    <div className={`threat-summary-card ${type}`}>
      <div>
        <span>{title}</span>
        <strong>{value}</strong>
      </div>

      <ShieldAlert size={22} />
    </div>
  );
}

function ProbabilityBar({ value }) {
  const probability = Math.min(
    Math.max(value, 0),
    100
  );

  return (
    <div className="probability-cell">
      <strong>
        {probability.toFixed(1)}%
      </strong>

      <div className="probability-track">
        <div
          className="probability-fill"
          style={{
            width: `${probability}%`,
          }}
        />
      </div>
    </div>
  );
}

function ThreatModal({ threat, onClose }) {
  const features = threat.features || {};

  return (
    <div
      className="threat-modal-backdrop"
      onClick={onClose}
    >
      <div
        className="threat-modal"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="threat-modal-header">
          <div>
            <span>THREAT INVESTIGATION</span>

            <h2>
              {threat.status}
            </h2>
          </div>

          <button onClick={onClose}>
            <X size={19} />
          </button>
        </div>

        <div className="threat-modal-probability">
          <span>Malicious Probability</span>

          <strong>
            {(
              threat.malicious_probability * 100
            ).toFixed(2)}
            %
          </strong>
        </div>

        <div className="investigation-grid">
          <InfoBox
            label="Risk Level"
            value={threat.risk_level}
          />

          <InfoBox
            label="Model Risk"
            value={threat.model_risk}
          />

          <InfoBox
            label="Behavior Diversity"
            value={`${threat.behavior_diversity}/5`}
          />

          <InfoBox
            label="Confirmed Threat"
            value={
              threat.confirmed_threat
                ? "YES"
                : "NO"
            }
          />
        </div>

        <div className="investigation-reason">
          <span>ANALYSIS</span>
          <p>{threat.reason}</p>
        </div>

        <h3 className="feature-title">
          Behavioral Features
        </h3>

        <div className="modal-feature-grid">
          <FeatureBox
            label="Process"
            value={
              features.process_activity || 0
            }
          />

          <FeatureBox
            label="Network"
            value={
              features.network_activity || 0
            }
          />

          <FeatureBox
            label="File"
            value={
              features.file_activity || 0
            }
          />

          <FeatureBox
            label="Registry"
            value={
              features.registry_activity || 0
            }
          />

          <FeatureBox
            label="DNS"
            value={
              features.event_22_count || 0
            }
          />

          <FeatureBox
            label="Total Events"
            value={
              features.total_events || 0
            }
          />
        </div>

        <div className="modal-time">
          Detection time:{" "}
          {formatFullDate(threat.timestamp)}
        </div>
      </div>
    </div>
  );
}

function InfoBox({ label, value }) {
  return (
    <div className="investigation-info">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function FeatureBox({ label, value }) {
  return (
    <div className="modal-feature">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function getRiskBadgeClass(value) {
  switch (value) {
    case "HIGH_RISK":
      return "badge-high";

    case "SUSPICIOUS":
      return "badge-suspicious";

    case "ELEVATED":
      return "badge-elevated";

    case "BENIGN":
    case "LOW":
      return "badge-low";

    default:
      return "";
  }
}

function formatDate(timestamp) {
  if (!timestamp) return "--";

  return new Date(timestamp).toLocaleTimeString();
}

function formatFullDate(timestamp) {
  if (!timestamp) return "--";

  return new Date(timestamp).toLocaleString();
}

export default Threats;