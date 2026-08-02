import { useEffect, useMemo, useState } from "react";

import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Database,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldAlert,
} from "lucide-react";

const API = "http://127.0.0.1:8000";

function DetectionHistory() {
  const [history, setHistory] = useState([]);

  const [filter, setFilter] = useState("ALL");
  const [search, setSearch] = useState("");

  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState(false);

  const fetchHistory = async () => {
    try {
      const response = await fetch(
        `${API}/api/history?limit=500`
      );

      if (!response.ok) {
        throw new Error(
          "Unable to retrieve detection history"
        );
      }

      const data = await response.json();

      setHistory(data.history || []);
      setApiError(false);
    } catch (error) {
      console.error(
        "History fetch error:",
        error
      );

      setApiError(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();

    const interval = setInterval(
      fetchHistory,
      3000
    );

    return () => clearInterval(interval);
  }, []);

  const filteredHistory = useMemo(() => {
    return history
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

  const benign = history.filter(
    (item) => item.status === "BENIGN"
  ).length;

  const suspicious = history.filter(
    (item) => item.status === "SUSPICIOUS"
  ).length;

  const confirmed = history.filter(
    (item) => item.confirmed_threat
  ).length;

  return (
    <main className="main">
      <header className="header">
        <div>
          <h2>Detection History</h2>

          <p>
            Historical Random Forest behavioral
            predictions
          </p>
        </div>

        <div className="header-actions">
          <button
            className="refresh-button"
            onClick={fetchHistory}
          >
            <RefreshCw size={17} />
          </button>
        </div>
      </header>

      {apiError && (
        <div className="api-error">
          <AlertTriangle size={19} />

          Unable to retrieve detection history.
        </div>
      )}

      <section className="history-summary-grid">
        <HistorySummary
          icon={<Database />}
          title="Total Predictions"
          value={history.length}
        />

        <HistorySummary
          icon={<ShieldCheck />}
          title="Benign"
          value={benign}
        />

        <HistorySummary
          icon={<ShieldAlert />}
          title="Suspicious"
          value={suspicious}
        />

        <HistorySummary
          icon={<CheckCircle2 />}
          title="Confirmed"
          value={confirmed}
        />
      </section>

      <section className="panel">
        <div className="live-events-toolbar">
          <div>
            <h3>Prediction Timeline</h3>

            <p>
              Behavioral windows analyzed by the
              detection engine
            </p>
          </div>

          <div className="history-count">
            <Clock size={13} />
            {history.length} records
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
              placeholder="Search detection history..."
            />
          </div>

          <select
            value={filter}
            onChange={(e) =>
              setFilter(e.target.value)
            }
          >
            <option value="ALL">
              All Risk Levels
            </option>

            <option value="LOW">
              Low
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
                <th>BENIGN</th>
                <th>MALICIOUS</th>
                <th>DIVERSITY</th>
                <th>ACTIVITY</th>
                <th>REASON</th>
              </tr>
            </thead>

            <tbody>
              {filteredHistory.map(
                (item, index) => (
                  <tr
                    key={`${item.timestamp}-${index}`}
                  >
                    <td>
                      {formatTime(
                        item.timestamp
                      )}
                    </td>

                    <td>
                      <span
                        className={`risk-table-badge ${getRiskBadgeClass(
                          item.status
                        )}`}
                      >
                        {item.status}
                      </span>
                    </td>

                    <td>
                      <span
                        className={`risk-table-badge ${getRiskBadgeClass(
                          item.risk_level
                        )}`}
                      >
                        {item.risk_level}
                      </span>
                    </td>

                    <td className="probability-benign">
                      {(
                        item.benign_probability *
                        100
                      ).toFixed(1)}
                      %
                    </td>

                    <td className="probability-malicious">
                      {(
                        item.malicious_probability *
                        100
                      ).toFixed(1)}
                      %
                    </td>

                    <td>
                      {item.behavior_diversity}/5
                    </td>

                    <td>
                      <ActivitySummary
                        features={
                          item.features || {}
                        }
                      />
                    </td>

                    <td className="reason-cell">
                      {item.reason}
                    </td>
                  </tr>
                )
              )}
            </tbody>
          </table>

          {loading && (
            <div className="empty-events">
              Loading detection history...
            </div>
          )}

          {!loading &&
            filteredHistory.length === 0 && (
              <div className="empty-events">
                No detection records match the
                current filter.
              </div>
            )}
        </div>

        <div className="event-footer">
          <span>
            Showing {filteredHistory.length} of{" "}
            {history.length} predictions
          </span>

          <span>
            Auto refresh: 3 seconds
          </span>
        </div>
      </section>
    </main>
  );
}

function HistorySummary({
  icon,
  title,
  value,
}) {
  return (
    <div className="event-summary-card">
      <div className="event-summary-icon">
        {icon}
      </div>

      <div>
        <span>{title}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function ActivitySummary({ features }) {
  return (
    <div className="activity-summary">
      <span>
        P:{features.process_activity || 0}
      </span>

      <span>
        N:{features.network_activity || 0}
      </span>

      <span>
        F:{features.file_activity || 0}
      </span>

      <span>
        R:{features.registry_activity || 0}
      </span>
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

function formatTime(timestamp) {
  if (!timestamp) return "--";

  return new Date(timestamp).toLocaleString();
}

export default DetectionHistory;