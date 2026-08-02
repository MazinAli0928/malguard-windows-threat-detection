import { useEffect, useState } from "react";
import "../App.css";
import {
  Activity,
  AlertTriangle,
  Database,
  FileText,
  Globe,
  Network,
  Play,
  Power,
  RefreshCw,
  Shield,
  ShieldAlert,
  Square,
  Terminal,
} from "lucide-react";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import "../App.css";


// ============================================================
// CONFIGURATION
// ============================================================

const API = "http://127.0.0.1:8000";

const EVENT_NAMES = {
  1: "Process Create",
  3: "Network Connection",
  5: "Process Terminate",
  11: "File Create",
  12: "Registry Event",
  13: "Registry Value Set",
  22: "DNS Query",
};


// ============================================================
// MAIN APPLICATION
// ============================================================

function Dashboard() {
  const [status, setStatus] = useState(null);
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [history, setHistory] = useState([]);

  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [apiError, setApiError] = useState(false);


  // ==========================================================
  // FETCH DASHBOARD DATA
  // ==========================================================

  const fetchData = async () => {
    try {
      const [
        statusResponse,
        statsResponse,
        eventsResponse,
        historyResponse,
      ] = await Promise.all([
        fetch(`${API}/api/status`),
        fetch(`${API}/api/stats`),
        fetch(`${API}/api/events?limit=30`),
        fetch(`${API}/api/history?limit=40`),
      ]);

      if (
        !statusResponse.ok ||
        !statsResponse.ok ||
        !eventsResponse.ok ||
        !historyResponse.ok
      ) {
        throw new Error("API request failed");
      }

      const statusData = await statusResponse.json();
      const statsData = await statsResponse.json();
      const eventsData = await eventsResponse.json();
      const historyData = await historyResponse.json();

      setStatus(statusData);
      setStats(statsData);
      setEvents(eventsData.events || []);
      setHistory(historyData.history || []);

      setApiError(false);
    } catch (error) {
      console.error(
        "MALGUARD API connection error:",
        error
      );

      setApiError(true);
    } finally {
      setLoading(false);
    }
  };


  // ==========================================================
  // AUTO REFRESH
  // ==========================================================

  useEffect(() => {
    fetchData();

    const interval = setInterval(() => {
      fetchData();
    }, 2000);

    return () => {
      clearInterval(interval);
    };
  }, []);


  // ==========================================================
  // START DETECTOR
  // ==========================================================

  const startDetector = async () => {
    try {
      setActionLoading(true);

      const response = await fetch(
        `${API}/api/start`,
        {
          method: "POST",
        }
      );

      if (!response.ok) {
        throw new Error(
          "Unable to start detector"
        );
      }

      await fetchData();
    } catch (error) {
      console.error(error);
      setApiError(true);
    } finally {
      setActionLoading(false);
    }
  };


  // ==========================================================
  // STOP DETECTOR
  // ==========================================================

  const stopDetector = async () => {
    try {
      setActionLoading(true);

      const response = await fetch(
        `${API}/api/stop`,
        {
          method: "POST",
        }
      );

      if (!response.ok) {
        throw new Error(
          "Unable to stop detector"
        );
      }

      await fetchData();
    } catch (error) {
      console.error(error);
      setApiError(true);
    } finally {
      setActionLoading(false);
    }
  };


  // ==========================================================
  // CURRENT PREDICTION
  // ==========================================================

  const prediction =
    status?.latest_prediction || null;

  const maliciousProbability =
    prediction?.malicious_probability != null
      ? prediction.malicious_probability * 100
      : 0;

  const riskLevel =
    prediction?.risk_level || "WAITING";

  const finalStatus =
    prediction?.status || "NO DATA";

  const features =
    prediction?.features || {};


  // ==========================================================
  // CHART DATA
  // ==========================================================

  const chartData = history.map(
    (item, index) => ({
      index: index + 1,

      probability: Number(
        (
          (item.malicious_probability || 0) *
          100
        ).toFixed(2)
      ),
    })
  );


  // ==========================================================
  // RISK CSS CLASS
  // ==========================================================

  const getRiskClass = (risk) => {
    switch (risk) {
      case "LOW":
        return "risk-low";

      case "ELEVATED":
        return "risk-elevated";

      case "SUSPICIOUS":
        return "risk-suspicious";

      case "HIGH_RISK":
        return "risk-high";

      default:
        return "risk-waiting";
    }
  };


  // ==========================================================
  // LOADING SCREEN
  // ==========================================================

  if (loading) {
    return (
      <div className="loading-screen">
        <Shield size={50} />

        <h2>
          MALGUARD
        </h2>

        <p>
          Connecting to detection engine...
        </p>
      </div>
    );
  }


  // ==========================================================
  // UI
  // ==========================================================

  return (
    <div className="app">

      {/* =====================================================
          SIDEBAR
      ===================================================== */}

      

      {/* =====================================================
          MAIN DASHBOARD
      ===================================================== */}

      <main className="main">

        {/* ===================================================
            HEADER
        =================================================== */}

        <header className="header">

          <div>

            <h2>
              Security Operations
            </h2>

            <p>
              Real-time Windows behavioral
              threat monitoring
            </p>

          </div>


          <div className="header-actions">

            <button
              className="refresh-button"
              onClick={fetchData}
              title="Refresh dashboard"
            >
              <RefreshCw size={17} />
            </button>


            {status?.running ? (

              <button
                className="stop-button"
                onClick={stopDetector}
                disabled={actionLoading}
              >
                <Square size={16} />

                {actionLoading
                  ? "Stopping..."
                  : "Stop Monitoring"}

              </button>

            ) : (

              <button
                className="start-button"
                onClick={startDetector}
                disabled={actionLoading}
              >
                <Play size={16} />

                {actionLoading
                  ? "Starting..."
                  : "Start Monitoring"}

              </button>

            )}

          </div>

        </header>


        {/* ===================================================
            API ERROR
        =================================================== */}

        {apiError && (

          <div className="api-error">

            <AlertTriangle size={20} />

            <span>
              Cannot connect to MALGUARD API.
              Make sure FastAPI is running on
              port 8000.
            </span>

          </div>

        )}


        {/* ===================================================
            METRICS
        =================================================== */}

        <section className="metric-grid">

          <MetricCard
            icon={<Terminal />}
            title="Events Analyzed"
            value={
              status?.total_events || 0
            }
            subtitle="Current session"
          />


          <MetricCard
            icon={<Activity />}
            title="Predictions"
            value={
              status?.total_predictions || 0
            }
            subtitle="Behavior windows"
          />


          <MetricCard
            icon={<ShieldAlert />}
            title="Confirmed Alerts"
            value={
              status?.total_alerts || 0
            }
            subtitle="Threat confirmations"
          />


          <MetricCard
            icon={<Power />}
            title="Engine"
            value={
              status?.running
                ? "LIVE"
                : "OFFLINE"
            }
            subtitle={
              status?.running
                ? "Monitoring Sysmon"
                : "Monitoring stopped"
            }
          />

        </section>


        {/* ===================================================
            THREAT + BEHAVIOR ROW
        =================================================== */}

        <section className="dashboard-row">

          {/* =================================================
              CURRENT THREAT
          ================================================= */}

          <div className="panel threat-panel">

            <div className="panel-header">

              <div>

                <h3>
                  Current Threat Assessment
                </h3>

                <p>
                  Latest behavioral analysis
                </p>

              </div>

              <Shield size={22} />

            </div>


            {/* ===============================================
                DYNAMIC THREAT GAUGE
            =============================================== */}

            <div
              className={`risk-display ${getRiskClass(
                riskLevel
              )}`}
              style={{
                "--risk-progress": `${Math.min(
                  Math.max(
                    maliciousProbability,
                    0
                  ),
                  100
                )}%`,
              }}
            >

              <div className="risk-ring">

                <div>

                  <strong>
                    {maliciousProbability.toFixed(
                      1
                    )}
                    %
                  </strong>

                  <span>
                    threat probability
                  </span>

                </div>

              </div>


              <div className="risk-details">

                <span>
                  CURRENT STATUS
                </span>

                <h2>
                  {finalStatus}
                </h2>

                <div className="risk-badge">
                  {riskLevel}
                </div>

                <p>
                  {prediction?.reason ||
                    "Waiting for enough Sysmon events to perform behavioral analysis."}
                </p>

              </div>

            </div>

          </div>


          {/* =================================================
              BEHAVIOR ACTIVITY
          ================================================= */}

          <div className="panel behavior-panel">

            <div className="panel-header">

              <div>

                <h3>
                  Behavioral Activity
                </h3>

                <p>
                  Latest 50-event window
                </p>

              </div>

            </div>


            <div className="behavior-grid">

              <BehaviorCard
                icon={<Activity />}
                label="Process"
                value={
                  features.process_activity ||
                  0
                }
              />


              <BehaviorCard
                icon={<Network />}
                label="Network"
                value={
                  features.network_activity ||
                  0
                }
              />


              <BehaviorCard
                icon={<FileText />}
                label="File"
                value={
                  features.file_activity ||
                  0
                }
              />


              <BehaviorCard
                icon={<Database />}
                label="Registry"
                value={
                  features.registry_activity ||
                  0
                }
              />


              <BehaviorCard
                icon={<Globe />}
                label="DNS"
                value={
                  features.event_22_count ||
                  0
                }
              />


              <BehaviorCard
                icon={<Shield />}
                label="Diversity"
                value={
                  `${
                    prediction?.behavior_diversity ||
                    0
                  }/5`
                }
              />

            </div>

          </div>

        </section>


        {/* ===================================================
            THREAT CHART
        =================================================== */}

        <section className="panel chart-panel">

          <div className="panel-header">

            <div>

              <h3>
                Threat Probability
              </h3>

              <p>
                Real-time behavioral risk trend
              </p>

            </div>


            <span className="live-label">

              <span />

              {status?.running
                ? "LIVE"
                : "STOPPED"}

            </span>

          </div>


          <div className="chart-container">

            {chartData.length > 0 ? (

              <ResponsiveContainer
                width="100%"
                height="100%"
              >

                <AreaChart
                  data={chartData}
                >

                  <defs>

                    <linearGradient
                      id="riskGradient"
                      x1="0"
                      y1="0"
                      x2="0"
                      y2="1"
                    >

                      <stop
                        offset="5%"
                        stopColor="#6366f1"
                        stopOpacity={0.35}
                      />

                      <stop
                        offset="95%"
                        stopColor="#6366f1"
                        stopOpacity={0}
                      />

                    </linearGradient>

                  </defs>


                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="#25283a"
                    vertical={false}
                  />


                  <XAxis
                    dataKey="index"
                    stroke="#666b80"
                    tickLine={false}
                  />


                  <YAxis
                    domain={[0, 100]}
                    stroke="#666b80"
                    tickLine={false}
                    tickFormatter={
                      (value) =>
                        `${value}%`
                    }
                  />


                  <Tooltip
                    contentStyle={{
                      background: "#171925",
                      border:
                        "1px solid #303348",
                      borderRadius: "8px",
                    }}
                    formatter={
                      (value) => [
                        `${value}%`,
                        "Threat",
                      ]
                    }
                  />


                  <Area
                    type="monotone"
                    dataKey="probability"
                    stroke="#6366f1"
                    strokeWidth={2}
                    fill="url(#riskGradient)"
                  />

                </AreaChart>

              </ResponsiveContainer>

            ) : (

              <div className="empty-chart">

                <Activity size={35} />

                <p>
                  Waiting for prediction
                  history...
                </p>

              </div>

            )}

          </div>

        </section>


        {/* ===================================================
            LIVE SYSMON EVENTS
        =================================================== */}

        <section className="panel event-panel">

          <div className="panel-header">

            <div>

              <h3>
                Live Sysmon Events
              </h3>

              <p>
                Latest compatible Windows
                telemetry
              </p>

            </div>

            <span>
              {events.length} displayed
            </span>

          </div>


          <div className="event-table-wrapper">

            <table>

              <thead>

                <tr>
                  <th>EVENT</th>
                  <th>TYPE</th>
                  <th>TIME</th>
                  <th>RECORD ID</th>
                </tr>

              </thead>


              <tbody>

                {events
                  .slice()
                  .reverse()
                  .map(
                    (event, index) => (

                      <tr
                        key={
                          event.record_id ||
                          index
                        }
                      >

                        <td>

                          <span className="event-id">
                            {event.event_id}
                          </span>

                        </td>


                        <td>

                          {EVENT_NAMES[
                            event.event_id
                          ] ||
                            event.event_type ||
                            "Unknown Event"}

                        </td>


                        <td>

                          {formatTime(
                            event.timestamp
                          )}

                        </td>


                        <td className="record-id">

                          {event.record_id ||
                            "--"}

                        </td>

                      </tr>

                    )
                  )}

              </tbody>

            </table>


            {events.length === 0 && (

              <div className="empty-events">

                {status?.running
                  ? "Waiting for Sysmon events..."
                  : "Start monitoring to receive Sysmon events."}

              </div>

            )}

          </div>

        </section>

      </main>

    </div>
  );
}


// ============================================================
// METRIC CARD
// ============================================================

function MetricCard({
  icon,
  title,
  value,
  subtitle,
}) {
  return (
    <div className="metric-card">

      <div className="metric-icon">
        {icon}
      </div>


      <div>

        <span>
          {title}
        </span>

        <strong>
          {value}
        </strong>

        <small>
          {subtitle}
        </small>

      </div>

    </div>
  );
}


// ============================================================
// BEHAVIOR CARD
// ============================================================

function BehaviorCard({
  icon,
  label,
  value,
}) {
  return (
    <div className="behavior-card">

      <div className="behavior-icon">
        {icon}
      </div>


      <div>

        <span>
          {label}
        </span>

        <strong>
          {value}
        </strong>

      </div>

    </div>
  );
}


// ============================================================
// FORMAT SYSMON TIMESTAMP
// ============================================================

function formatTime(timestamp) {
  if (!timestamp) {
    return "--";
  }

  try {
    return new Date(
      timestamp
    ).toLocaleTimeString();
  } catch {
    return timestamp;
  }
}


export default Dashboard;