import { useEffect, useMemo, useState } from "react";

import {
  Activity,
  AlertTriangle,
  FileText,
  Globe,
  Network,
  Pause,
  Play,
  RefreshCw,
  Search,
  Terminal,
} from "lucide-react";

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

const EVENT_CATEGORIES = {
  1: "PROCESS",
  3: "NETWORK",
  5: "PROCESS",
  11: "FILE",
  12: "REGISTRY",
  13: "REGISTRY",
  22: "DNS",
};

function LiveEvents() {
  const [events, setEvents] = useState([]);
  const [search, setSearch] = useState("");
  const [eventFilter, setEventFilter] = useState("ALL");

  const [paused, setPaused] = useState(false);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState(false);

  const fetchEvents = async () => {
    if (paused) return;

    try {
      const response = await fetch(
        `${API}/api/events?limit=100`
      );

      if (!response.ok) {
        throw new Error("Unable to retrieve events");
      }

      const data = await response.json();

      setEvents(data.events || []);
      setApiError(false);
    } catch (error) {
      console.error("Live event error:", error);
      setApiError(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();

    const interval = setInterval(() => {
      fetchEvents();
    }, 2000);

    return () => clearInterval(interval);
  }, [paused]);

  const filteredEvents = useMemo(() => {
    return events
      .slice()
      .reverse()
      .filter((event) => {
        if (
          eventFilter !== "ALL" &&
          String(event.event_id) !== eventFilter
        ) {
          return false;
        }

        if (!search.trim()) {
          return true;
        }

        const query = search.toLowerCase();

        const eventName =
          EVENT_NAMES[event.event_id] ||
          event.event_type ||
          "";

        return (
          String(event.event_id)
            .toLowerCase()
            .includes(query) ||
          String(event.record_id || "")
            .toLowerCase()
            .includes(query) ||
          eventName.toLowerCase().includes(query)
        );
      });
  }, [events, search, eventFilter]);

  const getEventIcon = (eventId) => {
    switch (Number(eventId)) {
      case 3:
        return <Network size={16} />;

      case 11:
        return <FileText size={16} />;

      case 22:
        return <Globe size={16} />;

      default:
        return <Activity size={16} />;
    }
  };

  return (
    <main className="main">
      <header className="header">
        <div>
          <h2>Live Events</h2>

          <p>
            Real-time Windows Sysmon telemetry
          </p>
        </div>

        <div className="header-actions">
          <button
            className="refresh-button"
            onClick={fetchEvents}
            title="Refresh events"
          >
            <RefreshCw size={17} />
          </button>

          <button
            className={
              paused
                ? "start-button"
                : "stop-button"
            }
            onClick={() => setPaused(!paused)}
          >
            {paused ? (
              <>
                <Play size={15} />
                Resume Feed
              </>
            ) : (
              <>
                <Pause size={15} />
                Pause Feed
              </>
            )}
          </button>
        </div>
      </header>

      {apiError && (
        <div className="api-error">
          <AlertTriangle size={19} />

          Unable to retrieve Sysmon events from
          MALGUARD API.
        </div>
      )}

      <section className="event-summary-grid">
        <SummaryCard
          title="Events Loaded"
          value={events.length}
          icon={<Terminal />}
        />

        <SummaryCard
          title="Process"
          value={countCategory(events, "PROCESS")}
          icon={<Activity />}
        />

        <SummaryCard
          title="Network"
          value={countCategory(events, "NETWORK")}
          icon={<Network />}
        />

        <SummaryCard
          title="File"
          value={countCategory(events, "FILE")}
          icon={<FileText />}
        />

        <SummaryCard
          title="DNS"
          value={countCategory(events, "DNS")}
          icon={<Globe />}
        />
      </section>

      <section className="panel live-events-panel">
        <div className="live-events-toolbar">
          <div>
            <h3>Windows Telemetry Stream</h3>

            <p>
              Latest compatible Sysmon security
              events
            </p>
          </div>

          <div className="feed-status">
            <span
              className={
                paused
                  ? "feed-dot paused"
                  : "feed-dot"
              }
            />

            {paused ? "PAUSED" : "AUTO REFRESH"}
          </div>
        </div>

        <div className="event-filters">
          <div className="event-search">
            <Search size={15} />

            <input
              type="text"
              placeholder="Search event type or record ID..."
              value={search}
              onChange={(e) =>
                setSearch(e.target.value)
              }
            />
          </div>

          <select
            value={eventFilter}
            onChange={(e) =>
              setEventFilter(e.target.value)
            }
          >
            <option value="ALL">
              All Event Types
            </option>

            <option value="1">
              Event 1 - Process Create
            </option>

            <option value="3">
              Event 3 - Network Connection
            </option>

            <option value="5">
              Event 5 - Process Terminate
            </option>

            <option value="11">
              Event 11 - File Create
            </option>

            <option value="12">
              Event 12 - Registry Event
            </option>

            <option value="13">
              Event 13 - Registry Value Set
            </option>

            <option value="22">
              Event 22 - DNS Query
            </option>
          </select>
        </div>

        <div className="event-table-wrapper live-table">
          <table>
            <thead>
              <tr>
                <th>EVENT</th>
                <th>CATEGORY</th>
                <th>TYPE</th>
                <th>TIME</th>
                <th>RECORD ID</th>
              </tr>
            </thead>

            <tbody>
              {filteredEvents.map(
                (event, index) => (
                  <tr
                    key={
                      event.record_id || index
                    }
                  >
                    <td>
                      <div className="event-number-cell">
                        <span className="event-icon-small">
                          {getEventIcon(
                            event.event_id
                          )}
                        </span>

                        <span className="event-id">
                          {event.event_id}
                        </span>
                      </div>
                    </td>

                    <td>
                      <span
                        className={`category-badge category-${(
                          EVENT_CATEGORIES[
                            event.event_id
                          ] || "OTHER"
                        ).toLowerCase()}`}
                      >
                        {EVENT_CATEGORIES[
                          event.event_id
                        ] || "OTHER"}
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
                      {event.record_id || "--"}
                    </td>
                  </tr>
                )
              )}
            </tbody>
          </table>

          {!loading &&
            filteredEvents.length === 0 && (
              <div className="empty-events">
                No events match the current
                filters.
              </div>
            )}

          {loading && (
            <div className="empty-events">
              Loading Sysmon events...
            </div>
          )}
        </div>

        <div className="event-footer">
          <span>
            Showing {filteredEvents.length} of{" "}
            {events.length} events
          </span>

          <span>
            Refresh interval: 2 seconds
          </span>
        </div>
      </section>
    </main>
  );
}

function SummaryCard({
  title,
  value,
  icon,
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

function countCategory(events, category) {
  return events.filter(
    (event) =>
      EVENT_CATEGORIES[event.event_id] ===
      category
  ).length;
}

function formatTime(timestamp) {
  if (!timestamp) return "--";

  try {
    return new Date(
      timestamp
    ).toLocaleTimeString();
  } catch {
    return timestamp;
  }
}

export default LiveEvents;