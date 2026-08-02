import {
  Activity,
  Database,
  Shield,
  ShieldAlert,
  Terminal,
} from "lucide-react";

import { NavLink } from "react-router-dom";

function Sidebar({ running }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-icon">
          <Shield size={25} />
        </div>

        <div>
          <h1>MALGUARD</h1>
          <span>Threat Intelligence</span>
        </div>
      </div>

      <nav>
        <NavLink
          to="/"
          end
          className={({ isActive }) =>
            `nav-item ${isActive ? "active" : ""}`
          }
        >
          <Activity size={19} />
          Dashboard
        </NavLink>

        <NavLink
          to="/events"
          className={({ isActive }) =>
            `nav-item ${isActive ? "active" : ""}`
          }
        >
          <Terminal size={19} />
          Live Events
        </NavLink>

        <NavLink
          to="/threats"
          className={({ isActive }) =>
            `nav-item ${isActive ? "active" : ""}`
          }
        >
          <ShieldAlert size={19} />
          Threats
        </NavLink>

        <NavLink
          to="/history"
          className={({ isActive }) =>
            `nav-item ${isActive ? "active" : ""}`
          }
        >
          <Database size={19} />
          Detection History
        </NavLink>
      </nav>

      <div className="sidebar-bottom">
        <div className="engine-info">
          <span
            className={
              running
                ? "status-dot online"
                : "status-dot"
            }
          />

          <div>
            <strong>Detection Engine</strong>

            <span>
              {running ? "Monitoring" : "Stopped"}
            </span>
          </div>
        </div>

        <p>Windows Behavioral Detection</p>
        <small>Random Forest + Risk Engine</small>
      </div>
    </aside>
  );
}

export default Sidebar;