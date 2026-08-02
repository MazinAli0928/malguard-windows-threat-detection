import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
} from "react-router-dom";

import { useEffect, useState } from "react";

import Sidebar from "./components/Sidebar";

import Dashboard from "./pages/Dashboard";
import LiveEvents from "./pages/LiveEvents";
import Threats from "./pages/Threats";
import DetectionHistory from "./pages/DetectionHistory";

import "./App.css";

const API = "http://127.0.0.1:8000";

function App() {
  const [running, setRunning] = useState(false);

  const fetchEngineStatus = async () => {
    try {
      const response = await fetch(
        `${API}/api/status`
      );

      if (!response.ok) {
        return;
      }

      const data = await response.json();

      setRunning(Boolean(data.running));
    } catch (error) {
      console.error(
        "Unable to retrieve engine status:",
        error
      );
    }
  };

  useEffect(() => {
    fetchEngineStatus();

    const interval = setInterval(
      fetchEngineStatus,
      2000
    );

    return () => {
      clearInterval(interval);
    };
  }, []);

  return (
    <BrowserRouter>
      <div className="app">
        <Sidebar running={running} />

        <Routes>
          <Route
            path="/"
            element={<Dashboard />}
          />

          <Route
            path="/events"
            element={<LiveEvents />}
          />

          <Route
            path="/threats"
            element={<Threats />}
          />

          <Route
            path="/history"
            element={<DetectionHistory />}
          />

          <Route
            path="*"
            element={<Navigate to="/" replace />}
          />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;