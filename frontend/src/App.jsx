import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
} from "react-router-dom";

import { useEffect, useState, useRef } from "react";

import ThemeToggle from "./components/ThemeToggle";

import Sidebar from "./components/Sidebar";

import Dashboard from "./pages/Dashboard";
import LiveEvents from "./pages/LiveEvents";
import Threats from "./pages/Threats";
import DetectionHistory from "./pages/DetectionHistory";
import ThreatPopup from "./components/ThreatPopup";

import "./App.css";

const API = "http://127.0.0.1:8000";

function App() {
  const [running, setRunning] = useState(false);
  const [activeThreat, setActiveThreat] = useState(null);
  const lastPredictionRef = useRef(0);

  // ==========================================================
  // GLOBAL THEME
  // ==========================================================

  const [darkMode, setDarkMode] = useState(() => {
    const savedTheme = localStorage.getItem("malguard-theme");

    if (savedTheme === "light") {
      return false;
    }

    if (savedTheme === "dark") {
      return true;
    }

    return true;
  });

  useEffect(() => {
    const theme = darkMode ? "dark" : "light";

    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("malguard-theme", theme);
  }, [darkMode]);

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
      
      // Check for new threat predictions
      if (data.total_predictions > lastPredictionRef.current) {
        lastPredictionRef.current = data.total_predictions;
        
        const prediction = data.latest_prediction;
        if (prediction) {
          if (
            prediction.risk_level === "HIGH_RISK" || 
            prediction.risk_level === "SUSPICIOUS" ||
            prediction.status === "MALICIOUS"
          ) {
            setActiveThreat(prediction);
          }
        }
      }

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

        <div className="global-theme-toggle">
          <ThemeToggle
            darkMode={darkMode}
            setDarkMode={setDarkMode}
          />
        </div>

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

        {activeThreat && (
          <ThreatPopup 
            threat={activeThreat} 
            onClose={() => setActiveThreat(null)} 
          />
        )}
      </div>
    </BrowserRouter>
  );
}

export default App;