import { useEffect, useState } from "react";
import { AlertTriangle, ShieldAlert, X } from "lucide-react";
import "../App.css";

export default function ThreatPopup({
  threat,
  onClose,
}) {
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    // Auto-dismiss after 8 seconds
    const timer = setTimeout(() => {
      handleClose();
    }, 8000);

    return () => clearTimeout(timer);
  }, [threat]);

  const handleClose = () => {
    setVisible(false);
    setTimeout(onClose, 300); // Wait for fade out animation
  };

  if (!threat) return null;

  const isHighRisk =
    threat.risk_level === "HIGH_RISK" || threat.status === "MALICIOUS";
  
  const probability = threat.malicious_probability
    ? (threat.malicious_probability * 100).toFixed(1)
    : 0;

  return (
    <div className={`threat-popup ${visible ? 'visible' : 'hidden'} ${isHighRisk ? 'high-risk' : 'suspicious'}`}>
      <div className="threat-popup-icon">
        {isHighRisk ? (
          <ShieldAlert size={24} />
        ) : (
          <AlertTriangle size={24} />
        )}
      </div>
      
      <div className="threat-popup-content">
        <h4>{isHighRisk ? "Malicious Threat Detected!" : "Suspicious Activity Detected"}</h4>
        <div className="threat-popup-prob">
          Probability: <strong>{probability}%</strong>
        </div>
        <p>{threat.reason || "Unusual behavioral pattern detected by MALGUARD."}</p>
      </div>

      <button className="threat-popup-close" onClick={handleClose}>
        <X size={18} />
      </button>
    </div>
  );
}
