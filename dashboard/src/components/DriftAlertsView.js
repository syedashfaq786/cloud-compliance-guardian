"use client";
import { useState, useEffect } from "react";
import { Icon } from "./Icons";

const API_BASE = "http://127.0.0.1:8000";

export default function DriftAlertsView() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [acknowledging, setAcknowledging] = useState(null);

  const fetchAlerts = () => {
    fetch(`${API_BASE}/api/drift`)
      .then((r) => r.json())
      .then((data) => { setAlerts(data.alerts || []); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { fetchAlerts(); }, []);

  const handleAcknowledge = async (alertId) => {
    setAcknowledging(alertId);
    try {
      await fetch(`${API_BASE}/api/drift/${alertId}/ack`, { method: "POST" });
      setAlerts((prev) => prev.filter((a) => a.id !== alertId));
    } catch (err) {
      console.error("Failed to acknowledge alert:", err);
    }
    setAcknowledging(null);
  };

  const ALERT_ICON_MAP = { critical: "siren", high: "triangle-alert", medium: "clipboard" };
  const SEVERITY_COLORS = { critical: "var(--accent-red)", high: "var(--accent-orange)", medium: "var(--accent-amber)" };

  if (loading) {
    return (
      <div className="glass-card" style={{ padding: 48, textAlign: "center" }}>
        <div className="spinner" style={{ margin: "0 auto 16px", width: 32, height: 32 }} />
        <p style={{ color: "var(--text-muted)" }}>Loading drift alerts...</p>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h2>Drift Detection Alerts</h2>
          <p>Monitor compliance regressions and infrastructure drift</p>
        </div>
        <button className="period-btn active" onClick={() => { setLoading(true); fetchAlerts(); }}>
          <Icon name="arrow-up" size={14} style={{ transform: "rotate(0deg)" }} /> Refresh
        </button>
      </div>

      {alerts.length === 0 ? (
        <div className="glass-card" style={{ padding: 64, textAlign: "center" }}>
          <Icon name="circle-check" size={56} style={{ color: "var(--accent-green)", marginBottom: 16 }} />
          <h3 style={{ fontSize: 20, color: "var(--text-secondary)", marginBottom: 8 }}>All Clear</h3>
          <p style={{ color: "var(--text-muted)", fontSize: 14, maxWidth: 400, margin: "0 auto" }}>
            No active drift alerts. Your infrastructure compliance is stable.
          </p>
        </div>
      ) : (
        <div className="drift-alerts-grid">
          {alerts.map((alert) => (
            <div key={alert.id} className="glass-card drift-alert-card">
              <div className="card-body">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
                  <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
                    <div
                      className="alert-icon-circle"
                      style={{ background: `${SEVERITY_COLORS[alert.severity]}20`, color: SEVERITY_COLORS[alert.severity] }}
                    >
                      <Icon name={ALERT_ICON_MAP[alert.severity] || "clipboard"} size={20} />
                    </div>
                    <div>
                      <span className={`severity-badge ${alert.severity}`} style={{ marginBottom: 6, display: "inline-flex" }}>
                        {alert.severity.toUpperCase()}
                      </span>
                      <h4 style={{ fontSize: 15, fontWeight: 600, marginTop: 6 }}>{alert.title}</h4>
                    </div>
                  </div>
                  <span style={{ fontSize: 11, color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                    {alert.created_at ? new Date(alert.created_at).toLocaleDateString() : ""}
                  </span>
                </div>

                <p style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text-secondary)", marginBottom: 12 }}>
                  {alert.description}
                </p>

                {alert.resource_address && (
                  <p style={{ fontFamily: "monospace", fontSize: 12, color: "var(--accent-purple)", marginBottom: 16 }}>
                    {alert.resource_address}
                  </p>
                )}

                <button
                  className="ack-btn"
                  onClick={() => handleAcknowledge(alert.id)}
                  disabled={acknowledging === alert.id}
                >
                  {acknowledging === alert.id ? (
                    <><span className="spinner" style={{ width: 14, height: 14 }} /> Acknowledging...</>
                  ) : (
                    <><Icon name="check" size={14} /> Acknowledge</>
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
