"use client";
import { useState } from "react";
import { Icon } from "./Icons";

export default function SettingsView() {
  const [endpoint, setEndpoint] = useState("http://localhost:11434");
  const [modelName, setModelName] = useState("cisco-sec-8b");
  const [dbUrl, setDbUrl] = useState("sqlite:///./compliance_guardian.db");
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div>
      <div className="page-header">
        <h2>Settings</h2>
        <p>Configure the auditor, model endpoint, and preferences</p>
      </div>

      <div className="settings-grid">
        {/* Model Configuration */}
        <div className="glass-card">
          <div className="card-header">
            <h3><Icon name="brain" size={16} style={{ marginRight: 6, color: "var(--accent-purple)" }} /> Model Configuration</h3>
          </div>
          <div className="card-body">
            <div className="settings-field">
              <label>Inference Endpoint</label>
              <input type="text" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} className="settings-input" />
              <span className="settings-help">Ollama or vLLM server address</span>
            </div>
            <div className="settings-field">
              <label>Model Name</label>
              <input type="text" value={modelName} onChange={(e) => setModelName(e.target.value)} className="settings-input" />
              <span className="settings-help">Model identifier to use for inference</span>
            </div>
          </div>
        </div>

        {/* Database Configuration */}
        <div className="glass-card">
          <div className="card-header">
            <h3><Icon name="database" size={16} style={{ marginRight: 6, color: "var(--accent-cyan)" }} /> Database</h3>
          </div>
          <div className="card-body">
            <div className="settings-field">
              <label>Database URL</label>
              <input type="text" value={dbUrl} onChange={(e) => setDbUrl(e.target.value)} className="settings-input" />
              <span className="settings-help">SQLite for local, PostgreSQL for production</span>
            </div>
            <div className="settings-field">
              <label>Connection Status</label>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--accent-green)", display: "inline-block" }} />
                <span style={{ fontSize: 13, color: "var(--accent-green)", fontWeight: 600 }}>Connected</span>
              </div>
            </div>
          </div>
        </div>

        {/* Appearance */}
        <div className="glass-card">
          <div className="card-header">
            <h3><Icon name="palette" size={16} style={{ marginRight: 6, color: "var(--accent-amber)" }} /> Appearance</h3>
          </div>
          <div className="card-body">
            <div className="settings-field">
              <label>Theme</label>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="period-btn active">Dark</button>
                <button className="period-btn" disabled>Light (Coming Soon)</button>
              </div>
            </div>
          </div>
        </div>

        {/* About */}
        <div className="glass-card">
          <div className="card-header">
            <h3><Icon name="cloud" size={16} style={{ marginRight: 6, color: "var(--accent-blue)" }} /> About</h3>
          </div>
          <div className="card-body">
            <div className="settings-field">
              <label>Version</label>
              <span style={{ fontSize: 14, fontWeight: 600 }}>1.0.0</span>
            </div>
            <div className="settings-field">
              <label>AI Engine</label>
              <span style={{ fontSize: 14, fontWeight: 600 }}>Cisco Sec-8B</span>
            </div>
            <div className="settings-field">
              <label>Runtime</label>
              <span style={{ fontSize: 14, fontWeight: 600 }}>Ollama / vLLM</span>
            </div>
          </div>
        </div>
      </div>

      <div style={{ marginTop: 24, display: "flex", gap: 12, alignItems: "center" }}>
        <button className="save-btn" onClick={handleSave}>
          {saved ? <><Icon name="check" size={14} /> Saved!</> : "Save Settings"}
        </button>
        {saved && <span style={{ fontSize: 13, color: "var(--accent-green)" }}>Settings updated successfully</span>}
      </div>
    </div>
  );
}
