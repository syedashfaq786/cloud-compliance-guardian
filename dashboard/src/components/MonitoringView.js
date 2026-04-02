"use client";
import { useState, useEffect } from "react";
import { Icon } from "./Icons";

const API = "http://localhost:8000";


export default function MonitoringView({ onNavigate }) {
  const [awsStatus, setAwsStatus] = useState(null);
  const [azureStatus, setAzureStatus] = useState(null);
  const [gcpStatus, setGcpStatus] = useState(null);
  const [selectedCloud, setSelectedCloud] = useState("aws");
  
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [events, setEvents] = useState([]);
  const [activeTab, setActiveTab] = useState("overview");
  const [activeFilter, setActiveFilter] = useState("all");
  
  const [availableRegions, setAvailableRegions] = useState([]);
  const [selectedRegions, setSelectedRegions] = useState([]);
  const [showRegionFilter, setShowRegionFilter] = useState(false);
  const [downloading, setDownloading] = useState(null); // 'pdf' | 'csv' | 'json' | null
  const [reportFramework, setReportFramework] = useState("All"); // All | CIS | NIST


  useEffect(() => {
    checkCloudStatuses();
    loadCachedResults();
  }, []);

  useEffect(() => {
    if (selectedCloud === "aws" && awsStatus?.connected) {
      fetchRegions();
    }
    loadCachedResults();
  }, [selectedCloud, awsStatus]);

  const fetchRegions = async () => {
    try {
      const res = await fetch(`${API}/api/aws/regions`);
      const data = await res.json();
      setAvailableRegions(data.regions || []);
      // Default to primary region only for fast scans
      if (data.primary) setSelectedRegions([data.primary]);
    } catch (err) {
      console.error("Failed to fetch AWS regions", err);
    }
  };

  const checkCloudStatuses = async () => {
    try {
      const [awsRes, azureRes, gcpRes] = await Promise.all([
        fetch(`${API}/api/aws/status`),
        fetch(`${API}/api/azure/status`),
        fetch(`${API}/api/gcp/status`)
      ]);
      const [awsData, azureData, gcpData] = await Promise.all([awsRes.json(), azureRes.json(), gcpRes.json()]);
      setAwsStatus(awsData);
      setAzureStatus(azureData);
      setGcpStatus(gcpData);

      if (!awsData.connected) {
        if (azureData.connected) setSelectedCloud("azure");
        else if (gcpData.connected) setSelectedCloud("gcp");
      }
    } catch (err) {
      console.error("Failed to check cloud statuses", err);
    }
  };

  const loadCachedResults = async () => {
    try {
      const res = await fetch(`${API}/api/${selectedCloud}/scan/latest`);
      const data = await res.json();
      if (data.cached) {
        setScanResults(data);
        if (data.audit?.events_analysis?.length) setEvents(data.audit.events_analysis);
      } else {
        setScanResults(null);
        setEvents([]);
      }
    } catch {}
  };

  const handleScan = async () => {
    setScanning(true);
    try {
      const body = selectedCloud === "aws" ? { regions: selectedRegions.length ? selectedRegions : null } : {};
      const res = await fetch(`${API}/api/${selectedCloud}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Scan failed");
      }
      const data = await res.json();
      setScanResults(data);
      if (selectedCloud === "aws") fetchEvents();
    } catch (err) {
      setScanResults({ error: err.message });
    } finally {
      setScanning(false);
    }
  };

  const fetchEvents = async () => {
    try {
      const res = await fetch(`${API}/api/aws/events`);
      const data = await res.json();
      setEvents(data.events || []);
    } catch {}
  };

  const handleDownloadReport = async (format) => {
    setDownloading(format);
    try {
      const frameworkParam = reportFramework !== "All" ? `&framework=${reportFramework}` : "";
      const res = await fetch(`${API}/api/${selectedCloud}/scan/report?format=${format}${frameworkParam}`);
      if (!res.ok) { alert("Report download failed — run a scan first."); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const fwLabel = reportFramework !== "All" ? `-${reportFramework.toLowerCase()}` : "";
      a.download = `${selectedCloud}-compliance-report${fwLabel}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("Failed to download report: " + err.message);
    } finally {
      setDownloading(null);
    }
  };


  const handleDisconnect = async () => {
    try {
      await fetch(`${API}/api/${selectedCloud}/disconnect`, { method: "POST" });
      checkCloudStatuses();
      setScanResults(null);
      setEvents([]);
    } catch {}
  };

  const isCloudConnected = (cloud) => {
    if (cloud === "aws") return awsStatus?.connected;
    if (cloud === "azure") return azureStatus?.connected;
    if (cloud === "gcp") return gcpStatus?.connected;
    return false;
  };

  const anyConnected = awsStatus?.connected || azureStatus?.connected || gcpStatus?.connected;

  if (!anyConnected && awsStatus !== null) {
    return (
      <div className="animate-fade-in">
        <div className="page-header">
          <h2>Monitoring</h2>
          <p>Real-time infrastructure monitoring and CIS compliance scanning.</p>
        </div>
        <div className="glass-card" style={{ maxWidth: 650, margin: "40px auto", padding: 48, textAlign: "center" }}>
          <div style={{ display: "flex", justifyContent: "center", gap: 24, marginBottom: 32 }}>
            <div style={{ padding: 16, background: "rgba(0,0,0,0.05)", borderRadius: 16 }}><img src="/logos/aws.svg" alt="AWS" style={{ width: 48, height: 48 }} /></div>
            <div style={{ padding: 16, background: "rgba(0,0,0,0.05)", borderRadius: 16 }}><img src="/logos/azure.svg" alt="Azure" style={{ width: 48, height: 48 }} /></div>
            <div style={{ padding: 16, background: "rgba(0,0,0,0.05)", borderRadius: 16 }}><img src="/logos/gcp.svg" alt="GCP" style={{ width: 48, height: 48 }} /></div>
          </div>
          <h3>No Cloud Accounts Connected</h3>
          <p style={{ color: "var(--text-secondary)", marginBottom: 24 }}>Connect your accounts to enable live infrastructure monitoring.</p>
          <button className="save-btn" onClick={() => onNavigate && onNavigate("connect")} style={{ padding: "12px 32px", display: "inline-flex", alignItems: "center", gap: 8 }}>
            <Icon name="cloud-plus" size={18} /> Go to Connect
          </button>
        </div>
      </div>
    );
  }

  const currentStatus = selectedCloud === "aws" ? awsStatus : selectedCloud === "azure" ? azureStatus : gcpStatus;
  const cloudLogo = selectedCloud === "aws" ? "/logos/aws.svg" : selectedCloud === "azure" ? "/logos/azure.svg" : "/logos/gcp.svg";
  const audit = scanResults?.audit;
  const metrics = scanResults?.scan || {};
  const findings = audit?.findings || [];
  const healthScore = audit?.health_score ?? 0;

  const getSeverityColor = (severity) => ({ CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#3b82f6" }[severity] || "#6b7280");

  return (
    <div className="animate-fade-in">
      {/* Cloud Selector */}
      <div style={{ display: "flex", gap: 12, marginBottom: 24, padding: "8px 0", borderBottom: "1px solid var(--border-color)" }}>
        {["aws", "azure", "gcp"].map(id => (
          <button
            key={id}
            onClick={() => isCloudConnected(id) && setSelectedCloud(id)}
            disabled={!isCloudConnected(id)}
            style={{
              display: "flex", alignItems: "center", gap: 10, padding: "10px 20px", borderRadius: 12,
              background: selectedCloud === id ? "var(--bg-tertiary)" : "transparent",
              border: selectedCloud === id ? "1px solid var(--accent-primary)" : "1px solid transparent",
              opacity: isCloudConnected(id) ? 1 : 0.4,
              cursor: isCloudConnected(id) ? "pointer" : "not-allowed",
              transition: "all 0.2s ease"
            }}
          >
            <img src={`/logos/${id}.svg`} alt={id} style={{ width: 24, height: 24 }} />
            <span style={{ fontWeight: 600, color: selectedCloud === id ? "var(--text-primary)" : "var(--text-secondary)", textTransform: "uppercase" }}>{id}</span>
          </button>
        ))}
      </div>

      {/* ── Page header ── */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
            <img src={cloudLogo} alt="" style={{ width: 32, height: 32 }} />
            <h2 style={{ margin: 0 }}>{selectedCloud.toUpperCase()} Monitoring</h2>
          </div>
          <p style={{ margin: 0, fontSize: 13, color: "var(--text-secondary)" }}>
            Managing compliance for <strong>{selectedCloud === "aws" ? currentStatus?.user : currentStatus?.project_id || currentStatus?.tenant_id}</strong>
            <span style={{ color: "#22c55e", marginLeft: 10, fontWeight: 600 }}>● Connected</span>
          </p>
        </div>

        {/* Right action buttons — scan + region + disconnect */}
        <div style={{ display: "flex", gap: 10, alignItems: "center", position: "relative" }}>
          {selectedCloud === "aws" && (
            <div style={{ position: "relative" }}>
              <button
                onClick={() => setShowRegionFilter(!showRegionFilter)}
                style={{
                  display: "flex", alignItems: "center", gap: 8, padding: "9px 16px",
                  background: showRegionFilter ? "var(--accent-primary)" : "var(--bg-tertiary)",
                  border: `1px solid ${showRegionFilter ? "var(--accent-primary)" : "var(--border-color)"}`,
                  borderRadius: 8, cursor: "pointer", fontSize: 13,
                  color: showRegionFilter ? "#fff" : "var(--text-primary)", fontWeight: 500,
                }}
              >
                <Icon name="globe" size={14} />
                {selectedRegions.length === 1 ? selectedRegions[0] : selectedRegions.length > 1 ? `${selectedRegions.length} Regions` : "Select Region"}
              </button>
              {showRegionFilter && (
                <div style={{
                  position: "absolute", top: "calc(100% + 8px)", right: 0, zIndex: 100,
                  background: "var(--bg-card)", border: "1px solid var(--border-color)",
                  borderRadius: 12, boxShadow: "0 8px 32px rgba(0,0,0,0.18)",
                  minWidth: 220, padding: "8px 0", maxHeight: 320, overflowY: "auto"
                }}>
                  <div style={{ padding: "8px 16px 4px", fontSize: 11, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                    Select Regions
                  </div>
                  {availableRegions.length === 0 && (
                    <div style={{ padding: "12px 16px", fontSize: 13, color: "var(--text-muted)" }}>Loading regions…</div>
                  )}
                  {availableRegions.map(region => {
                    const isSelected = selectedRegions.includes(region);
                    return (
                      <button
                        key={region}
                        onClick={() => {
                          setSelectedRegions(prev =>
                            isSelected ? prev.filter(r => r !== region) : [...prev, region]
                          );
                        }}
                        style={{
                          display: "flex", alignItems: "center", gap: 10, width: "100%",
                          padding: "9px 16px", background: isSelected ? "rgba(255,122,0,0.08)" : "transparent",
                          border: "none", cursor: "pointer", fontSize: 13, textAlign: "left",
                          color: isSelected ? "var(--accent-primary)" : "var(--text-primary)",
                          fontWeight: isSelected ? 700 : 400,
                        }}
                      >
                        <span style={{
                          width: 16, height: 16, borderRadius: 4, flexShrink: 0,
                          border: `2px solid ${isSelected ? "var(--accent-primary)" : "var(--border-color)"}`,
                          background: isSelected ? "var(--accent-primary)" : "transparent",
                          display: "flex", alignItems: "center", justifyContent: "center"
                        }}>
                          {isSelected && <span style={{ color: "#fff", fontSize: 10, fontWeight: 900 }}>✓</span>}
                        </span>
                        {region}
                      </button>
                    );
                  })}
                  <div style={{ borderTop: "1px solid var(--border-color)", padding: "8px 16px", display: "flex", gap: 8 }}>
                    <button
                      onClick={() => { setShowRegionFilter(false); }}
                      style={{ flex: 1, padding: "7px 0", borderRadius: 6, background: "var(--accent-primary)", color: "#fff", border: "none", cursor: "pointer", fontSize: 13, fontWeight: 700 }}
                    >
                      Apply
                    </button>
                    <button
                      onClick={() => { setSelectedRegions(availableRegions); }}
                      style={{ padding: "7px 12px", borderRadius: 6, background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-color)", cursor: "pointer", fontSize: 12 }}
                    >
                      All
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
          <button className="save-btn" onClick={handleScan} disabled={scanning} style={{ display: "flex", alignItems: "center", gap: 8, padding: "9px 20px" }}>
            {scanning ? <><span className="spinner"></span> Scanning…</> : <><Icon name="refresh" size={16} /> Run Live Scan</>}
          </button>
          <button
            onClick={handleDisconnect}
            style={{ padding: "9px 16px", background: "rgba(220,53,69,0.08)", color: "#dc3545", border: "1px solid rgba(220,53,69,0.25)", borderRadius: 8, fontSize: 13, fontWeight: 600, cursor: "pointer" }}
          >
            Disconnect
          </button>
        </div>
      </div>

      {/* ── Download report bar (only when scan results exist) ── */}
      {scanResults && !scanResults.error && (
        <div style={{
          padding: "14px 18px", marginBottom: 24,
          background: "var(--bg-card)", border: "1px solid var(--border-color)",
          borderRadius: 12, boxShadow: "var(--shadow-card)",
        }}>
          {/* Top row: icon + label + download buttons */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: "rgba(255,122,0,0.1)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Icon name="file-text" size={16} style={{ color: "var(--accent-amber)" }} />
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-primary)" }}>Compliance Report Ready</div>
                <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                  Last scan: {scanResults?.scan_time ? new Date(scanResults.scan_time).toLocaleString() : "Available"}
                  {reportFramework !== "All" && (
                    <span style={{ marginLeft: 8, fontWeight: 700, color: "var(--accent-primary)" }}>· {reportFramework} framework only</span>
                  )}
                </div>
              </div>
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              {/* Framework filter */}
              <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "5px 8px", background: "var(--bg-tertiary)", borderRadius: 8, border: "1px solid var(--border-color)" }}>
                <Icon name="shield" size={13} style={{ color: "var(--text-muted)" }} />
                <span style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 600, marginRight: 2 }}>Framework:</span>
                {["All", "CIS", "NIST"].map(fw => (
                  <button
                    key={fw}
                    onClick={() => setReportFramework(fw)}
                    style={{
                      padding: "3px 9px", borderRadius: 5, fontSize: 11, fontWeight: 700,
                      border: "none", cursor: "pointer",
                      background: reportFramework === fw ? "var(--accent-primary)" : "transparent",
                      color: reportFramework === fw ? "#fff" : "var(--text-secondary)",
                      transition: "all 0.15s",
                    }}
                  >{fw}</button>
                ))}
              </div>
              <button
                className="save-btn"
                onClick={() => handleDownloadReport("pdf")}
                disabled={!!downloading}
                style={{ display: "flex", alignItems: "center", gap: 7, padding: "9px 18px" }}
              >
                <Icon name="file-text" size={14} />
                {downloading === "pdf" ? "Generating…" : "Download Report (PDF)"}
              </button>
              <button className="download-btn" onClick={() => handleDownloadReport("csv")} disabled={!!downloading}>
                <Icon name="file-text" size={13} />
                {downloading === "csv" ? "…" : "CSV"}
              </button>
              <button className="download-btn" onClick={() => handleDownloadReport("json")} disabled={!!downloading}>
                <Icon name="file-text" size={13} />
                {downloading === "json" ? "…" : "JSON"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Sub-Tabs */}
      <div style={{ display: "flex", gap: 32, marginBottom: 32, borderBottom: "1px solid var(--border-color)" }}>
        {[
          { id: "overview", name: "Overview", icon: "dashboard" },
          { id: "inventory", name: "Inventory", icon: "box" },
          { id: "compliance", name: "Compliance", icon: "shield-check" },
          { id: "activity", name: "Activity", icon: "clock" }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              padding: "12px 4px", background: "none", border: "none",
              color: activeTab === tab.id ? "var(--accent-primary)" : "var(--text-secondary)",
              borderBottom: activeTab === tab.id ? "2px solid var(--accent-primary)" : "2px solid transparent",
              cursor: "pointer", fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8, marginBottom: -1
            }}
          >
            <Icon name={tab.icon} size={16} /> {tab.name}
          </button>
        ))}
      </div>

      {!scanResults && !scanning && activeTab !== "activity" && (
        <div className="glass-card" style={{ padding: 64, textAlign: "center" }}>
          <div style={{ width: 80, height: 80, borderRadius: 20, background: "rgba(var(--accent-primary-rgb), 0.1)", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 24px" }}>
            <Icon name="search" size={40} style={{ color: "var(--accent-primary)" }} />
          </div>
          <h3 style={{ fontSize: 24, marginBottom: 12 }}>Ready to Scan</h3>
          <p style={{ color: "var(--text-secondary)", maxWidth: 450, margin: "0 auto 32px", fontSize: 15, lineHeight: 1.6 }}>
            Run a live scan to analyze your {selectedCloud.toUpperCase()} resources against CIS Level 1 benchmarks.
          </p>
          <button className="save-btn" onClick={handleScan} style={{ padding: "14px 40px", fontSize: 16 }}>Start Initial Scan</button>
        </div>
      )}

      {/* Tab Contents */}
      {activeTab === "overview" && scanResults && (
        <div className="animate-fade-in">
          <div className="dashboard-grid" style={{ gridTemplateColumns: "280px 1fr 1fr 1fr", gap: 24, marginBottom: 32 }}>
            <div className="glass-card" style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 32 }}>
              <div style={{ position: "relative", width: 140, height: 140, marginBottom: 16 }}>
                <svg viewBox="0 0 120 120" style={{ transform: "rotate(-90deg)", width: "100%", height: "100%" }}>
                  <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(0,0,0,0.05)" strokeWidth="8" />
                  <circle cx="60" cy="60" r="50" fill="none" stroke={healthScore >= 80 ? "#22c55e" : healthScore >= 50 ? "#f59e0b" : "#ef4444"} strokeWidth="8" strokeDasharray={`${healthScore * 3.14} 314`} strokeLinecap="round" style={{ transition: "all 1s ease" }} />
                </svg>
                <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 32, fontWeight: 800 }}>{healthScore}%</div>
              </div>
              <div style={{ fontSize: 15, fontWeight: 700 }}>Infrastructure Health</div>
              <div style={{ fontSize: 13, color: "var(--text-secondary)" }}>Overall Compliance Score</div>
            </div>
            
            <div className="glass-card stat-card stat-blue">
              <div className="stat-card-top"><div className="stat-icon"><Icon name="folder" size={24} /></div></div>
              <div className="stat-value">{metrics.total_resources || 0}</div>
              <div className="stat-label">Total Resources</div>
            </div>
            <div className="glass-card stat-card stat-purple">
              <div className="stat-card-top"><div className="stat-icon"><Icon name="shield" size={24} /></div></div>
              <div className="stat-value">{findings.length}</div>
              <div className="stat-label">Audited Controls</div>
            </div>
            <div className="glass-card stat-card stat-amber">
              <div className="stat-card-top"><div className="stat-icon"><Icon name="triangle-alert" size={24} /></div></div>
              <div className="stat-value">{findings.filter(f => f.status === "FAIL").length}</div>
              <div className="stat-label">Critical Findings</div>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 24, marginBottom: 32 }}>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(sev => (
              <div key={sev} className="glass-card" style={{ padding: 24, display: "flex", alignItems: "center", gap: 16 }}>
                <div style={{ width: 12, height: 12, borderRadius: "50%", background: getSeverityColor(sev) }}></div>
                <div>
                  <div style={{ fontSize: 24, fontWeight: 800 }}>{audit?.summary?.[sev.toLowerCase()] || 0}</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", textTransform: "uppercase" }}>{sev} Risks</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === "inventory" && scanResults && (
        <div className="glass-card animate-fade-in" style={{ padding: 0, overflow: "hidden" }}>
          <div className="card-body" style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead style={{ background: "rgba(0,0,0,0.02)" }}>
                <tr>
                  <th style={{ textAlign: "left", padding: 16, fontSize: 12, color: "var(--text-secondary)" }}>NAME</th>
                  <th style={{ textAlign: "left", padding: 16, fontSize: 12, color: "var(--text-secondary)" }}>TYPE</th>
                  <th style={{ textAlign: "left", padding: 16, fontSize: 12, color: "var(--text-secondary)" }}>REGION</th>
                  <th style={{ textAlign: "left", padding: 16, fontSize: 12, color: "var(--text-secondary)" }}>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {(scanResults.resources || []).map((res, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid var(--border-color)" }}>
                    <td style={{ padding: 16 }}>
                      <div style={{ fontWeight: 600, fontSize: 14 }}>{res.resource_name}</div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "monospace" }}>{res.resource_id}</div>
                    </td>
                    <td style={{ padding: 16, fontSize: 13 }}>{res.resource_type?.split("_").slice(1).join(" ").toUpperCase()}</td>
                    <td style={{ padding: 16, fontSize: 13 }}>{res.region || "Global"}</td>
                    <td style={{ padding: 16 }}>
                      <span style={{ fontSize: 11, fontWeight: 800, color: "#22c55e", background: "rgba(34,197,94,0.1)", padding: "4px 12px", borderRadius: 20 }}>DISCOVERED</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === "compliance" && scanResults && (
        <div className="animate-fade-in" style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            {["all", "fail", "pass"].map(f => (
              <button key={f} onClick={() => setActiveFilter(f)} style={{ padding: "6px 16px", borderRadius: 8, fontSize: 13, fontWeight: 600, border: "none", cursor: "pointer", background: activeFilter === f ? "var(--accent-primary)" : "var(--bg-tertiary)", color: activeFilter === f ? "#fff" : "var(--text-secondary)", textTransform: "uppercase" }}>
                {f}
              </button>
            ))}
          </div>
          {findings.filter(f => activeFilter === "all" || f.status === activeFilter.toUpperCase()).map((f, i) => (
            <div key={i} className="glass-card" style={{ padding: 20, borderLeft: `4px solid ${f.status === "FAIL" ? getSeverityColor(f.severity) : "#22c55e"}` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                    <span style={{ fontSize: 12, fontWeight: 800, color: "var(--text-muted)" }}>{f.cis_rule_id}</span>
                    <span style={{ fontSize: 11, fontWeight: 800, padding: "2px 8px", borderRadius: 4, background: f.status === "FAIL" ? "rgba(239,68,68,0.1)" : "rgba(34,197,94,0.1)", color: f.status === "FAIL" ? "#ef4444" : "#22c55e" }}>{f.status}</span>
                    <span style={{ fontSize: 11, fontWeight: 800, color: getSeverityColor(f.severity) }}>{f.severity}</span>
                  </div>
                  <h4 style={{ margin: 0, fontSize: 15 }}>{f.title}</h4>
                </div>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)" }}>{f.resource_name}</div>
              </div>
              <p style={{ fontSize: 14, color: "var(--text-secondary)", margin: 0, lineHeight: 1.5 }}>{f.description}</p>
              {f.status === "FAIL" && f.remediation_step && (
                <div style={{ marginTop: 16, background: "rgba(0,0,0,0.03)", padding: 12, borderRadius: 8, fontSize: 12, fontFamily: "monospace" }}>
                  <div style={{ marginBottom: 4, fontWeight: 700, color: "var(--text-muted)" }}>Remediation:</div>
                  {f.remediation_step}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {activeTab === "activity" && (
        <div className="glass-card animate-fade-in" style={{ padding: 0 }}>
          <div className="card-header"><h3>Recent Activity Feed</h3></div>
          <div className="card-body" style={{ padding: 0 }}>
            {events.length === 0 ? <p style={{ padding: 48, textAlign: "center", color: "var(--text-secondary)" }}>No activity recorded in the last 24 hours.</p> : (
              events.map((evt, i) => (
                <div key={i} style={{ padding: "16px 20px", borderBottom: "1px solid var(--border-color)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 2 }}>{evt.event_name}</div>
                    <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>{evt.username} | {evt.event_source}</div>
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <div style={{ fontSize: 12, fontWeight: 700, color: evt.status === "FAIL" ? "#ef4444" : "#22c55e" }}>{evt.status}</div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{new Date(evt.event_time).toLocaleString()}</div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
