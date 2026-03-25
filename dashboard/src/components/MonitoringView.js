"use client";
import { useState, useEffect, useRef } from "react";
import { Icon } from "./Icons";

const API = "http://localhost:8000";

const SEVERITY_META = {
  "CRITICAL": { action: "Immediate remediation required", timeline: "Fix within 24 hours", color: "var(--accent-red, #ef4444)" },
  "HIGH": { action: "Schedule remediation promptly", timeline: "Fix within 1 week", color: "var(--accent-orange, #f97316)" },
  "MEDIUM": { action: "Plan remediation in next sprint", timeline: "Fix within 30 days", color: "var(--accent-amber, #eab308)" },
  "LOW": { action: "Address during routine maintenance", timeline: "Fix within 90 days", color: "var(--accent-blue, #3b82f6)" },
};

export default function MonitoringView({ onNavigate }) {
  const [awsStatus, setAwsStatus] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [events, setEvents] = useState([]);
  const [activeFilter, setActiveFilter] = useState("all");
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const feedRef = useRef(null);

  // Check AWS status on mount
  useEffect(() => {
    checkAwsStatus();
    loadCachedResults();
  }, []);

  const checkAwsStatus = async () => {
    try {
      const res = await fetch(`${API}/api/aws/status`);
      const data = await res.json();
      setAwsStatus(data);
    } catch {
      setAwsStatus({ connected: false, error: "Backend unavailable" });
    }
  };

  const loadCachedResults = async () => {
    try {
      const res = await fetch(`${API}/api/aws/scan/latest`);
      const data = await res.json();
      if (data.cached) {
        setScanResults(data);
        if (data.audit?.events_analysis?.length) {
          setEvents(data.audit.events_analysis);
        }
      }
    } catch {}
  };

  const handleScan = async () => {
    setScanning(true);
    try {
      const res = await fetch(`${API}/api/aws/scan`, { method: "POST" });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Scan failed");
      }
      const data = await res.json();
      setScanResults(data);
      fetchEvents();
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
    try {
      const res = await fetch(`${API}/api/aws/scan/report?format=${format}`);
      if (!res.ok) {
        const err = await res.json();
        alert(err.detail || "Report download failed");
        return;
      }
      const blob = await res.blob();
      const ext = format === "pdf" ? "pdf" : format === "csv" ? "csv" : "json";
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aws-audit-report.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert("Failed to download report: " + err.message);
    }
  };

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleDisconnect = async () => {
    try {
      await fetch(`${API}/api/aws/disconnect`, { method: "POST" });
      setAwsStatus({ connected: false });
      setScanResults(null);
      setEvents([]);
    } catch {}
  };

  const audit = scanResults?.audit;
  const healthScore = audit?.health_score ?? 0;
  const findings = audit?.findings || [];

  const filteredFindings = activeFilter === "all"
    ? findings
    : activeFilter === "fail"
    ? findings.filter(f => f.status === "FAIL")
    : findings.filter(f => f.status === "PASS");

  const failedFindings = findings.filter(f => f.status === "FAIL");

  const getSeverityColor = (severity) => {
    const colors = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#3b82f6", NONE: "#22c55e" };
    return colors[severity] || "#6b7280";
  };

  // ── Not Connected State — redirect to Connect tab ────────────────────
  if (!awsStatus?.connected) {
    return (
      <div className="animate-fade-in">
        <div className="page-header">
          <h2>Monitoring</h2>
          <p>Real-time AWS infrastructure monitoring and CIS compliance scanning.</p>
        </div>

        <div className="glass-card" style={{ maxWidth: 550, margin: "40px auto", padding: 48, textAlign: "center" }}>
          <div style={{ width: 80, height: 80, borderRadius: 20, background: "linear-gradient(135deg, #ff9900, #ff6600)", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 24px" }}>
            <Icon name="aws" size={48} />
          </div>
          <h3 style={{ fontSize: 22, marginBottom: 8 }}>AWS Not Connected</h3>
          <p style={{ color: "var(--text-secondary)", maxWidth: 400, margin: "0 auto 24px" }}>
            Connect your AWS account first to enable live infrastructure monitoring. Go to the Connect tab and enter your AWS Access Keys.
          </p>
          <button className="save-btn" onClick={() => onNavigate && onNavigate("connect")} style={{ padding: "12px 32px", fontSize: 15, display: "inline-flex", alignItems: "center", gap: 8 }}>
            <Icon name="cloud-plus" size={18} /> Go to Connect
          </button>
        </div>
      </div>
    );
  }

  // ── Connected State — Dashboard ────────────────────────────────────────
  return (
    <div className="animate-fade-in">
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h2>Monitoring</h2>
          <p>
            Connected to AWS ({awsStatus.region || "us-east-1"}) as {awsStatus.user || "unknown"}
            <span style={{ color: "#22c55e", marginLeft: 8 }}>● Connected</span>
          </p>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {scanResults && !scanResults.error && (
            <>
              <button onClick={() => handleDownloadReport("pdf")}
                style={{ display: "flex", alignItems: "center", gap: 6, padding: "10px 16px", background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border-color)", borderRadius: 8, cursor: "pointer", fontSize: 13, fontWeight: 500 }}>
                <Icon name="download" size={14} /> PDF
              </button>
              <button onClick={() => handleDownloadReport("csv")}
                style={{ display: "flex", alignItems: "center", gap: 6, padding: "10px 12px", background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-color)", borderRadius: 8, cursor: "pointer", fontSize: 12, fontWeight: 500 }}>
                CSV
              </button>
              <button onClick={() => handleDownloadReport("json")}
                style={{ display: "flex", alignItems: "center", gap: 6, padding: "10px 12px", background: "var(--bg-tertiary)", color: "var(--text-secondary)", border: "1px solid var(--border-color)", borderRadius: 8, cursor: "pointer", fontSize: 12, fontWeight: 500 }}>
                JSON
              </button>
            </>
          )}
          <button className="save-btn" onClick={handleScan} disabled={scanning}
            style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 24px" }}>
            {scanning ? (
              <><span style={{ width: 16, height: 16, border: "2px solid rgba(255,255,255,0.3)", borderTopColor: "#fff", borderRadius: "50%", animation: "spin 0.8s linear infinite", display: "inline-block" }}></span>Scanning...</>
            ) : (
              <><Icon name="refresh" size={16} /> Run Live Scan</>
            )}
          </button>
          <button onClick={handleDisconnect}
            style={{ padding: "10px 16px", background: "rgba(220,53,69,0.1)", color: "#dc3545", border: "1px solid rgba(220,53,69,0.3)", borderRadius: 8, cursor: "pointer", fontSize: 12, fontWeight: 500 }}>
            Disconnect
          </button>
        </div>
      </div>

      {/* ── Health Gauge + Summary Stats ── */}
      {scanResults && !scanResults.error && (
        <>
          <div className="dashboard-grid" style={{ gridTemplateColumns: "1fr 1fr 1fr 1fr", marginBottom: 24 }}>
            {/* Health Gauge */}
            <div className="glass-card" style={{ gridColumn: "1 / 2", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: 24 }}>
              <div style={{ position: "relative", width: 120, height: 120, marginBottom: 12 }}>
                <svg viewBox="0 0 120 120" style={{ transform: "rotate(-90deg)" }}>
                  <circle cx="60" cy="60" r="50" fill="none" stroke="var(--bg-tertiary)" strokeWidth="10" />
                  <circle cx="60" cy="60" r="50" fill="none"
                    stroke={healthScore >= 80 ? "#22c55e" : healthScore >= 50 ? "#eab308" : "#ef4444"}
                    strokeWidth="10" strokeDasharray={`${healthScore * 3.14} 314`} strokeLinecap="round"
                    style={{ transition: "stroke-dasharray 1s ease" }} />
                </svg>
                <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%, -50%)", textAlign: "center" }}>
                  <div style={{ fontSize: 28, fontWeight: 700, color: healthScore >= 80 ? "#22c55e" : healthScore >= 50 ? "#eab308" : "#ef4444" }}>
                    {healthScore}%
                  </div>
                </div>
              </div>
              <div style={{ fontSize: 14, fontWeight: 600 }}>Security Health</div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>CIS Benchmark Score</div>
            </div>

            {/* Resource Stats */}
            <div className="glass-card stat-card stat-blue animate-slide-in stagger-1">
              <div className="stat-card-top"><div className="stat-icon"><Icon name="folder" size={22} /></div></div>
              <div className="stat-value">{scanResults.scan?.s3_buckets || 0}</div>
              <div className="stat-label">S3 Buckets</div>
            </div>
            <div className="glass-card stat-card stat-purple animate-slide-in stagger-2">
              <div className="stat-card-top"><div className="stat-icon"><Icon name="shield" size={22} /></div></div>
              <div className="stat-value">{scanResults.scan?.security_groups || 0}</div>
              <div className="stat-label">Security Groups</div>
            </div>
            <div className="glass-card stat-card stat-amber animate-slide-in stagger-3">
              <div className="stat-card-top"><div className="stat-icon"><Icon name="users" size={22} /></div></div>
              <div className="stat-value">{(scanResults.scan?.iam_policies || 0) + (scanResults.scan?.iam_users || 0)}</div>
              <div className="stat-label">IAM Resources</div>
            </div>
          </div>

          {/* ── Severity Summary Row ── */}
          <div className="dashboard-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)", marginBottom: 24 }}>
            {[
              { label: "Critical", count: audit?.summary?.critical || 0, color: "#ef4444" },
              { label: "High", count: audit?.summary?.high || 0, color: "#f97316" },
              { label: "Medium", count: audit?.summary?.medium || 0, color: "#eab308" },
              { label: "Passing", count: audit?.summary?.passing || 0, color: "#22c55e" },
            ].map((s) => (
              <div key={s.label} className="glass-card" style={{ padding: "16px 20px", display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{ width: 10, height: 10, borderRadius: "50%", background: s.color, flexShrink: 0 }}></div>
                <div>
                  <div style={{ fontSize: 22, fontWeight: 700 }}>{s.count}</div>
                  <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>{s.label}</div>
                </div>
              </div>
            ))}
          </div>

          {/* ── Findings List (same format as Audits tab) ── */}
          <div className="glass-card" style={{ marginBottom: 24 }}>
            <div className="card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3><Icon name="shield" size={18} style={{ marginRight: 8, verticalAlign: "middle" }} /> CIS Compliance Findings ({findings.length})</h3>
              <div style={{ display: "flex", gap: 6 }}>
                {["all", "fail", "pass"].map((f) => (
                  <button key={f} onClick={() => setActiveFilter(f)}
                    style={{
                      padding: "4px 14px", borderRadius: 6, fontSize: 12, fontWeight: 500,
                      background: activeFilter === f ? "var(--accent-primary)" : "var(--bg-tertiary)",
                      color: activeFilter === f ? "#fff" : "var(--text-secondary)",
                      border: "none", cursor: "pointer", textTransform: "uppercase",
                    }}>
                    {f} {f === "fail" ? `(${failedFindings.length})` : f === "pass" ? `(${findings.length - failedFindings.length})` : ""}
                  </button>
                ))}
              </div>
            </div>
            <div className="card-body" style={{ padding: "12px 16px" }}>
              {filteredFindings.length === 0 ? (
                <p style={{ textAlign: "center", color: "var(--text-secondary)", padding: 24 }}>No findings to display.</p>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  {filteredFindings.map((f, i) => {
                    const meta = SEVERITY_META[f.severity] || SEVERITY_META["MEDIUM"];
                    const isExpanded = expandedFinding === i;
                    const isFail = f.status === "FAIL";
                    const borderColor = isFail ? (meta?.color || "#ef4444") : "var(--accent-green, #22c55e)";

                    return (
                      <div key={i} className="glass-card" style={{ borderLeft: `3px solid ${borderColor}`, cursor: "pointer", margin: 0 }}
                        onClick={() => setExpandedFinding(isExpanded ? null : i)}>
                        <div className="card-body" style={{ padding: 20 }}>
                          {/* Finding Header */}
                          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: isExpanded ? 16 : 0 }}>
                            <div style={{
                              width: 36, height: 36, borderRadius: 10,
                              background: isFail ? `${getSeverityColor(f.severity)}15` : "rgba(34,197,94,0.1)",
                              color: isFail ? getSeverityColor(f.severity) : "#22c55e",
                              display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0
                            }}>
                              <Icon name={isFail ? "triangle-alert" : "circle-check"} size={16} />
                            </div>
                            <div style={{ flex: 1 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 2, flexWrap: "wrap" }}>
                                <span className="rule-id" style={{ fontSize: 13 }}>{f.cis_rule_id}</span>
                                <span className={`severity-badge ${(f.severity || "medium").toLowerCase()}`}>{f.severity}</span>
                                <span style={{
                                  fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 99,
                                  background: isFail ? "rgba(239,68,68,0.1)" : "rgba(34,197,94,0.1)",
                                  color: isFail ? "#ef4444" : "#22c55e",
                                }}>{f.status}</span>
                                <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11, color: "var(--text-muted)" }}>
                                  <Icon name="aws" size={12} /> AWS
                                </span>
                              </div>
                              <p style={{ fontSize: 13, fontWeight: 600 }}>{f.title}</p>
                            </div>
                            <div style={{ display: "flex", alignItems: "center", gap: 12, flexShrink: 0 }}>
                              <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "monospace" }}>{f.resource_name}</span>
                              <Icon name={isExpanded ? "arrow-up" : "arrow-down"} size={14} style={{ color: "var(--text-muted)" }} />
                            </div>
                          </div>

                          {/* Expanded Detail */}
                          {isExpanded && (
                            <div className="animate-fade-in" onClick={(e) => e.stopPropagation()}>
                              {/* Resource Info */}
                              <div style={{ display: "flex", gap: 20, marginBottom: 16, flexWrap: "wrap" }}>
                                <div style={{ fontSize: 12 }}>
                                  <span style={{ color: "var(--text-muted)" }}>Resource: </span>
                                  <span className="resource-name">{f.resource_name}</span>
                                </div>
                                <div style={{ fontSize: 12 }}>
                                  <span style={{ color: "var(--text-muted)" }}>Type: </span>
                                  <span style={{ color: "var(--text-secondary)" }}>{f.resource_type?.replace("aws_", "").replace(/_/g, " ")}</span>
                                </div>
                                <div style={{ fontSize: 12 }}>
                                  <span style={{ color: "var(--text-muted)" }}>Provider: </span>
                                  <span style={{ color: "var(--text-secondary)" }}>AWS</span>
                                </div>
                              </div>

                              {/* Description */}
                              <div style={{ marginBottom: 16, padding: "12px 16px", background: "rgba(0,0,0,0.02)", borderRadius: 10 }}>
                                <p style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 4 }}>
                                  <Icon name="search" size={12} style={{ marginRight: 4 }} /> Description
                                </p>
                                <p style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text-primary)" }}>{f.description}</p>
                              </div>

                              {/* Reasoning */}
                              {f.reasoning && (
                                <div style={{ marginBottom: 16, padding: "12px 16px", background: "rgba(139,92,246,0.04)", borderRadius: 10 }}>
                                  <p style={{ fontSize: 12, fontWeight: 600, color: "var(--accent-purple, #8b5cf6)", marginBottom: 4 }}>
                                    <Icon name="brain" size={12} style={{ marginRight: 4 }} /> Analysis
                                  </p>
                                  <p style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text-secondary)" }}>{f.reasoning}</p>
                                </div>
                              )}

                              {/* Expected vs Actual */}
                              {(f.expected || f.actual) && (
                                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
                                  <div style={{ padding: "12px 16px", background: "rgba(34,197,94,0.04)", borderRadius: 10, border: "1px solid rgba(34,197,94,0.15)" }}>
                                    <p style={{ fontSize: 11, fontWeight: 700, color: "#22c55e", marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.5 }}>Expected</p>
                                    <p style={{ fontSize: 12, lineHeight: 1.5, color: "var(--text-secondary)" }}>{f.expected}</p>
                                  </div>
                                  <div style={{ padding: "12px 16px", background: isFail ? "rgba(239,68,68,0.04)" : "rgba(34,197,94,0.04)", borderRadius: 10, border: `1px solid ${isFail ? "rgba(239,68,68,0.15)" : "rgba(34,197,94,0.15)"}` }}>
                                    <p style={{ fontSize: 11, fontWeight: 700, color: isFail ? "#ef4444" : "#22c55e", marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.5 }}>Actual</p>
                                    <p style={{ fontSize: 12, lineHeight: 1.5, color: "var(--text-secondary)" }}>{f.actual}</p>
                                  </div>
                                </div>
                              )}

                              {/* Recommendation */}
                              {f.recommendation && (
                                <div style={{ marginBottom: 16, padding: "12px 16px", background: `${borderColor}08`, borderRadius: 10, border: `1px solid ${borderColor}20` }}>
                                  <p style={{ fontSize: 12, fontWeight: 600, color: borderColor, marginBottom: 4 }}>
                                    <Icon name="circle-check" size={12} style={{ marginRight: 4 }} /> Recommendation
                                  </p>
                                  <p style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text-secondary)" }}>{f.recommendation}</p>
                                  {isFail && meta && (
                                    <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                                      Priority: {meta.action} · Timeline: {meta.timeline}
                                    </p>
                                  )}
                                </div>
                              )}

                              {/* Remediation Command */}
                              {isFail && f.remediation_step && (
                                <div style={{ background: "var(--bg-tertiary)", borderRadius: 10, overflow: "hidden" }}>
                                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 14px", background: "rgba(0,0,0,0.03)", borderBottom: "1px solid var(--border-color)" }}>
                                    <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)" }}>Remediation — AWS CLI</span>
                                    <button onClick={() => handleCopy(f.remediation_step, i)}
                                      style={{ fontSize: 11, background: "none", border: "none", cursor: "pointer", color: "var(--accent-primary)", display: "flex", alignItems: "center", gap: 4 }}>
                                      {copiedId === i ? "Copied!" : "Copy"}
                                    </button>
                                  </div>
                                  <div style={{ padding: "12px 14px", fontSize: 12, fontFamily: "monospace", color: "var(--text-secondary)", whiteSpace: "pre-wrap", wordBreak: "break-all", lineHeight: 1.6 }}>
                                    {f.remediation_step}
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* ── CloudTrail Event Feed ── */}
          <div className="glass-card">
            <div className="card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3><Icon name="clock" size={18} style={{ marginRight: 8, verticalAlign: "middle" }} /> CloudTrail Event Feed</h3>
              <button onClick={fetchEvents} style={{
                padding: "4px 14px", borderRadius: 6, fontSize: 12, fontWeight: 500,
                background: "var(--bg-tertiary)", color: "var(--text-secondary)",
                border: "none", cursor: "pointer",
              }}>
                <Icon name="refresh" size={12} /> Refresh
              </button>
            </div>
            <div className="card-body" ref={feedRef} style={{ maxHeight: 300, overflowY: "auto" }}>
              {events.length === 0 ? (
                <p style={{ textAlign: "center", color: "var(--text-secondary)", padding: 24 }}>
                  {scanResults ? "No CloudTrail events found in the last 24 hours." : "Run a scan to load events."}
                </p>
              ) : (
                events.map((evt, i) => (
                  <div key={i}
                    style={{
                      padding: "10px 14px", borderBottom: "1px solid var(--border-color)",
                      display: "flex", alignItems: "center", gap: 10,
                      background: evt.status === "FAIL" ? "rgba(239, 68, 68, 0.03)" : evt.status === "WARN" ? "rgba(234, 179, 8, 0.03)" : "transparent",
                    }}>
                    <div style={{
                      width: 8, height: 8, borderRadius: "50%", flexShrink: 0,
                      background: evt.status === "FAIL" ? "#ef4444" : evt.status === "WARN" ? "#eab308" : "#22c55e",
                    }}></div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13, fontWeight: 500 }}>
                        {evt.event_name}
                        {evt.alert && (
                          <span style={{ fontSize: 11, color: getSeverityColor(evt.severity), marginLeft: 8 }}>
                            {evt.alert}
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                        {evt.event_source} | {evt.username} | {evt.source_ip || "N/A"}
                      </div>
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
                      {evt.event_time ? new Date(evt.event_time).toLocaleTimeString() : ""}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </>
      )}

      {scanResults?.error && (
        <div className="glass-card" style={{ padding: 24, textAlign: "center" }}>
          <p style={{ color: "#ef4444" }}>Scan failed: {scanResults.error}</p>
        </div>
      )}

      {!scanResults && !scanning && (
        <div className="glass-card" style={{ padding: 48, textAlign: "center" }}>
          <div style={{ width: 64, height: 64, borderRadius: 16, background: "rgba(255, 153, 0, 0.1)", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 16px" }}>
            <Icon name="search" size={32} />
          </div>
          <h3>Ready to Scan</h3>
          <p style={{ color: "var(--text-secondary)", maxWidth: 400, margin: "0 auto" }}>
            Click "Run Live Scan" to analyze your AWS infrastructure against CIS Benchmarks.
            This will check S3 buckets, security groups, IAM policies, users, and CloudTrail events.
          </p>
        </div>
      )}
    </div>
  );
}
