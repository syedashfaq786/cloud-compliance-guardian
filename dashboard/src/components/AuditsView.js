"use client";
import { useState, useEffect } from "react";
import { Icon } from "./Icons";

const API_BASE = "http://localhost:8000";

const SEVERITY_META = {
  "CRITICAL": { action: "Immediate remediation required", timeline: "Fix within 24 hours", color: "var(--accent-red)" },
  "HIGH": { action: "Schedule remediation promptly", timeline: "Fix within 1 week", color: "var(--accent-orange)" },
  "MEDIUM": { action: "Plan remediation in next sprint", timeline: "Fix within 30 days", color: "var(--accent-amber)" },
  "LOW": { action: "Address during routine maintenance", timeline: "Fix within 90 days", color: "var(--accent-blue)" },
};

const PROVIDER_ICON = { "AWS": "aws", "Azure": "azure", "GCP": "gcp" };

export default function AuditsView() {
  const [audits, setAudits] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAudit, setSelectedAudit] = useState(null);
  const [findings, setFindings] = useState([]);
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const [filterStatus, setFilterStatus] = useState("ALL"); // ALL, FAIL, PASS
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/api/audits?limit=50`)
      .then((r) => r.json())
      .then((data) => { setAudits(data.audits || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const viewAuditDetails = async (audit) => {
    setSelectedAudit(audit);
    setExpandedFinding(null);
    setFilterStatus("ALL");
    try {
      const res = await fetch(`${API_BASE}/api/audits/${audit.audit_id}`);
      const data = await res.json();
      setFindings(data.findings || []);
    } catch { setFindings([]); }
  };

  const handleCopy = (code, id) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const downloadReport = async (format) => {
    if (!selectedAudit) return;
    setDownloading(true);
    try {
      const res = await fetch(`${API_BASE}/api/audits/${selectedAudit.audit_id}/report?format=${format}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `audit-report-${selectedAudit.audit_id}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error("Download failed:", e);
    }
    setDownloading(false);
  };

  const getScoreColor = (score) => {
    if (score >= 75) return "var(--accent-green)";
    if (score >= 50) return "var(--accent-amber)";
    return "var(--accent-red)";
  };

  const getScoreLabel = (score) => {
    if (score >= 90) return "Excellent";
    if (score >= 75) return "Good";
    if (score >= 50) return "Needs Improvement";
    return "Critical";
  };

  if (loading) {
    return (
      <div className="glass-card" style={{ padding: 48, textAlign: "center" }}>
        <div className="spinner" style={{ margin: "0 auto 16px", width: 32, height: 32 }} />
        <p style={{ color: "var(--text-muted)" }}>Loading audits...</p>
      </div>
    );
  }

  // ── Audit Detail View ─────────────────────────────────────────────
  if (selectedAudit) {
    const score = selectedAudit.compliance_score;
    const failedFindings = findings.filter(f => f.status === "FAIL");
    const passedFindings = findings.filter(f => f.status === "PASS");

    const filteredFindings = filterStatus === "ALL" ? findings
      : filterStatus === "FAIL" ? failedFindings : passedFindings;

    // Group findings by cloud provider
    const providerGroups = {};
    for (const f of findings) {
      const p = f.cloud_provider || "Unknown";
      if (!providerGroups[p]) providerGroups[p] = { pass: 0, fail: 0 };
      if (f.status === "PASS") providerGroups[p].pass++;
      else providerGroups[p].fail++;
    }

    return (
      <div className="animate-fade-in">
        {/* ── Back + Download Buttons ────────────────────────────── */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20, flexWrap: "wrap", gap: 12 }}>
          <button
            onClick={() => { setSelectedAudit(null); setFindings([]); }}
            className="back-btn"
          >
            <Icon name="arrow-up" size={14} style={{ transform: "rotate(-90deg)" }} /> Back to Audits
          </button>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="save-btn" onClick={() => downloadReport("pdf")} disabled={downloading}
              style={{ display: "flex", alignItems: "center", gap: 6, padding: "8px 16px" }}>
              <Icon name="file-text" size={14} /> {downloading ? "Generating..." : "Download Report (PDF)"}
            </button>
            <button className="download-btn" onClick={() => downloadReport("csv")} disabled={downloading}>
              <Icon name="file-text" size={14} /> CSV
            </button>
            <button className="download-btn" onClick={() => downloadReport("json")} disabled={downloading}>
              <Icon name="file-text" size={14} /> JSON
            </button>
          </div>
        </div>

        {/* ── Header Card ──────────────────────────────────────────── */}
        <div className="glass-card" style={{ marginBottom: 20, overflow: "visible" }}>
          <div className="card-body" style={{ padding: 28 }}>
            <div style={{ display: "flex", gap: 28, alignItems: "flex-start", flexWrap: "wrap" }}>
              {/* Score Circle */}
              <div style={{ textAlign: "center", flexShrink: 0 }}>
                <div style={{
                  width: 100, height: 100, borderRadius: "50%",
                  background: `conic-gradient(${getScoreColor(score)} ${score * 3.6}deg, var(--border-glass) 0deg)`,
                  display: "flex", alignItems: "center", justifyContent: "center", padding: 6
                }}>
                  <div style={{
                    width: "100%", height: "100%", borderRadius: "50%",
                    background: "var(--bg-card)", display: "flex", flexDirection: "column",
                    alignItems: "center", justifyContent: "center"
                  }}>
                    <span style={{ fontSize: 26, fontWeight: 800, color: getScoreColor(score), lineHeight: 1 }}>{score}%</span>
                    <span style={{ fontSize: 9, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 1 }}>Score</span>
                  </div>
                </div>
                <span style={{
                  display: "inline-block", marginTop: 8, fontSize: 11, fontWeight: 700,
                  padding: "3px 12px", borderRadius: 99,
                  background: score >= 75 ? "rgba(34,197,94,0.1)" : "rgba(255,122,0,0.1)",
                  color: score >= 75 ? "var(--accent-green)" : "var(--accent-amber)"
                }}>{getScoreLabel(score)}</span>
              </div>

              {/* Info */}
              <div style={{ flex: 1, minWidth: 240 }}>
                <h2 style={{ fontSize: 20, fontWeight: 800, marginBottom: 4 }}>
                  Audit Report
                </h2>
                <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 4 }}>
                  ID: {selectedAudit.audit_id}
                </p>
                <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 16 }}>
                  <Icon name="folder" size={12} style={{ marginRight: 4 }} />
                  {selectedAudit.directory} · {new Date(selectedAudit.created_at).toLocaleString()}
                </p>

                {/* Stat Pills */}
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                  <div className="audit-pill">
                    <Icon name="folder" size={14} />
                    <span><strong>{selectedAudit.files_scanned}</strong> Files</span>
                  </div>
                  <div className="audit-pill">
                    <Icon name="shield" size={14} />
                    <span><strong>{selectedAudit.resources_scanned}</strong> Resources</span>
                  </div>
                  <div className="audit-pill" style={{ background: "rgba(34,197,94,0.08)", color: "var(--accent-green)" }}>
                    <Icon name="circle-check" size={14} />
                    <span><strong>{passedFindings.length}</strong> Passed</span>
                  </div>
                  <div className="audit-pill" style={{ background: "rgba(239,68,68,0.08)", color: "var(--accent-red)" }}>
                    <Icon name="triangle-alert" size={14} />
                    <span><strong>{failedFindings.length}</strong> Failed</span>
                  </div>
                </div>
              </div>

              {/* Provider Breakdown */}
              <div style={{ flexShrink: 0 }}>
                <p style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>By Provider</p>
                {Object.entries(providerGroups).map(([provider, counts]) => (
                  <div key={provider} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                    <Icon name={PROVIDER_ICON[provider] || "cloud"} size={16} />
                    <span style={{ fontSize: 13, fontWeight: 600, minWidth: 40 }}>{provider}</span>
                    <span style={{ fontSize: 11, color: "var(--accent-green)" }}>{counts.pass} pass</span>
                    <span style={{ fontSize: 11, color: "var(--accent-red)" }}>{counts.fail} fail</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Severity Summary Strip */}
            {failedFindings.length > 0 && (
              <div style={{ display: "flex", gap: 16, marginTop: 20, padding: "12px 16px", background: "rgba(0,0,0,0.02)", borderRadius: 10 }}>
                {Object.entries(SEVERITY_META).map(([sev, meta]) => {
                  const count = failedFindings.filter(f => f.severity === sev).length;
                  return count > 0 ? (
                    <div key={sev} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <div style={{ width: 8, height: 8, borderRadius: "50%", background: meta.color }} />
                      <span style={{ fontSize: 12, fontWeight: 600 }}>{count} {sev}</span>
                    </div>
                  ) : null;
                })}
              </div>
            )}
          </div>
        </div>

        {/* ── Filter Tabs ──────────────────────────────────────────── */}
        <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
          {[
            { key: "ALL", label: `All Checks (${findings.length})` },
            { key: "FAIL", label: `Failed (${failedFindings.length})` },
            { key: "PASS", label: `Passed (${passedFindings.length})` },
          ].map(tab => (
            <button key={tab.key}
              onClick={() => setFilterStatus(tab.key)}
              className={`filter-tab ${filterStatus === tab.key ? "active" : ""}`}
              style={{
                padding: "6px 16px", borderRadius: 8, border: "1px solid var(--border-glass)",
                background: filterStatus === tab.key ? "var(--accent-primary)" : "var(--bg-card)",
                color: filterStatus === tab.key ? "#fff" : "var(--text-secondary)",
                fontWeight: 600, fontSize: 12, cursor: "pointer"
              }}
            >{tab.label}</button>
          ))}
        </div>

        {/* ── Findings List ──────────────────────────────────────────── */}
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {filteredFindings.map((f, i) => {
            const meta = SEVERITY_META[f.severity] || SEVERITY_META["MEDIUM"];
            const isExpanded = expandedFinding === i;
            const isFail = f.status === "FAIL";
            const borderColor = isFail ? meta.color : "var(--accent-green)";

            return (
              <div key={i} className="glass-card" style={{ borderLeft: `3px solid ${borderColor}`, cursor: "pointer" }}
                onClick={() => setExpandedFinding(isExpanded ? null : i)}>
                <div className="card-body" style={{ padding: 20 }}>
                  {/* Finding Header */}
                  <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: isExpanded ? 16 : 0 }}>
                    <div style={{
                      width: 36, height: 36, borderRadius: 10,
                      background: isFail ? `${meta.color}15` : "rgba(34,197,94,0.1)",
                      color: isFail ? meta.color : "var(--accent-green)",
                      display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0
                    }}>
                      <Icon name={isFail ? "triangle-alert" : "circle-check"} size={16} />
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 2, flexWrap: "wrap" }}>
                        <span className="rule-id" style={{ fontSize: 13 }}>CIS {f.rule_id}</span>
                        <span className={`severity-badge ${f.severity.toLowerCase()}`}>{f.severity}</span>
                        <span style={{
                          fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 99,
                          background: isFail ? "rgba(239,68,68,0.1)" : "rgba(34,197,94,0.1)",
                          color: isFail ? "var(--accent-red)" : "var(--accent-green)",
                        }}>{f.status}</span>
                        {f.cloud_provider && (
                          <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 11, color: "var(--text-muted)" }}>
                            <Icon name={PROVIDER_ICON[f.cloud_provider] || "cloud"} size={12} /> {f.cloud_provider}
                          </span>
                        )}
                      </div>
                      <p style={{ fontSize: 13, fontWeight: 600 }}>{f.rule_title}</p>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 12, flexShrink: 0 }}>
                      <span className="resource-name" style={{ fontSize: 11 }}>{f.resource_address}</span>
                      <Icon name={isExpanded ? "arrow-up" : "arrow-down"} size={14} style={{ color: "var(--text-muted)" }} />
                    </div>
                  </div>

                  {/* Expanded Detail */}
                  {isExpanded && (
                    <div className="animate-fade-in" onClick={(e) => e.stopPropagation()}>
                      {/* Resource & File Info */}
                      <div style={{ display: "flex", gap: 20, marginBottom: 16, flexWrap: "wrap" }}>
                        <div style={{ fontSize: 12 }}>
                          <span style={{ color: "var(--text-muted)" }}>Resource: </span>
                          <span className="resource-name">{f.resource_address}</span>
                        </div>
                        <div style={{ fontSize: 12 }}>
                          <span style={{ color: "var(--text-muted)" }}>Type: </span>
                          <span style={{ color: "var(--text-secondary)" }}>{f.resource_type}</span>
                        </div>
                        <div style={{ fontSize: 12 }}>
                          <span style={{ color: "var(--text-muted)" }}>File: </span>
                          <span style={{ color: "var(--text-secondary)" }}>{f.file_path}</span>
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
                          <p style={{ fontSize: 12, fontWeight: 600, color: "var(--accent-purple)", marginBottom: 4 }}>
                            <Icon name="brain" size={12} style={{ marginRight: 4 }} /> Reasoning
                          </p>
                          <p style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text-secondary)" }}>{f.reasoning}</p>
                        </div>
                      )}

                      {/* Expected vs Actual */}
                      {(f.expected || f.actual) && (
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
                          <div style={{ padding: "12px 16px", background: "rgba(34,197,94,0.04)", borderRadius: 10, border: "1px solid rgba(34,197,94,0.15)" }}>
                            <p style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-green)", marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.5 }}>Expected</p>
                            <p style={{ fontSize: 12, lineHeight: 1.5, color: "var(--text-secondary)" }}>{f.expected}</p>
                          </div>
                          <div style={{ padding: "12px 16px", background: isFail ? "rgba(239,68,68,0.04)" : "rgba(34,197,94,0.04)", borderRadius: 10, border: `1px solid ${isFail ? "rgba(239,68,68,0.15)" : "rgba(34,197,94,0.15)"}` }}>
                            <p style={{ fontSize: 11, fontWeight: 700, color: isFail ? "var(--accent-red)" : "var(--accent-green)", marginBottom: 4, textTransform: "uppercase", letterSpacing: 0.5 }}>Actual</p>
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

                      {/* Remediation Code */}
                      {isFail && f.remediation_hcl && (
                        <div className="code-block">
                          <div className="code-header">
                            <span>Remediation — HCL</span>
                            <button className="code-copy-btn" onClick={() => handleCopy(f.remediation_hcl, i)}>
                              {copiedId === i ? <><Icon name="check" size={12} /> Copied!</> : <><Icon name="copy" size={12} /> Copy</>}
                            </button>
                          </div>
                          <div className="code-content">{f.remediation_hcl}</div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* ── No Findings at all ──────────────────────────────────── */}
        {findings.length === 0 && (
          <div className="glass-card" style={{ padding: 40, textAlign: "center" }}>
            <Icon name="circle-check" size={40} style={{ color: "var(--accent-green)", marginBottom: 12 }} />
            <h3 style={{ fontSize: 16, marginBottom: 6 }}>No Checks Performed</h3>
            <p style={{ color: "var(--text-muted)", fontSize: 13, maxWidth: 400, margin: "0 auto" }}>
              No applicable CIS rules were found for the scanned resources. This may happen if the Terraform files don't contain auditable resource types.
            </p>
          </div>
        )}
      </div>
    );
  }

  // ── Audit List View ───────────────────────────────────────────────
  return (
    <div>
      <div className="page-header">
        <h2>Audit History</h2>
        <p>View past compliance scans and their results</p>
      </div>

      {audits.length === 0 ? (
        <div className="glass-card" style={{ padding: 48, textAlign: "center" }}>
          <Icon name="folder" size={40} style={{ color: "var(--text-muted)", marginBottom: 12 }} />
          <h3 style={{ fontSize: 16, marginBottom: 6, color: "var(--text-secondary)" }}>No Audits Yet</h3>
          <p style={{ color: "var(--text-muted)", fontSize: 13, maxWidth: 400, margin: "0 auto" }}>
            Run your first scan from the Connect tab by uploading Terraform files or connecting a GitHub repository.
          </p>
        </div>
      ) : (
        <div className="glass-card">
          <div className="card-body" style={{ padding: 0, paddingBottom: 12 }}>
            <table className="findings-table">
              <thead>
                <tr>
                  <th>Audit ID</th>
                  <th>Directory</th>
                  <th>Score</th>
                  <th>Findings</th>
                  <th>Triggered By</th>
                  <th>Date</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {audits.map((a, i) => (
                  <tr key={i} onClick={() => viewAuditDetails(a)} style={{ cursor: "pointer" }}>
                    <td><span className="rule-id">{a.audit_id.substring(0, 12)}</span></td>
                    <td style={{ color: "var(--text-secondary)", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {a.directory.split(/[/\\]/).pop() || a.directory}
                    </td>
                    <td>
                      <span style={{ fontWeight: 700, color: getScoreColor(a.compliance_score) }}>
                        {a.compliance_score}%
                      </span>
                    </td>
                    <td>
                      <span style={{ display: "inline-flex", gap: 6, alignItems: "center", fontSize: 12 }}>
                        {a.critical_count > 0 && <span style={{ color: "var(--accent-red)" }}>{a.critical_count}C</span>}
                        {a.high_count > 0 && <span style={{ color: "var(--accent-orange)" }}>{a.high_count}H</span>}
                        {a.medium_count > 0 && <span style={{ color: "var(--accent-amber)" }}>{a.medium_count}M</span>}
                        {a.low_count > 0 && <span style={{ color: "var(--accent-blue)" }}>{a.low_count}L</span>}
                        {a.total_findings === 0 && <span style={{ color: "var(--accent-green)" }}>Clean</span>}
                      </span>
                    </td>
                    <td>
                      <span className="trigger-badge">{a.triggered_by}</span>
                    </td>
                    <td style={{ color: "var(--text-muted)", fontSize: 12 }}>
                      {new Date(a.created_at).toLocaleDateString()}
                    </td>
                    <td>
                      <Icon name="arrow-up" size={14} style={{ transform: "rotate(90deg)", color: "var(--text-muted)" }} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
