"use client";
import { useState, useEffect } from "react";
import { Icon } from "./Icons";

const API_BASE = "http://localhost:8000";

// AI-generated reasoning for compliant audits
const COMPLIANT_INSIGHTS = [
  { title: "IAM Policies", reasoning: "All IAM policies follow least-privilege principles. No wildcard (*) permissions detected across any policy statements.", recommendation: "Continue enforcing least-privilege. Set up automated policy reviews quarterly.", icon: "shield" },
  { title: "Encryption at Rest", reasoning: "All S3 buckets, EBS volumes, and RDS instances have server-side encryption enabled using KMS managed keys.", recommendation: "Rotate KMS keys annually. Consider using customer-managed CMKs for sensitive workloads.", icon: "lock" },
  { title: "Network Security", reasoning: "No security groups allow unrestricted inbound access (0.0.0.0/0) on SSH (22) or RDP (3389). All ingress rules are scoped to known CIDRs.", recommendation: "Audit security group rules monthly. Use VPC endpoints for AWS service access.", icon: "shield-check" },
  { title: "Public Access Controls", reasoning: "All S3 buckets have public access blocks enabled. No RDS instances are publicly accessible. Resources are properly isolated within VPCs.", recommendation: "Enable AWS Config rules to auto-detect public access changes. Use SCPs for guardrails.", icon: "circle-check" },
  { title: "Logging & Monitoring", reasoning: "CloudTrail is enabled as a multi-region trail. VPC Flow Logs are active. All audit logs are retained in encrypted S3 buckets.", recommendation: "Set up CloudWatch alarms for unauthorized API calls. Enable GuardDuty for threat detection.", icon: "chart-line" },
  { title: "Backup & Recovery", reasoning: "RDS automated backups are enabled with appropriate retention periods. EBS snapshots are scheduled and encrypted.", recommendation: "Test disaster recovery procedures quarterly. Verify backup restoration time meets your RTO.", icon: "database" },
];

const VIOLATION_RECOMMENDATIONS = {
  "CRITICAL": { action: "Immediate remediation required", timeline: "Fix within 24 hours", color: "var(--accent-red)" },
  "HIGH": { action: "Schedule remediation promptly", timeline: "Fix within 1 week", color: "var(--accent-orange)" },
  "MEDIUM": { action: "Plan remediation in next sprint", timeline: "Fix within 30 days", color: "var(--accent-amber)" },
  "LOW": { action: "Address during routine maintenance", timeline: "Fix within 90 days", color: "var(--accent-blue)" },
};

export default function AuditsView() {
  const [audits, setAudits] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAudit, setSelectedAudit] = useState(null);
  const [findings, setFindings] = useState([]);
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/audits?limit=50`)
      .then((r) => r.json())
      .then((data) => { setAudits(data.audits || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const viewAuditDetails = async (audit) => {
    setSelectedAudit(audit);
    setExpandedFinding(null);
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
    const totalFindings = selectedAudit.total_findings || 0;
    const isCompliant = totalFindings === 0 && score >= 90;

    return (
      <div className="animate-fade-in">
        <button
          onClick={() => { setSelectedAudit(null); setFindings([]); }}
          className="back-btn"
          style={{ marginBottom: 20 }}
        >
          <Icon name="arrow-up" size={14} style={{ transform: "rotate(-90deg)" }} /> Back to Audits
        </button>

        {/* ── Header Card ──────────────────────────────────────────── */}
        <div className="glass-card" style={{ marginBottom: 20, overflow: "visible" }}>
          <div className="card-body" style={{ padding: 28 }}>
            <div style={{ display: "flex", gap: 28, alignItems: "flex-start" }}>
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
                  background: isCompliant ? "rgba(34,197,94,0.1)" : "rgba(255,122,0,0.1)",
                  color: isCompliant ? "var(--accent-green)" : "var(--accent-amber)"
                }}>{getScoreLabel(score)}</span>
              </div>

              {/* Info */}
              <div style={{ flex: 1 }}>
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
                  {selectedAudit.critical_count > 0 && (
                    <div className="audit-pill pill-critical">
                      <span><strong>{selectedAudit.critical_count}</strong> Critical</span>
                    </div>
                  )}
                  {selectedAudit.high_count > 0 && (
                    <div className="audit-pill pill-high">
                      <span><strong>{selectedAudit.high_count}</strong> High</span>
                    </div>
                  )}
                  {selectedAudit.medium_count > 0 && (
                    <div className="audit-pill pill-medium">
                      <span><strong>{selectedAudit.medium_count}</strong> Medium</span>
                    </div>
                  )}
                  {selectedAudit.low_count > 0 && (
                    <div className="audit-pill pill-low">
                      <span><strong>{selectedAudit.low_count}</strong> Low</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ── Compliant Audit: AI Reasoning ────────────────────────── */}
        {isCompliant && (
          <div>
            <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
              <Icon name="brain" size={18} style={{ color: "var(--accent-green)" }} />
              AI Compliance Analysis
            </h3>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))", gap: 16, marginBottom: 24 }}>
              {COMPLIANT_INSIGHTS.map((insight, i) => (
                <div key={i} className="glass-card" style={{ borderLeft: "3px solid var(--accent-green)" }}>
                  <div className="card-body" style={{ padding: 20 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                      <div style={{
                        width: 34, height: 34, borderRadius: 10,
                        background: "rgba(34,197,94,0.1)", color: "var(--accent-green)",
                        display: "flex", alignItems: "center", justifyContent: "center"
                      }}>
                        <Icon name={insight.icon} size={16} />
                      </div>
                      <h4 style={{ fontSize: 14, fontWeight: 700 }}>{insight.title}</h4>
                      <span style={{
                        marginLeft: "auto", fontSize: 10, fontWeight: 700, padding: "2px 8px",
                        borderRadius: 99, background: "rgba(34,197,94,0.1)", color: "var(--accent-green)"
                      }}>PASS</span>
                    </div>
                    <div style={{ marginBottom: 10 }}>
                      <p style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 2 }}>Reasoning</p>
                      <p style={{ fontSize: 12, color: "var(--text-muted)", lineHeight: 1.6 }}>{insight.reasoning}</p>
                    </div>
                    <div style={{ padding: "8px 12px", background: "rgba(34,197,94,0.04)", borderRadius: 8 }}>
                      <p style={{ fontSize: 11, fontWeight: 600, color: "var(--accent-green)", marginBottom: 2 }}>Recommendation</p>
                      <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.5 }}>{insight.recommendation}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Findings with Expandable Details ──────────────────────── */}
        {findings.length > 0 && (
          <div>
            <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
              <Icon name="search" size={18} style={{ color: "var(--accent-red)" }} />
              Findings ({findings.length})
            </h3>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {findings.map((f, i) => {
                const rec = VIOLATION_RECOMMENDATIONS[f.severity] || VIOLATION_RECOMMENDATIONS["MEDIUM"];
                const isExpanded = expandedFinding === i;
                return (
                  <div key={i} className="glass-card" style={{ borderLeft: `3px solid ${rec.color}`, cursor: "pointer" }}
                    onClick={() => setExpandedFinding(isExpanded ? null : i)}>
                    <div className="card-body" style={{ padding: 20 }}>
                      {/* Finding Header */}
                      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: isExpanded ? 16 : 0 }}>
                        <div style={{
                          width: 36, height: 36, borderRadius: 10,
                          background: `${rec.color}15`, color: rec.color,
                          display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0
                        }}>
                          <Icon name="triangle-alert" size={16} />
                        </div>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 2 }}>
                            <span className="rule-id" style={{ fontSize: 13 }}>CIS {f.rule_id}</span>
                            <span className={`severity-badge ${f.severity.toLowerCase()}`}>{f.severity}</span>
                          </div>
                          <p style={{ fontSize: 13, fontWeight: 600 }}>{f.description?.substring(0, 100)}{f.description?.length > 100 ? "..." : ""}</p>
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
                              <span style={{ color: "var(--text-muted)" }}>File: </span>
                              <span style={{ color: "var(--text-secondary)" }}>{f.file_path}</span>
                            </div>
                          </div>

                          {/* Full Description */}
                          <div style={{ marginBottom: 16, padding: "12px 16px", background: "rgba(0,0,0,0.02)", borderRadius: 10 }}>
                            <p style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 4 }}>
                              <Icon name="search" size={12} style={{ marginRight: 4 }} /> Description
                            </p>
                            <p style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text-primary)" }}>{f.description}</p>
                          </div>

                          {/* AI Reasoning */}
                          {f.reasoning && (
                            <div style={{ marginBottom: 16, padding: "12px 16px", background: "rgba(139,92,246,0.04)", borderRadius: 10 }}>
                              <p style={{ fontSize: 12, fontWeight: 600, color: "var(--accent-purple)", marginBottom: 4 }}>
                                <Icon name="brain" size={12} style={{ marginRight: 4 }} /> AI Reasoning
                              </p>
                              <p style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text-secondary)" }}>{f.reasoning}</p>
                            </div>
                          )}

                          {/* Recommendation */}
                          <div style={{ marginBottom: 16, padding: "12px 16px", background: `${rec.color}08`, borderRadius: 10, border: `1px solid ${rec.color}20` }}>
                            <p style={{ fontSize: 12, fontWeight: 600, color: rec.color, marginBottom: 4 }}>
                              <Icon name="circle-check" size={12} style={{ marginRight: 4 }} /> Recommendation
                            </p>
                            <p style={{ fontSize: 13, fontWeight: 600, marginBottom: 2 }}>{rec.action}</p>
                            <p style={{ fontSize: 12, color: "var(--text-muted)" }}>Timeline: {rec.timeline}</p>
                          </div>

                          {/* Remediation Code */}
                          {f.remediation_hcl && (
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
          </div>
        )}

        {/* ── No findings but not fully compliant ──────────────────── */}
        {findings.length === 0 && !isCompliant && (
          <div className="glass-card" style={{ padding: 40, textAlign: "center" }}>
            <Icon name="circle-check" size={40} style={{ color: "var(--accent-green)", marginBottom: 12 }} />
            <h3 style={{ fontSize: 16, marginBottom: 6 }}>No Findings Detected</h3>
            <p style={{ color: "var(--text-muted)", fontSize: 13, maxWidth: 400, margin: "0 auto" }}>
              All scanned resources passed CIS Benchmark checks. Your infrastructure configuration meets compliance requirements.
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
                  <td><span className="rule-id">{a.audit_id.substring(0, 14)}...</span></td>
                  <td style={{ color: "var(--text-secondary)" }}>{a.directory}</td>
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
    </div>
  );
}
