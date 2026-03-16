"use client";
import { useState, useEffect } from "react";
import { Icon } from "./Icons";

const API_BASE = "http://localhost:8000";

export default function AuditsView() {
  const [audits, setAudits] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAudit, setSelectedAudit] = useState(null);
  const [findings, setFindings] = useState([]);

  useEffect(() => {
    fetch(`${API_BASE}/api/audits?limit=50`)
      .then((r) => r.json())
      .then((data) => { setAudits(data.audits || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const viewAuditDetails = async (audit) => {
    setSelectedAudit(audit);
    try {
      const res = await fetch(`${API_BASE}/api/audits/${audit.audit_id}`);
      const data = await res.json();
      setFindings(data.findings || []);
    } catch { setFindings([]); }
  };

  const getScoreColor = (score) => {
    if (score >= 75) return "var(--accent-green)";
    if (score >= 50) return "var(--accent-amber)";
    return "var(--accent-red)";
  };

  if (loading) {
    return (
      <div className="glass-card" style={{ padding: 48, textAlign: "center" }}>
        <div className="spinner" style={{ margin: "0 auto 16px", width: 32, height: 32 }} />
        <p style={{ color: "var(--text-muted)" }}>Loading audits...</p>
      </div>
    );
  }

  if (selectedAudit) {
    return (
      <div>
        <button
          onClick={() => { setSelectedAudit(null); setFindings([]); }}
          className="back-btn"
        >
          <Icon name="arrow-up" size={14} style={{ transform: "rotate(-90deg)" }} /> Back to Audits
        </button>

        <div className="glass-card" style={{ marginBottom: 20 }}>
          <div className="card-body">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
              <div>
                <h3 style={{ fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Audit {selectedAudit.audit_id}</h3>
                <p style={{ color: "var(--text-muted)", fontSize: 13 }}>
                  {selectedAudit.directory} · {new Date(selectedAudit.created_at).toLocaleString()}
                </p>
              </div>
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: 32, fontWeight: 800, color: getScoreColor(selectedAudit.compliance_score) }}>
                  {selectedAudit.compliance_score}%
                </div>
                <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase" }}>Compliance</span>
              </div>
            </div>
            <div className="audit-detail-stats">
              <div className="audit-detail-stat">
                <span className="audit-detail-stat-value">{selectedAudit.files_scanned}</span>
                <span className="audit-detail-stat-label">Files</span>
              </div>
              <div className="audit-detail-stat">
                <span className="audit-detail-stat-value">{selectedAudit.resources_scanned}</span>
                <span className="audit-detail-stat-label">Resources</span>
              </div>
              <div className="audit-detail-stat">
                <span className="audit-detail-stat-value" style={{ color: "var(--accent-red)" }}>{selectedAudit.critical_count}</span>
                <span className="audit-detail-stat-label">Critical</span>
              </div>
              <div className="audit-detail-stat">
                <span className="audit-detail-stat-value" style={{ color: "var(--accent-orange)" }}>{selectedAudit.high_count}</span>
                <span className="audit-detail-stat-label">High</span>
              </div>
              <div className="audit-detail-stat">
                <span className="audit-detail-stat-value" style={{ color: "var(--accent-amber)" }}>{selectedAudit.medium_count}</span>
                <span className="audit-detail-stat-label">Medium</span>
              </div>
              <div className="audit-detail-stat">
                <span className="audit-detail-stat-value" style={{ color: "var(--accent-blue)" }}>{selectedAudit.low_count}</span>
                <span className="audit-detail-stat-label">Low</span>
              </div>
            </div>
          </div>
        </div>

        {findings.length > 0 ? (
          <div className="glass-card">
            <div className="card-header">
              <h3><Icon name="search" size={16} style={{ marginRight: 6 }} /> Findings ({findings.length})</h3>
            </div>
            <div className="card-body" style={{ padding: 0, paddingBottom: 12 }}>
              <table className="findings-table">
                <thead><tr><th>Rule</th><th>Severity</th><th>Resource</th><th>File</th><th>Description</th></tr></thead>
                <tbody>
                  {findings.map((f, i) => (
                    <tr key={i}>
                      <td><span className="rule-id">CIS {f.rule_id}</span></td>
                      <td><span className={`severity-badge ${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                      <td><span className="resource-name">{f.resource_address}</span></td>
                      <td style={{ color: "var(--text-muted)" }}>{f.file_path}</td>
                      <td style={{ fontSize: 12 }}>{f.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <div className="glass-card" style={{ padding: 40, textAlign: "center" }}>
            <Icon name="circle-check" size={40} style={{ color: "var(--accent-green)", marginBottom: 12 }} />
            <h3 style={{ fontSize: 16, color: "var(--text-secondary)", marginBottom: 6 }}>No Findings</h3>
            <p style={{ color: "var(--text-muted)", fontSize: 13 }}>This audit completed with a clean bill of health.</p>
          </div>
        )}
      </div>
    );
  }

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
