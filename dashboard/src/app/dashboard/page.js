"use client";

import { useState, useEffect, useRef } from "react";
import Sidebar from "@/components/Sidebar";
import AuditsView from "@/components/AuditsView";
import TrendsView from "@/components/TrendsView";
import DriftAlertsView from "@/components/DriftAlertsView";
import CISRulesView from "@/components/CISRulesView";
import SettingsView from "@/components/SettingsView";
import ConnectView from "@/components/ConnectView";
import MonitoringView from "@/components/MonitoringView";
import TopologyView from "@/components/TopologyView";
import { Icon } from "@/components/Icons";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

const CLOUD_LOGOS = { aws: "/logos/aws.svg", azure: "/logos/azure.svg", gcp: "/logos/gcp.svg" };

const SEV_COLOR = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#3b82f6" };
const ALERT_ICON = { critical: "siren", high: "triangle-alert", medium: "clipboard", low: "circle-check" };

function getSourceLabel(audit) {
  const trigger = audit.triggered_by || "";
  const meta = audit.metadata_json || {};
  const domain = meta.domain || "";
  const provider = meta.provider || "";
  if (trigger === "cloud_monitoring" || domain === "cloud") {
    return { label: `${provider || "Cloud"} Monitoring`, logo: CLOUD_LOGOS[(provider || "").toLowerCase()] };
  }
  if (domain === "container") return { label: meta.target === "kubernetes" ? "K8s Scan" : "Docker Scan", logo: null };
  if (trigger === "github_sync" || trigger === "github") return { label: "GitHub Sync", logo: null };
  return { label: "Terraform Scan", logo: null };
}

function timeAgo(dateStr) {
  if (!dateStr) return "";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function DashboardOverview({ cloudStatuses, onNavigate }) {
  const [summary, setSummary] = useState(null);
  const [recentAudits, setRecentAudits] = useState([]);
  const [trendData, setTrendData] = useState(null);
  const [driftAlerts, setDriftAlerts] = useState([]);
  const [topFindings, setTopFindings] = useState([]);
  const [cloudScans, setCloudScans] = useState({});
  const [loading, setLoading] = useState(true);
  const chartRef = useRef(null);
  const chartInstance = useRef(null);

  useEffect(() => {
    Promise.all([
      fetch(`${API_BASE}/api/summary`).then(r => r.json()).catch(() => null),
      fetch(`${API_BASE}/api/audits?limit=8`).then(r => r.json()).catch(() => ({ audits: [] })),
      fetch(`${API_BASE}/api/trends?days=30`).then(r => r.json()).catch(() => ({ trends: [] })),
      fetch(`${API_BASE}/api/drift`).then(r => r.json()).catch(() => ({ alerts: [] })),
      fetch(`${API_BASE}/api/aws/scan/latest`).then(r => r.json()).catch(() => null),
      fetch(`${API_BASE}/api/azure/scan/latest`).then(r => r.json()).catch(() => null),
      fetch(`${API_BASE}/api/gcp/scan/latest`).then(r => r.json()).catch(() => null),
      fetch(`${API_BASE}/api/container/scan/latest`).then(r => r.json()).catch(() => null),
    ]).then(([sum, audits, trends, drift, aws, azure, gcp, container]) => {
      setSummary(sum);
      setRecentAudits(audits.audits || []);
      setDriftAlerts((drift.alerts || []).slice(0, 5));

      // Build trend chart data from /api/trends
      const t = trends.trends || [];
      if (t.length > 0) {
        setTrendData({
          labels: t.map(d => new Date(d.date).toLocaleDateString("en-US", { month: "short", day: "numeric" })),
          critical: t.map(d => d.critical_count || 0),
          high: t.map(d => d.high_count || 0),
          medium: t.map(d => d.medium_count || 0),
          scores: t.map(d => d.avg_compliance_score || 0),
        });
      }

      // Pull top FAIL findings from cloud scan caches
      const allFindings = [];
      if (aws?.cached && aws.audit?.findings) {
        aws.audit.findings.filter(f => f.status === "FAIL").slice(0, 5).forEach(f => allFindings.push({ ...f, _source: "AWS" }));
      }
      if (azure?.cached && azure.audit?.findings) {
        azure.audit.findings.filter(f => f.status === "FAIL").slice(0, 3).forEach(f => allFindings.push({ ...f, _source: "Azure" }));
      }
      if (gcp?.cached && gcp.audit?.findings) {
        gcp.audit.findings.filter(f => f.status === "FAIL").slice(0, 3).forEach(f => allFindings.push({ ...f, _source: "GCP" }));
      }
      if (container?.cached && container.audit?.findings) {
        container.audit.findings.filter(f => f.status === "FAIL").slice(0, 3).forEach(f => allFindings.push({ ...f, _source: "Container" }));
      }
      // If no cloud findings, pull from latest terraform audits
      if (allFindings.length === 0 && audits.audits?.length > 0) {
        const latestId = audits.audits[0]?.audit_id;
        if (latestId) {
          fetch(`${API_BASE}/api/audits/${latestId}`).then(r => r.json()).then(d => {
            const fails = (d.findings || []).filter(f => f.status === "FAIL").slice(0, 8);
            setTopFindings(fails.map(f => ({ ...f, _source: d.directory?.split(/[/\\]/).pop() || "Terraform" })));
          }).catch(() => {});
        }
      } else {
        setTopFindings(allFindings.slice(0, 8));
      }

      // Cloud scan summaries for the cards
      const scans = {};
      if (aws?.cached) scans.aws = { score: aws.audit?.health_score ?? 0, framework: aws.framework, scan_time: aws.scan_time, resources: aws.scan?.total_resources || 0, issues: (aws.audit?.findings || []).filter(f => f.status === "FAIL").length };
      if (azure?.cached) scans.azure = { score: azure.audit?.health_score ?? 0, framework: azure.framework, scan_time: azure.scan_time, resources: azure.scan?.total_resources || 0, issues: (azure.audit?.findings || []).filter(f => f.status === "FAIL").length };
      if (gcp?.cached) scans.gcp = { score: gcp.audit?.health_score ?? 0, framework: gcp.framework, scan_time: gcp.scan_time, resources: gcp.scan?.total_resources || 0, issues: (gcp.audit?.findings || []).filter(f => f.status === "FAIL").length };
      if (container?.cached) scans.container = { score: container.audit?.health_score ?? 0, framework: container.framework, scan_time: container.scan_time, resources: container.scan?.images_scanned || container.scan?.total || 0, issues: (container.audit?.findings || []).filter(f => f.status === "FAIL").length };
      setCloudScans(scans);
      setLoading(false);
    });
  }, []);

  // Trend chart
  useEffect(() => {
    if (!chartRef.current || !trendData) return;
    if (chartInstance.current) chartInstance.current.destroy();
    const { Chart, registerables } = require("chart.js");
    Chart.register(...registerables);
    const ctx = chartRef.current.getContext("2d");
    const makeGrad = (r, g, b) => {
      const g1 = ctx.createLinearGradient(0, 0, 0, 220);
      g1.addColorStop(0, `rgba(${r},${g},${b},0.25)`);
      g1.addColorStop(1, `rgba(${r},${g},${b},0)`);
      return g1;
    };
    chartInstance.current = new Chart(ctx, {
      type: "line",
      data: {
        labels: trendData.labels,
        datasets: [
          { label: "Critical", data: trendData.critical, borderColor: "#ef4444", backgroundColor: makeGrad(239,68,68), fill: true, tension: 0.4, pointRadius: 3, borderWidth: 2 },
          { label: "High", data: trendData.high, borderColor: "#f97316", backgroundColor: makeGrad(249,115,22), fill: true, tension: 0.4, pointRadius: 3, borderWidth: 2 },
          { label: "Medium", data: trendData.medium, borderColor: "#eab308", backgroundColor: makeGrad(234,179,8), fill: true, tension: 0.4, pointRadius: 3, borderWidth: 2 },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { intersect: false, mode: "index" },
        plugins: {
          legend: { position: "top", labels: { color: "#6b7280", font: { size: 11, weight: "600" }, usePointStyle: true, padding: 14 } },
          tooltip: { backgroundColor: "rgba(17,24,39,0.95)", titleColor: "#f1f5f9", bodyColor: "#94a3b8", borderColor: "rgba(99,102,241,0.2)", borderWidth: 1, cornerRadius: 8, padding: 10 },
        },
        scales: {
          x: { grid: { color: "rgba(0,0,0,0.04)" }, ticks: { color: "#9ca3af", font: { size: 10 } } },
          y: { beginAtZero: true, grid: { color: "rgba(0,0,0,0.04)" }, ticks: { color: "#9ca3af", font: { size: 10 }, stepSize: 5 } },
        },
        animation: { duration: 1000, easing: "easeInOutQuart" },
      },
    });
    return () => { if (chartInstance.current) chartInstance.current.destroy(); };
  }, [trendData]);

  const score = summary?.compliance_score ?? 0;
  const totalAudits = summary?.total_audits ?? 0;
  const totalFindings = summary?.total_findings ?? 0;
  const resourcesScanned = summary?.resources_scanned ?? 0;
  const sev = summary?.severity_breakdown || {};
  const sevMax = Math.max(sev.critical ?? 0, sev.high ?? 0, sev.medium ?? 0, sev.low ?? 0, 1);
  const connectedClouds = ["aws", "azure", "gcp"].filter(c => cloudStatuses?.[c]?.connected);

  const scoreColor = score >= 75 ? "#22c55e" : score >= 50 ? "#f97316" : "#ef4444";
  const radius = 60, circ = 2 * Math.PI * radius;
  const offset = circ - (score / 100) * circ;

  return (
    <>
      {/* ── Welcome Banner ─────────────────────────────────────── */}
      <div className="welcome-banner animate-fade-in">
        <div className="welcome-text">
          <h2>Welcome back</h2>
          <p>Live compliance status across all connected cloud environments and scans.</p>
        </div>
        <div className="welcome-date">
          <Icon name="calendar" size={16} />
          <span>{new Date().toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric" })}</span>
        </div>
      </div>

      {/* ── Top Stats Row ────────────────────────────────────────── */}
      <div className="dashboard-grid">
        <div className="glass-card stat-card stat-blue animate-slide-in stagger-1" style={{ cursor: "pointer" }} onClick={() => onNavigate("audits")}>
          <div className="stat-card-top">
            <div className="stat-icon"><Icon name="folder" size={22} /></div>
            <span className="stat-change positive"><Icon name="arrow-up" size={10} /> All time</span>
          </div>
          <div className="stat-value">{loading ? "—" : totalAudits}</div>
          <div className="stat-label">Total Audits</div>
          <div className="stat-bar"><div className="stat-bar-fill" style={{ width: `${Math.min(totalAudits * 5, 100)}%` }}></div></div>
        </div>

        <div className="glass-card stat-card stat-purple animate-slide-in stagger-2" style={{ cursor: "pointer" }} onClick={() => onNavigate("monitoring")}>
          <div className="stat-card-top">
            <div className="stat-icon"><Icon name="shield" size={22} /></div>
            <span className="stat-change positive">{connectedClouds.length} cloud{connectedClouds.length !== 1 ? "s" : ""}</span>
          </div>
          <div className="stat-value">{loading ? "—" : resourcesScanned}</div>
          <div className="stat-label">Resources Scanned</div>
          <div className="stat-bar"><div className="stat-bar-fill" style={{ width: `${Math.min(resourcesScanned / 5, 100)}%` }}></div></div>
        </div>

        <div className="glass-card stat-card stat-amber animate-slide-in stagger-3" style={{ cursor: "pointer" }} onClick={() => onNavigate("drift")}>
          <div className="stat-card-top">
            <div className="stat-icon"><Icon name="triangle-alert" size={22} /></div>
            {totalFindings > 0 && <span className="stat-change negative"><Icon name="arrow-up" size={10} /> {sev.critical ?? 0} critical</span>}
          </div>
          <div className="stat-value">{loading ? "—" : totalFindings}</div>
          <div className="stat-label">Open Violations</div>
          <div className="stat-bar"><div className="stat-bar-fill" style={{ width: `${Math.min(totalFindings / 3, 100)}%` }}></div></div>
        </div>

        <div className="glass-card stat-card stat-green animate-slide-in stagger-4" style={{ cursor: "pointer" }} onClick={() => onNavigate("audits")}>
          <div className="stat-card-top">
            <div className="stat-icon"><Icon name="circle-check" size={22} /></div>
            <span className="stat-change positive">{score.toFixed(1)}% score</span>
          </div>
          <div className="stat-value">{loading ? "—" : Math.max(0, resourcesScanned - totalFindings)}</div>
          <div className="stat-label">Passing Controls</div>
          <div className="stat-bar"><div className="stat-bar-fill" style={{ width: `${score}%` }}></div></div>
        </div>
      </div>

      {/* ── Score Ring + Trend Chart ─────────────────────────────── */}
      <div className="dashboard-row">
        {/* Score Ring */}
        <div className="glass-card score-gauge animate-slide-in stagger-1">
          <div className="score-ring">
            <svg viewBox="0 0 140 140">
              <circle cx="70" cy="70" r={radius} className="score-ring-bg" />
              <circle cx="70" cy="70" r={radius}
                className={`score-ring-fill ${score >= 75 ? "good" : score >= 50 ? "warn" : "bad"}`}
                strokeDasharray={circ} strokeDashoffset={offset}
                style={{ transition: "stroke-dashoffset 1.2s ease" }}
              />
            </svg>
            <div className="score-center">
              <div className={`score-value ${score >= 75 ? "good" : score >= 50 ? "warn" : "bad"}`}>{score.toFixed(1)}%</div>
              <div className="score-label">Compliance</div>
            </div>
          </div>
          <div className={`score-grade ${score >= 75 ? "good" : score >= 50 ? "warn" : "bad"}`}>
            Grade {score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F"}
          </div>
          {/* Cloud scan breakdown */}
          {Object.keys(cloudScans).length > 0 && (
            <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 8 }}>
              {Object.entries(cloudScans).map(([cloud, s]) => (
                <div key={cloud} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
                  {CLOUD_LOGOS[cloud]
                    ? <img src={CLOUD_LOGOS[cloud]} alt={cloud} style={{ width: 16, height: 16, objectFit: "contain" }} />
                    : <Icon name="shield" size={14} />
                  }
                  <span style={{ flex: 1, color: "var(--text-secondary)", textTransform: "capitalize" }}>{cloud}</span>
                  <span style={{ fontWeight: 700, color: s.score >= 75 ? "#22c55e" : s.score >= 50 ? "#f97316" : "#ef4444" }}>{s.score.toFixed(1)}%</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Trend Chart */}
        <div className="glass-card animate-slide-in stagger-3">
          <div className="card-header">
            <h3><Icon name="chart-line" size={18} style={{ marginRight: 8, verticalAlign: "middle", color: "var(--accent-cyan)" }} /> Violation Trend</h3>
            <span style={{ fontSize: 12, color: "var(--text-muted)" }}>Last 30 days</span>
          </div>
          <div className="chart-container">
            {trendData
              ? <canvas ref={chartRef} />
              : <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", fontSize: 13 }}>
                  {loading ? "Loading trends…" : "No trend data yet — run more scans to build history."}
                </div>
            }
          </div>
        </div>
      </div>

      {/* ── Connected Clouds ─────────────────────────────────────── */}
      {(connectedClouds.length > 0 || Object.keys(cloudScans).length > 0) && (
        <div className="glass-card animate-slide-in stagger-2" style={{ marginBottom: 24 }}>
          <div className="card-header">
            <h3><Icon name="cloud" size={18} style={{ marginRight: 8, verticalAlign: "middle", color: "var(--accent-blue)" }} /> Connected Environments</h3>
            <button onClick={() => onNavigate("monitoring")} style={{ fontSize: 12, color: "var(--accent-primary)", background: "none", border: "none", cursor: "pointer", fontWeight: 600 }}>
              View Monitoring →
            </button>
          </div>
          <div className="card-body">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 12 }}>
              {["aws", "azure", "gcp"].filter(c => cloudStatuses?.[c]?.connected).map(cloud => {
                const s = cloudScans[cloud];
                const connected = cloudStatuses?.[cloud]?.connected;
                return (
                  <div key={cloud} onClick={() => onNavigate("monitoring")} style={{ padding: "14px 16px", borderRadius: 12, border: "1px solid var(--border-color)", background: "var(--bg-tertiary)", cursor: "pointer", transition: "border-color 0.2s" }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = "var(--accent-primary)"}
                    onMouseLeave={e => e.currentTarget.style.borderColor = "var(--border-color)"}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                      <img src={CLOUD_LOGOS[cloud]} alt={cloud} style={{ width: 28, height: 28, objectFit: "contain" }} />
                      <div>
                        <div style={{ fontWeight: 700, fontSize: 13, color: "var(--text-primary)" }}>{cloud.toUpperCase()}</div>
                        <div style={{ fontSize: 10, color: connected ? "#22c55e" : "var(--text-muted)" }}>● {connected ? "Connected" : "Disconnected"}</div>
                      </div>
                      {s && <div style={{ marginLeft: "auto", fontWeight: 700, fontSize: 15, color: s.score >= 75 ? "#22c55e" : s.score >= 50 ? "#f97316" : "#ef4444" }}>{s.score.toFixed(1)}%</div>}
                    </div>
                    {s ? (
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, fontSize: 11 }}>
                        <div style={{ background: "rgba(0,0,0,0.2)", borderRadius: 6, padding: "5px 8px" }}>
                          <div style={{ color: "var(--text-muted)" }}>Resources</div>
                          <div style={{ fontWeight: 700, color: "var(--text-primary)" }}>{s.resources}</div>
                        </div>
                        <div style={{ background: "rgba(0,0,0,0.2)", borderRadius: 6, padding: "5px 8px" }}>
                          <div style={{ color: "var(--text-muted)" }}>Issues</div>
                          <div style={{ fontWeight: 700, color: s.issues > 0 ? "#ef4444" : "#22c55e" }}>{s.issues}</div>
                        </div>
                        <div style={{ background: "rgba(0,0,0,0.2)", borderRadius: 6, padding: "5px 8px", gridColumn: "1 / -1" }}>
                          <div style={{ color: "var(--text-muted)" }}>Framework · Last scan</div>
                          <div style={{ fontWeight: 600, color: "var(--text-secondary)" }}>{s.framework} · {s.scan_time ? new Date(s.scan_time).toLocaleString() : "—"}</div>
                        </div>
                      </div>
                    ) : (
                      <div style={{ fontSize: 12, color: "var(--text-muted)" }}>No scan yet — go to Monitoring to run a scan.</div>
                    )}
                  </div>
                );
              })}
              {/* Container scan card if present */}
              {cloudScans.container && (
                <div onClick={() => onNavigate("connect")} style={{ padding: "14px 16px", borderRadius: 12, border: "1px solid var(--border-color)", background: "var(--bg-tertiary)", cursor: "pointer" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                    <img src="/logos/docker.svg" alt="docker" style={{ width: 28, height: 28, objectFit: "contain" }} />
                    <div>
                      <div style={{ fontWeight: 700, fontSize: 13, color: "var(--text-primary)" }}>Container</div>
                      <div style={{ fontSize: 10, color: "#22c55e" }}>● Last scan available</div>
                    </div>
                    <div style={{ marginLeft: "auto", fontWeight: 700, fontSize: 15, color: cloudScans.container.score >= 75 ? "#22c55e" : cloudScans.container.score >= 50 ? "#f97316" : "#ef4444" }}>{cloudScans.container.score.toFixed(1)}%</div>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6, fontSize: 11 }}>
                    <div style={{ background: "rgba(0,0,0,0.2)", borderRadius: 6, padding: "5px 8px" }}>
                      <div style={{ color: "var(--text-muted)" }}>Images</div>
                      <div style={{ fontWeight: 700, color: "var(--text-primary)" }}>{cloudScans.container.resources}</div>
                    </div>
                    <div style={{ background: "rgba(0,0,0,0.2)", borderRadius: 6, padding: "5px 8px" }}>
                      <div style={{ color: "var(--text-muted)" }}>Issues</div>
                      <div style={{ fontWeight: 700, color: cloudScans.container.issues > 0 ? "#ef4444" : "#22c55e" }}>{cloudScans.container.issues}</div>
                    </div>
                  </div>
                </div>
              )}
              {connectedClouds.length === 0 && Object.keys(cloudScans).length === 0 && (
                <div style={{ gridColumn: "1 / -1", padding: "20px", textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
                  No cloud environments connected. <button onClick={() => onNavigate("connect")} style={{ color: "var(--accent-primary)", background: "none", border: "none", cursor: "pointer", fontWeight: 600 }}>Connect now →</button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Severity Breakdown + Recent Activity ────────────────── */}
      <div className="dashboard-row">
        <div className="glass-card animate-slide-in stagger-2">
          <div className="card-header">
            <h3><Icon name="shield" size={18} style={{ marginRight: 8, verticalAlign: "middle", color: "var(--accent-purple)" }} /> Severity Breakdown</h3>
          </div>
          <div className="card-body">
            <div className="severity-bars">
              {[["CRITICAL", sev.critical ?? 0], ["HIGH", sev.high ?? 0], ["MEDIUM", sev.medium ?? 0], ["LOW", sev.low ?? 0]].map(([label, count]) => (
                <div key={label} className="severity-bar-row">
                  <div className="severity-bar-label">
                    <span className="severity-dot" style={{ background: SEV_COLOR[label] }}></span>
                    <span>{label.charAt(0) + label.slice(1).toLowerCase()}</span>
                  </div>
                  <div className="severity-bar-track">
                    <div className="severity-bar-fill" style={{ width: `${Math.min((count / sevMax) * 100, 100)}%`, background: SEV_COLOR[label] }}></div>
                  </div>
                  <span className="severity-bar-count">{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="glass-card animate-slide-in stagger-3">
          <div className="card-header">
            <h3><Icon name="clock" size={18} style={{ marginRight: 8, verticalAlign: "middle", color: "var(--accent-cyan)" }} /> Recent Activity</h3>
            <button onClick={() => onNavigate("audits")} style={{ fontSize: 12, color: "var(--accent-primary)", background: "none", border: "none", cursor: "pointer", fontWeight: 600 }}>View all →</button>
          </div>
          <div className="card-body">
            <div className="activity-list">
              {recentAudits.length > 0 ? recentAudits.map((audit, i) => {
                const src = getSourceLabel(audit);
                return (
                  <div key={audit.audit_id || i} className="activity-item" onClick={() => onNavigate("audits")} style={{ cursor: "pointer" }}>
                    <div className={`activity-dot ${audit.compliance_score >= 75 ? "good" : audit.compliance_score >= 50 ? "warn" : "bad"}`}></div>
                    <div className="activity-info">
                      <span className="activity-title" style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        {src.logo && <img src={src.logo} alt="" style={{ width: 13, height: 13, objectFit: "contain" }} />}
                        {src.label}
                      </span>
                      <span className="activity-meta">
                        {audit.total_findings} issues · {audit.compliance_score?.toFixed(1)}%
                      </span>
                    </div>
                    <span className="activity-time">{timeAgo(audit.created_at)}</span>
                  </div>
                );
              }) : (
                <div style={{ textAlign: "center", padding: "24px 0", color: "var(--text-muted)", fontSize: 13 }}>
                  No scans yet. <button onClick={() => onNavigate("connect")} style={{ color: "var(--accent-primary)", background: "none", border: "none", cursor: "pointer", fontWeight: 600 }}>Run your first scan →</button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Top Findings ─────────────────────────────────────────── */}
      {topFindings.length > 0 && (
        <div className="glass-card animate-slide-in stagger-2" style={{ marginBottom: 24 }}>
          <div className="card-header">
            <h3><Icon name="search" size={18} style={{ marginRight: 8, verticalAlign: "middle", color: "var(--accent-cyan)" }} /> Top Violations</h3>
            <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>{topFindings.length} critical issues</span>
          </div>
          <div className="card-body" style={{ padding: "0 0 16px" }}>
            <table className="findings-table">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Resource</th>
                  <th>Source</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {topFindings.map((f, i) => (
                  <tr key={i} onClick={() => onNavigate(f._source === "AWS" || f._source === "Azure" || f._source === "GCP" ? "monitoring" : "audits")} style={{ cursor: "pointer" }}>
                    <td><span className="rule-id">{f.cis_rule_id || f.rule_id || "—"}</span></td>
                    <td><span className={`severity-badge ${(f.severity || "low").toLowerCase()}`}>{f.severity || "LOW"}</span></td>
                    <td><span className="resource-name" style={{ maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>{f.resource_name || f.resource_address || "—"}</span></td>
                    <td><span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)" }}>{f._source}</span></td>
                    <td style={{ color: "var(--text-secondary)", fontSize: 12 }}>{(f.title || f.rule_title || f.description || "").substring(0, 70)}{(f.title || f.rule_title || f.description || "").length > 70 ? "…" : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Drift Alerts ─────────────────────────────────────────── */}
      <div className="glass-card animate-slide-in stagger-4" style={{ marginBottom: 24 }}>
        <div className="card-header">
          <h3><Icon name="bell" size={18} style={{ marginRight: 8, verticalAlign: "middle", color: "var(--accent-amber)" }} /> Drift Detection Alerts</h3>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {driftAlerts.length > 0 && (
              <span style={{ fontSize: 12, padding: "3px 10px", background: "rgba(239,68,68,0.15)", color: "var(--accent-red)", borderRadius: 99, fontWeight: 600 }}>
                {driftAlerts.length} active
              </span>
            )}
            <button onClick={() => onNavigate("drift")} style={{ fontSize: 12, color: "var(--accent-primary)", background: "none", border: "none", cursor: "pointer", fontWeight: 600 }}>View all →</button>
          </div>
        </div>
        <div className="card-body">
          {driftAlerts.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon"><Icon name="circle-check" size={40} style={{ color: "var(--accent-green)" }} /></div>
              <h3>No Active Alerts</h3>
              <p>Your infrastructure compliance is stable with no drift detected.</p>
            </div>
          ) : (
            driftAlerts.map((alert) => (
              <div key={alert.id} className={`drift-alert ${alert.severity}`}>
                <span className="drift-alert-icon">
                  <Icon name={ALERT_ICON[alert.severity] || "clipboard"} size={20} />
                </span>
                <div className="drift-alert-content">
                  <h4>{alert.title}</h4>
                  <p>{alert.description}</p>
                  {alert.resource_address && (
                    <p style={{ marginTop: 4, fontFamily: "monospace", fontSize: 12, color: "var(--accent-purple)" }}>{alert.resource_address}</p>
                  )}
                </div>
                <span className="drift-alert-time">{timeAgo(alert.created_at) || alert.created_at}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </>
  );
}

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [mountedTabs, setMountedTabs] = useState(new Set(["dashboard"]));
  const [backendWaking, setBackendWaking] = useState(false);

  // Lift cloud status state so it persists across tab switches
  const [cloudStatuses, setCloudStatuses] = useState({
    aws: null,
    azure: null,
    gcp: null,
    loaded: false,
  });

  // Single fetch for all cloud statuses — runs once, shared across tabs
  useEffect(() => {
    let cancelled = false;
    const fetchStatuses = async () => {
      // Ping health first — detect Render cold start (>3s = waking up)
      const t0 = Date.now();
      try {
        await fetch(`${API_BASE}/api/health`, { signal: AbortSignal.timeout(4000) });
      } catch {
        setBackendWaking(true);
        // Wait for backend to fully wake (Render free tier ~30s)
        await new Promise(r => setTimeout(r, 20000));
        setBackendWaking(false);
      }
      try {
        const [awsRes, azureRes, gcpRes] = await Promise.all([
          fetch(`${API_BASE}/api/aws/status`).then(r => r.json()).catch(() => ({ connected: false })),
          fetch(`${API_BASE}/api/azure/status`).then(r => r.json()).catch(() => ({ connected: false })),
          fetch(`${API_BASE}/api/gcp/status`).then(r => r.json()).catch(() => ({ connected: false })),
        ]);
        if (!cancelled) {
          setCloudStatuses({ aws: awsRes, azure: azureRes, gcp: gcpRes, loaded: true });
        }
      } catch {
        if (!cancelled) {
          setCloudStatuses({ aws: { connected: false }, azure: { connected: false }, gcp: { connected: false }, loaded: true });
        }
      }
    };
    fetchStatuses();
    return () => { cancelled = true; };
  }, []);

  // Refresh cloud statuses (callable by child components)
  const refreshCloudStatuses = async () => {
    try {
      const [awsRes, azureRes, gcpRes] = await Promise.all([
        fetch(`${API_BASE}/api/aws/status`).then(r => r.json()).catch(() => ({ connected: false })),
        fetch(`${API_BASE}/api/azure/status`).then(r => r.json()).catch(() => ({ connected: false })),
        fetch(`${API_BASE}/api/gcp/status`).then(r => r.json()).catch(() => ({ connected: false })),
      ]);
      setCloudStatuses({ aws: awsRes, azure: azureRes, gcp: gcpRes, loaded: true });
    } catch {}
  };

  // Lazy-mount tabs: once visited, they stay mounted (preserves state)
  useEffect(() => {
    setMountedTabs(prev => {
      if (prev.has(activeTab)) return prev;
      const next = new Set(prev);
      next.add(activeTab);
      return next;
    });
  }, [activeTab]);

  // Render tabs with display:none for inactive ones (keeps state alive)
  const tabComponents = {
    dashboard: <DashboardOverview cloudStatuses={cloudStatuses} onNavigate={setActiveTab} />,
    audits:    <AuditsView />,
    connect:   <ConnectView cloudStatuses={cloudStatuses} onCloudStatusChange={refreshCloudStatuses} />,
    monitoring: <MonitoringView onNavigate={setActiveTab} cloudStatuses={cloudStatuses} onCloudStatusChange={refreshCloudStatuses} />,
    topology:  <TopologyView />,
    trends:    <TrendsView />,
    drift:     <DriftAlertsView />,
    rules:     <CISRulesView />,
    settings:  <SettingsView />,
  };

  // Topology needs full-bleed layout (no padding, full viewport height)
  const fullBleedTabs = new Set(["topology"]);

  return (
    <div className="app-layout">
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />
      {backendWaking && (
        <div style={{ position: "fixed", top: 0, left: 0, right: 0, zIndex: 9999, background: "linear-gradient(90deg, #f97316, #ff9f43)", color: "#fff", textAlign: "center", padding: "10px 16px", fontSize: 13, fontWeight: 600, display: "flex", alignItems: "center", justifyContent: "center", gap: 10 }}>
          <span style={{ width: 14, height: 14, border: "2px solid rgba(255,255,255,0.4)", borderTopColor: "#fff", borderRadius: "50%", display: "inline-block", animation: "spin 0.8s linear infinite" }} />
          Backend is waking up (Render free tier) — this takes ~30 seconds on first visit…
        </div>
      )}
      <main className="main-content" style={{ ...(fullBleedTabs.has(activeTab) ? { padding: 0 } : {}), ...(backendWaking ? { paddingTop: 44 } : {}) }}>
        {Object.entries(tabComponents).map(([key, component]) => (
          mountedTabs.has(key) && (
            <div
              key={key}
              style={{
                display: activeTab === key ? (fullBleedTabs.has(key) ? "flex" : "block") : "none",
                ...(fullBleedTabs.has(key) ? { height: "100vh", flexDirection: "column" } : {}),
              }}
            >
              {component}
            </div>
          )
        ))}
      </main>
    </div>
  );
}
