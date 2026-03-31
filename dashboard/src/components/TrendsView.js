"use client";
import { useState, useEffect, useRef } from "react";
import { Chart as ChartJS, registerables } from "chart.js";
import { Icon } from "./Icons";

ChartJS.register(...registerables);

const API_BASE = "http://localhost:8000";

export default function TrendsView() {
  const [trends, setTrends] = useState([]);
  const [loading, setLoading] = useState(true);
  const [period, setPeriod] = useState("30");
  const violationChartRef = useRef(null);
  const scoreChartRef = useRef(null);
  const violationInstance = useRef(null);
  const scoreInstance = useRef(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/trends?days=${period}`)
      .then((r) => r.json())
      .then((data) => { setTrends(data.trends || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [period]);

  useEffect(() => {
    if (!trends.length || !violationChartRef.current || !scoreChartRef.current) return;

    // Destroy existing charts
    if (violationInstance.current) violationInstance.current.destroy();
    if (scoreInstance.current) scoreInstance.current.destroy();

    const labels = trends.map((t) => new Date(t.date).toLocaleDateString("en-US", { month: "short", day: "numeric" }));

    // Violation Trend Chart
    const vCtx = violationChartRef.current.getContext("2d");
    const critGrad = vCtx.createLinearGradient(0, 0, 0, 300);
    critGrad.addColorStop(0, "rgba(239, 68, 68, 0.3)");
    critGrad.addColorStop(1, "rgba(239, 68, 68, 0)");
    const highGrad = vCtx.createLinearGradient(0, 0, 0, 300);
    highGrad.addColorStop(0, "rgba(249, 115, 22, 0.2)");
    highGrad.addColorStop(1, "rgba(249, 115, 22, 0)");

    violationInstance.current = new ChartJS(vCtx, {
      type: "line",
      data: {
        labels,
        datasets: [
          { label: "Critical", data: trends.map((t) => t.critical_count), borderColor: "#ef4444", backgroundColor: critGrad, fill: true, tension: 0.4, pointRadius: 3, borderWidth: 2 },
          { label: "High", data: trends.map((t) => t.high_count), borderColor: "#f97316", backgroundColor: highGrad, fill: true, tension: 0.4, pointRadius: 3, borderWidth: 2 },
          { label: "Medium", data: trends.map((t) => t.medium_count), borderColor: "#f59e0b", fill: false, tension: 0.4, pointRadius: 3, borderWidth: 2 },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { color: "#94a3b8", font: { family: "Inter", size: 11 }, usePointStyle: true } } },
        scales: {
          x: { grid: { color: "rgba(255,255,255,0.03)" }, ticks: { color: "#64748b", font: { size: 10 } } },
          y: { beginAtZero: true, grid: { color: "rgba(255,255,255,0.03)" }, ticks: { color: "#64748b" } },
        },
        animation: { duration: 800 },
      },
    });

    // Compliance Score Chart
    const sCtx = scoreChartRef.current.getContext("2d");
    const scoreGrad = sCtx.createLinearGradient(0, 0, 0, 300);
    scoreGrad.addColorStop(0, "rgba(16, 185, 129, 0.3)");
    scoreGrad.addColorStop(1, "rgba(16, 185, 129, 0)");

    scoreInstance.current = new ChartJS(sCtx, {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Compliance Score",
          data: trends.map((t) => t.avg_compliance_score),
          borderColor: "#10b981",
          backgroundColor: scoreGrad,
          fill: true,
          tension: 0.4,
          pointRadius: 3,
          borderWidth: 2,
          pointBackgroundColor: "#10b981",
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { color: "#94a3b8", font: { family: "Inter", size: 11 }, usePointStyle: true } } },
        scales: {
          x: { grid: { color: "rgba(255,255,255,0.03)" }, ticks: { color: "#64748b", font: { size: 10 } } },
          y: { min: 0, max: 100, grid: { color: "rgba(255,255,255,0.03)" }, ticks: { color: "#64748b", callback: (v) => v + "%" } },
        },
        animation: { duration: 800 },
      },
    });

    return () => {
      if (violationInstance.current) violationInstance.current.destroy();
      if (scoreInstance.current) scoreInstance.current.destroy();
    };
  }, [trends]);

  return (
    <div>
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h2>Compliance Trends</h2>
          <p>Track violations and compliance score over time</p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {["7", "30", "90"].map((d) => (
            <button
              key={d}
              onClick={() => { setLoading(true); setPeriod(d); }}
              className={`period-btn ${period === d ? "active" : ""}`}
            >
              {d}d
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="glass-card" style={{ padding: 48, textAlign: "center" }}>
          <div className="spinner" style={{ margin: "0 auto 16px", width: 32, height: 32 }} />
          <p style={{ color: "var(--text-muted)" }}>Loading trends...</p>
        </div>
      ) : (
        <div className="dashboard-row">
          <div className="glass-card">
            <div className="card-header">
              <h3><Icon name="chart-line" size={16} style={{ marginRight: 6, color: "var(--accent-cyan)" }} /> Violation Counts</h3>
            </div>
            <div className="chart-container">
              <canvas ref={violationChartRef} />
            </div>
          </div>
          <div className="glass-card">
            <div className="card-header">
              <h3><Icon name="shield-check" size={16} style={{ marginRight: 6, color: "var(--accent-green)" }} /> Compliance Score</h3>
            </div>
            <div className="chart-container">
              <canvas ref={scoreChartRef} />
            </div>
          </div>
        </div>
      )}

      {!loading && trends.length > 0 && (
        <div className="glass-card" style={{ marginTop: 20 }}>
          <div className="card-header"><h3>Summary Statistics</h3></div>
          <div className="card-body">
            <div className="audit-detail-stats">
              <div className="audit-detail-stat">
                <span className="audit-detail-stat-value">{trends.length}</span>
                <span className="audit-detail-stat-label">Data Points</span>
              </div>
              <div className="audit-detail-stat">
                <span className="audit-detail-stat-value" style={{ color: "var(--accent-green)" }}>
                  {trends.length > 0 ? trends[trends.length - 1].avg_compliance_score.toFixed(1) : 0}%
                </span>
                <span className="audit-detail-stat-label">Latest Score</span>
              </div>
              <div className="audit-detail-stat">
                <span className="audit-detail-stat-value" style={{ color: "var(--accent-red)" }}>
                  {trends.length > 0 ? trends[trends.length - 1].critical_count : 0}
                </span>
                <span className="audit-detail-stat-label">Critical (Latest)</span>
              </div>
              <div className="audit-detail-stat">
                <span className="audit-detail-stat-value">
                  {trends.reduce((sum, t) => sum + t.total_audits, 0)}
                </span>
                <span className="audit-detail-stat-label">Total Audits</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
