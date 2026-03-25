"use client";

import { useState, useEffect } from "react";
import Sidebar from "@/components/Sidebar";
import ScoreCard from "@/components/ScoreCard";
import TrendChart from "@/components/TrendChart";
import DriftAlerts from "@/components/DriftAlerts";
import FindingsTable from "@/components/FindingsTable";
import AuditsView from "@/components/AuditsView";
import TrendsView from "@/components/TrendsView";
import DriftAlertsView from "@/components/DriftAlertsView";
import CISRulesView from "@/components/CISRulesView";
import SettingsView from "@/components/SettingsView";
import ConnectView from "@/components/ConnectView";
import MonitoringView from "@/components/MonitoringView";
import { Icon } from "@/components/Icons";

const API_BASE = "http://localhost:8000";

function DashboardOverview() {
  const [summary, setSummary] = useState(null);
  const [recentAudits, setRecentAudits] = useState([]);

  useEffect(() => {
    fetch(`${API_BASE}/api/summary`)
      .then((r) => r.json())
      .then((data) => setSummary(data))
      .catch(() => {});
    fetch(`${API_BASE}/api/audits?limit=5`)
      .then((r) => r.json())
      .then((data) => setRecentAudits(data.audits || []))
      .catch(() => {});
  }, []);

  const score = summary?.compliance_score ?? 0;
  const totalAudits = summary?.total_audits ?? 0;
  const totalFindings = summary?.total_findings ?? 0;
  const resourcesScanned = summary?.resources_scanned ?? 0;
  const sev = summary?.severity_breakdown || {};
  const criticalCount = sev.critical ?? 0;
  const highCount = sev.high ?? 0;
  const compliantResources = resourcesScanned > 0 ? resourcesScanned - totalFindings : 0;
  const passRate = resourcesScanned > 0 ? ((compliantResources / resourcesScanned) * 100).toFixed(1) : "0";

  return (
    <>
      {/* ── Welcome Banner ─────────────────────────────────────── */}
      <div className="welcome-banner animate-fade-in">
        <div className="welcome-text">
          <h2>Welcome back</h2>
          <p>Here's an overview of your cloud infrastructure compliance status.</p>
        </div>
        <div className="welcome-date">
          <Icon name="calendar" size={16} />
          <span>{new Date().toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric" })}</span>
        </div>
      </div>

      {/* ── Top Stats Row ────────────────────────────────────────── */}
      <div className="dashboard-grid">
        <div className="glass-card stat-card stat-blue animate-slide-in stagger-1">
          <div className="stat-card-top">
            <div className="stat-icon"><Icon name="folder" size={22} /></div>
            {totalAudits > 0 && <span className="stat-change positive"><Icon name="arrow-up" size={10} /> {totalAudits}</span>}
          </div>
          <div className="stat-value">{totalAudits}</div>
          <div className="stat-label">Total Audits</div>
          <div className="stat-bar"><div className="stat-bar-fill" style={{ width: `${Math.min(totalAudits * 10, 100)}%` }}></div></div>
        </div>

        <div className="glass-card stat-card stat-purple animate-slide-in stagger-2">
          <div className="stat-card-top">
            <div className="stat-icon"><Icon name="shield" size={22} /></div>
            {resourcesScanned > 0 && <span className="stat-change positive"><Icon name="arrow-up" size={10} /> {resourcesScanned}</span>}
          </div>
          <div className="stat-value">{resourcesScanned}</div>
          <div className="stat-label">Resources Scanned</div>
          <div className="stat-bar"><div className="stat-bar-fill" style={{ width: `${Math.min(resourcesScanned * 3, 100)}%` }}></div></div>
        </div>

        <div className="glass-card stat-card stat-amber animate-slide-in stagger-3">
          <div className="stat-card-top">
            <div className="stat-icon"><Icon name="search" size={22} /></div>
            {totalFindings > 0 && <span className="stat-change negative"><Icon name="arrow-up" size={10} /> {totalFindings}</span>}
          </div>
          <div className="stat-value">{totalFindings}</div>
          <div className="stat-label">Open Violations</div>
          <div className="stat-bar"><div className="stat-bar-fill" style={{ width: `${Math.min(totalFindings * 5, 100)}%` }}></div></div>
        </div>

        <div className="glass-card stat-card stat-green animate-slide-in stagger-4">
          <div className="stat-card-top">
            <div className="stat-icon"><Icon name="circle-check" size={22} /></div>
            {compliantResources > 0 && <span className="stat-change positive">{passRate}%</span>}
          </div>
          <div className="stat-value">{compliantResources}</div>
          <div className="stat-label">Compliant Resources</div>
          <div className="stat-bar"><div className="stat-bar-fill" style={{ width: `${passRate}%` }}></div></div>
        </div>
      </div>

      {/* ── Scorecard + Trend Row ────────────────────────────────── */}
      <div className="dashboard-row">
        <ScoreCard score={score} />
        <TrendChart />
      </div>

      {/* ── Severity Summary + Recent Activity ─────────────────── */}
      <div className="dashboard-row">
        <div className="glass-card animate-slide-in stagger-2">
          <div className="card-header">
            <h3><Icon name="shield" size={18} style={{ marginRight: 8, verticalAlign: "middle", color: "var(--accent-purple)" }} /> Severity Breakdown</h3>
          </div>
          <div className="card-body">
            <div className="severity-bars">
              <div className="severity-bar-row">
                <div className="severity-bar-label">
                  <span className="severity-dot critical"></span>
                  <span>Critical</span>
                </div>
                <div className="severity-bar-track">
                  <div className="severity-bar-fill critical" style={{ width: `${criticalCount * 10}%` }}></div>
                </div>
                <span className="severity-bar-count">{criticalCount}</span>
              </div>
              <div className="severity-bar-row">
                <div className="severity-bar-label">
                  <span className="severity-dot high"></span>
                  <span>High</span>
                </div>
                <div className="severity-bar-track">
                  <div className="severity-bar-fill high" style={{ width: `${highCount * 10}%` }}></div>
                </div>
                <span className="severity-bar-count">{highCount}</span>
              </div>
              <div className="severity-bar-row">
                <div className="severity-bar-label">
                  <span className="severity-dot medium"></span>
                  <span>Medium</span>
                </div>
                <div className="severity-bar-track">
                  <div className="severity-bar-fill medium" style={{ width: `${(sev.medium ?? 1) * 10}%` }}></div>
                </div>
                <span className="severity-bar-count">{sev.medium ?? 1}</span>
              </div>
              <div className="severity-bar-row">
                <div className="severity-bar-label">
                  <span className="severity-dot low"></span>
                  <span>Low</span>
                </div>
                <div className="severity-bar-track">
                  <div className="severity-bar-fill low" style={{ width: `${(sev.low ?? 0) * 10}%` }}></div>
                </div>
                <span className="severity-bar-count">{sev.low ?? 0}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="glass-card animate-slide-in stagger-3">
          <div className="card-header">
            <h3><Icon name="clock" size={18} style={{ marginRight: 8, verticalAlign: "middle", color: "var(--accent-cyan)" }} /> Recent Activity</h3>
          </div>
          <div className="card-body">
            <div className="activity-list">
              {recentAudits.length > 0 ? recentAudits.map((audit, i) => (
                <div key={audit.audit_id || i} className="activity-item">
                  <div className={`activity-dot ${audit.compliance_score >= 80 ? 'good' : audit.compliance_score >= 50 ? 'warn' : 'bad'}`}></div>
                  <div className="activity-info">
                    <span className="activity-title">Scan #{audit.audit_id?.substring(0, 8) || i + 1}</span>
                    <span className="activity-meta">{audit.files_scanned} files | Score: {audit.compliance_score?.toFixed(1)}%</span>
                  </div>
                  <span className="activity-time">{audit.created_at ? new Date(audit.created_at).toLocaleDateString() : 'N/A'}</span>
                </div>
              )) : (
                <div className="activity-item">
                  <div className="activity-dot good"></div>
                  <div className="activity-info">
                    <span className="activity-title">Infrastructure scanned</span>
                    <span className="activity-meta">All checks passed</span>
                  </div>
                  <span className="activity-time">Just now</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Findings Table ───────────────────────────────────────── */}
      <div className="dashboard-full">
        <FindingsTable />
      </div>

      {/* ── Drift Alerts ─────────────────────────────────────────── */}
      <div className="dashboard-full">
        <DriftAlerts />
      </div>
    </>
  );
}

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState("dashboard");

  const renderContent = () => {
    switch (activeTab) {
      case "dashboard": return <DashboardOverview />;
      case "audits":    return <AuditsView />;
      case "connect":   return <ConnectView />;
      case "monitoring": return <MonitoringView onNavigate={setActiveTab} />;
      case "trends":    return <TrendsView />;
      case "drift":     return <DriftAlertsView />;
      case "rules":     return <CISRulesView />;
      case "settings":  return <SettingsView />;
      default:          return <DashboardOverview />;
    }
  };

  return (
    <div className="app-layout">
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />
      <main className="main-content">
        {renderContent()}
      </main>
    </div>
  );
}
