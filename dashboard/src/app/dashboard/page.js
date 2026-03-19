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
import { Icon } from "@/components/Icons";

const API_BASE = "http://localhost:8000";

function DashboardOverview() {
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/api/summary`)
      .then((r) => r.json())
      .then((data) => setSummary(data))
      .catch(() => {});
  }, []);

  const score = summary?.compliance_score ?? 78.5;
  const totalAudits = summary?.total_audits ?? 24;
  const totalFindings = summary?.total_findings ?? 8;
  const sev = summary?.severity_breakdown || {};

  return (
    <>
      {/* ── Page Header ──────────────────────────────────────────── */}
      <div className="page-header">
        <h2>Security Dashboard</h2>
        <p>Real-time CIS Benchmark compliance monitoring powered by Cisco Sec-8B</p>
      </div>

      {/* ── Top Stats Row ────────────────────────────────────────── */}
      <div className="dashboard-grid">
        <div className="glass-card stat-card animate-slide-in stagger-1">
          <div className="stat-icon"><Icon name="folder" size={28} style={{ color: "var(--accent-blue)" }} /></div>
          <div className="stat-value">{totalAudits}</div>
          <div className="stat-label">Total Audits</div>
          <span className="stat-change positive"><Icon name="arrow-up" size={10} /> 12% this week</span>
        </div>

        <div className="glass-card stat-card animate-slide-in stagger-2">
          <div className="stat-icon"><Icon name="shield" size={28} style={{ color: "var(--accent-purple)" }} /></div>
          <div className="stat-value">156</div>
          <div className="stat-label">Resources Scanned</div>
          <span className="stat-change positive"><Icon name="arrow-up" size={10} /> 8 new</span>
        </div>

        <div className="glass-card stat-card animate-slide-in stagger-3">
          <div className="stat-icon"><Icon name="search" size={28} style={{ color: "var(--accent-amber)" }} /></div>
          <div className="stat-value">{totalFindings}</div>
          <div className="stat-label">Open Violations</div>
          <span className="stat-change negative"><Icon name="arrow-up" size={10} /> 2 new</span>
        </div>

        <div className="glass-card stat-card animate-slide-in stagger-4">
          <div className="stat-icon"><Icon name="circle-check" size={28} style={{ color: "var(--accent-green)" }} /></div>
          <div className="stat-value">{156 - totalFindings}</div>
          <div className="stat-label">Compliant Resources</div>
          <span className="stat-change positive">94.8% pass rate</span>
        </div>
      </div>

      {/* ── Scorecard + Trend Row ────────────────────────────────── */}
      <div className="dashboard-row">
        <ScoreCard score={score} />
        <TrendChart />
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
