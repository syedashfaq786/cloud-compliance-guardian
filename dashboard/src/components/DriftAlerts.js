"use client";

import { Icon } from "./Icons";

const MOCK_ALERTS = [
  {
    id: 1,
    severity: "critical",
    alert_type: "regression",
    title: "3 new CRITICAL violations detected",
    description:
      "Security groups with open SSH (0.0.0.0/0) were introduced in the latest infrastructure changes. CIS 4.1 requires restricting SSH to trusted CIDRs.",
    resource_address: "aws_security_group.web_server",
    created_at: "2 hours ago",
  },
  {
    id: 2,
    severity: "high",
    alert_type: "score_drop",
    title: "Compliance score dropped by 15.2%",
    description:
      "Score dropped from 87% to 71.8% after merging the data-pipeline infrastructure module. Multiple S3 buckets lack encryption and public access blocks.",
    created_at: "5 hours ago",
  },
  {
    id: 3,
    severity: "medium",
    alert_type: "new_violation",
    title: "RDS instance publicly accessible",
    description:
      "Production database aws_db_instance.production_db has publicly_accessible = true. CIS 2.3.2 requires all RDS instances to be private.",
    resource_address: "aws_db_instance.production_db",
    created_at: "1 day ago",
  },
];

const ALERT_ICON_MAP = {
  critical: "siren",
  high: "triangle-alert",
  medium: "clipboard",
};

export default function DriftAlerts({ alerts = null }) {
  const displayAlerts = alerts || MOCK_ALERTS;

  return (
    <div className="glass-card animate-slide-in stagger-4">
      <div className="card-header">
        <h3><Icon name="bell" size={18} style={{ marginRight: 8, verticalAlign: "middle", color: "var(--accent-amber)" }} /> Drift Detection Alerts</h3>
        <span
          style={{
            fontSize: "12px",
            padding: "3px 10px",
            background: "rgba(239, 68, 68, 0.15)",
            color: "var(--accent-red)",
            borderRadius: "99px",
            fontWeight: "600",
          }}
        >
          {displayAlerts.length} active
        </span>
      </div>
      <div className="card-body">
        {displayAlerts.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon"><Icon name="circle-check" size={48} style={{ color: "var(--accent-green)" }} /></div>
            <h3>No Active Alerts</h3>
            <p>Your infrastructure compliance is stable with no drift detected.</p>
          </div>
        ) : (
          displayAlerts.map((alert) => (
            <div key={alert.id} className={`drift-alert ${alert.severity}`}>
              <span className="drift-alert-icon">
                <Icon name={ALERT_ICON_MAP[alert.severity] || "clipboard"} size={20} />
              </span>
              <div className="drift-alert-content">
                <h4>{alert.title}</h4>
                <p>{alert.description}</p>
                {alert.resource_address && (
                  <p style={{ marginTop: "4px", fontFamily: "monospace", color: "var(--accent-purple)" }}>
                    {alert.resource_address}
                  </p>
                )}
              </div>
              <span className="drift-alert-time">{alert.created_at}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
