"use client";
import { useState } from "react";
import { Icon } from "./Icons";

const CIS_RULES = [
  { id: "1.22", title: "Ensure IAM policies do not have wildcard permissions", severity: "CRITICAL", category: "IAM", description: "IAM policies should follow least-privilege principle. Wildcard (*) actions and resources grant unrestricted access." },
  { id: "2.1.2", title: "Ensure S3 buckets have server-side encryption enabled", severity: "HIGH", category: "Storage", description: "All S3 buckets must encrypt data at rest using SSE-S3, SSE-KMS, or SSE-C." },
  { id: "2.1.4", title: "Ensure S3 buckets have public access blocks", severity: "CRITICAL", category: "Storage", description: "Block all public access to S3 buckets by enabling all four public access block settings." },
  { id: "2.2.1", title: "Ensure EBS volumes are encrypted at rest", severity: "HIGH", category: "Compute", description: "EBS volumes must be encrypted using AWS KMS keys to protect data at rest." },
  { id: "2.3.2", title: "Ensure RDS instances are not publicly accessible", severity: "CRITICAL", category: "Database", description: "RDS instances must not have publicly_accessible set to true. Use VPC and security groups." },
  { id: "3.1", title: "Ensure CloudTrail is enabled in all regions", severity: "HIGH", category: "Logging", description: "CloudTrail must be configured as a multi-region trail to capture API activity across all regions." },
  { id: "4.1", title: "Ensure no security groups allow ingress from 0.0.0.0/0 to SSH", severity: "CRITICAL", category: "Networking", description: "SSH access (port 22) must be restricted to trusted CIDR ranges. Never allow 0.0.0.0/0." },
  { id: "4.2", title: "Ensure no security groups allow ingress from 0.0.0.0/0 to RDP", severity: "CRITICAL", category: "Networking", description: "RDP access (port 3389) must be restricted to trusted CIDR ranges." },
  { id: "5.1", title: "Ensure KMS keys have automatic rotation enabled", severity: "MEDIUM", category: "Encryption", description: "KMS customer-managed keys should have automatic annual rotation enabled." },
  { id: "5.2", title: "Ensure VPC flow logging is enabled", severity: "HIGH", category: "Networking", description: "VPC Flow Logs capture network traffic metadata for security analysis and troubleshooting." },
  { id: "6.1", title: "Ensure RDS instances have backup enabled", severity: "MEDIUM", category: "Database", description: "Automated backups ensure point-in-time recovery for RDS databases." },
  { id: "6.2", title: "Ensure RDS instances have minor version upgrade enabled", severity: "LOW", category: "Database", description: "Enable auto-minor-version-upgrade to receive security patches automatically." },
];

const CATEGORIES = ["All", ...Array.from(new Set(CIS_RULES.map((r) => r.category)))];
const SEVERITIES = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function CISRulesView() {
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("All");
  const [severityFilter, setSeverityFilter] = useState("All");

  const filtered = CIS_RULES.filter((r) => {
    const matchesSearch = !searchQuery || r.title.toLowerCase().includes(searchQuery.toLowerCase()) || r.id.includes(searchQuery);
    const matchesCategory = categoryFilter === "All" || r.category === categoryFilter;
    const matchesSeverity = severityFilter === "All" || r.severity === severityFilter;
    return matchesSearch && matchesCategory && matchesSeverity;
  });

  return (
    <div>
      <div className="page-header">
        <h2>CIS Benchmark Rules</h2>
        <p>Reference catalog of enforced compliance rules</p>
      </div>

      <div className="glass-card" style={{ marginBottom: 20 }}>
        <div className="card-body" style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
          <div className="input-wrapper" style={{ flex: 1, minWidth: 200 }}>
            <span className="input-icon"><Icon name="search" size={16} /></span>
            <input
              type="text"
              placeholder="Search rules by ID or title..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ width: "100%" }}
            />
          </div>
          <select className="filter-select" value={categoryFilter} onChange={(e) => setCategoryFilter(e.target.value)}>
            {CATEGORIES.map((c) => <option key={c} value={c}>{c === "All" ? "All Categories" : c}</option>)}
          </select>
          <select className="filter-select" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s === "All" ? "All Severities" : s}</option>)}
          </select>
        </div>
      </div>

      <div className="rules-grid">
        {filtered.map((rule) => (
          <div key={rule.id} className="glass-card rule-card">
            <div className="card-body">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                <span className="rule-id" style={{ fontSize: 14 }}>CIS {rule.id}</span>
                <span className={`severity-badge ${rule.severity.toLowerCase()}`}>{rule.severity}</span>
              </div>
              <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, lineHeight: 1.4 }}>{rule.title}</h4>
              <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.5, marginBottom: 10 }}>{rule.description}</p>
              <span className="category-tag">{rule.category}</span>
            </div>
          </div>
        ))}
      </div>

      {filtered.length === 0 && (
        <div className="glass-card" style={{ padding: 48, textAlign: "center" }}>
          <Icon name="search" size={40} style={{ color: "var(--text-muted)", marginBottom: 12 }} />
          <h3 style={{ fontSize: 16, color: "var(--text-secondary)" }}>No rules match your filters</h3>
          <p style={{ color: "var(--text-muted)", fontSize: 13 }}>Try adjusting your search or filter criteria.</p>
        </div>
      )}
    </div>
  );
}
