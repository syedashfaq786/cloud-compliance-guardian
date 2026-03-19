"use client";
import { useState } from "react";
import { Icon } from "./Icons";

const CIS_RULES = [
  // ── AWS ────────────────────────────────────────────────────────────
  { id: "1.22", title: "Ensure IAM policies do not have wildcard permissions", severity: "CRITICAL", category: "IAM", provider: "AWS", description: "IAM policies should follow least-privilege principle. Wildcard (*) actions and resources grant unrestricted access.", recommendation: "Replace wildcard permissions with specific service actions. Use AWS Access Analyzer to identify unused permissions." },
  { id: "2.1.2", title: "Ensure S3 buckets have server-side encryption enabled", severity: "HIGH", category: "Storage", provider: "AWS", description: "All S3 buckets must encrypt data at rest using SSE-S3, SSE-KMS, or SSE-C.", recommendation: "Enable default encryption on all S3 buckets using aws_s3_bucket_server_side_encryption_configuration." },
  { id: "2.1.4", title: "Ensure S3 buckets have public access blocks", severity: "CRITICAL", category: "Storage", provider: "AWS", description: "Block all public access to S3 buckets by enabling all four public access block settings.", recommendation: "Add aws_s3_bucket_public_access_block with all four flags set to true." },
  { id: "2.2.1", title: "Ensure EBS volumes are encrypted at rest", severity: "HIGH", category: "Compute", provider: "AWS", description: "EBS volumes must be encrypted using AWS KMS keys to protect data at rest.", recommendation: "Set encrypted = true and specify a kms_key_id on all aws_ebs_volume resources." },
  { id: "2.3.2", title: "Ensure RDS instances are not publicly accessible", severity: "CRITICAL", category: "Database", provider: "AWS", description: "RDS instances must not have publicly_accessible set to true. Use VPC and security groups.", recommendation: "Set publicly_accessible = false. Use VPC subnets and security groups for access control." },
  { id: "3.1", title: "Ensure CloudTrail is enabled in all regions", severity: "HIGH", category: "Logging", provider: "AWS", description: "CloudTrail must be configured as a multi-region trail to capture API activity across all regions.", recommendation: "Set is_multi_region_trail = true on your aws_cloudtrail resource." },
  { id: "4.1", title: "Ensure no security groups allow ingress from 0.0.0.0/0 to SSH", severity: "CRITICAL", category: "Networking", provider: "AWS", description: "SSH access (port 22) must be restricted to trusted CIDR ranges. Never allow 0.0.0.0/0.", recommendation: "Replace 0.0.0.0/0 with your organization's VPN or bastion CIDR range." },
  { id: "4.2", title: "Ensure no security groups allow ingress from 0.0.0.0/0 to RDP", severity: "CRITICAL", category: "Networking", provider: "AWS", description: "RDP access (port 3389) must be restricted to trusted CIDR ranges.", recommendation: "Restrict RDP ingress to specific trusted IPs. Consider using AWS SSM Session Manager instead." },
  { id: "5.1", title: "Ensure KMS keys have automatic rotation enabled", severity: "MEDIUM", category: "Encryption", provider: "AWS", description: "KMS customer-managed keys should have automatic annual rotation enabled.", recommendation: "Set enable_key_rotation = true on all aws_kms_key resources." },
  { id: "5.2", title: "Ensure VPC flow logging is enabled", severity: "HIGH", category: "Networking", provider: "AWS", description: "VPC Flow Logs capture network traffic metadata for security analysis and troubleshooting.", recommendation: "Create aws_flow_log resource for each VPC with log destination to CloudWatch or S3." },
  { id: "6.1", title: "Ensure RDS instances have backup enabled", severity: "MEDIUM", category: "Database", provider: "AWS", description: "Automated backups ensure point-in-time recovery for RDS databases.", recommendation: "Set backup_retention_period >= 7 on aws_db_instance resources." },
  { id: "6.2", title: "Ensure RDS instances have minor version upgrade enabled", severity: "LOW", category: "Database", provider: "AWS", description: "Enable auto-minor-version-upgrade to receive security patches automatically.", recommendation: "Set auto_minor_version_upgrade = true on aws_db_instance resources." },

  // ── Azure ──────────────────────────────────────────────────────────
  { id: "AZ-1.1", title: "Ensure Azure Storage accounts use HTTPS-only traffic", severity: "HIGH", category: "Storage", provider: "Azure", description: "Storage accounts must enforce HTTPS to prevent data interception via unencrypted HTTP connections.", recommendation: "Set enable_https_traffic_only = true on azurerm_storage_account resources." },
  { id: "AZ-1.2", title: "Ensure Storage account access keys are periodically rotated", severity: "MEDIUM", category: "Storage", provider: "Azure", description: "Storage account keys should be rotated regularly to limit exposure if compromised.", recommendation: "Use Azure Key Vault to manage storage keys and configure automatic rotation policies." },
  { id: "AZ-2.1", title: "Ensure Azure SQL Database has auditing enabled", severity: "HIGH", category: "Database", provider: "Azure", description: "SQL Database auditing tracks database events and writes them to an audit log.", recommendation: "Add azurerm_mssql_database_extended_auditing_policy with retention >= 90 days." },
  { id: "AZ-2.2", title: "Ensure Azure SQL Database uses TDE encryption", severity: "CRITICAL", category: "Database", provider: "Azure", description: "Transparent Data Encryption (TDE) encrypts SQL Database data at rest.", recommendation: "TDE is enabled by default for Azure SQL. Verify with azurerm_mssql_database transparent_data_encryption." },
  { id: "AZ-3.1", title: "Ensure NSG does not allow SSH from the internet", severity: "CRITICAL", category: "Networking", provider: "Azure", description: "Network Security Groups must not allow inbound SSH (port 22) from any source (0.0.0.0/0 or *).", recommendation: "Restrict SSH source_address_prefix to specific trusted CIDRs. Use Azure Bastion for secure access." },
  { id: "AZ-3.2", title: "Ensure NSG does not allow RDP from the internet", severity: "CRITICAL", category: "Networking", provider: "Azure", description: "Network Security Groups must not allow inbound RDP (port 3389) from the internet.", recommendation: "Use Azure Bastion or VPN Gateway for RDP access instead of public NSG rules." },
  { id: "AZ-4.1", title: "Ensure Azure Key Vault has soft delete enabled", severity: "HIGH", category: "Encryption", provider: "Azure", description: "Key Vault soft delete allows recovery of deleted vaults and secrets for a retention period.", recommendation: "Set soft_delete_retention_days >= 7 on azurerm_key_vault resources." },
  { id: "AZ-4.2", title: "Ensure Azure Key Vault has purge protection enabled", severity: "HIGH", category: "Encryption", provider: "Azure", description: "Purge protection prevents permanent deletion of key vaults during the soft delete retention period.", recommendation: "Set purge_protection_enabled = true on azurerm_key_vault resources." },
  { id: "AZ-5.1", title: "Ensure Activity Log alerts exist for security operations", severity: "MEDIUM", category: "Logging", provider: "Azure", description: "Activity Log alerts should monitor critical operations like policy assignments and security solution changes.", recommendation: "Create azurerm_monitor_activity_log_alert for Create/Update/Delete Policy Assignment operations." },
  { id: "AZ-6.1", title: "Ensure VM disks are encrypted with ADE or SSE", severity: "HIGH", category: "Compute", provider: "Azure", description: "Virtual Machine OS and data disks must be encrypted using Azure Disk Encryption or Server-Side Encryption.", recommendation: "Use azurerm_disk_encryption_set or enable encryption_at_host_enabled on VMs." },
  { id: "AZ-7.1", title: "Ensure Azure App Service uses the latest TLS version", severity: "MEDIUM", category: "Compute", provider: "Azure", description: "App Services should enforce TLS 1.2 or higher for all inbound connections.", recommendation: "Set min_tls_version = \"1.2\" in azurerm_app_service site_config." },

  // ── GCP ────────────────────────────────────────────────────────────
  { id: "GCP-1.1", title: "Ensure GCS buckets are not anonymously or publicly accessible", severity: "CRITICAL", category: "Storage", provider: "GCP", description: "Cloud Storage buckets must not grant access to allUsers or allAuthenticatedUsers IAM members.", recommendation: "Remove allUsers and allAuthenticatedUsers bindings. Use uniform bucket-level access." },
  { id: "GCP-1.2", title: "Ensure GCS bucket has uniform bucket-level access enabled", severity: "HIGH", category: "Storage", provider: "GCP", description: "Uniform access disables ACLs and ensures all access is managed through IAM policies only.", recommendation: "Set uniform_bucket_level_access = true on google_storage_bucket resources." },
  { id: "GCP-2.1", title: "Ensure Cloud SQL instances are not publicly accessible", severity: "CRITICAL", category: "Database", provider: "GCP", description: "Cloud SQL instances should not have authorized networks allowing 0.0.0.0/0.", recommendation: "Remove 0.0.0.0/0 from authorized_networks. Use Cloud SQL Proxy for secure connections." },
  { id: "GCP-2.2", title: "Ensure Cloud SQL instances have backup enabled", severity: "HIGH", category: "Database", provider: "GCP", description: "Automated backups ensure data recovery for Cloud SQL databases.", recommendation: "Set backup_configuration.enabled = true with point_in_time_recovery_enabled = true." },
  { id: "GCP-3.1", title: "Ensure VPC firewall rules do not allow SSH from 0.0.0.0/0", severity: "CRITICAL", category: "Networking", provider: "GCP", description: "Firewall rules must not allow SSH (port 22) from all sources (0.0.0.0/0).", recommendation: "Restrict source_ranges to specific trusted CIDRs. Use IAP tunneling for SSH access." },
  { id: "GCP-3.2", title: "Ensure VPC firewall rules do not allow RDP from 0.0.0.0/0", severity: "CRITICAL", category: "Networking", provider: "GCP", description: "Firewall rules must not allow RDP (port 3389) from the internet.", recommendation: "Use Identity-Aware Proxy (IAP) for RDP access instead of public firewall rules." },
  { id: "GCP-4.1", title: "Ensure Cloud KMS cryptokeys have rotation configured", severity: "MEDIUM", category: "Encryption", provider: "GCP", description: "KMS key rotation should be set to no more than 90 days.", recommendation: "Set rotation_period = \"7776000s\" (90 days) on google_kms_crypto_key resources." },
  { id: "GCP-5.1", title: "Ensure Cloud Audit Logging is enabled for all services", severity: "HIGH", category: "Logging", provider: "GCP", description: "Audit Logs should capture Admin Activity, Data Access, and System Event logs for all services.", recommendation: "Configure google_project_iam_audit_config with all log types for allServices." },
  { id: "GCP-5.2", title: "Ensure log metric filters and alerts exist for audit changes", severity: "MEDIUM", category: "Logging", provider: "GCP", description: "Metric filters should detect changes to audit configurations.", recommendation: "Create google_logging_metric for protoPayload.methodName=\"SetIamPolicy\" and attach alert policies." },
  { id: "GCP-6.1", title: "Ensure Compute instances do not use default service account", severity: "HIGH", category: "IAM", provider: "GCP", description: "Default service accounts have the Editor role, granting overly broad permissions.", recommendation: "Create custom service accounts with minimal permissions for each workload." },
  { id: "GCP-6.2", title: "Ensure Compute instances do not have public IP addresses", severity: "HIGH", category: "Compute", provider: "GCP", description: "Instances should use private IPs only, with Cloud NAT for outbound access.", recommendation: "Remove access_config from network_interface blocks. Use Cloud NAT for egress." },
];

const PROVIDERS = ["All", "AWS", "Azure", "GCP"];
const CATEGORIES = ["All", ...Array.from(new Set(CIS_RULES.map((r) => r.category))).sort()];
const SEVERITIES = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

const PROVIDER_COLORS = {
  AWS: { bg: "rgba(255,153,0,0.08)", color: "#ff9900", border: "rgba(255,153,0,0.2)" },
  Azure: { bg: "rgba(0,120,212,0.08)", color: "#0078d4", border: "rgba(0,120,212,0.2)" },
  GCP: { bg: "rgba(66,133,244,0.08)", color: "#4285f4", border: "rgba(66,133,244,0.2)" },
};

export default function CISRulesView() {
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("All");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [providerFilter, setProviderFilter] = useState("All");
  const [expandedRule, setExpandedRule] = useState(null);

  const filtered = CIS_RULES.filter((r) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch = !searchQuery ||
      r.title.toLowerCase().includes(q) ||
      r.id.toLowerCase().includes(q) ||
      r.description.toLowerCase().includes(q) ||
      r.category.toLowerCase().includes(q) ||
      r.provider.toLowerCase().includes(q) ||
      r.recommendation.toLowerCase().includes(q);
    const matchesCategory = categoryFilter === "All" || r.category === categoryFilter;
    const matchesSeverity = severityFilter === "All" || r.severity === severityFilter;
    const matchesProvider = providerFilter === "All" || r.provider === providerFilter;
    return matchesSearch && matchesCategory && matchesSeverity && matchesProvider;
  });

  const providerCounts = {
    All: CIS_RULES.length,
    AWS: CIS_RULES.filter(r => r.provider === "AWS").length,
    Azure: CIS_RULES.filter(r => r.provider === "Azure").length,
    GCP: CIS_RULES.filter(r => r.provider === "GCP").length,
  };

  return (
    <div>
      <div className="page-header">
        <h2>CIS Benchmark Rules</h2>
        <p>Reference catalog of compliance rules across AWS, Azure, and GCP</p>
      </div>

      {/* ── Provider Tabs ──────────────────────────────────────────── */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
        {PROVIDERS.map((p) => (
          <button
            key={p}
            className={`period-btn ${providerFilter === p ? "active" : ""}`}
            onClick={() => setProviderFilter(p)}
            style={{ display: "flex", alignItems: "center", gap: 6 }}
          >
            {p !== "All" && (
              <img src={`/logos/${p.toLowerCase()}.svg`} alt={p} style={{ width: 16, height: 16 }} />
            )}
            {p} <span style={{ opacity: 0.7, fontSize: 11 }}>({providerCounts[p]})</span>
          </button>
        ))}
      </div>

      {/* ── Search & Filters ───────────────────────────────────────── */}
      <div className="glass-card" style={{ marginBottom: 20 }}>
        <div className="card-body" style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
          <div className="input-wrapper" style={{ flex: 1, minWidth: 200 }}>
            <span className="input-icon"><Icon name="search" size={16} /></span>
            <input
              type="text"
              placeholder="Search by rule ID, title, description, category..."
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
          {searchQuery && (
            <button
              onClick={() => setSearchQuery("")}
              style={{
                padding: "8px 14px", border: "1px solid var(--border-glass)", borderRadius: "var(--radius-sm)",
                background: "var(--bg-card)", color: "var(--text-muted)", fontSize: 12, fontWeight: 600,
                cursor: "pointer", fontFamily: "'Inter', sans-serif"
              }}
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* ── Results Count ──────────────────────────────────────────── */}
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 16 }}>
        Showing {filtered.length} of {CIS_RULES.length} rules
        {searchQuery && <> matching &quot;<strong style={{ color: "var(--text-primary)" }}>{searchQuery}</strong>&quot;</>}
      </p>

      {/* ── Rules Grid ─────────────────────────────────────────────── */}
      <div className="rules-grid">
        {filtered.map((rule) => {
          const pc = PROVIDER_COLORS[rule.provider];
          const isExpanded = expandedRule === rule.id;
          return (
            <div key={rule.id} className="glass-card rule-card" onClick={() => setExpandedRule(isExpanded ? null : rule.id)}
              style={{ cursor: "pointer" }}>
              <div className="card-body">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span className="rule-id" style={{ fontSize: 14 }}>CIS {rule.id}</span>
                    <span style={{
                      fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 99,
                      background: pc.bg, color: pc.color, border: `1px solid ${pc.border}`
                    }}>{rule.provider}</span>
                  </div>
                  <span className={`severity-badge ${rule.severity.toLowerCase()}`}>{rule.severity}</span>
                </div>
                <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, lineHeight: 1.4 }}>{rule.title}</h4>
                <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.5, marginBottom: 10 }}>{rule.description}</p>

                {/* Expanded Recommendation */}
                {isExpanded && (
                  <div className="animate-fade-in" style={{ marginTop: 12, padding: "12px 14px", background: "rgba(255,122,0,0.04)", borderRadius: 10, border: "1px solid rgba(255,122,0,0.1)" }}>
                    <p style={{ fontSize: 11, fontWeight: 700, color: "var(--accent-amber)", marginBottom: 4 }}>
                      <Icon name="circle-check" size={12} style={{ marginRight: 4 }} /> Recommendation
                    </p>
                    <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>{rule.recommendation}</p>
                  </div>
                )}

                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 10 }}>
                  <span className="category-tag">{rule.category}</span>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    {isExpanded ? "Click to collapse" : "Click for recommendation"}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
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
