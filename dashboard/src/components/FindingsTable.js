"use client";
import React, { useState } from "react";
import { Icon } from "./Icons";

const MOCK_FINDINGS = [
  {
    rule_id: "4.1",
    severity: "CRITICAL",
    resource_address: "aws_security_group.web_server",
    file_path: "infra/network.tf",
    description: "SSH access (port 22) is open to 0.0.0.0/0. This allows anyone on the internet to attempt SSH connections.",
    reasoning: "The ingress rule allows TCP port 22 from 0.0.0.0/0. While port 443 being open is expected for a web server, SSH should be restricted to trusted networks.",
    remediation_hcl: `resource "aws_security_group_rule" "web_server_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]  # Replace with your VPN CIDR
  security_group_id = aws_security_group.web_server.id
  description       = "SSH from internal network only"
}`,
  },
  {
    rule_id: "2.3.2",
    severity: "CRITICAL",
    resource_address: "aws_db_instance.production_db",
    file_path: "infra/database.tf",
    description: "RDS instance is publicly accessible. Production databases must not be reachable from the internet.",
    reasoning: "publicly_accessible is set to true. This means the RDS instance gets a public DNS name and can be reached from outside the VPC.",
    remediation_hcl: `resource "aws_db_instance" "production_db" {
  # ... existing config ...
  publicly_accessible = false  # REQUIRED for CIS 2.3.2
}`,
  },
  {
    rule_id: "2.1.2",
    severity: "HIGH",
    resource_address: "aws_s3_bucket.data_lake",
    file_path: "infra/storage.tf",
    description: "S3 bucket does not have server-side encryption enabled. Data at rest is unprotected.",
    reasoning: "No aws_s3_bucket_server_side_encryption_configuration resource was found for this bucket.",
    remediation_hcl: `resource "aws_s3_bucket_server_side_encryption_configuration" "data_lake_sse" {
  bucket = aws_s3_bucket.data_lake.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}`,
  },
  {
    rule_id: "2.1.4",
    severity: "CRITICAL",
    resource_address: "aws_s3_bucket.data_lake",
    file_path: "infra/storage.tf",
    description: "S3 bucket has no public access block. The bucket could be made publicly accessible.",
    reasoning: "No aws_s3_bucket_public_access_block resource was found. All four block flags should be set to true.",
    remediation_hcl: `resource "aws_s3_bucket_public_access_block" "data_lake_block" {
  bucket = aws_s3_bucket.data_lake.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
  },
  {
    rule_id: "1.22",
    severity: "CRITICAL",
    resource_address: "aws_iam_policy.admin_full_access",
    file_path: "infra/iam.tf",
    description: 'IAM policy grants full administrative access with Action "*" and Resource "*".',
    reasoning: "The policy statement uses wildcard Action and Resource, granting unrestricted access to all AWS services.",
    remediation_hcl: `# Replace wildcard permissions with specific actions
resource "aws_iam_policy" "admin_scoped" {
  name = "ScopedAdminAccess"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:*", "s3:*", "rds:*"]
        Resource = "*"
      }
    ]
  })
}`,
  },
  {
    rule_id: "3.1",
    severity: "HIGH",
    resource_address: "aws_cloudtrail.main",
    file_path: "infra/logging.tf",
    description: "CloudTrail is not configured as a multi-region trail. API activity in other regions will not be logged.",
    reasoning: "is_multi_region_trail is set to false. CIS requires all-region coverage for complete audit logging.",
    remediation_hcl: `resource "aws_cloudtrail" "main" {
  name                  = "acme-main-trail"
  s3_bucket_name        = aws_s3_bucket.trail_logs.id
  is_multi_region_trail = true  # REQUIRED for CIS 3.1
  enable_logging        = true
}`,
  },
  {
    rule_id: "5.1",
    severity: "MEDIUM",
    resource_address: "aws_kms_key.app_key",
    file_path: "infra/encryption.tf",
    description: "KMS key does not have automatic rotation enabled.",
    reasoning: "enable_key_rotation is set to false. Regular rotation limits the impact of a compromised key.",
    remediation_hcl: `resource "aws_kms_key" "app_key" {
  description         = "Application encryption key"
  enable_key_rotation = true  # REQUIRED for CIS 5.1
}`,
  },
  {
    rule_id: "2.2.1",
    severity: "HIGH",
    resource_address: "aws_ebs_volume.data_volume",
    file_path: "infra/compute.tf",
    description: "EBS volume is not encrypted at rest.",
    reasoning: "encrypted is set to false. All EBS volumes should be encrypted to protect data at rest.",
    remediation_hcl: `resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-east-1a"
  size              = 500
  encrypted         = true  # REQUIRED for CIS 2.2.1
  kms_key_id        = var.kms_key_id
}`,
  },
];

const SEVERITY_DOT = {
  CRITICAL: "dot-critical",
  HIGH: "dot-high",
  MEDIUM: "dot-medium",
  LOW: "dot-low",
};

export default function FindingsTable({ findings = null }) {
  const [expandedRow, setExpandedRow] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const displayFindings = findings || MOCK_FINDINGS;

  const handleCopy = (code, id) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="glass-card animate-slide-in stagger-2">
      <div className="card-header">
        <h3><Icon name="search" size={18} style={{ marginRight: 8, verticalAlign: "middle", color: "var(--accent-cyan)" }} /> Audit Findings</h3>
        <span style={{ fontSize: "13px", color: "var(--text-secondary)" }}>
          {displayFindings.length} issues found
        </span>
      </div>
      <div className="card-body" style={{ padding: "0 0 16px" }}>
        <table className="findings-table">
          <thead>
            <tr>
              <th>CIS Rule</th>
              <th>Severity</th>
              <th>Resource</th>
              <th>File</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            {displayFindings.map((f, i) => (
              <React.Fragment key={`finding-${i}`}>
                <tr
                  onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                  style={{ cursor: "pointer" }}
                >
                  <td>
                    <span className="rule-id">CIS {f.rule_id}</span>
                  </td>
                  <td>
                    <span className={`severity-badge ${f.severity.toLowerCase()}`}>
                      <Icon name={SEVERITY_DOT[f.severity] || "dot-medium"} size={14} />
                      {f.severity}
                    </span>
                  </td>
                  <td>
                    <span className="resource-name">{f.resource_address}</span>
                  </td>
                  <td style={{ color: "var(--text-muted)" }}>{f.file_path}</td>
                  <td>{f.description.substring(0, 80)}...</td>
                </tr>

                {expandedRow === i && (
                  <tr>
                    <td colSpan="5" style={{ padding: "0 16px 16px" }}>
                      <div
                        style={{
                          background: "rgba(0,0,0,0.2)",
                          borderRadius: "12px",
                          padding: "20px",
                          border: "1px solid var(--border-glass)",
                        }}
                      >
                        <div style={{ marginBottom: "16px" }}>
                          <h4 style={{ fontSize: "13px", color: "var(--accent-cyan)", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
                            <Icon name="brain" size={16} /> AI Reasoning
                          </h4>
                          <p style={{ fontSize: "13px", lineHeight: "1.6", color: "var(--text-secondary)" }}>
                            {f.reasoning}
                          </p>
                        </div>

                        {f.remediation_hcl && (
                          <div>
                            <div className="code-block">
                              <div className="code-header">
                                <span>Remediation — HCL</span>
                                <button
                                  className="code-copy-btn"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleCopy(f.remediation_hcl, i);
                                  }}
                                >
                                  {copiedId === i ? (
                                    <><Icon name="check" size={12} /> Copied!</>
                                  ) : (
                                    <><Icon name="copy" size={12} /> Copy</>
                                  )}
                                </button>
                              </div>
                              <div className="code-content">{f.remediation_hcl}</div>
                            </div>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
