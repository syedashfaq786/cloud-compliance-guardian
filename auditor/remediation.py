"""
Remediation Engine — Generates and validates HCL fix snippets.

Provides fallback rule-based remediations for common CIS violations
and formats code blocks for PR comments and dashboard display.
"""

from typing import Dict, Optional


# ─── Fallback Remediation Templates ──────────────────────────────────────────
# Used when the AI model doesn't provide a remediation or the response is poor.

REMEDIATION_TEMPLATES: Dict[str, str] = {

    # ── S3 ────────────────────────────────────────────────────────────────────

    "2.1.1": '''# CIS 2.1.1 — Enforce HTTPS-only access on S3 bucket
resource "aws_s3_bucket_policy" "{bucket_name}_ssl" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.{bucket_name}.arn,
          "${{aws_s3_bucket.{bucket_name}.arn}}/*"
        ]
        Condition = {{
          Bool = {{
            "aws:SecureTransport" = "false"
          }}
        }}
      }}
    ]
  }})
}}''',

    "2.1.2": '''# CIS 2.1.2 — Enable server-side encryption on S3 bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "{bucket_name}_sse" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "aws:kms"
    }}
    bucket_key_enabled = true
  }}
}}''',

    "2.1.4": '''# CIS 2.1.4 — Block all public access on S3 bucket
resource "aws_s3_bucket_public_access_block" "{bucket_name}_public_block" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}''',

    "2.1.5": '''# CIS 2.1.5 — Enable versioning on S3 bucket
resource "aws_s3_bucket_versioning" "{bucket_name}_versioning" {{
  bucket = aws_s3_bucket.{bucket_name}.id

  versioning_configuration {{
    status = "Enabled"
  }}
}}''',

    # ── EBS & RDS ─────────────────────────────────────────────────────────────

    "2.2.1": '''# CIS 2.2.1 — Enable EBS volume encryption
resource "aws_ebs_volume" "{resource_name}" {{
  availability_zone = var.availability_zone
  size              = 20
  encrypted         = true  # <-- REQUIRED for CIS 2.2.1
  kms_key_id        = var.kms_key_id

  tags = {{
    Name = "{resource_name}"
  }}
}}''',

    "2.3.1": '''# CIS 2.3.1 — Enable RDS encryption at rest
resource "aws_db_instance" "{resource_name}" {{
  # ... existing configuration ...
  storage_encrypted = true  # <-- REQUIRED for CIS 2.3.1
  kms_key_id        = var.kms_key_id
}}''',

    "2.3.2": '''# CIS 2.3.2 — Disable public access on RDS instance
resource "aws_db_instance" "{resource_name}" {{
  # ... existing configuration ...
  publicly_accessible = false  # <-- REQUIRED for CIS 2.3.2
}}''',

    # ── CloudTrail ────────────────────────────────────────────────────────────

    "3.1": '''# CIS 3.1 — Enable CloudTrail in all regions
resource "aws_cloudtrail" "main" {{
  name                          = "compliance-guardian-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = true   # <-- REQUIRED for CIS 3.1
  include_global_service_events = true
  enable_logging                = true
}}''',

    "3.2": '''# CIS 3.2 — Enable CloudTrail log file validation
resource "aws_cloudtrail" "main" {{
  # ... existing configuration ...
  enable_log_file_validation = true  # <-- REQUIRED for CIS 3.2
}}''',

    # ── Security Groups ──────────────────────────────────────────────────────

    "4.1": '''# CIS 4.1 — Restrict SSH access to trusted CIDRs only
resource "aws_security_group_rule" "{resource_name}_ssh" {{
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]  # <-- Replace 0.0.0.0/0 with your VPN/office CIDR
  security_group_id = aws_security_group.{resource_name}.id
  description       = "SSH access from internal network only"
}}''',

    "4.2": '''# CIS 4.2 — Restrict RDP access to trusted CIDRs only
resource "aws_security_group_rule" "{resource_name}_rdp" {{
  type              = "ingress"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]  # <-- Replace 0.0.0.0/0 with your VPN/office CIDR
  security_group_id = aws_security_group.{resource_name}.id
  description       = "RDP access from internal network only"
}}''',

    # ── VPC ───────────────────────────────────────────────────────────────────

    "4.9": '''# CIS 4.9 — Enable VPC Flow Logs
resource "aws_flow_log" "{resource_name}_flow_log" {{
  vpc_id          = aws_vpc.{resource_name}.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
}}''',

    # ── KMS ───────────────────────────────────────────────────────────────────

    "5.1": '''# CIS 5.1 — Enable KMS key rotation
resource "aws_kms_key" "{resource_name}" {{
  description         = "KMS key with automatic rotation"
  enable_key_rotation = true  # <-- REQUIRED for CIS 5.1

  tags = {{
    Name = "{resource_name}"
  }}
}}''',
}


def get_fallback_remediation(rule_id: str, **kwargs) -> Optional[str]:
    """Get a fallback remediation template for a given CIS rule."""
    template = REMEDIATION_TEMPLATES.get(rule_id)
    if template and kwargs:
        try:
            return template.format(**kwargs)
        except KeyError:
            return template
    return template


def format_remediation_for_pr(rule_id: str, hcl_code: str) -> str:
    """Format a remediation snippet for GitHub PR comment (markdown)."""
    return (
        f"**Remediation for CIS {rule_id}:**\n\n"
        f"```hcl\n{hcl_code}\n```\n"
    )


def format_remediation_for_dashboard(rule_id: str, hcl_code: str) -> Dict:
    """Format a remediation snippet for dashboard display."""
    return {
        "rule_id": rule_id,
        "language": "hcl",
        "code": hcl_code,
        "copyable": True,
    }


def validate_remediation(hcl_code: str) -> bool:
    """Basic validation that the remediation looks like valid HCL."""
    if not hcl_code or not hcl_code.strip():
        return False
    # Check for basic HCL structure indicators
    has_resource = "resource" in hcl_code or "module" in hcl_code or "=" in hcl_code
    has_braces = "{" in hcl_code and "}" in hcl_code
    return has_resource and has_braces


def enrich_remediation(rule_id: str, ai_remediation: str, resource_name: str = "example") -> str:
    """Enrich AI-generated remediation or fall back to template."""
    if ai_remediation and validate_remediation(ai_remediation):
        return ai_remediation

    # Fall back to template
    fallback = get_fallback_remediation(
        rule_id,
        bucket_name=resource_name,
        resource_name=resource_name,
    )
    return fallback or f"# Manual remediation required for CIS {rule_id}\n# See CIS Benchmark documentation for details."
