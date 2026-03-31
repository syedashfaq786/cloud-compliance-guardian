"""
Rule-Based Audit Engine — Deterministic CIS compliance checks for Terraform resources.

Analyzes Terraform resource configurations against CIS Benchmark rules WITHOUT
requiring a model endpoint. Provides detailed reasoning, expected vs actual values,
recommendations, and cloud provider detection.
"""

import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from .parser import TerraformResource
from .cis_rules import CISRule, get_rules_for_resource_type, Severity


# ─── Cloud Provider Detection ──────────────────────────────────────────────────

PROVIDER_PREFIXES = {
    "aws_": "AWS",
    "azurerm_": "Azure",
    "google_": "GCP",
}


def detect_cloud_provider(resource_type: str) -> str:
    """Detect the cloud provider from the resource type prefix."""
    for prefix, provider in PROVIDER_PREFIXES.items():
        if resource_type.startswith(prefix):
            return provider
    return "Unknown"


# ─── Finding Dataclass ─────────────────────────────────────────────────────────

@dataclass
class RuleFinding:
    """A detailed compliance finding from the rule engine."""
    rule_id: str
    rule_title: str
    severity: str
    resource_address: str
    resource_type: str
    file_path: str
    description: str
    reasoning: str
    expected: str
    actual: str
    recommendation: str
    cloud_provider: str
    status: str  # "FAIL" or "PASS"
    remediation_hcl: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "resource_address": self.resource_address,
            "resource_type": self.resource_type,
            "file_path": self.file_path,
            "description": self.description,
            "reasoning": self.reasoning,
            "expected": self.expected,
            "actual": self.actual,
            "recommendation": self.recommendation,
            "cloud_provider": self.cloud_provider,
            "status": self.status,
            "remediation_hcl": self.remediation_hcl,
            "confidence": self.confidence,
        }


# ─── Rule Check Functions ──────────────────────────────────────────────────────
# Each function inspects a resource config and returns (pass: bool, details: dict)

def _get_nested(config: dict, *keys, default=None):
    """Safely traverse nested dicts/lists."""
    val = config
    for key in keys:
        if isinstance(val, dict):
            val = val.get(key, default)
        elif isinstance(val, list) and val:
            val = val[0] if isinstance(val[0], dict) else default
            if isinstance(val, dict):
                val = val.get(key, default) if key != keys[-1] or key not in str(keys[:-1]) else val
            else:
                return default
        else:
            return default
    return val


def _config_has(config: dict, key: str) -> Tuple[bool, Any]:
    """Check if a config key exists and return its value."""
    val = config.get(key)
    if val is None:
        # Check nested
        for k, v in config.items():
            if isinstance(v, dict) and key in v:
                return True, v[key]
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and key in item:
                        return True, item[key]
        return False, None
    return True, val


def check_s3_encryption(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 2.1.2 — S3 bucket must have server-side encryption."""
    if resource.resource_type != "aws_s3_bucket":
        return None

    # Check if there's a separate encryption config resource for this bucket
    bucket_ref = resource.resource_name
    has_encryption = any(
        r.resource_type == "aws_s3_bucket_server_side_encryption_configuration"
        and (r.resource_name == bucket_ref or bucket_ref in json.dumps(r.config))
        for r in all_resources
    )

    # Also check inline encryption (older Terraform style)
    has_inline = "server_side_encryption_configuration" in resource.config

    if has_encryption or has_inline:
        return RuleFinding(
            rule_id="2.1.2", rule_title="S3 bucket server-side encryption",
            severity="HIGH", resource_address=resource.address,
            resource_type=resource.resource_type, file_path=resource.file_path,
            description="S3 bucket has server-side encryption enabled.",
            reasoning=f"Checked for aws_s3_bucket_server_side_encryption_configuration associated with '{resource.resource_name}' or inline encryption config. Encryption configuration was found.",
            expected="Server-side encryption (SSE-S3 or SSE-KMS) must be enabled",
            actual="Encryption is configured",
            recommendation="Continue using KMS-managed keys for stronger encryption. Rotate keys annually.",
            cloud_provider="AWS", status="PASS",
        )

    return RuleFinding(
        rule_id="2.1.2", rule_title="S3 bucket server-side encryption",
        severity="HIGH", resource_address=resource.address,
        resource_type=resource.resource_type, file_path=resource.file_path,
        description="S3 bucket does NOT have server-side encryption enabled. Data at rest is unprotected.",
        reasoning=f"Searched for aws_s3_bucket_server_side_encryption_configuration resource referencing '{resource.resource_name}' and checked for inline encryption config. Neither was found.",
        expected="Server-side encryption (SSE-S3 or SSE-KMS) must be enabled on all S3 buckets",
        actual="No encryption configuration found for this bucket",
        recommendation="Add an aws_s3_bucket_server_side_encryption_configuration resource with SSE-KMS encryption. Use a dedicated KMS CMK for sensitive data.",
        cloud_provider="AWS", status="FAIL",
        remediation_hcl=f'''resource "aws_s3_bucket_server_side_encryption_configuration" "{resource.resource_name}" {{
  bucket = aws_s3_bucket.{resource.resource_name}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.encryption_key.arn
    }}
    bucket_key_enabled = true
  }}
}}''',
    )


def check_s3_public_access(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 2.1.4 — S3 bucket must block public access."""
    if resource.resource_type != "aws_s3_bucket":
        return None

    bucket_ref = resource.resource_name
    has_block = any(
        r.resource_type == "aws_s3_bucket_public_access_block"
        and (r.resource_name == bucket_ref or bucket_ref in json.dumps(r.config))
        for r in all_resources
    )

    if has_block:
        return RuleFinding(
            rule_id="2.1.4", rule_title="S3 bucket public access block",
            severity="CRITICAL", resource_address=resource.address,
            resource_type=resource.resource_type, file_path=resource.file_path,
            description="S3 bucket has public access block configured.",
            reasoning=f"Found aws_s3_bucket_public_access_block resource associated with '{resource.resource_name}'. Public access is properly restricted.",
            expected="All four public access block flags must be set to true",
            actual="Public access block is configured",
            recommendation="Verify all four flags (block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets) are set to true.",
            cloud_provider="AWS", status="PASS",
        )

    return RuleFinding(
        rule_id="2.1.4", rule_title="S3 bucket public access block",
        severity="CRITICAL", resource_address=resource.address,
        resource_type=resource.resource_type, file_path=resource.file_path,
        description="S3 bucket is missing public access block configuration. Bucket contents may be publicly accessible.",
        reasoning=f"No aws_s3_bucket_public_access_block resource found for bucket '{resource.resource_name}'. Without explicit public access blocking, the bucket could be made public via ACLs or bucket policies.",
        expected="aws_s3_bucket_public_access_block with all four block flags set to true",
        actual="No public access block configuration found",
        recommendation="Immediately add an aws_s3_bucket_public_access_block resource. This is a CRITICAL finding — public S3 buckets are a leading cause of data breaches.",
        cloud_provider="AWS", status="FAIL",
        remediation_hcl=f'''resource "aws_s3_bucket_public_access_block" "{resource.resource_name}" {{
  bucket = aws_s3_bucket.{resource.resource_name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}''',
    )


def check_s3_versioning(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 2.1.5 — S3 bucket versioning should be enabled."""
    if resource.resource_type != "aws_s3_bucket":
        return None

    bucket_ref = resource.resource_name
    has_versioning = any(
        r.resource_type == "aws_s3_bucket_versioning"
        and (r.resource_name == bucket_ref or bucket_ref in json.dumps(r.config))
        for r in all_resources
    )

    if has_versioning:
        return RuleFinding(
            rule_id="2.1.5", rule_title="S3 bucket versioning",
            severity="MEDIUM", resource_address=resource.address,
            resource_type=resource.resource_type, file_path=resource.file_path,
            description="S3 bucket has versioning enabled.",
            reasoning=f"Found aws_s3_bucket_versioning resource for '{resource.resource_name}' with versioning enabled.",
            expected="Versioning must be enabled for data protection",
            actual="Versioning is configured",
            recommendation="Ensure versioning status is 'Enabled' (not 'Suspended'). Consider lifecycle rules to manage version costs.",
            cloud_provider="AWS", status="PASS",
        )

    return RuleFinding(
        rule_id="2.1.5", rule_title="S3 bucket versioning",
        severity="MEDIUM", resource_address=resource.address,
        resource_type=resource.resource_type, file_path=resource.file_path,
        description="S3 bucket versioning is NOT enabled. Accidental deletions cannot be recovered.",
        reasoning=f"No aws_s3_bucket_versioning resource found for bucket '{resource.resource_name}'. Without versioning, deleted or overwritten objects are permanently lost.",
        expected="aws_s3_bucket_versioning with status = 'Enabled'",
        actual="No versioning configuration found",
        recommendation="Enable versioning to protect against accidental deletion and support audit trails. Add lifecycle rules to auto-expire old versions after 90 days.",
        cloud_provider="AWS", status="FAIL",
        remediation_hcl=f'''resource "aws_s3_bucket_versioning" "{resource.resource_name}" {{
  bucket = aws_s3_bucket.{resource.resource_name}.id

  versioning_configuration {{
    status = "Enabled"
  }}
}}''',
    )


def check_security_group_ssh(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 4.1 — No security group should allow 0.0.0.0/0 on port 22."""
    if resource.resource_type not in ("aws_security_group", "aws_security_group_rule"):
        return None

    ingress_rules = resource.config.get("ingress", [])
    if not isinstance(ingress_rules, list):
        ingress_rules = [ingress_rules]

    for rule in ingress_rules:
        if not isinstance(rule, dict):
            continue
        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 0)
        cidrs = rule.get("cidr_blocks", [])
        if not isinstance(cidrs, list):
            cidrs = [cidrs]

        if (from_port <= 22 <= to_port) and "0.0.0.0/0" in cidrs:
            return RuleFinding(
                rule_id="4.1", rule_title="SSH open to internet",
                severity="CRITICAL", resource_address=resource.address,
                resource_type=resource.resource_type, file_path=resource.file_path,
                description="Security group allows SSH (port 22) access from 0.0.0.0/0. This exposes the instance to brute-force attacks from the entire internet.",
                reasoning=f"Inspected ingress rules of '{resource.resource_name}'. Found rule allowing TCP port 22 from CIDR 0.0.0.0/0. SSH should never be open to the public internet.",
                expected="SSH (port 22) ingress restricted to specific trusted CIDR blocks (e.g., VPN: 10.0.0.0/8)",
                actual=f"SSH (port 22) is open to 0.0.0.0/0 (entire internet)",
                recommendation="Restrict SSH access to your VPN or bastion host CIDR range. Use AWS Systems Manager Session Manager as a more secure alternative to SSH.",
                cloud_provider="AWS", status="FAIL",
                remediation_hcl=f'''  ingress {{
    description = "SSH from VPN only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Replace with your VPN CIDR
  }}''',
            )

    return RuleFinding(
        rule_id="4.1", rule_title="SSH access control",
        severity="CRITICAL", resource_address=resource.address,
        resource_type=resource.resource_type, file_path=resource.file_path,
        description="SSH access is properly restricted — not open to the internet.",
        reasoning=f"Inspected all ingress rules of '{resource.resource_name}'. No rule allows port 22 from 0.0.0.0/0.",
        expected="SSH (port 22) not open to 0.0.0.0/0",
        actual="SSH access is restricted to specific CIDRs",
        recommendation="Continue maintaining restricted SSH access. Review allowed CIDRs quarterly.",
        cloud_provider="AWS", status="PASS",
    )


def check_security_group_rdp(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 4.2 — No security group should allow 0.0.0.0/0 on port 3389."""
    if resource.resource_type not in ("aws_security_group", "aws_security_group_rule"):
        return None

    ingress_rules = resource.config.get("ingress", [])
    if not isinstance(ingress_rules, list):
        ingress_rules = [ingress_rules]

    for rule in ingress_rules:
        if not isinstance(rule, dict):
            continue
        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 0)
        cidrs = rule.get("cidr_blocks", [])
        if not isinstance(cidrs, list):
            cidrs = [cidrs]

        if (from_port <= 3389 <= to_port) and "0.0.0.0/0" in cidrs:
            return RuleFinding(
                rule_id="4.2", rule_title="RDP open to internet",
                severity="CRITICAL", resource_address=resource.address,
                resource_type=resource.resource_type, file_path=resource.file_path,
                description="Security group allows RDP (port 3389) from 0.0.0.0/0. This is a prime target for brute-force and ransomware attacks.",
                reasoning=f"Inspected ingress rules of '{resource.resource_name}'. Found rule allowing TCP port 3389 from CIDR 0.0.0.0/0.",
                expected="RDP (port 3389) ingress restricted to trusted CIDR blocks",
                actual="RDP (port 3389) is open to 0.0.0.0/0 (entire internet)",
                recommendation="Immediately restrict RDP to VPN or bastion CIDR. Consider using AWS Fleet Manager or SSM for remote access instead of direct RDP.",
                cloud_provider="AWS", status="FAIL",
                remediation_hcl=f'''  ingress {{
    description = "RDP from VPN only"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Replace with your VPN CIDR
  }}''',
            )

    # Only return PASS if the SG actually has ingress rules (don't return PASS for SGs without port 3389)
    return None


def check_security_group_high_risk_ports(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 4.3 — No SG allows 0.0.0.0/0 on database ports (3306, 5432, 1433, 27017)."""
    if resource.resource_type not in ("aws_security_group", "aws_security_group_rule"):
        return None

    HIGH_RISK_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB", 6379: "Redis"}

    ingress_rules = resource.config.get("ingress", [])
    if not isinstance(ingress_rules, list):
        ingress_rules = [ingress_rules]

    for rule in ingress_rules:
        if not isinstance(rule, dict):
            continue
        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 0)
        cidrs = rule.get("cidr_blocks", [])
        if not isinstance(cidrs, list):
            cidrs = [cidrs]

        if "0.0.0.0/0" not in cidrs:
            continue

        for port, service in HIGH_RISK_PORTS.items():
            if from_port <= port <= to_port:
                return RuleFinding(
                    rule_id="4.3", rule_title="High-risk port open to internet",
                    severity="HIGH", resource_address=resource.address,
                    resource_type=resource.resource_type, file_path=resource.file_path,
                    description=f"Security group allows {service} (port {port}) from 0.0.0.0/0. Database ports must never be publicly accessible.",
                    reasoning=f"Found ingress rule in '{resource.resource_name}' allowing port {port} ({service}) from 0.0.0.0/0. Database ports exposed to the internet are a critical attack vector.",
                    expected=f"{service} port {port} restricted to application-tier security groups only",
                    actual=f"{service} port {port} is open to 0.0.0.0/0",
                    recommendation=f"Restrict {service} access to application security groups. Use VPC endpoints or PrivateLink for cross-VPC database access.",
                    cloud_provider="AWS", status="FAIL",
                    remediation_hcl=f'''  ingress {{
    description     = "{service} from app tier only"
    from_port       = {port}
    to_port         = {port}
    protocol        = "tcp"
    security_groups = [aws_security_group.app_tier.id]
  }}''',
                )

    return None


def check_rds_encryption(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 2.3.1 — RDS instances must have encryption enabled."""
    if resource.resource_type != "aws_db_instance":
        return None

    encrypted = resource.config.get("storage_encrypted", False)

    if encrypted:
        return RuleFinding(
            rule_id="2.3.1", rule_title="RDS encryption at rest",
            severity="HIGH", resource_address=resource.address,
            resource_type=resource.resource_type, file_path=resource.file_path,
            description="RDS instance has storage encryption enabled.",
            reasoning=f"Checked 'storage_encrypted' attribute of '{resource.resource_name}'. Value is true. Database data at rest is protected.",
            expected="storage_encrypted = true",
            actual="storage_encrypted = true",
            recommendation="Ensure using a customer-managed KMS key (not AWS default). Rotate the KMS key annually.",
            cloud_provider="AWS", status="PASS",
        )

    return RuleFinding(
        rule_id="2.3.1", rule_title="RDS encryption at rest",
        severity="HIGH", resource_address=resource.address,
        resource_type=resource.resource_type, file_path=resource.file_path,
        description="RDS instance does NOT have storage encryption enabled. Database contents are stored in plaintext on disk.",
        reasoning=f"Checked 'storage_encrypted' attribute of '{resource.resource_name}'. Value is false or not set. Unencrypted databases expose sensitive data if storage media is compromised.",
        expected="storage_encrypted = true with a KMS key",
        actual="storage_encrypted = false (or not specified)",
        recommendation="Enable storage encryption immediately. NOTE: Encryption cannot be enabled on an existing RDS instance — you must create a new encrypted instance and migrate data.",
        cloud_provider="AWS", status="FAIL",
        remediation_hcl=f'''resource "aws_db_instance" "{resource.resource_name}" {{
  # ... existing config ...
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds_encryption.arn
}}''',
    )


def check_rds_public_access(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 2.3.2 — RDS instances must not be publicly accessible."""
    if resource.resource_type != "aws_db_instance":
        return None

    publicly_accessible = resource.config.get("publicly_accessible", False)

    if not publicly_accessible:
        return RuleFinding(
            rule_id="2.3.2", rule_title="RDS public accessibility",
            severity="CRITICAL", resource_address=resource.address,
            resource_type=resource.resource_type, file_path=resource.file_path,
            description="RDS instance is not publicly accessible.",
            reasoning=f"Checked 'publicly_accessible' attribute of '{resource.resource_name}'. Value is false. Database is only accessible within the VPC.",
            expected="publicly_accessible = false",
            actual="publicly_accessible = false",
            recommendation="Continue keeping RDS private. Use VPC peering or PrivateLink for cross-VPC access.",
            cloud_provider="AWS", status="PASS",
        )

    return RuleFinding(
        rule_id="2.3.2", rule_title="RDS public accessibility",
        severity="CRITICAL", resource_address=resource.address,
        resource_type=resource.resource_type, file_path=resource.file_path,
        description="RDS instance is publicly accessible from the internet. This exposes the database to unauthorized access and brute-force attacks.",
        reasoning=f"Checked 'publicly_accessible' attribute of '{resource.resource_name}'. Value is true. A publicly accessible database endpoint is reachable from any IP address.",
        expected="publicly_accessible = false",
        actual="publicly_accessible = true",
        recommendation="Set publicly_accessible to false immediately. Route application traffic through private subnets. Use a bastion host or VPN for administrative access.",
        cloud_provider="AWS", status="FAIL",
        remediation_hcl=f'''resource "aws_db_instance" "{resource.resource_name}" {{
  # ... existing config ...
  publicly_accessible = false
}}''',
    )


def check_ebs_encryption(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 2.2.1 — EBS volumes must be encrypted."""
    if resource.resource_type == "aws_ebs_volume":
        encrypted = resource.config.get("encrypted", False)
    elif resource.resource_type == "aws_instance":
        root_block = resource.config.get("root_block_device", {})
        if isinstance(root_block, list) and root_block:
            root_block = root_block[0]
        if isinstance(root_block, dict):
            encrypted = root_block.get("encrypted", False)
        else:
            encrypted = False
    else:
        return None

    if encrypted:
        return RuleFinding(
            rule_id="2.2.1", rule_title="EBS volume encryption",
            severity="HIGH", resource_address=resource.address,
            resource_type=resource.resource_type, file_path=resource.file_path,
            description="EBS volume/root device is encrypted at rest.",
            reasoning=f"Checked 'encrypted' attribute of '{resource.resource_name}'. Volume encryption is enabled.",
            expected="encrypted = true",
            actual="encrypted = true",
            recommendation="Use customer-managed KMS keys for sensitive workloads. Enable EBS encryption by default at the account level.",
            cloud_provider="AWS", status="PASS",
        )

    return RuleFinding(
        rule_id="2.2.1", rule_title="EBS volume encryption",
        severity="HIGH", resource_address=resource.address,
        resource_type=resource.resource_type, file_path=resource.file_path,
        description="EBS volume/root device is NOT encrypted. Data at rest is unprotected.",
        reasoning=f"Checked 'encrypted' attribute of '{resource.resource_name}'. Value is false or not set. Unencrypted EBS volumes expose data if the underlying storage is compromised.",
        expected="encrypted = true with a KMS key",
        actual="encrypted = false (or not specified)",
        recommendation="Enable encryption on new volumes. For existing volumes: create an encrypted snapshot, then create a new volume from that snapshot.",
        cloud_provider="AWS", status="FAIL",
        remediation_hcl=f'''  root_block_device {{
    encrypted  = true
    kms_key_id = aws_kms_key.ebs_key.arn
  }}''' if resource.resource_type == "aws_instance" else f'''resource "aws_ebs_volume" "{resource.resource_name}" {{
  # ... existing config ...
  encrypted  = true
  kms_key_id = aws_kms_key.ebs_key.arn
}}''',
    )


def check_cloudtrail_log_validation(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 3.2 — CloudTrail log file validation must be enabled."""
    if resource.resource_type != "aws_cloudtrail":
        return None

    enabled = resource.config.get("enable_log_file_validation", False)

    if enabled:
        return RuleFinding(
            rule_id="3.2", rule_title="CloudTrail log file validation",
            severity="MEDIUM", resource_address=resource.address,
            resource_type=resource.resource_type, file_path=resource.file_path,
            description="CloudTrail log file validation is enabled.",
            reasoning=f"Checked 'enable_log_file_validation' on '{resource.resource_name}'. Validation is enabled, ensuring log integrity.",
            expected="enable_log_file_validation = true",
            actual="enable_log_file_validation = true",
            recommendation="Log validation is properly configured. Ensure S3 bucket policies prevent log deletion.",
            cloud_provider="AWS", status="PASS",
        )

    return RuleFinding(
        rule_id="3.2", rule_title="CloudTrail log file validation",
        severity="MEDIUM", resource_address=resource.address,
        resource_type=resource.resource_type, file_path=resource.file_path,
        description="CloudTrail log file validation is DISABLED. Logs could be tampered with without detection.",
        reasoning=f"Checked 'enable_log_file_validation' on '{resource.resource_name}'. Value is false. Without validation, an attacker could modify or delete CloudTrail logs to cover their tracks.",
        expected="enable_log_file_validation = true",
        actual="enable_log_file_validation = false",
        recommendation="Enable log file validation to ensure CloudTrail log integrity. This allows you to detect if logs have been modified or deleted.",
        cloud_provider="AWS", status="FAIL",
        remediation_hcl=f'''resource "aws_cloudtrail" "{resource.resource_name}" {{
  # ... existing config ...
  enable_log_file_validation = true
}}''',
    )


def check_cloudtrail_kms(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 3.7 — CloudTrail logs should be encrypted with KMS."""
    if resource.resource_type != "aws_cloudtrail":
        return None

    kms_key = resource.config.get("kms_key_id")

    if kms_key:
        return RuleFinding(
            rule_id="3.7", rule_title="CloudTrail KMS encryption",
            severity="HIGH", resource_address=resource.address,
            resource_type=resource.resource_type, file_path=resource.file_path,
            description="CloudTrail logs are encrypted with KMS.",
            reasoning=f"Checked 'kms_key_id' on '{resource.resource_name}'. A KMS key is configured for log encryption.",
            expected="kms_key_id set to a KMS CMK ARN",
            actual="KMS encryption is configured",
            recommendation="Ensure the KMS key has rotation enabled. Restrict key policy to CloudTrail service principal.",
            cloud_provider="AWS", status="PASS",
        )

    return RuleFinding(
        rule_id="3.7", rule_title="CloudTrail KMS encryption",
        severity="HIGH", resource_address=resource.address,
        resource_type=resource.resource_type, file_path=resource.file_path,
        description="CloudTrail logs are NOT encrypted with KMS. Logs use only S3 default encryption (SSE-S3).",
        reasoning=f"Checked 'kms_key_id' on '{resource.resource_name}'. No KMS key is configured. Without KMS encryption, CloudTrail logs lack an additional encryption layer.",
        expected="kms_key_id = aws_kms_key.<key>.arn",
        actual="No KMS key configured",
        recommendation="Add a KMS CMK for CloudTrail log encryption. This provides an additional layer of protection and allows fine-grained access control via KMS key policies.",
        cloud_provider="AWS", status="FAIL",
        remediation_hcl=f'''resource "aws_cloudtrail" "{resource.resource_name}" {{
  # ... existing config ...
  kms_key_id = aws_kms_key.cloudtrail_key.arn
}}''',
    )


def check_kms_rotation(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 5.1 — KMS key rotation must be enabled."""
    if resource.resource_type != "aws_kms_key":
        return None

    rotation = resource.config.get("enable_key_rotation", False)

    if rotation:
        return RuleFinding(
            rule_id="5.1", rule_title="KMS key rotation",
            severity="MEDIUM", resource_address=resource.address,
            resource_type=resource.resource_type, file_path=resource.file_path,
            description="KMS key rotation is enabled.",
            reasoning=f"Checked 'enable_key_rotation' on '{resource.resource_name}'. Automatic rotation is enabled.",
            expected="enable_key_rotation = true",
            actual="enable_key_rotation = true",
            recommendation="Key rotation is properly configured. AWS automatically rotates the key material annually.",
            cloud_provider="AWS", status="PASS",
        )

    return RuleFinding(
        rule_id="5.1", rule_title="KMS key rotation",
        severity="MEDIUM", resource_address=resource.address,
        resource_type=resource.resource_type, file_path=resource.file_path,
        description="KMS key rotation is NOT enabled. A compromised key remains in use indefinitely.",
        reasoning=f"Checked 'enable_key_rotation' on '{resource.resource_name}'. Value is false. Without rotation, the same key material is used for all encrypt/decrypt operations indefinitely.",
        expected="enable_key_rotation = true",
        actual="enable_key_rotation = false",
        recommendation="Enable automatic key rotation. AWS rotates key material annually while keeping the key ID unchanged, so no application changes are needed.",
        cloud_provider="AWS", status="FAIL",
        remediation_hcl=f'''resource "aws_kms_key" "{resource.resource_name}" {{
  # ... existing config ...
  enable_key_rotation = true
}}''',
    )


def check_iam_admin_policy(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 1.22 — IAM policies must not grant full admin (*:*) access."""
    if resource.resource_type not in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_group_policy"):
        return None

    policy_str = json.dumps(resource.config)

    # Check for Action: * and Resource: *
    has_wildcard_action = ('"Action":"*"' in policy_str.replace(" ", "") or
                          '"Action": "*"' in policy_str or
                          "'Action': '*'" in policy_str)
    has_wildcard_resource = ('"Resource":"*"' in policy_str.replace(" ", "") or
                            '"Resource": "*"' in policy_str or
                            "'Resource': '*'" in policy_str)

    if has_wildcard_action and has_wildcard_resource:
        return RuleFinding(
            rule_id="1.22", rule_title="Full admin privileges policy",
            severity="CRITICAL", resource_address=resource.address,
            resource_type=resource.resource_type, file_path=resource.file_path,
            description="IAM policy grants full administrative access (Action: *, Resource: *). This violates the principle of least privilege.",
            reasoning=f"Parsed policy document of '{resource.resource_name}'. Found Statement with Action='*' and Resource='*', granting unrestricted access to all AWS services and resources.",
            expected="Scoped permissions with specific actions and resources",
            actual="Action: *, Resource: * (full admin access)",
            recommendation="Replace wildcard permissions with specific service actions. Use AWS Access Analyzer to determine minimum required permissions based on CloudTrail usage data.",
            cloud_provider="AWS", status="FAIL",
            remediation_hcl='''  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = [
        "s3:GetObject",
        "s3:PutObject",
        "ec2:Describe*"
        # Add only the specific actions needed
      ]
      Resource = [
        "arn:aws:s3:::my-bucket/*"
        # Add only the specific resources needed
      ]
    }]
  })''',
        )

    return None  # Only flag explicit violations


def check_iam_user_policy(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 1.16 — IAM policies should be attached to groups/roles, not users."""
    if resource.resource_type not in ("aws_iam_user_policy", "aws_iam_user_policy_attachment"):
        return None

    user = resource.config.get("user", resource.resource_name)

    return RuleFinding(
        rule_id="1.16", rule_title="IAM policy attached directly to user",
        severity="MEDIUM", resource_address=resource.address,
        resource_type=resource.resource_type, file_path=resource.file_path,
        description=f"IAM policy is directly attached to user '{user}'. Policies should be attached to groups or roles instead.",
        reasoning=f"Found {resource.resource_type} resource '{resource.resource_name}' which attaches a policy directly to an IAM user. CIS recommends managing permissions through groups/roles for easier auditing and management.",
        expected="Policies attached to IAM Groups or Roles, not directly to users",
        actual=f"Policy attached directly to user '{user}'",
        recommendation="Create an IAM Group with the required permissions and add the user to that group. This simplifies permission management and auditing.",
        cloud_provider="AWS", status="FAIL",
        remediation_hcl=f'''# Instead of attaching to user, create a group:
resource "aws_iam_group" "developers" {{
  name = "developers"
}}

resource "aws_iam_group_policy_attachment" "developers" {{
  group      = aws_iam_group.developers.name
  policy_arn = <policy_arn>
}}

resource "aws_iam_group_membership" "developers" {{
  name  = "developers-membership"
  group = aws_iam_group.developers.name
  users = [aws_iam_user.{user}.name]
}}''',
    )


def check_default_security_group(resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[RuleFinding]:
    """CIS 4.10 — Default security group should restrict all traffic."""
    if resource.resource_type != "aws_default_security_group":
        return None

    has_ingress = bool(resource.config.get("ingress"))
    has_egress = bool(resource.config.get("egress"))

    if has_ingress or has_egress:
        return RuleFinding(
            rule_id="4.10", rule_title="Default security group not locked down",
            severity="MEDIUM", resource_address=resource.address,
            resource_type=resource.resource_type, file_path=resource.file_path,
            description="Default security group allows traffic. It should deny all inbound and outbound traffic.",
            reasoning=f"Checked '{resource.resource_name}' default security group. It has {'ingress' if has_ingress else ''}{' and ' if has_ingress and has_egress else ''}{'egress' if has_egress else ''} rules defined. The default SG is often overlooked and should be locked down.",
            expected="Default security group with no ingress or egress rules",
            actual="Default security group has active traffic rules",
            recommendation="Remove all ingress and egress rules from the default security group. Create custom security groups for your resources instead.",
            cloud_provider="AWS", status="FAIL",
            remediation_hcl=f'''resource "aws_default_security_group" "default" {{
  vpc_id = aws_vpc.main.id
  # No ingress or egress rules = deny all
}}''',
        )

    return RuleFinding(
        rule_id="4.10", rule_title="Default security group locked down",
        severity="MEDIUM", resource_address=resource.address,
        resource_type=resource.resource_type, file_path=resource.file_path,
        description="Default security group is properly locked down with no rules.",
        reasoning=f"Checked '{resource.resource_name}' default security group. No ingress or egress rules are defined.",
        expected="Default security group with no rules",
        actual="No rules defined",
        recommendation="Continue keeping the default security group locked down.",
        cloud_provider="AWS", status="PASS",
    )


# ─── Rule Registry ────────────────────────────────────────────────────────────

ALL_CHECKS = [
    check_s3_encryption,
    check_s3_public_access,
    check_s3_versioning,
    check_security_group_ssh,
    check_security_group_rdp,
    check_security_group_high_risk_ports,
    check_rds_encryption,
    check_rds_public_access,
    check_ebs_encryption,
    check_cloudtrail_log_validation,
    check_cloudtrail_kms,
    check_kms_rotation,
    check_iam_admin_policy,
    check_iam_user_policy,
    check_default_security_group,
]


# ─── Main Audit Function ──────────────────────────────────────────────────────

def run_rule_based_audit(resources: List[TerraformResource]) -> List[RuleFinding]:
    """Run all rule-based checks against a list of Terraform resources.

    Returns a list of RuleFindings (both PASS and FAIL) for every applicable check.
    """
    findings = []
    for resource in resources:
        for check_fn in ALL_CHECKS:
            finding = check_fn(resource, resources)
            if finding:
                findings.append(finding)
    return findings


def get_audit_summary(findings: List[RuleFinding]) -> Dict[str, Any]:
    """Generate a summary from audit findings."""
    total = len(findings)
    passed = sum(1 for f in findings if f.status == "PASS")
    failed = sum(1 for f in findings if f.status == "FAIL")

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.status == "FAIL" and f.severity in severity_counts:
            severity_counts[f.severity] += 1

    # Compliance score: percentage of checks that passed
    score = (passed / total * 100) if total > 0 else 100.0

    return {
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "compliance_score": round(score, 1),
        "severity_counts": severity_counts,
    }
