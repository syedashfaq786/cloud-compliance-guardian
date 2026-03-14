"""
CIS Benchmark Rules — Structured definitions for AWS CIS compliance checks.

Each rule maps to a specific CIS Benchmark control with severity,
affected resource types, and human-readable descriptions.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ComplianceStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_APPLICABLE = "N/A"


@dataclass
class CISRule:
    """Represents a single CIS Benchmark rule."""
    rule_id: str
    title: str
    description: str
    severity: Severity
    resource_types: List[str]
    section: str
    rationale: str = ""
    remediation_hint: str = ""
    references: List[str] = field(default_factory=list)

    @property
    def display_id(self) -> str:
        return f"CIS {self.rule_id}"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "resource_types": self.resource_types,
            "section": self.section,
            "rationale": self.rationale,
            "remediation_hint": self.remediation_hint,
        }


# ─── CIS AWS Foundations Benchmark v1.5 / v2.0 Rules ─────────────────────────

CIS_RULES: Dict[str, CISRule] = {}


def _register(*rules: CISRule):
    for rule in rules:
        CIS_RULES[rule.rule_id] = rule


# ═══════════════════════════════════════════════════════════════════════════════
# Section 1 — Identity and Access Management
# ═══════════════════════════════════════════════════════════════════════════════

_register(
    CISRule(
        rule_id="1.4",
        title="Ensure no root account access key exists",
        description="The root account should not have access keys. Remove them and use IAM users instead.",
        severity=Severity.CRITICAL,
        resource_types=["aws_iam_access_key"],
        section="1 - Identity and Access Management",
        rationale="The root account has unrestricted access. Access keys for root expose the entire account.",
        remediation_hint="Delete root access keys and create IAM users with least-privilege policies.",
    ),
    CISRule(
        rule_id="1.5",
        title="Ensure MFA is enabled for the root account",
        description="Multi-Factor Authentication must be enabled on the root account.",
        severity=Severity.CRITICAL,
        resource_types=["aws_iam_account_password_policy"],
        section="1 - Identity and Access Management",
        rationale="MFA adds an extra layer of protection on top of a username and password.",
    ),
    CISRule(
        rule_id="1.16",
        title="Ensure IAM policies are attached only to groups or roles",
        description="IAM policies should not be directly attached to users. Attach them to groups or roles instead.",
        severity=Severity.MEDIUM,
        resource_types=["aws_iam_user_policy", "aws_iam_user_policy_attachment"],
        section="1 - Identity and Access Management",
        rationale="Attaching policies to groups/roles simplifies access management and auditing.",
        remediation_hint="Remove user-level policy attachments and assign users to groups with appropriate policies.",
    ),
    CISRule(
        rule_id="1.22",
        title="Ensure IAM policies that allow full '*:*' administrative privileges are not created",
        description="No IAM policy should grant full administrative access with Action '*' and Resource '*'.",
        severity=Severity.CRITICAL,
        resource_types=["aws_iam_policy", "aws_iam_role_policy", "aws_iam_group_policy"],
        section="1 - Identity and Access Management",
        rationale="Providing full admin privileges violates the principle of least privilege.",
        remediation_hint='Scope down the policy to only the specific actions and resources needed. Replace "*" with explicit service actions.',
    ),
)


# ═══════════════════════════════════════════════════════════════════════════════
# Section 2 — Storage
# ═══════════════════════════════════════════════════════════════════════════════

_register(
    CISRule(
        rule_id="2.1.1",
        title="Ensure S3 Bucket Policy is set to deny HTTP requests",
        description="S3 buckets should enforce encryption in transit by denying non-HTTPS requests.",
        severity=Severity.HIGH,
        resource_types=["aws_s3_bucket", "aws_s3_bucket_policy"],
        section="2 - Storage",
        rationale="Unencrypted HTTP requests expose data in transit to eavesdropping.",
        remediation_hint="Add a bucket policy that denies s3:* when aws:SecureTransport is false.",
    ),
    CISRule(
        rule_id="2.1.2",
        title="Ensure S3 bucket server-side encryption is enabled",
        description="All S3 buckets must have default server-side encryption (SSE) enabled.",
        severity=Severity.HIGH,
        resource_types=["aws_s3_bucket", "aws_s3_bucket_server_side_encryption_configuration"],
        section="2 - Storage",
        rationale="Server-side encryption protects data at rest in S3 buckets.",
        remediation_hint='Enable SSE-S3 or SSE-KMS encryption on the bucket using aws_s3_bucket_server_side_encryption_configuration.',
    ),
    CISRule(
        rule_id="2.1.4",
        title="Ensure S3 bucket public access is blocked",
        description="S3 buckets should have public access block configuration enabled.",
        severity=Severity.CRITICAL,
        resource_types=["aws_s3_bucket", "aws_s3_bucket_public_access_block"],
        section="2 - Storage",
        rationale="Public S3 buckets can lead to data breaches and unauthorized access.",
        remediation_hint="Add aws_s3_bucket_public_access_block with all four block flags set to true.",
    ),
    CISRule(
        rule_id="2.1.5",
        title="Ensure S3 bucket versioning is enabled",
        description="S3 bucket versioning should be enabled for data protection and recovery.",
        severity=Severity.MEDIUM,
        resource_types=["aws_s3_bucket", "aws_s3_bucket_versioning"],
        section="2 - Storage",
        rationale="Versioning protects against accidental deletion and enables object recovery.",
        remediation_hint='Enable versioning with aws_s3_bucket_versioning resource, status = "Enabled".',
    ),
    CISRule(
        rule_id="2.2.1",
        title="Ensure EBS volume encryption is enabled",
        description="EBS volumes should be encrypted at rest.",
        severity=Severity.HIGH,
        resource_types=["aws_ebs_volume", "aws_instance"],
        section="2 - Storage",
        rationale="Encrypting EBS volumes protects data at rest from unauthorized access.",
        remediation_hint="Set encrypted = true on aws_ebs_volume resources.",
    ),
    CISRule(
        rule_id="2.3.1",
        title="Ensure RDS instances have encryption enabled",
        description="RDS database instances must have storage encryption enabled.",
        severity=Severity.HIGH,
        resource_types=["aws_db_instance"],
        section="2 - Storage",
        rationale="Encryption at rest protects sensitive database contents.",
        remediation_hint="Set storage_encrypted = true on aws_db_instance resources.",
    ),
    CISRule(
        rule_id="2.3.2",
        title="Ensure RDS instances are not publicly accessible",
        description="RDS instances should not be publicly accessible from the internet.",
        severity=Severity.CRITICAL,
        resource_types=["aws_db_instance"],
        section="2 - Storage",
        rationale="Publicly accessible databases are exposed to brute-force and exploit attacks.",
        remediation_hint="Set publicly_accessible = false on aws_db_instance resources.",
    ),
)


# ═══════════════════════════════════════════════════════════════════════════════
# Section 3 — Logging & Monitoring
# ═══════════════════════════════════════════════════════════════════════════════

_register(
    CISRule(
        rule_id="3.1",
        title="Ensure CloudTrail is enabled in all regions",
        description="AWS CloudTrail must be enabled and configured to log in all regions.",
        severity=Severity.HIGH,
        resource_types=["aws_cloudtrail"],
        section="3 - Logging",
        rationale="CloudTrail provides audit logging of all API activity across an AWS account.",
        remediation_hint="Create an aws_cloudtrail resource with is_multi_region_trail = true.",
    ),
    CISRule(
        rule_id="3.2",
        title="Ensure CloudTrail log file validation is enabled",
        description="CloudTrail log file integrity validation must be enabled.",
        severity=Severity.MEDIUM,
        resource_types=["aws_cloudtrail"],
        section="3 - Logging",
        rationale="Log validation detects tampering of CloudTrail log files.",
        remediation_hint="Set enable_log_file_validation = true on aws_cloudtrail.",
    ),
    CISRule(
        rule_id="3.4",
        title="Ensure CloudTrail trails are integrated with CloudWatch Logs",
        description="CloudTrail should send logs to CloudWatch Logs for real-time alerting.",
        severity=Severity.MEDIUM,
        resource_types=["aws_cloudtrail"],
        section="3 - Logging",
        rationale="Integration with CloudWatch enables real-time monitoring and alerting.",
        remediation_hint="Set cloud_watch_logs_group_arn and cloud_watch_logs_role_arn on aws_cloudtrail.",
    ),
    CISRule(
        rule_id="3.7",
        title="Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
        description="CloudTrail logs should be encrypted using KMS Customer Master Keys.",
        severity=Severity.HIGH,
        resource_types=["aws_cloudtrail"],
        section="3 - Logging",
        rationale="KMS encryption provides an additional layer of protection for audit logs.",
        remediation_hint="Set kms_key_id on aws_cloudtrail to use a KMS CMK for encryption.",
    ),
)


# ═══════════════════════════════════════════════════════════════════════════════
# Section 4 — Networking
# ═══════════════════════════════════════════════════════════════════════════════

_register(
    CISRule(
        rule_id="4.1",
        title="Ensure no security group allows ingress from 0.0.0.0/0 to port 22",
        description="SSH access (port 22) must not be open to the entire internet (0.0.0.0/0).",
        severity=Severity.CRITICAL,
        resource_types=["aws_security_group", "aws_security_group_rule"],
        section="4 - Networking",
        rationale="Open SSH access exposes instances to brute-force and unauthorized access attacks.",
        remediation_hint="Restrict SSH ingress to specific trusted CIDR blocks (e.g., your VPN IP range).",
    ),
    CISRule(
        rule_id="4.2",
        title="Ensure no security group allows ingress from 0.0.0.0/0 to port 3389",
        description="RDP access (port 3389) must not be open to the entire internet.",
        severity=Severity.CRITICAL,
        resource_types=["aws_security_group", "aws_security_group_rule"],
        section="4 - Networking",
        rationale="Open RDP access is a prime target for brute-force attacks.",
        remediation_hint="Restrict RDP ingress to trusted CIDR blocks; use a bastion host or VPN.",
    ),
    CISRule(
        rule_id="4.3",
        title="Ensure no security group allows unrestricted ingress to high-risk ports",
        description="Security groups must not allow unrestricted access (0.0.0.0/0) to high-risk ports like 3306, 5432, 1433, 27017.",
        severity=Severity.HIGH,
        resource_types=["aws_security_group", "aws_security_group_rule"],
        section="4 - Networking",
        rationale="Database and service ports exposed to the internet are vulnerable to exploitation.",
        remediation_hint="Restrict database port ingress to application-tier security groups only.",
    ),
    CISRule(
        rule_id="4.9",
        title="Ensure VPC flow logging is enabled in all VPCs",
        description="VPC Flow Logs must be enabled for all VPCs to capture network traffic metadata.",
        severity=Severity.MEDIUM,
        resource_types=["aws_vpc", "aws_flow_log"],
        section="4 - Networking",
        rationale="Flow logs enable network traffic analysis and security incident investigation.",
        remediation_hint="Create an aws_flow_log resource for each VPC with traffic_type = 'ALL'.",
    ),
    CISRule(
        rule_id="4.10",
        title="Ensure the default security group of every VPC restricts all traffic",
        description="The default security group should deny all inbound and outbound traffic.",
        severity=Severity.MEDIUM,
        resource_types=["aws_default_security_group"],
        section="4 - Networking",
        rationale="The default security group is often overlooked and can allow unintended traffic.",
        remediation_hint="Set the default security group to have no ingress or egress rules.",
    ),
)


# ═══════════════════════════════════════════════════════════════════════════════
# Section 5 — Encryption & Key Management
# ═══════════════════════════════════════════════════════════════════════════════

_register(
    CISRule(
        rule_id="5.1",
        title="Ensure KMS key rotation is enabled",
        description="KMS Customer Master Keys should have automatic key rotation enabled.",
        severity=Severity.MEDIUM,
        resource_types=["aws_kms_key"],
        section="5 - Encryption",
        rationale="Regular key rotation limits the blast radius of a compromised key.",
        remediation_hint="Set enable_key_rotation = true on aws_kms_key resources.",
    ),
)


# ─── Utility Functions ───────────────────────────────────────────────────────

def get_rules_for_resource_type(resource_type: str) -> List[CISRule]:
    """Get all CIS rules applicable to a given Terraform resource type."""
    return [
        rule for rule in CIS_RULES.values()
        if resource_type in rule.resource_types
    ]


def get_rule_by_id(rule_id: str) -> Optional[CISRule]:
    """Look up a CIS rule by its ID."""
    return CIS_RULES.get(rule_id)


def get_rules_by_severity(severity: Severity) -> List[CISRule]:
    """Get all CIS rules of a given severity."""
    return [r for r in CIS_RULES.values() if r.severity == severity]


def get_all_rules() -> List[CISRule]:
    """Return all registered CIS rules."""
    return list(CIS_RULES.values())


def get_rules_summary() -> Dict[str, int]:
    """Return a count of rules by severity."""
    summary = {}
    for rule in CIS_RULES.values():
        summary[rule.severity.value] = summary.get(rule.severity.value, 0) + 1
    return summary
