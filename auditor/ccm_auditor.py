"""
CSA Cloud Controls Matrix (CCM) v4.1 Auditor — Direct checks against AWS resources.

Performs genuine CCM v4.1 control checks. Does not map from CIS findings;
writes checks directly against the resource data from aws_scanner.py.

Function signature:
    audit_aws_resources_ccm(scan_data: dict) -> dict
"""

from datetime import datetime, timezone
from typing import Any, Dict, List


# ── Finding Builder ────────────────────────────────────────────────────────────

def _finding(
    resource_id: str,
    resource_name: str,
    resource_type: str,
    status: str,
    severity: str,
    rule_id: str,
    title: str,
    description: str,
    reasoning: str,
    expected: str,
    actual: str,
    recommendation: str,
    remediation_step: str,
    region: str = "global",
) -> Dict[str, Any]:
    return {
        "resource_id": resource_id,
        "resource_name": resource_name,
        "resource_type": resource_type,
        "region": region,
        "status": status,
        "severity": severity,
        "framework": "CCM",
        "rule_id": rule_id,
        "cis_rule_id": rule_id,
        "title": title,
        "description": description,
        "reasoning": reasoning,
        "expected": expected,
        "actual": actual,
        "recommendation": recommendation,
        "remediation_step": remediation_step,
    }


# ── IAM-07: Multi-Factor Authentication ───────────────────────────────────────

def _check_iam07_mfa(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """IAM-07: IAM users without MFA enabled."""
    findings = []
    iam_users = [r for r in resources if r.get("resource_type") == "aws_iam_user"]

    for user in iam_users:
        name = user.get("resource_name", "unknown")
        rid = user.get("resource_id", "")
        config = user.get("config", {})
        region = user.get("region", "global")
        has_mfa = config.get("has_mfa", False)

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_iam_user",
            status="PASS" if has_mfa else "FAIL",
            severity="HIGH",
            rule_id="IAM-07",
            title="IAM-07: Multi-Factor Authentication — MFA Not Enabled",
            description=f"IAM user '{name}' does not have MFA enabled. CCM IAM-07 requires multi-factor authentication for all user accounts accessing cloud environments.",
            reasoning=f"Checked MFA device enrollment for user '{name}'. has_mfa={has_mfa}.",
            expected="MFA device enrolled for all IAM users",
            actual=f"has_mfa: {has_mfa}",
            recommendation="Enable virtual or hardware MFA for all IAM users with AWS console access.",
            remediation_step="aws iam enable-mfa-device --user-name USER --serial-number ARN --authentication-code1 CODE1 --authentication-code2 CODE2",
            region=region,
        ))

    return findings


# ── IAM-02: Strong Authentication / Access Key Rotation ───────────────────────

def _check_iam02_key_rotation(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """IAM-02: Access keys older than 90 days (credential hygiene)."""
    findings = []
    iam_users = [r for r in resources if r.get("resource_type") == "aws_iam_user"]

    for user in iam_users:
        name = user.get("resource_name", "unknown")
        rid = user.get("resource_id", "")
        config = user.get("config", {})
        region = user.get("region", "global")
        access_keys = config.get("access_keys", [])

        active_keys = [k for k in access_keys if k.get("status", "") == "Active"]
        if not active_keys:
            # No active keys — compliant by default for this control
            findings.append(_finding(
                resource_id=rid,
                resource_name=name,
                resource_type="aws_iam_user",
                status="PASS",
                severity="MEDIUM",
                rule_id="IAM-02",
                title="IAM-02: Strong Password Policy — No Active Access Keys",
                description=f"IAM user '{name}' has no active access keys.",
                reasoning="No active access keys found for this user.",
                expected="Access keys rotated within 90 days",
                actual="No active access keys",
                recommendation="No action required.",
                remediation_step="",
                region=region,
            ))
            continue

        for key in active_keys:
            age_days = key.get("age_days", 0)
            is_old = key.get("is_old", False) or age_days > 90
            findings.append(_finding(
                resource_id=rid,
                resource_name=name,
                resource_type="aws_iam_user",
                status="FAIL" if is_old else "PASS",
                severity="MEDIUM",
                rule_id="IAM-02",
                title="IAM-02: Strong Password Policy — Access Key Rotation Required",
                description=f"IAM user '{name}' has an active access key that is {age_days} days old. CCM IAM-02 requires credential rotation to maintain a strong authentication posture.",
                reasoning=f"Access key creation date for user '{name}' indicates key is {age_days} days old. CCM recommends rotation within 90 days.",
                expected="Access keys rotated within 90 days",
                actual=f"Key age: {age_days} days",
                recommendation="Rotate all active access keys that are older than 90 days.",
                remediation_step="aws iam create-access-key --user-name USER  # then update applications and delete old key",
                region=region,
            ))

    return findings


# ── IAM-09: User Access Reviews (Wildcard Policies) ───────────────────────────

def _check_iam09_wildcard_policies(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """IAM-09: Policies with wildcard resource or action permissions."""
    findings = []
    iam_policies = [r for r in resources if r.get("resource_type") == "aws_iam_policy"]

    for pol in iam_policies:
        name = pol.get("resource_name", "unknown")
        rid = pol.get("resource_id", "")
        config = pol.get("config", {})
        statements = config.get("statements", [])
        region = pol.get("region", "global")

        wildcard_resource_stmts = []
        for stmt in statements:
            if stmt.get("effect") != "Allow":
                continue
            resources_list = stmt.get("resource", [])
            if isinstance(resources_list, str):
                resources_list = [resources_list]
            if "*" in resources_list:
                actions = stmt.get("action", [])
                if isinstance(actions, str):
                    actions = [actions]
                wildcard_resource_stmts.append(str(actions)[:80])

        has_wildcards = bool(wildcard_resource_stmts)
        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_iam_policy",
            status="FAIL" if has_wildcards else "PASS",
            severity="HIGH",
            rule_id="IAM-09",
            title="IAM-09: User Access Reviews — Wildcard Resource Permissions",
            description=f"IAM policy '{name}' contains Allow statements on Resource:* for actions: {wildcard_resource_stmts}. CCM IAM-09 requires periodic review and restriction of over-privileged access.",
            reasoning=f"Found {len(wildcard_resource_stmts)} Allow statement(s) with Resource:* in policy '{name}'.",
            expected="All Allow statements scoped to specific resource ARNs",
            actual=f"Wildcard resource Allow statements: {len(wildcard_resource_stmts)}",
            recommendation="Scope IAM policy statements to specific resource ARNs instead of using Resource:*.",
            remediation_step=f"aws iam create-policy-version --policy-arn ARN --policy-document file://scoped-policy.json --set-as-default",
            region=region,
        ))

    return findings


# ── IAM-01: IAM Policy — Admin Wildcard ───────────────────────────────────────

def _check_iam01_admin_policy(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """IAM-01: IAM policies with Action:* Resource:* (full admin)."""
    findings = []
    iam_policies = [r for r in resources if r.get("resource_type") == "aws_iam_policy"]

    for pol in iam_policies:
        name = pol.get("resource_name", "unknown")
        rid = pol.get("resource_id", "")
        config = pol.get("config", {})
        region = pol.get("region", "global")
        has_admin = config.get("has_admin_access", False)

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_iam_policy",
            status="FAIL" if has_admin else "PASS",
            severity="CRITICAL",
            rule_id="IAM-01",
            title="IAM-01: IAM Policy — Admin Wildcard Policy Detected",
            description=f"IAM policy '{name}' grants Action:* on Resource:* — a full-admin policy. CCM IAM-01 requires that IAM policies follow least-privilege principles.",
            reasoning=f"Policy document has_admin_access flag is {has_admin}. Checked for Allow * on * statements.",
            expected="No policy grants Action:* Resource:*",
            actual=f"has_admin_access: {has_admin}",
            recommendation="Replace the admin wildcard with granular permissions scoped to required services and resources.",
            remediation_step=f"aws iam create-policy-version --policy-arn ARN --policy-document file://least-privilege-policy.json --set-as-default",
            region=region,
        ))

    return findings


# ── CEK-03: Data Encryption ───────────────────────────────────────────────────

def _check_cek03_s3_encryption(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """CEK-03: S3 buckets without encryption at rest."""
    findings = []
    s3_buckets = [r for r in resources if r.get("resource_type") == "aws_s3_bucket"]

    for bucket in s3_buckets:
        name = bucket.get("resource_name", "unknown")
        rid = bucket.get("resource_id", "")
        config = bucket.get("config", {})
        region = bucket.get("region", "global")
        enc = config.get("encryption", {})
        encrypted = enc.get("enabled", False)
        algorithm = enc.get("algorithm", "none")

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_s3_bucket",
            status="PASS" if encrypted else "FAIL",
            severity="HIGH",
            rule_id="CEK-03",
            title="CEK-03: Data Encryption — S3 Bucket Encryption at Rest",
            description=f"S3 bucket '{name}' does not have server-side encryption enabled. CCM CEK-03 requires encryption of data at rest.",
            reasoning=f"Checked S3 encryption configuration for bucket '{name}'. Encrypted: {encrypted}, Algorithm: {algorithm}.",
            expected="Server-side encryption enabled (SSE-S3 or SSE-KMS)",
            actual=f"Encrypted: {encrypted}, Algorithm: {algorithm}",
            recommendation="Enable default server-side encryption for the S3 bucket using AES-256 or KMS.",
            remediation_step=f"aws s3api put-bucket-encryption --bucket {name} --server-side-encryption-configuration '{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"aws:kms\"}}}}]}}'",
            region=region,
        ))

    return findings


def _check_cek03_rds_encryption(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """CEK-03: RDS instances without storage encryption."""
    findings = []
    rds_instances = [r for r in resources if r.get("resource_type") == "aws_rds_instance"]

    for db in rds_instances:
        name = db.get("resource_name", "unknown")
        rid = db.get("resource_id", "")
        config = db.get("config", {})
        region = db.get("region", "unknown")
        encrypted = config.get("storage_encrypted", False)

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_rds_instance",
            status="PASS" if encrypted else "FAIL",
            severity="HIGH",
            rule_id="CEK-03",
            title="CEK-03: Data Encryption — RDS Storage Encryption",
            description=f"RDS instance '{name}' does not have storage encryption enabled. CCM CEK-03 requires encryption of data at rest.",
            reasoning=f"Checked StorageEncrypted for RDS '{name}'. Value: {encrypted}.",
            expected="StorageEncrypted: true",
            actual=f"StorageEncrypted: {encrypted}",
            recommendation="Enable storage encryption for RDS instances. Note: Encryption cannot be enabled on an existing unencrypted instance; create a new encrypted instance from a snapshot.",
            remediation_step=f"aws rds create-db-snapshot --db-instance-identifier {name} --db-snapshot-identifier {name}-encrypted-snapshot",
            region=region,
        ))

    return findings


# ── CEK-06: Key Rotation ──────────────────────────────────────────────────────

def _check_cek06_kms_rotation(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """CEK-06: KMS key rotation check (informational if no KMS keys found)."""
    findings = []
    kms_keys = [r for r in resources if r.get("resource_type") in ("aws_kms_key", "kms_key")]

    if not kms_keys:
        # No KMS keys discovered — mark as N/A informational finding
        findings.append(_finding(
            resource_id="kms-na",
            resource_name="KMS Key Rotation",
            resource_type="aws_kms_key",
            status="PASS",
            severity="LOW",
            rule_id="CEK-06",
            title="CEK-06: Key Rotation — No Customer-Managed KMS Keys Found",
            description="No customer-managed KMS keys were found in this scan. CEK-06 (key rotation) is not applicable.",
            reasoning="aws_scanner did not return any KMS key resources in this scan.",
            expected="Customer-managed KMS keys have automatic rotation enabled",
            actual="N/A — no customer-managed KMS keys discovered",
            recommendation="If you use customer-managed KMS keys, ensure automatic annual rotation is enabled.",
            remediation_step="aws kms enable-key-rotation --key-id KEY_ID",
        ))
        return findings

    for key in kms_keys:
        name = key.get("resource_name", "unknown")
        rid = key.get("resource_id", "")
        config = key.get("config", {})
        rotation_enabled = config.get("key_rotation_enabled", False)
        region = key.get("region", "unknown")

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_kms_key",
            status="PASS" if rotation_enabled else "FAIL",
            severity="MEDIUM",
            rule_id="CEK-06",
            title="CEK-06: Key Rotation — KMS Key Rotation Not Enabled",
            description=f"KMS key '{name}' does not have automatic key rotation enabled. CCM CEK-06 requires cryptographic keys to be regularly rotated.",
            reasoning=f"Checked key rotation status for KMS key '{name}'. Rotation enabled: {rotation_enabled}.",
            expected="Automatic key rotation enabled",
            actual=f"Key rotation enabled: {rotation_enabled}",
            recommendation="Enable automatic annual key rotation for all customer-managed KMS keys.",
            remediation_step=f"aws kms enable-key-rotation --key-id {name}",
            region=region,
        ))

    return findings


# ── DSP-10: Sensitive Data Protection (S3 Public Access) ─────────────────────

def _check_dsp10_s3_public(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """DSP-10: S3 buckets with public access not blocked."""
    findings = []
    s3_buckets = [r for r in resources if r.get("resource_type") == "aws_s3_bucket"]

    for bucket in s3_buckets:
        name = bucket.get("resource_name", "unknown")
        rid = bucket.get("resource_id", "")
        config = bucket.get("config", {})
        region = bucket.get("region", "global")
        pub = config.get("public_access_block", {})
        fully_blocked = all([
            pub.get("block_public_acls"),
            pub.get("block_public_policy"),
            pub.get("ignore_public_acls"),
            pub.get("restrict_public_buckets"),
        ])

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_s3_bucket",
            status="PASS" if fully_blocked else "FAIL",
            severity="CRITICAL",
            rule_id="DSP-10",
            title="DSP-10: Sensitive Data Protection — S3 Public Access Not Blocked",
            description=f"S3 bucket '{name}' does not have all public access block settings enabled. CCM DSP-10 requires protection of sensitive data from unauthorized public disclosure.",
            reasoning=f"Checked PublicAccessBlockConfiguration for bucket '{name}'. Settings: {pub}.",
            expected="All four S3 public access block settings enabled",
            actual=f"PublicAccessBlockConfiguration: {pub}",
            recommendation="Enable all four S3 public access block settings to prevent public exposure.",
            remediation_step=f"aws s3api put-public-access-block --bucket {name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            region=region,
        ))

    return findings


# ── DSP-07: Data Retention (S3 Versioning) ───────────────────────────────────

def _check_dsp07_s3_versioning(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """DSP-07: S3 buckets without versioning enabled."""
    findings = []
    s3_buckets = [r for r in resources if r.get("resource_type") == "aws_s3_bucket"]

    for bucket in s3_buckets:
        name = bucket.get("resource_name", "unknown")
        rid = bucket.get("resource_id", "")
        config = bucket.get("config", {})
        region = bucket.get("region", "global")
        versioning = config.get("versioning", "Disabled")
        versioning_enabled = versioning == "Enabled"

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_s3_bucket",
            status="PASS" if versioning_enabled else "FAIL",
            severity="MEDIUM",
            rule_id="DSP-07",
            title="DSP-07: Data Retention — S3 Bucket Versioning Not Enabled",
            description=f"S3 bucket '{name}' does not have versioning enabled. CCM DSP-07 requires data retention controls to protect against accidental or malicious deletion.",
            reasoning=f"Checked S3 versioning status for bucket '{name}'. Status: {versioning}.",
            expected="Versioning status: Enabled",
            actual=f"Versioning: {versioning}",
            recommendation="Enable S3 versioning to preserve, retrieve, and restore all object versions.",
            remediation_step=f"aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled",
            region=region,
        ))

    return findings


# ── I&S-07: Network Security ──────────────────────────────────────────────────

def _check_ins07_network_security(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """I&S-07: Security groups with 0.0.0.0/0 inbound rules."""
    findings = []
    sgs = [r for r in resources if r.get("resource_type") == "aws_security_group"]

    for sg in sgs:
        name = sg.get("resource_name", "unknown")
        rid = sg.get("resource_id", "")
        config = sg.get("config", {})
        region = sg.get("region", "unknown")
        ingress = config.get("ingress_rules", [])

        open_rules = [r for r in ingress if r.get("cidr") in ("0.0.0.0/0", "::/0")]
        is_open = bool(open_rules)

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_security_group",
            status="FAIL" if is_open else "PASS",
            severity="HIGH",
            rule_id="I&S-07",
            title="I&S-07: Network Security — Security Group Open to Internet",
            description=f"Security group '{name}' has {len(open_rules)} inbound rule(s) allowing traffic from 0.0.0.0/0. CCM I&S-07 requires network security controls to restrict unauthorized access.",
            reasoning=f"Found {len(open_rules)} ingress rules with CIDR 0.0.0.0/0 in security group '{name}'.",
            expected="No inbound rules from 0.0.0.0/0 except for intentionally public resources",
            actual=f"Open inbound rules: {len(open_rules)}",
            recommendation="Restrict inbound rules to known IP ranges or use security group references instead of CIDR 0.0.0.0/0.",
            remediation_step=f"aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol all --cidr 0.0.0.0/0",
            region=region,
        ))

    return findings


# ── LOG-05: Audit Logging ─────────────────────────────────────────────────────

def _check_log05_s3_logging(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """LOG-05: S3 buckets without access logging."""
    findings = []
    s3_buckets = [r for r in resources if r.get("resource_type") == "aws_s3_bucket"]

    for bucket in s3_buckets:
        name = bucket.get("resource_name", "unknown")
        rid = bucket.get("resource_id", "")
        config = bucket.get("config", {})
        region = bucket.get("region", "global")
        logging_enabled = config.get("logging", False)

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_s3_bucket",
            status="PASS" if logging_enabled else "FAIL",
            severity="MEDIUM",
            rule_id="LOG-05",
            title="LOG-05: Audit Logging — S3 Access Logging Not Enabled",
            description=f"S3 bucket '{name}' does not have server access logging enabled. CCM LOG-05 requires audit logs for all data access and security-relevant operations.",
            reasoning=f"Checked S3 server access logging status for bucket '{name}'. Enabled: {logging_enabled}.",
            expected="S3 server access logging enabled",
            actual=f"Logging enabled: {logging_enabled}",
            recommendation="Enable S3 server access logging to capture GET, PUT, DELETE, and other requests.",
            remediation_step=f"aws s3api put-bucket-logging --bucket {name} --bucket-logging-status '{{\"LoggingEnabled\":{{\"TargetBucket\":\"audit-logs\",\"TargetPrefix\":\"{name}/\"}}}}'",
            region=region,
        ))

    return findings


# ── BCR-08: Backup and Recovery ───────────────────────────────────────────────

def _check_bcr08_rds_backup(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """BCR-08: RDS instances without automated backups."""
    findings = []
    rds_instances = [r for r in resources if r.get("resource_type") == "aws_rds_instance"]

    for db in rds_instances:
        name = db.get("resource_name", "unknown")
        rid = db.get("resource_id", "")
        config = db.get("config", {})
        region = db.get("region", "unknown")
        backup_retention = config.get("backup_retention", 0)
        has_backup = backup_retention > 0

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_rds_instance",
            status="PASS" if has_backup else "FAIL",
            severity="HIGH",
            rule_id="BCR-08",
            title="BCR-08: Backup and Recovery — RDS Automated Backups Disabled",
            description=f"RDS instance '{name}' has automated backups disabled (retention period = {backup_retention} days). CCM BCR-08 requires backup and recovery controls to ensure business continuity.",
            reasoning=f"Checked BackupRetentionPeriod for RDS '{name}'. Value: {backup_retention}.",
            expected="BackupRetentionPeriod >= 7 days",
            actual=f"BackupRetentionPeriod: {backup_retention} days",
            recommendation="Enable automated backups with a retention period of at least 7 days.",
            remediation_step=f"aws rds modify-db-instance --db-instance-identifier {name} --backup-retention-period 7 --apply-immediately",
            region=region,
        ))

    return findings


def _check_bcr08_s3_versioning(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """BCR-08: S3 buckets without versioning (backup control)."""
    findings = []
    s3_buckets = [r for r in resources if r.get("resource_type") == "aws_s3_bucket"]

    for bucket in s3_buckets:
        name = bucket.get("resource_name", "unknown")
        rid = bucket.get("resource_id", "")
        config = bucket.get("config", {})
        region = bucket.get("region", "global")
        versioning = config.get("versioning", "Disabled")
        versioning_enabled = versioning == "Enabled"

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_s3_bucket",
            status="PASS" if versioning_enabled else "FAIL",
            severity="MEDIUM",
            rule_id="BCR-08",
            title="BCR-08: Backup and Recovery — S3 Versioning Not Enabled",
            description=f"S3 bucket '{name}' does not have versioning enabled. CCM BCR-08 requires that data can be recovered from backups after accidental deletion or corruption.",
            reasoning=f"Checked S3 versioning for bucket '{name}'. Status: {versioning}.",
            expected="Versioning: Enabled",
            actual=f"Versioning: {versioning}",
            recommendation="Enable S3 versioning and configure lifecycle policies to manage version storage costs.",
            remediation_step=f"aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled",
            region=region,
        ))

    return findings


# ── TVM-02: Vulnerability Management ─────────────────────────────────────────

def _check_tvm02_lambda_runtime(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """TVM-02: Lambda functions using deprecated/outdated runtimes."""
    findings = []
    lambdas = [r for r in resources if r.get("resource_type") == "aws_lambda_function"]

    # Outdated runtimes as of 2025 (no longer receiving security patches)
    deprecated_runtimes = {
        "python2.7", "python3.6", "python3.7",
        "nodejs10.x", "nodejs12.x", "nodejs14.x",
        "java8",
        "dotnetcore2.1", "dotnetcore3.1",
        "ruby2.5", "ruby2.7",
        "go1.x",  # go1.x is being deprecated
    }

    for func in lambdas:
        name = func.get("resource_name", "unknown")
        rid = func.get("resource_id", "")
        config = func.get("config", {})
        region = func.get("region", "unknown")
        runtime = config.get("runtime", "")
        is_deprecated = runtime.lower() in deprecated_runtimes

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_lambda_function",
            status="FAIL" if is_deprecated else "PASS",
            severity="HIGH" if is_deprecated else "LOW",
            rule_id="TVM-02",
            title="TVM-02: Vulnerability Management — Lambda Outdated Runtime",
            description=f"Lambda function '{name}' uses runtime '{runtime}' which is deprecated or approaching end-of-life. CCM TVM-02 requires timely patching of components.",
            reasoning=f"Checked Lambda runtime for function '{name}'. Runtime '{runtime}' is in the deprecated list: {is_deprecated}.",
            expected="Lambda runtime using a currently supported version",
            actual=f"Runtime: {runtime}",
            recommendation=f"Migrate Lambda function '{name}' to a supported runtime version.",
            remediation_step=f"aws lambda update-function-configuration --function-name {name} --runtime python3.12",
            region=region,
        ))

    return findings


def _check_tvm02_ec2_public_ip(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """TVM-02: EC2 instances with public IP (exposed attack surface)."""
    findings = []
    ec2_instances = [r for r in resources if r.get("resource_type") == "aws_ec2_instance"]

    for instance in ec2_instances:
        name = instance.get("resource_name", "unknown")
        rid = instance.get("resource_id", "")
        config = instance.get("config", {})
        region = instance.get("region", "unknown")
        public_ip = config.get("public_ip", "")
        state = config.get("state", "")

        if state not in ("running", "stopped"):
            continue

        has_public_ip = bool(public_ip)
        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_ec2_instance",
            status="FAIL" if has_public_ip else "PASS",
            severity="MEDIUM",
            rule_id="TVM-02",
            title="TVM-02: Vulnerability Management — EC2 Instance with Public IP",
            description=f"EC2 instance '{name}' has a public IP address ({public_ip}). Publicly accessible instances have a larger attack surface and require timely patch management.",
            reasoning=f"Checked EC2 PublicIpAddress for instance '{name}'. Value: {public_ip or 'none'}.",
            expected="EC2 instances in private subnets without public IP addresses",
            actual=f"Public IP: {public_ip or 'none'}",
            recommendation="Move EC2 instances to private subnets and use load balancers or VPN for access.",
            remediation_step="Modify subnet settings to not auto-assign public IPs, and relocate instance to private subnet",
            region=region,
        ))

    return findings


# ── GRC-01: Governance — Resources Without Tags ───────────────────────────────

def _check_grc01_untagged_resources(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """GRC-01: Resources with no tags (governance and accountability gap)."""
    findings = []

    # Only check resource types that are commonly taggable
    taggable_types = {
        "aws_s3_bucket", "aws_ec2_instance", "aws_rds_instance",
        "aws_lambda_function", "aws_security_group", "aws_vpc",
    }

    for resource in resources:
        rtype = resource.get("resource_type", "")
        if rtype not in taggable_types:
            continue

        name = resource.get("resource_name", "unknown")
        rid = resource.get("resource_id", "")
        config = resource.get("config", {})
        region = resource.get("region", "unknown")

        # Tags might be in config.tags or at root level
        tags = config.get("tags", {}) or {}
        has_tags = bool(tags)

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type=rtype,
            status="PASS" if has_tags else "FAIL",
            severity="LOW",
            rule_id="GRC-01",
            title="GRC-01: Governance — Resource Has No Tags",
            description=f"Resource '{name}' ({rtype}) has no tags. CCM GRC-01 requires governance controls including resource ownership and classification metadata.",
            reasoning=f"Checked tags for resource '{name}'. Tags dict: {tags}.",
            expected="Resource tagged with at least Owner, Environment, and Project tags",
            actual=f"Tags: {tags or 'none'}",
            recommendation="Apply mandatory tags (Owner, Environment, CostCenter, Project) to all cloud resources.",
            remediation_step=f"aws {rtype.split('_')[1]} create-tags --resources RESOURCE_ID --tags Key=Owner,Value=team Key=Environment,Value=production",
            region=region,
        ))

    return findings


# ── Main Entry Point ──────────────────────────────────────────────────────────

def audit_aws_resources_ccm(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run CSA Cloud Controls Matrix (CCM) v4.1 checks against AWS resources.

    Args:
        scan_data: dict with 'resources' key containing list of AWS resource dicts
                   (same format as aws_scanner.py output)

    Returns:
        dict with 'findings' list, 'summary', 'framework', 'generated_at'
    """
    resources = scan_data.get("resources", [])
    findings: List[Dict[str, Any]] = []

    # IAM-07: MFA
    findings.extend(_check_iam07_mfa(resources))

    # IAM-02: Access key rotation
    findings.extend(_check_iam02_key_rotation(resources))

    # IAM-09: Wildcard policies
    findings.extend(_check_iam09_wildcard_policies(resources))

    # IAM-01: Admin wildcard
    findings.extend(_check_iam01_admin_policy(resources))

    # CEK-03: Encryption at rest
    findings.extend(_check_cek03_s3_encryption(resources))
    findings.extend(_check_cek03_rds_encryption(resources))

    # CEK-06: KMS key rotation
    findings.extend(_check_cek06_kms_rotation(resources))

    # DSP-10: Sensitive data / S3 public access
    findings.extend(_check_dsp10_s3_public(resources))

    # DSP-07: Data retention / S3 versioning
    findings.extend(_check_dsp07_s3_versioning(resources))

    # I&S-07: Network security
    findings.extend(_check_ins07_network_security(resources))

    # LOG-05: Audit logging
    findings.extend(_check_log05_s3_logging(resources))

    # BCR-08: Backup and recovery
    findings.extend(_check_bcr08_rds_backup(resources))
    findings.extend(_check_bcr08_s3_versioning(resources))

    # TVM-02: Vulnerability management
    findings.extend(_check_tvm02_lambda_runtime(resources))
    findings.extend(_check_tvm02_ec2_public_ip(resources))

    # GRC-01: Governance / tagging
    findings.extend(_check_grc01_untagged_resources(resources))

    # Compute summary
    total = len(findings)
    passed = sum(1 for f in findings if f.get("status") == "PASS")
    failed = total - passed
    health_score = round((passed / total) * 100, 1) if total > 0 else 0.0

    sev_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.get("status") == "FAIL":
            sev = f.get("severity", "LOW").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1

    return {
        "framework": "CCM",
        "framework_version": "v4.1 (2021)",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "summary": {
            "total": total,
            "pass": passed,
            "fail": failed,
            "health_score": health_score,
            **sev_counts,
        },
    }
