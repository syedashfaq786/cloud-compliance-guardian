"""
NIST 800-53 Rev 5 Auditor — Direct checks against AWS resources.

Performs genuine NIST SP 800-53 Revision 5 control checks without mapping
from CIS rules. Each check is written directly against the resource data
produced by aws_scanner.py.

Function signature:
    audit_aws_resources_nist(scan_data: dict) -> dict
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
        "framework": "NIST",
        "rule_id": rule_id,
        # Provide cis_rule_id alias so existing report templates don't break
        "cis_rule_id": rule_id,
        "title": title,
        "description": description,
        "reasoning": reasoning,
        "expected": expected,
        "actual": actual,
        "recommendation": recommendation,
        "remediation_step": remediation_step,
    }


# ── AC-2: Account Management ──────────────────────────────────────────────────

def _check_ac2_iam_users(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    AC-2 (Account Management):
    - FAIL if any IAM user has no MFA
    - FAIL if any IAM user has access keys older than 90 days
    - FAIL if any IAM user has admin policy attached (has_admin_access flag)
    """
    findings = []
    iam_users = [r for r in resources if r.get("resource_type") == "aws_iam_user"]

    for user in iam_users:
        name = user.get("resource_name", "unknown")
        rid = user.get("resource_id", "")
        config = user.get("config", {})
        region = user.get("region", "global")

        # Check MFA
        has_mfa = config.get("has_mfa", False)
        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_iam_user",
            status="PASS" if has_mfa else "FAIL",
            severity="HIGH",
            rule_id="NIST AC-2",
            title="AC-2: Account Management — MFA Required for IAM User",
            description=f"IAM user '{name}' does not have multi-factor authentication (MFA) enabled. NIST AC-2 requires that managed accounts use strong authenticators.",
            reasoning=f"Checked MFA device list for IAM user '{name}'. has_mfa={has_mfa}.",
            expected="MFA device enrolled for all IAM users",
            actual=f"has_mfa: {has_mfa}",
            recommendation="Enable MFA for all IAM users, especially those with console access.",
            remediation_step="aws iam enable-mfa-device --user-name USER --serial-number ARN --authentication-code1 CODE1 --authentication-code2 CODE2",
            region=region,
        ))

        # Check access key age
        access_keys = config.get("access_keys", [])
        for key in access_keys:
            age_days = key.get("age_days", 0)
            is_old = key.get("is_old", False) or age_days > 90
            if key.get("status", "") == "Active":
                findings.append(_finding(
                    resource_id=rid,
                    resource_name=name,
                    resource_type="aws_iam_user",
                    status="FAIL" if is_old else "PASS",
                    severity="MEDIUM",
                    rule_id="NIST AC-2",
                    title="AC-2: Account Management — Access Key Rotation",
                    description=f"IAM user '{name}' has an active access key that is {age_days} days old. NIST AC-2 requires periodic credential rotation.",
                    reasoning=f"Access key creation date indicates key is {age_days} days old. NIST AC-2 requires rotation within 90 days.",
                    expected="Access keys rotated within 90 days",
                    actual=f"Key age: {age_days} days",
                    recommendation="Rotate access keys every 90 days. Deactivate and delete keys that have not been rotated.",
                    remediation_step="aws iam create-access-key --user-name USER && aws iam delete-access-key --user-name USER --access-key-id OLD_KEY_ID",
                    region=region,
                ))

    return findings


def _check_ac2_admin_users(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """AC-2: Flag IAM policies with admin wildcard attached to users."""
    findings = []
    iam_policies = [r for r in resources if r.get("resource_type") == "aws_iam_policy"]

    for pol in iam_policies:
        name = pol.get("resource_name", "unknown")
        rid = pol.get("resource_id", "")
        config = pol.get("config", {})
        has_admin = config.get("has_admin_access", False)

        if has_admin:
            findings.append(_finding(
                resource_id=rid,
                resource_name=name,
                resource_type="aws_iam_policy",
                status="FAIL",
                severity="CRITICAL",
                rule_id="NIST AC-2",
                title="AC-2: Account Management — Admin Wildcard Policy",
                description=f"IAM policy '{name}' grants Action:* on Resource:*. This is an admin policy that bypasses all permission boundaries.",
                reasoning=f"Policy document contains a statement with Effect:Allow, Action:*, Resource:*.",
                expected="No policy should grant Action:* Resource:* (wildcard admin access)",
                actual=f"Policy '{name}' has admin wildcard access",
                recommendation="Replace the admin wildcard policy with granular, least-privilege permissions.",
                remediation_step=f"aws iam create-policy-version --policy-arn ARN --policy-document file://restricted-policy.json --set-as-default",
            ))

    return findings


# ── AC-3: Access Enforcement ──────────────────────────────────────────────────

def _check_ac3_s3_public_access(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """AC-3: S3 buckets with public access not blocked."""
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
            rule_id="NIST AC-3",
            title="AC-3: Access Enforcement — S3 Public Access Not Blocked",
            description=f"S3 bucket '{name}' does not have all public access block settings enabled. NIST AC-3 requires that access is enforced based on authorizations.",
            reasoning=f"Checked S3 PublicAccessBlockConfiguration for bucket '{name}'. Not all four block settings are enabled: {pub}.",
            expected="All four public access block settings enabled",
            actual=f"PublicAccessBlockConfiguration: {pub}",
            recommendation="Enable all four S3 public access block settings at the bucket level.",
            remediation_step=f"aws s3api put-public-access-block --bucket {name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            region=region,
        ))

    return findings


def _check_ac3_security_groups(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """AC-3: Security groups allowing 0.0.0.0/0 on any port."""
    findings = []
    sgs = [r for r in resources if r.get("resource_type") == "aws_security_group"]

    for sg in sgs:
        name = sg.get("resource_name", "unknown")
        rid = sg.get("resource_id", "")
        config = sg.get("config", {})
        region = sg.get("region", "unknown")
        ingress = config.get("ingress_rules", [])

        open_rules = [
            rule for rule in ingress
            if rule.get("cidr") in ("0.0.0.0/0", "::/0")
        ]
        is_open = bool(open_rules)
        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_security_group",
            status="FAIL" if is_open else "PASS",
            severity="HIGH",
            rule_id="NIST AC-3",
            title="AC-3: Access Enforcement — Security Group Open to Internet",
            description=f"Security group '{name}' allows inbound traffic from 0.0.0.0/0, violating NIST AC-3 access enforcement controls.",
            reasoning=f"Checked ingress rules for security group '{name}'. Found {len(open_rules)} rule(s) with CIDR 0.0.0.0/0.",
            expected="No ingress rules allowing 0.0.0.0/0",
            actual=f"Open inbound rules: {len(open_rules)} rule(s) from 0.0.0.0/0",
            recommendation="Restrict security group ingress to specific IP ranges or security groups.",
            remediation_step=f"aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol all --cidr 0.0.0.0/0",
            region=region,
        ))

    return findings


# ── AC-6: Least Privilege ─────────────────────────────────────────────────────

def _check_ac6_iam_policies(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """AC-6: IAM policies with wildcard actions or admin access."""
    findings = []
    iam_policies = [r for r in resources if r.get("resource_type") == "aws_iam_policy"]

    for pol in iam_policies:
        name = pol.get("resource_name", "unknown")
        rid = pol.get("resource_id", "")
        config = pol.get("config", {})
        statements = config.get("statements", [])

        wildcard_services = []
        for stmt in statements:
            effect = stmt.get("effect", "")
            if effect != "Allow":
                continue
            actions = stmt.get("action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                action_str = str(action)
                # Service-wide wildcard: s3:*, ec2:*, iam:*, etc.
                if action_str != "*" and action_str.endswith(":*"):
                    service = action_str.split(":")[0]
                    wildcard_services.append(service)

        has_wildcards = bool(wildcard_services)
        if has_wildcards:
            findings.append(_finding(
                resource_id=rid,
                resource_name=name,
                resource_type="aws_iam_policy",
                status="FAIL",
                severity="HIGH",
                rule_id="NIST AC-6",
                title="AC-6: Least Privilege — Service-Wide Wildcard Actions",
                description=f"IAM policy '{name}' contains service-wide wildcard actions ({wildcard_services}), granting broader access than required.",
                reasoning=f"Policy statements contain actions ending in ':*' for services: {wildcard_services}.",
                expected="Actions limited to specific API operations required by the workload",
                actual=f"Service wildcards found: {wildcard_services}",
                recommendation="Replace service-wide wildcards with explicit, required API actions.",
                remediation_step=f"aws iam create-policy-version --policy-arn ARN --policy-document file://least-privilege-policy.json --set-as-default",
            ))
        else:
            findings.append(_finding(
                resource_id=rid,
                resource_name=name,
                resource_type="aws_iam_policy",
                status="PASS",
                severity="HIGH",
                rule_id="NIST AC-6",
                title="AC-6: Least Privilege — Policy Actions Within Scope",
                description=f"IAM policy '{name}' does not contain service-wide wildcard actions.",
                reasoning="No service:* wildcard actions found in policy statements.",
                expected="No service-wide wildcard actions",
                actual="No wildcards found",
                recommendation="No action required.",
                remediation_step="",
            ))

    return findings


# ── AC-17: Remote Access ──────────────────────────────────────────────────────

def _check_ac17_remote_access(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """AC-17: Security groups allowing SSH/RDP from 0.0.0.0/0."""
    findings = []
    sgs = [r for r in resources if r.get("resource_type") == "aws_security_group"]

    for sg in sgs:
        name = sg.get("resource_name", "unknown")
        rid = sg.get("resource_id", "")
        config = sg.get("config", {})
        region = sg.get("region", "unknown")
        ingress = config.get("ingress_rules", [])

        ssh_open = False
        rdp_open = False

        for rule in ingress:
            cidr = rule.get("cidr", "")
            proto = rule.get("protocol", "")
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 65535)

            if cidr not in ("0.0.0.0/0", "::/0"):
                continue

            if proto in ("-1", "all"):
                ssh_open = True
                rdp_open = True
                break

            if proto in ("tcp", "6"):
                if from_port <= 22 <= to_port:
                    ssh_open = True
                if from_port <= 3389 <= to_port:
                    rdp_open = True

        for port, is_open, service in [(22, ssh_open, "SSH"), (3389, rdp_open, "RDP")]:
            findings.append(_finding(
                resource_id=rid,
                resource_name=name,
                resource_type="aws_security_group",
                status="FAIL" if is_open else "PASS",
                severity="CRITICAL" if is_open else "LOW",
                rule_id="NIST AC-17",
                title=f"AC-17: Remote Access — {service} Open to Internet (0.0.0.0/0)",
                description=f"Security group '{name}' allows {service} (port {port}) from 0.0.0.0/0. NIST AC-17 requires remote access to be controlled and audited.",
                reasoning=f"Checked ingress rules for {service} port ({port}/tcp) from 0.0.0.0/0.",
                expected=f"{service} access restricted to known IP ranges or via VPN/bastion",
                actual=f"{service} open to internet: {is_open}",
                recommendation=f"Restrict {service} access to specific IP CIDR ranges or use AWS Systems Manager Session Manager instead.",
                remediation_step=f"aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port {port} --cidr 0.0.0.0/0",
                region=region,
            ))

    return findings


# ── AU-2: Event Logging ───────────────────────────────────────────────────────

def _check_au2_s3_logging(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """AU-2: S3 buckets without access logging."""
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
            rule_id="NIST AU-2",
            title="AU-2: Event Logging — S3 Access Logging Not Enabled",
            description=f"S3 bucket '{name}' does not have access logging enabled. NIST AU-2 requires that auditable events are defined and logged.",
            reasoning=f"Checked GetBucketLogging for bucket '{name}'. LoggingEnabled: {logging_enabled}.",
            expected="S3 access logging enabled",
            actual=f"Logging enabled: {logging_enabled}",
            recommendation="Enable S3 server access logging to capture all requests made to the bucket.",
            remediation_step=f"aws s3api put-bucket-logging --bucket {name} --bucket-logging-status '{{\"LoggingEnabled\":{{\"TargetBucket\":\"audit-logs\",\"TargetPrefix\":\"{name}/\"}}}}'",
            region=region,
        ))

    return findings


# ── SC-7: Boundary Protection ─────────────────────────────────────────────────

def _check_sc7_security_groups(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """SC-7: Security groups allowing all traffic from 0.0.0.0/0."""
    findings = []
    sgs = [r for r in resources if r.get("resource_type") == "aws_security_group"]

    for sg in sgs:
        name = sg.get("resource_name", "unknown")
        rid = sg.get("resource_id", "")
        config = sg.get("config", {})
        region = sg.get("region", "unknown")
        ingress = config.get("ingress_rules", [])

        all_traffic_open = any(
            rule.get("cidr") in ("0.0.0.0/0", "::/0") and
            rule.get("protocol") in ("-1", "all")
            for rule in ingress
        )
        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_security_group",
            status="FAIL" if all_traffic_open else "PASS",
            severity="CRITICAL",
            rule_id="NIST SC-7",
            title="SC-7: Boundary Protection — All Traffic Allowed from Internet",
            description=f"Security group '{name}' allows all TCP/UDP/ICMP traffic from 0.0.0.0/0, violating NIST SC-7 boundary protection requirements.",
            reasoning=f"Found ingress rule with protocol '-1' (all traffic) and CIDR 0.0.0.0/0.",
            expected="No security group should allow all traffic from 0.0.0.0/0",
            actual=f"All-traffic open inbound rule: {all_traffic_open}",
            recommendation="Replace all-traffic rules with specific protocol/port rules for required services only.",
            remediation_step=f"aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol -1 --cidr 0.0.0.0/0",
            region=region,
        ))

    return findings


def _check_sc7_rds_public(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """SC-7: RDS instances that are publicly accessible."""
    findings = []
    rds_instances = [r for r in resources if r.get("resource_type") == "aws_rds_instance"]

    for db in rds_instances:
        name = db.get("resource_name", "unknown")
        rid = db.get("resource_id", "")
        config = db.get("config", {})
        region = db.get("region", "unknown")
        publicly_accessible = config.get("publicly_accessible", False)

        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_rds_instance",
            status="FAIL" if publicly_accessible else "PASS",
            severity="CRITICAL",
            rule_id="NIST SC-7",
            title="SC-7: Boundary Protection — RDS Instance Publicly Accessible",
            description=f"RDS instance '{name}' is publicly accessible from the internet. NIST SC-7 requires that information system boundary protections are implemented.",
            reasoning=f"Checked PubliclyAccessible flag for RDS instance '{name}'. Value: {publicly_accessible}.",
            expected="PubliclyAccessible: false",
            actual=f"PubliclyAccessible: {publicly_accessible}",
            recommendation="Disable public accessibility and access RDS only through private subnets or VPN.",
            remediation_step=f"aws rds modify-db-instance --db-instance-identifier {name} --no-publicly-accessible",
            region=region,
        ))

    return findings


# ── SC-28: Protection of Information at Rest ──────────────────────────────────

def _check_sc28_s3_encryption(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """SC-28: S3 buckets without encryption."""
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
            rule_id="NIST SC-28",
            title="SC-28: Protection of Information at Rest — S3 Encryption",
            description=f"S3 bucket '{name}' does not have server-side encryption enabled. NIST SC-28 requires that information at rest is protected.",
            reasoning=f"Checked S3 bucket encryption configuration. encrypted={encrypted}, algorithm={algorithm}.",
            expected="Server-side encryption enabled (SSE-S3 or SSE-KMS)",
            actual=f"Encrypted: {encrypted}, Algorithm: {algorithm}",
            recommendation="Enable default server-side encryption for the S3 bucket.",
            remediation_step=f"aws s3api put-bucket-encryption --bucket {name} --server-side-encryption-configuration '{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"aws:kms\"}}}}]}}'",
            region=region,
        ))

    return findings


def _check_sc28_rds_encryption(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """SC-28: RDS instances without storage encryption."""
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
            rule_id="NIST SC-28",
            title="SC-28: Protection of Information at Rest — RDS Storage Encryption",
            description=f"RDS instance '{name}' does not have storage encryption enabled. NIST SC-28 requires that information at rest is cryptographically protected.",
            reasoning=f"Checked StorageEncrypted flag for RDS '{name}'. Value: {encrypted}.",
            expected="StorageEncrypted: true",
            actual=f"StorageEncrypted: {encrypted}",
            recommendation="Enable storage encryption when creating new RDS instances. For existing instances, create an encrypted snapshot and restore.",
            remediation_step=f"aws rds create-db-snapshot --db-instance-identifier {name} --db-snapshot-identifier {name}-snap && aws rds restore-db-instance-from-db-snapshot --db-instance-identifier {name}-encrypted --db-snapshot-identifier {name}-snap --storage-encrypted",
            region=region,
        ))

    return findings


# ── IA-2: Multi-Factor Authentication ─────────────────────────────────────────

def _check_ia2_mfa(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """IA-2: IAM users without MFA."""
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
            rule_id="NIST IA-2",
            title="IA-2: Identification and Authentication — MFA for IAM User",
            description=f"IAM user '{name}' does not have MFA enabled. NIST IA-2 requires multi-factor authentication for privileged accounts.",
            reasoning=f"MFA device list for user '{name}' returned has_mfa={has_mfa}.",
            expected="MFA device enrolled for all IAM users with console access",
            actual=f"has_mfa: {has_mfa}",
            recommendation="Require MFA for all IAM users. Use a virtual MFA device or hardware token.",
            remediation_step="aws iam enable-mfa-device --user-name USER --serial-number arn:aws:iam::ACCOUNT:mfa/USER --authentication-code1 CODE1 --authentication-code2 CODE2",
            region=region,
        ))

    return findings


# ── CM-2: Baseline Configuration ──────────────────────────────────────────────

def _check_cm2_ec2_baseline(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """CM-2: EC2 instances with public IP or no instance profile."""
    findings = []
    ec2_instances = [r for r in resources if r.get("resource_type") == "aws_ec2_instance"]

    for instance in ec2_instances:
        name = instance.get("resource_name", "unknown")
        rid = instance.get("resource_id", "")
        config = instance.get("config", {})
        region = instance.get("region", "unknown")
        public_ip = config.get("public_ip", "")
        iam_profile = config.get("iam_instance_profile", "")
        state = config.get("state", "")

        if state not in ("running", "stopped"):
            continue

        # Public IP check
        has_public_ip = bool(public_ip)
        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_ec2_instance",
            status="FAIL" if has_public_ip else "PASS",
            severity="HIGH",
            rule_id="NIST CM-2",
            title="CM-2: Baseline Configuration — EC2 Instance Has Public IP",
            description=f"EC2 instance '{name}' has a public IP address ({public_ip}). NIST CM-2 requires systems to be configured according to approved baseline configurations.",
            reasoning=f"Checked EC2 PublicIpAddress for instance '{name}'. Value: {public_ip or 'none'}.",
            expected="EC2 instances in private subnets without public IP addresses",
            actual=f"Public IP: {public_ip or 'none'}",
            recommendation="Place EC2 instances in private subnets. Use NAT Gateway for outbound access and Load Balancer for inbound.",
            remediation_step=f"aws ec2 modify-instance-attribute --instance-id INSTANCE_ID --no-source-dest-check  # then reassign to private subnet",
            region=region,
        ))

        # IAM instance profile check
        has_profile = bool(iam_profile)
        findings.append(_finding(
            resource_id=rid,
            resource_name=name,
            resource_type="aws_ec2_instance",
            status="PASS" if has_profile else "FAIL",
            severity="MEDIUM",
            rule_id="NIST CM-2",
            title="CM-2: Baseline Configuration — EC2 Instance Has No IAM Role",
            description=f"EC2 instance '{name}' has no IAM instance profile attached. Without an instance profile, applications may use hardcoded credentials instead of temporary role credentials.",
            reasoning=f"Checked IamInstanceProfile for instance '{name}'. Value: {iam_profile or 'none'}.",
            expected="IAM instance profile attached to all EC2 instances",
            actual=f"IAM instance profile: {iam_profile or 'none'}",
            recommendation="Attach an IAM instance profile with least-privilege permissions to the EC2 instance.",
            remediation_step=f"aws ec2 associate-iam-instance-profile --instance-id INSTANCE_ID --iam-instance-profile Name=MyInstanceProfile",
            region=region,
        ))

    return findings


# ── Main Entry Point ──────────────────────────────────────────────────────────

def audit_aws_resources_nist(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run NIST SP 800-53 Rev 5 control checks against AWS resources.

    Args:
        scan_data: dict with 'resources' key containing list of AWS resource dicts
                   (same format as aws_scanner.py output)

    Returns:
        dict with 'findings' list, 'summary', 'framework', 'generated_at'
    """
    resources = scan_data.get("resources", [])
    findings: List[Dict[str, Any]] = []

    # AC-2: Account Management
    findings.extend(_check_ac2_iam_users(resources))
    findings.extend(_check_ac2_admin_users(resources))

    # AC-3: Access Enforcement
    findings.extend(_check_ac3_s3_public_access(resources))
    findings.extend(_check_ac3_security_groups(resources))

    # AC-6: Least Privilege
    findings.extend(_check_ac6_iam_policies(resources))

    # AC-17: Remote Access
    findings.extend(_check_ac17_remote_access(resources))

    # AU-2: Event Logging
    findings.extend(_check_au2_s3_logging(resources))

    # SC-7: Boundary Protection
    findings.extend(_check_sc7_security_groups(resources))
    findings.extend(_check_sc7_rds_public(resources))

    # SC-28: Protection of Information at Rest
    findings.extend(_check_sc28_s3_encryption(resources))
    findings.extend(_check_sc28_rds_encryption(resources))

    # IA-2: MFA
    findings.extend(_check_ia2_mfa(resources))

    # CM-2: Baseline Configuration
    findings.extend(_check_cm2_ec2_baseline(resources))

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
        "framework": "NIST",
        "framework_version": "SP 800-53 Rev 5",
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
