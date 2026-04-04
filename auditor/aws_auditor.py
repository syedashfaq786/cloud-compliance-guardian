"""
AWS Live Auditor — Analyzes live AWS resources against CIS Benchmarks.

Uses rule-based checks (no model dependency) for instant results,
with optional Sec-8B enrichment when the model is available.
"""

import json
import os
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone


# ── CIS Rule-Based Checks (No model needed) ──────────────────────────────────

def audit_s3_bucket(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check S3 bucket against CIS Benchmark rules."""
    findings = []
    config = resource.get("config", {})
    name = resource.get("resource_name", "unknown")

    # CIS 2.1.1 — S3 bucket encryption
    enc = config.get("encryption", {})
    if not enc.get("enabled"):
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", "global"),
            "resource_type": "aws_s3_bucket",
            "status": "FAIL",
            "severity": "HIGH",
            "cis_rule_id": "CIS 2.1.1",
            "title": "S3 Bucket Server-Side Encryption Not Enabled",
            "description": f"Bucket '{name}' does not have server-side encryption enabled. Data at rest is unprotected.",
            "reasoning": f"Checked ServerSideEncryptionConfiguration for bucket '{name}'. No encryption rule was found, meaning objects stored in this bucket are not encrypted at rest. This violates CIS AWS Foundations Benchmark 2.1.1.",
            "expected": "Server-side encryption enabled with SSE-S3 (AES-256) or SSE-KMS algorithm",
            "actual": f"Encryption: {enc.get('algorithm', 'none')} (disabled)",
            "recommendation": "Enable default server-side encryption using SSE-S3 or SSE-KMS. SSE-KMS provides additional audit trail via CloudTrail and supports key rotation.",
            "remediation_step": "aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'",
        })

    # CIS 2.1.2 — S3 bucket versioning
    versioning_status = config.get("versioning", "Disabled")
    if versioning_status != "Enabled":
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "aws_s3_bucket",
            "status": "FAIL",
            "severity": "MEDIUM",
            "cis_rule_id": "CIS 2.1.2",
            "title": "S3 Bucket Versioning Not Enabled",
            "description": f"Bucket '{name}' does not have versioning enabled. Data cannot be recovered if accidentally deleted.",
            "reasoning": f"Checked GetBucketVersioning for bucket '{name}'. Versioning status is '{versioning_status}'. Without versioning, deleted or overwritten objects cannot be recovered, increasing risk of data loss.",
            "expected": "Versioning status: Enabled",
            "actual": f"Versioning status: {versioning_status}",
            "recommendation": "Enable versioning to protect against accidental deletion and overwrites. Consider adding lifecycle rules to manage version storage costs.",
            "remediation_step": "aws s3api put-bucket-versioning --bucket BUCKET --versioning-configuration Status=Enabled",
        })

    # CIS 2.1.5 — S3 public access block
    pub = config.get("public_access_block", {})
    all_blocked = all([pub.get("block_public_acls"), pub.get("block_public_policy"),
                pub.get("ignore_public_acls"), pub.get("restrict_public_buckets")])
    if not all_blocked:
        missing = [k for k, v in [
            ("BlockPublicAcls", pub.get("block_public_acls")),
            ("BlockPublicPolicy", pub.get("block_public_policy")),
            ("IgnorePublicAcls", pub.get("ignore_public_acls")),
            ("RestrictPublicBuckets", pub.get("restrict_public_buckets")),
        ] if not v]
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "aws_s3_bucket",
            "status": "FAIL",
            "severity": "CRITICAL",
            "cis_rule_id": "CIS 2.1.5",
            "title": "S3 Public Access Block Not Fully Configured",
            "description": f"Bucket '{name}' does not have all public access block settings enabled. This could expose data publicly.",
            "reasoning": f"Checked PublicAccessBlockConfiguration for bucket '{name}'. The following settings are not enabled: {', '.join(missing)}. Without full public access blocking, the bucket or its objects could be made publicly accessible through ACLs or bucket policies.",
            "expected": "All four public access block settings enabled (BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets)",
            "actual": f"Missing: {', '.join(missing)}",
            "recommendation": "Enable all four public access block settings. This is the most effective way to prevent accidental public exposure of S3 data.",
            "remediation_step": "aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        })

    # CIS 3.6 — S3 access logging
    if not config.get("logging"):
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "aws_s3_bucket",
            "status": "FAIL",
            "severity": "MEDIUM",
            "cis_rule_id": "CIS 3.6",
            "title": "S3 Bucket Access Logging Not Enabled",
            "description": f"Bucket '{name}' does not have server access logging enabled. Cannot track who accessed what.",
            "reasoning": f"Checked GetBucketLogging for bucket '{name}'. No LoggingEnabled configuration found. Without access logging, there is no audit trail of who accessed or modified objects in the bucket.",
            "expected": "Server access logging enabled with target bucket configured",
            "actual": "Logging: Disabled",
            "recommendation": "Enable server access logging to a dedicated logging bucket. This provides an audit trail for security investigations and compliance.",
            "remediation_step": "aws s3api put-bucket-logging --bucket BUCKET --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"LOG_BUCKET\",\"TargetPrefix\":\"logs/\"}}'",
        })

    # If all checks pass
    if not findings:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "aws_s3_bucket",
            "status": "PASS",
            "severity": "NONE",
            "cis_rule_id": "ALL",
            "title": "S3 Bucket Fully Compliant",
            "description": f"Bucket '{name}' passes all CIS Benchmark checks (encryption, versioning, public access block, logging).",
            "remediation_step": "No action needed.",
        })

    return findings


def audit_security_group(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check EC2 Security Group against CIS Benchmark rules."""
    findings = []
    config = resource.get("config", {})
    name = resource.get("resource_name", "unknown")

    dangerous_ports = {
        22: ("SSH", "CIS 5.2"),
        3389: ("RDP", "CIS 5.3"),
        3306: ("MySQL", "CIS 5.4"),
        5432: ("PostgreSQL", "CIS 5.4"),
        1433: ("MSSQL", "CIS 5.4"),
        27017: ("MongoDB", "CIS 5.4"),
    }

    for rule in config.get("ingress_rules", []):
        cidr = rule.get("cidr", "")
        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 0)

        # Check for unrestricted access (0.0.0.0/0)
        if cidr in ("0.0.0.0/0", "::/0"):
            # Check all-traffic open
            protocol = rule.get("protocol", "")
            if protocol == "-1" or (from_port == 0 and to_port == 65535):
                findings.append({
                    "resource_id": resource.get("resource_id", ""),
                    "resource_name": name,
                    "region": resource.get("region", ""),
                    "resource_type": "aws_security_group",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "cis_rule_id": "CIS 5.1",
                    "title": "Security Group Allows All Traffic from Internet",
                    "description": f"Security group '{name}' allows ALL inbound traffic from 0.0.0.0/0. This exposes all ports to the internet.",
                    "reasoning": f"Analyzed ingress rules for security group '{name}'. Found a rule with protocol=-1 (all traffic) and CIDR 0.0.0.0/0 (all IPs). This effectively makes every port on associated instances accessible from anywhere on the internet.",
                    "expected": "Ingress rules restricted to specific ports and source IP ranges",
                    "actual": f"Protocol: ALL, Ports: 0-65535, Source: {cidr}",
                    "recommendation": "Remove the unrestricted rule. Create specific rules for only the ports needed (e.g., 443 for HTTPS) and restrict source IPs to known ranges.",
                    "remediation_step": "Restrict ingress rules to specific ports and source IPs. Remove the 0.0.0.0/0 rule.",
                })
                continue

            # Check specific dangerous ports
            for port, (service, cis_id) in dangerous_ports.items():
                if from_port <= port <= to_port:
                    findings.append({
                        "resource_id": resource.get("resource_id", ""),
                        "resource_name": name,
                        "resource_type": "aws_security_group",
                        "status": "FAIL",
                        "severity": "CRITICAL" if port in (22, 3389) else "HIGH",
                        "cis_rule_id": cis_id,
                        "title": f"{service} (Port {port}) Open to Internet",
                        "description": f"Security group '{name}' allows {service} access (port {port}) from 0.0.0.0/0. This is a critical security risk.",
                        "reasoning": f"Found ingress rule in security group '{name}' that allows traffic on port {port} ({service}) from CIDR {cidr}. This exposes the {service} service to the entire internet, making it vulnerable to brute force attacks and exploitation.",
                        "expected": f"Port {port} ({service}) restricted to specific trusted IP ranges or accessed via VPN/bastion",
                        "actual": f"Port {port} ({service}) open to {cidr}",
                        "recommendation": f"Restrict {service} access to specific trusted IPs. Use a VPN or bastion host for administrative access. Consider using AWS Systems Manager Session Manager as a secure alternative to direct SSH/RDP.",
                        "remediation_step": f"Restrict port {port} to specific trusted IPs or use a VPN/bastion host.",
                    })

    if not findings:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "aws_security_group",
            "status": "PASS",
            "severity": "NONE",
            "cis_rule_id": "ALL",
            "title": "Security Group Compliant",
            "description": f"Security group '{name}' passes all CIS Benchmark checks. No unrestricted ingress rules found.",
            "remediation_step": "No action needed.",
        })

    return findings


def audit_iam_policy(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check IAM Policy against CIS Benchmark rules."""
    findings = []
    config = resource.get("config", {})
    name = resource.get("resource_name", "unknown")

    # CIS 1.16 — No full admin (*:*) policies
    if config.get("has_admin_access"):
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", "global"),
            "resource_type": "aws_iam_policy",
            "status": "FAIL",
            "severity": "CRITICAL",
            "cis_rule_id": "CIS 1.16",
            "title": "IAM Policy Grants Full Admin Access",
            "description": f"Policy '{name}' grants Action:* on Resource:* — full administrator access. This violates least-privilege principles.",
            "reasoning": f"Analyzed policy document for '{name}'. Found a statement with Effect:Allow, Action:*, Resource:*. This grants unrestricted access to all AWS services and resources, equivalent to root access.",
            "expected": "Policies should follow least-privilege — grant only specific actions on specific resources",
            "actual": "Effect: Allow, Action: *, Resource: * (full administrator access)",
            "recommendation": "Replace wildcard permissions with specific service actions. Use AWS managed policies like PowerUserAccess or create custom policies scoped to required services only.",
            "remediation_step": "Replace wildcard permissions with specific service actions. Use AWS managed policies like PowerUserAccess instead of custom admin policies.",
        })

    # Check for overly broad permissions
    for stmt in config.get("statements", []):
        if stmt.get("effect") == "Allow":
            actions = stmt.get("action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action.endswith(":*") and action != "*":
                    service = action.split(":")[0]
                    findings.append({
                        "resource_id": resource.get("resource_id", ""),
                        "resource_name": name,
                        "resource_type": "aws_iam_policy",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "cis_rule_id": "CIS 1.22",
                        "title": f"IAM Policy Grants All Actions for {service}",
                        "description": f"Policy '{name}' grants all actions ({action}) for the {service} service. Use specific actions instead.",
                        "reasoning": f"Found statement in policy '{name}' with Action:{action}. This grants every possible API action for the {service} service, which is overly permissive and violates least-privilege.",
                        "expected": f"Specific {service} actions listed (e.g., {service}:GetObject, {service}:PutObject)",
                        "actual": f"Action: {action} (all actions for {service})",
                        "recommendation": f"Identify the specific {service} API actions needed and replace '{action}' with only those actions. Review AWS documentation for the minimum permissions required.",
                        "remediation_step": f"Replace '{action}' with specific actions needed (e.g., {service}:GetObject, {service}:PutObject).",
                    })

    if not findings:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "aws_iam_policy",
            "status": "PASS",
            "severity": "NONE",
            "cis_rule_id": "ALL",
            "title": "IAM Policy Compliant",
            "description": f"Policy '{name}' follows least-privilege principles. No wildcard or overly broad permissions found.",
            "remediation_step": "No action needed.",
        })

    return findings


def audit_iam_user(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check IAM User against CIS Benchmark rules."""
    findings = []
    config = resource.get("config", {})
    name = resource.get("resource_name", "unknown")

    # CIS 1.10 — MFA enabled
    if not config.get("has_mfa"):
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", "global"),
            "resource_type": "aws_iam_user",
            "status": "FAIL",
            "severity": "CRITICAL",
            "cis_rule_id": "CIS 1.10",
            "title": "MFA Not Enabled for IAM User",
            "description": f"User '{name}' does not have Multi-Factor Authentication enabled. Account is vulnerable to credential compromise.",
            "reasoning": f"Checked MFA devices for user '{name}' via ListMFADevices. No MFA device is associated with this user. Without MFA, a compromised password alone is sufficient to access the AWS account.",
            "expected": "At least one MFA device (virtual or hardware) assigned to the user",
            "actual": "MFA devices: 0 (no MFA configured)",
            "recommendation": "Enable MFA immediately. Use a virtual MFA app (Google Authenticator, Authy) or a hardware key (YubiKey). For console users, MFA should be mandatory.",
            "remediation_step": "Enable MFA: IAM Console > Users > Security Credentials > Assign MFA Device. Use a virtual MFA app like Google Authenticator.",
        })

    # CIS 1.14 — Access key rotation (90 days)
    for key in config.get("access_keys", []):
        if key.get("status") == "Active" and key.get("is_old"):
            age = key.get('age_days', '?')
            findings.append({
                "resource_id": resource.get("resource_id", ""),
                "resource_name": name,
                "resource_type": "aws_iam_user",
                "status": "FAIL",
                "severity": "HIGH",
                "cis_rule_id": "CIS 1.14",
                "title": f"Access Key Not Rotated ({age} days old)",
                "description": f"User '{name}' has an access key that is {age} days old (>90 days). Old keys increase risk of compromise.",
                "reasoning": f"Checked access key metadata for user '{name}'. Found an active key that was created {age} days ago, exceeding the 90-day rotation threshold. Long-lived credentials have a higher chance of being leaked or compromised.",
                "expected": "Access keys rotated within 90 days",
                "actual": f"Access key age: {age} days (threshold: 90 days)",
                "recommendation": "Rotate the access key immediately. Create a new key, update all applications using the old key, then deactivate and delete the old key. Consider using IAM roles instead of long-lived keys.",
                "remediation_step": "Rotate the access key: Create new key > Update applications > Deactivate old key > Delete old key.",
            })

    if not findings:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "aws_iam_user",
            "status": "PASS",
            "severity": "NONE",
            "cis_rule_id": "ALL",
            "title": "IAM User Compliant",
            "description": f"User '{name}' has MFA enabled and access keys are current (< 90 days old).",
            "remediation_step": "No action needed.",
        })

    return findings


# ── Audit EC2 Instance ─────────────────────────────────────────────

def audit_ec2_instance(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    config = resource.get("config", {})
    name = resource.get("resource_name", "")

    # Check for IAM Instance Profile
    if not config.get("iam_instance_profile"):
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", ""),
            "resource_type": "aws_ec2_instance",
            "status": "FAIL",
            "severity": "MEDIUM",
            "check_id": "EC2.1",
            "title": "EC2 instance should have an IAM Instance Profile",
            "description": "EC2 instances should use IAM roles instead of hardcoded credentials.",
            "reasoning": f"Instance {name} has no associated IAM instance profile.",
            "expected": "IAM Instance Profile associated",
            "actual": "None",
            "remediation": f"Attach an IAM role to instance {name}.",
        })

    # Check for Public IP
    if config.get("public_ip"):
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", ""),
            "resource_type": "aws_ec2_instance",
            "status": "FAIL",
            "severity": "HIGH",
            "check_id": "EC2.2",
            "title": "EC2 instance should not have a public IP address",
            "description": "Public IP addresses increase the attack surface of the instance.",
            "reasoning": f"Instance {name} has a public IP address: {config.get('public_ip')}",
            "expected": "No Public IP address",
            "actual": config.get("public_ip"),
            "remediation": f"Remove the public IP from instance {name} if not absolutely necessary.",
        })

    if not findings:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", ""),
            "resource_type": "aws_ec2_instance",
            "status": "PASS",
            "severity": "NONE",
            "check_id": "EC2.0",
            "title": "EC2 instance compliance check",
            "description": "Instance follows basic security best practices.",
        })
    return findings

# ── Audit VPC ───────────────────────────────────────────────────

def audit_vpc(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    config = resource.get("config", {})
    name = resource.get("resource_name", "")

    # Check if it's a default VPC
    if config.get("is_default"):
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", ""),
            "resource_type": "aws_vpc",
            "status": "FAIL",
            "severity": "LOW",
            "check_id": "VPC.1",
            "title": "Avoid using the default VPC",
            "description": "Standard practice is to create custom VPCs for better isolation.",
            "reasoning": f"VPC {name} is the default VPC.",
            "expected": "Custom VPC",
            "actual": "Default VPC",
            "remediation": f"Use a custom VPC instead of the default {name}.",
        })

    if not findings:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", ""),
            "resource_type": "aws_vpc",
            "status": "PASS",
            "severity": "NONE",
            "check_id": "VPC.0",
            "title": "VPC compliance check",
            "description": "VPC follows basic security best practices.",
        })
    return findings

# ── Audit RDS ───────────────────────────────────────────────────

def audit_rds_instance(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    config = resource.get("config", {})
    name = resource.get("resource_name", "")

    # Check Public Accessibility
    if config.get("publicly_accessible"):
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", ""),
            "resource_type": "aws_rds_instance",
            "status": "FAIL",
            "severity": "CRITICAL",
            "check_id": "RDS.1",
            "title": "RDS instance should not be publicly accessible",
            "description": "Databases should be kept in private subnets.",
            "reasoning": f"RDS {name} is publicly accessible.",
            "expected": "PubliclyAccessible=False",
            "actual": "PubliclyAccessible=True",
            "remediation": f"Modify RDS {name} to set PubliclyAccessible=False.",
        })

    # Check Encryption
    if not config.get("storage_encrypted"):
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", ""),
            "resource_type": "aws_rds_instance",
            "status": "FAIL",
            "severity": "HIGH",
            "check_id": "RDS.2",
            "title": "RDS instance should have storage encryption enabled",
            "description": "Encrypting data at rest protects against unauthorized hardware access.",
            "reasoning": f"RDS {name} storage is not encrypted.",
            "expected": "StorageEncrypted=True",
            "actual": "StorageEncrypted=False",
            "remediation": f"Enable encryption for RDS {name}.",
        })

    if not findings:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", ""),
            "resource_type": "aws_rds_instance",
            "status": "PASS",
            "severity": "NONE",
            "check_id": "RDS.0",
            "title": "RDS compliance check",
            "description": "RDS follows basic security best practices.",
        })
    return findings

# ── Audit Lambda ──────────────────────────────────────────────────

def audit_lambda_function(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    config = resource.get("config", {})
    name = resource.get("resource_name", "")

    # Check for outdated runtimes
    outdated_runtimes = ["python2.7", "python3.6", "python3.7", "nodejs10.x", "nodejs12.x"]
    if config.get("runtime") in outdated_runtimes:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", ""),
            "resource_type": "aws_lambda_function",
            "status": "FAIL",
            "severity": "MEDIUM",
            "check_id": "LAM.1",
            "title": "Lambda function runtime should be supported",
            "description": "Outdated runtimes may have security vulnerabilities and no support.",
            "reasoning": f"Lambda {name} uses an outdated runtime: {config.get('runtime')}",
            "expected": "Latest supported runtime",
            "actual": config.get("runtime"),
            "remediation": f"Update Lambda {name} runtime to a newer version.",
        })

    if not findings:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", ""),
            "resource_type": "aws_lambda_function",
            "status": "PASS",
            "severity": "NONE",
            "check_id": "LAM.0",
            "title": "Lambda compliance check",
            "description": "Lambda follows basic security best practices.",
        })
    return findings


def audit_generic_resource(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generic audit for resources not handled by specific CIS rules."""
    findings = []
    config = resource.get("config", {})
    name = resource.get("resource_name", "unknown")
    rtype = resource.get("resource_type", "aws_resource")
    tags = config.get("tags", {})

    # Check for mandatory tagging (Best Practice)
    if not tags:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", "global"),
            "resource_type": rtype,
            "status": "WARN",
            "severity": "LOW",
            "check_id": "GEN.1",
            "title": "Resource Missing Tags",
            "description": f"Resource '{name}' has no tags. Tagging is essential for cost allocation and security ownership.",
            "reasoning": f"Resource discovery found that '{name}' ({rtype}) has an empty tag set. CIS best practices recommend tagging all resources with at least Owner and Environment tags.",
            "expected": "At least one tag (e.g., Owner, Environment, Project)",
            "actual": "No tags found",
            "recommendation": "Add descriptive tags to this resource to improve governance and auditability.",
            "remediation_step": "Use AWS Console or Tagging API to add relevant tags to the resource.",
        })

    if not findings:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "region": resource.get("region", "global"),
            "resource_type": rtype,
            "status": "PASS",
            "severity": "NONE",
            "check_id": "GEN.0",
            "title": "Generic Resource Check",
            "description": f"Resource '{name}' has basic metadata/tagging and is accounted for in inventory.",
        })

    return findings


def audit_cloudtrail_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze a CloudTrail event for security concerns."""
    result = {
        "event_id": event.get("event_id", ""),
        "event_name": event.get("event_name", ""),
        "event_source": event.get("event_source", ""),
        "event_time": event.get("event_time", ""),
        "username": event.get("username", ""),
        "source_ip": event.get("source_ip", ""),
        "status": "PASS",
        "severity": "NONE",
        "alert": None,
    }

    name = event.get("event_name", "")
    error = event.get("error_code", "")

    # Access denied events
    if error in ("AccessDenied", "UnauthorizedAccess", "Client.UnauthorizedAccess"):
        result["status"] = "FAIL"
        result["severity"] = "HIGH"
        result["alert"] = f"Access denied: {name} by {event.get('username', 'unknown')} from {event.get('source_ip', 'unknown')}"

    # Destructive actions
    elif any(name.startswith(prefix) for prefix in ("Delete", "Remove", "Detach", "Disable", "Deregister")):
        result["status"] = "WARN"
        result["severity"] = "MEDIUM"
        result["alert"] = f"Destructive action: {name} by {event.get('username', 'unknown')}"

    # Console login without MFA
    elif name == "ConsoleLogin":
        result["status"] = "INFO"
        result["severity"] = "LOW"
        result["alert"] = f"Console login by {event.get('username', 'unknown')} from {event.get('source_ip', 'unknown')}"

    # Security-related changes
    elif any(keyword in name for keyword in ("SecurityGroup", "Policy", "Role", "Permission", "Encryption", "Password")):
        result["status"] = "WARN"
        result["severity"] = "MEDIUM"
        result["alert"] = f"Security config change: {name} by {event.get('username', 'unknown')}"

    return result


# ── Main Audit Orchestrator ───────────────────────────────────────────────────

def audit_live_resources(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Run CIS audit on all scanned AWS resources."""
    results = {
        "audit_time": datetime.now(timezone.utc).isoformat(),
        "findings": [],
        "events_analysis": [],
        "health_score": 100.0,
        "total_checks": 0,
        "passed": 0,
        "failed": 0,
        "summary": {
            "total_resources": 0,
            "passing": 0,
            "failing": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
    }

    audit_functions = {
        "aws_s3_bucket": audit_s3_bucket,
        "aws_security_group": audit_security_group,
        "aws_iam_policy": audit_iam_policy,
        "aws_iam_user": audit_iam_user,
        "aws_ec2_instance": audit_ec2_instance,
        "aws_vpc": audit_vpc,
        "aws_rds_instance": audit_rds_instance,
        "aws_lambda_function": audit_lambda_function,
    }

    # Audit each resource
    for resource in scan_data.get("resources", []):
        if "error" in resource:
            continue
        rtype = resource.get("resource_type", "")
        audit_fn = audit_functions.get(rtype)
        
        if audit_fn:
            resource_findings = audit_fn(resource)
        else:
            # Fallback to generic auditor for unknown types
            resource_findings = audit_generic_resource(resource)
            
        results["findings"].extend(resource_findings)
        results["summary"]["total_resources"] += 1

    # Analyze CloudTrail events
    for event in scan_data.get("events", []):
        if "error" in event:
            continue
        event_result = audit_cloudtrail_event(event)
        results["events_analysis"].append(event_result)

    # Calculate summary
    for f in results["findings"]:
        if f["status"] == "PASS":
            results["summary"]["passing"] += 1
        else:
            results["summary"]["failing"] += 1
            sev = f["severity"].lower()
            if sev in results["summary"]:
                results["summary"][sev] += 1

    total_checks = len(results["findings"])
    results["total_checks"] = total_checks
    results["passed"] = results["summary"]["passing"]
    results["failed"] = results["summary"]["failing"]

    # Calculate health score — based on findings, not resource count, for consistency
    if total_checks > 0:
        severity_weights = {"critical": 15, "high": 8, "medium": 3, "low": 1}
        # Only FAIL findings with known severity incur penalty
        total_penalty = sum(
            results["summary"].get(sev, 0) * weight
            for sev, weight in severity_weights.items()
        )
        # Max possible penalty: all checks are CRITICAL
        max_penalty = total_checks * severity_weights["critical"]
        results["health_score"] = max(0, round(100 - (total_penalty / max_penalty * 100), 1))

    return results
