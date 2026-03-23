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
            "resource_type": "aws_s3_bucket",
            "status": "FAIL",
            "severity": "HIGH",
            "cis_rule_id": "CIS 2.1.1",
            "title": "S3 Bucket Server-Side Encryption Not Enabled",
            "description": f"Bucket '{name}' does not have server-side encryption enabled. Data at rest is unprotected.",
            "remediation_step": "Enable SSE-S3 or SSE-KMS encryption: aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'",
        })

    # CIS 2.1.2 — S3 bucket versioning
    if config.get("versioning") != "Enabled":
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "aws_s3_bucket",
            "status": "FAIL",
            "severity": "MEDIUM",
            "cis_rule_id": "CIS 2.1.2",
            "title": "S3 Bucket Versioning Not Enabled",
            "description": f"Bucket '{name}' does not have versioning enabled. Data cannot be recovered if accidentally deleted.",
            "remediation_step": "Enable versioning: aws s3api put-bucket-versioning --bucket BUCKET --versioning-configuration Status=Enabled",
        })

    # CIS 2.1.5 — S3 public access block
    pub = config.get("public_access_block", {})
    if not all([pub.get("block_public_acls"), pub.get("block_public_policy"),
                pub.get("ignore_public_acls"), pub.get("restrict_public_buckets")]):
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "aws_s3_bucket",
            "status": "FAIL",
            "severity": "CRITICAL",
            "cis_rule_id": "CIS 2.1.5",
            "title": "S3 Public Access Block Not Fully Configured",
            "description": f"Bucket '{name}' does not have all public access block settings enabled. This could expose data publicly.",
            "remediation_step": "Enable all public access block settings: aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
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
            "remediation_step": "Enable access logging: aws s3api put-bucket-logging --bucket BUCKET --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"LOG_BUCKET\",\"TargetPrefix\":\"logs/\"}}'",
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
            "description": f"Bucket '{name}' passes all CIS Benchmark checks.",
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
                    "resource_type": "aws_security_group",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "cis_rule_id": "CIS 5.1",
                    "title": "Security Group Allows All Traffic from Internet",
                    "description": f"Security group '{name}' allows ALL inbound traffic from 0.0.0.0/0. This exposes all ports to the internet.",
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
            "description": f"Security group '{name}' passes all CIS Benchmark checks.",
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
            "resource_type": "aws_iam_policy",
            "status": "FAIL",
            "severity": "CRITICAL",
            "cis_rule_id": "CIS 1.16",
            "title": "IAM Policy Grants Full Admin Access",
            "description": f"Policy '{name}' grants Action:* on Resource:* — full administrator access. This violates least-privilege principles.",
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
            "description": f"Policy '{name}' follows least-privilege principles.",
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
            "resource_type": "aws_iam_user",
            "status": "FAIL",
            "severity": "CRITICAL",
            "cis_rule_id": "CIS 1.10",
            "title": "MFA Not Enabled for IAM User",
            "description": f"User '{name}' does not have Multi-Factor Authentication enabled. Account is vulnerable to credential compromise.",
            "remediation_step": "Enable MFA: IAM Console > Users > Security Credentials > Assign MFA Device. Use a virtual MFA app like Google Authenticator.",
        })

    # CIS 1.14 — Access key rotation (90 days)
    for key in config.get("access_keys", []):
        if key.get("status") == "Active" and key.get("is_old"):
            findings.append({
                "resource_id": resource.get("resource_id", ""),
                "resource_name": name,
                "resource_type": "aws_iam_user",
                "status": "FAIL",
                "severity": "HIGH",
                "cis_rule_id": "CIS 1.14",
                "title": f"Access Key Not Rotated ({key.get('age_days', '?')} days old)",
                "description": f"User '{name}' has an access key that is {key.get('age_days', '?')} days old (>90 days). Old keys increase risk of compromise.",
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
            "description": f"User '{name}' has MFA enabled and keys are current.",
            "remediation_step": "No action needed.",
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
    }

    # Audit each resource
    for resource in scan_data.get("resources", []):
        if "error" in resource:
            continue
        rtype = resource.get("resource_type", "")
        audit_fn = audit_functions.get(rtype)
        if audit_fn:
            resource_findings = audit_fn(resource)
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

    # Calculate health score
    total = results["summary"]["total_resources"]
    if total > 0:
        severity_weights = {"critical": 15, "high": 8, "medium": 3, "low": 1}
        total_penalty = sum(
            results["summary"].get(sev, 0) * weight
            for sev, weight in severity_weights.items()
        )
        max_penalty = total * 15
        results["health_score"] = max(0, round(100 - (total_penalty / max_penalty * 100), 1))

    return results
