from datetime import datetime, timezone
from typing import Dict, Any, List

def audit_storage_bucket(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    config = resource.get("config", {})
    name = resource.get("resource_name", "")

    # Check for versioning
    if not config.get("versioning_enabled"):
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "google_storage_bucket",
            "status": "FAIL",
            "severity": "LOW",
            "check_id": "GCP.S3.1",
            "title": "Enable versioning for storage buckets",
            "description": "Bucket versioning protects against accidental deletion and overwriting of objects.",
            "reasoning": f"Bucket {name} is Not versioned.",
            "expected": "VersioningEnabled=True",
            "actual": "VersioningEnabled=False",
            "remediation": f"Enable versioning on bucket {name}.",
        })

    if not findings:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "google_storage_bucket",
            "status": "PASS",
            "severity": "NONE",
            "check_id": "GCP.S3.0",
            "title": "Storage Bucket compliance check",
            "description": "Storage bucket follows basic security best practices.",
        })
    return findings

def audit_compute_instance(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    config = resource.get("config", {})
    name = resource.get("resource_name", "")

    # (Mock check for demo)
    if not findings:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "google_compute_instance",
            "status": "PASS",
            "severity": "NONE",
            "check_id": "GCP.GCE.0",
            "title": "Compute Instance compliance check",
            "description": "Compute instance follows basic security best practices.",
        })
    return findings

def audit_gcp_resources(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Run compliance audit on all scanned GCP resources."""
    results = {
        "audit_time": datetime.now(timezone.utc).isoformat(),
        "findings": [],
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
        "google_storage_bucket": audit_storage_bucket,
        "google_compute_instance": audit_compute_instance,
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

    # Calculate summary
    for f in results["findings"]:
        if f["status"] == "PASS":
            results["summary"]["passing"] += 1
        else:
            results["summary"]["failing"] += 1
            sev = f["severity"].lower()
            if sev in results["summary"]:
                results["summary"][sev] += 1

    results["total_checks"] = len(results["findings"])
    results["passed"] = results["summary"]["passing"]
    results["failed"] = results["summary"]["failing"]

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
