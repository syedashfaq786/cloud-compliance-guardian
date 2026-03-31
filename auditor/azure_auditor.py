from datetime import datetime, timezone
from typing import Dict, Any, List

def audit_resource_group(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    config = resource.get("config", {})
    name = resource.get("resource_name", "")

    # Check for empty resource groups or specific tags if needed
    # (Mock check for demo)
    if not config.get("tags"):
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "azurerm_resource_group",
            "status": "FAIL",
            "severity": "LOW",
            "check_id": "AZ.RG.1",
            "title": "Resource groups should have tags",
            "description": "Tagging is essential for cost management and ownership tracking.",
            "reasoning": f"Resource group {name} has no tags.",
            "expected": "At least one tag defined",
            "actual": "No tags",
            "remediation": f"Assign tags to resource group {name} for easier management.",
        })

    if not findings:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "azurerm_resource_group",
            "status": "PASS",
            "severity": "NONE",
            "check_id": "AZ.RG.0",
            "title": "Resource Group compliance check",
            "description": "Resource group follows basic security best practices.",
        })
    return findings

def audit_virtual_machine(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    config = resource.get("config", {})
    name = resource.get("resource_name", "")

    # Check for VM size or provisioning status
    # (Mock check for demo)
    if "Standard_D" in config.get("vm_size", ""):
        # Example: D-series might be expensive, warn about it
        pass

    if not findings:
        findings.append({
            "resource_id": resource.get("resource_id", ""),
            "resource_name": name,
            "resource_type": "azurerm_virtual_machine",
            "status": "PASS",
            "severity": "NONE",
            "check_id": "AZ.VM.0",
            "title": "Virtual Machine compliance check",
            "description": "Virtual machine follows basic security best practices.",
        })
    return findings

def audit_azure_resources(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Run compliance audit on all scanned Azure resources."""
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
        "azurerm_resource_group": audit_resource_group,
        "azurerm_virtual_machine": audit_virtual_machine,
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
