"""
Shared Compliance Scoring Logic — Unifies the "Health Score" calculation across the dashboard and reports.
"""

from typing import List, Dict, Any

# Standardized weights for compliance health penalty system
SEVERITY_WEIGHTS = {
    "CRITICAL": 15.0,
    "HIGH": 8.0,
    "MEDIUM": 3.0,
    "LOW": 1.0,
    "INFO": 0.0,
    "NONE": 0.0,
}

# Statuses that count as "failed" in the compliance health calculation
FAILED_STATUSES = {"FAIL", "WARN", "NON_COMPLIANT"}

def calculate_compliance_score(findings: List[Dict[str, Any]], total_checks: int) -> float:
    """
    Calculate a compliance health score (0-100) based on weighted penalties.
    
    Formula: 100 - (Total Penalty / Max Possible Penalty * 100)
    Max Possible Penalty = Total Checks * weight('CRITICAL')
    """
    if total_checks <= 0:
        return 100.0

    total_penalty = 0.0
    for f in findings:
        status = str(f.get("status") or f.get("check_status") or "").upper()
        if status in FAILED_STATUSES:
            sev = str(f.get("severity") or "LOW").upper()
            total_penalty += SEVERITY_WEIGHTS.get(sev, 1.0)

    # Max penalty assumes every check failed with CRITICAL severity
    max_penalty = total_checks * SEVERITY_WEIGHTS["CRITICAL"]
    if max_penalty <= 0:
        return 100.0

    score = max(0.0, 100.0 - (total_penalty / max_penalty * 100.0))
    return round(score, 1)

def get_issue_count(findings: List[Dict[str, Any]]) -> int:
    """Return the total number of findings with FAIL or WARN status."""
    return sum(
        1 for f in findings 
        if str(f.get("status") or f.get("check_status") or "").upper() in FAILED_STATUSES
    )

def get_severity_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Return a count of issues by severity level."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        status = str(f.get("status") or f.get("check_status") or "").upper()
        if status in FAILED_STATUSES:
            sev = str(f.get("severity") or "LOW").upper()
            if sev in counts:
                counts[sev] += 1
    return counts
