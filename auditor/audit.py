"""
Audit Orchestrator — Ties together parser, inference, remediation, and database.

Provides the main `run_audit()` function that takes a Terraform directory,
runs the full CIS compliance analysis pipeline, and stores results.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

from .parser import HCLParser, ParseResult
from .inference import InferenceClient, ViolationFinding
from .cis_rules import get_rules_for_resource_type, Severity
from .remediation import enrich_remediation
from .database import init_db, get_session, save_audit, save_drift_alert, get_recent_audits
from .rule_engine import run_rule_based_audit, get_audit_summary, detect_cloud_provider
from .scoring import calculate_compliance_score, get_severity_summary


@dataclass
class AuditReport:
    """Complete audit report with findings, score, and metadata."""
    audit_id: str
    directory: str
    timestamp: str
    files_scanned: int = 0
    resources_scanned: int = 0
    compliance_score: float = 100.0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    compliant_resources: List[str] = field(default_factory=list)
    parse_errors: List[Dict[str, str]] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    status: str = "completed"

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def has_critical(self) -> bool:
        return self.severity_counts.get("CRITICAL", 0) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "directory": self.directory,
            "timestamp": self.timestamp,
            "files_scanned": self.files_scanned,
            "resources_scanned": self.resources_scanned,
            "compliance_score": self.compliance_score,
            "total_findings": self.total_findings,
            "severity_counts": self.severity_counts,
            "findings": self.findings,
            "compliant_resources": self.compliant_resources,
            "parse_errors": self.parse_errors,
            "status": self.status,
        }


def _calculate_compliance_score(findings: List[ViolationFinding], total_checks: int) -> float:
    """Calculate compliance score using the shared scoring utility."""
    # Convert findings to dicts for the utility
    finding_dicts = [f.to_dict() if hasattr(f, "to_dict") else f.__dict__ for f in findings]
    return calculate_compliance_score(finding_dicts, total_checks)


def _count_severities(findings: List[ViolationFinding]) -> Dict[str, int]:
    """Count findings by severity level using the shared scoring utility."""
    finding_dicts = [f.to_dict() if hasattr(f, "to_dict") else f.__dict__ for f in findings]
    return get_severity_summary(finding_dicts)


def _detect_drift(current_findings: List[ViolationFinding], audit_id: str):
    """Compare with previous audit to detect compliance drift."""
    try:
        session = get_session()
        recent = get_recent_audits(session, limit=1)
        if not recent:
            session.close()
            return

        previous = recent[0]

        # Check for score drop
        current_score = _calculate_compliance_score(current_findings, max(len(current_findings), 1))
        if previous.compliance_score - current_score > 10:
            save_drift_alert(session, {
                "alert_type": "score_drop",
                "severity": "HIGH",
                "title": f"Compliance score dropped by {previous.compliance_score - current_score:.1f}%",
                "description": (
                    f"Score dropped from {previous.compliance_score}% to {current_score}%. "
                    f"This may indicate new infrastructure changes introducing vulnerabilities."
                ),
                "previous_audit_id": previous.audit_id,
                "current_audit_id": audit_id,
            })

        # Check for new critical findings
        current_critical = [f for f in current_findings if f.severity == "CRITICAL"]
        if len(current_critical) > previous.critical_count:
            save_drift_alert(session, {
                "alert_type": "regression",
                "severity": "CRITICAL",
                "title": f"{len(current_critical) - previous.critical_count} new CRITICAL violations detected",
                "description": "New critical CIS benchmark violations have been introduced.",
                "current_audit_id": audit_id,
            })

        session.close()
    except Exception:
        pass  # Drift detection is best-effort


def run_audit(
    directory: str,
    endpoint: Optional[str] = None,
    model: Optional[str] = None,
    backend: Optional[str] = None,
    framework: str = "CIS",
    triggered_by: str = "cli",
    pr_url: Optional[str] = None,
    store_results: bool = True,
) -> AuditReport:
    """Run a full CIS compliance audit on a Terraform directory.

    Args:
        directory: Path to Terraform files
        endpoint: Sec-8B model endpoint (uses env var if not provided)
        model: Model name (uses env var if not provided)
        backend: 'ollama' or 'vllm' (uses env var if not provided)
        framework: Compliance framework (CIS | NIST | CCM)
        triggered_by: What triggered this audit (cli, pr, api, scheduled)
        pr_url: Associated PR URL (if triggered from GitHub)
        store_results: Whether to persist results in the database

    Returns:
        AuditReport with all findings, score, and metadata
    """
    audit_id = str(uuid.uuid4())[:12]
    timestamp = datetime.now(timezone.utc).isoformat()

    report = AuditReport(
        audit_id=audit_id,
        directory=directory,
        timestamp=timestamp,
    )
    selected_framework = (framework or "CIS").upper()
    if selected_framework not in {"CIS", "NIST", "CCM"}:
        selected_framework = "CIS"

    # ── Step 1: Parse Terraform files ─────────────────────────────────────
    try:
        parser = HCLParser(directory)
        parse_result = parser.parse_directory()
    except (FileNotFoundError, NotADirectoryError) as e:
        report.status = "error"
        report.parse_errors.append({"file": directory, "error": str(e)})
        return report

    report.files_scanned = parse_result.files_scanned
    report.resources_scanned = parse_result.resource_count
    report.parse_errors = parse_result.errors

    if not parse_result.resources:
        report.status = "completed"
        report.compliance_score = 100.0
        report.severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        if store_results:
            try:
                init_db()
                session = get_session()
                save_audit(session, {
                    "audit_id": audit_id,
                    "directory": directory,
                    "files_scanned": report.files_scanned,
                    "resources_scanned": report.resources_scanned,
                    "total_findings": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "compliance_score": 100.0,
                    "status": "completed",
                    "triggered_by": triggered_by,
                    "pr_url": pr_url,
                    "metadata_json": {
                        "domain": "terraform",
                        "target": "terraform",
                        "framework": selected_framework,
                        "mode": "directory",
                    },
                    "findings": [],
                })
                session.close()
            except Exception:
                pass
        return report

    # ── Step 2: Run rule-based audit engine ─────────────────────────────
    rule_findings = run_rule_based_audit(parse_result.resources)
    summary = get_audit_summary(rule_findings)

    # Separate PASS and FAIL findings
    failed_findings = [f for f in rule_findings if f.status == "FAIL"]
    passed_findings = [f for f in rule_findings if f.status == "PASS"]

    # Track compliant resources
    failed_addresses = set(f.resource_address for f in failed_findings)
    for resource in parse_result.resources:
        if resource.address not in failed_addresses:
            report.compliant_resources.append(resource.address)

    # ── Step 3: Calculate score and counts ─────────────────────────────────
    report.compliance_score = summary["compliance_score"]
    report.severity_counts = summary["severity_counts"]
    findings_data = [f.to_dict() for f in rule_findings]
    if selected_framework == "CIS":
        for f in findings_data:
            f.setdefault("framework", "CIS")
            f.setdefault("rule_id", f.get("cis_rule_id") or f.get("rule_id", ""))
        report.findings = findings_data
    else:
        from .framework_mapping import translate_findings_to_framework
        report.findings = translate_findings_to_framework(findings_data, selected_framework)

    # ── Step 5: Store in database ─────────────────────────────────────────
    if store_results:
        try:
            init_db()
            session = get_session()
            save_audit(session, {
                "audit_id": audit_id,
                "directory": directory,
                "files_scanned": report.files_scanned,
                "resources_scanned": report.resources_scanned,
                "total_findings": summary["failed"],
                "critical_count": report.severity_counts.get("CRITICAL", 0),
                "high_count": report.severity_counts.get("HIGH", 0),
                "medium_count": report.severity_counts.get("MEDIUM", 0),
                "low_count": report.severity_counts.get("LOW", 0),
                "compliance_score": report.compliance_score,
                "status": "completed",
                "triggered_by": triggered_by,
                "pr_url": pr_url,
                "metadata_json": {
                    "domain": "terraform",
                    "target": "terraform",
                    "framework": selected_framework,
                    "mode": "directory",
                },
                "findings": report.findings,
            })
            session.close()
        except Exception:
            pass  # Don't fail the audit if DB is unavailable

    # ── Step 5: Detect drift ──────────────────────────────────────────────
    if store_results:
        # Convert rule findings to ViolationFinding format for drift detection
        violation_findings = [
            ViolationFinding(
                rule_id=f.rule_id, rule_title=f.rule_title,
                severity=f.severity, resource_address=f.resource_address,
                resource_type=f.resource_type, file_path=f.file_path,
                description=f.description, reasoning=f.reasoning,
            )
            for f in failed_findings
        ]
        _detect_drift(violation_findings, audit_id)

    report.status = "completed"
    return report
