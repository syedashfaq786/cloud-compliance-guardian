"""
FastAPI REST API — Serves audit data to the Security Dashboard.

Endpoints:
    GET  /api/audits          — List recent audits
    GET  /api/audits/{id}     — Get audit details with findings
    GET  /api/trends          — Get compliance trend data
    GET  /api/drift           — Get active drift alerts
    POST /api/scan            — Trigger a new audit
    GET  /api/summary         — Get compliance summary
    POST /api/drift/{id}/ack  — Acknowledge a drift alert
"""

import os
import csv
import io
import json
import threading
from typing import Optional
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .database import (
    init_db,
    get_session,
    get_recent_audits,
    get_audit_by_id,
    get_findings_by_audit,
    get_trend_data,
    get_active_drift_alerts,
    acknowledge_alert,
    get_compliance_summary,
    save_github_repo,
    get_connected_repo,
    update_repo_sync_time,
)
from .audit import run_audit
from .github import clone_repo, get_repo_metadata, sync_and_scan, get_repo_name_from_url
from .aws_scanner import AWSScanner
from .aws_auditor import audit_live_resources


# ─── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Cloud-Compliance Guardian API",
    description="CIS Benchmark compliance auditor powered by Cisco Sec-8B",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, lock this down
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    """Initialize the database on startup."""
    init_db()


# ─── Request/Response Models ─────────────────────────────────────────────────

class ScanRequest(BaseModel):
    directory: str
    endpoint: Optional[str] = None
    model: Optional[str] = None
    backend: Optional[str] = None


class ScanResponse(BaseModel):
    audit_id: str
    compliance_score: float
    total_findings: int
    severity_counts: dict
    status: str


class GitHubConnectRequest(BaseModel):
    url: str


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "compliance-guardian"}


@app.get("/api/summary")
def get_summary():
    """Get overall compliance summary."""
    session = get_session()
    try:
        return get_compliance_summary(session)
    finally:
        session.close()


@app.get("/api/audits")
def list_audits(limit: int = Query(20, ge=1, le=100)):
    """List recent audits."""
    session = get_session()
    try:
        audits = get_recent_audits(session, limit=limit)
        return {"audits": [a.to_dict() for a in audits]}
    finally:
        session.close()


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: str):
    """Get a specific audit with its findings and scanned file list."""
    session = get_session()
    try:
        audit = get_audit_by_id(session, audit_id)
        if not audit:
            raise HTTPException(status_code=404, detail="Audit not found")

        findings = get_findings_by_audit(session, audit.id)
        findings_data = [f.to_dict() for f in findings]
        result = audit.to_dict()
        result["findings"] = findings_data

        # Build scanned files list with status from findings
        files_with_findings = {}
        for f in findings_data:
            fp = f.get("file_path", "")
            if not fp:
                continue
            if fp not in files_with_findings:
                files_with_findings[fp] = {"file": fp, "pass": 0, "fail": 0, "resources": set()}
            files_with_findings[fp]["resources"].add(f.get("resource_address", ""))
            if f.get("status") == "FAIL":
                files_with_findings[fp]["fail"] += 1
            else:
                files_with_findings[fp]["pass"] += 1

        # Try to also discover files with no findings by scanning directory
        directory = audit.directory
        try:
            from pathlib import Path
            dir_path = Path(directory)
            if dir_path.exists() and dir_path.is_dir():
                for tf_file in sorted(dir_path.rglob("*.tf")):
                    rel = str(tf_file.relative_to(dir_path))
                    if rel not in files_with_findings:
                        files_with_findings[rel] = {"file": rel, "pass": 0, "fail": 0, "resources": set()}
        except Exception:
            pass

        # Convert sets to lists for JSON serialization
        scanned_files = []
        for fp, info in sorted(files_with_findings.items()):
            status = "clean" if info["fail"] == 0 else "issues"
            scanned_files.append({
                "file": fp,
                "pass_count": info["pass"],
                "fail_count": info["fail"],
                "resources": list(info["resources"]),
                "status": status,
            })

        result["scanned_files"] = scanned_files
        return result
    finally:
        session.close()


@app.get("/api/trends")
def get_trends(days: int = Query(30, ge=1, le=365)):
    """Get compliance trend data."""
    session = get_session()
    try:
        snapshots = get_trend_data(session, days=days)
        return {"trends": [s.to_dict() for s in snapshots]}
    finally:
        session.close()


@app.get("/api/drift")
def get_drift_alerts():
    """Get active drift detection alerts."""
    session = get_session()
    try:
        alerts = get_active_drift_alerts(session)
        return {"alerts": [a.to_dict() for a in alerts]}
    finally:
        session.close()


@app.post("/api/scan", response_model=ScanResponse)
def trigger_scan(request: ScanRequest):
    """Trigger a new compliance audit."""
    try:
        report = run_audit(
            directory=request.directory,
            endpoint=request.endpoint,
            model=request.model,
            backend=request.backend,
            triggered_by="api",
        )
        return ScanResponse(
            audit_id=report.audit_id,
            compliance_score=report.compliance_score,
            total_findings=report.total_findings,
            severity_counts=report.severity_counts,
            status=report.status,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audits/{audit_id}/report")
def download_audit_report(audit_id: str, format: str = Query("pdf", pattern="^(pdf|csv|json)$")):
    """Download an audit report as PDF, CSV, or JSON."""
    session = get_session()
    try:
        audit = get_audit_by_id(session, audit_id)
        if not audit:
            raise HTTPException(status_code=404, detail="Audit not found")

        findings = get_findings_by_audit(session, audit.id)
        audit_data = audit.to_dict()
        findings_data = [f.to_dict() for f in findings]

        if format == "pdf":
            from .report_generator import generate_pdf_report
            pdf_bytes = generate_pdf_report(audit_data, findings_data)
            return StreamingResponse(
                io.BytesIO(pdf_bytes),
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=audit-report-{audit_id}.pdf"},
            )

        if format == "json":
            report = {
                "report_title": "Cloud Compliance Guardian — Audit Report",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "audit": audit_data,
                "summary": {
                    "total_checks": len(findings_data),
                    "passed": sum(1 for f in findings_data if f.get("status") == "PASS"),
                    "failed": sum(1 for f in findings_data if f.get("status") == "FAIL"),
                    "compliance_score": audit_data["compliance_score"],
                },
                "findings": findings_data,
            }
            content = json.dumps(report, indent=2)
            return StreamingResponse(
                io.BytesIO(content.encode()),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=audit-report-{audit_id}.json"},
            )

        # CSV format
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Status", "Severity", "Rule ID", "Rule Title", "Resource",
            "Resource Type", "Cloud Provider", "File", "Description",
            "Expected", "Actual", "Recommendation", "Remediation HCL"
        ])
        for f in findings_data:
            writer.writerow([
                f.get("status", ""), f.get("severity", ""), f.get("rule_id", ""),
                f.get("rule_title", ""), f.get("resource_address", ""),
                f.get("resource_type", ""), f.get("cloud_provider", ""),
                f.get("file_path", ""), f.get("description", ""),
                f.get("expected", ""), f.get("actual", ""),
                f.get("recommendation", ""), f.get("remediation_hcl", ""),
            ])
        content = output.getvalue()
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=audit-report-{audit_id}.csv"},
        )
    finally:
        session.close()


@app.post("/api/drift/{alert_id}/ack")
def ack_drift_alert(alert_id: int):
    """Acknowledge a drift detection alert."""
    session = get_session()
    try:
        success = acknowledge_alert(session, alert_id)
        if not success:
            raise HTTPException(status_code=404, detail="Alert not found")
        return {"status": "acknowledged", "alert_id": alert_id}
    finally:
        session.close()


# ─── GitHub Integration ──────────────────────────────────────────────────────


@app.post("/api/github/connect")
def connect_github(request: GitHubConnectRequest):
    """Clone a GitHub repo, save to DB, and auto-trigger a scan."""
    try:
        repo_name = clone_repo(request.url)
        metadata = get_repo_metadata(repo_name)

        session = get_session()
        try:
            repo = save_github_repo(session, repo_name, request.url)
            repo_id = repo.id
            result = repo.to_dict()
            result["metadata"] = metadata
        finally:
            session.close()

        # Auto-trigger scan in background after cloning
        def _auto_scan():
            try:
                sync_and_scan(repo_name)
            except Exception:
                pass
            try:
                s = get_session()
                update_repo_sync_time(s, repo_id)
                s.close()
            except Exception:
                pass

        thread = threading.Thread(target=_auto_scan, daemon=True)
        thread.start()

        result["scan_triggered"] = True
        result["message"] = "Repository cloned and scan started. Check the Audits tab for results."
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/github/repo")
def get_github_repo():
    """Get the currently connected GitHub repository."""
    session = get_session()
    try:
        repo = get_connected_repo(session)
        if not repo:
            return {"connected": False}

        repo_name = get_repo_name_from_url(repo.url)
        metadata = get_repo_metadata(repo_name)
        result = repo.to_dict()
        result["connected"] = True
        result["metadata"] = metadata
        return result
    finally:
        session.close()


@app.post("/api/github/sync")
def sync_github_repo():
    """Pull latest changes and run a compliance scan."""
    session = get_session()
    try:
        repo = get_connected_repo(session)
        if not repo:
            raise HTTPException(status_code=404, detail="No connected repository")

        repo_name = get_repo_name_from_url(repo.url)
        repo_id = repo.id
        session.close()

        # Run scan in background thread so the API responds quickly
        def _background_scan():
            try:
                sync_and_scan(repo_name)
            except Exception:
                pass
            try:
                s = get_session()
                update_repo_sync_time(s, repo_id)
                s.close()
            except Exception:
                pass

        thread = threading.Thread(target=_background_scan, daemon=True)
        thread.start()

        return {"status": "syncing", "message": "Sync started. Audit will appear in Audits tab when complete."}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/github/disconnect")
def disconnect_github():
    """Disconnect the GitHub repository."""
    session = get_session()
    try:
        repo = get_connected_repo(session)
        if not repo:
            raise HTTPException(status_code=404, detail="No connected repository")

        repo.is_active = False
        session.commit()
        return {"status": "disconnected"}
    finally:
        session.close()


# ─── AWS Live Auditor ────────────────────────────────────────────────────────

class AWSCredentialsRequest(BaseModel):
    access_key: str
    secret_key: str
    region: Optional[str] = "us-east-1"


# In-memory cache for latest scan results
_aws_scan_cache: dict = {}


@app.get("/api/aws/status")
def aws_connection_status():
    """Check if AWS credentials are configured and valid."""
    scanner = AWSScanner()
    result = scanner.test_connection()
    return result


@app.post("/api/aws/configure")
def configure_aws(creds: AWSCredentialsRequest):
    """Save AWS credentials to environment (session only, not persisted to disk)."""
    # Strip whitespace — copy-paste often adds trailing spaces/newlines
    access_key = creds.access_key.strip()
    secret_key = creds.secret_key.strip()
    region = (creds.region or "us-east-1").strip()

    os.environ["AWS_ACCESS_KEY_ID"] = access_key
    os.environ["AWS_SECRET_ACCESS_KEY"] = secret_key
    os.environ["AWS_DEFAULT_REGION"] = region

    # Test the credentials with a fresh scanner
    scanner = AWSScanner(access_key, secret_key, region)
    result = scanner.test_connection()
    if not result.get("connected"):
        # Clean up env vars on failure so status endpoint doesn't show stale creds
        os.environ.pop("AWS_ACCESS_KEY_ID", None)
        os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
        return {"status": "error", "message": result.get("error", "Invalid credentials")}

    return {"status": "connected", **result}


@app.post("/api/aws/scan")
def run_aws_scan():
    """Run a full AWS live scan and audit."""
    global _aws_scan_cache
    scanner = AWSScanner()

    # Test connection first
    conn = scanner.test_connection()
    if not conn.get("connected"):
        raise HTTPException(status_code=401, detail=conn.get("error", "AWS not configured"))

    # Run the scan
    scan_data = scanner.run_full_scan()

    # Run the audit
    audit_results = audit_live_resources(scan_data)

    # Merge scan summary with audit results
    result = {
        "scan": scan_data["summary"],
        "scan_time": scan_data["scan_time"],
        "region": scan_data["region"],
        "audit": audit_results,
    }

    _aws_scan_cache = result
    return result


@app.get("/api/aws/scan/latest")
def get_latest_aws_scan():
    """Get the most recent AWS scan results from cache."""
    if not _aws_scan_cache:
        return {"cached": False, "message": "No scan results available. Run a scan first."}
    return {"cached": True, **_aws_scan_cache}


@app.get("/api/aws/scan/report")
def download_aws_report(format: str = Query("pdf", pattern="^(pdf|csv|json)$")):
    """Download the latest AWS live scan report."""
    if not _aws_scan_cache:
        raise HTTPException(status_code=404, detail="No scan results. Run a scan first.")

    audit = _aws_scan_cache.get("audit", {})
    scan = _aws_scan_cache.get("scan", {})
    findings_list = audit.get("findings", [])
    region = _aws_scan_cache.get("region", "unknown")
    scan_time = _aws_scan_cache.get("scan_time", "")

    if format == "json":
        report = {
            "report_title": "Cloud Compliance Guardian — AWS Live Audit Report",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "region": region,
            "scan_time": scan_time,
            "scan_summary": scan,
            "health_score": audit.get("health_score", 0),
            "total_checks": audit.get("total_checks", 0),
            "passed": audit.get("passed", 0),
            "failed": audit.get("failed", 0),
            "findings": findings_list,
        }
        content = json.dumps(report, indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=aws-audit-report.json"},
        )

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Status", "Severity", "Rule ID", "Rule Title", "Resource",
            "Resource Type", "Cloud Provider", "Description", "Recommendation"
        ])
        for f in findings_list:
            writer.writerow([
                f.get("status", ""), f.get("severity", ""), f.get("rule_id", ""),
                f.get("rule_title", ""), f.get("resource", f.get("resource_name", "")),
                f.get("resource_type", ""), "AWS",
                f.get("description", ""), f.get("recommendation", ""),
            ])
        content = output.getvalue()
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=aws-audit-report.csv"},
        )

    # PDF
    from .report_generator import generate_aws_pdf_report
    pdf_bytes = generate_aws_pdf_report(_aws_scan_cache)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=aws-audit-report.pdf"},
    )


@app.get("/api/aws/events")
def get_aws_events():
    """Fetch latest CloudTrail events."""
    scanner = AWSScanner()
    conn = scanner.test_connection()
    if not conn.get("connected"):
        raise HTTPException(status_code=401, detail=conn.get("error", "AWS not configured"))

    events = scanner.fetch_cloudtrail_events(max_events=50)
    # Analyze each event
    from .aws_auditor import audit_cloudtrail_event
    analyzed = [audit_cloudtrail_event(e) for e in events if "error" not in e]
    return {"events": analyzed, "total": len(analyzed)}
