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
from pathlib import Path
from typing import Optional, List
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

# ─── Persistence Paths ───────────────────────────────────────────────────────
_DATA_DIR = Path(__file__).parent / ".data"
_DATA_DIR.mkdir(exist_ok=True)
_AWS_CREDS_FILE = _DATA_DIR / "aws_credentials.json"
_AZURE_CREDS_FILE = _DATA_DIR / "azure_credentials.json"
_GCP_CREDS_FILE = _DATA_DIR / "gcp_credentials.json"
_AWS_SCAN_CACHE_FILE = _DATA_DIR / "aws_scan_cache.json"
_AZURE_SCAN_CACHE_FILE = _DATA_DIR / "azure_scan_cache.json"
_GCP_SCAN_CACHE_FILE = _DATA_DIR / "gcp_scan_cache.json"

import logging
logger = logging.getLogger(__name__)

_aws_scan_cache = {}
_azure_scan_cache = None
_gcp_scan_cache = None

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, BackgroundTasks
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
from .aws_auditor import audit_live_resources as audit_aws_resources
from .azure_scanner import AzureScanner
from .azure_auditor import audit_azure_resources
from .gcp_scanner import GCPScanner
from .gcp_auditor import audit_gcp_resources


# ─── WebSocket Broadcast Manager ──────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()


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


@app.get("/api/aws/regions")
def get_aws_regions():
    """Get list of available AWS regions."""
    try:
        scanner = AWSScanner()
        regions = scanner.get_available_regions()
        return {"regions": regions, "primary": scanner.region}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.on_event("startup")
def startup():
    """Initialize the database and restore persisted state on startup."""
    global _aws_scan_cache, _azure_scan_cache, _gcp_scan_cache
    init_db()
    _load_aws_credentials()
    _load_azure_credentials()
    _load_gcp_credentials()
    _aws_scan_cache = _load_scan_cache("aws")
    _azure_scan_cache = _load_scan_cache("azure")
    _gcp_scan_cache = _load_scan_cache("gcp")


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


class AWSScanRequest(BaseModel):
    regions: Optional[List[str]] = ["all"]


class AzureCredentialsRequest(BaseModel):
    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str


class GCPCredentialsRequest(BaseModel):
    project_id: str
    service_account_json: str  # This would normally be the content of the JSON key file


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


def _filter_findings_by_framework(findings_data: list, framework: str) -> list:
    """Filter findings to only those matching the given compliance framework.
    CIS rules have IDs like 'CIS 1.4', 'CIS-AZ 1.1.1', 'CIS-GCP 3.1'.
    NIST rules have IDs like 'NIST AC-2', 'NIST AU-3', etc.
    CCM rules have IDs like 'A&A-01', 'IAM-07', 'TVM-09', etc. (domain-code-number format).
    If framework is 'All', return all findings unchanged.
    """
    if not framework or framework == "All":
        return findings_data
    framework_upper = framework.upper()
    # CCM domain prefixes (17 domains from CSA CCM v4.1)
    CCM_DOMAINS = {"A&A", "AIS", "BCR", "CCC", "CEK", "DCS", "DSP", "GRC", "HRS",
                   "IAM", "IPY", "I&S", "LOG", "SEF", "STA", "TVM", "UEM"}
    filtered = []
    for f in findings_data:
        rule_id = (f.get("rule_id") or f.get("cis_rule_id") or "").upper()
        framework_field = (f.get("framework") or "").upper()
        if framework_field == framework_upper:
            filtered.append(f)
        elif framework_upper == "CIS" and (rule_id.startswith("CIS") or framework_field == "CIS"):
            filtered.append(f)
        elif framework_upper == "NIST" and (rule_id.startswith("NIST") or framework_field == "NIST"):
            filtered.append(f)
        elif framework_upper == "CCM":
            # CCM IDs start with a domain prefix followed by a dash and number
            domain_prefix = rule_id.split("-")[0] if "-" in rule_id else ""
            if framework_field == "CCM" or domain_prefix in CCM_DOMAINS:
                filtered.append(f)
    return filtered


@app.get("/api/audits/{audit_id}/report")
def download_audit_report(
    audit_id: str,
    format: str = Query("pdf", pattern="^(pdf|csv|json)$"),
    framework: str = Query("All", pattern="^(All|CIS|NIST|CCM)$"),
):
    """Download an audit report as PDF, CSV, or JSON, optionally filtered by compliance framework."""
    session = get_session()
    try:
        audit = get_audit_by_id(session, audit_id)
        if not audit:
            raise HTTPException(status_code=404, detail="Audit not found")

        findings = get_findings_by_audit(session, audit.id)
        audit_data = audit.to_dict()
        all_findings_data = [f.to_dict() for f in findings]
        findings_data = _filter_findings_by_framework(all_findings_data, framework)

        fw_suffix = f"-{framework.lower()}" if framework != "All" else ""
        fw_label = f" ({framework} Framework)" if framework != "All" else ""

        if format == "pdf":
            from .report_generator import generate_pdf_report
            pdf_bytes = generate_pdf_report(audit_data, findings_data, framework_label=fw_label, framework=framework)
            return StreamingResponse(
                io.BytesIO(pdf_bytes),
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=audit-report-{audit_id}{fw_suffix}.pdf"},
            )

        if format == "json":
            fw_total = len(findings_data)
            fw_passed = sum(1 for f in findings_data if f.get("status") == "PASS")
            fw_failed = fw_total - fw_passed
            fw_score = round((fw_passed / fw_total) * 100, 1) if fw_total > 0 else 0.0
            report = {
                "report_title": f"Cloud Compliance Guardian — Audit Report{fw_label}",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "framework_filter": framework,
                "audit": audit_data,
                "summary": {
                    "total_checks": fw_total,
                    "passed": fw_passed,
                    "failed": fw_failed,
                    "compliance_score": fw_score,
                },
                "findings": findings_data,
            }
            content = json.dumps(report, indent=2)
            return StreamingResponse(
                io.BytesIO(content.encode()),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=audit-report-{audit_id}{fw_suffix}.json"},
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
            headers={"Content-Disposition": f"attachment; filename=audit-report-{audit_id}{fw_suffix}.csv"},
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


# (aws_scan_cache initialized at module top)


def _save_aws_credentials(access_key: str, secret_key: str, region: str):
    """Persist AWS credentials to disk so they survive server restarts."""
    _AWS_CREDS_FILE.write_text(json.dumps({
        "access_key": access_key,
        "secret_key": secret_key,
        "region": region,
    }))


def _load_aws_credentials():
    """Load persisted AWS credentials on startup."""
    if _AWS_CREDS_FILE.exists():
        try:
            creds = json.loads(_AWS_CREDS_FILE.read_text())
            if creds.get("access_key") and creds.get("secret_key"):
                os.environ["AWS_ACCESS_KEY_ID"] = creds["access_key"]
                os.environ["AWS_SECRET_ACCESS_KEY"] = creds["secret_key"]
                os.environ["AWS_DEFAULT_REGION"] = creds.get("region", "us-east-1")
                return True
        except Exception:
            pass
    return False


def _delete_aws_credentials():
    """Remove persisted AWS credentials from disk."""
    if _AWS_CREDS_FILE.exists():
        _AWS_CREDS_FILE.unlink()
    os.environ.pop("AWS_ACCESS_KEY_ID", None)
    os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
    os.environ.pop("AWS_DEFAULT_REGION", None)

def _save_azure_credentials(creds: dict):
    _AZURE_CREDS_FILE.write_text(json.dumps(creds))

def _load_azure_credentials():
    if _AZURE_CREDS_FILE.exists():
        try:
            creds = json.loads(_AZURE_CREDS_FILE.read_text())
            os.environ["AZURE_TENANT_ID"] = creds.get("tenant_id", "")
            os.environ["AZURE_CLIENT_ID"] = creds.get("client_id", "")
            os.environ["AZURE_CLIENT_SECRET"] = creds.get("client_secret", "")
            os.environ["AZURE_SUBSCRIPTION_ID"] = creds.get("subscription_id", "")
            return True
        except Exception: pass
    return False

def _delete_azure_credentials():
    if _AZURE_CREDS_FILE.exists():
        _AZURE_CREDS_FILE.unlink()
    os.environ.pop("AZURE_TENANT_ID", None)
    os.environ.pop("AZURE_CLIENT_ID", None)
    os.environ.pop("AZURE_CLIENT_SECRET", None)
    os.environ.pop("AZURE_SUBSCRIPTION_ID", None)

def _save_gcp_credentials(creds: dict):
    _GCP_CREDS_FILE.write_text(json.dumps(creds))

def _load_gcp_credentials():
    if _GCP_CREDS_FILE.exists():
        try:
            creds = json.loads(_GCP_CREDS_FILE.read_text())
            os.environ["GOOGLE_CLOUD_PROJECT"] = creds.get("project_id", "")
            # In a real app, you'd handle the service account JSON file path here
            return True
        except Exception: pass
    return False

def _delete_gcp_credentials():
    if _GCP_CREDS_FILE.exists():
        _GCP_CREDS_FILE.unlink()
    os.environ.pop("GOOGLE_CLOUD_PROJECT", None)


def _save_scan_cache(data: dict, provider: str = "aws"):
    """Persist scan results to disk."""
    cache_file = _AWS_SCAN_CACHE_FILE
    if provider == "azure": cache_file = _AZURE_SCAN_CACHE_FILE
    elif provider == "gcp": cache_file = _GCP_SCAN_CACHE_FILE
    
    try:
        cache_file.write_text(json.dumps(data, default=str))
    except Exception:
        pass


def _load_scan_cache(provider: str = "aws") -> dict:
    """Load persisted scan cache on startup."""
    cache_file = _AWS_SCAN_CACHE_FILE
    if provider == "azure": cache_file = _AZURE_SCAN_CACHE_FILE
    elif provider == "gcp": cache_file = _GCP_SCAN_CACHE_FILE
    
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text())
        except Exception:
            pass
    return {}


@app.get("/api/aws/status")
def aws_connection_status():
    """Check if AWS credentials are configured and valid."""
    scanner = AWSScanner()
    result = scanner.test_connection()
    return result


@app.post("/api/aws/configure")
def configure_aws(creds: AWSCredentialsRequest, background_tasks: BackgroundTasks):
    """Save AWS credentials and persist to disk until user disconnects."""
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

    # Persist credentials to disk
    _save_aws_credentials(access_key, secret_key, region)

    return {"status": "connected", **result}


async def background_resource_broadcast():
    """Notify all clients that infrastructure has changed."""
    await manager.broadcast({
        "type": "RESOURCE_UPDATED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": "aws"
    })


    return {"status": "disconnected"}


# ── Azure Endpoints ───────────────────────────────────────────────────────

@app.get("/api/azure/status")
def azure_connection_status():
    if not os.getenv("AZURE_CLIENT_ID"):
        return {"connected": False}
    return {
        "connected": True,
        "tenant_id": os.getenv("AZURE_TENANT_ID", "")[:8] + "...",
        "subscription_id": os.getenv("AZURE_SUBSCRIPTION_ID", "")[:8] + "...",
        "region": "Global (Azure)"
    }

@app.post("/api/azure/configure")
def configure_azure(creds: AzureCredentialsRequest, background_tasks: BackgroundTasks):
    """Save Azure credentials and persist to disk."""
    os.environ["AZURE_TENANT_ID"] = creds.tenant_id.strip()
    os.environ["AZURE_CLIENT_ID"] = creds.client_id.strip()
    os.environ["AZURE_CLIENT_SECRET"] = creds.client_secret.strip()
    os.environ["AZURE_SUBSCRIPTION_ID"] = creds.subscription_id.strip()
    
    scanner = AzureScanner()
    result = scanner.test_connection()
    if not result.get("connected"):
        for var in ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID"]:
            os.environ.pop(var, None)
        return {"status": "error", "message": result.get("error", "Invalid credentials")}

    _save_azure_credentials({
        "tenant_id": creds.tenant_id,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "subscription_id": creds.subscription_id
    })
    
    # Trigger discovery in background
    background_tasks.add_task(run_azure_scan)
    
    return {"status": "connected", **result}

@app.post("/api/azure/disconnect")
def disconnect_azure():
    _delete_azure_credentials()
    return {"status": "disconnected"}


# ── GCP Endpoints ─────────────────────────────────────────────────────────

@app.get("/api/gcp/status")
def gcp_connection_status():
    if not os.getenv("GOOGLE_CLOUD_PROJECT"):
        return {"connected": False}
    return {
        "connected": True,
        "project_id": os.getenv("GOOGLE_CLOUD_PROJECT", ""),
        "user_identity": "Service Account (GCP)"
    }

@app.post("/api/gcp/configure")
def configure_gcp(creds: GCPCredentialsRequest, background_tasks: BackgroundTasks):
    """Save GCP credentials and persist to disk."""
    project_id = creds.project_id.strip()
    service_account_json = creds.service_account_json.strip()

    # Save to a temp file that the scanner can use
    key_path = _DATA_DIR / "gcp_key.json"
    key_path.write_text(service_account_json)
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(key_path)

    scanner = GCPScanner()
    result = scanner.test_connection()
    if not result.get("connected"):
        os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)
        return {"status": "error", "message": result.get("error", "Invalid credentials")}

    _save_gcp_credentials({
        "project_id": project_id,
        "service_account_json": service_account_json
    })
    
    # Trigger discovery in background
    background_tasks.add_task(run_gcp_scan)
    
    return {"status": "connected", **result}

@app.post("/api/gcp/disconnect")
def disconnect_gcp():
    _delete_gcp_credentials()
    return {"status": "disconnected"}


@app.post("/api/aws/scan")
async def run_aws_scan(request: Optional[AWSScanRequest] = None):
    """Run a full AWS live scan and audit across specified regions."""
    global _aws_scan_cache
    scanner = AWSScanner()

    # Determine regions to scan — default to primary region for speed
    regions = (request.regions if request else None) or [scanner.region]

    # Run the scan (synchronous blocking call, but in a thread if called via background_tasks)
    scan_data = scanner.run_full_scan(regions=regions)

    # Run the audit
    audit_results = audit_aws_resources(scan_data)

    # Merge scan summary with audit results
    result = {
        "scan": scan_data["summary"],
        "scan_time": scan_data["scan_time"],
        "regions_scanned": scan_data["regions_scanned"],
        "primary_region": scan_data["primary_region"],
        "resources": scan_data["resources"],
        "audit": audit_results,
    }

    _aws_scan_cache = result
    _save_scan_cache(result, "aws")
    
    # Broadcast to topology view
    await manager.broadcast({
        "type": "RESOURCE_UPDATED",
        "provider": "aws",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return result


@app.post("/api/azure/scan")
async def run_azure_scan():
    """Run a full Azure live scan and audit."""
    global _azure_scan_cache
    scanner = AzureScanner()

    # Test connection
    conn = scanner.test_connection()
    if not conn.get("connected"):
        raise HTTPException(status_code=401, detail=conn.get("error", "Azure not configured"))

    # Run the scan
    scan_data = scanner.run_full_scan()

    # Run the audit
    audit_results = audit_azure_resources(scan_data)

    result = {
        "scan": scan_data["summary"],
        "scan_time": scan_data["scan_time"],
        "subscription_id": scan_data["subscription_id"],
        "resources": scan_data["resources"],
        "audit": audit_results,
    }

    _azure_scan_cache = result
    _save_scan_cache(result, "azure")
    
    await manager.broadcast({
        "type": "RESOURCE_UPDATED",
        "provider": "azure",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return result


@app.get("/api/azure/scan/latest")
def get_latest_azure_scan():
    """Get the most recent Azure scan results from cache."""
    if not _azure_scan_cache:
        return {"cached": False, "message": "No scan results available. Run a scan first."}
    return {"cached": True, **_azure_scan_cache}


@app.post("/api/gcp/scan")
async def run_gcp_scan():
    """Run a full GCP live scan and audit."""
    global _gcp_scan_cache
    scanner = GCPScanner()

    # Test connection
    conn = scanner.test_connection()
    if not conn.get("connected"):
        raise HTTPException(status_code=401, detail=conn.get("error", "GCP not configured"))

    # Run the scan
    scan_data = scanner.run_full_scan()

    # Run the audit
    audit_results = audit_gcp_resources(scan_data)

    result = {
        "scan": scan_data["summary"],
        "scan_time": scan_data["scan_time"],
        "project_id": scan_data["project_id"],
        "resources": scan_data["resources"],
        "audit": audit_results,
    }

    _gcp_scan_cache = result
    _save_scan_cache(result, "gcp")
    
    await manager.broadcast({
        "type": "RESOURCE_UPDATED",
        "provider": "gcp",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return result


@app.get("/api/gcp/scan/latest")
def get_latest_gcp_scan():
    """Get the most recent GCP scan results from cache."""
    if not _gcp_scan_cache:
        return {"cached": False, "message": "No scan results available. Run a scan first."}
    return {"cached": True, **_gcp_scan_cache}


# ─── Topology Endpoints ───────────────────────────────────────────────────────

@app.websocket("/api/ws/topology")
async def topology_websocket(websocket: WebSocket):
    """WebSocket for real-time topology updates."""
    await manager.connect(websocket)
    try:
        # Send initial snapshot if available
        topo = get_topology()
        await websocket.send_json({
            "type": "INITIAL_STATE",
            "data": topo
        })
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/api/topology")
def get_topology():
    """
    Build a force-graph topology from scan cache.
    Returns nodes and edges with relationship data for D3 force simulation.
    """
    try:
        resources = _aws_scan_cache.get("resources", []) if _aws_scan_cache else []
        findings  = _aws_scan_cache.get("audit", {}).get("findings", []) if _aws_scan_cache else []
        scan_meta = _aws_scan_cache.get("scan", {}) if _aws_scan_cache else {}

        failed_ids = {f.get("resource_id") for f in findings if f.get("status") == "FAIL"}

        if not resources:
            return {"nodes": [], "edges": [], "groups": [],
                    "meta": {"total": 0, "compliant": 0, "violations": 0, "scan_time": None}}

        TYPE_META = {
            "aws_iam_user":        {"label": "IAM Users",        "color": "#a78bfa", "group": "Identity"},
            "aws_iam_policy":      {"label": "IAM Policies",     "color": "#7c3aed", "group": "Identity"},
            "aws_s3_bucket":       {"label": "S3 Buckets",       "color": "#60a5fa", "group": "Storage"},
            "aws_ec2_instance":    {"label": "EC2 Instances",    "color": "#34d399", "group": "Compute"},
            "aws_security_group":  {"label": "Security Groups",  "color": "#f59e0b", "group": "Network"},
            "aws_vpc":             {"label": "VPCs",             "color": "#22d3ee", "group": "Network"},
            "aws_rds_instance":    {"label": "RDS Instances",    "color": "#fb923c", "group": "Database"},
            "aws_lambda_function": {"label": "Lambda Functions", "color": "#e879f9", "group": "Compute"},
            "aws_ec2_subnet":      {"label": "Subnets",          "color": "#6ee7b7", "group": "Network"},
            "aws_ec2_internet-gateway": {"label": "IGWs",        "color": "#38bdf8", "group": "Network"},
            "aws_secretsmanager_secret": {"label": "Secrets",    "color": "#f87171", "group": "Security"},
        }

        # Build resource id → node index map
        res_by_id = {r.get("resource_id"): r for r in resources if r.get("resource_id")}

        nodes = []
        edges = []
        edge_set = set()
        total_compliant = 0
        total_violations = 0
        type_counts = {}

        for res in resources:
            rid   = res.get("resource_id")
            rtype = res.get("resource_type", "aws_unknown")
            if not rid:
                continue

            is_fail = rid in failed_ids
            if is_fail:
                total_violations += 1
            else:
                total_compliant += 1

            type_counts[rtype] = type_counts.get(rtype, 0) + 1
            meta = TYPE_META.get(rtype, {"label": rtype.replace("aws_","").replace("_"," ").title(), "color": "#94a3b8", "group": "Other"})

            nodes.append({
                "id":      rid,
                "label":   res.get("resource_name") or rid,
                "type":    rtype,
                "group":   meta["group"],
                "color":   meta["color"],
                "status":  "fail" if is_fail else "pass",
                "region":  res.get("region", "global"),
                "config":  res.get("config", {}),
            })

        # ── Build edges from config relationships ─────────────────────────────
        vpc_id_to_rid   = {}
        sg_id_to_rid    = {}
        subnet_id_to_rid = {}

        for res in resources:
            rid   = res.get("resource_id")
            rtype = res.get("resource_type", "")
            cfg   = res.get("config", {})
            if not rid:
                continue
            if rtype == "aws_vpc":
                # store original vpc_id from config
                pass
            if rtype == "aws_security_group":
                pass
            if rtype == "aws_ec2_subnet":
                pass

        # EC2 → Security Group edges
        for res in resources:
            rid   = res.get("resource_id")
            rtype = res.get("resource_type", "")
            cfg   = res.get("config", {})
            if not rid:
                continue

            # EC2 instances linked to security groups by resource_id hash matching
            if rtype == "aws_ec2_instance":
                for sg in cfg.get("security_groups", []):
                    # find sg node by matching hashed id
                    from .aws_scanner import AWSScanner
                    hashed = AWSScanner._hash_id(sg)
                    if hashed in res_by_id:
                        ek = f"{rid}:{hashed}"
                        if ek not in edge_set:
                            edge_set.add(ek)
                            edges.append({"source": rid, "target": hashed, "type": "uses_sg"})

        # IAM Policy → IAM User edges (policies attached to users)
        # Link by attachment_count heuristic — connect policies to first N users
        iam_users   = [r for r in resources if r.get("resource_type") == "aws_iam_user"]
        iam_policies = [r for r in resources if r.get("resource_type") == "aws_iam_policy"]
        for pol in iam_policies:
            pid = pol.get("resource_id")
            cnt = pol.get("config", {}).get("attachment_count", 0)
            if cnt and pid:
                for user in iam_users[:min(cnt, 3)]:
                    uid = user.get("resource_id")
                    ek  = f"{pid}:{uid}"
                    if uid and ek not in edge_set:
                        edge_set.add(ek)
                        edges.append({"source": pid, "target": uid, "type": "attached_to"})

        # VPC → Subnet edges (same region cluster)
        vpcs    = [r for r in resources if r.get("resource_type") == "aws_vpc"]
        subnets = [r for r in resources if r.get("resource_type") == "aws_ec2_subnet"]
        for vpc in vpcs:
            vid = vpc.get("resource_id")
            vregion = vpc.get("region")
            if not vid:
                continue
            for sub in subnets:
                sid = sub.get("resource_id")
                if sid and sub.get("region") == vregion:
                    ek = f"{vid}:{sid}"
                    if ek not in edge_set:
                        edge_set.add(ek)
                        edges.append({"source": vid, "target": sid, "type": "contains"})

        # Build groups summary
        groups = []
        group_map = {}
        for rtype, meta in TYPE_META.items():
            g = meta["group"]
            if g not in group_map:
                group_map[g] = {"name": g, "types": [], "count": 0, "violations": 0}
            group_map[g]["types"].append(rtype)
        for res in resources:
            rtype = res.get("resource_type", "")
            rid   = res.get("resource_id")
            meta  = TYPE_META.get(rtype, {"group": "Other"})
            g     = meta["group"]
            if g not in group_map:
                group_map[g] = {"name": g, "types": [], "count": 0, "violations": 0}
            group_map[g]["count"] += 1
            if rid in failed_ids:
                group_map[g]["violations"] += 1
        groups = list(group_map.values())

        return {
            "nodes": nodes,
            "edges": edges,
            "groups": groups,
            "type_counts": type_counts,
            "meta": {
                "total":      len(nodes),
                "compliant":  total_compliant,
                "violations": total_violations,
                "regions":    scan_meta.get("regions_scanned", []),
                "scan_time":  _aws_scan_cache.get("scan_time") if _aws_scan_cache else None,
            }
        }
    except Exception as e:
        logger.error(f"Failed to generate topology: {e}", exc_info=True)
        return {"nodes": [], "edges": [], "groups": [], "error": str(e), "meta": {}}


@app.get("/api/aws/scan/latest")
def get_latest_aws_scan():
    """Get the most recent AWS scan results from cache."""
    if not _aws_scan_cache:
        return {"cached": False, "message": "No scan results available. Run a scan first."}
    return {"cached": True, **_aws_scan_cache}


@app.get("/api/aws/scan/report")
def download_aws_report(
    format: str = Query("pdf", pattern="^(pdf|csv|json)$"),
    framework: str = Query("All", pattern="^(All|CIS|NIST|CCM)$"),
):
    """Download the latest AWS live scan report, optionally filtered by compliance framework."""
    if not _aws_scan_cache:
        raise HTTPException(status_code=404, detail="No scan results. Run a scan first.")

    audit = _aws_scan_cache.get("audit", {})
    scan = _aws_scan_cache.get("scan", {})
    all_findings = audit.get("findings", [])
    findings_list = _filter_findings_by_framework(all_findings, framework)
    region = _aws_scan_cache.get("region", "unknown")
    scan_time = _aws_scan_cache.get("scan_time", "")

    fw_suffix = f"-{framework.lower()}" if framework != "All" else ""
    fw_label = f" ({framework} Framework)" if framework != "All" else ""

    if format == "json":
        report = {
            "report_title": f"Cloud Compliance Guardian — AWS Live Audit Report{fw_label}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "framework_filter": framework,
            "region": region,
            "scan_time": scan_time,
            "scan_summary": scan,
            "health_score": audit.get("health_score", 0),
            "total_checks": len(findings_list),
            "passed": sum(1 for f in findings_list if f.get("status") == "PASS"),
            "failed": sum(1 for f in findings_list if f.get("status") == "FAIL"),
            "findings": findings_list,
        }
        content = json.dumps(report, indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=aws-audit-report{fw_suffix}.json"},
        )

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Status", "Severity", "Rule ID", "Title", "Resource",
            "Resource Type", "Cloud Provider", "Framework", "Description", "Reasoning",
            "Expected", "Actual", "Recommendation", "Remediation"
        ])
        for f in findings_list:
            writer.writerow([
                f.get("status", ""), f.get("severity", ""),
                f.get("cis_rule_id", f.get("rule_id", "")),
                f.get("title", f.get("rule_title", "")),
                f.get("resource_name", f.get("resource", "")),
                f.get("resource_type", ""), "AWS",
                f.get("framework", "CIS"),
                f.get("description", ""), f.get("reasoning", ""),
                f.get("expected", ""), f.get("actual", ""),
                f.get("recommendation", ""), f.get("remediation_step", ""),
            ])
        content = output.getvalue()
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=aws-audit-report{fw_suffix}.csv"},
        )

    # PDF
    from .report_generator import generate_aws_pdf_report
    cache_filtered = {**_aws_scan_cache, "audit": {**audit, "findings": findings_list}, "framework_label": fw_label, "framework": framework}
    pdf_bytes = generate_aws_pdf_report(cache_filtered)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=aws-audit-report{fw_suffix}.pdf"},
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
