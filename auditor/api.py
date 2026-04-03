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
_CONTAINER_SCAN_CACHE_FILE = _DATA_DIR / "container_scan_cache.json"

import logging
logger = logging.getLogger(__name__)

_aws_scan_cache = {}
_azure_scan_cache = None
_gcp_scan_cache = None
_container_scan_cache = {}

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
try:
    from .container_auditor import ContainerAuditor
except ImportError:
    ContainerAuditor = None
try:
    from .nist_auditor import audit_aws_resources_nist
except ImportError:
    audit_aws_resources_nist = None
try:
    from .ccm_auditor import audit_aws_resources_ccm
except ImportError:
    audit_aws_resources_ccm = None


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
    global _aws_scan_cache, _azure_scan_cache, _gcp_scan_cache, _container_scan_cache
    init_db()
    _load_aws_credentials()
    _load_azure_credentials()
    _load_gcp_credentials()
    _aws_scan_cache = _load_scan_cache("aws")
    _azure_scan_cache = _load_scan_cache("azure")
    _gcp_scan_cache = _load_scan_cache("gcp")
    _container_scan_cache = _load_scan_cache("container")


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
    framework: Optional[str] = "All"  # All | CIS | NIST | CCM


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
    """
    For NIST and CCM: translate ALL findings to the target framework using the
    control mapping table — so every finding gets the correct control ID, title,
    description and recommendation for the selected framework.

    For CIS: return only findings originally tagged as CIS.
    For All: return all findings unchanged.
    """
    from .framework_mapping import translate_findings_to_framework

    if not framework or framework == "All":
        return findings_data

    if framework in ("NIST", "CCM"):
        # Translate every finding to the selected framework
        return translate_findings_to_framework(findings_data, framework)

    # CIS: only return findings originally generated as CIS checks
    framework_upper = framework.upper()
    filtered = []
    for f in findings_data:
        rule_id = (f.get("rule_id") or f.get("cis_rule_id") or "").upper()
        framework_field = (f.get("framework") or "").upper()
        if framework_field == framework_upper:
            filtered.append(f)
        elif rule_id.startswith("CIS") or framework_field == "CIS":
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
    elif provider == "container": cache_file = _CONTAINER_SCAN_CACHE_FILE

    try:
        cache_file.write_text(json.dumps(data, default=str))
    except Exception:
        pass


def _load_scan_cache(provider: str = "aws") -> dict:
    """Load persisted scan cache on startup."""
    cache_file = _AWS_SCAN_CACHE_FILE
    if provider == "azure": cache_file = _AZURE_SCAN_CACHE_FILE
    elif provider == "gcp": cache_file = _GCP_SCAN_CACHE_FILE
    elif provider == "container": cache_file = _CONTAINER_SCAN_CACHE_FILE

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


@app.post("/api/aws/disconnect")
def disconnect_aws():
    """Remove AWS credentials and clear scan cache."""
    global _aws_scan_cache
    _delete_aws_credentials()
    _aws_scan_cache = {}
    # Also clear the persisted scan cache file
    if _AWS_SCAN_CACHE_FILE.exists():
        _AWS_SCAN_CACHE_FILE.unlink()
    return {"status": "disconnected"}


async def background_resource_broadcast():
    """Notify all clients that infrastructure has changed."""
    await manager.broadcast({
        "type": "RESOURCE_UPDATED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": "aws"
    })


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
    global _azure_scan_cache
    _delete_azure_credentials()
    _azure_scan_cache = None
    if _AZURE_SCAN_CACHE_FILE.exists():
        _AZURE_SCAN_CACHE_FILE.unlink()
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
    global _gcp_scan_cache
    _delete_gcp_credentials()
    _gcp_scan_cache = None
    if _GCP_SCAN_CACHE_FILE.exists():
        _GCP_SCAN_CACHE_FILE.unlink()
    return {"status": "disconnected"}


@app.post("/api/aws/scan")
async def run_aws_scan(request: Optional[AWSScanRequest] = None):
    """Run a full AWS live scan and audit across specified regions."""
    global _aws_scan_cache
    scanner = AWSScanner()

    # Determine regions to scan — default to ALL opted-in regions in the account
    regions = (request.regions if request else None) or scanner.get_available_regions() or [scanner.region]
    framework = (request.framework if request else None) or "All"

    # Run the scan (synchronous blocking call, but in a thread if called via background_tasks)
    scan_data = scanner.run_full_scan(regions=regions)

    # Run the correct auditor based on selected framework
    if framework == "NIST" and audit_aws_resources_nist is not None:
        audit_results = audit_aws_resources_nist(scan_data)
    elif framework == "CCM" and audit_aws_resources_ccm is not None:
        audit_results = audit_aws_resources_ccm(scan_data)
    else:
        # CIS or All — run CIS auditor (default)
        audit_results = audit_aws_resources(scan_data)

    # Merge scan summary with audit results
    result = {
        "scan": scan_data["summary"],
        "scan_time": scan_data["scan_time"],
        "regions_scanned": scan_data["regions_scanned"],
        "primary_region": scan_data["primary_region"],
        "resources": scan_data["resources"],
        "audit": audit_results,
        "framework": framework,
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


# ─── Container (Docker / Kubernetes) Endpoints ───────────────────────────────

@app.post("/api/container/scan")
async def run_container_scan():
    """Run a full Docker and Kubernetes security scan using CIS Benchmarks."""
    global _container_scan_cache

    if ContainerAuditor is None:
        raise HTTPException(status_code=500, detail="ContainerAuditor module is not available.")

    auditor = ContainerAuditor()
    result = auditor.run_full_scan()

    _container_scan_cache = result
    _save_scan_cache(result, "container")

    await manager.broadcast({
        "type": "RESOURCE_UPDATED",
        "provider": "container",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    return result


@app.get("/api/container/scan/latest")
def get_latest_container_scan():
    """Get the most recent Container scan results from cache."""
    if not _container_scan_cache:
        return {"cached": False, "message": "No container scan results available. Run a scan first."}
    return {"cached": True, **_container_scan_cache}


@app.get("/api/container/scan/report")
def download_container_report(
    format: str = Query("pdf", pattern="^(pdf|csv|json)$"),
    framework: str = Query("All", pattern="^(All|CIS|NIST|CCM)$"),
):
    """Download the latest Container scan report as PDF, CSV, or JSON."""
    if not _container_scan_cache:
        raise HTTPException(status_code=404, detail="No container scan results. Run a scan first.")

    audit_data = _container_scan_cache.get("audit", {})
    all_findings = audit_data.get("findings", [])

    # Container reports always use CIS framework; NIST/CCM fall back to all findings
    if framework == "CIS":
        findings_list = [f for f in all_findings if str(f.get("framework", "CIS")).upper() == "CIS"]
    elif framework in ("NIST", "CCM"):
        # Container checks are CIS-based; for NIST/CCM return all findings with framework label
        findings_list = all_findings
    else:
        findings_list = all_findings

    scan_time = _container_scan_cache.get("scan_time", "")
    fw_suffix = f"-{framework.lower()}" if framework != "All" else ""
    fw_label = f" ({framework} Framework)" if framework != "All" else ""

    scan_meta = {
        "scan_time": scan_time,
        "docker_available": _container_scan_cache.get("docker_available", False),
        "k8s_available": _container_scan_cache.get("k8s_available", False),
        "total_resources": _container_scan_cache.get("scan", {}).get("total_resources", 0),
        "framework": framework,
    }

    if format == "json":
        total = len(findings_list)
        passed = sum(1 for f in findings_list if f.get("status") == "PASS")
        failed = total - passed
        score = round((passed / total) * 100, 1) if total > 0 else 0.0
        report = {
            "report_title": f"Cloud Compliance Guardian — Container Security Audit{fw_label}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "framework_filter": framework,
            "scan_summary": scan_meta,
            "health_score": audit_data.get("health_score", 0),
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "compliance_score": score,
            "findings": findings_list,
        }
        content = json.dumps(report, indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=container-audit-report{fw_suffix}.json"},
        )

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Status", "Severity", "Rule ID", "Title", "Resource",
            "Resource Type", "Framework", "Description", "Reasoning",
            "Expected", "Actual", "Recommendation", "Remediation",
        ])
        for f in findings_list:
            writer.writerow([
                f.get("status", ""), f.get("severity", ""),
                f.get("rule_id", f.get("cis_rule_id", "")),
                f.get("title", ""),
                f.get("resource_name", ""),
                f.get("resource_type", ""), f.get("framework", "CIS"),
                f.get("description", ""), f.get("reasoning", ""),
                f.get("expected", ""), f.get("actual", ""),
                f.get("recommendation", ""), f.get("remediation_step", ""),
            ])
        content = output.getvalue()
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=container-audit-report{fw_suffix}.csv"},
        )

    # PDF — build a compatible scan cache dict for the existing PDF generator
    from .report_generator import generate_aws_pdf_report
    pdf_cache = {
        "scan": scan_meta,
        "scan_time": scan_time,
        "regions_scanned": ["local"],
        "primary_region": "local",
        "resources": _container_scan_cache.get("resources", []),
        "audit": {**audit_data, "findings": findings_list},
        "framework_label": fw_label,
        "framework": framework,
    }
    pdf_bytes = generate_aws_pdf_report(pdf_cache)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=container-audit-report{fw_suffix}.pdf"},
    )


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
    Build an audit-grade topology:
      Org layer → Account → Regions → VPCs → Subnets → Resources
      Attribution layer (CloudTrail events → IAM identities)
      Compliance layer (per-resource pass/fail + severity)
      Evidence layer (type-grouped inventory with counts)
    """
    try:
        resources = _aws_scan_cache.get("resources", []) if _aws_scan_cache else []
        findings  = _aws_scan_cache.get("audit", {}).get("findings", []) if _aws_scan_cache else []
        scan_meta = _aws_scan_cache.get("scan", {}) if _aws_scan_cache else {}
        events    = _aws_scan_cache.get("events", [])[:50] if _aws_scan_cache else []

        failed_ids = {f.get("resource_id") for f in findings if f.get("status") == "FAIL"}

        if not resources:
            return {
                "org_layer": {}, "regions": [], "attribution": [], "evidence": {},
                "type_counts": {}, "meta": {"total": 0, "compliant": 0, "violations": 0, "scan_time": None}
            }

        from .aws_scanner import AWSScanner

        # ── Index by type and id ──────────────────────────────────────────────
        by_type   = {}
        res_by_id = {}
        for r in resources:
            rid   = r.get("resource_id")
            rtype = r.get("resource_type", "")
            if not rid:
                continue
            res_by_id[rid] = r
            by_type.setdefault(rtype, []).append(r)

        # ── Compliance index ──────────────────────────────────────────────────
        # findings keyed by resource_id → list of findings
        findings_by_rid = {}
        for f in findings:
            rid = f.get("resource_id")
            if rid:
                findings_by_rid.setdefault(rid, []).append(f)

        failed_ids = {rid for rid, fs in findings_by_rid.items()
                      if any(f.get("status") == "FAIL" for f in fs)}

        def compliance_summary(rid):
            fs = findings_by_rid.get(rid, [])
            total_f  = len(fs)
            failed_f = sum(1 for f in fs if f.get("status") == "FAIL")
            critical = sum(1 for f in fs if f.get("status") == "FAIL" and f.get("severity") in ("CRITICAL", "HIGH"))
            return {
                "status":    "fail" if failed_f > 0 else ("pass" if total_f > 0 else "unknown"),
                "total":     total_f,
                "failed":    failed_f,
                "critical":  critical,
                "findings":  [{"rule_id": f.get("rule_id",""), "title": f.get("rule_title",""),
                               "severity": f.get("severity",""), "status": f.get("status","")}
                              for f in fs[:5]],
            }

        def make_node(r):
            rid = r.get("resource_id", "")
            return {
                "id":         rid,
                "label":      r.get("resource_name") or rid,
                "type":       r.get("resource_type", ""),
                "region":     r.get("region", "global"),
                "config":     r.get("config", {}),
                "compliance": compliance_summary(rid),
            }

        # ── Stats ────────────────────────────────────────────────────────────
        total      = len(res_by_id)
        violations = len(failed_ids)
        compliant  = total - violations

        type_counts = {}
        for r in resources:
            rt = r.get("resource_type", "")
            if "error" not in r:
                type_counts[rt] = type_counts.get(rt, 0) + 1

        # ── 1. ORG LAYER — account + scope metadata ───────────────────────────
        scan_time    = _aws_scan_cache.get("scan_time", "") if _aws_scan_cache else ""
        regions_list = scan_meta.get("regions_scanned", [])
        account_id   = scan_meta.get("account_id", "")
        primary_reg  = scan_meta.get("primary_region") or (regions_list[0] if regions_list else "us-east-1")

        # compliance posture
        score = round((compliant / total) * 100) if total > 0 else 0
        if score >= 80:
            posture = "COMPLIANT"
        elif score >= 60:
            posture = "PARTIAL"
        else:
            posture = "NON-COMPLIANT"

        org_layer = {
            "account_id":    account_id,
            "primary_region": primary_reg,
            "regions_active": len(regions_list),
            "regions":        regions_list,
            "scan_time":      scan_time,
            "posture":        posture,
            "score":          score,
            "total_resources": total,
            "compliant":      compliant,
            "violations":     violations,
            # CloudTrail coverage
            "cloudtrail_enabled": len(by_type.get("aws_cloudtrail", [])) > 0,
            "cloudtrail_count":   len(by_type.get("aws_cloudtrail", [])),
            # Config coverage (check for non-compliant resources)
            "config_rules_checked": len(findings),
        }

        # ── 2. REGIONS — per-region resource breakdown ────────────────────────
        region_map = {}
        for r in resources:
            if "error" in r:
                continue
            reg   = r.get("region", "global")
            rtype = r.get("resource_type", "")
            rid   = r.get("resource_id", "")
            if reg not in region_map:
                region_map[reg] = {
                    "name": reg,
                    "resources": [],
                    "vpcs": [],
                    "total": 0, "violations": 0,
                    "cloudtrail": False,
                }
            region_map[reg]["total"] += 1
            if rid in failed_ids:
                region_map[reg]["violations"] += 1
            if rtype == "aws_cloudtrail":
                region_map[reg]["cloudtrail"] = True

        # Build VPC zones inside each region
        vpcs    = by_type.get("aws_vpc", [])
        subnets = by_type.get("aws_subnet", [])
        igws    = by_type.get("aws_internet_gateway", [])

        subnets_by_vpc = {}
        for sub in subnets:
            hv = sub.get("config", {}).get("vpc_id", "")
            if hv:
                subnets_by_vpc.setdefault(hv, []).append(sub)

        igws_by_vpc = {}
        for igw in igws:
            for hv in igw.get("config", {}).get("attached_vpc_ids", []):
                if hv:
                    igws_by_vpc.setdefault(hv, []).append(igw)

        compute_types = ("aws_ec2_instance", "aws_lambda_function", "aws_ecs_cluster",
                         "aws_lb", "aws_elb", "aws_eks_cluster", "aws_elasticache_cluster")
        compute_by_subnet = {}
        compute_by_vpc    = {}
        for rtype in compute_types:
            for r in by_type.get(rtype, []):
                cfg = r.get("config", {})
                hs  = cfg.get("subnet_id", "")
                hv  = cfg.get("vpc_id", "")
                if hs:
                    compute_by_subnet.setdefault(hs, []).append(r)
                elif hv:
                    compute_by_vpc.setdefault(hv, []).append(r)

        sgs_by_vpc = {}
        for sg in by_type.get("aws_security_group", []):
            hv = sg.get("config", {}).get("vpc_id", "")
            if hv:
                sgs_by_vpc.setdefault(hv, []).append(sg)

        for vpc in vpcs:
            vid     = vpc["resource_id"]
            cfg     = vpc.get("config", {})
            reg     = vpc.get("region", "global")

            vpc_subnets = subnets_by_vpc.get(vid, [])
            subnet_nodes = []
            for sub in vpc_subnets:
                sid     = sub["resource_id"]
                sub_cfg = sub.get("config", {})
                is_pub  = sub_cfg.get("public_subnet", False)
                sub_resources = [make_node(r) for r in compute_by_subnet.get(sid, [])]
                subnet_nodes.append({
                    **make_node(sub),
                    "is_public": is_pub,
                    "resources": sub_resources,
                    "az": sub_cfg.get("availability_zone", ""),
                })

            igw_list = list({n["id"]: n for n in [make_node(ig) for ig in igws_by_vpc.get(vid, [])]}.values())

            vpc_node = {
                **make_node(vpc),
                "cidr":       cfg.get("cidr_block", ""),
                "is_default": cfg.get("is_default", False),
                "subnets":    subnet_nodes,
                "unplaced":   [make_node(r) for r in compute_by_vpc.get(vid, [])],
                "sgs":        [make_node(sg) for sg in sgs_by_vpc.get(vid, [])],
                "igws":       igw_list,
                "internet_exposed": len(igw_list) > 0,
            }

            if reg not in region_map:
                region_map[reg] = {"name": reg, "resources": [], "vpcs": [],
                                   "total": 0, "violations": 0, "cloudtrail": False}
            region_map[reg]["vpcs"].append(vpc_node)

        # Attach non-VPC regional resources to each region
        non_vpc_types = (
            "aws_rds_instance", "aws_rds_cluster", "aws_dynamodb_table",
            "aws_elasticache_cluster", "aws_sqs_queue", "aws_sns_topic",
            "aws_lambda_function", "aws_acm_certificate", "aws_ecr_repository",
            "aws_eks_cluster", "aws_cloudtrail", "aws_cloudwatch_alarm",
            "aws_kms_key", "aws_secretsmanager_secret", "aws_ebs_volume",
            "aws_api_gateway_rest_api", "aws_apigatewayv2_api",
            "aws_sfn_state_machine", "aws_elastic_beanstalk_environment",
            "aws_wafv2_web_acl", "aws_opensearch_domain", "aws_msk_cluster",
            "aws_lb", "aws_elb", "aws_eip",
        )
        for rtype in non_vpc_types:
            for r in by_type.get(rtype, []):
                reg = r.get("region", "global")
                if reg not in region_map:
                    region_map[reg] = {"name": reg, "resources": [], "vpcs": [],
                                       "total": 0, "violations": 0, "cloudtrail": False}
                region_map[reg]["resources"].append(make_node(r))

        regions_out = sorted(region_map.values(), key=lambda x: x["name"])

        # ── 3. ATTRIBUTION LAYER — CloudTrail events ──────────────────────────
        attribution = []
        for ev in events[:30]:
            if "error" in ev:
                continue
            attribution.append({
                "event_name":  ev.get("event_name", ""),
                "event_source": ev.get("event_source", ""),
                "username":    ev.get("username", "unknown"),
                "event_time":  ev.get("event_time", ""),
                "region":      ev.get("region", ""),
                "source_ip":   ev.get("source_ip", ""),
                "is_suspicious": ev.get("is_suspicious", False),
                "error_code":  ev.get("error_code", ""),
            })

        # ── 4. EVIDENCE LAYER — grouped inventory for auditors ────────────────
        SERVICE_GROUPS = {
            "Identity & Access": ["aws_iam_user", "aws_iam_role", "aws_iam_policy"],
            "Compute":           ["aws_ec2_instance", "aws_lambda_function", "aws_ecs_cluster",
                                  "aws_eks_cluster", "aws_elastic_beanstalk_environment"],
            "Network":           ["aws_vpc", "aws_subnet", "aws_security_group",
                                  "aws_internet_gateway", "aws_nat_gateway", "aws_route_table",
                                  "aws_eip", "aws_lb", "aws_elb", "aws_wafv2_web_acl"],
            "Storage & Data":    ["aws_s3_bucket", "aws_ebs_volume", "aws_dynamodb_table",
                                  "aws_rds_instance", "aws_rds_cluster", "aws_elasticache_cluster",
                                  "aws_opensearch_domain", "aws_msk_cluster"],
            "Security":          ["aws_kms_key", "aws_secretsmanager_secret", "aws_acm_certificate",
                                  "aws_cloudtrail", "aws_cloudwatch_alarm"],
            "Delivery & Integration": ["aws_sns_topic", "aws_sqs_queue", "aws_api_gateway_rest_api",
                                       "aws_apigatewayv2_api", "aws_sfn_state_machine",
                                       "aws_cloudfront_distribution", "aws_ecr_repository"],
        }

        evidence = {}
        for group, rtypes in SERVICE_GROUPS.items():
            group_nodes = []
            group_violations = 0
            for rtype in rtypes:
                for r in by_type.get(rtype, []):
                    if "error" in r:
                        continue
                    node = make_node(r)
                    group_nodes.append(node)
                    if node["compliance"]["status"] == "fail":
                        group_violations += 1
            if group_nodes:
                evidence[group] = {
                    "resources":  group_nodes,
                    "count":      len(group_nodes),
                    "violations": group_violations,
                }

        # Global resources (IAM, CloudFront) not tied to a region
        global_resources = []
        for rtype in ("aws_iam_user", "aws_iam_role", "aws_iam_policy",
                       "aws_s3_bucket", "aws_cloudfront_distribution"):
            for r in by_type.get(rtype, []):
                if "error" not in r:
                    global_resources.append(make_node(r))

        return {
            "org_layer":        org_layer,
            "regions":          regions_out,
            "global_resources": global_resources,
            "attribution":      attribution,
            "evidence":         evidence,
            "type_counts":      type_counts,
            "meta": {
                "total":      total,
                "compliant":  compliant,
                "violations": violations,
                "score":      score,
                "posture":    posture,
                "regions":    regions_list,
                "scan_time":  scan_time,
            }
        }
    except Exception as e:
        logger.error(f"Failed to generate topology: {e}", exc_info=True)
        return {"org_layer": {}, "regions": [], "global_resources": [], "attribution": [],
                "evidence": {}, "type_counts": {}, "error": str(e), "meta": {}}


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
    region = _aws_scan_cache.get("region", "unknown")
    scan_time = _aws_scan_cache.get("scan_time", "")

    # Use scan framework from cache if no override is requested
    cached_framework = _aws_scan_cache.get("framework", "All")
    # If the requested framework matches what was scanned (or All), use cached findings directly
    if framework == "All" or framework == cached_framework:
        findings_list = all_findings
        framework = cached_framework  # use actual scan framework for labels
    elif framework == "NIST" and audit_aws_resources_nist is not None:
        nist_result = audit_aws_resources_nist({"resources": _aws_scan_cache.get("resources", [])})
        findings_list = nist_result["findings"]
    elif framework == "CCM" and audit_aws_resources_ccm is not None:
        ccm_result = audit_aws_resources_ccm({"resources": _aws_scan_cache.get("resources", [])})
        findings_list = ccm_result["findings"]
    elif framework == "CIS":
        findings_list = [f for f in all_findings if not str(f.get("cis_rule_id", "")).startswith("NIST")]
    else:
        findings_list = _filter_findings_by_framework(all_findings, framework)

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
