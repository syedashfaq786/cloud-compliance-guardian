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
import re
import threading
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any
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

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, BackgroundTasks, UploadFile, File, Form
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
    save_audit,
    upsert_cloud_scan_audit,
)
from .audit import run_audit
from .github import clone_repo, get_repo_metadata, sync_and_scan, get_repo_name_from_url
from .aws_scanner import AWSScanner
from .aws_auditor import audit_live_resources as audit_aws_resources
from .azure_scanner import AzureScanner
from .azure_auditor import audit_azure_resources
from .gcp_scanner import GCPScanner
from .gcp_auditor import audit_gcp_resources
from .topology import get_topology_builder
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

from .scoring import calculate_compliance_score, get_issue_count, get_severity_summary


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
    title="Invecto Compliance Guard API",
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
    framework: Optional[str] = "CIS"  # CIS | NIST | CCM


class ScanResponse(BaseModel):
    audit_id: str
    compliance_score: float
    total_findings: int
    severity_counts: dict
    status: str


class GitHubConnectRequest(BaseModel):
    url: str
    terraform_framework: Optional[str] = "CIS"  # CIS | NIST | CCM
    container_framework: Optional[str] = "CIS"  # CIS | NIST
    scan_containers: Optional[bool] = True


class GitHubSyncRequest(BaseModel):
    terraform_framework: Optional[str] = "CIS"  # CIS | NIST | CCM
    container_framework: Optional[str] = "CIS"  # CIS | NIST
    scan_containers: Optional[bool] = True


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
    """
    Get overall compliance summary.
    Prefers live scan caches (same source as Monitoring/Topology) so all tabs
    show the same numbers. Falls back to DB aggregate when no scan has run yet.
    """
    # ── Try live caches first (AWS → Azure → GCP → Container) ────────────────
    for cache in (_aws_scan_cache, _azure_scan_cache, _gcp_scan_cache, _container_scan_cache):
        if not cache:
            continue
        audit = cache.get("audit") or {}
        findings = audit.get("findings") or []
        scan = cache.get("scan") or {}

        total_resources = scan.get("total_resources") or len(cache.get("resources") or [])
        fail_findings = [f for f in findings if str(f.get("status", "")).upper() in ("FAIL", "WARN")]
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in fail_findings:
            s = str(f.get("severity") or "low").lower()
            if s in sev:
                sev[s] += 1

        # Get total audit count from DB for the counter card
        db_session = get_session()
        try:
            db_summary = get_compliance_summary(db_session)
        finally:
            db_session.close()

        return {
            "compliance_score": round(audit.get("health_score") or 0, 1),
            "total_audits": db_summary.get("total_audits", 0),
            "total_findings": len(fail_findings),
            "resources_scanned": total_resources,
            "severity_breakdown": sev,
        }

    # ── Fallback: DB aggregate ────────────────────────────────────────────────
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
            framework=(request.framework or "CIS"),
            triggered_by="api",
        )
        return ScanResponse(
            audit_id=report.audit_id,
            compliance_score=report.compliance_score,
            total_findings=report.total_findings,
            severity_counts=report.severity_counts,
            status=report.status,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _build_static_container_finding(
    *,
    rule_id: str,
    rule_title: str,
    description: str,
    severity: str,
    status: str,
    expected: str,
    actual: str,
    recommendation: str,
    reasoning: str,
    framework: str,
    target: str,
    file_path: str,
) -> Dict[str, Any]:
    provider = "Docker" if target == "docker" else "Kubernetes"
    resource_type = "docker_file" if target == "docker" else "kubernetes_manifest"
    resource_address = file_path or f"{target}-upload"
    return {
        "rule_id": rule_id,
        "rule_title": rule_title,
        "description": description,
        "severity": severity,
        "status": status,
        "framework": framework,
        "resource_type": resource_type,
        "resource_address": resource_address,
        "file_path": file_path,
        "reasoning": reasoning,
        "recommendation": recommendation,
        "expected": expected,
        "actual": actual,
        "cloud_provider": provider,
    }


def _severity_counts_from_findings(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        status = str(finding.get("status", "")).upper()
        if status not in {"FAIL", "WARN"}:
            continue
        sev = str(finding.get("severity", "LOW")).upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def _run_static_container_file_scan(directory: str, target: str, framework: str) -> Dict[str, Any]:
    root = Path(directory)
    target_norm = (target or "docker").strip().lower()
    framework_norm = (framework or "CIS").strip().upper()
    scan_time = datetime.now(timezone.utc).isoformat()

    file_entries: List[Dict[str, str]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        text = _safe_read_text(path)
        file_entries.append({"rel": rel, "name": path.name, "suffix": path.suffix.lower(), "text": text})

    if target_norm == "docker":
        docker_entries = []
        compose_entries = []
        for entry in file_entries:
            name_lower = entry["name"].lower()
            if (
                name_lower == "dockerfile"
                or name_lower.endswith(".dockerfile")
                or name_lower.startswith("dockerfile.")
            ):
                docker_entries.append(entry)
            elif entry["suffix"] in {".yml", ".yaml", ".json"} and (
                "services:" in entry["text"].lower() or "\"services\"" in entry["text"].lower()
            ):
                compose_entries.append(entry)

        if not docker_entries and not compose_entries:
            raise HTTPException(status_code=400, detail="No Dockerfile or docker-compose files found in upload.")

        if framework_norm == "CIS":
            controls = {
                "non_root": ("5.17.1", "Ensure 'USER' instruction is used in container images", "HIGH"),
                "healthcheck": ("5.2.1", "Ensure health check instructions are included in container images", "LOW"),
                "pinned_base": ("5.3.1", "Ensure minimal base images are used", "MEDIUM"),
                "secret_env": ("5.5.1", "Ensure sensitive information is not included in container images", "HIGH"),
            }
        else:
            controls = {
                "non_root": ("AC-6", "Least Privilege", "HIGH"),
                "healthcheck": ("AU-12", "Audit Generation", "MEDIUM"),
                "pinned_base": ("CM-6", "Configuration Settings", "HIGH"),
                "secret_env": ("SC-28", "Protection of Information at Rest", "HIGH"),
            }

        findings: List[Dict[str, Any]] = []

        non_root_failures = []
        non_root_failure_files = []
        for entry in docker_entries:
            user_values = re.findall(r"(?im)^\s*USER\s+([^\s#]+)", entry["text"])
            if not user_values:
                non_root_failures.append(f"{entry['rel']} (missing USER)")
                non_root_failure_files.append(entry["rel"])
                continue
            last_user = user_values[-1].strip("\"'").lower()
            if last_user in {"root", "0", "0:0"} or last_user.startswith("0:"):
                non_root_failures.append(f"{entry['rel']} (USER {last_user})")
                non_root_failure_files.append(entry["rel"])
        for entry in compose_entries:
            if re.search(r"(?im)^\s*user\s*:\s*[\"']?(root|0)([\"']|\s|$)", entry["text"]):
                non_root_failures.append(f"{entry['rel']} (user: root)")
                non_root_failure_files.append(entry["rel"])

        non_root_status = "FAIL" if non_root_failures else "PASS"
        non_root_actual = "; ".join(non_root_failures[:5]) if non_root_failures else "No root user directives detected"
        non_root_file = ", ".join(list(dict.fromkeys(non_root_failure_files))[:3])
        findings.append(_build_static_container_finding(
            rule_id=controls["non_root"][0],
            rule_title=controls["non_root"][1],
            description="Container workloads should avoid running as root.",
            severity=controls["non_root"][2],
            status=non_root_status,
            expected="Container definitions run as non-root users.",
            actual=non_root_actual,
            recommendation="Set USER in Dockerfile and avoid root users in compose definitions.",
            reasoning="Static check over Dockerfile USER instructions and compose user fields.",
            framework=framework_norm,
            target="docker",
            file_path=non_root_file,
        ))

        healthcheck_failures = []
        for entry in docker_entries:
            if not re.search(r"(?im)^\s*HEALTHCHECK\b", entry["text"]):
                healthcheck_failures.append(entry["rel"])
        healthcheck_status = "FAIL" if healthcheck_failures else "PASS"
        healthcheck_actual = (
            "No Dockerfile uploaded for HEALTHCHECK validation"
            if not docker_entries else
            (", ".join(healthcheck_failures[:5]) if healthcheck_failures else "HEALTHCHECK found in Dockerfile(s)")
        )
        findings.append(_build_static_container_finding(
            rule_id=controls["healthcheck"][0],
            rule_title=controls["healthcheck"][1],
            description="Container definitions should include a health probe instruction.",
            severity=controls["healthcheck"][2],
            status=healthcheck_status,
            expected="HEALTHCHECK instruction present in Dockerfile.",
            actual=healthcheck_actual,
            recommendation="Add HEALTHCHECK to Dockerfile to improve observability and recovery.",
            reasoning="Static check over Dockerfile content.",
            framework=framework_norm,
            target="docker",
            file_path=", ".join(healthcheck_failures[:3]),
        ))

        unpinned_base_images = []
        unpinned_base_files = []
        for entry in docker_entries:
            images = re.findall(r"(?im)^\s*FROM\s+([^\s#]+)", entry["text"])
            for image in images:
                image_ref = image.strip()
                if "@sha256:" in image_ref.lower():
                    continue
                image_name = image_ref.split("/")[-1]
                if image_ref.lower().endswith(":latest") or ":" not in image_name:
                    unpinned_base_images.append(f"{entry['rel']} ({image_ref})")
                    unpinned_base_files.append(entry["rel"])
        pinned_status = "FAIL" if unpinned_base_images else "PASS"
        pinned_actual = "; ".join(unpinned_base_images[:5]) if unpinned_base_images else "Base images are version pinned"
        findings.append(_build_static_container_finding(
            rule_id=controls["pinned_base"][0],
            rule_title=controls["pinned_base"][1],
            description="Container definitions should avoid floating image tags.",
            severity=controls["pinned_base"][2],
            status=pinned_status,
            expected="Base images are pinned to immutable digest or explicit non-latest tags.",
            actual=pinned_actual,
            recommendation="Pin base images to fixed tags or digests and avoid latest.",
            reasoning="Static check over Dockerfile FROM instructions.",
            framework=framework_norm,
            target="docker",
            file_path=", ".join(list(dict.fromkeys(unpinned_base_files))[:3]),
        ))

        secret_failures = []
        docker_secret_pattern = re.compile(r"(?im)^\s*(ENV|ARG)\s+.*(PASSWORD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY)\b")
        compose_secret_pattern = re.compile(r"(?im)^\s*[-\w\"']*(PASSWORD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY)[\w\"']*\s*[:=]\s*.+$")
        for entry in docker_entries:
            if docker_secret_pattern.search(entry["text"]):
                secret_failures.append(entry["rel"])
        for entry in compose_entries:
            if compose_secret_pattern.search(entry["text"]):
                secret_failures.append(entry["rel"])
        secret_status = "FAIL" if secret_failures else "PASS"
        secret_actual = ", ".join(secret_failures[:5]) if secret_failures else "No inline secrets detected"
        findings.append(_build_static_container_finding(
            rule_id=controls["secret_env"][0],
            rule_title=controls["secret_env"][1],
            description="Container definitions should not include plaintext secrets.",
            severity=controls["secret_env"][2],
            status=secret_status,
            expected="No plaintext credentials in Dockerfile/compose files.",
            actual=secret_actual,
            recommendation="Move secrets to a secret manager or runtime-injected secure store.",
            reasoning="Static pattern checks over ENV/ARG and compose environment definitions.",
            framework=framework_norm,
            target="docker",
            file_path=", ".join(secret_failures[:3]),
        ))

        resource_files = docker_entries + compose_entries
        benchmark_version = "CIS Docker Benchmark v1.8.0 (Static)" if framework_norm == "CIS" else "NIST SP 800-190 (Static)"
    else:
        manifest_entries = []
        for entry in file_entries:
            if entry["suffix"] not in {".yaml", ".yml", ".json"}:
                continue
            text_lower = entry["text"].lower()
            if "apiversion" in text_lower or "kind" in text_lower:
                manifest_entries.append(entry)

        if not manifest_entries:
            raise HTTPException(status_code=400, detail="No Kubernetes manifest files found in upload.")

        if framework_norm == "CIS":
            controls = {
                "run_as_non_root": ("K8S-CIS-001", "Ensure containers run as non-root", "HIGH"),
                "no_privilege_escalation": ("K8S-CIS-002", "Ensure privilege escalation is disabled", "HIGH"),
                "read_only_root": ("K8S-CIS-003", "Ensure root filesystem is read-only", "MEDIUM"),
                "avoid_public_service": ("K8S-CIS-004", "Ensure public LoadBalancer exposure is minimized", "MEDIUM"),
            }
        else:
            controls = {
                "run_as_non_root": ("AC-6", "Least Privilege", "HIGH"),
                "no_privilege_escalation": ("SC-39", "Process Isolation", "HIGH"),
                "read_only_root": ("SC-28", "Protection of Information at Rest", "HIGH"),
                "avoid_public_service": ("SC-7", "Boundary Protection", "HIGH"),
            }

        workload_entries = []
        service_entries = []
        for entry in manifest_entries:
            text = entry["text"]
            if re.search(r"(?i)(^|\n)\s*kind\s*:\s*(Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob)\b", text) or re.search(r'(?i)"kind"\s*:\s*"(Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob)"', text):
                workload_entries.append(entry)
            if re.search(r"(?i)(^|\n)\s*kind\s*:\s*Service\b", text) or re.search(r'(?i)"kind"\s*:\s*"Service"', text):
                service_entries.append(entry)

        findings = []

        run_as_non_root_failures = [
            entry["rel"]
            for entry in workload_entries
            if not (re.search(r"(?i)runAsNonRoot\s*:\s*true", entry["text"]) or re.search(r'(?i)"runAsNonRoot"\s*:\s*true', entry["text"]))
        ]
        run_as_non_root_status = "FAIL" if run_as_non_root_failures else "PASS"
        run_as_non_root_actual = (
            "No workload manifests found"
            if not workload_entries else
            (", ".join(run_as_non_root_failures[:5]) if run_as_non_root_failures else "runAsNonRoot is configured")
        )
        findings.append(_build_static_container_finding(
            rule_id=controls["run_as_non_root"][0],
            rule_title=controls["run_as_non_root"][1],
            description="Workload containers should run as non-root users.",
            severity=controls["run_as_non_root"][2],
            status=run_as_non_root_status,
            expected="securityContext.runAsNonRoot: true",
            actual=run_as_non_root_actual,
            recommendation="Set securityContext.runAsNonRoot to true for all workload containers.",
            reasoning="Static check over workload manifest securityContext fields.",
            framework=framework_norm,
            target="kubernetes",
            file_path=", ".join(run_as_non_root_failures[:3]),
        ))

        privilege_escalation_failures = [
            entry["rel"]
            for entry in workload_entries
            if not (re.search(r"(?i)allowPrivilegeEscalation\s*:\s*false", entry["text"]) or re.search(r'(?i)"allowPrivilegeEscalation"\s*:\s*false', entry["text"]))
        ]
        privilege_escalation_status = "FAIL" if privilege_escalation_failures else "PASS"
        privilege_escalation_actual = (
            "No workload manifests found"
            if not workload_entries else
            (", ".join(privilege_escalation_failures[:5]) if privilege_escalation_failures else "allowPrivilegeEscalation is disabled")
        )
        findings.append(_build_static_container_finding(
            rule_id=controls["no_privilege_escalation"][0],
            rule_title=controls["no_privilege_escalation"][1],
            description="Workload containers should disable privilege escalation.",
            severity=controls["no_privilege_escalation"][2],
            status=privilege_escalation_status,
            expected="securityContext.allowPrivilegeEscalation: false",
            actual=privilege_escalation_actual,
            recommendation="Set securityContext.allowPrivilegeEscalation to false.",
            reasoning="Static check over workload manifest securityContext fields.",
            framework=framework_norm,
            target="kubernetes",
            file_path=", ".join(privilege_escalation_failures[:3]),
        ))

        readonly_root_failures = [
            entry["rel"]
            for entry in workload_entries
            if not (re.search(r"(?i)readOnlyRootFilesystem\s*:\s*true", entry["text"]) or re.search(r'(?i)"readOnlyRootFilesystem"\s*:\s*true', entry["text"]))
        ]
        readonly_root_status = "FAIL" if readonly_root_failures else "PASS"
        readonly_root_actual = (
            "No workload manifests found"
            if not workload_entries else
            (", ".join(readonly_root_failures[:5]) if readonly_root_failures else "readOnlyRootFilesystem is enabled")
        )
        findings.append(_build_static_container_finding(
            rule_id=controls["read_only_root"][0],
            rule_title=controls["read_only_root"][1],
            description="Workload containers should use read-only root filesystems where possible.",
            severity=controls["read_only_root"][2],
            status=readonly_root_status,
            expected="securityContext.readOnlyRootFilesystem: true",
            actual=readonly_root_actual,
            recommendation="Set securityContext.readOnlyRootFilesystem to true.",
            reasoning="Static check over workload manifest securityContext fields.",
            framework=framework_norm,
            target="kubernetes",
            file_path=", ".join(readonly_root_failures[:3]),
        ))

        public_service_failures = [
            entry["rel"]
            for entry in service_entries
            if re.search(r"(?i)(^|\n)\s*type\s*:\s*LoadBalancer\b", entry["text"]) or re.search(r'(?i)"type"\s*:\s*"LoadBalancer"', entry["text"])
        ]
        public_service_status = "FAIL" if public_service_failures else "PASS"
        public_service_actual = (
            "No Service manifests found"
            if not service_entries else
            (", ".join(public_service_failures[:5]) if public_service_failures else "No public LoadBalancer Services detected")
        )
        findings.append(_build_static_container_finding(
            rule_id=controls["avoid_public_service"][0],
            rule_title=controls["avoid_public_service"][1],
            description="Service definitions should minimize unnecessary public exposure.",
            severity=controls["avoid_public_service"][2],
            status=public_service_status,
            expected="Service type should avoid unrestricted LoadBalancer exposure.",
            actual=public_service_actual,
            recommendation="Prefer ClusterIP/Internal LoadBalancer and restrict ingress exposure.",
            reasoning="Static check over Service manifest type fields.",
            framework=framework_norm,
            target="kubernetes",
            file_path=", ".join(public_service_failures[:3]),
        ))

        resource_files = manifest_entries
        benchmark_version = "CIS Kubernetes Benchmark v1.12.0 (Static)" if framework_norm == "CIS" else "NIST SP 800-190 (Static)"

    pass_count = sum(1 for f in findings if str(f.get("status", "")).upper() == "PASS")
    fail_count = sum(1 for f in findings if str(f.get("status", "")).upper() == "FAIL")
    total = len(findings)
    health_score = round((pass_count / total) * 100, 1) if total else 100.0

    resources = [
        {
            "resource_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{target_norm}:{entry['rel']}"))[:16],
            "resource_name": entry["rel"],
            "resource_type": "docker_file" if target_norm == "docker" else "k8s_manifest",
            "region": "uploaded-files",
            "config": {"path": entry["rel"]},
        }
        for entry in resource_files
    ]

    return {
        "scan_time": scan_time,
        "target": target_norm,
        "framework": framework_norm,
        "mode": "file_upload",
        "docker_available": target_norm == "docker",
        "kubernetes_available": target_norm == "kubernetes",
        "resources": resources,
        "audit": {
            "findings": findings,
            "summary": {
                "total": total,
                "pass": pass_count,
                "fail": fail_count,
                "warn": 0,
                "info": 0,
                "health_score": health_score,
            },
            "health_score": health_score,
            "framework": framework_norm,
            "target": target_norm,
            "benchmark_version": benchmark_version,
        },
        "scan": {
            "total_resources": len(resources),
            "docker_containers": 0,
            "docker_images": 0,
            "k8s_resources": 0,
        },
    }


@app.post("/api/scan/upload", response_model=ScanResponse)
async def upload_and_scan(
    files: List[UploadFile] = File(...),
    target: str = Form("terraform"),
    framework: str = Form("CIS"),
):
    """Upload IaC files and trigger Terraform or container static compliance audit."""
    import shutil
    import tempfile

    selected_target = (target or "terraform").strip().lower()
    if selected_target not in {"terraform", "docker", "kubernetes"}:
        raise HTTPException(status_code=400, detail="Invalid target. Use terraform, docker, or kubernetes.")

    # Create a temporary directory to store uploaded files
    temp_dir = tempfile.mkdtemp(prefix=f"{selected_target}_upload_")

    selected_framework = (framework or "CIS").upper()
    if selected_target == "terraform":
        if selected_framework not in {"CIS", "NIST", "CCM"}:
            raise HTTPException(status_code=400, detail="Invalid framework for Terraform. Use CIS, NIST, or CCM.")
    else:
        if selected_framework not in {"CIS", "NIST"}:
            raise HTTPException(status_code=400, detail="Invalid framework for container file scan. Use CIS or NIST.")

    try:
        # Save uploaded files to temp directory
        saved_files = []
        for file in files:
            if file.filename:
                file_path = Path(temp_dir) / file.filename
                with open(file_path, "wb") as f:
                    content = await file.read()
                    f.write(content)
                saved_files.append(file.filename)
        
        if not saved_files:
            raise HTTPException(status_code=400, detail="No valid files uploaded")

        if selected_target == "terraform":
            report = run_audit(
                directory=temp_dir,
                framework=selected_framework,
                triggered_by="file_upload",
            )

            return ScanResponse(
                audit_id=report.audit_id,
                compliance_score=report.compliance_score,
                total_findings=report.total_findings,
                severity_counts=report.severity_counts,
                status=report.status,
            )

        container_result = _run_static_container_file_scan(
            directory=temp_dir,
            target=selected_target,
            framework=selected_framework,
        )
        audit_id = _persist_container_audit(
            container_result,
            framework=selected_framework,
            target=selected_target,
            mode="file_upload",
        )
        if not audit_id:
            raise HTTPException(status_code=500, detail="Container scan completed but could not be saved to audit history.")

        findings = (container_result.get("audit") or {}).get("findings") or []
        severity_counts = _severity_counts_from_findings(findings)
        total_findings = sum(severity_counts.values())
        compliance_score = float((container_result.get("audit") or {}).get("health_score", 0.0) or 0.0)

        return ScanResponse(
            audit_id=audit_id,
            compliance_score=compliance_score,
            total_findings=total_findings,
            severity_counts=severity_counts,
            status="completed",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Clean up temp directory
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            pass


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
            fw_failed = get_issue_count(findings_data)
            fw_passed = fw_total - fw_failed
            fw_score = calculate_compliance_score(findings_data, fw_total)
            report = {
                "report_title": f"Invecto Compliance Guard — Audit Report{fw_label}",
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
        terraform_framework = _normalize_terraform_framework(request.terraform_framework)
        container_framework = _normalize_container_framework(request.container_framework)
        scan_containers = True if request.scan_containers is None else bool(request.scan_containers)

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
                _run_github_repo_scan(
                    repo_name=repo_name,
                    terraform_framework=terraform_framework,
                    container_framework=container_framework,
                    scan_containers=scan_containers,
                )
            except Exception as exc:
                logger.exception("GitHub auto scan failed for %s: %s", repo_name, exc)
            try:
                s = get_session()
                update_repo_sync_time(s, repo_id)
                s.close()
            except Exception as exc:
                logger.exception("Failed updating repo sync time for %s: %s", repo_name, exc)

        thread = threading.Thread(target=_auto_scan, daemon=True)
        thread.start()

        result["scan_triggered"] = True
        result["scan_config"] = {
            "terraform_framework": terraform_framework,
            "container_framework": container_framework,
            "scan_containers": scan_containers,
        }
        result["message"] = (
            f"Repository cloned. Background scan started for Terraform ({terraform_framework})"
            + (f" and Docker/Kubernetes ({container_framework})." if scan_containers else ".")
            + " Check the Audits tab for results."
        )
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
def sync_github_repo(request: Optional[GitHubSyncRequest] = None):
    """Pull latest changes and run a compliance scan."""
    terraform_framework = _normalize_terraform_framework((request.terraform_framework if request else "CIS"))
    container_framework = _normalize_container_framework((request.container_framework if request else "CIS"))
    scan_containers = True if (request is None or request.scan_containers is None) else bool(request.scan_containers)

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
                _run_github_repo_scan(
                    repo_name=repo_name,
                    terraform_framework=terraform_framework,
                    container_framework=container_framework,
                    scan_containers=scan_containers,
                )
            except Exception as exc:
                logger.exception("GitHub sync scan failed for %s: %s", repo_name, exc)
            try:
                s = get_session()
                update_repo_sync_time(s, repo_id)
                s.close()
            except Exception as exc:
                logger.exception("Failed updating repo sync time for %s: %s", repo_name, exc)

        thread = threading.Thread(target=_background_scan, daemon=True)
        thread.start()

        return {
            "status": "syncing",
            "scan_config": {
                "terraform_framework": terraform_framework,
                "container_framework": container_framework,
                "scan_containers": scan_containers,
            },
            "message": (
                f"Sync started for Terraform ({terraform_framework})"
                + (f" and Docker/Kubernetes ({container_framework})." if scan_containers else ".")
                + " Audits will appear in the Audits tab when complete."
            ),
        }
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


def _persist_cloud_scan(
    result: Dict[str, Any],
    provider: str,
    framework: str = "CIS",
) -> Optional[str]:
    """Persist a cloud monitoring scan result to audits/findings tables so it appears in audit history."""
    try:
        findings = (result.get("audit") or {}).get("findings") or []
        resources = result.get("resources") or []
        scan_summary = result.get("scan") or {}

        failed_findings = [f for f in findings if str(f.get("status", "")).upper() in {"FAIL", "WARN"}]
        sev_counts = get_severity_summary(findings)

        mapped_findings = []
        for finding in findings:
            db_status = str(finding.get("status", "FAIL")).upper()
            mapped_findings.append({
                "rule_id": finding.get("rule_id") or finding.get("cis_rule_id") or "",
                "rule_title": finding.get("rule_title") or finding.get("title") or "Cloud Security Control",
                "severity": finding.get("severity", "LOW"),
                "resource_address": finding.get("resource_address") or finding.get("resource_name") or "",
                "resource_type": finding.get("resource_type") or "",
                "file_path": finding.get("file_path", ""),
                "description": finding.get("description", ""),
                "remediation_hcl": finding.get("remediation_hcl", ""),
                "reasoning": finding.get("reasoning", ""),
                "expected": finding.get("expected", ""),
                "actual": finding.get("actual", ""),
                "recommendation": finding.get("recommendation") or finding.get("remediation_step", ""),
                "cloud_provider": finding.get("cloud_provider", provider.upper()),
                "status": db_status,
                "confidence": float(finding.get("confidence", 1.0) or 1.0),
            })

        health_score = (result.get("audit") or {}).get("health_score", 0.0) or 0.0
        # Some auditors store summary differently
        if health_score == 0.0:
            summary_obj = (result.get("audit") or {}).get("summary") or {}
            health_score = summary_obj.get("health_score", 0.0) or 0.0

        provider_upper = provider.upper()
        regions = result.get("regions_scanned") or []
        scan_time = result.get("scan_time") or ""

        audit_id = str(uuid.uuid4())[:12]
        init_db()
        session = get_session()
        upsert_cloud_scan_audit(session, {
            "audit_id": audit_id,
            "directory": f"{provider_upper} Live Scan",
            "files_scanned": 0,
            "resources_scanned": len(resources),
            "total_findings": len(failed_findings),
            "critical_count": sev_counts["CRITICAL"],
            "high_count": sev_counts["HIGH"],
            "medium_count": sev_counts["MEDIUM"],
            "low_count": sev_counts["LOW"],
            "compliance_score": float(calculate_compliance_score(findings, len(resources))),
            "status": "completed",
            "triggered_by": "cloud_monitoring",
            "metadata_json": {
                "domain": "cloud",
                "target": provider.lower(),
                "framework": framework,
                "mode": "live_scan",
                "source": "monitoring",
                "provider": provider_upper,
                "scan_time": scan_time,
                "regions_scanned": regions,
                "total_resources": scan_summary.get("total_resources", len(resources)),
            },
            "findings": mapped_findings,
        })
        session.close()
        logger.info("Persisted %s cloud scan as audit %s (%d findings)", provider_upper, audit_id, len(failed_findings))
        return audit_id
    except Exception as exc:
        logger.exception("Failed to persist %s cloud scan audit: %s", provider, exc)
        return None


def _persist_container_audit(
    result: Dict[str, Any],
    framework: str,
    target: str,
    mode: str = "runtime",
    triggered_by: str = "container_scan",
    source_directory: Optional[str] = None,
) -> Optional[str]:
    """Persist container scan result to audits/findings tables so it appears in audit history."""
    try:
        findings = (result.get("audit") or {}).get("findings") or []
        resources = result.get("resources") or []
        summary = (result.get("audit") or {}).get("summary") or {}

        failed_findings = [f for f in findings if str(f.get("status", "")).upper() in {"FAIL", "WARN"}]
        sev_counts = get_severity_summary(findings)

        mapped_findings = []
        for finding in findings:
            db_status = str(finding.get("status", "FAIL")).upper()
            mapped_findings.append({
                "rule_id": finding.get("rule_id") or finding.get("cis_rule_id") or "",
                "rule_title": finding.get("rule_title") or finding.get("title") or "Container Security Control",
                "severity": finding.get("severity", "LOW"),
                "resource_address": finding.get("resource_address") or finding.get("resource_name") or f"{target}-host",
                "resource_type": finding.get("resource_type") or f"{target}_resource",
                "file_path": finding.get("file_path", ""),
                "description": finding.get("description", ""),
                "remediation_hcl": finding.get("remediation_hcl", ""),
                "reasoning": finding.get("reasoning", ""),
                "expected": finding.get("expected", ""),
                "actual": finding.get("actual", ""),
                "recommendation": finding.get("recommendation") or finding.get("remediation_step", ""),
                "cloud_provider": finding.get("cloud_provider", "Container"),
                "status": db_status,
                "confidence": float(finding.get("confidence", 1.0) or 1.0),
            })

        audit_id = str(uuid.uuid4())[:12]
        session = get_session()
        files_scanned = len(resources) if mode in {"file_upload", "repository"} else 0
        save_audit(session, {
            "audit_id": audit_id,
            "directory": source_directory or f"container://{target}",
            "files_scanned": files_scanned,
            "resources_scanned": len(resources),
            "total_findings": len(failed_findings),
            "critical_count": sev_counts["CRITICAL"],
            "high_count": sev_counts["HIGH"],
            "medium_count": sev_counts["MEDIUM"],
            "low_count": sev_counts["LOW"],
            "compliance_score": float(calculate_compliance_score(findings, len(resources))),
            "status": "completed",
            "triggered_by": triggered_by,
            "metadata_json": {
                "domain": "container",
                "target": target,
                "framework": framework,
                "mode": mode,
                "source": "github" if triggered_by == "github" else "direct",
                "scan_time": result.get("scan_time"),
                "benchmark_version": (result.get("audit") or {}).get("benchmark_version") or result.get("benchmark_version"),
            },
            "findings": mapped_findings,
        })
        session.close()
        return audit_id
    except Exception as exc:
        logger.exception("Failed to persist container audit: %s", exc)
        return None


def _normalize_terraform_framework(value: Optional[str]) -> str:
    fw = (value or "CIS").strip().upper()
    if fw not in {"CIS", "NIST", "CCM"}:
        raise HTTPException(status_code=400, detail="Invalid Terraform framework. Use CIS, NIST, or CCM.")
    return fw


def _normalize_container_framework(value: Optional[str]) -> str:
    fw = (value or "CIS").strip().upper()
    if fw not in {"CIS", "NIST"}:
        raise HTTPException(status_code=400, detail="Invalid container framework. Use CIS or NIST.")
    return fw


def _run_github_repo_scan(
    repo_name: str,
    terraform_framework: str = "CIS",
    container_framework: str = "CIS",
    scan_containers: bool = True,
) -> Dict[str, Any]:
    """Run GitHub repo scan workflow across Terraform and (optionally) static container file audits."""
    repo_path = Path(__file__).parent / "repos" / repo_name
    if not repo_path.exists():
        raise FileNotFoundError(f"Repo {repo_name} not found")

    scan_summary: Dict[str, Any] = {
        "repo": repo_name,
        "terraform_framework": terraform_framework,
        "container_framework": container_framework,
        "scan_containers": scan_containers,
        "terraform_audit_id": None,
        "container": [],
    }

    terraform_report = sync_and_scan(repo_name, terraform_framework=terraform_framework)
    scan_summary["terraform_audit_id"] = terraform_report.get("audit_id")

    if not scan_containers:
        return scan_summary

    for target in ("docker", "kubernetes"):
        try:
            container_result = _run_static_container_file_scan(
                directory=str(repo_path),
                target=target,
                framework=container_framework,
            )
            audit_id = _persist_container_audit(
                container_result,
                framework=container_framework,
                target=target,
                mode="repository",
                triggered_by="github",
                source_directory=str(repo_path),
            )
            if audit_id:
                scan_summary["container"].append({
                    "target": target,
                    "framework": container_framework,
                    "audit_id": audit_id,
                    "status": "completed",
                })
            else:
                scan_summary["container"].append({
                    "target": target,
                    "framework": container_framework,
                    "status": "error",
                    "reason": "Persistence failed",
                })
        except HTTPException as exc:
            detail = str(exc.detail)
            if exc.status_code == 400 and (
                "No Dockerfile or docker-compose files found" in detail
                or "No Kubernetes manifest files found" in detail
            ):
                scan_summary["container"].append({
                    "target": target,
                    "framework": container_framework,
                    "status": "skipped",
                    "reason": detail,
                })
                continue
            scan_summary["container"].append({
                "target": target,
                "framework": container_framework,
                "status": "error",
                "reason": detail,
            })
        except Exception as exc:
            scan_summary["container"].append({
                "target": target,
                "framework": container_framework,
                "status": "error",
                "reason": str(exc),
            })

    return scan_summary


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

    # Clear old scan cache on new connection
    global _aws_scan_cache
    _aws_scan_cache = {}
    if _AWS_SCAN_CACHE_FILE.exists():
        try:
            _AWS_SCAN_CACHE_FILE.unlink()
        except:
            pass

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
    
    # Clear old scan cache on new connection
    global _azure_scan_cache
    _azure_scan_cache = None
    if _AZURE_SCAN_CACHE_FILE.exists():
        try:
            _AZURE_SCAN_CACHE_FILE.unlink()
        except:
            pass
    
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
    
    # Clear old scan cache on new connection
    global _gcp_scan_cache
    _gcp_scan_cache = None
    if _GCP_SCAN_CACHE_FILE.exists():
        try:
            _GCP_SCAN_CACHE_FILE.unlink()
        except:
            pass
    
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
    
    # Get credentials from environment (set by startup or configure endpoint)
    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    
    # Verify credentials are set
    if not access_key or not secret_key:
        raise HTTPException(status_code=401, detail="AWS credentials not configured. Please connect AWS first.")
    
    # Create scanner with explicit credentials
    scanner = AWSScanner(access_key, secret_key, region)
    
    # Verify connection before scanning
    conn = scanner.test_connection()
    if not conn.get("connected"):
        raise HTTPException(status_code=401, detail=conn.get("error", "AWS connection failed"))

    # Determine regions to scan — default to available regions in the account
    regions = (request.regions if request else None) or scanner.get_available_regions() or [scanner.region]
    framework = (request.framework if request else None) or "All"
    
    print(f"🔍 Starting AWS scan with {len(regions)} regions: {regions}")

    # Run the scan (synchronous blocking call)
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
    
    # Persist as audit record so it appears in Audit History
    _persist_cloud_scan(result, provider="aws", framework=framework)
    
    # Broadcast to topology view
    await manager.broadcast({
        "type": "RESOURCE_UPDATED",
        "provider": "aws",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    return result


@app.get("/api/aws/scan/diagnostic")
def aws_scan_diagnostic():
    """Diagnostic endpoint to debug region discovery and resource scanning issues.
    
    Returns:
    - All discovered regions (API vs hardcoded fallback)
    - Which regions were actually enabled/accessible
    - Resource count per region
    - Any errors encountered
    """
    scanner = AWSScanner()
    
    # Try to get available regions
    try:
        discovered_regions = scanner.get_available_regions()
    except Exception as e:
        discovered_regions = []
        discovery_error = str(e)
    else:
        discovery_error = None
    
    # Test each region for access
    region_status = {}
    for region in discovered_regions[:5]:  # Sample first 5 to avoid timeout
        try:
            ec2 = scanner._client("ec2", region=region)
            # Try a simple call that requires no permissions (describe-regions is global)
            response = ec2.describe_instances(MaxResults=1)
            region_status[region] = {
                "accessible": True,
                "error": None
            }
        except Exception as e:
            region_status[region] = {
                "accessible": False,
                "error": str(e)
            }
    
    # If there's a cached scan, extract region-level diagnostic info
    region_diagnostics = {}
    if _aws_scan_cache:
        error_log = _aws_scan_cache.get("_region_error_log", {})
        regions_scanned = _aws_scan_cache.get("regions_scanned", [])
        for region in regions_scanned:
            region_diagnostics[region] = {
                "errors": error_log.get(region, {}),
                "region_in_error_log": region in error_log
            }
    
    return {
        "account_id": scanner.test_connection().get("account_id"),
        "primary_region": scanner.region,
        "discovered_regions": discovered_regions,
        "total_regions": len(discovered_regions),
        "discovery_error": discovery_error,
        "region_access_sample": region_status,
        "last_scan_regions": _aws_scan_cache.get("regions_scanned") if _aws_scan_cache else None,
        "region_diagnostics": region_diagnostics if region_diagnostics else "No scan results yet",
        "last_scan_summary": _aws_scan_cache.get("summary") if _aws_scan_cache else None,
        "note": "Sample tests first 5 regions. Run full scan to see all region diagnostic data.",
    }


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
    
    # Persist as audit record so it appears in Audit History
    _persist_cloud_scan(result, provider="azure", framework="CIS")
    
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
    
    # Persist as audit record so it appears in Audit History
    _persist_cloud_scan(result, provider="gcp", framework="CIS")
    
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

class ContainerScanRequest(BaseModel):
    target: str = "docker"  # docker | kubernetes
    framework: str = "CIS"  # CIS | NIST
    mode: str = "runtime"   # runtime

@app.post("/api/container/scan")
async def run_container_scan(request: ContainerScanRequest = None):
    """Run container security scan for docker/kubernetes using CIS or NIST controls."""
    global _container_scan_cache

    if ContainerAuditor is None:
        raise HTTPException(status_code=500, detail="ContainerAuditor module is not available.")

    target = ((request.target if request else "docker") or "docker").strip().lower()
    framework = ((request.framework if request else "CIS") or "CIS").strip().upper()
    mode = ((request.mode if request else "runtime") or "runtime").strip().lower()

    if target not in {"docker", "kubernetes"}:
        raise HTTPException(status_code=400, detail="Invalid target. Use 'docker' or 'kubernetes'.")
    if framework not in {"CIS", "NIST"}:
        raise HTTPException(status_code=400, detail="Invalid framework. Use 'CIS' or 'NIST'.")
    if mode != "runtime":
        raise HTTPException(status_code=400, detail="Only runtime mode is currently supported for container scans.")
    
    auditor = ContainerAuditor()
    result = auditor.run_full_scan(framework=framework, target=target)
    
    # Add workflow metadata
    result["framework"] = framework
    result["target"] = target
    result["mode"] = mode
    result["audit"]["framework"] = framework
    result["audit"]["target"] = target

    audit_id = _persist_container_audit(result, framework=framework, target=target, mode=mode)
    if audit_id:
        result["audit_id"] = audit_id

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
    framework: str = Query("All", pattern="^(All|CIS|NIST)$"),
):
    """Download the latest Container scan report as PDF, CSV, or JSON."""
    if not _container_scan_cache:
        raise HTTPException(status_code=404, detail="No container scan results. Run a scan first.")

    audit_data = _container_scan_cache.get("audit", {})
    all_findings = audit_data.get("findings", [])

    # Container reports support CIS and NIST framework filtering
    if framework == "CIS":
        findings_list = [f for f in all_findings if str(f.get("framework", "CIS")).upper() == "CIS"]
    elif framework == "NIST":
        findings_list = all_findings
    else:
        findings_list = all_findings

    scan_time = _container_scan_cache.get("scan_time", "")
    fw_suffix = f"-{framework.lower()}" if framework != "All" else ""
    fw_label = f" ({framework} Framework)" if framework != "All" else ""

    scan_meta = {
        "scan_time": scan_time,
        "docker_available": _container_scan_cache.get("docker_available", False),
        "kubernetes_available": _container_scan_cache.get("kubernetes_available", False),
        "total_resources": _container_scan_cache.get("scan", {}).get("total_resources", 0),
        "target": _container_scan_cache.get("target", "docker"),
        "mode": _container_scan_cache.get("mode", "runtime"),
        "framework": framework,
    }

    if format == "json":
        total = len(findings_list)
        passed = sum(1 for f in findings_list if f.get("status") == "PASS")
        failed = total - passed
        score = round((passed / total) * 100, 1) if total > 0 else 0.0
        report = {
            "report_title": f"Invecto Compliance Guard — Container Security Audit{fw_label}",
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

        # Use health_score directly from the scan cache — same value Monitoring shows.
        # Do NOT recalculate with resource count as denominator (gives wrong result).
        score = round((_aws_scan_cache.get("audit") or {}).get("health_score") or
                      calculate_compliance_score(findings, len(findings)), 1)
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
        # Build per-region findings for consistent weighted scoring
        findings_by_region = {}
        for f in findings:
            reg = f.get("resource_region") or "global"
            findings_by_region.setdefault(reg, []).append(f)

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

        # Add weighted compliance score to each region (consistent with Monitoring view)
        for reg_data in region_map.values():
            reg_name = reg_data["name"]
            reg_findings = findings_by_region.get(reg_name, [])
            reg_data["score"] = round(calculate_compliance_score(reg_findings, reg_data["total"]), 1)

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
            "report_title": f"Invecto Compliance Guard — AWS Live Audit Report{fw_label}",
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


# ─── Organization Topology Endpoints ──────────────────────────────────────────

@app.get("/api/topology/organization")
def get_organization_topology():
    """Fetch AWS Organization hierarchy (Org → OUs → Accounts)"""
    try:
        access_key = os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        
        if not access_key or not secret_key:
            # Return mock data for demo purposes
            return {
                "success": True,
                "nodes": [
                    {"id": "org-1", "label": "AWS Organization", "type": "organization", "position": {"x": 0, "y": 0}, "data": {"type": "organization"}},
                    {"id": "acc-1", "label": "Production Account", "type": "account", "position": {"x": -300, "y": 150}, "data": {"type": "aws_account"}},
                    {"id": "acc-2", "label": "Staging Account", "type": "account", "position": {"x": 0, "y": 150}, "data": {"type": "aws_account"}},
                    {"id": "acc-3", "label": "Dev Account", "type": "account", "position": {"x": 300, "y": 150}, "data": {"type": "aws_account"}},
                ],
                "edges": [
                    {"id": "e1", "source": "org-1", "target": "acc-1"},
                    {"id": "e2", "source": "org-1", "target": "acc-2"},
                    {"id": "e3", "source": "org-1", "target": "acc-3"},
                ]
            }
        
        builder = get_topology_builder()
        builder.initialize(access_key, secret_key)
        
        result = builder.get_organization_structure()
        return result
    except Exception as e:
        print(f"Error fetching org topology: {str(e)}")
        # Return fallback demo data
        return {
            "success": True,
            "nodes": [
                {"id": "org-1", "label": "AWS Organization", "type": "organization", "position": {"x": 0, "y": 0}, "data": {"type": "organization"}},
                {"id": "acc-1", "label": "Production Account", "type": "account", "position": {"x": -300, "y": 150}, "data": {"type": "aws_account"}},
                {"id": "acc-2", "label": "Staging Account", "type": "account", "position": {"x": 0, "y": 150}, "data": {"type": "aws_account"}},
                {"id": "acc-3", "label": "Dev Account", "type": "account", "position": {"x": 300, "y": 150}, "data": {"type": "aws_account"}},
            ],
            "edges": [
                {"id": "e1", "source": "org-1", "target": "acc-1"},
                {"id": "e2", "source": "org-1", "target": "acc-2"},
                {"id": "e3", "source": "org-1", "target": "acc-3"},
            ]
        }


@app.get("/api/topology/account/{account_id}/iam")
def get_account_iam_topology(account_id: str):
    """Fetch IAM structure for a specific account (Users, Roles, Policies)"""
    try:
        access_key = os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        
        if not access_key or not secret_key:
            return {"success": False, "error": "AWS credentials not configured"}
        
        builder = get_topology_builder()
        builder.initialize(access_key, secret_key)
        
        result = builder.get_account_iam_topology(account_id)
        return result
    except Exception as e:
        print(f"Error fetching IAM topology: {str(e)}")
        return {"success": False, "error": str(e)}
