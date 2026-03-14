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
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
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
)
from .audit import run_audit


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
    """Get a specific audit with its findings."""
    session = get_session()
    try:
        audit = get_audit_by_id(session, audit_id)
        if not audit:
            raise HTTPException(status_code=404, detail="Audit not found")

        findings = get_findings_by_audit(session, audit.id)
        result = audit.to_dict()
        result["findings"] = [f.to_dict() for f in findings]
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
