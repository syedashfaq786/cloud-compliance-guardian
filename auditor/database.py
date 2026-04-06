"""
Database Layer — PostgreSQL storage for audit history, findings, and trend data.

Uses SQLAlchemy ORM for models and queries. Auto-creates tables on first run.
"""

import os
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    Text,
    DateTime,
    Boolean,
    JSON,
    ForeignKey,
    func,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./compliance_guardian.db",
)

# Use check_same_thread=False for SQLite to work with FastAPI
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


# ═══════════════════════════════════════════════════════════════════════════════
# ORM Models
# ═══════════════════════════════════════════════════════════════════════════════


class Audit(Base):
    __tablename__ = "audits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_id = Column(String(64), unique=True, nullable=False, index=True)
    directory = Column(String(512), nullable=False)
    files_scanned = Column(Integer, default=0)
    resources_scanned = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    compliance_score = Column(Float, default=100.0)
    status = Column(String(32), default="completed")
    triggered_by = Column(String(128), default="cli")  # cli, pr, api, scheduled
    pr_url = Column(String(512), nullable=True)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    findings = relationship("Finding", back_populates="audit", cascade="all, delete-orphan")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "audit_id": self.audit_id,
            "directory": self.directory,
            "files_scanned": self.files_scanned,
            "resources_scanned": self.resources_scanned,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "compliance_score": self.compliance_score,
            "status": self.status,
            "triggered_by": self.triggered_by,
            "pr_url": self.pr_url,
            "metadata_json": self.metadata_json,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_id = Column(Integer, ForeignKey("audits.id"), nullable=False, index=True)
    rule_id = Column(String(32), nullable=False, index=True)
    rule_title = Column(String(256), nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    resource_address = Column(String(256), nullable=False)
    resource_type = Column(String(128), nullable=False)
    file_path = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)
    remediation_hcl = Column(Text, default="")
    reasoning = Column(Text, default="")
    expected = Column(Text, default="")
    actual = Column(Text, default="")
    recommendation = Column(Text, default="")
    cloud_provider = Column(String(32), default="AWS")
    check_status = Column(String(16), default="FAIL")  # "PASS" or "FAIL"
    confidence = Column(Float, default=0.0)
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    audit = relationship("Audit", back_populates="findings")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "resource_address": self.resource_address,
            "resource_type": self.resource_type,
            "file_path": self.file_path,
            "description": self.description,
            "remediation_hcl": self.remediation_hcl,
            "reasoning": self.reasoning,
            "expected": self.expected,
            "actual": self.actual,
            "recommendation": self.recommendation,
            "cloud_provider": self.cloud_provider,
            "status": self.check_status,
            "confidence": self.confidence,
            "is_resolved": self.is_resolved,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class TrendSnapshot(Base):
    __tablename__ = "trend_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(DateTime, nullable=False, index=True)
    total_audits = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    avg_compliance_score = Column(Float, default=100.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "date": self.date.isoformat() if self.date else None,
            "total_audits": self.total_audits,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "avg_compliance_score": self.avg_compliance_score,
        }


class DriftAlert(Base):
    __tablename__ = "drift_alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(Text, default="")
    resource_address = Column(String(256), nullable=True)
    previous_audit_id = Column(String(64), nullable=True)
    current_audit_id = Column(String(64), nullable=True)
    is_acknowledged = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "resource_address": self.resource_address,
            "is_acknowledged": self.is_acknowledged,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class GitHubRepo(Base):
    __tablename__ = "github_repos"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(256), nullable=False)
    url = Column(String(512), nullable=False, unique=True)
    last_sync = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "last_sync": self.last_sync.isoformat() if self.last_sync else None,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Database Operations
# ═══════════════════════════════════════════════════════════════════════════════


def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)


def get_session() -> Session:
    """Get a new database session."""
    return SessionLocal()


def save_audit(session: Session, audit_data: Dict[str, Any]) -> Audit:
    """Save an audit record with its findings."""
    audit = Audit(
        audit_id=audit_data["audit_id"],
        directory=audit_data.get("directory", ""),
        files_scanned=audit_data.get("files_scanned", 0),
        resources_scanned=audit_data.get("resources_scanned", 0),
        total_findings=audit_data.get("total_findings", 0),
        critical_count=audit_data.get("critical_count", 0),
        high_count=audit_data.get("high_count", 0),
        medium_count=audit_data.get("medium_count", 0),
        low_count=audit_data.get("low_count", 0),
        compliance_score=audit_data.get("compliance_score", 100.0),
        status=audit_data.get("status", "completed"),
        triggered_by=audit_data.get("triggered_by", "cli"),
        pr_url=audit_data.get("pr_url"),
        metadata_json=audit_data.get("metadata_json"),
    )
    session.add(audit)
    session.flush()  # Get the audit.id

    for finding_data in audit_data.get("findings", []):
        finding = Finding(
            audit_id=audit.id,
            rule_id=finding_data.get("rule_id", ""),
            rule_title=finding_data.get("rule_title", ""),
            severity=finding_data.get("severity", "MEDIUM"),
            resource_address=finding_data.get("resource_address", ""),
            resource_type=finding_data.get("resource_type", ""),
            file_path=finding_data.get("file_path", ""),
            description=finding_data.get("description", ""),
            remediation_hcl=finding_data.get("remediation_hcl", ""),
            reasoning=finding_data.get("reasoning", ""),
            expected=finding_data.get("expected", ""),
            actual=finding_data.get("actual", ""),
            recommendation=finding_data.get("recommendation", ""),
            cloud_provider=finding_data.get("cloud_provider", "AWS"),
            check_status=finding_data.get("status", "FAIL"),
            confidence=finding_data.get("confidence", 0.0),
        )
        session.add(finding)

    session.commit()
    return audit


def upsert_cloud_scan_audit(session: Session, audit_data: Dict[str, Any]) -> Audit:
    """
    Upsert a cloud monitoring scan audit.
    If an audit already exists for the same provider+framework, update it in-place
    (preserving the audit_id). Otherwise insert a new record.
    This prevents unbounded duplicate rows every time a scan runs.
    """
    meta = audit_data.get("metadata_json", {}) or {}

    # Find the most recent existing record for this provider+framework
    existing = (
        session.query(Audit)
        .filter(
            Audit.triggered_by == "cloud_monitoring",
            Audit.directory == audit_data.get("directory", ""),
        )
        .order_by(Audit.created_at.desc())
        .first()
    )

    if existing:
        # Update fields in-place
        existing.resources_scanned = audit_data.get("resources_scanned", 0)
        existing.total_findings = audit_data.get("total_findings", 0)
        existing.critical_count = audit_data.get("critical_count", 0)
        existing.high_count = audit_data.get("high_count", 0)
        existing.medium_count = audit_data.get("medium_count", 0)
        existing.low_count = audit_data.get("low_count", 0)
        existing.compliance_score = audit_data.get("compliance_score", 100.0)
        existing.metadata_json = meta
        existing.created_at = datetime.now(timezone.utc)

        # Replace findings: delete old, insert new
        session.query(Finding).filter(Finding.audit_id == existing.id).delete()
        session.flush()
        for finding_data in audit_data.get("findings", []):
            session.add(Finding(
                audit_id=existing.id,
                rule_id=finding_data.get("rule_id", ""),
                rule_title=finding_data.get("rule_title", ""),
                severity=finding_data.get("severity", "MEDIUM"),
                resource_address=finding_data.get("resource_address", ""),
                resource_type=finding_data.get("resource_type", ""),
                file_path=finding_data.get("file_path", ""),
                description=finding_data.get("description", ""),
                remediation_hcl=finding_data.get("remediation_hcl", ""),
                reasoning=finding_data.get("reasoning", ""),
                expected=finding_data.get("expected", ""),
                actual=finding_data.get("actual", ""),
                recommendation=finding_data.get("recommendation", ""),
                cloud_provider=finding_data.get("cloud_provider", "AWS"),
                check_status=finding_data.get("status", "FAIL"),
                confidence=finding_data.get("confidence", 0.0),
            ))
        session.commit()
        return existing
    else:
        return save_audit(session, audit_data)


def get_recent_audits(session: Session, limit: int = 20) -> List[Audit]:
    """Get the most recent audits."""
    return (
        session.query(Audit)
        .order_by(Audit.created_at.desc())
        .limit(limit)
        .all()
    )


def get_audit_by_id(session: Session, audit_id: str) -> Optional[Audit]:
    """Get an audit by its audit_id string."""
    return session.query(Audit).filter(Audit.audit_id == audit_id).first()


def get_findings_by_audit(session: Session, audit_db_id: int) -> List[Finding]:
    """Get all findings for an audit."""
    return session.query(Finding).filter(Finding.audit_id == audit_db_id).all()


def get_trend_data(session: Session, days: int = 30) -> List[TrendSnapshot]:
    """Get trend snapshots for the last N days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return (
        session.query(TrendSnapshot)
        .filter(TrendSnapshot.date >= cutoff)
        .order_by(TrendSnapshot.date.asc())
        .all()
    )


def get_active_drift_alerts(session: Session) -> List[DriftAlert]:
    """Get unacknowledged drift alerts."""
    return (
        session.query(DriftAlert)
        .filter(DriftAlert.is_acknowledged == False)
        .order_by(DriftAlert.created_at.desc())
        .all()
    )


def save_drift_alert(session: Session, alert_data: Dict[str, Any]) -> DriftAlert:
    """Save a drift detection alert."""
    alert = DriftAlert(
        alert_type=alert_data.get("alert_type", "new_violation"),
        severity=alert_data.get("severity", "MEDIUM"),
        title=alert_data.get("title", ""),
        description=alert_data.get("description", ""),
        resource_address=alert_data.get("resource_address"),
        previous_audit_id=alert_data.get("previous_audit_id"),
        current_audit_id=alert_data.get("current_audit_id"),
    )
    session.add(alert)
    session.commit()
    return alert


def acknowledge_alert(session: Session, alert_id: int) -> bool:
    """Mark a drift alert as acknowledged."""
    alert = session.query(DriftAlert).filter(DriftAlert.id == alert_id).first()
    if alert:
        alert.is_acknowledged = True
        session.commit()
        return True
    return False


def get_compliance_summary(session: Session) -> Dict[str, Any]:
    """Get an aggregate compliance summary from recent audits."""
    latest = (
        session.query(Audit)
        .order_by(Audit.created_at.desc())
        .first()
    )
    if not latest:
        return {
            "compliance_score": 0,
            "total_audits": 0,
            "total_findings": 0,
            "resources_scanned": 0,
            "severity_breakdown": {},
        }

    total_audits = session.query(func.count(Audit.id)).scalar()

    return {
        "compliance_score": latest.compliance_score,
        "total_audits": total_audits,
        "total_findings": latest.total_findings,
        "resources_scanned": latest.resources_scanned,
        "latest_audit_id": latest.audit_id,
        "latest_audit_date": latest.created_at.isoformat() if latest.created_at else None,
        "severity_breakdown": {
            "critical": latest.critical_count,
            "high": latest.high_count,
            "medium": latest.medium_count,
            "low": latest.low_count,
        },
    }


def save_github_repo(session: Session, name: str, url: str) -> GitHubRepo:
    """Save or update a GitHub repository connection."""
    existing = session.query(GitHubRepo).filter(GitHubRepo.url == url).first()
    if existing:
        existing.name = name
        existing.is_active = True
        session.commit()
        return existing
    
    repo = GitHubRepo(name=name, url=url)
    session.add(repo)
    session.commit()
    return repo


def get_connected_repo(session: Session) -> Optional[GitHubRepo]:
    """Get the currently active GitHub repository."""
    return session.query(GitHubRepo).filter(GitHubRepo.is_active == True).first()


def update_repo_sync_time(session: Session, repo_id: int):
    """Update the last sync timestamp for a repository."""
    repo = session.query(GitHubRepo).get(repo_id)
    if repo:
        repo.last_sync = datetime.now(timezone.utc)
        session.commit()
