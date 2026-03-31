
import os
import uuid
from datetime import datetime, timedelta, timezone
from auditor.database import init_db, get_session, Audit, Finding, TrendSnapshot, DriftAlert

def seed_data():
    print("🌱 Seeding dummy data...")
    init_db()
    session = get_session()

    # Clear existing data if any (optional, but good for clean demo)
    session.query(Finding).delete()
    session.query(Audit).delete()
    session.query(TrendSnapshot).delete()
    session.query(DriftAlert).delete()

    now = datetime.now(timezone.utc)

    # 1. Create some audits over the last 7 days
    for i in range(7):
        audit_date = now - timedelta(days=7-i)
        audit_id = f"audit-{uuid.uuid4().hex[:8]}"
        
        # Improve score over time
        score = 70.0 + (i * 4.0)
        total_f = 20 - (i * 2)
        
        audit = Audit(
            audit_id=audit_id,
            directory="./infra/prod",
            files_scanned=12,
            resources_scanned=45,
            total_findings=total_f,
            critical_count=max(0, 3 - (i // 2)),
            high_count=max(0, 5 - i),
            medium_count=6,
            low_count=total_f - 11 - max(0, 3 - (i // 2)) - max(0, 5 - i),
            compliance_score=score,
            status="completed",
            triggered_by="scheduled" if i % 2 == 0 else "cli",
            created_at=audit_date
        )
        session.add(audit)
        session.flush()

        # Add findings for the latest audit
        if i == 6:
            findings = [
                Finding(
                    audit_id=audit.id,
                    rule_id="CIS-1.2",
                    rule_title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
                    severity="CRITICAL",
                    resource_address="aws_security_group.allow_ssh",
                    resource_type="aws_security_group",
                    file_path="networks.tf",
                    description="Security group 'allow_ssh' allows unrestricted SSH access from the internet.",
                    remediation_hcl='resource "aws_security_group" "allow_ssh" {\n  # ...\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = ["10.0.0.0/8"] # Restricted to internal network\n  }\n}',
                    reasoning="The security group is configured with an ingress rule that allows all traffic (0.0.0.0/0) on port 22. This exposes the instances to brute-force attacks from anywhere in the world.",
                    confidence=0.98,
                    created_at=audit_date
                ),
                Finding(
                    audit_id=audit.id,
                    rule_id="CIS-2.1",
                    rule_title="Ensure S3 buckets have public access block enabled",
                    severity="HIGH",
                    resource_address="aws_s3_bucket.user_data",
                    resource_type="aws_s3_bucket",
                    file_path="storage.tf",
                    description="S3 bucket 'user_data' is missing public access block configuration.",
                    remediation_hcl='resource "aws_s3_bucket_public_access_block" "user_data" {\n  bucket = aws_s3_bucket.user_data.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}',
                    reasoning="Without public access block, the bucket could potentially be made public, leading to data leaks of sensitive user information.",
                    confidence=0.95,
                    created_at=audit_date
                )
            ]
            for f in findings:
                session.add(f)

    # 2. Create trend snapshots
    for i in range(30):
        snap_date = now - timedelta(days=30-i)
        snap = TrendSnapshot(
            date=snap_date,
            total_audits=i+1,
            total_findings=25 - (i // 2),
            critical_count=max(0, 5 - (i // 6)),
            high_count=max(0, 8 - (i // 4)),
            medium_count=10,
            low_count=5,
            avg_compliance_score=65.0 + (i * 0.8),
            created_at=snap_date
        )
        session.add(snap)

    # 3. Create some drift alerts
    alerts = [
        DriftAlert(
            alert_type="new_violation",
            severity="CRITICAL",
            title="New Unrestricted SSH Access Detected",
            description="A new security group rule was detected allowing port 22 from 0.0.0.0/0 in 'networks.tf'.",
            resource_address="aws_security_group.allow_ssh",
            created_at=now - timedelta(hours=2)
        ),
        DriftAlert(
            alert_type="score_drop",
            severity="HIGH",
            title="Compliance Score Dropped Below 80%",
            description="The overall compliance score dropped from 84.5% to 78.2% after the last scan.",
            created_at=now - timedelta(hours=5)
        )
    ]
    for a in alerts:
        session.add(a)

    session.commit()
    print("✅ Dummy data seeded successfully!")
    session.close()

if __name__ == "__main__":
    seed_data()
