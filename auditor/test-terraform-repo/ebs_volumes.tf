# ──────────────────────────────────────────────────────────────────────────────
# EBS Volumes — One encrypted (compliant), one not (CIS 2.2.1)
# ──────────────────────────────────────────────────────────────────────────────

# MISCONFIGURED — No encryption
resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-east-1a"
  size              = 500
  type              = "gp3"
  encrypted         = false  # VIOLATION: CIS 2.2.1

  tags = {
    Name        = "data-volume"
    Environment = var.environment
  }
}

# COMPLIANT — Encrypted with KMS
resource "aws_ebs_volume" "backup_volume" {
  availability_zone = "us-east-1a"
  size              = 200
  type              = "gp3"
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs_encryption.arn

  tags = {
    Name        = "backup-volume"
    Environment = var.environment
    Encrypted   = "true"
  }
}
