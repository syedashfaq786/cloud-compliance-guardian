# ──────────────────────────────────────────────────────────────────────────────
# KMS Keys — One with rotation enabled (compliant), one without (CIS 5.1)
# ──────────────────────────────────────────────────────────────────────────────

# COMPLIANT — Key rotation enabled
resource "aws_kms_key" "s3_encryption" {
  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name    = "s3-encryption-key"
    Purpose = "S3 SSE-KMS"
  }
}

resource "aws_kms_alias" "s3_encryption" {
  name          = "alias/s3-encryption"
  target_key_id = aws_kms_key.s3_encryption.key_id
}

# COMPLIANT — Key rotation enabled
resource "aws_kms_key" "rds_encryption" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name    = "rds-encryption-key"
    Purpose = "RDS encryption"
  }
}

# MISCONFIGURED — Key rotation NOT enabled (violates CIS 5.1)
resource "aws_kms_key" "ebs_encryption" {
  description             = "KMS key for EBS volume encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = false

  tags = {
    Name    = "ebs-encryption-key"
    Purpose = "EBS encryption"
  }
}
