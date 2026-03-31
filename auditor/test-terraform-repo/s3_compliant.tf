# ──────────────────────────────────────────────────────────────────────────────
# COMPLIANT S3 Bucket — Properly configured with encryption, versioning,
# public access block, and logging
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "audit_logs" {
  bucket = "company-audit-logs-prod"

  tags = {
    Name        = "Audit Logs"
    Environment = var.environment
    Compliance  = "CIS-2.1"
  }
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_encryption.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  target_bucket = aws_s3_bucket.audit_logs.id
  target_prefix = "access-logs/"
}
