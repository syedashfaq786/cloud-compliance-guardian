# ──────────────────────────────────────────────────────────────────────────────
# MISCONFIGURED S3 Bucket — Missing encryption, no versioning,
# no public access block (multiple CIS violations)
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "data_lake" {
  bucket = "company-data-lake-raw"

  tags = {
    Name        = "Data Lake Raw"
    Environment = var.environment
  }
}

# No versioning configured — violates CIS 2.1.5
# No server-side encryption — violates CIS 2.1.2
# No public access block — violates CIS 2.1.4
