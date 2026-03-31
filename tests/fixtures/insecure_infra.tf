# ─── Intentionally insecure Terraform for testing ────────────────────────────
# This file contains CIS Benchmark violations for Cloud-Compliance Guardian demo.

provider "aws" {
  region = "us-east-1"
}

# ══════════════════════════════════════════════════════════════════════════════
# CIS 2.1.x — S3 Bucket (multiple violations)
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_s3_bucket" "data_lake" {
  bucket = "acme-corp-data-lake"

  tags = {
    Environment = "production"
    Team        = "data-engineering"
  }
}

# Missing: aws_s3_bucket_server_side_encryption_configuration (CIS 2.1.2)
# Missing: aws_s3_bucket_public_access_block (CIS 2.1.4)
# Missing: aws_s3_bucket_versioning (CIS 2.1.5)
# Missing: aws_s3_bucket_policy denying HTTP (CIS 2.1.1)


# ══════════════════════════════════════════════════════════════════════════════
# CIS 4.1 — Security Group with SSH open to 0.0.0.0/0
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_security_group" "web_server" {
  name        = "web-server-sg"
  description = "Security group for web servers"
  vpc_id      = "vpc-12345678"

  # VIOLATION: SSH open to entire internet
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # This is OK — port 443 for HTTPS is expected for a web server
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS access"
  }

  # VIOLATION: RDP open to entire internet (CIS 4.2)
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP access"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "web-server-sg"
  }
}


# ══════════════════════════════════════════════════════════════════════════════
# CIS 2.3.x — RDS Instance (insecure)
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_db_instance" "production_db" {
  identifier     = "acme-production-db"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"

  allocated_storage = 100
  storage_type      = "gp3"

  db_name  = "acme_production"
  username = "admin"
  password = "SuperSecret123!"  # VIOLATION: hardcoded password

  # VIOLATION: Publicly accessible (CIS 2.3.2)
  publicly_accessible = true

  # VIOLATION: No encryption at rest (CIS 2.3.1)
  storage_encrypted = false

  skip_final_snapshot = true

  tags = {
    Environment = "production"
  }
}


# ══════════════════════════════════════════════════════════════════════════════
# CIS 1.22 — IAM Policy with full admin access
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_iam_policy" "admin_full_access" {
  name        = "FullAdminAccess"
  description = "Full administrative access"

  # VIOLATION: Wildcard admin access (CIS 1.22)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}


# ══════════════════════════════════════════════════════════════════════════════
# CIS 3.x — CloudTrail (incomplete config)
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_cloudtrail" "main" {
  name           = "acme-main-trail"
  s3_bucket_name = aws_s3_bucket.data_lake.id

  # VIOLATION: Not multi-region (CIS 3.1)
  is_multi_region_trail = false

  # VIOLATION: No log file validation (CIS 3.2)
  enable_log_file_validation = false

  # Missing: CloudWatch integration (CIS 3.4)
  # Missing: KMS encryption (CIS 3.7)
}


# ══════════════════════════════════════════════════════════════════════════════
# CIS 5.1 — KMS Key without rotation
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_kms_key" "app_key" {
  description = "KMS key for application encryption"

  # VIOLATION: No key rotation (CIS 5.1)
  enable_key_rotation = false

  tags = {
    Environment = "production"
  }
}


# ══════════════════════════════════════════════════════════════════════════════
# CIS 2.2.1 — EBS Volume without encryption
# ══════════════════════════════════════════════════════════════════════════════

resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-east-1a"
  size              = 500

  # VIOLATION: Not encrypted (CIS 2.2.1)
  encrypted = false

  tags = {
    Name = "data-volume"
  }
}
