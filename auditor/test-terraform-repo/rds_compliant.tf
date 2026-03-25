# ──────────────────────────────────────────────────────────────────────────────
# COMPLIANT RDS — Encrypted, private, properly configured
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_db_instance" "analytics_db" {
  identifier     = "analytics-db-prod"
  engine         = "postgresql"
  engine_version = "15.4"
  instance_class = "db.r6g.large"

  allocated_storage     = 200
  max_allocated_storage = 1000

  db_name  = "analytics"
  username = "analytics_admin"
  password = var.db_password

  publicly_accessible = false
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.rds_encryption.arn

  multi_az               = true
  skip_final_snapshot    = false
  backup_retention_period = 30
  deletion_protection    = true

  vpc_security_group_ids = [aws_security_group.bastion.id]
  db_subnet_group_name   = aws_db_subnet_group.private.name

  tags = {
    Name        = "analytics-db"
    Environment = var.environment
    Encrypted   = "true"
  }
}

resource "aws_db_subnet_group" "private" {
  name       = "private-db-subnet-group"
  subnet_ids = [aws_subnet.private_a.id]

  tags = {
    Name = "Private DB Subnet Group"
  }
}
