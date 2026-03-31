# ──────────────────────────────────────────────────────────────────────────────
# MISCONFIGURED RDS — Publicly accessible, no encryption (CIS 2.3.1, 2.3.2)
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_db_instance" "app_database" {
  identifier     = "app-database-prod"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.medium"

  allocated_storage     = 100
  max_allocated_storage = 500

  db_name  = "application"
  username = "admin"
  password = var.db_password

  # VIOLATION: publicly_accessible = true (CIS 2.3.2)
  publicly_accessible = true

  # VIOLATION: storage_encrypted = false (CIS 2.3.1)
  storage_encrypted = false

  multi_az               = false
  skip_final_snapshot    = true
  backup_retention_period = 7

  vpc_security_group_ids = [aws_security_group.web_server_bad.id]

  tags = {
    Name        = "app-database"
    Environment = var.environment
  }
}
