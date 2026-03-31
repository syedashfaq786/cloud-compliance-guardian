output "vpc_id" {
  description = "ID of the main VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_id" {
  description = "ID of the public subnet"
  value       = aws_subnet.public_a.id
}

output "rds_endpoint" {
  description = "RDS database endpoint"
  value       = aws_db_instance.analytics_db.endpoint
}

output "s3_audit_bucket" {
  description = "S3 audit logs bucket name"
  value       = aws_s3_bucket.audit_logs.id
}
