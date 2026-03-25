# ──────────────────────────────────────────────────────────────────────────────
# PARTIALLY COMPLIANT CloudTrail — Multi-region but missing log validation,
# CloudWatch integration, and KMS encryption (CIS 3.2, 3.4, 3.7)
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true

  # VIOLATION: Missing enable_log_file_validation = true (CIS 3.2)
  enable_log_file_validation = false

  # VIOLATION: Missing CloudWatch Logs integration (CIS 3.4)
  # cloud_watch_logs_group_arn = ...
  # cloud_watch_logs_role_arn  = ...

  # VIOLATION: Missing KMS encryption (CIS 3.7)
  # kms_key_id = ...

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Name        = "main-cloudtrail"
    Environment = var.environment
  }
}
