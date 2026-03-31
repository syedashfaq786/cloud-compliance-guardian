# ──────────────────────────────────────────────────────────────────────────────
# IAM — Mix of compliant and misconfigured policies
# ──────────────────────────────────────────────────────────────────────────────

# COMPLIANT — Least-privilege policy attached to a role
resource "aws_iam_role" "app_role" {
  name = "app-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "App Service Role"
  }
}

resource "aws_iam_role_policy" "app_s3_access" {
  name = "app-s3-read-only"
  role = aws_iam_role.app_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        aws_s3_bucket.audit_logs.arn,
        "${aws_s3_bucket.audit_logs.arn}/*"
      ]
    }]
  })
}

# MISCONFIGURED — Full admin access policy (violates CIS 1.22)
resource "aws_iam_policy" "admin_full_access" {
  name        = "full-admin-access"
  description = "Full administrative access - DO NOT USE IN PRODUCTION"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# MISCONFIGURED — Policy directly attached to user (violates CIS 1.16)
resource "aws_iam_user" "developer" {
  name = "developer-john"
  path = "/developers/"

  tags = {
    Team = "Engineering"
  }
}

resource "aws_iam_user_policy_attachment" "developer_direct" {
  user       = aws_iam_user.developer.name
  policy_arn = aws_iam_policy.admin_full_access.arn
}

# COMPLIANT — IAM password policy
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}
