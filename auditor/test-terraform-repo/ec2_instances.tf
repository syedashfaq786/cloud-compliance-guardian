# ──────────────────────────────────────────────────────────────────────────────
# EC2 Instances — One with unencrypted EBS (CIS 2.2.1), one compliant
# ──────────────────────────────────────────────────────────────────────────────

# MISCONFIGURED — Root EBS volume not encrypted
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.public_a.id

  vpc_security_group_ids = [aws_security_group.web_server_bad.id]

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = false  # VIOLATION: CIS 2.2.1
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"  # Should be "required" for IMDSv2
  }

  tags = {
    Name        = "web-server-01"
    Environment = var.environment
  }
}

# COMPLIANT — Encrypted root volume, IMDSv2 enforced
resource "aws_instance" "app_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.large"
  subnet_id     = aws_subnet.private_a.id

  vpc_security_group_ids = [aws_security_group.bastion.id]
  iam_instance_profile   = aws_iam_role.app_role.name

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
    encrypted   = true
    kms_key_id  = aws_kms_key.ebs_encryption.arn
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name        = "app-server-01"
    Environment = var.environment
    Encrypted   = "true"
  }
}
