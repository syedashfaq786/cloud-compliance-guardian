# ──────────────────────────────────────────────────────────────────────────────
# Lambda Functions — Additional resources for scanning
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_lambda_function" "data_processor" {
  function_name = "data-processor"
  runtime       = "python3.11"
  handler       = "handler.process"
  role          = aws_iam_role.app_role.arn
  filename      = "lambda.zip"
  timeout       = 300
  memory_size   = 512

  environment {
    variables = {
      ENVIRONMENT = var.environment
      DB_ENDPOINT = aws_db_instance.analytics_db.endpoint
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Name        = "data-processor"
    Environment = var.environment
  }
}

resource "aws_lambda_function" "api_handler" {
  function_name = "api-handler"
  runtime       = "nodejs18.x"
  handler       = "index.handler"
  role          = aws_iam_role.app_role.arn
  filename      = "api.zip"
  timeout       = 30
  memory_size   = 256

  tags = {
    Name        = "api-handler"
    Environment = var.environment
  }
}
