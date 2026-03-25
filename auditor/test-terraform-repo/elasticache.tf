# ──────────────────────────────────────────────────────────────────────────────
# ElastiCache — Redis cluster for caching
# ──────────────────────────────────────────────────────────────────────────────

resource "aws_elasticache_cluster" "session_cache" {
  cluster_id           = "session-cache"
  engine               = "redis"
  node_type            = "cache.t3.medium"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379

  # No encryption at rest or in transit configured
  tags = {
    Name        = "session-cache"
    Environment = var.environment
  }
}
