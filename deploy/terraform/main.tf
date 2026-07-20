data "aws_caller_identity" "current" {}

resource "random_password" "database" {
  length  = 40
  special = false
}
resource "random_password" "redis" {
  length  = 40
  special = false
}
resource "random_password" "break_glass" {
  length  = 48
  special = false
}

resource "aws_kms_key" "capabilities" {
  description              = "Warden capability-token signing"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_3072"
  deletion_window_in_days  = 30
  enable_key_rotation      = false
}
resource "aws_kms_alias" "capabilities" {
  name          = "alias/warden-${var.environment}-capability-signing"
  target_key_id = aws_kms_key.capabilities.key_id
}

resource "aws_s3_bucket" "audit" {
  bucket_prefix       = "warden-${var.environment}-audit-"
  object_lock_enabled = true
}
resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}

resource "aws_security_group" "database" {
  name_prefix = "warden-db-"
  vpc_id      = var.vpc_id
}
resource "aws_security_group" "redis" {
  name_prefix = "warden-redis-"
  vpc_id      = var.vpc_id
}
resource "aws_security_group" "service" {
  name_prefix = "warden-service-"
  vpc_id      = var.vpc_id
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "alb" {
  name_prefix = "warden-alb-"
  vpc_id      = var.vpc_id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.service.id]
  }
}
resource "aws_vpc_security_group_ingress_rule" "service_from_alb" {
  security_group_id            = aws_security_group.service.id
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = 8000
  to_port                      = 8000
  ip_protocol                  = "tcp"
}
resource "aws_vpc_security_group_ingress_rule" "database_from_service" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.service.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}
resource "aws_vpc_security_group_ingress_rule" "redis_from_service" {
  security_group_id            = aws_security_group.redis.id
  referenced_security_group_id = aws_security_group.service.id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}
resource "aws_vpc_security_group_egress_rule" "service_to_database" {
  security_group_id            = aws_security_group.service.id
  referenced_security_group_id = aws_security_group.database.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}
resource "aws_vpc_security_group_egress_rule" "service_to_redis" {
  security_group_id            = aws_security_group.service.id
  referenced_security_group_id = aws_security_group.redis.id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_db_subnet_group" "warden" {
  name_prefix = "warden-"
  subnet_ids  = var.private_subnet_ids
}
resource "aws_db_instance" "warden" {
  identifier_prefix            = "warden-${var.environment}-"
  engine                       = "postgres"
  instance_class               = var.database_instance_class
  allocated_storage            = 30
  max_allocated_storage        = 250
  db_name                      = "warden"
  username                     = "warden"
  password                     = random_password.database.result
  db_subnet_group_name         = aws_db_subnet_group.warden.name
  vpc_security_group_ids       = [aws_security_group.database.id]
  multi_az                     = true
  storage_encrypted            = true
  backup_retention_period      = 14
  deletion_protection          = true
  skip_final_snapshot          = false
  final_snapshot_identifier    = "warden-${var.environment}-final"
  publicly_accessible          = false
  auto_minor_version_upgrade   = true
  performance_insights_enabled = true
}

resource "aws_elasticache_subnet_group" "warden" {
  name       = "warden-${var.environment}"
  subnet_ids = var.private_subnet_ids
}
resource "aws_elasticache_replication_group" "warden" {
  replication_group_id       = "warden-${var.environment}"
  description                = "Warden distributed limits and ephemeral state"
  node_type                  = var.redis_node_type
  num_cache_clusters         = 2
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.warden.name
  security_group_ids         = [aws_security_group.redis.id]
  automatic_failover_enabled = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis.result
  snapshot_retention_limit   = 7
}

locals {
  database_url = "postgresql://warden:${random_password.database.result}@${aws_db_instance.warden.address}:5432/warden?sslmode=require"
  redis_url    = "rediss://:${random_password.redis.result}@${aws_elasticache_replication_group.warden.primary_endpoint_address}:6379/0"
}
resource "aws_secretsmanager_secret" "runtime" { name = "/warden/${var.environment}/runtime" }
resource "aws_secretsmanager_secret_version" "runtime" {
  secret_id = aws_secretsmanager_secret.runtime.id
  secret_string = jsonencode({
    DATABASE_URL            = local.database_url
    REDIS_URL               = local.redis_url
    CONTROL_PLANE_ADMIN_KEY = random_password.break_glass.result
  })
}

resource "aws_ecs_cluster" "warden" { name = "warden-${var.environment}" }
resource "aws_cloudwatch_log_group" "warden" {
  name              = "/ecs/warden-${var.environment}"
  retention_in_days = 30
}
resource "aws_iam_role" "execution" {
  name_prefix        = "warden-execution-"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}
resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
resource "aws_iam_role_policy" "execution_secrets" {
  role   = aws_iam_role.execution.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.runtime.arn }] })
}
resource "aws_iam_role" "task" {
  name_prefix        = "warden-task-"
  assume_role_policy = aws_iam_role.execution.assume_role_policy
}
resource "aws_iam_role_policy" "task" {
  role = aws_iam_role.task.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["kms:GetPublicKey", "kms:Sign"], Resource = aws_kms_key.capabilities.arn },
    { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${aws_s3_bucket.audit.arn}/audit-anchors/*" },
    { Effect = "Allow", Action = ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"], Resource = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:/warden/${var.environment}/connectors/*" },
    { Effect = "Allow", Action = ["secretsmanager:CreateSecret"], Resource = "*", Condition = { StringLike = { "secretsmanager:Name" = "/warden/${var.environment}/connectors/*" } } }
  ] })
}

resource "aws_lb" "warden" {
  name_prefix        = "wrdn-"
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids
  security_groups    = [aws_security_group.alb.id]
}
resource "aws_lb_target_group" "warden" {
  name_prefix = "wrdn-"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"
  health_check {
    path    = "/health"
    matcher = "200"
  }
}
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.warden.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.warden.arn
  }
}

resource "aws_ecs_task_definition" "warden" {
  family                   = "warden-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  container_definitions = jsonencode([{
    name         = "warden", image = var.container_image, essential = true, readonlyRootFilesystem = true,
    portMappings = [{ containerPort = 8000, protocol = "tcp" }],
    environment = [
      { name = "CONTROL_PLANE_ENV", value = "prod" }, { name = "AWS_REGION", value = var.aws_region },
      { name = "WARDEN_PUBLIC_URL", value = var.public_url },
      { name = "WARDEN_SIGNING_PROVIDER", value = "aws_kms" },
      { name = "WARDEN_SECRETS_PROVIDER", value = "aws_secrets_manager" },
      { name = "WARDEN_AUDIT_PROVIDER", value = "aws_s3" },
      { name = "WARDEN_SIGNING_KEY_ID", value = aws_kms_key.capabilities.arn },
      { name = "WARDEN_SECRETS_PREFIX", value = "/warden/${var.environment}/connectors" },
      { name = "WARDEN_AUDIT_TARGET", value = aws_s3_bucket.audit.id },
      { name = "WARDEN_PROVIDER_REGION", value = var.aws_region },
      { name = "WARDEN_OIDC_ISSUER", value = var.oidc_issuer }, { name = "WARDEN_OIDC_AUDIENCE", value = var.oidc_audience },
      { name = "CONTROL_PLANE_ISSUER", value = "warden-${var.environment}" }, { name = "CONTROL_PLANE_AUDIENCE", value = "warden-action-gateway" },
      { name = "CONTROL_PLANE_ALLOWED_EGRESS_HOSTS", value = var.allowed_egress_hosts }
    ],
    secrets = [
      { name = "DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.runtime.arn}:DATABASE_URL::" },
      { name = "REDIS_URL", valueFrom = "${aws_secretsmanager_secret.runtime.arn}:REDIS_URL::" },
      { name = "CONTROL_PLANE_ADMIN_KEY", valueFrom = "${aws_secretsmanager_secret.runtime.arn}:CONTROL_PLANE_ADMIN_KEY::" }
    ],
    logConfiguration = { logDriver = "awslogs", options = { "awslogs-group" = aws_cloudwatch_log_group.warden.name, "awslogs-region" = var.aws_region, "awslogs-stream-prefix" = "app" } },
    healthCheck      = { command = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)\""], interval = 30, timeout = 5, retries = 3, startPeriod = 20 }
  }])
}
resource "aws_ecs_service" "warden" {
  name                               = "warden-${var.environment}"
  cluster                            = aws_ecs_cluster.warden.id
  task_definition                    = aws_ecs_task_definition.warden.arn
  desired_count                      = var.desired_count
  launch_type                        = "FARGATE"
  platform_version                   = "LATEST"
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  enable_execute_command             = false
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.service.id]
    assign_public_ip = false
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.warden.arn
    container_name   = "warden"
    container_port   = 8000
  }
  depends_on = [aws_lb_listener.https]
}
