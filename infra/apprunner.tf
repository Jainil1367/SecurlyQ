resource "aws_apprunner_vpc_connector" "main" {
  vpc_connector_name = local.name
  subnets            = aws_subnet.private[*].id
  security_groups    = [aws_security_group.app.id]
}

resource "aws_apprunner_auto_scaling_configuration_version" "main" {
  auto_scaling_configuration_name = local.name
  min_size                        = 1
  max_size                        = 2
  max_concurrency                 = 50
}

resource "aws_apprunner_service" "backend" {
  service_name = "${local.name}-api"

  source_configuration {
    auto_deployments_enabled = false # deploys are explicit (see the deploy workflow)

    authentication_configuration {
      access_role_arn = aws_iam_role.apprunner_access.arn
    }

    image_repository {
      image_repository_type = "ECR"
      image_identifier      = "${aws_ecr_repository.backend.repository_url}:${var.image_tag}"

      image_configuration {
        port          = "8000"

        runtime_environment_variables = {
          ENVIRONMENT           = "production" # makes the app refuse a weak JWT secret
          OPEN_REGISTRATION     = "false"      # only the first admin can self-register
          LOG_LEVEL             = "INFO"
          LLM_PROVIDER          = var.llm_provider
          BEDROCK_MODEL_ID      = var.bedrock_model_id
          AWS_REGION            = var.region
          LLM_REQUESTS_PER_HOUR = tostring(var.llm_requests_per_hour)
        }

        runtime_environment_secrets = {
          DATABASE_URL = aws_secretsmanager_secret.database_url.arn
          JWT_SECRET   = aws_secretsmanager_secret.jwt.arn
        }
      }
    }
  }

  instance_configuration {
    cpu               = "512"
    memory            = "1024"
    instance_role_arn = aws_iam_role.apprunner_instance.arn
  }

  network_configuration {
    egress_configuration {
      egress_type       = "VPC"
      vpc_connector_arn = aws_apprunner_vpc_connector.main.arn
    }
  }

  health_check_configuration {
    protocol            = "HTTP"
    path                = "/health"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 1
    unhealthy_threshold = 5
  }

  auto_scaling_configuration_arn = aws_apprunner_auto_scaling_configuration_version.main.arn

  depends_on = [
    aws_iam_role_policy_attachment.apprunner_access_ecr,
    aws_iam_role_policy.instance,
    aws_secretsmanager_secret_version.database_url,
    aws_secretsmanager_secret_version.jwt,
  ]
}
