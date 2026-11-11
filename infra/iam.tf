# Two roles, each with the least privilege it needs.

# 1) Access role: lets App Runner PULL the image from ECR.
data "aws_iam_policy_document" "apprunner_build_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["build.apprunner.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "apprunner_access" {
  name               = "${local.name}-apprunner-access"
  assume_role_policy = data.aws_iam_policy_document.apprunner_build_trust.json
}

resource "aws_iam_role_policy_attachment" "apprunner_access_ecr" {
  role       = aws_iam_role.apprunner_access.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSAppRunnerServicePolicyForECRAccess"
}

# 2) Instance role: what the running app itself may do. Read two secrets; optionally call Bedrock.
data "aws_iam_policy_document" "apprunner_tasks_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["tasks.apprunner.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "apprunner_instance" {
  name               = "${local.name}-apprunner-instance"
  assume_role_policy = data.aws_iam_policy_document.apprunner_tasks_trust.json
}

data "aws_iam_policy_document" "instance" {
  statement {
    sid       = "ReadOwnSecrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.database_url.arn, aws_secretsmanager_secret.jwt.arn]
  }

  dynamic "statement" {
    for_each = local.bedrock_on ? [1] : []
    content {
      sid     = "InvokeBedrockModels"
      actions = ["bedrock:InvokeModel"] # the Converse API is authorized by this action
      resources = [
        "arn:aws:bedrock:*::foundation-model/*",
        "arn:aws:bedrock:${var.region}:${local.account_id}:inference-profile/*",
      ]
    }
  }
}

resource "aws_iam_role_policy" "instance" {
  name   = "app-permissions"
  role   = aws_iam_role.apprunner_instance.id
  policy = data.aws_iam_policy_document.instance.json
}
