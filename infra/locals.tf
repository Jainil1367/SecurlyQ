data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name       = "${var.project}-${var.environment}"
  azs        = slice(data.aws_availability_zones.available.names, 0, 2)
  bedrock_on = var.llm_provider == "bedrock"
  account_id = data.aws_caller_identity.current.account_id
}
