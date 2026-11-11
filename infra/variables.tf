variable "region" {
  description = "AWS region for everything."
  type        = string
  default     = "us-east-2"
}

variable "project" {
  description = "Name prefix for every resource."
  type        = string
  default     = "securlyq"
}

variable "environment" {
  description = "Environment label (used in tags and names)."
  type        = string
  default     = "prod"
}

variable "alert_email" {
  description = "Email that receives CloudWatch alarm and budget notifications."
  type        = string
}

variable "monthly_budget_usd" {
  description = "AWS Budget limit. You are emailed at 80% of actual and 100% of forecasted spend."
  type        = number
  default     = 40
}

variable "image_tag" {
  description = "Backend image tag in ECR that App Runner runs."
  type        = string
  default     = "latest"
}

variable "db_instance_class" {
  description = "RDS instance size. db.t4g.micro is the smallest sensible choice."
  type        = string
  default     = "db.t4g.micro"
}

variable "enable_deletion_protection" {
  description = "Block accidental deletion of the database. Set to false only when tearing everything down."
  type        = bool
  default     = true
}

variable "llm_provider" {
  description = "\"disabled\" (template explanations) or \"bedrock\". Start disabled; switch after Bedrock model access is granted."
  type        = string
  default     = "disabled"

  validation {
    condition     = contains(["disabled", "bedrock"], var.llm_provider)
    error_message = "llm_provider must be \"disabled\" or \"bedrock\"."
  }
}

variable "bedrock_model_id" {
  description = "Exact model or inference-profile ID copied from the Bedrock console (required when llm_provider = bedrock)."
  type        = string
  default     = ""

  validation {
    condition     = var.llm_provider != "bedrock" || length(var.bedrock_model_id) > 0
    error_message = "Set bedrock_model_id when llm_provider is \"bedrock\"."
  }
}

variable "llm_requests_per_hour" {
  description = "Per-user cap on real model calls (cost control)."
  type        = number
  default     = 30
}
