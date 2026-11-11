output "app_url" {
  description = "Open this: the dashboard and API (same origin)."
  value       = "https://${aws_cloudfront_distribution.main.domain_name}"
}

output "ecr_repository_url" {
  description = "Push the backend image here."
  value       = aws_ecr_repository.backend.repository_url
}

output "apprunner_service_arn" {
  description = "Used by the deploy workflow to start a deployment."
  value       = aws_apprunner_service.backend.arn
}

output "frontend_bucket" {
  description = "Upload the built dashboard (frontend/dist) here."
  value       = aws_s3_bucket.frontend.bucket
}

output "cloudfront_distribution_id" {
  description = "Invalidate this after uploading a new frontend build."
  value       = aws_cloudfront_distribution.main.id
}
