output "ecr_repository_url" {
  value       = aws_ecr_repository.app.repository_url
  description = "Push the image here, then ECS will pull it."
}

output "service_url" {
  value       = "http://${aws_lb.app.dns_name}"
  description = "Public ALB URL. Probe /health once the service stabilizes."
}

output "region" {
  value = var.region
}
