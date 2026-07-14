output "api_url" { value = "https://${aws_lb.warden.dns_name}" }
output "audit_bucket" { value = aws_s3_bucket.audit.id }
output "kms_signing_key_arn" { value = aws_kms_key.capabilities.arn }
output "database_endpoint" {
  value     = aws_db_instance.warden.address
  sensitive = true
}
