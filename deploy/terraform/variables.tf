variable "aws_region" {
  type    = string
  default = "ap-south-1"
}
variable "environment" {
  type    = string
  default = "prod"
}
variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "private_subnet_ids" { type = list(string) }
variable "container_image" { type = string }
variable "certificate_arn" { type = string }
variable "oidc_issuer" { type = string }
variable "oidc_audience" { type = string }
variable "public_url" {
  type        = string
  description = "Canonical HTTPS URL for the Warden control plane"
  validation {
    condition     = startswith(var.public_url, "https://")
    error_message = "public_url must use HTTPS."
  }
}
variable "allowed_egress_hosts" {
  type    = string
  default = ""
}
variable "desired_count" {
  type    = number
  default = 2
}
variable "database_instance_class" {
  type    = string
  default = "db.t4g.medium"
}
variable "redis_node_type" {
  type    = string
  default = "cache.t4g.small"
}
