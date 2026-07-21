variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "ap-southeast-1"
}

variable "project_name" {
  description = "Project name used for tagging resources"
  type        = string
  default     = "hybrid-cloud-starter"
}

variable "my_ip_cidr" {
  description = "Your IP address for SSH access, format: x.x.x.x/32. Override via terraform.tfvars locally, or TF_VAR_my_ip_cidr in CI."
  type        = string
  default     = "203.0.113.0/32"  # TEST-NET-3 placeholder (RFC 5737) — not a real IP, safe for public repo/CI default
}

variable "proxy_cidr" {
  description = "CIDR block of the on-premise forward proxy. Override via terraform.tfvars locally, or TF_VAR_proxy_cidr in CI."
  type        = string
  default     = "203.0.113.0/32"  # Same placeholder — represents the simulated proxy IP for this demo
}