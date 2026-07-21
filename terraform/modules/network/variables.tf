variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.0.1.0/24"
}

variable "availability_zone" {
  type    = string
  default = "ap-southeast-1a"
}

variable "project_name" {
  type = string
}

variable "my_ip_cidr" {
  description = "Your IP address for SSH access, format: x.x.x.x/32"
  type        = string
}

variable "proxy_cidr" {
  description = "CIDR block of the on-premise forward proxy, the only permitted source for inbound HTTPS API traffic"
  type        = string
}