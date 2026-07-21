variable "instance_type" {
  type    = string
  default = "t2.micro"  # Free tier eligible
}

variable "subnet_id" {
  type = string
}

variable "security_group_id" {
  type = string
}

variable "project_name" {
  type = string
}

variable "key_name" {
  description = "Name of an existing EC2 key pair for SSH access"
  type        = string
}