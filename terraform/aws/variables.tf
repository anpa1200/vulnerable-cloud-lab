variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Resource name prefix"
  type        = string
  default     = "vuln-lab"
}

variable "allowed_ssh_cidr" {
  description = "CIDR allowed for SSH access (default: open to all — intentional vuln)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "dvwa_admin_password" {
  description = "DVWA web admin password"
  type        = string
  default     = "password"
  sensitive   = true
}

variable "db_password" {
  description = "Database password (stored in plaintext as intentional vuln)"
  type        = string
  default     = "S3cr3tP@ssw0rd"
  sensitive   = true
}
