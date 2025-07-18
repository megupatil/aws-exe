variable "aws_region" {
  description = "The AWS region to deploy resources in."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "A name for the project to prefix resources."
  type        = string
  default     = "wiz-exercise"
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_az1_cidr" {
  description = "The CIDR block for the public subnet in AZ1."
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_az1_cidr" {
  description = "The CIDR block for the private subnet in AZ1."
  type        = string
  default     = "10.0.2.0/24"
}

variable "public_subnet_az2_cidr" {
  description = "The CIDR block for the public subnet in AZ2."
  type        = string
  default     = "10.0.3.0/24"
}

variable "private_subnet_az2_cidr" {
  description = "The CIDR block for the private subnet in AZ2."
  type        = string
  default     = "10.0.4.0/24"
}

# ----------------- THIS IS THE HIGHLIGHTED CHANGE -----------------
variable "db_instance_type" {
  description = "EC2 instance type for the MongoDB server."
  type        = string
  default     = "t3.medium"
}
# ------------------------------------------------------------------
