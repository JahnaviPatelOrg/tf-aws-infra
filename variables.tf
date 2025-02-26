
variable "aws_profile" {
  description = "The AWS CLI profile to use"
  type        = string
}

variable "aws_region" {
  description = "The AWS region to deploy to"
  type        = string
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC"
  type        = string
}

variable "vpc_name" {
  description = "The name of the VPC"
  type        = string
}

variable "public_subnets" {
  description = "List of public subnet CIDR blocks"
  type        = list(string)
}

variable "private_subnets" {
  description = "List of private subnet CIDR blocks"
  type        = list(string)
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
}

variable "https_port" {
  description = "The HTTPS port to allow"
    type        = number
    default     = 443
}

variable "ssh_port" {
  description = "The SSH port to allow"
  type        = number
  default     = 22
}

variable "http_port" {
  description = "The HTTP port to allow"
  type        = number
  default     = 80
}

variable "app_port" {
  description = "The application port to allow"
  type        = number
  default     = 8000
}

variable "custom_ami_id" {
  description = "The ID of the custom AMI to use."

}


variable "instance_type" {
  description = "The type of EC2 instance."
  default     = "t2.micro" // Adjust according to your needs
}

variable "key_name" {
  description = "The name of the key pair to use for SSH access."
  default     = "ubuntu"
}

# volume_type
variable "volume_type" {
  description = "The type of volume to use for the EC2 instance."
  default     = "gp2"
}

# volume_size
variable "volume_size" {
  description = "The size of the volume in GB."
  default     = 8
}