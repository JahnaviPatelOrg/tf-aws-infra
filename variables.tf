
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

variable "db_password" {
  description = "The password for the database."
  type        = string
  sensitive   = true
}

variable "db_user" {
  description = "The username for the database."
  type        = string
}

variable "db_name" {
  description = "The name of the database."
  type        = string
}

variable "identifier" {
  description = "The identifier for the database."
  type        = string
}

variable "secret_key" {
  description = "The secret key for the application."
  type        = string
  sensitive   = true
}

# route53_zone_id
variable "route53_zone_id" {
  description = "The Route 53 zone ID."
  type        = string
}

# # min_size
# variable "min_size" {
#   description = "The minimum size of the Auto Scaling group."
#   type        = number
#   default     = 3
# }
#
# # max_size
# variable "max_size" {
#   description = "The maximum size of the Auto Scaling group."
#   type        = number
#   default     = 5
# }
#
# # desired_capacity
# variable "desired_capacity" {
#   description = "The desired capacity of the Auto Scaling group."
#   type        = number
#   default     = 3
# }
#
# # health_check_grace_period
# variable "health_check_grace_period" {
#   description = "The amount of time, in seconds, that Auto Scaling waits before checking the health status of an instance."
#   type        = number
#   default     = 300
# }
#
# # health_check_interval
# variable "health_check_interval" {
#   description = "The interval between health checks."
#   type        = number
#   default     = 60
# }
#
# # health_check_timeout
# variable "health_check_timeout" {
#   description = "The timeout for health checks."
#   type        = number
#   default     = 5
# }
#
# # healthy_threshold
# variable "healthy_threshold" {
#   description = "The number of consecutive successful health checks required before considering the target healthy."
#   type        = number
#   default     = 5
# }
#
# # unhealthy_threshold
# variable "unhealthy_threshold" {
#   description = "The number of consecutive failed health checks required before considering the target unhealthy."
#   type        = number
#   default     = 2
# }
#
# variable "evaluation_periods" {
#   description = "The number of periods over which data is compared to the specified threshold."
#   type        = number
#   default     = 1
# }
#
# variable "cooldown_period" {
#   description = "The length of time associated with a specific CloudWatch statistic."
#   type        = number
#   default     = 60
# }
#
# # threshold_scale_up
# variable "threshold_scale_up" {
#   description = "The threshold for scaling up."
#   type        = number
#   default     = 5
# }
#
# # threshold_scale_down
# variable "threshold_scale_down" {
#   description = "The threshold for scaling down."
#   type        = number
#   default     = 3
# }

