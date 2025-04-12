# creating vpc
resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr

  tags = {
    Name = var.vpc_name
  }
}

data "aws_caller_identity" "current" {}

# creating 3 public subnets in different availability zones
resource "aws_subnet" "public" {
  count             = length(var.public_subnets)
  vpc_id            = aws_vpc.main.id
  cidr_block        = element(var.public_subnets, count.index)
  availability_zone = element(var.availability_zones, count.index)

  tags = {
    Name = "${var.vpc_name}-public-subnet-${count.index + 1}"
  }
}

# creating 3 private subnets in different availability zones
resource "aws_subnet" "private" {
  count             = length(var.private_subnets)
  vpc_id            = aws_vpc.main.id
  cidr_block        = element(var.private_subnets, count.index)
  availability_zone = element(var.availability_zones, count.index)
  tags = {
    Name = "${var.vpc_name}-private-subnet-${count.index + 1}"
  }
}

# Set up Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.vpc_name}-igw"
  }
}

# Set up public route table
resource "aws_route_table" "second_rt" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${var.vpc_name}-public-route-table"
  }
}

# Attach all public subnets created to the route table.
resource "aws_route_table_association" "public_subnet_asso" {
  count          = length(var.public_subnets)
  subnet_id      = element(aws_subnet.public.*.id, count.index)
  route_table_id = aws_route_table.second_rt.id
}

# create a private route table (no internet access)
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.vpc_name}-private-route-table"
  }
}

# Attach all private subnets created to the route table.
resource "aws_route_table_association" "private_subnet_asso" {
  count          = length(var.private_subnets)
  subnet_id      = element(aws_subnet.private.*.id, count.index)
  route_table_id = aws_route_table.private.id
}


# Create a security group for the web server
resource "aws_security_group" "web_sg" {
  name        = "application security group"
  description = "Allow only necessary traffic"
  vpc_id      = aws_vpc.main.id

  # Ingress rule for SSH (port 22)
  ingress {
    from_port = var.ssh_port
    to_port   = var.ssh_port
    protocol  = "tcp"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }

  #   Ingree for application port
  ingress {
    from_port = var.app_port
    to_port   = var.app_port
    protocol  = "tcp"
    security_groups = [
      aws_security_group.lb_sg.id
    ]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }
  tags = {
    Name = "${var.vpc_name}-web-sg"
  }
}



# iam instance profile
resource "aws_iam_role" "ec2_role" {
  name = "${var.vpc_name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
      }
    ]
  })
}

# attach policy to the role
resource "aws_iam_role_policy_attachment" "ec2_policy_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"

}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "${var.vpc_name}-ec2-instance-profile"
  role = aws_iam_role.ec2_role.name
}

# S3 Bucket

# TODO-add this private S3 bucket with a bucket name being a UUID. -${uuid()}
# terraform can delete the bucket even if it is not empty
resource "aws_s3_bucket" "private_bucket" {
  bucket        = "${var.vpc_name}-private-bucket"
  force_destroy = true

  tags = {
    Name = "${var.vpc_name}-private-bucket"
  }

  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_encryption" {
  bucket = aws_s3_bucket.private_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_kms.key_id
    }
  }
}

# set up a lifecycle policy for the bucket's data. This policy transitions the data to the STANDARD_IA storage class after 30 days
resource "aws_s3_bucket_lifecycle_configuration" "lifecycle_policy" {
  bucket = aws_s3_bucket.private_bucket.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

# DB Security Group

# Create a security group for the database
resource "aws_security_group" "db_sg" {
  name        = "database-security-group"
  description = "Allow MySQL access"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.web_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "db-security-group"

  }
}

# aws_db_subnet_group for all private subnets
resource "aws_db_subnet_group" "main" {
  name       = "rds-private-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name        = "rds-private-subnet-group"
    Environment = var.aws_profile
  }
}

# parameter group for MySQL
resource "aws_db_parameter_group" "rds_param_group" {
  name        = "rds-parameter-group"
  family      = "mysql8.0"
  description = "Parameter group for MySQL"
}

# RDS Instance
resource "aws_db_instance" "db_instance" {
  identifier             = var.identifier
  instance_class         = "db.t3.micro"
  engine                 = "mysql"
  engine_version         = "8.0"
  multi_az               = false
  username               = var.db_user
  password               = random_password.db_password.result
  db_subnet_group_name   = aws_db_subnet_group.main.name
  publicly_accessible    = false
  db_name                = var.db_name
  allocated_storage      = 10
  skip_final_snapshot    = true
  parameter_group_name   = aws_db_parameter_group.rds_param_group.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.rds_kms.arn
}

# IAM Policy for S3 Access
resource "aws_iam_policy" "s3_access_policy" {
  name        = "S3AccessPolicy"
  description = "Policy to allow EC2 to access S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ],
        Resource = [
          aws_s3_bucket.private_bucket.arn,
          "${aws_s3_bucket.private_bucket.arn}/*"
        ]
      },
      {
        Action = [
          "rds:*",
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}


# attach the policy to the role
resource "aws_iam_role_policy_attachment" "s3_access_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.s3_access_policy.arn
}

resource "aws_iam_policy" "cloudwatch_policy" {
  name        = "CloudWatchAgentServerPolicy-${var.vpc_name}"
  description = "Permissions for CloudWatch Agent"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "cloudwatch:PutMetricData",
          "ec2:DescribeVolumes",
          "ec2:DescribeTags",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups",
          "logs:CreateLogStream",
          "logs:CreateLogGroup"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "ssm:GetParameter",
          "ssm:PutParameter"
        ],
        Resource = "arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"
      }
    ]
  })
}


# Attach CloudWatch policy to the EC2 role
resource "aws_iam_role_policy_attachment" "cloudwatch_policy_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.cloudwatch_policy.arn
}


# Load Balancer Security Group
resource "aws_security_group" "lb_sg" {
  name        = "load-balancer-security-group"
  description = "Allow HTTP and HTTPS traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "load-balancer-sg"
  }
}

resource "aws_launch_template" "my_launch_template" {
  name_prefix   = "my_launch_template_"
  image_id      = var.custom_ami_id
  instance_type = "t3.micro"
  key_name      = var.key_name

  network_interfaces {
    device_index                = 0
    associate_public_ip_address = true
    security_groups             = [aws_security_group.web_sg.id]
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_instance_profile.name
  }

  user_data = base64encode(<<-EOF
            #!/bin/bash
            # Update packages
            sudo apt-get update -y

            # Install jq for JSON parsing if not already available
            sudo apt-get install -y jq unzip curl

            # Download the AWS CLI installation script
            curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"

            # Unzip the installer
            unzip awscliv2.zip

            # Install AWS CLI
            sudo ./aws/install

            # Verify installation
            if ! aws --version; then
              echo "AWS CLI installation failed" >> /var/log/aws_cli_install.log
              exit 1
            fi

            # Fetch the secret JSON from Secrets Manager
            SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id ${aws_secretsmanager_secret.db_password_secret.name} --query SecretString --output text)


            # Parse values from JSON and export to env file
            DB_PASS=$(echo $SECRET_JSON | jq -r .password)
            echo "DB_PASS=$DB_PASS" | sudo tee -a /etc/.env > /dev/null



            # Database and app environment variables
            sudo bash -c 'echo "DB_HOST=${aws_db_instance.db_instance.address}" >> /etc/.env'
            sudo bash -c 'echo "DB_USER=${var.db_user}" >> /etc/.env'

            sudo bash -c 'echo "DB_NAME=${var.db_name}" >> /etc/.env'
            sudo bash -c 'echo "SECRET_KEY=${var.secret_key}" >> /etc/.env'
            sudo bash -c 'echo "S3_BUCKET_NAME=${aws_s3_bucket.private_bucket.bucket}" >> /etc/.env'
            sudo bash -c 'echo "VM_IP=\'*\'" >> /etc/.env'

            # Configure and start CloudWatch agent
            sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s
            sudo systemctl enable amazon-cloudwatch-agent
            sudo systemctl restart amazon-cloudwatch-agent

            # Enable the web application service
            sudo systemctl daemon-reload
            sudo systemctl enable webapp
            sudo systemctl start webapp.service
            sleep 30
            sudo systemctl restart webapp.service
          EOF
  )

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = var.volume_size
      volume_type           = var.volume_type
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.ec2_kms.arn
    }
  }
}

resource "aws_autoscaling_group" "my_autoscaling_group" {
  launch_template {
    id      = aws_launch_template.my_launch_template.id
    version = "$Latest"
  }

  min_size                  = 3
  max_size                  = 5
  desired_capacity          = 3
  health_check_grace_period = 300
  vpc_zone_identifier       = aws_subnet.public[*].id

  target_group_arns = [aws_lb_target_group.app_tg.arn]

  tag {
    key                 = "Name"
    value               = "csye6225_asg"
    propagate_at_launch = true
  }

  tag {
    key                 = "AutoScalingGroup"
    value               = "TagPropertyLinks"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_policy" "scale_up" {
  name                   = "scale_up_policy"
  autoscaling_group_name = aws_autoscaling_group.my_autoscaling_group.name
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  policy_type            = "SimpleScaling"
}

resource "aws_autoscaling_policy" "scale_down" {
  name                   = "scale_down_policy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.my_autoscaling_group.name
  scaling_adjustment     = -1
  policy_type            = "SimpleScaling"
}

# setup an Application Load Balancer (ALB)
resource "aws_lb" "app_lb" {
  name               = "${var.vpc_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_sg.id]
  subnets            = aws_subnet.public[*].id

  tags = {
    Name = "${var.vpc_name}-alb"
  }
}

resource "aws_lb_target_group" "app_tg" {
  name     = "${var.vpc_name}-tg"
  port     = var.app_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/healthz"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }

  tags = {
    Name = "${var.vpc_name}-tg"
  }
}



resource "aws_route53_record" "webapp_a_record" {
  name    = "${var.aws_profile}.glitchgetaway.me"
  type    = "A"
  zone_id = var.route53_zone_id

  alias {
    name                   = aws_lb.app_lb.dns_name
    zone_id                = aws_lb.app_lb.zone_id
    evaluate_target_health = true
  }
}

# when ec2 instance cpu utilization is greater than 5% for 2 minutes, scale up
resource "aws_cloudwatch_metric_alarm" "scale_up_alarm" {
  alarm_name          = "${var.vpc_name}-scale-up-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 5
  alarm_description   = "This metric monitors ec2 cpu utilization"
  alarm_actions       = [aws_autoscaling_policy.scale_up.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.my_autoscaling_group.name
  }
}

# iam policy for certificate
resource "aws_iam_policy" "certificate_policy" {
  name        = "CertificatePolicy"
  description = "Policy to allow EC2 to access ACM certificate"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "acm:RequestCertificate",
          "acm:DescribeCertificate",
          "acm:DeleteCertificate",
          "acm:AddTagsToCertificate",
          "acm:ListCertificates"
        ],
        Resource = "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "secretsmanager:CreateSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:UpdateSecret",
          "secretsmanager:DeleteSecret",
          "secretsmanager:ListSecrets"
        ],
        "Resource" : "arn:aws:secretsmanager:*:*:secret:*"
      }
    ]
  })
}

# Attach the policy to the role
resource "aws_iam_role_policy_attachment" "certificate_policy_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.certificate_policy.arn
}

# when ec2 instance cpu utilization is less than 3% for 2 minutes, scale down
resource "aws_cloudwatch_metric_alarm" "scale_down_alarm" {
  alarm_name          = "${var.vpc_name}-scale-down-alarm"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 3
  alarm_description   = "This metric monitors ec2 cpu utilization"
  alarm_actions       = [aws_autoscaling_policy.scale_down.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.my_autoscaling_group.name
  }
}

# Request and validate an SSL certificate from AWS Certificate Manager (ACM)
resource "aws_acm_certificate" "webapp_cert" {
  domain_name       = "${var.aws_profile}.glitchgetaway.me"
  validation_method = "DNS"

  tags = {
    Name = "${var.aws_profile}-webapp-cert"
  }
}

# Associate the SSL certificate with the ALB listener
resource "aws_lb_listener_certificate" "webapp_cert_association" {
  listener_arn    = aws_lb_listener.app_listener.arn
  certificate_arn = var.certificate_arn
}

resource "aws_lb_listener" "app_listener" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = var.https_port
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}

# RDS password in Terraform
resource "random_password" "db_password" {
  length           = 16
  special          = true
  override_special = "_%!"
}

# Create a secret in AWS Secrets Manager
resource "aws_secretsmanager_secret" "db_password_secret" {
  name        = "${var.vpc_name}-db-password-${uuid()}"
  description = "Database password for RDS instance"
  kms_key_id  = aws_kms_key.secrets_kms.key_id
}

# Store the generated password in the secret
resource "aws_secretsmanager_secret_version" "db_password_secret_version" {
  secret_id = aws_secretsmanager_secret.db_password_secret.id
  secret_string = jsonencode({
    password = random_password.db_password.result
  })
}

# encryption keys for secrets manager
resource "aws_kms_key" "secrets_kms" {
  description             = "KMS for Secrets Manager encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 10
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowRootAccountAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid    = "AllowSecretsManagerAccess",
        Effect = "Allow",
        Principal = {
          Service = "secretsmanager.amazonaws.com"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      },
      {
        Sid    = "AllowEC2AppAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:role/${aws_iam_role.ec2_role.name}"
        },
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ],
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.vpc_name}-secrets-kms"
    Environment = var.aws_profile
  }
}

resource "aws_kms_key" "rds_kms" {
  description             = "My KMS Key for RDS Encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 10
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowRootAccountAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid    = "AllowRDSAccess",
        Effect = "Allow",
        Principal = {
          Service = "rds.amazonaws.com"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      },
      {
        Sid    = "AllowEC2AppAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:role/${aws_iam_role.ec2_role.name}"
        },
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ],
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.vpc_name}-rds-kms"
    Environment = var.aws_profile
  }
}


resource "aws_kms_key" "ec2_kms" {
  description             = "KMS key for EC2 EBS encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 10
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid : "AllowRootAccountAccess",
        Effect : "Allow",
        Principal : {
          AWS : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action : "kms:*",
        Resource : "*"
      },
      {
        Sid : "AllowEC2Access",
        Effect : "Allow",
        Principal : {
          Service : "ec2.amazonaws.com"
        },
        Action : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource : "*"
      },
      {
        Sid : "AllowEC2AppAccess",
        Effect : "Allow",
        Principal : {
          AWS : "arn:aws:iam::${var.account_id}:role/${aws_iam_role.ec2_role.name}"
        },
        Action : [
          "kms:Decrypt",
          "kms:DescribeKey"
        ],
        Resource : "*"
      },
      {
        Sid : "AllowAutoScalingServiceAccess",
        Effect : "Allow",
        Principal : {
          Service : "autoscaling.amazonaws.com"
        },
        Action : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource : "*"
      },
      {
        Sid : "AllowAutoScalingRoleAccess",
        Effect : "Allow",
        Principal : {
          AWS : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        Action : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource : "*"
      },
      {
        Sid    = "Allow attachment of persistent resources",
        Effect = "Allow",
        Principal = {
          AWS = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        Action = [
          "kms:CreateGrant"
        ],
        Resource = "*",
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" : true
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.vpc_name}-ec2-kms"
    Environment = var.aws_profile
  }
}

resource "aws_kms_key" "s3_kms" {
  description             = "KMS key for S3 bucket encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 10
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowRootAccountAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid    = "AllowS3Access",
        Effect = "Allow",
        Principal = {
          Service = "s3.amazonaws.com"
        },
        Action   = "kms:Encrypt",
        Resource = "*"
      },
      {
        Sid : "AllowEC2Access",
        Effect : "Allow",
        Principal : {
          Service : "ec2.amazonaws.com"
        },
        Action : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource : "*"
      },
      {
        Sid : "AllowEC2AppAccess",
        Effect : "Allow",
        Principal : {
          AWS : "arn:aws:iam::${var.account_id}:role/${aws_iam_role.ec2_role.name}"
        },
        Action : [
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:Decrypt",
          "kms:DescribeKey"
        ],
        Resource : "*"
      }
    ]
  })

  tags = {
    Name        = "${var.vpc_name}-s3-kms"
    Environment = var.aws_profile
  }

}

