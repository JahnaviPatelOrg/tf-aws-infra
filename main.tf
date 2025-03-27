
# creating vpc
resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr

  tags = {
    Name = var.vpc_name
  }
}

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
  description = "Allow HTTP and SSH traffic"
  vpc_id      = aws_vpc.main.id

  # Ingress rule for HTTPS (port 443)
  ingress {
    from_port = var.https_port
    to_port   = var.https_port
    protocol  = "tcp"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }

  # Ingress rule for HTTP (port 80)
  ingress {
    from_port = var.http_port
    to_port   = var.http_port
    protocol  = "tcp"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }

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
    cidr_blocks = [
      "0.0.0.0/0"
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

#Terraform resource to spin up an EC2 instance.
resource "aws_instance" "webapp" {
  ami                         = var.custom_ami_id
  instance_type               = var.instance_type
  key_name                    = var.key_name
  security_groups             = [aws_security_group.web_sg.id]
  subnet_id                   = aws_subnet.public[0].id
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ec2_instance_profile.name

  user_data = <<-EOF
            #!/bin/bash
            # Database and app environment variables
            sudo bash -c 'echo "DB_HOST=${aws_db_instance.db_instance.address}" >> /etc/.env'
            sudo bash -c 'echo "DB_USER=${var.db_user}" >> /etc/.env'
            sudo bash -c 'echo "DB_PASS=${var.db_password}" >> /etc/.env'
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

  root_block_device {
    volume_type           = var.volume_type
    volume_size           = var.volume_size
    delete_on_termination = true
  }

  tags = {
    Name = "${var.vpc_name}-webapp"
  }
}

# S3 Bucket

# private S3 bucket with a bucket name being a UUID.
# terraform can delete the bucket even if it is not empty
resource "aws_s3_bucket" "private_bucket" {
  bucket        = "${var.vpc_name}-private-bucket-${uuid()}"
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
      sse_algorithm = "AES256"
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
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.main.name
  publicly_accessible    = false
  db_name                = var.db_name
  allocated_storage      = 10
  skip_final_snapshot    = true
  parameter_group_name   = aws_db_parameter_group.rds_param_group.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
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
          "${aws_s3_bucket.private_bucket.arn}",
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

