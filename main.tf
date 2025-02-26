
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
  name        = "${var.vpc_name}-web-sg"
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

#Terraform resource to spin up an EC2 instance.
resource "aws_instance" "webapp" {
  ami                         = var.custom_ami_id
  instance_type               = var.instance_type
  key_name                    = var.key_name
  security_groups      = [aws_security_group.web_sg.id]
  subnet_id = "${aws_subnet.public[0].id}"
  root_block_device {
    volume_type           = var.volume_type
    volume_size           = var.volume_size
    delete_on_termination = true
  }

    tags = {
        Name = "${var.vpc_name}-webapp"
    }
}