# ── PROVIDER ──────────────────────────────────────────────────────────────────
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── VPC ───────────────────────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "${var.project}-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
  tags = { Name = "${var.project}-public-subnet" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${var.project}-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ── SECURITY GROUP ─────────────────────────────────────────────────────────────
resource "aws_security_group" "app" {
  name        = "${var.project}-sg"
  description = "Threat Intel Platform security group"
  vpc_id      = aws_vpc.main.id

  # SSH — your IP only (set in tfvars)
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  # App
  ingress {
    description = "Flask app"
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Grafana
  ingress {
    description = "Grafana"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Prometheus (restrict to your IP in production)
  ingress {
    description = "Prometheus"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  # HTTP/HTTPS (for future nginx reverse proxy)
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

  tags = { Name = "${var.project}-sg" }
}

# ── KEY PAIR ──────────────────────────────────────────────────────────────────
resource "aws_key_pair" "deployer" {
  key_name   = "${var.project}-key"
  public_key = file(var.public_key_path)
}

# ── EC2 (t2.micro — free tier) ────────────────────────────────────────────────
resource "aws_instance" "app" {
  ami                    = var.ami_id        # Ubuntu 22.04 LTS
  instance_type          = "t3.micro"       # free tier
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.app.id]
  key_name               = aws_key_pair.deployer.key_name

  root_block_device {
    volume_size = 20    # GB — free tier allows up to 30GB
    volume_type = "gp2"
    encrypted   = true
  }

user_data = <<-EOF
    #!/bin/bash
    set -e
    apt-get update -y
    apt-get install -y ca-certificates curl gnupg git

    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
      gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/ubuntu jammy stable" | \
      tee /etc/apt/sources.list.d/docker.list > /dev/null

    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin docker-compose-plugin

    systemctl enable docker
    systemctl start docker
    usermod -aG docker ubuntu
  EOF

  tags = {
    Name        = "${var.project}-server"
    Project     = var.project
    ManagedBy   = "Terraform"
  }
}

# ── ELASTIC IP (so URL never changes) ─────────────────────────────────────────
resource "aws_eip" "app" {
  instance = aws_instance.app.id
  domain   = "vpc"
  tags     = { Name = "${var.project}-eip" }
}

# ── OUTPUTS ───────────────────────────────────────────────────────────────────
output "public_ip" {
  value       = aws_eip.app.public_ip
  description = "Elastic IP — put this in your resume and README"
}
output "app_url" {
  value = "http://${aws_eip.app.public_ip}:5000"
}
output "grafana_url" {
  value = "http://${aws_eip.app.public_ip}:3000"
}
output "ssh_command" {
  value = "ssh -i ~/.ssh/threat-intel ubuntu@${aws_eip.app.public_ip}"
}
