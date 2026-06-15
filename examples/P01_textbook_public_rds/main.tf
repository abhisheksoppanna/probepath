# P01 — the textbook "ONE real path": internet -> public EC2 (SSH) -> RDS (Postgres).
# The RDS is NOT directly public; it is reachable only by pivoting through the web host
# whose security group the DB trusts. A per-resource scanner sees "RDS SG references an
# internal SG, looks fine" — probepath proves the transitive internet path.
#
# Expected: REACHABLE  (internet -> igw -> aws_instance.web:22 -> aws_db_instance.main:5432)

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags       = { Name = "probepath-p01" }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "db_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_subnet" "db_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-east-1b"
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "SSH from the world"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name   = "db"
  vpc_id = aws_vpc.main.id

  ingress {
    description     = "Postgres from the web tier only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }
}

resource "aws_instance" "web" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = true
}

resource "aws_db_subnet_group" "db" {
  name       = "probepath-p01-db"
  subnet_ids = [aws_subnet.db_a.id, aws_subnet.db_b.id]
}

resource "aws_db_instance" "main" {
  identifier             = "probepath-p01"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "correcthorsebatterystaple"
  port                   = 5432
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.db.name
  vpc_security_group_ids = [aws_security_group.db.id]
  skip_final_snapshot    = true
}
