# P02 — the most damning finding: a database directly on the internet. publicly_accessible,
# in a public subnet (0.0.0.0/0 -> igw), with a security group open to the world on 5432.
# No pivot needed.
#
# Expected: REACHABLE  (internet -> aws_db_instance.main:5432, directly).

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}

resource "aws_subnet" "pub_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_subnet" "pub_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}

resource "aws_route_table_association" "pub_a" {
  subnet_id      = aws_subnet.pub_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "pub_b" {
  subnet_id      = aws_subnet.pub_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_db_subnet_group" "db" {
  name       = "probepath-p02"
  subnet_ids = [aws_subnet.pub_a.id, aws_subnet.pub_b.id]
}

resource "aws_security_group" "db" {
  name   = "db-public"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  identifier             = "probepath-p02"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "correcthorsebatterystaple"
  port                   = 5432
  publicly_accessible    = true
  db_subnet_group_name   = aws_db_subnet_group.db.name
  vpc_security_group_ids = [aws_security_group.db.id]
  skip_final_snapshot    = true
}
