# N01 — the flagship SUPPRESSION. The RDS security group is wide open to the entire
# internet on 5432 AND publicly_accessible = true. Every per-resource scanner screams.
# probepath proves it is UNREACHABLE: the database lives in a private subnet whose route
# table has no 0.0.0.0/0 -> internet-gateway route, so no internet packet can arrive.
#
# Expected: UNREACHABLE (suppressed) — proof: "database subnet is private (no 0.0.0.0/0 -> igw route)".

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
}

# Private subnets for the DB, associated to a route table with NO default route.
resource "aws_subnet" "db_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_subnet" "db_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "us-east-1b"
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  # intentionally no 0.0.0.0/0 route — local only
}

resource "aws_route_table_association" "db_a" {
  subnet_id      = aws_subnet.db_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "db_b" {
  subnet_id      = aws_subnet.db_b.id
  route_table_id = aws_route_table.private.id
}

resource "aws_db_subnet_group" "db" {
  name       = "probepath-n01"
  subnet_ids = [aws_subnet.db_a.id, aws_subnet.db_b.id]
}

# The misconfiguration a scanner flags: open to the world + publicly_accessible.
resource "aws_security_group" "db" {
  name   = "db-open"
  vpc_id = aws_vpc.main.id
  ingress {
    description = "Postgres from anywhere (scary, but unreachable)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  identifier             = "probepath-n01"
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
