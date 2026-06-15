# demo_corp_stack — a realistic environment. A scanner flags every database, cache,
# warehouse and bucket here as a "public access" or "open security group" risk. probepath
# cuts the noise to what an attacker on the internet can ACTUALLY reach:
#
#   REACHABLE   aws_db_instance.orders     internet -> web (443) -> orders DB (5432)
#   REACHABLE   aws_s3_bucket.exports      public bucket policy (Principal:*)
#   suppressed  aws_db_instance.legacy     SG open to world BUT in a private subnet
#   suppressed  aws_elasticache_cluster.sessions   only the internal SG can reach it
#   suppressed  aws_redshift_cluster.warehouse      private, internal-only
#   suppressed  aws_s3_bucket.secrets      Block Public Access fully enabled

resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_internet_gateway" "gw" { vpc_id = aws_vpc.main.id }

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}
resource "aws_route_table" "private" { vpc_id = aws_vpc.main.id }  # local only — no internet

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
}
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "us-east-1a"
}
resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "us-east-1b"
}
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}
resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}
resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

# --- tiers ---------------------------------------------------------------
resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = aws_vpc.main.id
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
}

# An internal-only tier with no path from the internet (private subnet, no public ingress).
resource "aws_security_group" "internal" {
  name   = "internal"
  vpc_id = aws_vpc.main.id
  ingress {
    description = "self only"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }
}

resource "aws_instance" "web" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = true
}

resource "aws_instance" "batch" {
  ami                    = "ami-0abcdef1234567890"
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.private_a.id
  vpc_security_group_ids = [aws_security_group.internal.id]
}

# --- REACHABLE: orders DB trusts the internet-facing web tier ------------
resource "aws_db_subnet_group" "db" {
  name       = "demo-db"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}
resource "aws_security_group" "orders_db" {
  name   = "orders-db"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }
}
resource "aws_db_instance" "orders" {
  identifier             = "demo-orders"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "correcthorsebatterystaple"
  port                   = 5432
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.db.name
  vpc_security_group_ids = [aws_security_group.orders_db.id]
  skip_final_snapshot    = true
}

# --- SUPPRESSED: legacy DB looks wide open but lives in a private subnet --
resource "aws_security_group" "legacy_db" {
  name   = "legacy-db"
  vpc_id = aws_vpc.main.id
  ingress {
    description = "Postgres open to the world (scary, unreachable)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "legacy" {
  identifier             = "demo-legacy"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "correcthorsebatterystaple"
  port                   = 5432
  publicly_accessible    = true
  db_subnet_group_name   = aws_db_subnet_group.db.name
  vpc_security_group_ids = [aws_security_group.legacy_db.id]
  skip_final_snapshot    = true
}

# --- SUPPRESSED: cache reachable only from the internal tier -------------
resource "aws_elasticache_subnet_group" "cache" {
  name       = "demo-cache"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}
resource "aws_security_group" "cache" {
  name   = "cache"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.internal.id]
  }
}
resource "aws_elasticache_cluster" "sessions" {
  cluster_id           = "demo-sessions"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  subnet_group_name    = aws_elasticache_subnet_group.cache.name
  security_group_ids   = [aws_security_group.cache.id]
}

# --- SUPPRESSED: warehouse, private + internal-only ----------------------
resource "aws_redshift_subnet_group" "wh" {
  name       = "demo-wh"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}
resource "aws_security_group" "warehouse" {
  name   = "warehouse"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port       = 5439
    to_port         = 5439
    protocol        = "tcp"
    security_groups = [aws_security_group.internal.id]
  }
}
resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier        = "demo-wh"
  node_type                 = "dc2.large"
  master_username           = "admin"
  master_password           = "Correcthorse1"
  cluster_type              = "single-node"
  publicly_accessible       = false
  cluster_subnet_group_name = aws_redshift_subnet_group.wh.name
  vpc_security_group_ids    = [aws_security_group.warehouse.id]
  skip_final_snapshot       = true
}

# --- S3: one genuinely public, one locked down --------------------------
resource "aws_s3_bucket" "exports" { bucket = "demo-probepath-exports" }
resource "aws_s3_bucket_policy" "exports" {
  bucket = aws_s3_bucket.exports.id
  # Literal ARN (not the computed attribute) so the policy is fully known at plan time and
  # probepath can prove — not merely suspect — that it is world-readable.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::demo-probepath-exports/*"
    }]
  })
}

resource "aws_s3_bucket" "secrets" { bucket = "demo-probepath-secrets" }
resource "aws_s3_bucket_public_access_block" "secrets" {
  bucket                  = aws_s3_bucket.secrets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
