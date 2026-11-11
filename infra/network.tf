# A private network with NO internet gateway and NO NAT gateway (a NAT costs ~$32/month).
# The database has no public address. App Runner reaches it through a VPC connector.
# If Bedrock is enabled, a VPC endpoint gives the app a private path to Bedrock only.

resource "aws_vpc" "main" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = local.name }
}

resource "aws_subnet" "private" {
  count             = length(local.azs)
  vpc_id            = aws_vpc.main.id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  tags              = { Name = "${local.name}-private-${count.index}" }
}

# Traffic leaving App Runner into the VPC.
resource "aws_security_group" "app" {
  name_prefix = "${local.name}-app-"
  description = "App Runner VPC connector"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "To the database and VPC endpoints inside the VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  lifecycle { create_before_destroy = true }
}

# The database accepts connections only from the app, only on the PostgreSQL port.
resource "aws_security_group" "db" {
  name_prefix = "${local.name}-db-"
  description = "RDS PostgreSQL"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from the app"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "endpoints" {
  count       = local.bedrock_on ? 1 : 0
  name_prefix = "${local.name}-vpce-"
  description = "Interface VPC endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "HTTPS from the app"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_endpoint" "bedrock_runtime" {
  count               = local.bedrock_on ? 1 : 0
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private[0].id] # one AZ halves the endpoint's hourly cost
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true
  tags                = { Name = "${local.name}-bedrock-runtime" }
}
