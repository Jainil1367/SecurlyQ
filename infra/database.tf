resource "random_password" "db" {
  length  = 32
  special = false # avoids characters that need escaping inside a connection URL
}

resource "aws_db_subnet_group" "main" {
  name       = local.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_instance" "main" {
  identifier     = local.name
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  allocated_storage     = 20
  max_allocated_storage = 100 # storage autoscaling ceiling
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = "securlyq"
  username = "securlyq"
  password = random_password.db.result

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false
  multi_az               = false # single-AZ keeps cost down; turn on for real production

  backup_retention_period    = 7
  auto_minor_version_upgrade = true
  deletion_protection        = var.enable_deletion_protection
  skip_final_snapshot        = !var.enable_deletion_protection
  final_snapshot_identifier  = var.enable_deletion_protection ? "${local.name}-final" : null

  performance_insights_enabled = true
  apply_immediately            = false
}
