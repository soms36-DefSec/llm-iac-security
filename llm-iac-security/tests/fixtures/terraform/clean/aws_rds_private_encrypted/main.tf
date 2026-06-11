resource "aws_db_instance" "customer_db" {
  identifier          = "customer-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  publicly_accessible = false
  storage_encrypted   = true
  username            = "dbadmin"
}
