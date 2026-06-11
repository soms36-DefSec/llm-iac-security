resource "aws_db_instance" "customer_db" {
  identifier           = "customer-db"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  publicly_accessible  = true
  storage_encrypted    = false
  username             = "dbadmin"
}
