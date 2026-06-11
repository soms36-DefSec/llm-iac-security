resource "aws_s3_bucket" "logs" {
  bucket = "example-multi-logs"
}

resource "aws_iam_policy" "wildcard" {
  name = "wildcard-policy"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:*",
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_security_group" "open_all" {
  name        = "open-all"
  description = "Open all traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "customer_db" {
  identifier          = "customer-db"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  storage_encrypted   = false
  publicly_accessible = true
}

resource "aws_secretsmanager_secret_version" "example" {
  secret_id     = "example"
  secret_string = "example-password-value"
}
