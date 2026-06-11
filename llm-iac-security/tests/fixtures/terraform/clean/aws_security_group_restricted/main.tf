resource "aws_security_group" "restricted_admin" {
  name        = "restricted-admin"
  description = "Restricted administrative access"

  ingress {
    description = "SSH from VPN"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }
}
