resource "aws_security_group" "open_admin" {
  name        = "open-admin"
  description = "Open administrative access"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description      = "RDP from anywhere"
    from_port        = 3389
    to_port          = 3389
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}
