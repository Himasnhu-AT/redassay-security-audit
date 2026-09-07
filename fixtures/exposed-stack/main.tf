# VULN pack: exposure
resource "aws_security_group_rule" "db" {
  type        = "ingress"
  from_port   = 5432
  to_port     = 5432
  protocol    = "tcp"
  # VULN: expose.open-cidr
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "internal" {
  type        = "ingress"
  from_port   = 8080
  to_port     = 8080
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}
