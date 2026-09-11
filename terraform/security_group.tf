# Intentional inline exclusive rule ownership. Standalone rule resources do not
# remove arbitrary out-of-band additions during terraform apply. Never mix them.
resource "aws_security_group" "demo" {
  name        = "${var.project_name}-${random_id.suffix.hex}"
  description = "Unattached disposable group for security drift demonstrations"
  vpc_id      = aws_vpc.demo.id
  ingress = [for rule in local.ingress_expected : {
    description      = "Terraform approved ingress"
    protocol         = rule.protocol
    from_port        = rule.from_port
    to_port          = rule.to_port
    cidr_blocks      = [rule.source]
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
    security_groups  = []
    self             = false
  }]
  egress = []
  tags = {
    Name      = "${var.project_name}-unattached"
    DriftDemo = "true"
  }
}
