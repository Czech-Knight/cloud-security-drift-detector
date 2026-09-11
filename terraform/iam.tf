resource "aws_iam_role" "demo" {
  name               = "${var.project_name}-${random_id.suffix.hex}"
  assume_role_policy = jsonencode(local.trust_policy)
  description        = "Unused demo role, scoped to reading this demo bucket"
}

resource "aws_iam_role_policy" "read" {
  name   = "DemoBucketRead"
  role   = aws_iam_role.demo.id
  policy = jsonencode(local.read_policy)
}

# Ensure apply removes unexpected attachments and inline policies too.
resource "aws_iam_role_policy_attachments_exclusive" "demo" {
  role_name   = aws_iam_role.demo.name
  policy_arns = []
}

resource "aws_iam_role_policies_exclusive" "demo" {
  role_name    = aws_iam_role.demo.name
  policy_names = [aws_iam_role_policy.read.name]
}
