resource "aws_iam_policy" "read_logs" {
  name = "read-logs"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::example-secure-logs/*"
    }
  ]
}
POLICY
}
