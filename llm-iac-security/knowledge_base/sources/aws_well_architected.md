# AWS Well-Architected Framework — Security Pillar

## IAM Least Privilege
Grant only the permissions required to perform a task. Use AWS managed policies as
a starting point and then refine to remove unneeded permissions.

## S3 Security
- Enable S3 Block Public Access at the account level.
- Enable server-side encryption (SSE-S3 or SSE-KMS) for all buckets.
- Enable versioning to protect against accidental deletions.

## Security Group Best Practices
- Restrict inbound rules to the minimum required IP ranges and ports.
- Avoid 0.0.0.0/0 on sensitive ports such as 22 (SSH) and 3389 (RDP).
