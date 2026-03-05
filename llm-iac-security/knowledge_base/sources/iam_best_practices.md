# IAM Least-Privilege Guidelines

- Use the principle of least privilege: grant only necessary permissions.
- Avoid wildcard (*) actions in IAM policies; be specific.
- Never use Principal: "*" in trust policies unless implementing a public resource.
- Use IAM roles for EC2/Lambda rather than embedding access keys.
- Enable MFA for all IAM users with console access.
