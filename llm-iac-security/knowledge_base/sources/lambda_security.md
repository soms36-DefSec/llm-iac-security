# AWS Lambda Security Best Practices

## Lambda Execution Role — Least Privilege

Every Lambda function must have a dedicated IAM execution role with only the permissions required for its specific task. Never reuse a single role across multiple functions with different responsibilities.

**AWS Well-Architected SEC-2**: Apply the principle of least privilege.

```yaml
# VULNERABLE — overly broad role
ExecutionRole:
  Type: AWS::IAM::Role
  Properties:
    ManagedPolicyArns:
      - arn:aws:iam::aws:policy/AdministratorAccess  # CRITICAL

# SECURE — minimal permissions
ExecutionRole:
  Type: AWS::IAM::Role
  Properties:
    Policies:
      - PolicyDocument:
          Statement:
            - Effect: Allow
              Action:
                - dynamodb:GetItem
                - dynamodb:PutItem
              Resource: !GetAtt MyTable.Arn
```

## Lambda VPC Configuration

For functions that access private resources (RDS, ElastiCache, internal APIs), deploy them inside a VPC with appropriate security groups and private subnets.

```yaml
VpcConfig:
  SecurityGroupIds:
    - !Ref LambdaSecurityGroup
  SubnetIds:
    - !Ref PrivateSubnet1
    - !Ref PrivateSubnet2
```

Functions accessing sensitive data without VPC isolation is a HIGH vulnerability.

## Lambda Environment Variables — No Plaintext Secrets

Never store secrets, API keys, passwords, or connection strings in Lambda environment variables as plaintext. Use AWS Secrets Manager or SSM Parameter Store with SecureString.

```yaml
# VULNERABLE
Environment:
  Variables:
    DB_PASSWORD: "mysecretpassword"    # CRITICAL — plaintext secret
    API_KEY: "sk-1234567890abcdef"     # CRITICAL

# SECURE — reference Secrets Manager
Environment:
  Variables:
    DB_SECRET_ARN: !Ref MyDatabaseSecret
```

Hardcoded secrets in environment variables is a CRITICAL vulnerability.

## Lambda Reserved Concurrency

Set reserved concurrency to prevent a single Lambda function from consuming all available concurrency in a region, which could cause a denial-of-service to other functions.

```yaml
ReservedConcurrentExecutions: 100
```

## Lambda Dead Letter Queue (DLQ)

Configure a DLQ (SQS queue or SNS topic) to capture failed asynchronous invocations for retry or investigation.

```yaml
DeadLetterConfig:
  TargetArn: !GetAtt DLQQueue.Arn
```

Missing DLQ for async functions is a MEDIUM vulnerability (silent data loss).

## Lambda Function URL Security

If using Lambda Function URLs, ensure `AuthType` is not `NONE` unless the function genuinely needs unauthenticated public access.

```yaml
# VULNERABLE
FunctionUrlConfig:
  AuthType: NONE    # HIGH — publicly accessible without authentication

# SECURE
FunctionUrlConfig:
  AuthType: AWS_IAM
```

## Lambda Runtime and Layer Security

Keep Lambda runtimes updated. Avoid deprecated runtimes (Python 2.7, Node.js 10, etc.). Monitor AWS announcements for end-of-life dates.

## Lambda Code Signing

For production environments, enable code signing to ensure only signed code packages are deployed.

```yaml
CodeSigningConfigArn: !Ref MyCodeSigningConfig
```

## Common Lambda Vulnerability Types

| Vulnerability | Severity | CloudFormation Property |
|--------------|----------|------------------------|
| Admin/wildcard execution role | CRITICAL | `ManagedPolicyArns: AdministratorAccess` |
| Plaintext secrets in env vars | CRITICAL | `Environment.Variables` with passwords/keys |
| No VPC for private resource access | HIGH | Missing `VpcConfig` |
| Public Function URL (no auth) | HIGH | `FunctionUrlConfig.AuthType: NONE` |
| No DLQ for async invocations | MEDIUM | Missing `DeadLetterConfig` |
| No reserved concurrency | LOW | Missing `ReservedConcurrentExecutions` |
| Deprecated runtime | MEDIUM | `Runtime: python2.7` or `nodejs10.x` |
