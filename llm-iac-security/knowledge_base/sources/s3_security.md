# AWS S3 Bucket Security Best Practices

## S3 Encryption at Rest

All S3 buckets must have server-side encryption enabled. Use `BucketEncryption` with either:
- `aws:kms` (preferred — uses AWS KMS customer-managed keys for audit trail)
- `AES256` (SSE-S3 — AWS managed keys, simpler but less auditable)

**CIS AWS Benchmark 2.1.1**: Ensure all S3 buckets employ encryption-at-rest.

```yaml
BucketEncryption:
  ServerSideEncryptionConfiguration:
    - ServerSideEncryptionByDefault:
        SSEAlgorithm: aws:kms
        KMSMasterKeyID: !Ref MyKMSKey
```

Missing `BucketEncryption` is a HIGH or CRITICAL vulnerability depending on data sensitivity.

## S3 Public Access Block

All S3 buckets must have all four public access block settings set to `true` unless the bucket intentionally serves public static content.

**CIS AWS Benchmark 2.1.5**: Ensure that S3 Buckets are configured with 'Block public access'.

```yaml
PublicAccessBlockConfiguration:
  BlockPublicAcls: true
  BlockPublicPolicy: true
  IgnorePublicAcls: true
  RestrictPublicBuckets: true
```

Setting any of these flags to `false` — or omitting `PublicAccessBlockConfiguration` entirely — is a CRITICAL vulnerability that can expose data to the public internet.

## S3 Versioning

Enable versioning to protect against accidental deletion and enable point-in-time recovery.

**CIS AWS Benchmark 2.1.3**: Ensure MFA Delete is enabled on S3 buckets.

```yaml
VersioningConfiguration:
  Status: Enabled
```

`Status: Suspended` or a missing `VersioningConfiguration` is a MEDIUM vulnerability.

## S3 Access Logging

Enable server access logging to audit who accessed objects and when.

```yaml
LoggingConfiguration:
  DestinationBucketName: !Ref LogBucket
  LogFilePrefix: s3-access-logs/
```

Missing `LoggingConfiguration` is a LOW vulnerability (audit gap).

## S3 Lifecycle Policies

Define lifecycle rules to automatically transition or expire objects, reducing cost and limiting the window of exposure for sensitive data.

## S3 Object Ownership

Set `ObjectOwnership` to `BucketOwnerEnforced` to disable ACLs and ensure the bucket owner always owns all objects.

```yaml
OwnershipControls:
  Rules:
    - ObjectOwnership: BucketOwnerEnforced
```

## S3 Bucket Policies

Bucket policies should:
- Deny `s3:PutObject` without `aws:SecureTransport` to enforce TLS-in-transit
- Deny `s3:*` for `"AWS": "*"` principals (public access via policy)

```json
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
  "Condition": {"Bool": {"aws:SecureTransport": "false"}}
}
```

Missing TLS enforcement is a HIGH vulnerability (data in transit unencrypted).

## Common S3 Vulnerability Types

| Vulnerability | Severity | CloudFormation Property |
|--------------|----------|------------------------|
| No encryption at rest | HIGH | Missing `BucketEncryption` |
| Public access enabled | CRITICAL | `PublicAccessBlockConfiguration` flags = false |
| Versioning disabled | MEDIUM | `VersioningConfiguration.Status` = Suspended |
| No access logging | LOW | Missing `LoggingConfiguration` |
| No TLS enforcement | HIGH | Missing bucket policy deny on http |
| ACLs enabled (canned ACL = public) | CRITICAL | `AccessControl: PublicRead` or `PublicReadWrite` |
