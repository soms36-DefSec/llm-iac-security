# AWS RDS Security Best Practices

## RDS Encryption at Rest

All RDS database instances must have `StorageEncrypted: true`. Once created without encryption, a database cannot be encrypted in-place — a snapshot restore is required.

**CIS AWS Benchmark 2.3.1**: Ensure that encryption-at-rest is enabled for RDS Instances.

```yaml
# VULNERABLE
MyDatabase:
  Type: AWS::RDS::DBInstance
  Properties:
    StorageEncrypted: false   # CRITICAL

# SECURE
MyDatabase:
  Type: AWS::RDS::DBInstance
  Properties:
    StorageEncrypted: true
    KmsKeyId: !Ref MyRDSKmsKey
```

Missing or `false` `StorageEncrypted` is a CRITICAL vulnerability.

## RDS Public Accessibility

Set `PubliclyAccessible: false` unless the database absolutely must accept direct internet connections (which is almost never appropriate for production databases).

**CIS AWS Benchmark 2.3.2**: Ensure that public access is not given to RDS Instance.

```yaml
# VULNERABLE
MyDatabase:
  Type: AWS::RDS::DBInstance
  Properties:
    PubliclyAccessible: true  # CRITICAL — internet-accessible database

# SECURE
MyDatabase:
  Type: AWS::RDS::DBInstance
  Properties:
    PubliclyAccessible: false
    DBSubnetGroupName: !Ref PrivateSubnetGroup
```

`PubliclyAccessible: true` is a CRITICAL vulnerability.

## RDS Encryption in Transit

Enforce TLS/SSL for all connections to the RDS instance. This is done via parameter group settings:

- PostgreSQL: `rds.force_ssl = 1`
- MySQL/MariaDB: `require_secure_transport = ON`
- SQL Server: Use `rds.force_ssl`

Missing TLS enforcement is a HIGH vulnerability.

## RDS Automated Backups

Configure automated backups with a minimum retention period of 7 days.

```yaml
BackupRetentionPeriod: 7    # minimum; 30+ recommended for compliance
```

`BackupRetentionPeriod: 0` disables automated backups — this is a HIGH vulnerability (no recovery point).

## RDS Multi-AZ

Enable Multi-AZ for production databases to ensure high availability and automatic failover.

```yaml
MultiAZ: true
```

Single-AZ for production is a MEDIUM vulnerability (availability risk).

## RDS Deletion Protection

Enable deletion protection to prevent accidental database deletion.

```yaml
DeletionProtection: true
```

Missing `DeletionProtection` is a MEDIUM vulnerability.

## RDS Enhanced Monitoring and Logging

Enable CloudWatch logs export for audit, error, general, and slow query logs:

```yaml
EnableCloudwatchLogsExports:
  - audit
  - error
  - general
  - slowquery
```

No log exports is a LOW vulnerability (reduced auditability).

## RDS IAM Authentication

Prefer IAM database authentication over static username/password credentials for supported engines (MySQL, PostgreSQL).

```yaml
EnableIAMDatabaseAuthentication: true
```

## RDS VPC and Subnet Groups

Always deploy RDS instances in private subnets via a `DBSubnetGroup`. Never deploy in the default VPC.

## Common RDS Vulnerability Types

| Vulnerability | Severity | CloudFormation Property |
|--------------|----------|------------------------|
| No encryption at rest | CRITICAL | `StorageEncrypted: false` or missing |
| Publicly accessible | CRITICAL | `PubliclyAccessible: true` |
| No automated backups | HIGH | `BackupRetentionPeriod: 0` |
| No TLS enforcement | HIGH | Missing parameter group ssl setting |
| No deletion protection | MEDIUM | Missing `DeletionProtection: true` |
| Single-AZ deployment | MEDIUM | `MultiAZ: false` in production |
| No audit logging | LOW | Missing `EnableCloudwatchLogsExports` |
| Default master password in plaintext | CRITICAL | `MasterUserPassword` hardcoded |
