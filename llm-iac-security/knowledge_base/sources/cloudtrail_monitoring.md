# AWS CloudTrail, GuardDuty, and Monitoring Best Practices

## CloudTrail — Audit Logging

AWS CloudTrail records API calls across your AWS account. It is the primary audit mechanism for detecting unauthorized access and investigating security incidents.

**CIS AWS Benchmark 3.1**: Ensure CloudTrail is enabled in all regions.
**CIS AWS Benchmark 3.2**: Ensure CloudTrail log file validation is enabled.

### Required CloudTrail Configuration

```yaml
MyTrail:
  Type: AWS::CloudTrail::Trail
  Properties:
    IsLogging: true                    # Must be true
    IsMultiRegionTrail: true           # Cover all regions
    IncludeGlobalServiceEvents: true   # Include IAM, STS, Route53
    EnableLogFileValidation: true      # Detect log tampering
    S3BucketName: !Ref AuditLogBucket
```

**Missing `IsLogging: true`** — CRITICAL (no audit trail).
**`IsMultiRegionTrail: false`** — HIGH (blind spots in other regions).
**Missing `EnableLogFileValidation: true`** — HIGH (logs can be tampered undetected).

### CloudTrail Log Encryption

Encrypt CloudTrail logs with a KMS key to prevent unauthorized access to audit logs.

```yaml
KMSKeyId: !Ref CloudTrailKMSKey
```

Missing KMS encryption for CloudTrail logs is a MEDIUM vulnerability.

### CloudTrail S3 Bucket Hardening

The S3 bucket receiving CloudTrail logs must:
- Block all public access
- Enable versioning
- Enable MFA delete
- Have a bucket policy that only allows CloudTrail to write

## AWS Config

Enable AWS Config to record resource configuration changes and evaluate compliance rules.

```yaml
ConfigurationRecorder:
  Type: AWS::Config::ConfigurationRecorder
  Properties:
    RecordingGroup:
      AllSupported: true
      IncludeGlobalResourceTypes: true
```

No Config recorder is a MEDIUM vulnerability (no compliance baselines).

## Amazon GuardDuty

GuardDuty uses ML and threat intelligence to detect malicious activity including compromised credentials, unauthorized API calls, crypto-mining, and unusual data access.

```yaml
GuardDutyDetector:
  Type: AWS::GuardDuty::Detector
  Properties:
    Enable: true
    FindingPublishingFrequency: FIFTEEN_MINUTES
```

GuardDuty disabled is a HIGH vulnerability (no automated threat detection).

## VPC Flow Logs

Enable VPC Flow Logs to capture network traffic metadata for security analysis.

```yaml
FlowLog:
  Type: AWS::EC2::FlowLog
  Properties:
    ResourceId: !Ref MyVPC
    ResourceType: VPC
    TrafficType: ALL        # ACCEPT, REJECT, or ALL
    LogDestinationType: cloud-watch-logs
    LogGroupName: /aws/vpc/flowlogs
```

Missing VPC Flow Logs is a MEDIUM vulnerability (no network visibility).

## CloudWatch Alarms for Security Events

Create CloudWatch alarms for critical security events from CloudTrail:

| Alarm | Metric Filter | Description |
|-------|--------------|-------------|
| UnauthorizedAPICalls | `errorCode = "AccessDenied" OR "UnauthorizedOperation"` | Detect probing |
| ConsoleSigninWithoutMFA | `userIdentity.type = "IAMUser" AND mfaAuthenticated = "false"` | Enforce MFA |
| RootAccountUsage | `userIdentity.type = "Root"` | Alert on root login |
| IAMPolicyChanges | `eventName = "CreatePolicy" OR "DeletePolicy"` | Track privilege changes |
| S3BucketPolicyChanges | `eventSource = "s3.amazonaws.com"` | Track data exposure changes |
| SecurityGroupChanges | `eventName = "AuthorizeSecurityGroupIngress"` | Track firewall changes |

## AWS Security Hub

Enable Security Hub to aggregate findings from GuardDuty, Inspector, Config, Macie, and third-party tools into a single dashboard.

## Common Monitoring Vulnerability Types

| Vulnerability | Severity | Resource |
|--------------|----------|----------|
| CloudTrail disabled or not logging | CRITICAL | `AWS::CloudTrail::Trail` |
| No multi-region trail | HIGH | `IsMultiRegionTrail: false` |
| Log file validation disabled | HIGH | `EnableLogFileValidation: false` |
| GuardDuty disabled | HIGH | `AWS::GuardDuty::Detector` |
| No VPC Flow Logs | MEDIUM | Missing `AWS::EC2::FlowLog` |
| No CloudTrail KMS encryption | MEDIUM | Missing `KMSKeyId` |
| No AWS Config recorder | MEDIUM | Missing `AWS::Config::ConfigurationRecorder` |
| No security event alarms | LOW | Missing `AWS::CloudWatch::Alarm` |
