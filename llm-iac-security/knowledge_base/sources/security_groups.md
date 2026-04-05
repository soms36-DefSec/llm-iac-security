# AWS Security Group Best Practices

## Security Group Overview

AWS Security Groups are stateful virtual firewalls that control inbound and outbound traffic to EC2 instances, RDS databases, Lambda functions, and other VPC resources. Overly permissive security group rules are one of the most common IaC misconfigurations.

## Ingress Rules — Principle of Least Privilege

Never allow unrestricted inbound access from `0.0.0.0/0` (all IPv4) or `::/0` (all IPv6) except for specific public-facing use cases such as HTTP/HTTPS on a load balancer.

**CIS AWS Benchmark 5.2**: Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (SSH).
**CIS AWS Benchmark 5.3**: Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (RDP).

### Critical open port findings

| Port | Protocol | Description | Severity |
|------|----------|-------------|----------|
| 22 | TCP | SSH from 0.0.0.0/0 | CRITICAL |
| 3389 | TCP | RDP from 0.0.0.0/0 | CRITICAL |
| -1 (all) | -1 | All traffic from 0.0.0.0/0 | CRITICAL |
| 3306 | TCP | MySQL from 0.0.0.0/0 | CRITICAL |
| 5432 | TCP | PostgreSQL from 0.0.0.0/0 | CRITICAL |
| 1433 | TCP | MSSQL from 0.0.0.0/0 | CRITICAL |
| 27017 | TCP | MongoDB from 0.0.0.0/0 | CRITICAL |
| 6379 | TCP | Redis from 0.0.0.0/0 | HIGH |
| 9200 | TCP | Elasticsearch from 0.0.0.0/0 | HIGH |
| 8080 | TCP | HTTP alt from 0.0.0.0/0 | MEDIUM |

## Identifying Overly Permissive Rules in CloudFormation

```yaml
# VULNERABLE — allows SSH from anywhere
SecurityGroupIngress:
  - IpProtocol: tcp
    FromPort: 22
    ToPort: 22
    CidrIp: 0.0.0.0/0       # CRITICAL: unrestricted SSH

# VULNERABLE — allows all traffic
SecurityGroupIngress:
  - IpProtocol: "-1"
    CidrIp: 0.0.0.0/0       # CRITICAL: all traffic from internet

# SECURE — restrict SSH to specific CIDR
SecurityGroupIngress:
  - IpProtocol: tcp
    FromPort: 22
    ToPort: 22
    CidrIp: 10.0.0.0/8      # Only internal network

# SECURE — use Security Group references instead of CIDRs
SecurityGroupIngress:
  - IpProtocol: tcp
    FromPort: 5432
    ToPort: 5432
    SourceSecurityGroupId: !Ref AppSecurityGroup
```

## Egress Rules

By default, AWS allows all outbound traffic (`0.0.0.0/0`). For sensitive workloads, restrict egress to only required destinations.

```yaml
# BEST PRACTICE: restrict egress
SecurityGroupEgress:
  - IpProtocol: tcp
    FromPort: 443
    ToPort: 443
    CidrIp: 0.0.0.0/0       # Allow HTTPS out only
```

Overly permissive egress (`-1` protocol or all ports) is a LOW/MEDIUM finding as it enables data exfiltration.

## Security Group Naming and Description

Always provide meaningful descriptions. Missing or default descriptions ("Managed by Terraform", empty strings) indicate lack of documentation.

## Security Group Chaining

Prefer Security Group IDs over CIDR ranges for intra-VPC rules. This is more maintainable and prevents accidental IP range expansion.

## AWS Well-Architected: Network Security

- Use VPC Flow Logs to monitor traffic accepted/rejected by security group rules.
- Apply security groups at the most granular level (per-resource, not shared across all resources).
- Use AWS Network Firewall or WAF for additional L7 protection.
- Avoid the default security group; create purpose-specific groups.

## Common CloudFormation Fields to Check

- `SecurityGroupIngress[*].CidrIp` — should never be `0.0.0.0/0` for admin/database ports
- `SecurityGroupIngress[*].CidrIpv6` — should never be `::/0` for admin/database ports
- `SecurityGroupIngress[*].IpProtocol` — `-1` means all protocols (very permissive)
- `SecurityGroupIngress[*].FromPort` / `ToPort` — `0` to `65535` means all ports (very permissive)
