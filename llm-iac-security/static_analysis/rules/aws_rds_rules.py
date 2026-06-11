"""AWS RDS static analysis rules."""

from __future__ import annotations

from iac.models import IaCTemplate
from static_analysis.base_rule import StaticRule, falsey, truthy


class RDSStorageEncryptionRule(StaticRule):
    """Detect unencrypted RDS instances."""

    rule_id = "AWS_RDS_STORAGE_ENCRYPTION_DISABLED"
    title = "RDS storage encryption disabled or missing"
    severity = "HIGH"
    tags = ["aws", "rds", "encryption"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in template.resources:
            if resource.resource_type not in {"AWS::RDS::DBInstance", "aws_db_instance"}:
                continue
            prop_name = "StorageEncrypted" if template.iac_type == "cloudformation" else "storage_encrypted"
            value = resource.properties.get(prop_name)
            if not truthy(value):
                findings.append(
                    self.finding(
                        template,
                        resource,
                        "The RDS instance does not explicitly enable storage encryption.",
                        f"{prop_name} is {value!r}.",
                        "Set storage encryption to true and use a customer-managed KMS key where appropriate.",
                    )
                )
        return findings


class RDSPubliclyAccessibleRule(StaticRule):
    """Detect publicly accessible RDS instances."""

    rule_id = "AWS_RDS_PUBLICLY_ACCESSIBLE"
    title = "RDS instance is publicly accessible"
    severity = "HIGH"
    tags = ["aws", "rds", "network"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in template.resources:
            if resource.resource_type not in {"AWS::RDS::DBInstance", "aws_db_instance"}:
                continue
            prop_name = "PubliclyAccessible" if template.iac_type == "cloudformation" else "publicly_accessible"
            value = resource.properties.get(prop_name)
            if truthy(value):
                findings.append(
                    self.finding(
                        template,
                        resource,
                        "The RDS instance is configured to be publicly accessible.",
                        f"{prop_name} is true.",
                        "Set publicly accessible to false and place the database in private subnets.",
                    )
                )
        return findings
