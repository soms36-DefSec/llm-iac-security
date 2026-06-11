"""Static rule engine for normalized IaC templates."""

from __future__ import annotations

from typing import Any

from config.logging_config import get_logger
from static_analysis.base_rule import StaticRule, ensure_template
from static_analysis.models import StaticFinding
from static_analysis.rules.aws_iam_rules import AdminPolicyRiskRule, IAMWildcardActionRule, IAMWildcardResourceRule
from static_analysis.rules.aws_network_rules import (
    SecurityGroupAllTrafficOpenRule,
    SecurityGroupRdpOpenRule,
    SecurityGroupSshOpenRule,
)
from static_analysis.rules.aws_rds_rules import RDSPubliclyAccessibleRule, RDSStorageEncryptionRule
from static_analysis.rules.aws_s3_rules import S3BucketEncryptionRule, S3PublicAccessBlockRule
from static_analysis.rules.generic_secret_rules import HardcodedSecretRule
from static_analysis.rules.multi_provider_rules import (
    AzureKeyVaultPublicNetworkRule,
    AzureKeyVaultPurgeProtectionRule,
    AzureNetworkSecurityAllTrafficOpenRule,
    AzureNetworkSecurityRdpOpenRule,
    AzureNetworkSecuritySshOpenRule,
    AzureStorageMinimumTLSRule,
    AzureStoragePublicNetworkAccessRule,
    GCPFirewallAllTrafficOpenRule,
    GCPFirewallRdpOpenRule,
    GCPFirewallSshOpenRule,
    GCPKMSRotationRule,
    GCPStoragePublicIAMRule,
    KubernetesDangerousCapabilitiesRule,
    KubernetesHostNetworkRule,
    KubernetesPrivilegeEscalationRule,
    KubernetesPrivilegedContainerRule,
    KubernetesRunAsRootRule,
)

logger = get_logger(__name__)


class StaticAnalysisEngine:
    """Runs deterministic rules against a normalized IaC template."""

    def __init__(self, rules: list[StaticRule] | None = None) -> None:
        self._rules = rules or default_rules()

    def scan(self, template: dict[str, Any] | Any) -> list[StaticFinding]:
        """Run all static rules and return structured findings."""
        normalized = ensure_template(template)
        findings: list[StaticFinding] = []
        for rule in self._rules:
            rule_findings = rule.scan(normalized)
            findings.extend(rule_findings)
            logger.info("static_rule_completed", rule_id=rule.rule_id, findings=len(rule_findings))
        logger.info("static_scan_completed", total_findings=len(findings), iac_type=normalized.iac_type)
        return findings

    def scan_to_dicts(self, template: dict[str, Any] | Any) -> list[dict[str, object]]:
        """Run rules and serialize findings to dictionaries."""
        return [finding.to_dict() for finding in self.scan(template)]


def default_rules() -> list[StaticRule]:
    """Return the built-in static rule set."""
    return [
        S3BucketEncryptionRule(),
        S3PublicAccessBlockRule(),
        IAMWildcardActionRule(),
        IAMWildcardResourceRule(),
        AdminPolicyRiskRule(),
        SecurityGroupSshOpenRule(),
        SecurityGroupRdpOpenRule(),
        SecurityGroupAllTrafficOpenRule(),
        RDSStorageEncryptionRule(),
        RDSPubliclyAccessibleRule(),
        AzureStoragePublicNetworkAccessRule(),
        AzureStorageMinimumTLSRule(),
        AzureKeyVaultPurgeProtectionRule(),
        AzureKeyVaultPublicNetworkRule(),
        AzureNetworkSecuritySshOpenRule(),
        AzureNetworkSecurityRdpOpenRule(),
        AzureNetworkSecurityAllTrafficOpenRule(),
        GCPStoragePublicIAMRule(),
        GCPFirewallSshOpenRule(),
        GCPFirewallRdpOpenRule(),
        GCPFirewallAllTrafficOpenRule(),
        GCPKMSRotationRule(),
        KubernetesPrivilegedContainerRule(),
        KubernetesHostNetworkRule(),
        KubernetesPrivilegeEscalationRule(),
        KubernetesRunAsRootRule(),
        KubernetesDangerousCapabilitiesRule(),
        HardcodedSecretRule(),
    ]
