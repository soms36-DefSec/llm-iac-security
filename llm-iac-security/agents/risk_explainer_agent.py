"""Risk explanation and auto-fix enrichment for IaC findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from iac.models import IaCResource, IaCTemplate


@dataclass(frozen=True)
class RiskGuidance:
    """Reusable human guidance for a deterministic rule finding."""

    risk_explanation: str
    attack_path: list[str]
    business_impact: str
    compliance_mappings: list[str]
    fix_summary: str
    policy_description: str
    fix_steps: list[str] = field(default_factory=list)


class RiskExplainerAgent:
    """Add risk explanations, attack paths, and safe auto-fix guidance."""

    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        findings_doc = context.get("findings")
        if not isinstance(findings_doc, dict):
            return context

        findings = findings_doc.get("findings") or findings_doc.get("vulnerabilities") or []
        if not isinstance(findings, list):
            return context

        template = _template_from_context(context)
        resources = {resource.logical_id: resource for resource in template.resources}
        enriched_findings = [
            enrich_finding(finding, resources.get(str(finding.get("resource_id", ""))))
            for finding in findings
            if isinstance(finding, dict)
        ]

        raw_summary = findings_doc.get("summary")
        summary = dict(raw_summary) if isinstance(raw_summary, dict) else {}
        if isinstance(raw_summary, str) and raw_summary:
            summary["note"] = raw_summary
        summary["autofix_available"] = sum(
            1 for finding in enriched_findings if finding.get("auto_fix", {}).get("available")
        )
        summary["risk_explainer"] = "enabled"

        enriched_doc = {
            **findings_doc,
            "findings": enriched_findings,
            "vulnerabilities": enriched_findings,
            "summary": summary,
        }
        return {
            **context,
            "findings": enriched_doc,
            "risk_explainer_enabled": True,
        }


def enrich_finding(
    finding: dict[str, Any],
    resource: IaCResource | None = None,
) -> dict[str, Any]:
    """Return a finding with risk explanation and auto-fix guidance."""
    rule_id = str(finding.get("rule_id", ""))
    guidance = _GUIDANCE.get(rule_id, _fallback_guidance(finding))
    auto_fix = _auto_fix_for(finding, resource, guidance)
    policy_as_code = _policy_as_code_for(finding, resource, guidance)
    return {
        **finding,
        "risk_explanation": guidance.risk_explanation,
        "attack_path": guidance.attack_path,
        "business_impact": guidance.business_impact,
        "compliance_mappings": guidance.compliance_mappings,
        "auto_fix": auto_fix,
        "policy_as_code": policy_as_code,
        "priority_reason": _priority_reason(finding, guidance),
    }


def _template_from_context(context: dict[str, Any]) -> IaCTemplate:
    normalized = context.get("normalized_template") or {}
    if isinstance(normalized, IaCTemplate):
        return normalized
    if isinstance(normalized, dict):
        return IaCTemplate.from_dict(normalized)
    return IaCTemplate(iac_type="terraform", source_path="")


def _auto_fix_for(
    finding: dict[str, Any],
    resource: IaCResource | None,
    guidance: RiskGuidance,
) -> dict[str, Any]:
    snippet = _fix_snippet(finding, resource)
    return {
        "available": bool(snippet),
        "summary": guidance.fix_summary,
        "safety": _fix_safety(finding),
        "patch_type": _patch_type(finding),
        "steps": guidance.fix_steps or _default_fix_steps(finding),
        "snippet": snippet,
    }


def _policy_as_code_for(
    finding: dict[str, Any],
    resource: IaCResource | None,
    guidance: RiskGuidance,
) -> dict[str, str]:
    rule_id = str(finding.get("rule_id", "UNKNOWN_RULE"))
    provider = str(finding.get("provider") or (resource.provider if resource else "unknown"))
    resource_type = str(finding.get("resource_type") or (resource.resource_type if resource else "resource"))
    resource_id = str(finding.get("resource_id", "resource"))
    package = f"iac.security.{_rego_identifier(provider)}"
    rego = (
        f"package {package}\n\n"
        f"deny[msg] {{\n"
        f'  input.rule_id == "{rule_id}"\n'
        f'  input.resource_type == "{resource_type}"\n'
        f'  msg := "{rule_id} must be remediated before deployment"\n'
        f"}}\n"
    )
    return {
        "type": "opa_rego_guardrail",
        "description": guidance.policy_description,
        "resource": resource_id,
        "rego": rego,
    }


def _fix_snippet(finding: dict[str, Any], resource: IaCResource | None) -> str:
    rule_id = str(finding.get("rule_id", ""))
    iac_type = str(finding.get("iac_type", "terraform"))
    resource_type = str(finding.get("resource_type", ""))
    resource_name = _resource_name(finding, resource)

    if rule_id == "AWS_S3_BUCKET_ENCRYPTION_MISSING":
        if iac_type == "cloudformation":
            return _yaml_block(
                [
                    "BucketEncryption:",
                    "  ServerSideEncryptionConfiguration:",
                    "    - ServerSideEncryptionByDefault:",
                    "        SSEAlgorithm: AES256",
                ]
            )
        return _hcl_block(
            [
                f'resource "aws_s3_bucket_server_side_encryption_configuration" "{resource_name}_encryption" {{',
                f"  bucket = aws_s3_bucket.{resource_name}.id",
                "",
                "  rule {",
                "    apply_server_side_encryption_by_default {",
                '      sse_algorithm = "AES256"',
                "    }",
                "  }",
                "}",
            ]
        )

    if rule_id == "AWS_S3_PUBLIC_ACCESS_BLOCK_WEAK":
        if iac_type == "cloudformation":
            return _yaml_block(
                [
                    "PublicAccessBlockConfiguration:",
                    "  BlockPublicAcls: true",
                    "  BlockPublicPolicy: true",
                    "  IgnorePublicAcls: true",
                    "  RestrictPublicBuckets: true",
                ]
            )
        if resource_type == "aws_s3_bucket_public_access_block":
            return _hcl_block(
                [
                    "block_public_acls       = true",
                    "block_public_policy     = true",
                    "ignore_public_acls      = true",
                    "restrict_public_buckets = true",
                ]
            )
        return _hcl_block(
            [
                f'resource "aws_s3_bucket_public_access_block" "{resource_name}_public_access_block" {{',
                f"  bucket = aws_s3_bucket.{resource_name}.id",
                "  block_public_acls       = true",
                "  block_public_policy     = true",
                "  ignore_public_acls      = true",
                "  restrict_public_buckets = true",
                "}",
            ]
        )

    if rule_id in {"AWS_IAM_WILDCARD_ACTION", "AWS_IAM_WILDCARD_RESOURCE", "AWS_IAM_ADMIN_POLICY"}:
        if iac_type == "cloudformation":
            return _yaml_block(
                [
                    "PolicyDocument:",
                    "  Version: '2012-10-17'",
                    "  Statement:",
                    "    - Effect: Allow",
                    "      Action:",
                    "        - service:SpecificAction",
                    "      Resource:",
                    "        - arn:aws:service:region:account-id:resource/resource-id",
                ]
            )
        return _hcl_block(
            [
                "# Replace wildcard permissions with the exact actions and ARNs the workload needs.",
                "statement {",
                '  effect    = "Allow"',
                '  actions   = ["service:SpecificAction"]',
                '  resources = ["arn:aws:service:region:account-id:resource/resource-id"]',
                "}",
            ]
        )

    if rule_id in {"AWS_SG_OPEN_SSH", "AWS_SG_OPEN_RDP"}:
        port = "22" if rule_id.endswith("SSH") else "3389"
        service = "SSH" if port == "22" else "RDP"
        if iac_type == "cloudformation":
            return _yaml_block(
                [
                    "SecurityGroupIngress:",
                    "  - IpProtocol: tcp",
                    f"    FromPort: {port}",
                    f"    ToPort: {port}",
                    "    CidrIp: <trusted-admin-cidr>/32",
                ]
            )
        return _hcl_block(
            [
                "ingress {",
                f'  description = "{service} from trusted admin network only"',
                "  protocol    = \"tcp\"",
                f"  from_port   = {port}",
                f"  to_port     = {port}",
                '  cidr_blocks = ["<trusted-admin-cidr>/32"]',
                "}",
            ]
        )

    if rule_id == "AWS_SG_OPEN_ALL_TRAFFIC":
        if iac_type == "cloudformation":
            return _yaml_block(
                [
                    "SecurityGroupIngress:",
                    "  - IpProtocol: tcp",
                    "    FromPort: 443",
                    "    ToPort: 443",
                    "    CidrIp: <trusted-application-cidr>",
                ]
            )
        return _hcl_block(
            [
                "# Remove the all-traffic 0.0.0.0/0 rule and add only required traffic.",
                "ingress {",
                '  description = "Required application traffic"',
                '  protocol    = "tcp"',
                "  from_port   = 443",
                "  to_port     = 443",
                '  cidr_blocks = ["<trusted-application-cidr>"]',
                "}",
            ]
        )

    if rule_id == "AWS_RDS_STORAGE_ENCRYPTION_DISABLED":
        if iac_type == "cloudformation":
            return _yaml_block(["StorageEncrypted: true", "KmsKeyId: !Ref RdsKmsKey"])
        return _hcl_block(["storage_encrypted = true", "kms_key_id        = aws_kms_key.rds.arn"])

    if rule_id == "AWS_RDS_PUBLICLY_ACCESSIBLE":
        if iac_type == "cloudformation":
            return _yaml_block(["PubliclyAccessible: false"])
        return _hcl_block(["publicly_accessible = false"])

    if rule_id == "AZURE_STORAGE_PUBLIC_NETWORK_ACCESS":
        return _hcl_block(["public_network_access_enabled = false"])

    if rule_id == "AZURE_STORAGE_MIN_TLS_WEAK":
        return _hcl_block(['min_tls_version = "TLS1_2"'])

    if rule_id == "AZURE_KEYVAULT_PURGE_PROTECTION_DISABLED":
        return _hcl_block(["purge_protection_enabled = true"])

    if rule_id == "AZURE_KEYVAULT_PUBLIC_NETWORK_ACCESS":
        return _hcl_block(
            [
                "public_network_access_enabled = false",
                "",
                "network_acls {",
                '  default_action = "Deny"',
                '  bypass         = "AzureServices"',
                "}",
            ]
        )

    if rule_id in {"AZURE_NSG_OPEN_SSH", "AZURE_NSG_OPEN_RDP"}:
        port = "22" if rule_id.endswith("SSH") else "3389"
        return _hcl_block(
            [
                'direction                  = "Inbound"',
                'access                     = "Allow"',
                'protocol                   = "Tcp"',
                f'destination_port_range    = "{port}"',
                'source_address_prefix      = "<trusted-admin-cidr>"',
            ]
        )

    if rule_id == "AZURE_NSG_OPEN_ALL_TRAFFIC":
        return _hcl_block(
            [
                "# Replace the broad inbound rule with the smallest required port and source.",
                'direction                  = "Inbound"',
                'access                     = "Allow"',
                'protocol                   = "Tcp"',
                'destination_port_range     = "443"',
                'source_address_prefix      = "<trusted-application-cidr>"',
            ]
        )

    if rule_id == "GCP_STORAGE_PUBLIC_IAM":
        return _hcl_block(
            [
                "# Remove allUsers/allAuthenticatedUsers from the IAM member list.",
                'members = ["serviceAccount:<workload-service-account>@<project>.iam.gserviceaccount.com"]',
            ]
        )

    if rule_id in {"GCP_FIREWALL_OPEN_SSH", "GCP_FIREWALL_OPEN_RDP"}:
        port = "22" if rule_id.endswith("SSH") else "3389"
        return _hcl_block(
            [
                'source_ranges = ["<trusted-admin-cidr>/32"]',
                "",
                "allow {",
                '  protocol = "tcp"',
                f'  ports    = ["{port}"]',
                "}",
            ]
        )

    if rule_id == "GCP_FIREWALL_OPEN_ALL_TRAFFIC":
        return _hcl_block(
            [
                'source_ranges = ["<trusted-application-cidr>"]',
                "",
                "allow {",
                '  protocol = "tcp"',
                '  ports    = ["443"]',
                "}",
            ]
        )

    if rule_id == "GCP_KMS_ROTATION_MISSING":
        return _hcl_block(['rotation_period = "7776000s"'])

    if rule_id in {
        "K8S_PRIVILEGED_CONTAINER",
        "K8S_ALLOW_PRIVILEGE_ESCALATION",
        "K8S_RUN_AS_ROOT",
        "K8S_DANGEROUS_CAPABILITIES",
    }:
        return _hcl_block(
            [
                "security_context {",
                "  privileged                 = false",
                "  allow_privilege_escalation = false",
                "  run_as_non_root            = true",
                "",
                "  capabilities {",
                '    drop = ["ALL"]',
                "  }",
                "}",
            ]
        )

    if rule_id == "K8S_HOST_NETWORK_ENABLED":
        return _hcl_block(["host_network = false"])

    if rule_id == "GENERIC_HARDCODED_SECRET":
        if iac_type == "cloudformation":
            return _yaml_block(["Password: '{{resolve:secretsmanager:secret-id:SecretString:password}}'"])
        return _hcl_block(
            [
                'variable "app_secret" {',
                "  type      = string",
                "  sensitive = true",
                "}",
                "",
                "# Replace the literal secret with a variable or managed secret reference.",
                "password = var.app_secret",
            ]
        )

    return ""


def _fix_safety(finding: dict[str, Any]) -> str:
    rule_id = str(finding.get("rule_id", ""))
    if rule_id in {"AWS_IAM_WILDCARD_ACTION", "AWS_IAM_WILDCARD_RESOURCE", "AWS_IAM_ADMIN_POLICY"}:
        return "review_required_permissions_must_match_workload"
    if rule_id == "GENERIC_HARDCODED_SECRET":
        return "review_required_secret_rotation_needed"
    return "candidate_safe_default_review_before_apply"


def _patch_type(finding: dict[str, Any]) -> str:
    rule_id = str(finding.get("rule_id", ""))
    if rule_id in {"GENERIC_HARDCODED_SECRET", "AWS_IAM_WILDCARD_ACTION", "AWS_IAM_WILDCARD_RESOURCE", "AWS_IAM_ADMIN_POLICY"}:
        return "guided_rewrite"
    if "MISSING" in rule_id or "DISABLED" in rule_id:
        return "add_or_update_property"
    return "update_property_or_block"


def _default_fix_steps(finding: dict[str, Any]) -> list[str]:
    resource_id = str(finding.get("resource_id", "the resource"))
    return [
        f"Update {resource_id} with the recommended secure setting.",
        "Run terraform validate, cfn-lint, or the equivalent IaC validation for the file type.",
        "Re-run the scanner to confirm the finding is resolved.",
    ]


def _priority_reason(finding: dict[str, Any], guidance: RiskGuidance) -> str:
    severity = str(finding.get("severity", "INFO")).upper()
    confidence = str(finding.get("confidence", "")).upper()
    return f"{severity} severity with {confidence or 'UNKNOWN'} confidence. {guidance.business_impact}"


def _resource_name(finding: dict[str, Any], resource: IaCResource | None) -> str:
    if resource and resource.name:
        return _hcl_identifier(resource.name)
    resource_id = str(finding.get("resource_id", "resource"))
    return _hcl_identifier(resource_id.split(".")[-1])


def _hcl_identifier(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in {"_", "-"} else "_" for char in value)
    return cleaned.strip("_") or "resource"


def _rego_identifier(value: str) -> str:
    cleaned = "".join(char if char.isalnum() else "_" for char in value.lower())
    return cleaned.strip("_") or "unknown"


def _hcl_block(lines: list[str]) -> str:
    return "\n".join(lines)


def _yaml_block(lines: list[str]) -> str:
    return "\n".join(lines)


def _fallback_guidance(finding: dict[str, Any]) -> RiskGuidance:
    title = str(finding.get("title", "IaC security finding"))
    return RiskGuidance(
        risk_explanation=f"{title} can weaken the intended security boundary for this cloud resource.",
        attack_path=[
            "An attacker identifies the exposed or weakly configured resource.",
            "The attacker attempts to use the weak control to access data, credentials, or runtime infrastructure.",
            "The weakness may support lateral movement or data exposure depending on the resource role.",
        ],
        business_impact="The issue can increase exposure, incident response effort, and audit risk.",
        compliance_mappings=["NIST SP 800-53 security control families", "CIS cloud benchmark guidance"],
        fix_summary=str(finding.get("remediation", "Apply the least-privilege secure configuration.")),
        policy_description="Block deployments that reproduce this finding.",
    )


_GUIDANCE: dict[str, RiskGuidance] = {
    "AWS_S3_BUCKET_ENCRYPTION_MISSING": RiskGuidance(
        risk_explanation="Objects in the bucket do not have an explicit default encryption control in IaC.",
        attack_path=[
            "A workload writes sensitive logs, exports, or customer data to the bucket.",
            "A misconfigured identity, replication path, or backup workflow exposes stored objects.",
            "Unencrypted data increases the impact of unauthorized storage access or mishandled copies.",
        ],
        business_impact="Sensitive object data may fail internal encryption standards and customer audit expectations.",
        compliance_mappings=["CIS AWS guidance for S3 encryption", "NIST SP 800-53 SC-13", "ISO 27001 cryptography controls"],
        fix_summary="Enable default server-side encryption with SSE-S3 or SSE-KMS.",
        policy_description="Require every S3 bucket to define default server-side encryption.",
    ),
    "AWS_S3_PUBLIC_ACCESS_BLOCK_WEAK": RiskGuidance(
        risk_explanation="The bucket lacks the full S3 public access block guardrail.",
        attack_path=[
            "A future bucket policy or ACL accidentally grants public access.",
            "Internet users can list or retrieve objects if another public setting is introduced.",
            "Sensitive logs, backups, or application assets may become publicly reachable.",
        ],
        business_impact="Public storage exposure can trigger data disclosure, regulatory reporting, and emergency remediation.",
        compliance_mappings=["CIS AWS guidance for S3 public access", "NIST SP 800-53 AC-3", "SOC 2 confidentiality criteria"],
        fix_summary="Set all four S3 public access block controls to true.",
        policy_description="Reject S3 buckets that do not block public ACLs and public policies.",
    ),
    "AWS_IAM_WILDCARD_ACTION": RiskGuidance(
        risk_explanation="Wildcard IAM actions grant more API permissions than the workload has proven it needs.",
        attack_path=[
            "An attacker compromises the principal or a service using this policy.",
            "The attacker calls extra APIs covered by the wildcard action.",
            "Those permissions can enable privilege escalation, persistence, or data access.",
        ],
        business_impact="Over-permissioned IAM increases blast radius and makes access reviews harder to defend.",
        compliance_mappings=["CIS AWS IAM least privilege guidance", "NIST SP 800-53 AC-6", "ISO 27001 access control"],
        fix_summary="Replace wildcard actions with the exact API actions required by the workload.",
        policy_description="Reject IAM policies that use wildcard or service-wide actions.",
        fix_steps=["Review CloudTrail or application requirements for required APIs.", "Replace wildcard actions with a minimal action list.", "Test the workload with least-privilege permissions."],
    ),
    "AWS_IAM_WILDCARD_RESOURCE": RiskGuidance(
        risk_explanation="Wildcard resources allow the policy to act across all matching resources.",
        attack_path=[
            "An attacker compromises the principal using this policy.",
            "The attacker applies allowed actions to unrelated resources in the account.",
            "The broader scope can expose data or modify infrastructure outside the intended workload.",
        ],
        business_impact="Resource-wide access increases account blast radius and weakens separation of duties.",
        compliance_mappings=["CIS AWS IAM least privilege guidance", "NIST SP 800-53 AC-6", "SOC 2 logical access controls"],
        fix_summary="Scope Resource to specific ARNs wherever the action supports resource-level permissions.",
        policy_description="Reject IAM Allow statements that use Resource \"*\" for resource-scoped actions.",
        fix_steps=["Identify the exact resources the workload needs.", "Replace Resource \"*\" with those ARNs.", "Keep Resource \"*\" only where AWS does not support resource-level permissions and document the exception."],
    ),
    "AWS_IAM_ADMIN_POLICY": RiskGuidance(
        risk_explanation="AdministratorAccess-like policies can fully control the account or workload boundary.",
        attack_path=[
            "An attacker obtains credentials for the principal.",
            "The attacker creates new users, roles, policies, or access keys.",
            "The attacker can disable controls, persist access, and move through the cloud account.",
        ],
        business_impact="A single credential compromise can become a full account compromise.",
        compliance_mappings=["CIS AWS IAM least privilege guidance", "NIST SP 800-53 AC-6", "ISO 27001 privileged access controls"],
        fix_summary="Replace AdministratorAccess with narrowly scoped managed or custom policies.",
        policy_description="Reject AdministratorAccess attachments and Allow Action \"*\" with Resource \"*\".",
        fix_steps=["Remove AdministratorAccess from workload roles.", "Create task-specific policies.", "Require break-glass admin access to use monitored, time-bound roles."],
    ),
    "AWS_SG_OPEN_SSH": RiskGuidance(
        risk_explanation="SSH is reachable from the internet, exposing administrative access to brute force and credential attacks.",
        attack_path=["An attacker scans the public IP range.", "The attacker finds port 22 open.", "The attacker attempts stolen keys, weak credentials, or SSH service exploits."],
        business_impact="A successful SSH compromise can lead to host takeover and lateral movement.",
        compliance_mappings=["CIS AWS network exposure guidance", "NIST SP 800-53 SC-7", "SOC 2 change and access controls"],
        fix_summary="Restrict SSH to a trusted VPN, bastion, or administrator CIDR.",
        policy_description="Reject security groups that expose SSH to 0.0.0.0/0 or ::/0.",
    ),
    "AWS_SG_OPEN_RDP": RiskGuidance(
        risk_explanation="RDP is reachable from the internet, exposing Windows administration to credential attacks.",
        attack_path=["An attacker scans for port 3389.", "The attacker attempts password spraying or known RDP weaknesses.", "The attacker gains interactive access to the instance."],
        business_impact="A successful RDP compromise can expose systems, credentials, and internal network paths.",
        compliance_mappings=["CIS AWS network exposure guidance", "NIST SP 800-53 SC-7", "ISO 27001 network security controls"],
        fix_summary="Restrict RDP to a trusted VPN, bastion, or administrator CIDR.",
        policy_description="Reject security groups that expose RDP to 0.0.0.0/0 or ::/0.",
    ),
    "AWS_SG_OPEN_ALL_TRAFFIC": RiskGuidance(
        risk_explanation="All inbound protocols and ports are reachable from the internet.",
        attack_path=["An attacker scans every exposed service.", "Any vulnerable service can be targeted directly.", "The compromised host can become a pivot point into private systems."],
        business_impact="Broad internet exposure materially increases likelihood and impact of compromise.",
        compliance_mappings=["CIS AWS network exposure guidance", "NIST SP 800-53 SC-7", "SOC 2 security criteria"],
        fix_summary="Remove unrestricted ingress and allow only required protocols, ports, and trusted sources.",
        policy_description="Reject all-traffic ingress from public CIDR ranges.",
    ),
    "AWS_RDS_STORAGE_ENCRYPTION_DISABLED": RiskGuidance(
        risk_explanation="Database storage encryption is not explicitly enabled.",
        attack_path=["A snapshot, backup, or storage layer copy is accessed outside the intended boundary.", "Unencrypted data increases exposure if storage media or exports are mishandled.", "The incident may require broader disclosure review."],
        business_impact="Database data may violate encryption baselines and increase audit findings.",
        compliance_mappings=["CIS AWS database encryption guidance", "NIST SP 800-53 SC-13", "PCI-DSS encryption expectations"],
        fix_summary="Enable RDS storage encryption and use a customer-managed KMS key where appropriate.",
        policy_description="Reject RDS instances that do not explicitly enable storage encryption.",
    ),
    "AWS_RDS_PUBLICLY_ACCESSIBLE": RiskGuidance(
        risk_explanation="The database is configured for public network reachability.",
        attack_path=["An attacker discovers the database endpoint.", "The attacker attempts credential attacks or database engine exploits.", "Successful access can expose application data directly."],
        business_impact="Public databases create high-impact data exposure and incident response risk.",
        compliance_mappings=["CIS AWS database network guidance", "NIST SP 800-53 SC-7", "SOC 2 confidentiality criteria"],
        fix_summary="Set publicly accessible to false and place the database in private subnets.",
        policy_description="Reject RDS instances marked publicly accessible.",
    ),
    "AZURE_STORAGE_PUBLIC_NETWORK_ACCESS": RiskGuidance(
        risk_explanation="The storage account allows network access from public endpoints.",
        attack_path=["An attacker reaches the storage endpoint from the internet.", "Any weak identity, SAS token, or ACL issue becomes externally exploitable.", "Stored data may be read, changed, or deleted."],
        business_impact="Public storage reachability raises the likelihood of data exposure and audit exceptions.",
        compliance_mappings=["CIS Azure storage network guidance", "NIST SP 800-53 SC-7", "ISO 27001 network controls"],
        fix_summary="Disable public network access and use private endpoints where possible.",
        policy_description="Reject Azure Storage accounts with public network access enabled.",
    ),
    "AZURE_STORAGE_MIN_TLS_WEAK": RiskGuidance(
        risk_explanation="The storage account does not require TLS 1.2 or newer.",
        attack_path=["A client connects using an older TLS protocol.", "Weak transport settings increase downgrade or interception risk.", "Sensitive data in transit may not meet modern security baselines."],
        business_impact="Weak TLS can fail compliance checks and customer security requirements.",
        compliance_mappings=["CIS Azure storage TLS guidance", "NIST SP 800-53 SC-8", "PCI-DSS secure transmission expectations"],
        fix_summary="Set minimum TLS version to TLS1_2 or TLS1_3.",
        policy_description="Reject Azure Storage accounts below TLS 1.2.",
    ),
    "AZURE_KEYVAULT_PURGE_PROTECTION_DISABLED": RiskGuidance(
        risk_explanation="Key Vault secrets and keys can be permanently purged after deletion.",
        attack_path=["An attacker or mistaken operator deletes vault contents.", "Without purge protection, recovery may be impossible.", "Applications depending on keys or secrets can fail or lose protected data."],
        business_impact="Permanent secret or key loss can cause outages and data recovery problems.",
        compliance_mappings=["CIS Azure Key Vault resilience guidance", "NIST SP 800-53 CP-10", "ISO 27001 backup and recovery controls"],
        fix_summary="Enable purge protection for the Key Vault.",
        policy_description="Reject Azure Key Vaults without purge protection.",
    ),
    "AZURE_KEYVAULT_PUBLIC_NETWORK_ACCESS": RiskGuidance(
        risk_explanation="The Key Vault accepts connections over public network paths.",
        attack_path=["An attacker reaches the vault endpoint from the internet.", "Any credential, firewall, or access policy weakness becomes externally reachable.", "Secrets, keys, or certificates may be targeted directly."],
        business_impact="Public secret-store exposure increases credential theft and compliance risk.",
        compliance_mappings=["CIS Azure Key Vault network guidance", "NIST SP 800-53 SC-7", "SOC 2 confidentiality criteria"],
        fix_summary="Disable public network access and use private endpoints or restrictive network ACLs.",
        policy_description="Reject Azure Key Vaults with public network access enabled.",
    ),
    "AZURE_NSG_OPEN_SSH": RiskGuidance(
        risk_explanation="The Azure NSG allows SSH from the internet.",
        attack_path=["An attacker scans for SSH on public Azure IPs.", "The attacker attempts credential or key compromise.", "A successful login can expose the VM and connected network."],
        business_impact="Internet-exposed administration increases compromise and lateral movement risk.",
        compliance_mappings=["CIS Azure network guidance", "NIST SP 800-53 SC-7", "ISO 27001 network controls"],
        fix_summary="Restrict SSH access to trusted administrator source ranges.",
        policy_description="Reject Azure NSG rules exposing SSH to the internet.",
    ),
    "AZURE_NSG_OPEN_RDP": RiskGuidance(
        risk_explanation="The Azure NSG allows RDP from the internet.",
        attack_path=["An attacker scans for RDP on public Azure IPs.", "The attacker performs password spraying or exploit attempts.", "A successful login can expose the VM and credentials."],
        business_impact="Internet-exposed RDP is a common path to system compromise.",
        compliance_mappings=["CIS Azure network guidance", "NIST SP 800-53 SC-7", "SOC 2 security criteria"],
        fix_summary="Restrict RDP access to trusted administrator source ranges.",
        policy_description="Reject Azure NSG rules exposing RDP to the internet.",
    ),
    "AZURE_NSG_OPEN_ALL_TRAFFIC": RiskGuidance(
        risk_explanation="The Azure NSG allows all inbound traffic from public sources.",
        attack_path=["An attacker scans every reachable port.", "Any vulnerable service can be attacked directly.", "The compromised workload can expose data or internal routes."],
        business_impact="Broad public ingress increases compromise likelihood and operational response cost.",
        compliance_mappings=["CIS Azure network guidance", "NIST SP 800-53 SC-7", "ISO 27001 network controls"],
        fix_summary="Limit inbound access to required ports and trusted source ranges.",
        policy_description="Reject Azure NSG all-traffic inbound rules from internet sources.",
    ),
    "GCP_STORAGE_PUBLIC_IAM": RiskGuidance(
        risk_explanation="The storage bucket IAM grants access to public principals.",
        attack_path=["An internet user accesses the bucket through allUsers or allAuthenticatedUsers.", "Objects can be read or modified depending on the granted role.", "Public access can expose sensitive application or customer data."],
        business_impact="Public bucket IAM can lead to immediate data disclosure and compliance incidents.",
        compliance_mappings=["CIS GCP storage IAM guidance", "NIST SP 800-53 AC-3", "SOC 2 confidentiality criteria"],
        fix_summary="Remove public principals and grant access only to named identities.",
        policy_description="Reject GCP Storage IAM grants to allUsers or allAuthenticatedUsers.",
    ),
    "GCP_FIREWALL_OPEN_SSH": RiskGuidance(
        risk_explanation="The GCP firewall allows SSH from the internet.",
        attack_path=["An attacker scans public GCP addresses for SSH.", "The attacker attempts key theft, weak credentials, or SSH exploits.", "A successful compromise can expose the VM and service account."],
        business_impact="Internet-exposed administration increases host and cloud identity blast radius.",
        compliance_mappings=["CIS GCP network guidance", "NIST SP 800-53 SC-7", "ISO 27001 network controls"],
        fix_summary="Restrict SSH to trusted administrator source ranges.",
        policy_description="Reject GCP firewall rules exposing SSH to public source ranges.",
    ),
    "GCP_FIREWALL_OPEN_RDP": RiskGuidance(
        risk_explanation="The GCP firewall allows RDP from the internet.",
        attack_path=["An attacker scans for RDP.", "The attacker attempts credential attacks or service exploits.", "A successful login can expose host data and internal paths."],
        business_impact="Internet-exposed RDP materially increases compromise risk.",
        compliance_mappings=["CIS GCP network guidance", "NIST SP 800-53 SC-7", "SOC 2 security criteria"],
        fix_summary="Restrict RDP to trusted administrator source ranges.",
        policy_description="Reject GCP firewall rules exposing RDP to public source ranges.",
    ),
    "GCP_FIREWALL_OPEN_ALL_TRAFFIC": RiskGuidance(
        risk_explanation="The GCP firewall allows all traffic from public source ranges.",
        attack_path=["An attacker scans all exposed ports.", "Any service on the instance can be targeted.", "The compromised instance can expose data or internal services."],
        business_impact="Broad public firewall exposure increases incident likelihood and blast radius.",
        compliance_mappings=["CIS GCP network guidance", "NIST SP 800-53 SC-7", "ISO 27001 network controls"],
        fix_summary="Restrict firewall source ranges, protocols, and ports to least privilege.",
        policy_description="Reject GCP firewall rules allowing all traffic from public sources.",
    ),
    "GCP_KMS_ROTATION_MISSING": RiskGuidance(
        risk_explanation="The KMS key does not define automatic rotation.",
        attack_path=["A long-lived key is exposed or overused.", "The same key protects data for longer than policy allows.", "Recovery requires manual rotation and broad re-encryption review."],
        business_impact="Missing key rotation can fail cryptographic hygiene and audit requirements.",
        compliance_mappings=["CIS GCP KMS guidance", "NIST SP 800-57 key management guidance", "ISO 27001 cryptography controls"],
        fix_summary="Set an organization-approved KMS rotation period.",
        policy_description="Reject GCP KMS keys without a rotation period.",
    ),
    "K8S_PRIVILEGED_CONTAINER": RiskGuidance(
        risk_explanation="A privileged container can access host-level capabilities beyond normal container isolation.",
        attack_path=["An attacker exploits the application container.", "Privileged mode gives access to host devices and kernel-sensitive operations.", "The attacker may escape the container or affect other workloads."],
        business_impact="Privileged workloads can turn an application bug into node compromise.",
        compliance_mappings=["Kubernetes Pod Security Standards", "NIST SP 800-190 container security", "CIS Kubernetes benchmark guidance"],
        fix_summary="Disable privileged mode and grant only the minimum required capabilities.",
        policy_description="Reject Kubernetes workloads with privileged containers.",
    ),
    "K8S_HOST_NETWORK_ENABLED": RiskGuidance(
        risk_explanation="The workload uses the node network namespace instead of pod network isolation.",
        attack_path=["An attacker compromises the pod.", "Host networking gives broader visibility and port binding capability on the node.", "The attacker can interfere with node-level traffic or services."],
        business_impact="Host networking weakens workload isolation and complicates network policy enforcement.",
        compliance_mappings=["Kubernetes Pod Security Standards", "NIST SP 800-190 container security", "CIS Kubernetes benchmark guidance"],
        fix_summary="Disable host networking unless the workload has a documented node-level networking requirement.",
        policy_description="Reject Kubernetes workloads with host networking enabled.",
    ),
    "K8S_ALLOW_PRIVILEGE_ESCALATION": RiskGuidance(
        risk_explanation="The container can allow a process to gain more privileges than its parent process.",
        attack_path=["An attacker exploits a process inside the container.", "Privilege escalation paths inside the container remain available.", "The attacker increases control over the workload or node-facing interfaces."],
        business_impact="Privilege escalation can convert a low-privilege bug into a high-impact compromise.",
        compliance_mappings=["Kubernetes Pod Security Standards", "NIST SP 800-190 container security", "CIS Kubernetes benchmark guidance"],
        fix_summary="Set allow_privilege_escalation to false in each container security context.",
        policy_description="Reject Kubernetes containers that allow privilege escalation.",
    ),
    "K8S_RUN_AS_ROOT": RiskGuidance(
        risk_explanation="The container can run as UID 0, increasing the impact of application compromise.",
        attack_path=["An attacker exploits the application process.", "The process already runs as root inside the container.", "Misconfigured mounts or runtime weaknesses can increase node impact."],
        business_impact="Root containers weaken workload hardening and can fail platform security baselines.",
        compliance_mappings=["Kubernetes Pod Security Standards", "NIST SP 800-190 container security", "CIS Kubernetes benchmark guidance"],
        fix_summary="Require non-root execution and use a non-zero run_as_user value.",
        policy_description="Reject Kubernetes containers that run as root or do not require non-root execution.",
    ),
    "K8S_DANGEROUS_CAPABILITIES": RiskGuidance(
        risk_explanation="The container adds Linux capabilities that can bypass normal workload isolation.",
        attack_path=["An attacker compromises the container.", "Dangerous capabilities provide elevated kernel or network control.", "The attacker can tamper with the node, traffic, or neighboring workloads."],
        business_impact="Dangerous capabilities increase the chance of node compromise from an application issue.",
        compliance_mappings=["Kubernetes Pod Security Standards", "NIST SP 800-190 container security", "CIS Kubernetes benchmark guidance"],
        fix_summary="Drop all capabilities by default and add back only what the workload proves it needs.",
        policy_description="Reject Kubernetes containers that add ALL, SYS_ADMIN, or NET_ADMIN capabilities.",
    ),
    "GENERIC_HARDCODED_SECRET": RiskGuidance(
        risk_explanation="A secret-like value appears directly in IaC, where it can be copied into Git history, logs, and review tools.",
        attack_path=["An attacker or insider reads repository history, artifacts, or scan logs.", "The exposed secret is used against the application or cloud provider.", "The credential may remain valid until rotated everywhere it was used."],
        business_impact="Hardcoded secrets create credential theft, rotation, and incident response risk.",
        compliance_mappings=["CIS secrets management guidance", "NIST SP 800-53 IA-5", "SOC 2 logical access controls"],
        fix_summary="Move the value to a managed secret store or sensitive variable and rotate the exposed credential.",
        policy_description="Reject literal secret-looking values in IaC properties.",
        fix_steps=["Remove the literal value from IaC.", "Store the secret in a managed secret service or secure CI variable.", "Rotate the exposed credential before redeploying."],
    ),
}
