from iac.models import IaCResource, IaCTemplate
from static_analysis.engine import StaticAnalysisEngine
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


def _template(*resources: IaCResource) -> IaCTemplate:
    return IaCTemplate(
        iac_type="terraform",
        source_path="test.tf",
        resources=list(resources),
    )


def test_azure_storage_rules_detect_public_network_and_weak_tls():
    resource = IaCResource(
        logical_id="azurerm_storage_account.logs",
        resource_type="azurerm_storage_account",
        provider="azure",
        properties={
            "public_network_access_enabled": True,
            "min_tls_version": "TLS1_0",
        },
    )
    template = _template(resource)

    assert [finding.rule_id for finding in AzureStoragePublicNetworkAccessRule().scan(template)] == [
        "AZURE_STORAGE_PUBLIC_NETWORK_ACCESS"
    ]
    assert [finding.rule_id for finding in AzureStorageMinimumTLSRule().scan(template)] == [
        "AZURE_STORAGE_MIN_TLS_WEAK"
    ]


def test_azure_storage_rules_ignore_private_network_and_modern_tls():
    resource = IaCResource(
        logical_id="azurerm_storage_account.secure",
        resource_type="azurerm_storage_account",
        provider="azure",
        properties={
            "public_network_access_enabled": False,
            "min_tls_version": "TLS1_2",
        },
    )
    template = _template(resource)

    assert AzureStoragePublicNetworkAccessRule().scan(template) == []
    assert AzureStorageMinimumTLSRule().scan(template) == []


def test_gcp_storage_public_iam_rule_detects_public_members():
    resource = IaCResource(
        logical_id="google_storage_bucket_iam_binding.public",
        resource_type="google_storage_bucket_iam_binding",
        provider="gcp",
        properties={
            "role": "roles/storage.objectViewer",
            "members": ["allUsers"],
        },
    )
    findings = GCPStoragePublicIAMRule().scan(_template(resource))

    assert [finding.rule_id for finding in findings] == ["GCP_STORAGE_PUBLIC_IAM"]


def test_gcp_storage_public_iam_rule_ignores_named_identities():
    resource = IaCResource(
        logical_id="google_storage_bucket_iam_member.private",
        resource_type="google_storage_bucket_iam_member",
        provider="gcp",
        properties={
            "role": "roles/storage.objectViewer",
            "member": "serviceAccount:scanner@example.iam.gserviceaccount.com",
        },
    )

    assert GCPStoragePublicIAMRule().scan(_template(resource)) == []


def test_azure_key_vault_rules_detect_public_vault_without_purge_protection():
    resource = IaCResource(
        logical_id="azurerm_key_vault.main",
        resource_type="azurerm_key_vault",
        provider="azure",
        properties={
            "purge_protection_enabled": False,
            "public_network_access_enabled": True,
        },
    )
    template = _template(resource)

    assert [finding.rule_id for finding in AzureKeyVaultPurgeProtectionRule().scan(template)] == [
        "AZURE_KEYVAULT_PURGE_PROTECTION_DISABLED"
    ]
    assert [finding.rule_id for finding in AzureKeyVaultPublicNetworkRule().scan(template)] == [
        "AZURE_KEYVAULT_PUBLIC_NETWORK_ACCESS"
    ]


def test_azure_nsg_rules_detect_open_admin_and_all_traffic():
    resource = IaCResource(
        logical_id="azurerm_network_security_group.web",
        resource_type="azurerm_network_security_group",
        provider="azure",
        properties={
            "security_rule": [
                {
                    "name": "ssh",
                    "access": "Allow",
                    "direction": "Inbound",
                    "protocol": "Tcp",
                    "source_address_prefix": "0.0.0.0/0",
                    "destination_port_range": "22",
                },
                {
                    "name": "rdp",
                    "access": "Allow",
                    "direction": "Inbound",
                    "protocol": "Tcp",
                    "source_address_prefix": "Internet",
                    "destination_port_range": "3389",
                },
                {
                    "name": "all",
                    "access": "Allow",
                    "direction": "Inbound",
                    "protocol": "*",
                    "source_address_prefix": "*",
                    "destination_port_range": "*",
                },
            ]
        },
    )
    template = _template(resource)

    assert AzureNetworkSecuritySshOpenRule().scan(template)
    assert AzureNetworkSecurityRdpOpenRule().scan(template)
    assert AzureNetworkSecurityAllTrafficOpenRule().scan(template)


def test_gcp_firewall_and_kms_rules_detect_public_access_and_missing_rotation():
    firewall = IaCResource(
        logical_id="google_compute_firewall.open",
        resource_type="google_compute_firewall",
        provider="gcp",
        properties={
            "direction": "INGRESS",
            "source_ranges": ["0.0.0.0/0"],
            "allow": [
                {"protocol": "tcp", "ports": ["22", "3389"]},
                {"protocol": "all"},
            ],
        },
    )
    key = IaCResource(
        logical_id="google_kms_crypto_key.app",
        resource_type="google_kms_crypto_key",
        provider="gcp",
        properties={"name": "app"},
    )
    template = _template(firewall, key)

    assert GCPFirewallSshOpenRule().scan(template)
    assert GCPFirewallRdpOpenRule().scan(template)
    assert GCPFirewallAllTrafficOpenRule().scan(template)
    assert GCPKMSRotationRule().scan(template)


def test_kubernetes_rules_detect_privileged_and_host_network():
    resource = IaCResource(
        logical_id="kubernetes_pod.app",
        resource_type="kubernetes_pod",
        provider="kubernetes",
        properties={
            "spec": [
                {
                    "host_network": True,
                    "container": [
                        {
                            "name": "app",
                            "security_context": [{"privileged": True}],
                        }
                    ],
                }
            ]
        },
    )
    template = _template(resource)

    assert [finding.rule_id for finding in KubernetesPrivilegedContainerRule().scan(template)] == [
        "K8S_PRIVILEGED_CONTAINER"
    ]
    assert [finding.rule_id for finding in KubernetesHostNetworkRule().scan(template)] == [
        "K8S_HOST_NETWORK_ENABLED"
    ]


def test_kubernetes_rules_detect_escalation_root_and_dangerous_capabilities():
    resource = IaCResource(
        logical_id="kubernetes_pod.app",
        resource_type="kubernetes_pod",
        provider="kubernetes",
        properties={
            "spec": [
                {
                    "container": [
                        {
                            "security_context": [
                                {
                                    "allow_privilege_escalation": True,
                                    "run_as_user": 0,
                                    "capabilities": [{"add": ["SYS_ADMIN"]}],
                                }
                            ],
                        }
                    ],
                }
            ]
        },
    )
    template = _template(resource)

    assert KubernetesPrivilegeEscalationRule().scan(template)
    assert KubernetesRunAsRootRule().scan(template)
    assert KubernetesDangerousCapabilitiesRule().scan(template)


def test_kubernetes_rules_ignore_restricted_workloads():
    resource = IaCResource(
        logical_id="kubernetes_pod.app",
        resource_type="kubernetes_pod",
        provider="kubernetes",
        properties={
            "spec": [
                {
                    "host_network": False,
                    "container": [
                        {
                            "name": "app",
                            "security_context": [{"privileged": False}],
                        }
                    ],
                }
            ]
        },
    )
    template = _template(resource)

    assert KubernetesPrivilegedContainerRule().scan(template) == []
    assert KubernetesHostNetworkRule().scan(template) == []


def test_static_engine_includes_multi_provider_rules():
    template = _template(
        IaCResource(
            logical_id="azurerm_storage_account.logs",
            resource_type="azurerm_storage_account",
            provider="azure",
            properties={"public_network_access_enabled": True, "min_tls_version": "TLS1_0"},
        ),
        IaCResource(
            logical_id="google_storage_bucket_iam_member.public",
            resource_type="google_storage_bucket_iam_member",
            provider="gcp",
            properties={"role": "roles/storage.objectViewer", "member": "allAuthenticatedUsers"},
        ),
        IaCResource(
            logical_id="kubernetes_deployment.app",
            resource_type="kubernetes_deployment",
            provider="kubernetes",
            properties={
                "spec": [
                    {
                        "template": [
                            {
                                "spec": [
                                    {
                                        "host_network": True,
                                        "container": [
                                            {
                                                "security_context": [
                                                    {
                                                        "allow_privilege_escalation": True,
                                                        "run_as_user": 0,
                                                        "capabilities": [{"add": ["ALL"]}],
                                                    }
                                                ]
                                            }
                                        ],
                                    }
                                ]
                            }
                        ]
                    }
                ]
            },
        ),
    )

    rule_ids = {finding.rule_id for finding in StaticAnalysisEngine().scan(template)}
    assert {
        "AZURE_STORAGE_PUBLIC_NETWORK_ACCESS",
        "AZURE_STORAGE_MIN_TLS_WEAK",
        "GCP_STORAGE_PUBLIC_IAM",
        "K8S_HOST_NETWORK_ENABLED",
        "K8S_ALLOW_PRIVILEGE_ESCALATION",
        "K8S_RUN_AS_ROOT",
        "K8S_DANGEROUS_CAPABILITIES",
    }.issubset(rule_ids)
