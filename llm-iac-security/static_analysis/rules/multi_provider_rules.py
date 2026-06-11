"""Static rules for non-AWS Terraform providers."""

from __future__ import annotations

from typing import Any

from iac.models import IaCResource, IaCTemplate
from static_analysis.base_rule import StaticRule, as_list, falsey, safe_json, truthy, walk_properties


class AzureStoragePublicNetworkAccessRule(StaticRule):
    """Detect Azure storage accounts exposed to public networks."""

    rule_id = "AZURE_STORAGE_PUBLIC_NETWORK_ACCESS"
    title = "Azure Storage Account public network access enabled"
    severity = "HIGH"
    provider = "azure"
    tags = ["azure", "storage", "network"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in _resources_by_type(template, "azurerm_storage_account"):
            value = resource.properties.get("public_network_access_enabled")
            if value is not False:
                findings.append(
                    self.finding(
                        template,
                        resource,
                        "The Azure Storage Account allows public network access.",
                        f"public_network_access_enabled is {value!r}.",
                        "Set public_network_access_enabled to false and use private endpoints where possible.",
                    )
                )
        return findings


class AzureStorageMinimumTLSRule(StaticRule):
    """Detect Azure storage accounts that do not require TLS 1.2 or newer."""

    rule_id = "AZURE_STORAGE_MIN_TLS_WEAK"
    title = "Azure Storage Account minimum TLS version is weak"
    severity = "MEDIUM"
    provider = "azure"
    tags = ["azure", "storage", "tls"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in _resources_by_type(template, "azurerm_storage_account"):
            value = resource.properties.get("min_tls_version")
            if value not in {"TLS1_2", "TLS1_3"}:
                findings.append(
                    self.finding(
                        template,
                        resource,
                        "The Azure Storage Account does not enforce TLS 1.2 or newer.",
                        f"min_tls_version is {value!r}.",
                        "Set min_tls_version to TLS1_2 or TLS1_3.",
                    )
                )
        return findings


class AzureKeyVaultPurgeProtectionRule(StaticRule):
    """Detect Azure Key Vaults without purge protection."""

    rule_id = "AZURE_KEYVAULT_PURGE_PROTECTION_DISABLED"
    title = "Azure Key Vault purge protection is disabled"
    severity = "HIGH"
    provider = "azure"
    tags = ["azure", "key-vault", "data-protection"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in _resources_by_type(template, "azurerm_key_vault"):
            value = resource.properties.get("purge_protection_enabled")
            if value is not True:
                findings.append(
                    self.finding(
                        template,
                        resource,
                        "The Azure Key Vault does not require purge protection.",
                        f"purge_protection_enabled is {value!r}.",
                        "Set purge_protection_enabled to true to prevent irreversible secret/key deletion.",
                    )
                )
        return findings


class AzureKeyVaultPublicNetworkRule(StaticRule):
    """Detect Azure Key Vaults reachable from public networks."""

    rule_id = "AZURE_KEYVAULT_PUBLIC_NETWORK_ACCESS"
    title = "Azure Key Vault public network access enabled"
    severity = "HIGH"
    provider = "azure"
    tags = ["azure", "key-vault", "network"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in _resources_by_type(template, "azurerm_key_vault"):
            value = resource.properties.get("public_network_access_enabled")
            if value is not False:
                findings.append(
                    self.finding(
                        template,
                        resource,
                        "The Azure Key Vault allows public network access.",
                        f"public_network_access_enabled is {value!r}.",
                        "Disable public network access and use private endpoints or tightly scoped network ACLs.",
                    )
                )
        return findings


class AzureNetworkSecuritySshOpenRule(StaticRule):
    """Detect Azure NSG rules exposing SSH to the internet."""

    rule_id = "AZURE_NSG_OPEN_SSH"
    title = "Azure Network Security Group allows SSH from the internet"
    severity = "HIGH"
    provider = "azure"
    tags = ["azure", "network", "ssh"]

    def scan(self, template: IaCTemplate):
        return _scan_azure_nsg_port_rule(self, template, "22", "SSH")


class AzureNetworkSecurityRdpOpenRule(StaticRule):
    """Detect Azure NSG rules exposing RDP to the internet."""

    rule_id = "AZURE_NSG_OPEN_RDP"
    title = "Azure Network Security Group allows RDP from the internet"
    severity = "HIGH"
    provider = "azure"
    tags = ["azure", "network", "rdp"]

    def scan(self, template: IaCTemplate):
        return _scan_azure_nsg_port_rule(self, template, "3389", "RDP")


class AzureNetworkSecurityAllTrafficOpenRule(StaticRule):
    """Detect Azure NSG rules exposing all inbound traffic to the internet."""

    rule_id = "AZURE_NSG_OPEN_ALL_TRAFFIC"
    title = "Azure Network Security Group allows all traffic from the internet"
    severity = "CRITICAL"
    provider = "azure"
    tags = ["azure", "network", "public-access"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in template.resources:
            for suffix, rule in _azure_security_rules(resource):
                if _azure_rule_is_inbound_allow(rule) and _has_internet_source(rule) and _allows_all_ports(rule):
                    findings.append(
                        self.finding(
                            template,
                            resource,
                            "The Azure NSG rule allows all inbound traffic from the internet.",
                            f"source={_source_evidence(rule)}, ports={_port_evidence(rule)}, protocol={rule.get('protocol')!r}.",
                            "Restrict inbound access to required ports and trusted source CIDR ranges.",
                            suffix=suffix,
                        )
                    )
        return findings


class GCPStoragePublicIAMRule(StaticRule):
    """Detect public IAM grants on GCP storage buckets."""

    rule_id = "GCP_STORAGE_PUBLIC_IAM"
    title = "GCP Storage bucket IAM grants public access"
    severity = "HIGH"
    provider = "gcp"
    tags = ["gcp", "storage", "iam", "public-access"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in template.resources:
            if resource.resource_type not in {
                "google_storage_bucket_iam_binding",
                "google_storage_bucket_iam_member",
            }:
                continue
            members = _members(resource.properties)
            role = str(resource.properties.get("role", ""))
            public_members = sorted(member for member in members if member in {"allUsers", "allAuthenticatedUsers"})
            if public_members:
                findings.append(
                    self.finding(
                        template,
                        resource,
                        "The GCP Storage bucket IAM resource grants access to public principals.",
                        f"role={role!r}, public members={', '.join(public_members)}.",
                        "Remove allUsers/allAuthenticatedUsers grants and use least-privilege identities.",
                    )
                )
        return findings


class GCPFirewallSshOpenRule(StaticRule):
    """Detect GCP firewall rules exposing SSH to the internet."""

    rule_id = "GCP_FIREWALL_OPEN_SSH"
    title = "GCP firewall allows SSH from the internet"
    severity = "HIGH"
    provider = "gcp"
    tags = ["gcp", "network", "ssh"]

    def scan(self, template: IaCTemplate):
        return _scan_gcp_firewall_port_rule(self, template, "22", "SSH")


class GCPFirewallRdpOpenRule(StaticRule):
    """Detect GCP firewall rules exposing RDP to the internet."""

    rule_id = "GCP_FIREWALL_OPEN_RDP"
    title = "GCP firewall allows RDP from the internet"
    severity = "HIGH"
    provider = "gcp"
    tags = ["gcp", "network", "rdp"]

    def scan(self, template: IaCTemplate):
        return _scan_gcp_firewall_port_rule(self, template, "3389", "RDP")


class GCPFirewallAllTrafficOpenRule(StaticRule):
    """Detect GCP firewall rules exposing all traffic to the internet."""

    rule_id = "GCP_FIREWALL_OPEN_ALL_TRAFFIC"
    title = "GCP firewall allows all traffic from the internet"
    severity = "CRITICAL"
    provider = "gcp"
    tags = ["gcp", "network", "public-access"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in _resources_by_type(template, "google_compute_firewall"):
            if not _gcp_firewall_is_ingress(resource.properties) or not _has_internet_source(resource.properties):
                continue
            for index, allow in enumerate(as_list(resource.properties.get("allow"))):
                if isinstance(allow, dict) and _gcp_allow_all_traffic(allow):
                    findings.append(
                        self.finding(
                            template,
                            resource,
                            "The GCP firewall rule allows all traffic from the internet.",
                            f"source_ranges={safe_json(resource.properties.get('source_ranges'))}, allow={safe_json(allow)}.",
                            "Restrict firewall source ranges, protocols, and ports to least privilege.",
                            suffix=str(index),
                        )
                    )
        return findings


class GCPKMSRotationRule(StaticRule):
    """Detect GCP KMS keys without automatic rotation."""

    rule_id = "GCP_KMS_ROTATION_MISSING"
    title = "GCP KMS key rotation is not configured"
    severity = "MEDIUM"
    provider = "gcp"
    tags = ["gcp", "kms", "encryption"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in _resources_by_type(template, "google_kms_crypto_key"):
            if not resource.properties.get("rotation_period"):
                findings.append(
                    self.finding(
                        template,
                        resource,
                        "The GCP KMS key does not configure automatic rotation.",
                        "rotation_period is missing or empty.",
                        "Set rotation_period to an organization-approved interval such as 7776000s.",
                    )
                )
        return findings


class KubernetesPrivilegedContainerRule(StaticRule):
    """Detect privileged Kubernetes containers."""

    rule_id = "K8S_PRIVILEGED_CONTAINER"
    title = "Kubernetes workload uses privileged containers"
    severity = "HIGH"
    provider = "kubernetes"
    tags = ["kubernetes", "container", "privilege"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in template.resources:
            if not resource.resource_type.startswith("kubernetes_"):
                continue
            for path, value in walk_properties(resource.properties):
                if path.lower().endswith("privileged") and truthy(value):
                    findings.append(
                        self.finding(
                            template,
                            resource,
                            "The Kubernetes workload enables privileged container mode.",
                            f"{path} is true.",
                            "Set privileged to false and grant only the Linux capabilities the workload requires.",
                            suffix=path,
                        )
                    )
                    break
        return findings


class KubernetesPrivilegeEscalationRule(StaticRule):
    """Detect Kubernetes containers that allow privilege escalation."""

    rule_id = "K8S_ALLOW_PRIVILEGE_ESCALATION"
    title = "Kubernetes workload allows privilege escalation"
    severity = "HIGH"
    provider = "kubernetes"
    tags = ["kubernetes", "container", "privilege"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in _kubernetes_resources(template):
            for path, value in walk_properties(resource.properties):
                if path.lower().endswith("allow_privilege_escalation") and truthy(value):
                    findings.append(
                        self.finding(
                            template,
                            resource,
                            "The Kubernetes workload allows container privilege escalation.",
                            f"{path} is true.",
                            "Set allow_privilege_escalation to false in each container security context.",
                            suffix=path,
                        )
                    )
                    break
        return findings


class KubernetesRunAsRootRule(StaticRule):
    """Detect Kubernetes containers configured to run as root."""

    rule_id = "K8S_RUN_AS_ROOT"
    title = "Kubernetes workload can run as root"
    severity = "HIGH"
    provider = "kubernetes"
    tags = ["kubernetes", "container", "identity"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in _kubernetes_resources(template):
            for path, value in walk_properties(resource.properties):
                normalized_path = path.lower()
                if normalized_path.endswith("run_as_user") and str(value) == "0":
                    findings.append(
                        self.finding(
                            template,
                            resource,
                            "The Kubernetes workload explicitly runs as UID 0.",
                            f"{path} is 0.",
                            "Set run_as_non_root to true and use a non-zero run_as_user value.",
                            suffix=path,
                        )
                    )
                    break
                if normalized_path.endswith("run_as_non_root") and falsey(value):
                    findings.append(
                        self.finding(
                            template,
                            resource,
                            "The Kubernetes workload does not require non-root execution.",
                            f"{path} is false.",
                            "Set run_as_non_root to true and use a non-zero run_as_user value.",
                            suffix=path,
                        )
                    )
                    break
        return findings


class KubernetesDangerousCapabilitiesRule(StaticRule):
    """Detect dangerous Linux capabilities added to Kubernetes containers."""

    rule_id = "K8S_DANGEROUS_CAPABILITIES"
    title = "Kubernetes workload adds dangerous Linux capabilities"
    severity = "HIGH"
    provider = "kubernetes"
    tags = ["kubernetes", "container", "capabilities"]
    dangerous_capabilities = {"ALL", "SYS_ADMIN", "NET_ADMIN"}

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in _kubernetes_resources(template):
            for path, value in walk_properties(resource.properties):
                if ".add" not in path.lower():
                    continue
                capability = str(value).upper()
                if capability in self.dangerous_capabilities:
                    findings.append(
                        self.finding(
                            template,
                            resource,
                            "The Kubernetes workload adds a high-risk Linux capability.",
                            f"{path} includes {capability}.",
                            "Remove dangerous capabilities and add only the minimum capability set required.",
                            suffix=path,
                        )
                    )
                    break
        return findings


class KubernetesHostNetworkRule(StaticRule):
    """Detect Kubernetes workloads using the host network namespace."""

    rule_id = "K8S_HOST_NETWORK_ENABLED"
    title = "Kubernetes workload uses host networking"
    severity = "MEDIUM"
    provider = "kubernetes"
    tags = ["kubernetes", "network"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in template.resources:
            if not resource.resource_type.startswith("kubernetes_"):
                continue
            for path, value in walk_properties(resource.properties):
                if path.lower().endswith("host_network") and truthy(value):
                    findings.append(
                        self.finding(
                            template,
                            resource,
                            "The Kubernetes workload uses the node host network namespace.",
                            f"{path} is true.",
                            "Disable host networking unless the workload explicitly requires node-level networking.",
                            suffix=path,
                        )
                    )
                    break
        return findings


def _resources_by_type(template: IaCTemplate, resource_type: str) -> list[IaCResource]:
    return [resource for resource in template.resources if resource.resource_type == resource_type]


def _kubernetes_resources(template: IaCTemplate) -> list[IaCResource]:
    return [resource for resource in template.resources if resource.resource_type.startswith("kubernetes_")]


def _members(properties: dict[str, Any]) -> set[str]:
    values = set()
    for item in as_list(properties.get("member")) + as_list(properties.get("members")):
        if isinstance(item, str):
            values.add(item)
        else:
            values.add(safe_json(item))
    return values


def _scan_azure_nsg_port_rule(rule: StaticRule, template: IaCTemplate, port: str, service: str):
    findings = []
    for resource in template.resources:
        for suffix, security_rule in _azure_security_rules(resource):
            if _azure_rule_is_inbound_allow(security_rule) and _has_internet_source(security_rule) and _port_matches(_ports(security_rule), port):
                findings.append(
                    rule.finding(
                        template,
                        resource,
                        f"The Azure NSG rule allows {service} from the internet.",
                        f"source={_source_evidence(security_rule)}, ports={_port_evidence(security_rule)}.",
                        f"Restrict {service} access to trusted source CIDR ranges or use a private access path.",
                        suffix=suffix,
                    )
                )
    return findings


def _azure_security_rules(resource: IaCResource) -> list[tuple[str, dict[str, Any]]]:
    if resource.resource_type == "azurerm_network_security_rule":
        return [(resource.logical_id, resource.properties)]
    if resource.resource_type != "azurerm_network_security_group":
        return []
    rules = []
    for index, rule in enumerate(as_list(resource.properties.get("security_rule"))):
        if isinstance(rule, dict):
            rules.append((str(index), rule))
    return rules


def _azure_rule_is_inbound_allow(rule: dict[str, Any]) -> bool:
    return str(rule.get("access", "")).lower() == "allow" and str(rule.get("direction", "")).lower() == "inbound"


def _scan_gcp_firewall_port_rule(rule: StaticRule, template: IaCTemplate, port: str, service: str):
    findings = []
    for resource in _resources_by_type(template, "google_compute_firewall"):
        if not _gcp_firewall_is_ingress(resource.properties) or not _has_internet_source(resource.properties):
            continue
        for index, allow in enumerate(as_list(resource.properties.get("allow"))):
            if isinstance(allow, dict) and _gcp_allow_port(allow, port):
                findings.append(
                    rule.finding(
                        template,
                        resource,
                        f"The GCP firewall rule allows {service} from the internet.",
                        f"source_ranges={safe_json(resource.properties.get('source_ranges'))}, allow={safe_json(allow)}.",
                        f"Restrict {service} access to trusted source ranges or use a private access path.",
                        suffix=str(index),
                    )
                )
    return findings


def _gcp_firewall_is_ingress(properties: dict[str, Any]) -> bool:
    return str(properties.get("direction", "INGRESS")).upper() == "INGRESS"


def _gcp_allow_port(allow: dict[str, Any], port: str) -> bool:
    protocol = str(allow.get("protocol", "")).lower()
    return protocol in {"tcp", "all", "-1", "*"} and _port_matches(as_list(allow.get("ports")), port)


def _gcp_allow_all_traffic(allow: dict[str, Any]) -> bool:
    protocol = str(allow.get("protocol", "")).lower()
    return protocol in {"all", "-1", "*"} or _allows_all_ports(allow)


def _has_internet_source(properties: dict[str, Any]) -> bool:
    sources = (
        as_list(properties.get("source_address_prefix"))
        + as_list(properties.get("source_address_prefixes"))
        + as_list(properties.get("source_ranges"))
    )
    return any(str(source) in {"*", "Internet", "0.0.0.0/0", "::/0"} for source in sources)


def _ports(properties: dict[str, Any]) -> list[Any]:
    return as_list(properties.get("destination_port_range")) + as_list(properties.get("destination_port_ranges"))


def _port_matches(ports: list[Any], target: str) -> bool:
    return any(_single_port_matches(str(port), int(target)) for port in ports)


def _single_port_matches(port: str, target: int) -> bool:
    if port in {"*", "all", "0-65535"}:
        return True
    if "-" in port:
        start, end = port.split("-", 1)
        if start.isdigit() and end.isdigit():
            return int(start) <= target <= int(end)
    return port == str(target)


def _allows_all_ports(properties: dict[str, Any]) -> bool:
    ports = _ports(properties) or as_list(properties.get("ports"))
    protocol = str(properties.get("protocol", "")).lower()
    return protocol in {"*", "all", "-1"} or any(str(port) in {"*", "all", "0-65535"} for port in ports)


def _source_evidence(properties: dict[str, Any]) -> str:
    return safe_json(
        properties.get("source_address_prefix")
        or properties.get("source_address_prefixes")
        or properties.get("source_ranges")
    )


def _port_evidence(properties: dict[str, Any]) -> str:
    return safe_json(
        properties.get("destination_port_range")
        or properties.get("destination_port_ranges")
        or properties.get("ports")
    )
