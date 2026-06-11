"""AWS network exposure static analysis rules."""

from __future__ import annotations

from typing import Any

from iac.models import IaCResource, IaCTemplate
from static_analysis.base_rule import StaticRule, as_list, get_any, safe_json

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


class SecurityGroupSshOpenRule(StaticRule):
    """Detect unrestricted SSH ingress."""

    rule_id = "AWS_SG_OPEN_SSH"
    title = "Security group allows SSH from the internet"
    severity = "HIGH"
    tags = ["aws", "network", "ssh"]

    def scan(self, template: IaCTemplate):
        return _scan_port_rule(
            self,
            template,
            port=22,
            description="A security group ingress rule allows SSH from an unrestricted CIDR.",
            remediation="Restrict SSH ingress to a trusted bastion, VPN, or administrative CIDR.",
        )


class SecurityGroupRdpOpenRule(StaticRule):
    """Detect unrestricted RDP ingress."""

    rule_id = "AWS_SG_OPEN_RDP"
    title = "Security group allows RDP from the internet"
    severity = "HIGH"
    tags = ["aws", "network", "rdp"]

    def scan(self, template: IaCTemplate):
        return _scan_port_rule(
            self,
            template,
            port=3389,
            description="A security group ingress rule allows RDP from an unrestricted CIDR.",
            remediation="Restrict RDP ingress to a trusted VPN or administrative CIDR.",
        )


class SecurityGroupAllTrafficOpenRule(StaticRule):
    """Detect unrestricted all-traffic ingress."""

    rule_id = "AWS_SG_OPEN_ALL_TRAFFIC"
    title = "Security group allows all traffic from the internet"
    severity = "CRITICAL"
    tags = ["aws", "network", "internet-exposure"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in _security_group_resources(template.resources):
            for index, rule in enumerate(_ingress_rules(resource)):
                if _is_open(rule) and _is_all_traffic(rule):
                    findings.append(
                        self.finding(
                            template,
                            resource,
                            "A security group ingress rule allows all traffic from an unrestricted CIDR.",
                            f"Ingress rule {index}: {safe_json(rule)}.",
                            "Remove unrestricted ingress or scope it to the smallest required protocol, port, and CIDR.",
                            suffix=str(index),
                        )
                    )
                    break
        return findings


def _scan_port_rule(rule_obj: StaticRule, template: IaCTemplate, port: int, description: str, remediation: str):
    findings = []
    for resource in _security_group_resources(template.resources):
        for index, rule in enumerate(_ingress_rules(resource)):
            if _is_open(rule) and _port_in_range(rule, port):
                findings.append(
                    rule_obj.finding(
                        template,
                        resource,
                        description,
                        f"Ingress rule {index}: {safe_json(rule)}.",
                        remediation,
                        suffix=str(index),
                    )
                )
                break
    return findings


def _security_group_resources(resources: list[IaCResource]) -> list[IaCResource]:
    supported = {
        "AWS::EC2::SecurityGroup",
        "AWS::EC2::SecurityGroupIngress",
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
    }
    return [resource for resource in resources if resource.resource_type in supported]


def _ingress_rules(resource: IaCResource) -> list[dict[str, Any]]:
    props = resource.properties or {}
    if resource.resource_type == "AWS::EC2::SecurityGroup":
        return [rule for rule in as_list(props.get("SecurityGroupIngress")) if isinstance(rule, dict)]
    if resource.resource_type == "aws_security_group":
        return [rule for rule in as_list(props.get("ingress")) if isinstance(rule, dict)]
    if resource.resource_type == "aws_security_group_rule" and props.get("type") != "ingress":
        return []
    return [props]


def _is_open(rule: dict[str, Any]) -> bool:
    cidrs: list[str] = []
    for key in ("CidrIp", "CidrIpv6", "cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6"):
        cidrs.extend(str(item) for item in as_list(rule.get(key)))
    return any(cidr in OPEN_CIDRS for cidr in cidrs)


def _port_in_range(rule: dict[str, Any], port: int) -> bool:
    if _is_all_traffic(rule):
        return True
    from_port = _as_int(get_any(rule, "FromPort", "from_port", default=None))
    to_port = _as_int(get_any(rule, "ToPort", "to_port", default=from_port))
    if from_port is None or to_port is None:
        return False
    return from_port <= port <= to_port


def _is_all_traffic(rule: dict[str, Any]) -> bool:
    protocol = str(get_any(rule, "IpProtocol", "ip_protocol", "protocol", default="")).lower()
    if protocol in {"-1", "all"}:
        return True
    from_port = _as_int(get_any(rule, "FromPort", "from_port", default=None))
    to_port = _as_int(get_any(rule, "ToPort", "to_port", default=None))
    return from_port == 0 and to_port == 0 and protocol in {"", "-1"}


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
