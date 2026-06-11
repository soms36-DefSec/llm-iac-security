"""AWS IAM static analysis rules."""

from __future__ import annotations

from iac.models import IaCResource, IaCTemplate
from static_analysis.base_rule import (
    StaticRule,
    action_values,
    as_list,
    is_allow_statement,
    is_broad_action,
    iter_policy_statements,
    resource_values,
)

IAM_TYPES = {
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::Role",
    "AWS::IAM::User",
    "AWS::IAM::Group",
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
    "aws_iam_role",
    "aws_iam_policy_document",
}


class IAMWildcardActionRule(StaticRule):
    """Detect wildcard IAM actions."""

    rule_id = "AWS_IAM_WILDCARD_ACTION"
    title = "IAM policy uses wildcard actions"
    severity = "HIGH"
    tags = ["aws", "iam", "least-privilege"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in _iam_resources(template.resources):
            broad_actions = sorted(
                {
                    action
                    for statement in iter_policy_statements(resource)
                    if is_allow_statement(statement)
                    for action in action_values(statement)
                    if is_broad_action(action)
                }
            )
            if broad_actions:
                findings.append(
                    self.finding(
                        template,
                        resource,
                        "An IAM policy grants wildcard or service-wide actions.",
                        f"Broad actions detected: {', '.join(broad_actions)}.",
                        "Replace wildcard actions with the minimum API actions required.",
                    )
                )
        return findings


class IAMWildcardResourceRule(StaticRule):
    """Detect wildcard IAM resources."""

    rule_id = "AWS_IAM_WILDCARD_RESOURCE"
    title = "IAM policy uses wildcard resources"
    severity = "HIGH"
    tags = ["aws", "iam", "least-privilege"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in _iam_resources(template.resources):
            wildcard = any(
                resource_value == "*"
                for statement in iter_policy_statements(resource)
                if is_allow_statement(statement)
                for resource_value in resource_values(statement)
            )
            if wildcard:
                findings.append(
                    self.finding(
                        template,
                        resource,
                        "An IAM policy grants access to all resources.",
                        'Resource "*" detected in an Allow statement.',
                        "Scope Resource to specific ARNs wherever the AWS action supports resource-level permissions.",
                    )
                )
        return findings


class AdminPolicyRiskRule(StaticRule):
    """Detect AdministratorAccess-like policies."""

    rule_id = "AWS_IAM_ADMIN_POLICY"
    title = "AdministratorAccess-like IAM policy"
    severity = "CRITICAL"
    tags = ["aws", "iam", "privilege-escalation"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in _iam_resources(template.resources):
            if _has_admin_managed_policy(resource) or _has_admin_statement(resource):
                findings.append(
                    self.finding(
                        template,
                        resource,
                        "The IAM configuration resembles AdministratorAccess.",
                        "Detected AdministratorAccess managed policy or Allow with Action '*' and Resource '*'.",
                        "Use narrowly scoped managed policies or custom least-privilege policies.",
                    )
                )
        return findings


def _iam_resources(resources: list[IaCResource]) -> list[IaCResource]:
    return [resource for resource in resources if resource.resource_type in IAM_TYPES]


def _has_admin_managed_policy(resource: IaCResource) -> bool:
    props = resource.properties or {}
    values = []
    for key in ("ManagedPolicyArns", "managed_policy_arns", "policy_arn", "policy_arns"):
        values.extend(str(item) for item in as_list(props.get(key)))
    return any("AdministratorAccess" in value for value in values)


def _has_admin_statement(resource: IaCResource) -> bool:
    for statement in iter_policy_statements(resource):
        if not is_allow_statement(statement):
            continue
        if "*" in action_values(statement) and "*" in resource_values(statement):
            return True
    return False
