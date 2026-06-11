"""Base classes and helpers for static analysis rules."""

from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from typing import Any, Iterable

from iac.models import IaCResource, IaCTemplate
from static_analysis.models import StaticFinding


class StaticRule(ABC):
    """Base class for deterministic static analysis rules."""

    rule_id: str
    title: str
    severity: str
    confidence: str = "HIGH"
    provider: str = "aws"
    tags: list[str] = []
    references: list[str] = []

    @abstractmethod
    def scan(self, template: IaCTemplate) -> list[StaticFinding]:
        """Return findings for one normalized template."""

    def finding(
        self,
        template: IaCTemplate,
        resource: IaCResource,
        description: str,
        evidence: str,
        remediation: str,
        suffix: str = "",
    ) -> StaticFinding:
        """Build a stable finding object for a resource."""
        finding_id = stable_finding_id(self.rule_id, resource.logical_id, suffix)
        return StaticFinding(
            finding_id=finding_id,
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,  # type: ignore[arg-type]
            confidence=self.confidence,  # type: ignore[arg-type]
            iac_type=template.iac_type,
            provider=resource.provider or self.provider,
            resource_id=resource.logical_id,
            resource_type=resource.resource_type,
            source_file=resource.source_file or template.source_path,
            description=description,
            evidence=evidence,
            remediation=remediation,
            references=list(self.references),
            tags=list(self.tags),
            line_number=resource.line_number,
        )


def stable_finding_id(rule_id: str, resource_id: str, suffix: str = "") -> str:
    """Create a deterministic compact finding ID."""
    seed = f"{rule_id}:{resource_id}:{suffix}"
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:10]
    return f"{rule_id}:{resource_id}:{digest}"


def ensure_template(template: IaCTemplate | dict[str, Any]) -> IaCTemplate:
    """Accept either the normalized dataclass or the legacy parser dict."""
    if isinstance(template, IaCTemplate):
        return template
    return IaCTemplate.from_dict(template)


def truthy(value: Any) -> bool:
    """Return True only for explicit true-ish IaC values."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def falsey(value: Any) -> bool:
    """Return True only for explicit false-ish IaC values."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, str):
        return value.strip().lower() == "false"
    return False


def as_list(value: Any) -> list[Any]:
    """Normalize Terraform and CloudFormation scalar/list shapes."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def get_any(mapping: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Get the first matching key from a dictionary."""
    for key in keys:
        if key in mapping:
            return mapping[key]
    return default


def safe_json(value: Any) -> str:
    """Render evidence without failing on non-JSON values."""
    try:
        return json.dumps(value, sort_keys=True)
    except TypeError:
        return str(value)


def parse_policy_document(value: Any) -> dict[str, Any] | None:
    """Parse a policy document from dict or JSON string form."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text = _strip_heredoc(value.strip())
        if not text or text.startswith("${"):
            return _parse_policy_document_text(text)
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return _parse_policy_document_text(text)
    return None


def _strip_heredoc(text: str) -> str:
    if not text.startswith("<<"):
        return text
    lines = text.splitlines()
    if len(lines) < 3:
        return text
    marker = lines[0].removeprefix("<<").strip()
    body = lines[1:]
    if body and body[-1].strip() == marker:
        body = body[:-1]
    return "\n".join(body).strip()


def _parse_policy_document_text(text: str) -> dict[str, Any] | None:
    """Best-effort parser for Terraform jsonencode/HCL policy text."""
    actions = _extract_policy_values(text, "Action") or _extract_policy_values(text, "actions")
    resources = _extract_policy_values(text, "Resource") or _extract_policy_values(text, "resources")
    if not actions and not resources:
        return None
    effect = "Deny" if re.search(r'["\']?Effect["\']?\s*[:=]\s*["\']Deny["\']', text, re.I) else "Allow"
    return {"Statement": [{"Effect": effect, "Action": actions, "Resource": resources}]}


def _extract_policy_values(text: str, key: str) -> list[str]:
    pattern = rf'["\']?{re.escape(key)}["\']?\s*[:=]\s*(\[[^\]]+\]|"[^"]+"|\'[^\']+\'|[A-Za-z0-9_.*:-]+)'
    match = re.search(pattern, text, re.I | re.DOTALL)
    if not match:
        return []
    raw_value = match.group(1).strip()
    if raw_value.startswith("["):
        return [
            item.strip().strip("\"'")
            for item in re.split(r"[, \n]+", raw_value.strip("[]"))
            if item.strip().strip("\"'")
        ]
    return [raw_value.strip("\"'")]


def iter_policy_statements(resource: IaCResource) -> Iterable[dict[str, Any]]:
    """Yield IAM policy statements from common CloudFormation and Terraform shapes."""
    props = resource.properties or {}
    documents: list[Any] = [
        props.get("PolicyDocument"),
        props.get("AssumeRolePolicyDocument"),
        props.get("policy"),
        props.get("assume_role_policy"),
    ]

    for policy in as_list(props.get("Policies")) + as_list(props.get("policies")):
        if isinstance(policy, dict):
            documents.append(policy.get("PolicyDocument") or policy.get("policy_document"))

    for inline_policy in as_list(props.get("inline_policy")):
        if isinstance(inline_policy, dict):
            documents.append(inline_policy.get("policy"))

    if resource.resource_type == "aws_iam_policy_document":
        documents.append(props)

    for document in documents:
        parsed = parse_policy_document(document)
        if not parsed:
            continue
        for statement in as_list(parsed.get("Statement") or parsed.get("statement")):
            if isinstance(statement, dict):
                yield statement


def action_values(statement: dict[str, Any]) -> list[str]:
    """Return statement actions as strings."""
    return [
        str(value)
        for value in as_list(get_any(statement, "Action", "action", "actions", default=[]))
    ]


def resource_values(statement: dict[str, Any]) -> list[str]:
    """Return statement resources as strings."""
    return [
        str(value)
        for value in as_list(get_any(statement, "Resource", "resource", "resources", default=[]))
    ]


def is_allow_statement(statement: dict[str, Any]) -> bool:
    """Return whether a statement is an Allow or lacks an explicit Deny."""
    effect = str(get_any(statement, "Effect", "effect", default="Allow")).lower()
    return effect != "deny"


def is_broad_action(action: str) -> bool:
    """Detect wildcard IAM actions."""
    return action == "*" or bool(re.match(r"^[A-Za-z0-9-]+:\*$", action))


def mask_secret(value: Any) -> str:
    """Mask a secret-like value for safe evidence output."""
    text = str(value)
    if not text:
        return "****"
    if len(text) <= 4:
        return "****"
    if len(text) <= 8:
        return f"{text[0]}***{text[-1]}"
    return f"{text[:2]}***{text[-2:]}"


def is_reference_like(value: Any) -> bool:
    """Return True when a value points to a variable or managed secret source."""
    if isinstance(value, dict):
        ref_keys = {"Ref", "Fn::Sub", "Fn::Join", "Fn::ImportValue", "Fn::GetAtt", "Fn::FindInMap"}
        return any(key in value for key in ref_keys)
    if not isinstance(value, str):
        return True
    text = value.strip().lower()
    if not text:
        return True
    reference_markers = (
        "${var.",
        "var.",
        "module.",
        "data.aws_secretsmanager_secret",
        "data.aws_ssm_parameter",
        "{{resolve:secretsmanager",
        "{{resolve:ssm",
        "aws_secretsmanager_secret",
        "aws_ssm_parameter",
    )
    return any(marker in text for marker in reference_markers)


def walk_properties(value: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    """Yield leaf property paths and values from nested IaC properties."""
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from walk_properties(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_properties(child, f"{path}[{index}]")
    else:
        yield path, value
