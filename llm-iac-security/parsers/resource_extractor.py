from __future__ import annotations
from typing import Any
from static_analysis.rules.generic_secret_rules import SUSPICIOUS_KEY
from static_analysis.base_rule import mask_secret

RESOURCE_TYPE_MAP = {
    "s3": "AWS::S3::", "iam": "AWS::IAM::",
    "security_group": "AWS::EC2::SecurityGroup", "rds": "AWS::RDS::",
    "secrets_manager": "AWS::SecretsManager::", "lambda": "AWS::Lambda::", "ec2": "AWS::EC2::",
}

class ResourceExtractor:
    """Extracts and categorizes resources from a normalized CloudFormation template."""
    def __init__(self, normalized_template: dict[str, Any]) -> None:
        self._resources = normalized_template.get("resources", {})

    def extract_by_category(self, category: str) -> dict[str, Any]:
        prefix = RESOURCE_TYPE_MAP.get(category.lower(), "")
        return {lid: r for lid, r in self._resources.items() if r.get("type", "").startswith(prefix)}

    def extract_all_types(self) -> set[str]:
        return {r.get("type", "") for r in self._resources.values()}

    def to_summary_text(self) -> str:
        lines = []
        for lid, res in self._resources.items():
            lines.append(f"Resource: {lid} (Type: {res.get('type') or res.get('resource_type', 'Unknown')})")
            for k, v in res.get("properties", {}).items():
                lines.append(f"  {k}: {_safe_summary_value(k, v)}")
        return "\n".join(lines)


def _safe_summary_value(key: str, value: Any) -> Any:
    if SUSPICIOUS_KEY.search(key):
        return mask_secret(value)
    if isinstance(value, dict):
        return {child_key: _safe_summary_value(str(child_key), child_value) for child_key, child_value in value.items()}
    if isinstance(value, list):
        return [_safe_summary_value(key, item) for item in value]
    return value
