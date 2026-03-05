from __future__ import annotations
from typing import Any

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
            lines.append(f"Resource: {lid} (Type: {res.get('type', 'Unknown')})")
            for k, v in res.get("properties", {}).items():
                lines.append(f"  {k}: {v}")
        return "
".join(lines)
