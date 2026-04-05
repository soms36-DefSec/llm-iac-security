from __future__ import annotations
from typing import Any

from config.logging_config import get_logger

logger = get_logger(__name__)

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

    @staticmethod
    def _sanitize_value(value: str) -> str:
        """Sanitize a property value string to resist prompt injection.

        Strips leading/trailing whitespace and removes common injection
        patterns such as instruction-override phrases.
        """
        # Truncate long values first
        if len(value) > 200:
            value = value[:197] + "..."
        # Remove patterns that attempt to override instructions (MISS-10)
        injection_patterns = [
            "ignore previous instructions",
            "ignore all instructions",
            "disregard the above",
            "forget the above",
            "you are now",
            "act as",
        ]
        lower_val = value.lower()
        for pattern in injection_patterns:
            if pattern in lower_val:
                value = "[REDACTED: potential prompt injection detected]"
                break
        return value

    def to_summary_text(self) -> str:
        """Generate a human-readable summary, truncated to avoid context overflow.

        Property values are wrapped in XML-style markers to signal to the LLM
        that this content is data (not instructions), reducing prompt injection
        risk (MISS-10).
        """
        lines = ["<template_content>"]
        truncated_props = False

        for lid, res in self._resources.items():
            lines.append(f"Resource: {lid} (Type: {res.get('type', 'Unknown')})")
            for k, v in res.get("properties", {}).items():
                val_str = self._sanitize_value(str(v))
                if val_str.endswith("..."):
                    truncated_props = True
                lines.append(f"  {k}: {val_str}")

        lines.append("</template_content>")
        summary = "\n".join(lines)

        if len(summary) > 4000:
            logger.warning("Resource summary truncated due to length (>4000 chars)")
            summary = summary[:3994] + "...\n</template_content>"
        elif truncated_props:
            logger.warning("Some resource property values were truncated (>200 chars)")

        return summary
