"""Generic secret detection rules."""

from __future__ import annotations

import re

from iac.models import IaCTemplate
from static_analysis.base_rule import StaticRule, is_reference_like, mask_secret, walk_properties

SUSPICIOUS_KEY = re.compile(r"(password|secret|token|access[_-]?key|private[_-]?key|client[_-]?secret)", re.I)


class HardcodedSecretRule(StaticRule):
    """Detect hardcoded secret-looking property values."""

    rule_id = "GENERIC_HARDCODED_SECRET"
    title = "Hardcoded secret-looking value"
    severity = "HIGH"
    confidence = "MEDIUM"
    provider = "unknown"
    tags = ["secret", "credential"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in template.resources:
            for path, value in walk_properties(resource.properties):
                key = path.split(".")[-1].split("[")[0]
                if not SUSPICIOUS_KEY.search(key):
                    continue
                if is_reference_like(value):
                    continue
                findings.append(
                    self.finding(
                        template,
                        resource,
                        "A secret-like property appears to contain a literal value.",
                        f"{path} contains masked value {mask_secret(value)}.",
                        "Move secrets to AWS Secrets Manager, SSM Parameter Store, or a secure variable source.",
                        suffix=path,
                    )
                )
                break
        return findings
