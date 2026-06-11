"""Models returned by deterministic static analysis rules."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Confidence = Literal["HIGH", "MEDIUM", "LOW"]


@dataclass(slots=True)
class StaticFinding:
    """A deterministic finding from a static IaC rule."""

    finding_id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    iac_type: str
    provider: str
    resource_id: str
    resource_type: str
    source_file: str
    description: str
    evidence: str
    remediation: str
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    detected_by: str = "static"
    line_number: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize to a JSON-ready dictionary."""
        return asdict(self)
