"""Normalized IaC data model shared by parsers, rules, and agents."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

IaCType = Literal["cloudformation", "terraform"]
Provider = Literal["aws", "azure", "gcp", "kubernetes", "unknown"]


@dataclass(slots=True)
class IaCResource:
    """A provider resource normalized from CloudFormation or Terraform."""

    logical_id: str
    resource_type: str
    provider: Provider = "unknown"
    name: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    source_file: str = ""
    line_number: int | None = None
    depends_on: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def address(self) -> str:
        """Return the canonical resource identifier."""
        return self.logical_id

    def to_dict(self) -> dict[str, Any]:
        """Serialize the resource to a plain dict."""
        data = asdict(self)
        data["address"] = self.address
        data["type"] = self.resource_type
        return data

    @classmethod
    def from_dict(cls, resource_id: str, data: dict[str, Any]) -> "IaCResource":
        """Build a normalized resource from a legacy parser dictionary."""
        return cls(
            logical_id=data.get("logical_id") or data.get("address") or resource_id,
            resource_type=data.get("resource_type") or data.get("type") or "Unknown",
            provider=data.get("provider") or _provider_from_type(data.get("type", "")),
            name=data.get("name") or resource_id,
            properties=data.get("properties") or {},
            source_file=data.get("source_file") or "",
            line_number=data.get("line_number"),
            depends_on=_as_list(data.get("depends_on") or data.get("dependsOn") or []),
            metadata=data.get("metadata") or {},
        )


@dataclass(slots=True)
class IaCTemplate:
    """A normalized IaC template or Terraform module directory."""

    iac_type: IaCType
    source_path: str
    raw_content: str | None = None
    resources: list[IaCResource] = field(default_factory=list)
    variables: dict[str, Any] = field(default_factory=dict)
    parameters: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the template to a legacy-friendly plain dict."""
        resources = {resource.logical_id: resource.to_dict() for resource in self.resources}
        return {
            "iac_type": self.iac_type,
            "source_path": self.source_path,
            "raw_content": self.raw_content,
            "resources": resources,
            "variables": self.variables,
            "parameters": self.parameters,
            "outputs": self.outputs,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IaCTemplate":
        """Build a normalized template from parser output or legacy test fixtures."""
        resources = data.get("resources") or {}
        if isinstance(resources, dict):
            normalized_resources = [
                IaCResource.from_dict(resource_id, resource_data or {})
                for resource_id, resource_data in resources.items()
            ]
        else:
            normalized_resources = [
                resource if isinstance(resource, IaCResource) else IaCResource.from_dict(
                    resource.get("logical_id") or resource.get("address") or resource.get("name", "unknown"),
                    resource,
                )
                for resource in resources
            ]
        iac_type = data.get("iac_type") or "cloudformation"
        return cls(
            iac_type=iac_type,
            source_path=data.get("source_path") or "",
            raw_content=data.get("raw_content"),
            resources=normalized_resources,
            variables=data.get("variables") or {},
            parameters=data.get("parameters") or {},
            outputs=data.get("outputs") or {},
            metadata=data.get("metadata") or {},
        )


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _provider_from_type(resource_type: str) -> Provider:
    if resource_type.startswith("AWS::") or resource_type.startswith("aws_"):
        return "aws"
    if resource_type.startswith("azurerm_"):
        return "azure"
    if resource_type.startswith("google_"):
        return "gcp"
    if resource_type.startswith("kubernetes_"):
        return "kubernetes"
    return "unknown"
