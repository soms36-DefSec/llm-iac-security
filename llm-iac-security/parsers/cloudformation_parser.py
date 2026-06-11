from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Union
import yaml
from config.logging_config import get_logger
from iac.models import IaCResource, IaCTemplate
from parsers.base_parser import BaseParser
from utils.exceptions import ParsingError, UnsupportedTemplateFormatError

logger = get_logger(__name__)

class CloudFormationParser(BaseParser):
    """Parses and normalizes AWS CloudFormation templates (YAML/JSON)."""
    SUPPORTED_SUFFIXES = {".yaml", ".yml", ".json"}

    def parse(self, path: Union[str, Path]) -> dict[str, Any]:
        p = Path(path)
        if p.suffix.lower() not in self.SUPPORTED_SUFFIXES:
            raise UnsupportedTemplateFormatError(f"Unsupported extension: {p.suffix}")
        try:
            text = p.read_text(encoding="utf-8")
            logger.info("cloudformation_parse_started", path=str(p))
            return json.loads(text) if p.suffix.lower() == ".json" else yaml.load(text, Loader=_CloudFormationLoader) or {}
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise ParsingError(f"Failed to parse {p}: {e}") from e

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "template_format_version": raw.get("AWSTemplateFormatVersion", ""),
            "description": raw.get("Description", ""),
            "parameters": raw.get("Parameters", {}),
            "resources": self._normalize_resources(raw.get("Resources", {})),
            "outputs": raw.get("Outputs", {}),
        }

    def parse_and_normalize(self, path: Union[str, Path]) -> dict[str, Any]:
        """Parse and normalize while adding common IaC metadata."""
        p = Path(path)
        raw_content = p.read_text(encoding="utf-8")
        raw = self.parse(p)
        legacy = self.normalize(raw)
        template = IaCTemplate(
            iac_type="cloudformation",
            source_path=str(p),
            raw_content=raw_content,
            resources=[
                IaCResource(
                    logical_id=logical_id,
                    resource_type=resource.get("type", "Unknown"),
                    provider="aws" if resource.get("type", "").startswith("AWS::") else "unknown",
                    name=logical_id,
                    properties=resource.get("properties", {}),
                    source_file=str(p),
                    depends_on=_as_list(resource.get("depends_on", [])),
                    metadata={
                        "condition": resource.get("condition"),
                        **(resource.get("metadata") or {}),
                    },
                )
                for logical_id, resource in legacy.get("resources", {}).items()
            ],
            parameters=legacy.get("parameters", {}),
            outputs=legacy.get("outputs", {}),
            metadata={
                "template_format_version": legacy.get("template_format_version", ""),
                "description": legacy.get("description", ""),
            },
        )
        normalized = template.to_dict()
        normalized.update(
            {
                "template_format_version": legacy.get("template_format_version", ""),
                "description": legacy.get("description", ""),
            }
        )
        logger.info("cloudformation_parse_completed", path=str(p), resources=len(normalized["resources"]))
        return normalized

    @staticmethod
    def _normalize_resources(resources: dict) -> dict[str, Any]:
        return {
            lid: {
                "type": d.get("Type", "Unknown"),
                "properties": d.get("Properties", {}),
                "depends_on": d.get("DependsOn", []),
                "metadata": d.get("Metadata", {}),
                "condition": d.get("Condition"),
            }
            for lid, d in (resources or {}).items()
        }


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


class _CloudFormationLoader(yaml.SafeLoader):
    """YAML loader that preserves CloudFormation intrinsic tags."""


def _unknown_tag(loader: _CloudFormationLoader, tag_suffix: str, node: yaml.Node) -> Any:
    tag = tag_suffix.lstrip("!")
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    if tag == "Ref":
        return {"Ref": value}
    return {f"Fn::{tag}": value}


_CloudFormationLoader.add_multi_constructor("!", _unknown_tag)
