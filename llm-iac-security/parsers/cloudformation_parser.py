from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Union
import yaml
from parsers.base_parser import BaseParser
from utils.exceptions import ParsingError, UnsupportedTemplateFormatError

class CloudFormationParser(BaseParser):
    """Parses and normalizes AWS CloudFormation templates (YAML/JSON)."""
    SUPPORTED_SUFFIXES = {".yaml", ".yml", ".json"}

    def parse(self, path: Union[str, Path]) -> dict[str, Any]:
        p = Path(path)
        if p.suffix.lower() not in self.SUPPORTED_SUFFIXES:
            raise UnsupportedTemplateFormatError(f"Unsupported extension: {p.suffix}")
        try:
            text = p.read_text(encoding="utf-8")
            return json.loads(text) if p.suffix.lower() == ".json" else yaml.safe_load(text) or {}
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
