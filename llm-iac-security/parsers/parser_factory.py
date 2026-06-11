"""Parser selection for supported IaC inputs."""

from __future__ import annotations

from pathlib import Path
from typing import Type

from config.logging_config import get_logger
from parsers.base_parser import BaseParser
from parsers.cloudformation_parser import CloudFormationParser
from parsers.terraform_parser import TerraformParser
from utils.exceptions import UnsupportedTemplateFormatError

logger = get_logger(__name__)


class ParserFactory:
    """Chooses a parser from a file or directory path."""

    @staticmethod
    def get_parser(path: str | Path) -> BaseParser:
        """Return the parser appropriate for the supplied path."""
        p = Path(path)
        parser_class = ParserFactory.get_parser_class(p)
        logger.info("parser_selected", parser=parser_class.__name__, path=str(p))
        return parser_class()

    @staticmethod
    def get_parser_class(path: str | Path) -> Type[BaseParser]:
        """Return a parser class without instantiating it."""
        p = Path(path)
        if p.is_dir():
            if any(p.rglob("*.tf")):
                return TerraformParser
            raise UnsupportedTemplateFormatError(f"No supported IaC files found in directory: {p}")

        suffix = p.suffix.lower()
        if suffix in CloudFormationParser.SUPPORTED_SUFFIXES:
            return CloudFormationParser
        if suffix == ".tf":
            return TerraformParser
        raise UnsupportedTemplateFormatError(f"Unsupported IaC extension: {suffix}")
