from pathlib import Path

from parsers.parser_factory import ParserFactory
from utils.exceptions import ValidationError

SUPPORTED_EXTENSIONS = {".yaml", ".yml", ".json", ".tf"}


def validate_template_path(path):
    """Validate a supported IaC file or Terraform directory path."""
    p = Path(path)
    if not p.exists():
        raise ValidationError(f"Template not found: {p}")
    try:
        ParserFactory.get_parser_class(p)
    except Exception as exc:
        raise ValidationError(str(exc)) from exc
    return p

def validate_non_empty(value: str, field_name: str) -> str:
    if not value or not value.strip(): raise ValidationError(f"'{field_name}' must not be empty.")
    return value.strip()
