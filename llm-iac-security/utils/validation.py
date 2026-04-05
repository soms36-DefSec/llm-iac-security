from pathlib import Path
from utils.exceptions import ValidationError

SUPPORTED_EXTENSIONS = {".yaml", ".yml", ".json", ".tf"}

def validate_template_path(path):
    p = Path(path)
    if not p.exists(): raise ValidationError(f"Template not found: {p}")
    if p.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValidationError(f"Unsupported extension '{p.suffix}'")
    return p

def validate_non_empty(value: str, field_name: str) -> str:
    if not value or not value.strip(): raise ValidationError(f"'{field_name}' must not be empty.")
    return value.strip()
