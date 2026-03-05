from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Union
import yaml
from utils.exceptions import ParsingError

def read_text(path: Union[str, Path]) -> str: return Path(path).read_text(encoding="utf-8")
def write_text(path: Union[str, Path], content: str) -> None:
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
def read_yaml(path):
    try: return yaml.safe_load(read_text(path)) or {}
    except yaml.YAMLError as e: raise ParsingError(str(e)) from e
def read_json(path):
    try: return json.loads(read_text(path))
    except json.JSONDecodeError as e: raise ParsingError(str(e)) from e
def write_json(path, data: Any, indent: int = 2) -> None:
    write_text(path, json.dumps(data, indent=indent, default=str))
def ensure_dir(path) -> Path:
    p = Path(path); p.mkdir(parents=True, exist_ok=True); return p
