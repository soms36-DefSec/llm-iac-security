from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Union, List
import yaml
from pypdf import PdfReader
from utils.exceptions import ParsingError

def read_text(path: Union[str, Path]) -> str: return Path(path).read_text(encoding="utf-8")

def read_pdf(path: Union[str, Path]) -> str:
    try:
        reader = PdfReader(path)
        text = ""
        for page in reader.pages:
            content = page.extract_text()
            if content:
                text += content + "\n"
        return text
    except Exception as e:
        raise ParsingError(f"Failed to read PDF {path}: {str(e)}") from e

def chunk_text(text: str, chunk_size: int = 1000, overlap: int = 200) -> List[str]:
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start += chunk_size - overlap
    return chunks

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
