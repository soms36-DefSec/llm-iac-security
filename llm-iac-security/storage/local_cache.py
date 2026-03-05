from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Optional

BASE_CACHE_DIR = Path(".cache/llm-iac-security")

class LocalCache:
    """File-based cache to avoid redundant LLM/embedding calls."""
    def __init__(self, namespace: str):
        self._dir = BASE_CACHE_DIR / namespace; self._dir.mkdir(parents=True, exist_ok=True)

    def _key_path(self, key: str) -> Path:
        return self._dir / f"{hashlib.sha256(key.encode()).hexdigest()}.json"

    def get(self, key: str) -> Optional[Any]:
        p = self._key_path(key); return json.loads(p.read_text()) if p.exists() else None

    def set(self, key: str, value: Any) -> None: self._key_path(key).write_text(json.dumps(value))
    def clear(self) -> None: [f.unlink() for f in self._dir.glob("*.json")]
