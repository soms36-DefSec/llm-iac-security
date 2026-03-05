from __future__ import annotations
import json, re
from typing import Any
from utils.exceptions import LLMResponseParseError

def extract_json_block(text: str) -> str:
    m = re.search(r"```(?:json)?\s*(\{.*?})\s*```", text, re.DOTALL)
    if m: return m.group(1)
    m = re.search(r"\{.*}", text, re.DOTALL)
    return m.group(0) if m else text.strip()

def parse_vulnerability_response(raw_text: str) -> dict[str, Any]:
    try: data = json.loads(extract_json_block(raw_text))
    except json.JSONDecodeError as e:
        raise LLMResponseParseError(f"Cannot parse LLM response: {e}") from e
    if "vulnerabilities" not in data:
        raise LLMResponseParseError("'vulnerabilities' key missing from response.")
    return data
