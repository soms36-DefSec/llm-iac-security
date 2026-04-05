from __future__ import annotations
import json, re
from typing import Any
from utils.exceptions import LLMResponseParseError
from config.logging_config import get_logger

logger = get_logger(__name__)

REQUIRED_FIELDS = [
    "resource_name",
    "resource_type",
    "vulnerability_type",
    "severity",
    "description",
    "remediation",
    "best_practice_reference"
]

def extract_json_block(text: str) -> str:
    # 1. Look for markdown code fence
    m = re.search(r"```(?:json)?\s*([\[\{].*?[\]\}])\s*```", text, re.DOTALL)
    if m: return m.group(1)
    
    # 2. Look for anything that looks like a JSON object or array
    m = re.search(r"([\[\{].*[\]\}])", text, re.DOTALL)
    return m.group(0) if m else text.strip()

def validate_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Ensures finding has all required fields and normalises severity."""
    # GAP 8: Standardise to resource_name
    if "resource_id" in finding and "resource_name" not in finding:
        finding["resource_name"] = finding.pop("resource_id")
    if "resource" in finding and "resource_name" not in finding:
        finding["resource_name"] = finding.pop("resource")
        
    for field in REQUIRED_FIELDS:
        if field not in finding:
            finding[field] = "N/A"
            
    # Normalise severity
    sev = str(finding.get("severity", "MEDIUM")).upper()
    if sev not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        sev = "MEDIUM"
    finding["severity"] = sev
    
    # Keep only required fields (or at least ensure they are present)
    return finding

def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate findings on (resource_name, vulnerability_type) key.

    When the LLM returns the same finding twice, keep only the first occurrence.
    """
    seen: dict[tuple, dict] = {}
    for finding in findings:
        key = (
            finding.get("resource_name", ""),
            finding.get("vulnerability_type", ""),
        )
        if key not in seen:
            seen[key] = finding
    return list(seen.values())


def parse_vulnerability_response(raw_text: str) -> dict[str, Any]:
    try:
        json_str = extract_json_block(raw_text)
        data = json.loads(json_str)

        vulnerabilities = []
        summary = ""

        if isinstance(data, list):
            # Case 1: Bare array
            vulnerabilities = data
        elif isinstance(data, dict):
            # Case 2: Wrapped object
            vulnerabilities = data.get("vulnerabilities", [])
            summary = data.get("summary", "")
        else:
            logger.warning(f"Unexpected JSON type from LLM: {type(data)}")
            return {"vulnerabilities": [], "summary": ""}

        # Validate, normalize, then deduplicate (MISS-12)
        validated = [validate_finding(v) for v in vulnerabilities if isinstance(v, dict)]
        deduped = _deduplicate_findings(validated)
        return {"vulnerabilities": deduped, "summary": summary}

    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"Failed to parse LLM response as JSON. Returning empty list. Error: {e}")
        return {"vulnerabilities": [], "summary": ""}
