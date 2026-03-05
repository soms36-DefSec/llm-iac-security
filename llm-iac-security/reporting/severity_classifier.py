from enum import Enum
from typing import Any

class Severity(str, Enum):
    CRITICAL = "CRITICAL"; HIGH = "HIGH"; MEDIUM = "MEDIUM"; LOW = "LOW"; INFO = "INFO"

SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}

def classify(s: str) -> Severity:
    try: return Severity(s.upper())
    except ValueError: return Severity.INFO

def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(classify(f.get("severity", "INFO")), 99))
