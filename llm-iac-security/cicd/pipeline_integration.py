"""CI/CD hook entry point with configurable severity threshold."""
from __future__ import annotations
import sys
from pathlib import Path
from orchestrator.pipeline import IaCSecurityPipeline
from config.logging_config import configure_logging

# Maps severity label -> numeric level (lower = more severe)
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def run_ci_scan(template_path: str, min_severity: str = "LOW") -> int:
    """Run an IaC security scan and return a CI exit code.

    Args:
        template_path: Path to the CloudFormation template.
        min_severity:  Minimum severity level that causes pipeline failure.
                       One of CRITICAL, HIGH, MEDIUM, LOW (default LOW).
                       INFO findings never cause failure.

    Returns:
        0 if no findings at or above min_severity, 1 otherwise.
    """
    configure_logging()
    result = IaCSecurityPipeline().run(template_path)

    vulnerabilities = result.get("findings", {}).get("vulnerabilities", [])
    threshold = _SEVERITY_ORDER.get(min_severity.upper(), 3)  # default LOW

    blocking = [
        v for v in vulnerabilities
        if _SEVERITY_ORDER.get(str(v.get("severity", "LOW")).upper(), 4) <= threshold
        and v.get("vulnerability_type") != "No misconfigurations detected"
    ]

    count = len(blocking)
    print(
        f"Scan complete. Blocking findings (severity>={min_severity}): {count}. "
        f"Report: {result.get('report_path')}"
    )
    return 1 if count > 0 else 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CI/CD IaC security gate")
    parser.add_argument("template", help="Path to CloudFormation template")
    parser.add_argument(
        "--min-severity",
        default="LOW",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity level to fail CI (default: LOW, INFO never fails)",
    )
    args = parser.parse_args()
    sys.exit(run_ci_scan(args.template, args.min_severity))
