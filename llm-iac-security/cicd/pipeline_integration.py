"""CI/CD hook entry point."""
from __future__ import annotations
import sys
from pathlib import Path
from orchestrator.pipeline import IaCSecurityPipeline
from config.logging_config import configure_logging

def run_ci_scan(template_path: str) -> int:
    configure_logging()
    result = IaCSecurityPipeline().run(template_path)
    vuln_count = len(result.get("findings", {}).get("vulnerabilities", []))
    print(f"Scan complete. Findings: {vuln_count}. Report: {result.get('report_path')}")
    return 1 if vuln_count > 0 else 0

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: python pipeline_integration.py <template>"); sys.exit(1)
    sys.exit(run_ci_scan(sys.argv[1]))
