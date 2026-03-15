"""CI/CD hook entry point — runs security scan and returns exit code."""
from __future__ import annotations
import os
import sys
from pathlib import Path
from orchestrator.pipeline import IaCSecurityPipeline
from config.logging_config import configure_logging


def run_ci_scan(template_path: str, mode: str = "local") -> int:
    """Run a scan in CI/CD context. Returns 1 if vulnerabilities found, 0 otherwise."""
    os.environ.setdefault("MODE", mode)
    configure_logging()
    try:
        result = IaCSecurityPipeline().run(template_path)
        vuln_count = len(result.get("findings", {}).get("vulnerabilities", []))
        print(f"Scan complete. Findings: {vuln_count}. Report: {result.get('report_path')}")
        return 1 if vuln_count > 0 else 0
    except Exception as e:
        print(f"Scan failed: {e}")
        return 2


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pipeline_integration.py <template> [--mode local|aws]")
        sys.exit(1)
    template = sys.argv[1]
    mode = "local"
    if "--mode" in sys.argv:
        idx = sys.argv.index("--mode")
        if idx + 1 < len(sys.argv):
            mode = sys.argv[idx + 1]
    sys.exit(run_ci_scan(template, mode))
