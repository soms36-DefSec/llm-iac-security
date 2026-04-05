#!/usr/bin/env python3
"""
CLI entry point for the LLM IaC Security Scanner.

Usage:
    python scripts/run_scan.py <template_path> [--mode {local,aws}]
                               [--output OUTPUT] [--top-k TOP_K] [--verbose]

Exit codes:
    0  — Scan completed successfully (even if findings exist)
    1  — Pipeline failed — exception occurred
    2  — Invalid arguments — template not found or bad flag value
"""
from __future__ import annotations
import argparse
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Allow running from any directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Ensure UTF-8 output on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf_8"):
    sys.stdout = open(sys.stdout.fileno(), mode="w", encoding="utf-8", buffering=1)


def _print_banner() -> None:
    """Print the scanner banner to stdout."""
    print("╔══════════════════════════════════════════════════════╗")
    print("║      LLM IaC Security Scanner  v1.0.0               ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()


def _auto_output_path(template_path: Path) -> Path:
    """Generate a timestamped output path for the scan report.

    Args:
        template_path: Path to the CloudFormation template.

    Returns:
        Path object for the generated report file.
    """
    import config.settings as settings
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(settings.REPORTS_OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / f"{timestamp}_{template_path.stem}.md"


def _mode_label(mode: str) -> str:
    """Return a human-readable label for the active mode.

    Args:
        mode: 'local' or 'aws'.

    Returns:
        Descriptive string for display.
    """
    if mode == "local":
        return "local (Ollama + ChromaDB)"
    return "aws (Bedrock + Pinecone)"


def main() -> None:
    """Parse arguments and run the IaC security scan pipeline."""
    parser = argparse.ArgumentParser(
        description="LLM IaC Security Scanner — detect misconfigurations in CloudFormation templates."
    )
    parser.add_argument(
        "template_path",
        help="Path to the CloudFormation template (.yaml or .json)",
    )
    parser.add_argument(
        "--mode",
        choices=["local", "aws"],
        default=None,
        help="LLM and vector store mode (default: from MODE env var or 'local')",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output path for the Markdown report "
             "(default: data/reports/generated/<timestamp>_<name>.md)",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=None,
        help="KB snippets to retrieve per scan (default: 5)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Print per-agent progress logs to terminal",
    )

    args = parser.parse_args()

    # Validate template path
    template_path = Path(args.template_path)
    if not template_path.exists():
        print(f"Error: Template not found: {template_path}", file=sys.stderr)
        sys.exit(2)
    if template_path.suffix.lower() not in (".yaml", ".yml", ".json", ".tf"):
        print(
            f"Error: Unsupported file type '{template_path.suffix}'. "
            "Use .yaml, .yml, .json, or .tf (Terraform).",
            file=sys.stderr,
        )
        sys.exit(2)

    # Apply overrides to environment before importing settings-dependent modules
    if args.mode:
        os.environ["MODE"] = args.mode
    if args.top_k is not None:
        os.environ["TOP_K_RESULTS"] = str(args.top_k)
    if args.verbose:
        os.environ["LOG_LEVEL"] = "DEBUG"

    import config.settings as settings
    from config.logging_config import configure_logging
    configure_logging()

    # Validate required environment variables before doing any real work (MISS-01)
    try:
        settings.validate_config()
    except Exception as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(2)

    # Determine output path
    output_path = Path(args.output) if args.output else _auto_output_path(template_path)

    # Display header
    _print_banner()
    mode = settings.MODE
    print(f" Mode:      {_mode_label(mode)}")
    print(f" Template:  {template_path}")
    print(f" Output:    {output_path}")
    print()

    # Run pipeline
    t_total_start = time.time()
    try:
        from orchestrator.pipeline import IaCSecurityPipeline

        pipeline = IaCSecurityPipeline()
        result = pipeline.run(template_path, output_path=str(output_path))

        total_elapsed = time.time() - t_total_start

        # Summary
        summary = result.get("summary", {})
        findings = result.get("findings", {})
        vuln_list = findings.get("vulnerabilities", []) if isinstance(findings, dict) else []
        total_findings = len(vuln_list)

        # Count by severity
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in vuln_list:
            sev = str(vuln.get("severity", "LOW")).upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        print("─" * 54)
        print(f" SCAN COMPLETE — {total_findings} findings in {total_elapsed:.1f} seconds")
        print()
        print(f"  CRITICAL   {severity_counts['CRITICAL']}")
        print(f"  HIGH       {severity_counts['HIGH']}")
        print(f"  MEDIUM     {severity_counts['MEDIUM']}")
        print(f"  LOW        {severity_counts['LOW']}")
        print()
        print(f" Report saved to: {result.get('report_path', output_path)}")
        print("─" * 54)

        sys.exit(0)

    except SystemExit:
        raise
    except Exception as exc:
        total_elapsed = time.time() - t_total_start
        print(f"\nError: Pipeline failed after {total_elapsed:.1f}s: {exc}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
