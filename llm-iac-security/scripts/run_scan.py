#!/usr/bin/env python3
"""CLI entry point for scanning CloudFormation or Terraform IaC."""
import sys
import os
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import click
from rich.console import Console
from rich.panel import Panel

console = Console()


def _json_safe_result(result: dict) -> dict:
    normalized = result.get("normalized_template", {})
    resources = normalized.get("resources", {})
    return {
        "scan_mode": result.get("scan_mode"),
        "llm_enrichment_skipped": result.get("llm_enrichment_skipped", False),
        "scan_metadata": result.get("scan_metadata", {}),
        "report_path": result.get("report_path"),
        "iac": {
            "type": normalized.get("iac_type"),
            "source_path": normalized.get("source_path"),
            "resource_count": len(resources),
        },
        "static_findings": result.get("static_findings", []),
        "findings": result.get("findings", {}),
    }


@click.command()
@click.argument("template_path", type=click.Path(exists=True, path_type=Path))
@click.option("--mode", type=click.Choice(["local", "aws"], case_sensitive=False),
              default=None, help="Run mode: 'local' (Ollama+ChromaDB) or 'aws' (Bedrock+Pinecone)")
@click.option("--output", type=click.Path(path_type=Path), default=None,
              help="Custom output path for the report")
@click.option("--json-output", type=click.Path(path_type=Path), default=None,
              help="Write machine-readable scan results to JSON")
@click.option("--static-only", is_flag=True, default=False,
              help="Run deterministic static rules only; never calls the LLM")
@click.option("--hybrid", is_flag=True, default=False,
              help="Run static rules plus RAG and LLM reasoning")
@click.option("--verbose", is_flag=True, default=False, help="Enable debug logging")
def scan(
    template_path: Path,
    mode: str,
    output: Path,
    json_output: Path,
    static_only: bool,
    hybrid: bool,
    verbose: bool,
) -> None:
    """Scan a CloudFormation template, Terraform file, or Terraform directory."""
    if mode:
        os.environ["MODE"] = mode
    if verbose:
        os.environ["LOG_LEVEL"] = "DEBUG"

    # Delay config-dependent imports until after CLI overrides are applied.
    from config.logging_config import configure_logging
    from orchestrator.pipeline import IaCSecurityPipeline

    configure_logging()

    current_mode = os.getenv("MODE", "local")
    console.print(Panel(
        f"[bold blue]IaC Security Scanner[/bold blue]\n"
        f"Template: {template_path}\n"
        f"Mode: [bold]{current_mode}[/bold]"
    ))

    try:
        run_hybrid = False if static_only else True if not hybrid else hybrid
        result = IaCSecurityPipeline(static_only=static_only, hybrid=run_hybrid).run(template_path)
        vuln_count = len(result.get("findings", {}).get("findings", result.get("findings", {}).get("vulnerabilities", [])))

        if output:
            from utils.file_utils import write_text
            write_text(output, result.get("report_markdown", ""))
            console.print(f"Report saved to: [bold]{output}[/bold]")
        else:
            console.print(f"Report: [bold]{result.get('report_path')}[/bold]")

        if json_output:
            from utils.file_utils import write_text
            write_text(json_output, json.dumps(_json_safe_result(result), indent=2))
            console.print(f"JSON results saved to: [bold]{json_output}[/bold]")

        mode_label = result.get("scan_mode", "hybrid")
        if result.get("llm_enrichment_skipped"):
            console.print("[yellow]LLM enrichment skipped; static findings returned.[/yellow]")

        console.print(f"\n[green]Scan complete![/green] Mode: [bold]{mode_label}[/bold] Findings: [bold]{vuln_count}[/bold]")
        sys.exit(1 if vuln_count > 0 else 0)

    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        sys.exit(2)


if __name__ == "__main__":
    scan()
