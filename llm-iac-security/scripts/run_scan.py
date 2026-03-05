#!/usr/bin/env python3
"""CLI entry point for scanning a CloudFormation template."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import click
from rich.console import Console
from rich.panel import Panel
from config.logging_config import configure_logging
from orchestrator.pipeline import IaCSecurityPipeline

console = Console()

@click.command()
@click.argument("template_path", type=click.Path(exists=True, path_type=Path))
@click.option("--verbose", is_flag=True, default=False)
def scan(template_path: Path, verbose: bool) -> None:
    """Scan a CloudFormation TEMPLATE_PATH for security vulnerabilities."""
    import os
    if verbose: os.environ["LOG_LEVEL"] = "DEBUG"
    configure_logging()
    console.print(Panel(f"[bold blue]IaC Security Scanner[/bold blue]\nTemplate: {template_path}"))
    result = IaCSecurityPipeline().run(template_path)
    vuln_count = len(result.get("findings", {}).get("vulnerabilities", []))
    console.print(f"\n[green]Scan complete![/green] Vulnerabilities: [bold]{vuln_count}[/bold]")
    console.print(f"Report: [bold]{result.get('report_path')}[/bold]")
    sys.exit(1 if vuln_count > 0 else 0)

if __name__ == "__main__":
    scan()
