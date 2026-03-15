#!/usr/bin/env python3
"""CLI entry point for scanning a CloudFormation template."""
import sys
import os
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
@click.option("--mode", type=click.Choice(["local", "aws"], case_sensitive=False),
              default=None, help="Run mode: 'local' (Ollama+ChromaDB) or 'aws' (Bedrock+Pinecone)")
@click.option("--output", type=click.Path(path_type=Path), default=None,
              help="Custom output path for the report")
@click.option("--verbose", is_flag=True, default=False, help="Enable debug logging")
def scan(template_path: Path, mode: str, output: Path, verbose: bool) -> None:
    """Scan a CloudFormation TEMPLATE_PATH for security vulnerabilities."""
    if mode:
        os.environ["MODE"] = mode
    if verbose:
        os.environ["LOG_LEVEL"] = "DEBUG"
    configure_logging()

    current_mode = os.getenv("MODE", "local")
    console.print(Panel(
        f"[bold blue]IaC Security Scanner[/bold blue]\n"
        f"Template: {template_path}\n"
        f"Mode: [bold]{current_mode}[/bold]"
    ))

    try:
        result = IaCSecurityPipeline().run(template_path)
        vuln_count = len(result.get("findings", {}).get("vulnerabilities", []))

        if output:
            from utils.file_utils import write_text
            write_text(output, result.get("report_markdown", ""))
            console.print(f"Report saved to: [bold]{output}[/bold]")
        else:
            console.print(f"Report: [bold]{result.get('report_path')}[/bold]")

        console.print(f"\n[green]Scan complete![/green] Vulnerabilities: [bold]{vuln_count}[/bold]")
        sys.exit(1 if vuln_count > 0 else 0)

    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        sys.exit(2)


if __name__ == "__main__":
    scan()
