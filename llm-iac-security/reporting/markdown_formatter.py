from typing import Any
from reporting.severity_classifier import Severity, classify, sort_findings

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴", 
    Severity.HIGH: "🟠", 
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵", 
    Severity.INFO: "⚪"
}

def escape_markdown(text: Any) -> str:
    """GAP 16: Escape pipe characters and backticks for Markdown tables."""
    if text is None: return "N/A"
    s = str(text)
    return s.replace("|", "\\|").replace("`", "\\`").replace("\n", " ")

class MarkdownFormatter:
    """Renders structured findings into a deterministic Markdown report."""

    def format(self, findings: dict[str, Any], template_name: str) -> str:
        # GAP 6: Classification and sorting already happen in sort_findings
        vulns = sort_findings(findings.get("vulnerabilities", []))
        
        lines = [
            f"# Security Scan Report: `{template_name}`",
            "",
            "## Summary",
            f"{findings.get('summary', 'No summary provided.')}",
            "",
            f"**Total findings:** {len(vulns)}",
            ""
        ]
        
        # Severity breakdown
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = sum(1 for v in vulns if classify(v.get("severity", "")) == sev)
            if count > 0:
                lines.append(f"- {SEVERITY_EMOJI[sev]} **{sev.value}**: {count}")
        
        lines.extend([
            "",
            "## Findings Overview",
            "",
            "| Severity | Resource | Vulnerability Type |",
            "|:---------|:---------|:-------------------|"
        ])
        
        for v in vulns:
            sev_str = v.get("severity", "INFO")
            sev_enum = classify(sev_str)
            emoji = SEVERITY_EMOJI.get(sev_enum, "⚪")
            
            # GAP 8: Use resource_name instead of resource_id
            res_name = escape_markdown(v.get("resource_name", "N/A"))
            vuln_type = escape_markdown(v.get("vulnerability_type", "N/A"))
            
            lines.append(f"| {emoji} {sev_str} | `{res_name}` | {vuln_type} |")
            
        lines.append("\n## Detailed Findings")
        
        for i, v in enumerate(vulns, 1):
            sev_str = v.get("severity", "INFO")
            sev_enum = classify(sev_str)
            emoji = SEVERITY_EMOJI.get(sev_enum, "⚪")
            
            vuln_type = v.get("vulnerability_type", "Untitled Finding")
            res_name = v.get("resource_name", "N/A")
            res_type = v.get("resource_type", "N/A")
            
            lines.extend([
                f"\n### {i}. {emoji} {vuln_type}",
                f"**Resource:** `{res_name}` ({res_type}) | **Severity:** {sev_str}",
                f"\n**Description:** {v.get('description', 'N/A')}",
                f"\n**Remediation:** {v.get('remediation', 'N/A')}",
                f"\n**Reference:** {v.get('best_practice_reference', 'N/A')}",
                "\n---"
            ])
            
        return "\n".join(lines)
