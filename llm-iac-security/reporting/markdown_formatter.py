from typing import Any
from reporting.severity_classifier import Severity, classify, sort_findings

SEVERITY_EMOJI = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
                  Severity.LOW: "🔵", Severity.INFO: "⚪"}

class MarkdownFormatter:
    def format(self, findings: dict[str, Any], template_name: str) -> str:
        vulns = sort_findings(findings.get("vulnerabilities", []))
        lines = [f"# Security Scan Report: `{template_name}`\n",
                 f"## Summary\n{findings.get('summary', '')}\n",
                 f"**Total findings:** {len(vulns)}\n"]
        for sev in Severity:
            c = sum(1 for v in vulns if classify(v.get("severity","")) == sev)
            if c: lines.append(f"- {SEVERITY_EMOJI[sev]} **{sev.value}**: {c}")
        lines += ["", "## Findings\n", "| Severity | Resource | Issue |", "|----------|----------|-------|"]
        for v in vulns:
            sev = v.get("severity","INFO"); e = SEVERITY_EMOJI.get(classify(sev),"⚪")
            lines.append(f"| {e} {sev} | `{v.get('resource_id','N/A')}` | {v.get('title','')} |")
        lines.append("\n## Detailed Findings\n")
        for i, v in enumerate(vulns, 1):
            sev = classify(v.get("severity","INFO")); e = SEVERITY_EMOJI[sev]
            lines += [f"### {i}. {e} {v.get('title','Untitled')}",
                      f"**Resource:** `{v.get('resource_id','')}` | **Severity:** {v.get('severity','')}",
                      f"\n**Description:** {v.get('description','')}",
                      f"\n**Remediation:** {v.get('remediation','')}",
                      f"\n**Reference:** {v.get('reference','N/A')}\n---\n"]
        return "\n".join(lines)
