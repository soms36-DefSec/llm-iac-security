from typing import Any
from reporting.severity_classifier import Severity, classify, sort_findings

class MarkdownFormatter:
    """Formats static or hybrid scan output as Markdown."""

    def format(self, findings: dict[str, Any], template_name: str, context: dict[str, Any] | None = None) -> str:
        context = context or {}
        vulns = sort_findings(findings.get("findings") or findings.get("vulnerabilities", []))
        summary = findings.get("summary", {})
        if isinstance(summary, str):
            summary_text = summary
            summary = {}
        else:
            summary_text = summary.get("note", "") if isinstance(summary, dict) else ""
        static_count = len(context.get("static_findings", []))
        iac_type = context.get("normalized_template", {}).get("iac_type", "unknown")
        metadata = context.get("scan_metadata", {})

        lines = [
            f"# Security Scan Report: `{template_name}`",
            "",
            "## Scan Metadata",
            f"- IaC type: `{iac_type}`",
            f"- Source: `{context.get('template_path', 'unknown')}`",
            f"- Scan mode: `{context.get('scan_mode', 'hybrid')}`",
            f"- Static findings: **{static_count}**",
            f"- Validated findings: **{len(vulns)}**",
        ]
        if context.get("risk_explainer_enabled"):
            autofix_count = summary.get("autofix_available", 0) if isinstance(summary, dict) else 0
            lines.append(f"- Risk explainer and auto-fix assistant: enabled (**{autofix_count}** candidate fixes)")
        if metadata.get("latency_seconds") is not None:
            lines.append(f"- Latency: **{metadata['latency_seconds']:.3f}s**")
        if context.get("llm_enrichment_skipped"):
            lines.append("- LLM enrichment: skipped")
        if summary_text:
            lines.extend(["", f"> {summary_text}"])

        lines.extend(["", "## Findings By Severity"])
        for sev in Severity:
            c = sum(1 for v in vulns if classify(v.get("severity","")) == sev)
            lines.append(f"- **{sev.value}**: {c}")

        needs_review = sum(1 for v in vulns if v.get("validation_status") == "needs_review")
        lines.extend(["", "## Review Queue", f"Findings needing review: **{needs_review}**"])

        lines += [
            "",
            "## Findings",
            "",
            "| Severity | Rule ID | Resource | Location | Status | Confidence | Remediation Summary |",
            "|----------|---------|----------|----------|--------|------------|---------------------|",
        ]
        for v in vulns:
            sev = v.get("severity","INFO")
            remediation = _first_sentence(v.get("remediation", ""))
            location = _format_location(v)
            fix_status = "yes" if (v.get("auto_fix") or {}).get("available") else "manual"
            lines.append(
                f"| {sev} | `{v.get('rule_id','N/A')}` | `{v.get('resource_id','N/A')}` | {location} | "
                f"{v.get('validation_status','n/a')} | {v.get('confidence','')} | {remediation} ({fix_status}) |"
            )
        lines.append("\n## Detailed Findings\n")
        for i, v in enumerate(vulns, 1):
            refs = v.get("references") or ([v.get("reference")] if v.get("reference") else [])
            auto_fix = v.get("auto_fix") or {}
            policy = v.get("policy_as_code") or {}
            lines += [
                f"### {i}. {v.get('title','Untitled')}",
                f"**Resource:** `{v.get('resource_id','')}`",
                f"**Type:** `{v.get('resource_type','')}`",
                f"**Location:** {_format_location(v)}",
                f"**Severity:** {v.get('severity','')} | **Confidence:** {v.get('confidence','')}",
                f"**Status:** {v.get('validation_status','n/a')} | **Detected by:** {v.get('detected_by','')}",
                "",
                f"**Description:** {v.get('description','')}",
                "",
                f"**Risk explanation:** {v.get('risk_explanation','')}",
                "",
                "**Likely attack path:**",
                *[f"- {step}" for step in v.get("attack_path", [])],
                "",
                f"**Impact:** {v.get('impact','')}",
                "",
                f"**Business impact:** {v.get('business_impact','')}",
                "",
                f"**Evidence:** `{v.get('evidence','')}`",
                "",
                f"**Remediation:** {v.get('remediation','')}",
                "",
                f"**Auto-fix assistant:** {auto_fix.get('summary', 'N/A')}",
                f"**Fix safety:** `{auto_fix.get('safety', 'n/a')}`",
                "",
            ]
            if auto_fix.get("steps"):
                lines += ["**Fix steps:**", *[f"- {step}" for step in auto_fix.get("steps", [])], ""]
            if auto_fix.get("snippet"):
                lines += [
                    "**Suggested IaC change:**",
                    "",
                    "```",
                    str(auto_fix.get("snippet", "")),
                    "```",
                    "",
                ]
            if policy.get("rego"):
                lines += [
                    "**Policy-as-code guardrail:**",
                    f"{policy.get('description', '')}",
                    "",
                    "```rego",
                    str(policy.get("rego", "")),
                    "```",
                    "",
                ]
            compliance = v.get("compliance_mappings", [])
            lines += [
                f"**Compliance mappings:** {', '.join(str(item) for item in compliance) if compliance else 'N/A'}",
                "",
                f"**References:** {', '.join(str(ref) for ref in refs) if refs else 'N/A'}",
                "",
                "---",
                "",
            ]
        if context.get("evaluation_metrics"):
            lines += ["## Evaluation Metrics", "", "```json", str(context["evaluation_metrics"]), "```"]
        return "\n".join(lines)


def _first_sentence(text: str) -> str:
    if not text:
        return ""
    return text.split(".")[0][:120]


def _format_location(finding: dict[str, Any]) -> str:
    source_file = finding.get("source_file") or "N/A"
    line_number = finding.get("line_number")
    if line_number:
        return f"`{source_file}:{line_number}`"
    return f"`{source_file}`"
