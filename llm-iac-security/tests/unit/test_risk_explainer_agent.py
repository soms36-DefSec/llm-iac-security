from agents.risk_explainer_agent import RiskExplainerAgent
from reporting.markdown_formatter import MarkdownFormatter


def test_risk_explainer_adds_attack_path_autofix_and_policy():
    context = {
        "normalized_template": {
            "iac_type": "terraform",
            "source_path": "main.tf",
            "resources": {
                "aws_s3_bucket.logs": {
                    "logical_id": "aws_s3_bucket.logs",
                    "resource_type": "aws_s3_bucket",
                    "provider": "aws",
                    "name": "logs",
                    "properties": {"bucket": "app-logs"},
                    "source_file": "main.tf",
                }
            },
        },
        "findings": {
            "findings": [
                {
                    "finding_id": "f1",
                    "rule_id": "AWS_S3_BUCKET_ENCRYPTION_MISSING",
                    "title": "S3 bucket encryption missing",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "validation_status": "true_positive",
                    "resource_id": "aws_s3_bucket.logs",
                    "resource_type": "aws_s3_bucket",
                    "description": "The bucket is not encrypted.",
                    "impact": "Data exposure risk.",
                    "evidence": "BucketEncryption not found.",
                    "remediation": "Enable default encryption.",
                    "references": [],
                    "detected_by": "static",
                    "iac_type": "terraform",
                    "provider": "aws",
                    "source_file": "main.tf",
                    "tags": ["s3"],
                }
            ],
            "summary": {"total_findings": 1},
        },
    }

    enriched = RiskExplainerAgent().run(context)
    finding = enriched["findings"]["findings"][0]

    assert enriched["risk_explainer_enabled"] is True
    assert enriched["findings"]["summary"]["autofix_available"] == 1
    assert finding["risk_explanation"]
    assert finding["attack_path"]
    assert finding["auto_fix"]["available"] is True
    assert "aws_s3_bucket_server_side_encryption_configuration" in finding["auto_fix"]["snippet"]
    assert finding["policy_as_code"]["type"] == "opa_rego_guardrail"
    assert "AWS_S3_BUCKET_ENCRYPTION_MISSING" in finding["policy_as_code"]["rego"]


def test_markdown_report_renders_risk_explainer_sections():
    finding = {
        "finding_id": "f1",
        "rule_id": "AWS_S3_PUBLIC_ACCESS_BLOCK_WEAK",
        "title": "S3 public access block missing or weak",
        "severity": "HIGH",
        "confidence": "HIGH",
        "validation_status": "true_positive",
        "resource_id": "aws_s3_bucket.logs",
        "resource_type": "aws_s3_bucket",
        "description": "The bucket does not block public access.",
        "impact": "Public exposure risk.",
        "evidence": "public access block missing",
        "remediation": "Set public access block controls.",
        "references": [],
        "detected_by": "static",
        "iac_type": "terraform",
        "provider": "aws",
        "source_file": "main.tf",
        "risk_explanation": "The bucket lacks public access guardrails.",
        "attack_path": ["A public policy is added.", "Objects become reachable."],
        "business_impact": "Data can become public.",
        "compliance_mappings": ["CIS AWS guidance for S3 public access"],
        "auto_fix": {
            "available": True,
            "summary": "Set all four public access block flags to true.",
            "safety": "candidate_safe_default_review_before_apply",
            "steps": ["Add the public access block resource."],
            "snippet": "block_public_acls = true",
        },
        "policy_as_code": {
            "description": "Reject weak S3 public access block settings.",
            "rego": 'package iac.security.aws\n\ndeny[msg] {\n  input.rule_id == "AWS_S3_PUBLIC_ACCESS_BLOCK_WEAK"\n}\n',
        },
    }
    report = MarkdownFormatter().format(
        {"findings": [finding], "summary": {"autofix_available": 1}},
        "main",
        {
            "template_path": "main.tf",
            "scan_mode": "static-only",
            "risk_explainer_enabled": True,
            "normalized_template": {"iac_type": "terraform"},
        },
    )

    assert "Risk explainer and auto-fix assistant: enabled" in report
    assert "**Risk explanation:** The bucket lacks public access guardrails." in report
    assert "**Likely attack path:**" in report
    assert "**Suggested IaC change:**" in report
    assert "```rego" in report
    assert "**Compliance mappings:** CIS AWS guidance for S3 public access" in report
