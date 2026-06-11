import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from orchestrator.pipeline import IaCSecurityPipeline

ROOT = Path(__file__).resolve().parents[2]


def test_terraform_pipeline_hybrid_with_mocked_llm_and_rag():
    fixture = ROOT / "tests/fixtures/terraform/vulnerable/aws_s3_public_unencrypted"
    mock_kb = MagicMock()
    mock_kb.retrieve.return_value = ["S3 buckets should use default encryption and block public access."]

    mock_llm = MagicMock()
    mock_llm.invoke.return_value = json.dumps(
        {
            "findings": [
                {
                    "finding_id": "hybrid-1",
                    "source_finding_ids": ["static-1"],
                    "title": "S3 bucket lacks encryption",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "validation_status": "true_positive",
                    "resource_id": "aws_s3_bucket.logs",
                    "resource_type": "aws_s3_bucket",
                    "description": "The bucket has no encryption configuration.",
                    "impact": "Objects may not be encrypted by explicit IaC configuration.",
                    "evidence": "BucketEncryption/server_side_encryption_configuration not found.",
                    "remediation": "Add server-side encryption configuration.",
                    "references": ["retrieved:S3 encryption"],
                    "detected_by": "hybrid",
                }
            ],
            "summary": {},
        }
    )

    with patch("agents.retrieval_agent.KnowledgeBaseManager", return_value=mock_kb), \
         patch("agents.vulnerability_detection_agent.get_llm_client", return_value=mock_llm):
        result = IaCSecurityPipeline(hybrid=True).run(fixture)

    assert result["scan_mode"] == "hybrid"
    assert result["llm_enrichment_skipped"] is False
    assert result["findings"]["findings"][0]["detected_by"] == "hybrid"
    mock_llm.invoke.assert_called_once()


def test_terraform_pipeline_hybrid_malformed_llm_falls_back_to_static():
    fixture = ROOT / "tests/fixtures/terraform/vulnerable/aws_s3_public_unencrypted"
    mock_kb = MagicMock()
    mock_kb.retrieve.return_value = []
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = "not json"

    with patch("agents.retrieval_agent.KnowledgeBaseManager", return_value=mock_kb), \
         patch("agents.vulnerability_detection_agent.get_llm_client", return_value=mock_llm):
        result = IaCSecurityPipeline(hybrid=True).run(fixture)

    assert len(result["findings"]["findings"]) == len(result["static_findings"])
    assert result["findings"]["summary"]["note"]
