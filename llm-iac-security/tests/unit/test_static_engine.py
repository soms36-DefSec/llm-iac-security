from pathlib import Path

from parsers.terraform_parser import TerraformParser
from static_analysis.engine import StaticAnalysisEngine

ROOT = Path(__file__).resolve().parents[2]


def _rule_ids(path: Path) -> set[str]:
    template = TerraformParser().parse_and_normalize(path)
    return {finding.rule_id for finding in StaticAnalysisEngine().scan(template)}


def test_static_engine_detects_multi_resource_vulnerabilities():
    path = ROOT / "tests/fixtures/terraform/vulnerable/multi_resource_vulnerable"
    rule_ids = _rule_ids(path)
    assert "AWS_S3_BUCKET_ENCRYPTION_MISSING" in rule_ids
    assert "AWS_IAM_WILDCARD_ACTION" in rule_ids
    assert "AWS_SG_OPEN_ALL_TRAFFIC" in rule_ids
    assert "AWS_RDS_PUBLICLY_ACCESSIBLE" in rule_ids
    assert "GENERIC_HARDCODED_SECRET" in rule_ids


def test_static_engine_clean_s3_fixture_has_no_findings():
    path = ROOT / "tests/fixtures/terraform/clean/aws_s3_secure"
    assert StaticAnalysisEngine().scan(TerraformParser().parse_and_normalize(path)) == []
