from pathlib import Path

from iac.models import IaCTemplate
from parsers.terraform_parser import TerraformParser
from static_analysis.rules.aws_s3_rules import S3BucketEncryptionRule, S3PublicAccessBlockRule

ROOT = Path(__file__).resolve().parents[2]


def test_s3_rules_find_unencrypted_bucket_and_missing_public_access_block():
    template = TerraformParser().parse_and_normalize(
        ROOT / "tests/fixtures/terraform/vulnerable/aws_s3_public_unencrypted"
    )
    normalized = IaCTemplate.from_dict(template)
    findings = S3BucketEncryptionRule().scan(normalized)
    findings += S3PublicAccessBlockRule().scan(normalized)
    assert {finding.rule_id for finding in findings} == {
        "AWS_S3_BUCKET_ENCRYPTION_MISSING",
        "AWS_S3_PUBLIC_ACCESS_BLOCK_WEAK",
    }


def test_s3_rules_accept_secure_bucket():
    template = IaCTemplate.from_dict(
        TerraformParser().parse_and_normalize(ROOT / "tests/fixtures/terraform/clean/aws_s3_secure")
    )
    assert S3BucketEncryptionRule().scan(template) == []
    assert S3PublicAccessBlockRule().scan(template) == []
