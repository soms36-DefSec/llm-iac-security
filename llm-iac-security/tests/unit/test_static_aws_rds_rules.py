from pathlib import Path

from iac.models import IaCTemplate
from parsers.terraform_parser import TerraformParser
from static_analysis.rules.aws_rds_rules import RDSPubliclyAccessibleRule, RDSStorageEncryptionRule

ROOT = Path(__file__).resolve().parents[2]


def test_rds_rules_detect_public_unencrypted_instance():
    template = IaCTemplate.from_dict(
        TerraformParser().parse_and_normalize(ROOT / "tests/fixtures/terraform/vulnerable/aws_rds_public_unencrypted")
    )
    assert RDSStorageEncryptionRule().scan(template)
    assert RDSPubliclyAccessibleRule().scan(template)


def test_rds_rules_ignore_private_encrypted_instance():
    template = IaCTemplate.from_dict(
        TerraformParser().parse_and_normalize(ROOT / "tests/fixtures/terraform/clean/aws_rds_private_encrypted")
    )
    assert RDSStorageEncryptionRule().scan(template) == []
    assert RDSPubliclyAccessibleRule().scan(template) == []
