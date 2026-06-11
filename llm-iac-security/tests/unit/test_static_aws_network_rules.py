from pathlib import Path

from iac.models import IaCTemplate
from parsers.terraform_parser import TerraformParser
from static_analysis.rules.aws_network_rules import SecurityGroupRdpOpenRule, SecurityGroupSshOpenRule

ROOT = Path(__file__).resolve().parents[2]


def test_security_group_rules_detect_open_admin_ports():
    template = IaCTemplate.from_dict(
        TerraformParser().parse_and_normalize(ROOT / "tests/fixtures/terraform/vulnerable/aws_security_group_open")
    )
    assert SecurityGroupSshOpenRule().scan(template)
    assert SecurityGroupRdpOpenRule().scan(template)


def test_security_group_rules_ignore_restricted_cidrs():
    template = IaCTemplate.from_dict(
        TerraformParser().parse_and_normalize(ROOT / "tests/fixtures/terraform/clean/aws_security_group_restricted")
    )
    assert SecurityGroupSshOpenRule().scan(template) == []
    assert SecurityGroupRdpOpenRule().scan(template) == []
