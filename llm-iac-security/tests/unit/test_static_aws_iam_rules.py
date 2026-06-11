from pathlib import Path

from iac.models import IaCTemplate
from parsers.terraform_parser import TerraformParser
from static_analysis.rules.aws_iam_rules import AdminPolicyRiskRule, IAMWildcardActionRule, IAMWildcardResourceRule

ROOT = Path(__file__).resolve().parents[2]


def test_iam_rules_detect_wildcards_and_admin_policy():
    template = IaCTemplate.from_dict(
        TerraformParser().parse_and_normalize(ROOT / "tests/fixtures/terraform/vulnerable/aws_iam_wildcard")
    )
    findings = []
    findings.extend(IAMWildcardActionRule().scan(template))
    findings.extend(IAMWildcardResourceRule().scan(template))
    findings.extend(AdminPolicyRiskRule().scan(template))
    assert {finding.rule_id for finding in findings} == {
        "AWS_IAM_WILDCARD_ACTION",
        "AWS_IAM_WILDCARD_RESOURCE",
        "AWS_IAM_ADMIN_POLICY",
    }


def test_iam_rules_ignore_least_privilege_policy():
    template = IaCTemplate.from_dict(
        TerraformParser().parse_and_normalize(ROOT / "tests/fixtures/terraform/clean/aws_iam_least_privilege")
    )
    assert IAMWildcardActionRule().scan(template) == []
    assert IAMWildcardResourceRule().scan(template) == []
    assert AdminPolicyRiskRule().scan(template) == []


def test_iam_rules_detect_jsonencode_policy(tmp_path):
    terraform = tmp_path / "main.tf"
    terraform.write_text(
        """
        resource "aws_iam_policy" "jsonencoded" {
          name = "jsonencoded"
          policy = jsonencode({
            Version = "2012-10-17"
            Statement = [
              {
                Effect = "Allow"
                Action = "s3:*"
                Resource = "*"
              }
            ]
          })
        }
        """,
        encoding="utf-8",
    )
    template = IaCTemplate.from_dict(TerraformParser().parse_and_normalize(terraform))
    assert IAMWildcardActionRule().scan(template)
    assert IAMWildcardResourceRule().scan(template)
