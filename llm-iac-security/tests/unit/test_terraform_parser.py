from pathlib import Path
from textwrap import dedent

import pytest

from parsers.terraform_parser import TerraformParser, detect_provider
from static_analysis.engine import StaticAnalysisEngine
from utils.exceptions import ParsingError

ROOT = Path(__file__).resolve().parents[2]


def test_parse_single_tf_file():
    fixture = ROOT / "tests/fixtures/terraform/vulnerable/aws_s3_public_unencrypted/main.tf"
    parsed = TerraformParser().parse_and_normalize(fixture)
    assert parsed["iac_type"] == "terraform"
    assert "aws_s3_bucket.logs" in parsed["resources"]
    assert parsed["resources"]["aws_s3_bucket.logs"]["provider"] == "aws"


def test_parse_directory_with_multiple_tf_files(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "logs" { bucket = "logs" }',
        encoding="utf-8",
    )
    (tmp_path / "variables.tf").write_text(
        'variable "env" { default = "dev" }\noutput "bucket" { value = aws_s3_bucket.logs.id }',
        encoding="utf-8",
    )
    parsed = TerraformParser().parse_and_normalize(tmp_path)
    assert "aws_s3_bucket.logs" in parsed["resources"]
    assert "env" in parsed["variables"]
    assert "bucket" in parsed["outputs"]


def test_invalid_hcl_raises_parsing_error(tmp_path):
    bad = tmp_path / "bad.tf"
    bad.write_text('resource "aws_s3_bucket" "bad" {', encoding="utf-8")
    with pytest.raises(ParsingError):
        TerraformParser().parse_and_normalize(bad)


def test_empty_terraform_directory_is_graceful(tmp_path):
    parsed = TerraformParser().parse_and_normalize(tmp_path)
    assert parsed["resources"] == {}
    assert parsed["iac_type"] == "terraform"


def test_detect_provider_prefixes():
    assert detect_provider("aws_s3_bucket") == "aws"
    assert detect_provider("azurerm_resource_group") == "azure"
    assert detect_provider("google_project_iam_member") == "gcp"
    assert detect_provider("kubernetes_pod") == "kubernetes"
    assert detect_provider("random_id") == "unknown"


def test_terraform_parser_resolves_common_expressions_and_line_numbers(tmp_path):
    terraform = tmp_path / "main.tf"
    source = dedent(
        """\
        variable "env" {
          default = "dev"
        }

        locals {
          bucket_name = "${var.env}-logs"
        }

        resource "aws_s3_bucket" "logs" {
          bucket = local.bucket_name
          tags = {
            Env = var.env
          }
        }

        resource "aws_iam_policy" "jsonencoded" {
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
        """
    )
    terraform.write_text(source, encoding="utf-8")

    parsed = TerraformParser().parse_and_normalize(terraform)
    bucket = parsed["resources"]["aws_s3_bucket.logs"]
    policy = parsed["resources"]["aws_iam_policy.jsonencoded"]

    assert bucket["line_number"] == source.splitlines().index('resource "aws_s3_bucket" "logs" {') + 1
    assert policy["line_number"] == source.splitlines().index('resource "aws_iam_policy" "jsonencoded" {') + 1
    assert bucket["metadata"]["property_line_numbers"]["bucket"] == source.splitlines().index("  bucket = local.bucket_name") + 1
    assert bucket["metadata"]["property_line_numbers"]["tags.Env"] == source.splitlines().index("    Env = var.env") + 1
    assert bucket["properties"]["bucket"] == "dev-logs"
    assert bucket["properties"]["tags"]["Env"] == "dev"
    assert isinstance(policy["properties"]["policy"], dict)
    assert {
        finding.rule_id
        for finding in StaticAnalysisEngine().scan(parsed)
    } >= {"AWS_IAM_WILDCARD_ACTION", "AWS_IAM_WILDCARD_RESOURCE"}


def test_terraform_parser_resolves_functions_conditionals_and_indexing(tmp_path):
    terraform = tmp_path / "main.tf"
    source = dedent(
        """\
        variable "env" {
          default = "Prod"
        }

        variable "tags" {
          default = {
            owner = "platform"
          }
        }

        locals {
          normalized_env = lower(var.env)
          bucket_name = format("%s-%s", local.normalized_env, "logs")
          joined = join("-", [local.normalized_env, "logs"])
          owner = var.tags.owner
          selected = local.normalized_env == "prod" ? "critical" : "standard"
          merged_tags = merge(var.tags, {
            Env = local.normalized_env
            Tier = local.selected
          })
        }

        resource "aws_s3_bucket" "logs" {
          bucket = local.bucket_name
          tags   = local.merged_tags
        }
        """
    )
    terraform.write_text(source, encoding="utf-8")

    parsed = TerraformParser().parse_and_normalize(terraform)
    bucket = parsed["resources"]["aws_s3_bucket.logs"]

    assert parsed["metadata"]["locals"]["normalized_env"] == "prod"
    assert parsed["metadata"]["locals"]["joined"] == "prod-logs"
    assert parsed["metadata"]["locals"]["owner"] == "platform"
    assert parsed["metadata"]["locals"]["selected"] == "critical"
    assert bucket["properties"]["bucket"] == "prod-logs"
    assert bucket["properties"]["tags"] == {
        "owner": "platform",
        "Env": "prod",
        "Tier": "critical",
    }


def test_terraform_parser_records_nested_property_line_numbers(tmp_path):
    terraform = tmp_path / "main.tf"
    source = dedent(
        """\
        resource "kubernetes_pod" "app" {
          metadata {
            name = "app"
          }

          spec {
            host_network = true

            container {
              name = "app"
              security_context {
                privileged = true
              }
            }
          }
        }
        """
    )
    terraform.write_text(source, encoding="utf-8")

    parsed = TerraformParser().parse_and_normalize(terraform)
    metadata = parsed["resources"]["kubernetes_pod.app"]["metadata"]["property_line_numbers"]

    assert metadata["metadata.name"] == source.splitlines().index('    name = "app"') + 1
    assert metadata["spec.host_network"] == source.splitlines().index("    host_network = true") + 1
    assert metadata["spec.container.security_context.privileged"] == source.splitlines().index("        privileged = true") + 1
