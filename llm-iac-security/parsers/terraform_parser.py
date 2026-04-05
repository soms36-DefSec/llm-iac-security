"""Terraform HCL parser for LLM IaC Security Scanner.

Parses .tf files using python-hcl2 and normalises them into the same
dict structure that CloudFormationParser produces so the rest of the
pipeline (ResourceExtractor, agents, formatter) works unchanged.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any, Union

from parsers.base_parser import BaseParser
from utils.exceptions import ParsingError, UnsupportedTemplateFormatError

# Mapping of common Terraform resource types to AWS CloudFormation-style types
_TF_TO_AWS_TYPE: dict[str, str] = {
    "aws_s3_bucket": "AWS::S3::Bucket",
    "aws_s3_bucket_acl": "AWS::S3::BucketAcl",
    "aws_s3_bucket_public_access_block": "AWS::S3::PublicAccessBlock",
    "aws_s3_bucket_versioning": "AWS::S3::BucketVersioning",
    "aws_s3_bucket_server_side_encryption_configuration": "AWS::S3::BucketEncryption",
    "aws_iam_role": "AWS::IAM::Role",
    "aws_iam_policy": "AWS::IAM::ManagedPolicy",
    "aws_iam_role_policy": "AWS::IAM::RolePolicy",
    "aws_iam_user": "AWS::IAM::User",
    "aws_iam_group": "AWS::IAM::Group",
    "aws_security_group": "AWS::EC2::SecurityGroup",
    "aws_security_group_rule": "AWS::EC2::SecurityGroupIngress",
    "aws_db_instance": "AWS::RDS::DBInstance",
    "aws_db_subnet_group": "AWS::RDS::DBSubnetGroup",
    "aws_lambda_function": "AWS::Lambda::Function",
    "aws_lambda_permission": "AWS::Lambda::Permission",
    "aws_cloudtrail": "AWS::CloudTrail::Trail",
    "aws_kms_key": "AWS::KMS::Key",
    "aws_kms_alias": "AWS::KMS::Alias",
    "aws_vpc": "AWS::EC2::VPC",
    "aws_subnet": "AWS::EC2::Subnet",
    "aws_instance": "AWS::EC2::Instance",
    "aws_elb": "AWS::ElasticLoadBalancing::LoadBalancer",
    "aws_alb": "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "aws_cloudwatch_log_group": "AWS::Logs::LogGroup",
    "aws_cloudwatch_metric_alarm": "AWS::CloudWatch::Alarm",
    "aws_guardduty_detector": "AWS::GuardDuty::Detector",
    "aws_config_configuration_recorder": "AWS::Config::ConfigurationRecorder",
    "aws_flow_log": "AWS::EC2::FlowLog",
    "aws_secrets_manager_secret": "AWS::SecretsManager::Secret",
    "aws_ssm_parameter": "AWS::SSM::Parameter",
    "aws_sns_topic": "AWS::SNS::Topic",
    "aws_sqs_queue": "AWS::SQS::Queue",
}


def _tf_type_to_aws(tf_type: str) -> str:
    """Map a Terraform resource type string to an AWS-style type label."""
    return _TF_TO_AWS_TYPE.get(tf_type, f"Terraform::{tf_type}")


def _flatten_hcl2_list(value: Any) -> Any:
    """hcl2 wraps some values in extra lists; flatten one level."""
    if isinstance(value, list) and len(value) == 1 and not isinstance(value[0], (str, int, float, bool)):
        return value[0]
    return value


class TerraformParser(BaseParser):
    """Parses Terraform HCL (.tf) files into the scanner's normalized format.

    Requires `python-hcl2` to be installed:
        pip install python-hcl2

    The normalized output uses the same schema as CloudFormationParser so
    the rest of the pipeline (ResourceExtractor, agents, formatter) works
    without modification.
    """

    def parse(self, path: Union[str, Path]) -> dict[str, Any]:
        """Parse a Terraform HCL file into a raw dict.

        Args:
            path: Path to the .tf file.

        Returns:
            Raw hcl2 parse result dict.

        Raises:
            UnsupportedTemplateFormatError: If python-hcl2 is not installed.
            ParsingError: If the file cannot be parsed.
        """
        try:
            import hcl2
        except ImportError as exc:
            raise UnsupportedTemplateFormatError(
                "python-hcl2 is required for Terraform parsing. "
                "Install with: pip install python-hcl2"
            ) from exc

        p = Path(path)
        try:
            with p.open(encoding="utf-8") as fh:
                return hcl2.load(fh)
        except Exception as exc:
            raise ParsingError(f"Failed to parse Terraform file {p.name}: {exc}") from exc

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize a raw hcl2 parse result into the scanner's standard format.

        Args:
            raw: Dict produced by hcl2.load().

        Returns:
            Normalized template dict with keys:
            template_format_version, description, parameters, resources, outputs.
        """
        resources: dict[str, Any] = {}

        for block in raw.get("resource", []):
            for tf_type, instances in block.items():
                aws_type = _tf_type_to_aws(tf_type)
                instances_resolved = _flatten_hcl2_list(instances) if isinstance(instances, list) else instances
                if isinstance(instances_resolved, dict):
                    for logical_id, props_raw in instances_resolved.items():
                        props = _flatten_hcl2_list(props_raw) if isinstance(props_raw, list) else props_raw
                        if not isinstance(props, dict):
                            props = {}
                        depends_on = props.pop("depends_on", [])
                        if isinstance(depends_on, list) and depends_on and isinstance(depends_on[0], list):
                            depends_on = depends_on[0]
                        resources[logical_id] = {
                            "type": aws_type,
                            "properties": props,
                            "depends_on": depends_on if isinstance(depends_on, list) else [],
                            "metadata": {},
                            "condition": None,
                        }

        outputs: dict[str, Any] = {}
        for block in raw.get("output", []):
            for name, val in block.items():
                outputs[name] = _flatten_hcl2_list(val) if isinstance(val, list) else val

        return {
            "template_format_version": "terraform",
            "description": "",
            "parameters": {},
            "resources": resources,
            "outputs": outputs,
        }
