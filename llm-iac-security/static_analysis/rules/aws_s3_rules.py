"""AWS S3 static analysis rules."""

from __future__ import annotations

from typing import Any

from iac.models import IaCResource, IaCTemplate
from static_analysis.base_rule import StaticRule, falsey, get_any, safe_json

PAB_FLAGS = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
CF_PAB_FLAGS = ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")


class S3BucketEncryptionRule(StaticRule):
    """Detect S3 buckets without server-side encryption."""

    rule_id = "AWS_S3_BUCKET_ENCRYPTION_MISSING"
    title = "S3 bucket encryption missing"
    severity = "HIGH"
    tags = ["aws", "s3", "encryption"]
    references = ["AWS S3 default encryption best practices"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in template.resources:
            if resource.resource_type not in {"AWS::S3::Bucket", "aws_s3_bucket"}:
                continue
            if _bucket_has_encryption(resource, template.resources):
                continue
            findings.append(
                self.finding(
                    template,
                    resource,
                    "The S3 bucket does not define server-side encryption.",
                    "BucketEncryption/server_side_encryption_configuration not found.",
                    "Configure default server-side encryption with SSE-S3 or SSE-KMS.",
                )
            )
        return findings


class S3PublicAccessBlockRule(StaticRule):
    """Detect missing or weak S3 public access block settings."""

    rule_id = "AWS_S3_PUBLIC_ACCESS_BLOCK_WEAK"
    title = "S3 public access block missing or weak"
    severity = "HIGH"
    tags = ["aws", "s3", "public-access"]
    references = ["AWS S3 Block Public Access"]

    def scan(self, template: IaCTemplate):
        findings = []
        for resource in template.resources:
            if resource.resource_type == "AWS::S3::Bucket":
                pab = resource.properties.get("PublicAccessBlockConfiguration")
                if not isinstance(pab, dict):
                    findings.append(
                        self.finding(
                            template,
                            resource,
                            "The S3 bucket does not configure public access blocking.",
                            "PublicAccessBlockConfiguration not found.",
                            "Set all S3 public access block controls to true.",
                        )
                    )
                    continue
                weak = [flag for flag in CF_PAB_FLAGS if falsey(pab.get(flag)) or flag not in pab]
                if weak:
                    findings.append(
                        self.finding(
                            template,
                            resource,
                            "The S3 bucket has weak public access block settings.",
                            f"Weak or missing settings: {', '.join(weak)}.",
                            "Set BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, and RestrictPublicBuckets to true.",
                            suffix="weak",
                        )
                    )

            if resource.resource_type == "aws_s3_bucket":
                pab = _related_public_access_block(resource, template.resources)
                if pab is None:
                    findings.append(
                        self.finding(
                            template,
                            resource,
                            "The S3 bucket does not have an aws_s3_bucket_public_access_block resource.",
                            "aws_s3_bucket_public_access_block not found for this bucket.",
                            "Add aws_s3_bucket_public_access_block with all four block settings set to true.",
                        )
                    )
                    continue
                weak = [flag for flag in PAB_FLAGS if falsey(pab.properties.get(flag)) or flag not in pab.properties]
                if weak:
                    findings.append(
                        self.finding(
                            template,
                            pab,
                            "The S3 public access block resource has weak settings.",
                            f"Weak or missing settings: {', '.join(weak)}.",
                            "Set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true.",
                            suffix=resource.logical_id,
                        )
                    )
        return findings


def _bucket_has_encryption(bucket: IaCResource, resources: list[IaCResource]) -> bool:
    props = bucket.properties or {}
    if bucket.resource_type == "AWS::S3::Bucket":
        return bool(props.get("BucketEncryption"))
    if props.get("server_side_encryption_configuration"):
        return True
    if props.get("bucket_encryption"):
        return True
    for resource in resources:
        if resource.resource_type != "aws_s3_bucket_server_side_encryption_configuration":
            continue
        if _references_bucket(resource.properties.get("bucket"), bucket):
            return True
    return False


def _related_public_access_block(bucket: IaCResource, resources: list[IaCResource]) -> IaCResource | None:
    candidates = [resource for resource in resources if resource.resource_type == "aws_s3_bucket_public_access_block"]
    for candidate in candidates:
        if _references_bucket(candidate.properties.get("bucket"), bucket):
            return candidate
    if len(candidates) == 1 and _single_bucket(resources):
        return candidates[0]
    return None


def _single_bucket(resources: list[IaCResource]) -> bool:
    return sum(1 for resource in resources if resource.resource_type == "aws_s3_bucket") == 1


def _references_bucket(value: Any, bucket: IaCResource) -> bool:
    text = safe_json(value)
    identifiers = {
        bucket.logical_id,
        bucket.name,
        f"aws_s3_bucket.{bucket.name}",
        f"aws_s3_bucket.{bucket.name}.id",
        f"aws_s3_bucket.{bucket.name}.bucket",
    }
    bucket_name = get_any(bucket.properties, "bucket", "bucket_name", default=None)
    if bucket_name:
        identifiers.add(str(bucket_name))
    return any(identifier and identifier in text for identifier in identifiers)
