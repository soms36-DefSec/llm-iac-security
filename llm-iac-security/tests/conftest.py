from pathlib import Path
from typing import Any
from unittest.mock import patch
import pytest

@pytest.fixture
def sample_normalized_template() -> dict[str, Any]:
    return {"template_format_version": "2010-09-09", "description": "Test", "parameters": {},
            "resources": {
                "MyBucket": {"type": "AWS::S3::Bucket",
                             "properties": {"BucketName": "test", "VersioningConfiguration": {"Status": "Suspended"}},
                             "depends_on": [], "metadata": {}, "condition": None},
                "MyRole": {"type": "AWS::IAM::Role",
                           "properties": {"AssumeRolePolicyDocument": {"Statement": [{"Effect":"Allow","Principal":"*","Action":"*"}]}},
                           "depends_on": [], "metadata": {}, "condition": None},
            }, "outputs": {}}

@pytest.fixture
def sample_findings() -> dict[str, Any]:
    return {"vulnerabilities": [{"resource_id": "MyBucket", "resource_type": "AWS::S3::Bucket",
                                  "severity": "HIGH", "title": "S3 versioning disabled",
                                  "description": "Versioning suspended.", "remediation": "Enable versioning.",
                                  "reference": "CIS 2.1.2"}], "summary": "1 finding."}
