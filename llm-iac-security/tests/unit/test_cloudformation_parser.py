import textwrap
from pathlib import Path
import pytest
from parsers.cloudformation_parser import CloudFormationParser
from utils.exceptions import ParsingError, UnsupportedTemplateFormatError

@pytest.fixture
def tmp_yaml(tmp_path):
    p = tmp_path / "t.yaml"
    p.write_text(textwrap.dedent("""
        AWSTemplateFormatVersion: "2010-09-09"
        Resources:
          Bucket:
            Type: AWS::S3::Bucket
            Properties:
              BucketName: test
    """))
    return p

def test_parse_yaml(tmp_yaml): assert "Resources" in CloudFormationParser().parse(tmp_yaml)
def test_normalize(tmp_yaml): assert "resources" in CloudFormationParser().parse_and_normalize(tmp_yaml)
def test_unsupported(tmp_path):
    p = tmp_path/"t.tf"; p.write_text("x{}")
    with pytest.raises(UnsupportedTemplateFormatError): CloudFormationParser().parse(p)
def test_bad_yaml(tmp_path):
    p = tmp_path/"bad.yaml"; p.write_text("key: {bad:")
    with pytest.raises(ParsingError): CloudFormationParser().parse(p)
