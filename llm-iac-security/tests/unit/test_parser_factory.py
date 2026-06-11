from pathlib import Path

import pytest

from parsers.cloudformation_parser import CloudFormationParser
from parsers.parser_factory import ParserFactory
from parsers.terraform_parser import TerraformParser
from utils.exceptions import UnsupportedTemplateFormatError


def test_selects_cloudformation_for_yaml(tmp_path):
    path = tmp_path / "template.yaml"
    path.write_text("Resources: {}", encoding="utf-8")
    assert isinstance(ParserFactory.get_parser(path), CloudFormationParser)


def test_selects_terraform_for_tf_file(tmp_path):
    path = tmp_path / "main.tf"
    path.write_text("", encoding="utf-8")
    assert isinstance(ParserFactory.get_parser(path), TerraformParser)


def test_selects_terraform_for_directory_with_tf(tmp_path):
    (tmp_path / "main.tf").write_text("", encoding="utf-8")
    assert isinstance(ParserFactory.get_parser(tmp_path), TerraformParser)


def test_unsupported_path_raises(tmp_path):
    path = tmp_path / "template.txt"
    path.write_text("", encoding="utf-8")
    with pytest.raises(UnsupportedTemplateFormatError):
        ParserFactory.get_parser(path)
