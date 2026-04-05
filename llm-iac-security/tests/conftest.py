"""
Pytest fixtures for LLM IaC Security Scanner tests.

Provides the seven fixtures required by the test suite:
    sample_parsed_template    — Dict output of cloudformation_parser.parse(T1)
    mock_llm_client           — MagicMock returning a pre-written findings JSON
    mock_vector_store         — MagicMock returning KB snippet dicts
    mock_kb_manager           — MagicMock wrapping the mock vector store
    temp_output_dir           — tmp_path subdirectory for report output
    ground_truth_annotations  — Parsed annotations.json (session scope)
    all_fixture_templates     — Dict mapping T1…T10 to parsed template dicts
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Session-scoped logging setup (MISS-11)
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True, scope="session")
def configure_test_logging():
    """Configure structlog once for the entire test session."""
    from config.logging_config import configure_logging
    configure_logging()


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
FIXTURES_DIR = Path(__file__).parent / "fixtures"
TEMPLATES_DIR = FIXTURES_DIR / "templates"
GROUND_TRUTH_FILE = FIXTURES_DIR / "ground_truth" / "annotations.json"


# ---------------------------------------------------------------------------
# Pre-written LLM findings JSON used by mock_llm_client
# ---------------------------------------------------------------------------
_MOCK_FINDINGS_JSON = json.dumps(
    {
        "vulnerabilities": [
            {
                "resource_id": "MyS3Bucket",
                "resource_type": "AWS::S3::Bucket",
                "severity": "CRITICAL",
                "title": "Public access enabled",
                "description": "All four PublicAccessBlock flags are false.",
                "remediation": "Set all PublicAccessBlockConfiguration flags to true.",
                "reference": "CIS AWS 2.1.5",
            },
            {
                "resource_id": "MyS3Bucket",
                "resource_type": "AWS::S3::Bucket",
                "severity": "HIGH",
                "title": "No server-side encryption",
                "description": "BucketEncryption property is absent.",
                "remediation": "Add BucketEncryption with aws:kms or AES256.",
                "reference": "AWS Well-Architected SEC-8",
            },
        ],
        "summary": "2 vulnerabilities found in T1_basic_s3.",
    }
)

_MOCK_SNIPPETS = [
    {
        "text": "## S3 Encryption\n\nEnable server-side encryption for all S3 buckets.",
        "metadata": {"source": "cis_benchmarks.md", "chunk_index": 0},
        "score": 0.92,
    },
    {
        "text": "## S3 Public Access\n\nBlock all public access using PublicAccessBlockConfiguration.",
        "metadata": {"source": "aws_well_architected.md", "chunk_index": 1},
        "score": 0.88,
    },
]


# ---------------------------------------------------------------------------
# Fixture 1: sample_parsed_template
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_parsed_template() -> dict[str, Any]:
    """Return the dict output of cloudformation_parser.parse() on T1_basic_s3.yaml.

    Returns:
        Parsed CloudFormation template dict as produced by the parser.
    """
    from parsers.cloudformation_parser import CloudFormationParser
    return CloudFormationParser().parse(TEMPLATES_DIR / "T1_basic_s3.yaml")


# ---------------------------------------------------------------------------
# Fixture 2: sample_normalized_template  (used by existing agent tests)
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_normalized_template() -> dict[str, Any]:
    """Return a normalized template dict for use in agent unit tests.

    Returns:
        Normalized template dict compatible with agent run() input.
    """
    return {
        "template_format_version": "2010-09-09",
        "description": "Test",
        "parameters": {},
        "resources": {
            "MyBucket": {
                "type": "AWS::S3::Bucket",
                "properties": {
                    "BucketName": "test",
                    "VersioningConfiguration": {"Status": "Suspended"},
                },
                "depends_on": [],
                "metadata": {},
                "condition": None,
            },
            "MyRole": {
                "type": "AWS::IAM::Role",
                "properties": {
                    "AssumeRolePolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "*",
                            }
                        ]
                    }
                },
                "depends_on": [],
                "metadata": {},
                "condition": None,
            },
        },
        "outputs": {},
    }


# ---------------------------------------------------------------------------
# Fixture 3: sample_findings  (used by existing agent tests)
# ---------------------------------------------------------------------------
@pytest.fixture
def sample_findings() -> dict[str, Any]:
    """Return a sample findings dict for use in report generation tests.

    Returns:
        Findings dict compatible with ReportGenerationAgent run() input.
    """
    return {
        "vulnerabilities": [
            {
                "resource_name": "MyBucket",
                "resource_type": "AWS::S3::Bucket",
                "vulnerability_type": "S3 versioning disabled",
                "severity": "HIGH",
                "description": "Versioning suspended.",
                "remediation": "Enable versioning.",
                "best_practice_reference": "CIS 2.1.2",
            }
        ],
        "summary": "1 finding.",
    }


# ---------------------------------------------------------------------------
# Fixture 4: mock_llm_client
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_llm_client() -> MagicMock:
    """Return a MagicMock LLMClient that returns pre-written findings JSON.

    The mock's generate() and invoke() methods both return
    _MOCK_FINDINGS_JSON so agent tests can verify parsing logic without
    hitting any LLM.

    Returns:
        MagicMock configured to return canned findings JSON.
    """
    mock = MagicMock()
    mock.generate.return_value = _MOCK_FINDINGS_JSON
    mock.invoke.return_value = _MOCK_FINDINGS_JSON
    return mock


# ---------------------------------------------------------------------------
# Fixture 5: mock_vector_store
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_vector_store() -> MagicMock:
    """Return a MagicMock VectorStore returning pre-written KB snippet dicts.

    Returns:
        MagicMock whose search() returns _MOCK_SNIPPETS.
    """
    mock = MagicMock()
    mock.search.return_value = _MOCK_SNIPPETS
    mock.document_count.return_value = len(_MOCK_SNIPPETS)
    mock.upsert.return_value = None
    mock.clear.return_value = None
    return mock


# ---------------------------------------------------------------------------
# Fixture 6: mock_kb_manager
# ---------------------------------------------------------------------------
@pytest.fixture
def mock_kb_manager(mock_vector_store: MagicMock) -> MagicMock:
    """Return a MagicMock KnowledgeBaseManager wrapping mock_vector_store.

    Args:
        mock_vector_store: The mock VectorStore fixture.

    Returns:
        MagicMock whose retrieve() and query() return canned snippet data.
    """
    mock = MagicMock()
    mock.retrieve.return_value = [s["text"] for s in _MOCK_SNIPPETS]
    mock.query.return_value = _MOCK_SNIPPETS
    mock.initialize.return_value = None
    return mock


# ---------------------------------------------------------------------------
# Fixture 7: temp_output_dir
# ---------------------------------------------------------------------------
@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Return a temporary directory for report output during tests.

    Args:
        tmp_path: Pytest built-in temporary directory fixture.

    Returns:
        Path to a 'reports' subdirectory inside tmp_path.
    """
    output_dir = tmp_path / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


# ---------------------------------------------------------------------------
# Fixture 8: ground_truth_annotations  (session scope)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def ground_truth_annotations() -> dict[str, Any]:
    """Load and return the parsed annotations.json once per test session.

    Returns:
        Dict mapping template IDs (T1…T10) to their vulnerability entries.

    Raises:
        FileNotFoundError: If annotations.json is missing.
    """
    return json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Fixture 9: all_fixture_templates  (session scope)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def all_fixture_templates() -> dict[str, dict[str, Any]]:
    """Parse and return all T1–T10 fixture templates once per session.

    Returns:
        Dict mapping 'T1'…'T10' to their parsed CloudFormation template
        dicts as produced by CloudFormationParser.parse().
    """
    from parsers.cloudformation_parser import CloudFormationParser
    parser = CloudFormationParser()
    templates: dict[str, dict[str, Any]] = {}
    for i in range(1, 11):
        prefix = f"T{i}"
        matches = list(TEMPLATES_DIR.glob(f"{prefix}_*.yaml"))
        if matches:
            try:
                templates[prefix] = parser.parse(matches[0])
            except Exception:
                templates[prefix] = {}
    return templates
