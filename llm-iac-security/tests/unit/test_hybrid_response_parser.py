import json

from llm.response_parser import parse_hybrid_vulnerability_response


STATIC_FINDING = {
    "finding_id": "f1",
    "rule_id": "AWS_S3_BUCKET_ENCRYPTION_MISSING",
    "title": "S3 bucket encryption missing",
    "severity": "HIGH",
    "confidence": "HIGH",
    "resource_id": "aws_s3_bucket.logs",
    "resource_type": "aws_s3_bucket",
    "description": "Missing encryption",
    "evidence": "masked",
    "remediation": "Enable encryption",
    "references": [],
    "detected_by": "static",
    "iac_type": "terraform",
    "provider": "aws",
    "source_file": "main.tf",
    "tags": ["s3"],
}


def test_parse_hybrid_json():
    payload = {
        "findings": [
            {
                "finding_id": "hf1",
                "source_finding_ids": ["f1"],
                "title": "S3 bucket encryption missing",
                "severity": "HIGH",
                "confidence": "HIGH",
                "validation_status": "true_positive",
                "resource_id": "aws_s3_bucket.logs",
                "resource_type": "aws_s3_bucket",
                "description": "Missing encryption",
                "impact": "Data exposure risk",
                "evidence": "masked",
                "remediation": "Enable encryption",
                "references": [],
                "detected_by": "hybrid",
            }
        ],
        "summary": {},
    }
    parsed = parse_hybrid_vulnerability_response(json.dumps(payload), [STATIC_FINDING])
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["vulnerabilities"] == parsed["findings"]


def test_malformed_hybrid_json_falls_back_to_static_findings():
    parsed = parse_hybrid_vulnerability_response("not json", [STATIC_FINDING])
    assert parsed["findings"][0]["finding_id"] == "f1"
    assert parsed["summary"]["note"]
    assert parsed["findings"][0]["iac_type"] == "terraform"
    assert parsed["findings"][0]["provider"] == "aws"
