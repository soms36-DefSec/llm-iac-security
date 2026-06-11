#!/usr/bin/env python3
"""Evaluate scanner output against fixture ground truth."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import settings
from llm.response_parser import static_findings_to_hybrid_response
from orchestrator.pipeline import IaCSecurityPipeline

ROOT = Path(__file__).resolve().parent.parent
TERRAFORM_GT = ROOT / "tests/fixtures/ground_truth/terraform_annotations.json"
CLOUDFORMATION_GT = ROOT / "tests/fixtures/ground_truth/cloudformation_annotations.json"
OUTPUT = settings.app.report_output_dir / "evaluation_results.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate IaC scanner results.")
    parser.add_argument("--iac", choices=["all", "terraform", "cloudformation"], default="all")
    parser.add_argument("--mode", choices=["static-only", "hybrid-mocked"], default="static-only")
    args = parser.parse_args()

    cases = load_cases(args.iac)
    if not cases:
        print("No evaluation cases found.")
        return 1

    results = []
    total_started = time.perf_counter()
    for case in cases:
        result = run_case(case["path"], args.mode)
        detected = finding_keys(result.get("findings", {}).get("findings", []))
        truth = finding_keys(case["expected_findings"])
        metrics = compute_metrics(detected, truth)
        results.append(
            {
                "id": case["id"],
                "iac_type": case["iac_type"],
                "path": str(case["path"]),
                "expected": sorted([list(item) for item in truth]),
                "detected": sorted([list(item) for item in detected]),
                "false_positive_findings": sorted([list(item) for item in detected - truth]),
                "false_negative_findings": sorted([list(item) for item in truth - detected]),
                "latency_seconds": result.get("scan_metadata", {}).get("latency_seconds", 0.0),
                **metrics,
            }
        )

    overall = aggregate(results)
    per_rule = per_rule_metrics(results)
    payload = {
        "mode": args.mode,
        "iac": args.iac,
        "scan_summary": scan_summary(results),
        "total_scan_time_seconds": time.perf_counter() - total_started,
        "average_latency_seconds": overall["average_latency_seconds"],
        "overall": overall,
        "per_rule": per_rule,
        "per_template": results,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print_table(results, overall, per_rule)
    print(f"\nSaved evaluation results to {OUTPUT}")
    return 0


def load_cases(iac: str) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    if iac in {"all", "terraform"}:
        cases.extend(_load_ground_truth(TERRAFORM_GT, "terraform"))
    if iac in {"all", "cloudformation"}:
        cases.extend(_load_ground_truth(CLOUDFORMATION_GT, "cloudformation"))
    return cases


def _load_ground_truth(path: Path, iac_type: str) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    cases = []
    for case_id, entry in data.items():
        fixture_path = ROOT / entry["fixture_path"]
        cases.append(
            {
                "id": case_id,
                "iac_type": iac_type,
                "path": fixture_path,
                "expected_findings": entry.get("expected_findings", []),
            }
        )
    return cases


def run_case(path: Path, mode: str) -> dict[str, Any]:
    if mode == "static-only":
        return IaCSecurityPipeline(static_only=True).run(path)

    mock_kb = MagicMock()
    mock_kb.retrieve.return_value = ["Mocked best-practice context for deterministic evaluation."]
    mock_llm = _HybridMockLLM()
    with patch("agents.retrieval_agent.KnowledgeBaseManager", return_value=mock_kb), \
         patch("agents.vulnerability_detection_agent.get_llm_client", return_value=mock_llm):
        return IaCSecurityPipeline(hybrid=True).run(path)


class _HybridMockLLM:
    """Mock LLM that returns static findings in the hybrid JSON schema."""

    def invoke(self, messages: list[dict[str, Any]], system: str = "", **_: Any) -> str:
        content = messages[0]["content"] if messages else ""
        static_findings = _extract_static_findings(content)
        response = static_findings_to_hybrid_response(static_findings)
        for finding in response["findings"]:
            finding["detected_by"] = "hybrid"
            finding["validation_status"] = "true_positive"
            finding["impact"] = finding.get("description", "")
        return json.dumps(response)


def _extract_static_findings(prompt: str) -> list[dict[str, Any]]:
    match = re.search(r"## Static Findings JSON\s*(.*?)\s*## Best-Practice Context", prompt, re.DOTALL)
    if not match:
        return []
    try:
        data = json.loads(match.group(1))
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def finding_keys(findings: list[dict[str, Any]]) -> set[tuple[str, str]]:
    return {
        (str(finding.get("rule_id", "")), str(finding.get("resource_id", "")))
        for finding in findings
        if finding.get("rule_id") and finding.get("resource_id")
    }


def compute_metrics(detected: set[tuple[Any, ...]], truth: set[tuple[Any, ...]]) -> dict[str, Any]:
    tp = len(detected & truth)
    fp = len(detected - truth)
    fn = len(truth - detected)
    precision = tp / (tp + fp) if tp + fp else 1.0 if not truth else 0.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(item["true_positives"] for item in results)
    fp = sum(item["false_positives"] for item in results)
    fn = sum(item["false_negatives"] for item in results)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "average_latency_seconds": round(
            sum(item["latency_seconds"] for item in results) / len(results),
            4,
        ),
    }


def per_rule_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    rules = sorted(
        {
            rule_id
            for result in results
            for rule_id, _resource in [tuple(item) for item in result["expected"] + result["detected"]]
            if rule_id
        }
    )
    output = {}
    for rule_id in rules:
        detected = {
            (result["id"], rule, resource)
            for result in results
            for rule, resource in result["detected"]
            if rule == rule_id
        }
        truth = {
            (result["id"], rule, resource)
            for result in results
            for rule, resource in result["expected"]
            if rule == rule_id
        }
        output[rule_id] = compute_metrics(detected, truth)
    return output


def scan_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Return aggregate counts for the evaluated fixture set."""
    by_iac: dict[str, int] = {}
    for result in results:
        by_iac[result["iac_type"]] = by_iac.get(result["iac_type"], 0) + 1
    return {
        "templates_scanned": len(results),
        "templates_by_iac_type": by_iac,
        "templates_with_findings": sum(1 for result in results if result["detected"]),
        "total_expected_findings": sum(len(result["expected"]) for result in results),
        "total_detected_findings": sum(len(result["detected"]) for result in results),
    }


def print_table(results: list[dict[str, Any]], overall: dict[str, Any], per_rule: dict[str, Any]) -> None:
    print("\nPer-template metrics")
    print("| Template | IaC | TP | FP | FN | Precision | Recall | F1 | Latency |")
    print("|----------|-----|----|----|----|-----------|--------|----|---------|")
    for item in results:
        print(
            f"| {item['id']} | {item['iac_type']} | {item['true_positives']} | {item['false_positives']} | "
            f"{item['false_negatives']} | {item['precision']:.2f} | {item['recall']:.2f} | "
            f"{item['f1']:.2f} | {item['latency_seconds']:.3f}s |"
        )

    print("\nPer-rule metrics")
    print("| Rule ID | Precision | Recall | F1 |")
    print("|---------|-----------|--------|----|")
    for rule_id, metrics in per_rule.items():
        print(f"| {rule_id} | {metrics['precision']:.2f} | {metrics['recall']:.2f} | {metrics['f1']:.2f} |")

    print("\nOverall")
    print(json.dumps(overall, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
