from __future__ import annotations
import json, re
from typing import Any
from utils.exceptions import LLMResponseParseError

def extract_json_block(text: str) -> str:
    m = re.search(r"```(?:json)?\s*(\{.*?})\s*```", text, re.DOTALL)
    if m: return m.group(1)
    m = re.search(r"\{.*}", text, re.DOTALL)
    return m.group(0) if m else text.strip()

def parse_vulnerability_response(raw_text: str) -> dict[str, Any]:
    try: data = json.loads(extract_json_block(raw_text))
    except json.JSONDecodeError as e:
        raise LLMResponseParseError(f"Cannot parse LLM response: {e}") from e
    if "vulnerabilities" not in data:
        raise LLMResponseParseError("'vulnerabilities' key missing from response.")
    return data


def parse_hybrid_vulnerability_response(
    raw_text: str,
    fallback_static_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Parse strict hybrid JSON, falling back to static findings on failure."""
    fallback_static_findings = fallback_static_findings or []
    try:
        data = json.loads(extract_json_block(raw_text))
        if isinstance(data, dict) and "findings" not in data and "vulnerabilities" in data:
            legacy_findings = [
                _legacy_vulnerability_to_hybrid(item)
                for item in data.get("vulnerabilities", [])
                if isinstance(item, dict)
            ]
            legacy_findings = _enrich_with_static_metadata(legacy_findings, fallback_static_findings)
            legacy_findings = _merge_missing_static_findings(legacy_findings, fallback_static_findings)
            response = {"findings": legacy_findings, "summary": _summary(legacy_findings)}
            response["vulnerabilities"] = legacy_findings
            return response
        if not isinstance(data, dict) or "findings" not in data:
            raise LLMResponseParseError("'findings' key missing from hybrid response.")
        findings = data.get("findings")
        if not isinstance(findings, list):
            raise LLMResponseParseError("'findings' must be a list.")
        normalized = {
            "findings": [_normalize_hybrid_finding(item) for item in findings if isinstance(item, dict)],
            "summary": data.get("summary") if isinstance(data.get("summary"), dict) else {},
        }
        normalized["findings"] = _enrich_with_static_metadata(normalized["findings"], fallback_static_findings)
        normalized["findings"] = _merge_missing_static_findings(normalized["findings"], fallback_static_findings)
        normalized["summary"] = _summary(normalized["findings"], normalized["summary"])
        normalized["vulnerabilities"] = normalized["findings"]
        return normalized
    except (json.JSONDecodeError, LLMResponseParseError):
        return static_findings_to_hybrid_response(
            fallback_static_findings,
            summary_note="LLM response could not be parsed; returned static findings.",
        )


def static_findings_to_hybrid_response(
    static_findings: list[dict[str, Any]],
    summary_note: str | None = None,
) -> dict[str, Any]:
    """Convert deterministic static findings to the hybrid response shape."""
    findings = []
    for finding in static_findings:
        finding_id = str(finding.get("finding_id") or "")
        findings.append(
            {
                "finding_id": finding_id,
                "source_finding_ids": [finding_id] if finding_id else [],
                "rule_id": finding.get("rule_id", ""),
                "title": finding.get("title", ""),
                "severity": finding.get("severity", "INFO"),
                "confidence": finding.get("confidence", "MEDIUM"),
                "validation_status": "needs_review" if summary_note else "true_positive",
                "resource_id": finding.get("resource_id", ""),
                "resource_type": finding.get("resource_type", ""),
                "description": finding.get("description", ""),
                "impact": finding.get("description", ""),
                "evidence": finding.get("evidence", ""),
                "remediation": finding.get("remediation", ""),
                "references": finding.get("references", []),
                "detected_by": finding.get("detected_by", "static"),
                "iac_type": finding.get("iac_type", ""),
                "provider": finding.get("provider", ""),
                "source_file": finding.get("source_file", ""),
                "line_number": finding.get("line_number"),
                "tags": finding.get("tags", []),
            }
        )
    response = {"findings": findings, "summary": _summary(findings)}
    if summary_note:
        response["summary"]["note"] = summary_note
    response["vulnerabilities"] = findings
    return response


def _normalize_hybrid_finding(finding: dict[str, Any]) -> dict[str, Any]:
    finding_id = str(finding.get("finding_id") or "")
    return {
        "finding_id": finding_id,
        "source_finding_ids": finding.get("source_finding_ids") or ([finding_id] if finding_id else []),
        "rule_id": finding.get("rule_id", ""),
        "title": finding.get("title", ""),
        "severity": str(finding.get("severity", "INFO")).upper(),
        "confidence": str(finding.get("confidence", "MEDIUM")).upper(),
        "validation_status": finding.get("validation_status", "needs_review"),
        "resource_id": finding.get("resource_id", ""),
        "resource_type": finding.get("resource_type", ""),
        "description": finding.get("description", ""),
        "impact": finding.get("impact", ""),
        "evidence": finding.get("evidence", ""),
        "remediation": finding.get("remediation", ""),
        "references": finding.get("references", []),
        "detected_by": finding.get("detected_by", "hybrid"),
        "iac_type": finding.get("iac_type", ""),
        "provider": finding.get("provider", ""),
        "source_file": finding.get("source_file", ""),
        "line_number": finding.get("line_number"),
        "tags": finding.get("tags", []),
    }


def _legacy_vulnerability_to_hybrid(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": finding.get("finding_id") or finding.get("resource_id", "llm-finding"),
        "source_finding_ids": finding.get("source_finding_ids", []),
        "rule_id": finding.get("rule_id", ""),
        "title": finding.get("title", ""),
        "severity": str(finding.get("severity", "INFO")).upper(),
        "confidence": finding.get("confidence", "MEDIUM"),
        "validation_status": finding.get("validation_status", "needs_review"),
        "resource_id": finding.get("resource_id", ""),
        "resource_type": finding.get("resource_type", ""),
        "description": finding.get("description", ""),
        "impact": finding.get("impact", finding.get("description", "")),
        "evidence": finding.get("evidence", ""),
        "remediation": finding.get("remediation", ""),
        "references": finding.get("references") or ([finding.get("reference")] if finding.get("reference") else []),
        "detected_by": finding.get("detected_by", "llm"),
        "iac_type": finding.get("iac_type", ""),
        "provider": finding.get("provider", ""),
        "source_file": finding.get("source_file", ""),
        "line_number": finding.get("line_number"),
        "tags": finding.get("tags", []),
    }


def _summary(findings: list[dict[str, Any]], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    summary = dict(existing or {})
    summary["total_findings"] = len(findings)
    summary["critical"] = _count(findings, "CRITICAL")
    summary["high"] = _count(findings, "HIGH")
    summary["medium"] = _count(findings, "MEDIUM")
    summary["low"] = _count(findings, "LOW")
    summary["needs_review"] = sum(1 for item in findings if item.get("validation_status") == "needs_review")
    return summary


def _count(findings: list[dict[str, Any]], severity: str) -> int:
    return sum(1 for item in findings if str(item.get("severity", "")).upper() == severity)


def _merge_missing_static_findings(
    findings: list[dict[str, Any]],
    static_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not static_findings:
        return findings
    covered_ids = {
        source_id
        for finding in findings
        for source_id in finding.get("source_finding_ids", [])
    }
    covered_ids.update(str(finding.get("finding_id", "")) for finding in findings)
    covered_pairs = {
        (str(finding.get("rule_id", "")), str(finding.get("resource_id", "")))
        for finding in findings
    }
    additions = []
    for static_finding in static_findings:
        finding_id = str(static_finding.get("finding_id", ""))
        pair = (str(static_finding.get("rule_id", "")), str(static_finding.get("resource_id", "")))
        if finding_id in covered_ids or pair in covered_pairs:
            continue
        additions.extend(static_findings_to_hybrid_response([static_finding])["findings"])
    return findings + additions


def _enrich_with_static_metadata(
    findings: list[dict[str, Any]],
    static_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Carry source location metadata forward when the LLM omits it."""
    if not static_findings:
        return findings
    by_id = {str(item.get("finding_id", "")): item for item in static_findings}
    by_pair = {
        (str(item.get("rule_id", "")), str(item.get("resource_id", ""))): item
        for item in static_findings
    }
    enriched: list[dict[str, Any]] = []
    for finding in findings:
        match = None
        for source_id in finding.get("source_finding_ids", []):
            match = by_id.get(str(source_id))
            if match:
                break
        if not match:
            match = by_id.get(str(finding.get("finding_id", "")))
        if not match:
            match = by_pair.get((str(finding.get("rule_id", "")), str(finding.get("resource_id", ""))))
        if match:
            for key in ("source_file", "line_number", "iac_type", "provider", "tags"):
                if finding.get(key) in (None, "", []):
                    finding[key] = match.get(key)
        enriched.append(finding)
    return enriched
