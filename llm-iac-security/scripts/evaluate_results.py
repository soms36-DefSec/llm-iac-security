#!/usr/bin/env python3
"""
Evaluation script for LLM IaC Security Scanner.

Reproduces Table 1 from the base paper by computing precision, recall,
and F1 for each of the 10 test templates and reporting overall metrics.

Metric definitions:
    Precision = TP / (TP + FP)
    Recall    = TP / (TP + FN)
    F1        = 2 * (Precision * Recall) / (Precision + Recall)

A detected vulnerability counts as a True Positive if its resource_name
and vulnerability_type match a ground-truth entry with at least 80%
string similarity (case-insensitive).

Usage:
    python scripts/evaluate_results.py [--mode {local,aws}] [--verbose]
    python scripts/evaluate_results.py --annotations path/to/annotations.json
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Ensure UTF-8 output on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf_8"):
    sys.stdout = open(sys.stdout.fileno(), mode="w", encoding="utf-8", buffering=1)


# ---------------------------------------------------------------------------
# Similarity helper
# ---------------------------------------------------------------------------

def _similarity(a: str, b: str) -> float:
    """Compute normalised character-level overlap between two strings.

    Uses the Dice coefficient on character bigrams as a fast approximation
    of string similarity.

    Args:
        a: First string.
        b: Second string.

    Returns:
        Float in [0.0, 1.0] — 1.0 means identical strings.
    """
    a, b = a.lower().strip(), b.lower().strip()
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    bigrams_a = {a[i:i + 2] for i in range(len(a) - 1)}
    bigrams_b = {b[i:i + 2] for i in range(len(b) - 1)}
    if not bigrams_a or not bigrams_b:
        return float(a == b)
    intersection = bigrams_a & bigrams_b
    return 2 * len(intersection) / (len(bigrams_a) + len(bigrams_b))


def _is_match(detected: dict, ground_truth: dict, threshold: float = 0.8) -> bool:
    """Check whether a detected vulnerability matches a ground-truth entry.

    A match requires ≥ threshold string similarity on both resource_name
    and vulnerability_type fields (case-insensitive).

    Args:
        detected:     Detected vulnerability dict (from LLM output).
        ground_truth: Ground-truth annotation dict.
        threshold:    Minimum similarity required on both fields.

    Returns:
        True if the detected entry is considered a True Positive.
    """
    # Ground-truth uses "resource" or "resource_name"
    gt_resource = ground_truth.get("resource") or ground_truth.get("resource_name", "")
    gt_vuln_type = ground_truth.get("vulnerability_type", "")

    # Detected uses "resource_id", "resource_name", or "resource"
    det_resource = (
        detected.get("resource_name")
        or detected.get("resource_id")
        or detected.get("resource", "")
    )
    det_vuln_type = detected.get("vulnerability_type", "")

    resource_sim = _similarity(det_resource, gt_resource)
    vuln_sim = _similarity(det_vuln_type, gt_vuln_type)
    return resource_sim >= threshold and vuln_sim >= threshold


# ---------------------------------------------------------------------------
# Per-template metrics
# ---------------------------------------------------------------------------

def _compute_metrics(
    detected: list[dict],
    ground_truth: list[dict],
) -> dict:
    """Compute TP, FP, FN, precision, recall, and F1 for one template.

    Args:
        detected:     List of detected vulnerability dicts.
        ground_truth: List of ground-truth annotation dicts.

    Returns:
        Dict with keys: tp, fp, fn, precision, recall, f1.
        precision/recall/f1 are None when ground_truth is empty.
    """
    # Precision = TP / (TP + FP)
    # Recall    = TP / (TP + FN)
    # F1        = 2 * P * R / (P + R)

    gt_matched = [False] * len(ground_truth)
    tp = 0
    fp = 0

    for det in detected:
        matched = False
        for i, gt in enumerate(ground_truth):
            if not gt_matched[i] and _is_match(det, gt):
                gt_matched[i] = True
                matched = True
                break
        if matched:
            tp += 1
        else:
            fp += 1

    fn = sum(1 for m in gt_matched if not m)

    if not ground_truth:
        return {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": None,
            "recall": None,
            "f1": None,
        }

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _pct(value: float | None) -> str:
    """Format a metric value as a percentage string.

    Args:
        value: Float in [0, 1] or None.

    Returns:
        Formatted string like '85.0%' or 'N/A'.
    """
    if value is None:
        return "N/A"
    return f"{value * 100:.1f}%"


def _print_table(rows: list[tuple], overall: dict) -> None:
    """Print the evaluation results table in the spec format.

    Args:
        rows:    List of (tid, known, detected, fp, precision, recall, f1) tuples.
        overall: Overall metrics dict.
    """
    header = (
        " Template | Known Vulns | Detected | False Positives"
        " | Precision | Recall | F1"
    )
    sep = " " + "-" * 8 + "|" + "-" * 13 + "|" + "-" * 10 + "|" + "-" * 17 + "|" + "-" * 11 + "|" + "-" * 8 + "|------"

    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║              Evaluation Results — 10 CloudFormation Templates                ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print()
    print(header)
    print(sep)

    for tid, known, detected, fp, p, r, f in rows:
        print(
            f" {tid:<8} | {known:^11} | {detected:^8} | {fp:^15} "
            f"| {_pct(p):^9} | {_pct(r):^6} | {_pct(f)}"
        )

    print(sep)

    total_known = sum(r[1] for r in rows)
    total_detected = sum(r[2] for r in rows)
    total_fp = sum(r[3] for r in rows)
    print(
        f" {'Overall':<8} | {total_known:^11} | {total_detected:^8} | {total_fp:^15} "
        f"| {_pct(overall['precision']):^9} | {_pct(overall['recall']):^6} | {_pct(overall['f1'])}"
    )
    print()
    print(
        " Note: Precision, Recall, and F1 are N/A for templates with zero known vulnerabilities."
    )
    print(
        "       False positives on clean templates are recorded but excluded from overall metrics."
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Load annotations, compute metrics, print table, and save JSON."""
    parser = argparse.ArgumentParser(
        description="Evaluate scanner detection performance against ground-truth annotations."
    )
    parser.add_argument(
        "--mode",
        choices=["local", "aws"],
        default=None,
        help="Mode override (sets MODE env var).",
    )
    parser.add_argument(
        "--annotations",
        default=str(
            Path(__file__).parent.parent
            / "tests"
            / "fixtures"
            / "ground_truth"
            / "annotations.json"
        ),
        help="Path to annotations.json (default: tests/fixtures/ground_truth/annotations.json)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show per-template matched / unmatched details.",
    )
    args = parser.parse_args()

    if args.mode:
        os.environ["MODE"] = args.mode

    annotations_path = Path(args.annotations)
    if not annotations_path.exists():
        print(f"Ground truth not found: {annotations_path}", file=sys.stderr)
        sys.exit(1)

    data = json.loads(annotations_path.read_text(encoding="utf-8"))

    rows: list[tuple] = []
    # Aggregate only over templates with known vulnerabilities (for overall P/R/F1)
    agg_tp = agg_fp = agg_fn = 0

    for tid in sorted(data.keys()):
        entry = data[tid]
        ground_truth = entry.get("known_vulnerabilities", [])
        detected_raw = entry.get("detected_vulnerabilities", [])

        # Detected may be list[str] (IDs) or list[dict] — normalise to list[dict]
        detected: list[dict]
        if detected_raw and isinstance(detected_raw[0], str):
            detected = [{"resource_name": d, "vulnerability_type": d} for d in detected_raw]
        else:
            detected = detected_raw  # type: ignore[assignment]

        m = _compute_metrics(detected, ground_truth)

        rows.append((
            tid,
            len(ground_truth),
            m["tp"],          # detected = TP (matched)
            m["fp"],
            m["precision"],
            m["recall"],
            m["f1"],
        ))

        if args.verbose:
            print(f"\n{tid}: TP={m['tp']} FP={m['fp']} FN={m['fn']}")

        # Only accumulate for templates with known vulns
        if ground_truth:
            agg_tp += m["tp"]
            agg_fp += m["fp"]
            agg_fn += m["fn"]

    # Overall metrics (excluding clean templates from P/R/F1 denominator)
    overall_precision = agg_tp / (agg_tp + agg_fp) if (agg_tp + agg_fp) > 0 else 0.0
    overall_recall = agg_tp / (agg_tp + agg_fn) if (agg_tp + agg_fn) > 0 else 0.0
    overall_f1 = (
        2 * overall_precision * overall_recall / (overall_precision + overall_recall)
        if (overall_precision + overall_recall) > 0
        else 0.0
    )
    overall = {
        "precision": round(overall_precision, 4),
        "recall": round(overall_recall, 4),
        "f1": round(overall_f1, 4),
    }

    _print_table(rows, overall)

    # Save JSON results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = (
        Path(__file__).parent.parent / "data" / "reports"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"evaluation_{timestamp}.json"

    eval_output = {
        "timestamp": timestamp,
        "overall": overall,
        "per_template": {
            row[0]: {
                "known_vulnerabilities": row[1],
                "detected": row[2],
                "false_positives": row[3],
                "precision": row[4],
                "recall": row[5],
                "f1": row[6],
            }
            for row in rows
        },
    }
    output_file.write_text(json.dumps(eval_output, indent=2))
    print(f"\n Results saved to: {output_file}")


if __name__ == "__main__":
    main()
