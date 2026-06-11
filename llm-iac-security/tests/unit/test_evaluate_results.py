from scripts.evaluate_results import compute_metrics, per_rule_metrics, scan_summary


def test_compute_metrics_counts_false_positive_and_negative():
    detected = {("RULE_A", "res1"), ("RULE_B", "res2")}
    truth = {("RULE_A", "res1"), ("RULE_C", "res3")}
    metrics = compute_metrics(detected, truth)
    assert metrics["true_positives"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["false_negatives"] == 1
    assert metrics["precision"] == 0.5


def test_per_rule_metrics_keeps_duplicate_resource_ids_per_template():
    results = [
        {"id": "case1", "expected": [["RULE_A", "same"]], "detected": [["RULE_A", "same"]]},
        {"id": "case2", "expected": [["RULE_A", "same"]], "detected": []},
    ]
    metrics = per_rule_metrics(results)
    assert metrics["RULE_A"]["true_positives"] == 1
    assert metrics["RULE_A"]["false_negatives"] == 1


def test_scan_summary_counts_templates_and_findings():
    results = [
        {"iac_type": "terraform", "expected": [["R", "a"]], "detected": [["R", "a"]]},
        {"iac_type": "cloudformation", "expected": [], "detected": []},
    ]
    summary = scan_summary(results)
    assert summary["templates_scanned"] == 2
    assert summary["templates_by_iac_type"] == {"terraform": 1, "cloudformation": 1}
    assert summary["templates_with_findings"] == 1
