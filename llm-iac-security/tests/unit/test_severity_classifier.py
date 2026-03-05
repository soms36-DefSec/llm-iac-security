from reporting.severity_classifier import Severity, classify, sort_findings
def test_critical(): assert classify("CRITICAL") == Severity.CRITICAL
def test_case(): assert classify("high") == Severity.HIGH
def test_unknown(): assert classify("XYZ") == Severity.INFO
def test_sort():
    r = sort_findings([{"severity":"LOW"},{"severity":"CRITICAL"},{"severity":"MEDIUM"}])
    assert r[0]["severity"] == "CRITICAL" and r[-1]["severity"] == "LOW"
