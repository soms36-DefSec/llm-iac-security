import json
from pathlib import Path

from click.testing import CliRunner

from scripts.run_scan import scan

ROOT = Path(__file__).resolve().parents[2]


def test_run_scan_writes_json_output_for_clean_terraform(tmp_path):
    output_path = tmp_path / "results.json"
    fixture = ROOT / "tests/fixtures/terraform/clean/aws_rds_private_encrypted"

    result = CliRunner().invoke(
        scan,
        [str(fixture), "--static-only", "--json-output", str(output_path)],
    )

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["scan_mode"] == "static-only"
    assert payload["iac"]["type"] == "terraform"
    assert payload["scan_metadata"]["findings_count"] == 0
