from datetime import datetime, timezone

import reporting.report_builder as report_builder
from config.settings import settings
from reporting.report_builder import ReportBuilder


class _FixedDateTime:
    @staticmethod
    def now(tz=None):
        return datetime(2026, 1, 1, 0, 0, 0, tzinfo=tz or timezone.utc)


def test_report_builder_does_not_overwrite_same_timestamp(tmp_path, monkeypatch):
    monkeypatch.setattr(settings.app, "report_output_dir", tmp_path)
    monkeypatch.setattr(report_builder, "datetime", _FixedDateTime)

    builder = ReportBuilder()
    first = builder.save("# First", "scan")
    second = builder.save("# Second", "scan")

    assert first != second
    assert first.read_text(encoding="utf-8") == "# First"
    assert second.read_text(encoding="utf-8") == "# Second"
