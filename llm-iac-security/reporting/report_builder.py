"""Report builder: saves Markdown reports to the configured output directory."""
from __future__ import annotations
from datetime import datetime
from pathlib import Path

import config.settings as settings
from config.logging_config import get_logger
from utils.file_utils import write_text

logger = get_logger(__name__)


class ReportBuilder:
    """Saves Markdown report strings to disk with timestamped filenames."""

    def __init__(self) -> None:
        self._output_dir = Path(settings.REPORTS_OUTPUT_DIR)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def save(self, markdown: str, template_name: str, output_path: str | Path = None) -> Path:
        """Save a Markdown report string to the output directory.

        Args:
            markdown:      Full Markdown report content.
            template_name: Base name for the output file (no extension).
            output_path:   Optional override for the final report path.

        Returns:
            Path to the saved report file.
        """
        if output_path:
            path = Path(output_path)
        else:
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            path = self._output_dir / f"{template_name}_{ts}.md"
            
        path.parent.mkdir(parents=True, exist_ok=True)
        write_text(path, markdown)
        logger.info("report_saved", path=str(path))

        # GAP 15: S3 upload if in AWS mode
        if settings.MODE == "aws" and settings.S3_REPORTS_BUCKET:
            from storage.s3_handler import S3Handler
            try:
                s3 = S3Handler()
                s3.upload_report(path)
                logger.info("report_uploaded_to_s3", bucket=settings.S3_REPORTS_BUCKET, key=path.name)
            except Exception as e:
                logger.error(f"Failed to upload report to S3: {e}")

        return path
