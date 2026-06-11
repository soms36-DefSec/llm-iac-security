from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from config.settings import settings
from config.logging_config import get_logger
from utils.file_utils import write_text

logger = get_logger(__name__)

class ReportBuilder:
    def __init__(self):
        self._output_dir = settings.app.report_output_dir
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def save(self, markdown: str, template_name: str) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        path = self._output_dir / f"{template_name}_{ts}.md"
        counter = 1
        while path.exists():
            path = self._output_dir / f"{template_name}_{ts}_{counter}.md"
            counter += 1
        write_text(path, markdown)
        logger.info("report_saved", path=str(path))
        return path
