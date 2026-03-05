from __future__ import annotations
from datetime import datetime
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
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        path = self._output_dir / f"{template_name}_{ts}.md"
        write_text(path, markdown)
        logger.info("report_saved", path=str(path))
        return path
