from __future__ import annotations
from pathlib import Path
from config.settings import settings
from config.logging_config import get_logger
from utils.aws_utils import get_client
from utils.exceptions import StorageError

logger = get_logger(__name__)

class S3Handler:
    def __init__(self): self._client = get_client("s3")

    def upload_report(self, local_path: Path) -> str:
        return self._upload(local_path, settings.s3.reports_bucket, f"reports/{local_path.name}")

    def upload_template(self, local_path: Path) -> str:
        return self._upload(local_path, settings.s3.templates_bucket, f"templates/{local_path.name}")

    def download(self, bucket: str, key: str, dest: Path) -> None:
        try: self._client.download_file(bucket, key, str(dest))
        except Exception as e: raise StorageError(str(e)) from e

    def _upload(self, local: Path, bucket: str, key: str) -> str:
        try:
            self._client.upload_file(str(local), bucket, key)
            return f"s3://{bucket}/{key}"
        except Exception as e: raise StorageError(str(e)) from e
