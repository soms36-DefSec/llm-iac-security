"""S3 handler for uploading reports and downloading templates."""
from __future__ import annotations
from pathlib import Path

import config.settings as settings
from config.logging_config import get_logger
from utils.aws_utils import get_client
from utils.exceptions import StorageError

logger = get_logger(__name__)


class S3Handler:
    """Upload reports and download CloudFormation templates from S3."""

    def __init__(self) -> None:
        self._client = get_client("s3")

    def upload_report(self, local_path: Path) -> str:
        """Upload a report file to the reports S3 bucket.

        Args:
            local_path: Local path to the report file.

        Returns:
            s3:// URI of the uploaded object.

        Raises:
            StorageError: If the upload fails.
        """
        return self._upload(
            local_path,
            settings.S3_REPORTS_BUCKET,
            f"reports/{local_path.name}",
        )

    def upload_template(self, local_path: Path) -> str:
        """Upload a CloudFormation template to the templates S3 bucket.

        Args:
            local_path: Local path to the template file.

        Returns:
            s3:// URI of the uploaded object.

        Raises:
            StorageError: If the upload fails.
        """
        return self._upload(
            local_path,
            settings.S3_TEMPLATES_BUCKET,
            f"templates/{local_path.name}",
        )

    def download(self, bucket: str, key: str, dest: Path) -> None:
        """Download an object from S3 to a local path.

        Args:
            bucket: S3 bucket name.
            key:    Object key.
            dest:   Local destination path.

        Raises:
            StorageError: If the download fails.
        """
        try:
            self._client.download_file(bucket, key, str(dest))
        except Exception as exc:
            raise StorageError(str(exc)) from exc

    def _upload(self, local: Path, bucket: str, key: str) -> str:
        """Upload a local file to S3 and return its s3:// URI.

        Args:
            local:  Local file path.
            bucket: Destination bucket.
            key:    Destination object key.

        Returns:
            s3:// URI string.

        Raises:
            StorageError: If the upload fails.
        """
        try:
            self._client.upload_file(str(local), bucket, key)
            return f"s3://{bucket}/{key}"
        except Exception as exc:
            raise StorageError(str(exc)) from exc
