"""AWS boto3 session and client helpers."""
from __future__ import annotations
from functools import lru_cache
from typing import Optional

import boto3
from botocore.config import Config

import config.settings as settings
from config.logging_config import get_logger

logger = get_logger(__name__)


def _is_valid(val: Optional[str]) -> bool:
    """Return True if val is set and does not look like a placeholder.

    Args:
        val: String to check.

    Returns:
        True if val is non-empty and not a placeholder string.
    """
    if not val:
        return False
    return "your_" not in val.lower() and "_here" not in val.lower()


@lru_cache(maxsize=1)
def get_session() -> boto3.Session:
    """Create and cache a boto3 Session from settings.

    Returns:
        Configured boto3.Session instance.
    """
    kwargs: dict = {"region_name": settings.AWS_REGION}

    if _is_valid(settings.AWS_ACCESS_KEY_ID) and _is_valid(settings.AWS_SECRET_ACCESS_KEY):
        kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
        kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY
    elif _is_valid(settings.AWS_PROFILE):
        kwargs["profile_name"] = settings.AWS_PROFILE

    logger.info(
        "creating_boto3_session",
        region=kwargs.get("region_name"),
        has_keys=bool(kwargs.get("aws_access_key_id")),
        profile=kwargs.get("profile_name"),
    )
    return boto3.Session(**kwargs)


def get_client(service: str, region: Optional[str] = None):
    """Return a boto3 service client with adaptive retry config.

    Args:
        service: AWS service name (e.g. 'bedrock-runtime', 's3').
        region:  Override region. Defaults to settings.AWS_REGION.

    Returns:
        Configured boto3 client.
    """
    cfg = Config(retries={"max_attempts": 3, "mode": "adaptive"})
    return get_session().client(
        service,
        region_name=region or settings.AWS_REGION,
        config=cfg,
    )
