"""AWS session and client management — only used in AWS mode."""
from __future__ import annotations
from functools import lru_cache
from typing import Optional
import boto3
from botocore.config import Config
from config.settings import settings
from config.logging_config import get_logger

logger = get_logger(__name__)


def _is_valid(val: Optional[str]) -> bool:
    if not val:
        return False
    return "your_" not in val.lower() and "_here" not in val.lower()


@lru_cache(maxsize=1)
def get_session() -> boto3.Session:
    if settings.is_local:
        raise RuntimeError(
            "AWS session requested in local mode. "
            "Set MODE=aws in .env or use --mode aws to use AWS services."
        )

    kwargs: dict = {"region_name": settings.aws.region}

    if _is_valid(settings.aws.access_key_id) and _is_valid(settings.aws.secret_access_key):
        kwargs["aws_access_key_id"] = settings.aws.access_key_id
        kwargs["aws_secret_access_key"] = settings.aws.secret_access_key
    elif _is_valid(settings.aws.profile):
        kwargs["profile_name"] = settings.aws.profile

    logger.info("creating_boto3_session", region=kwargs.get("region_name"),
                has_keys=bool(kwargs.get("aws_access_key_id")),
                profile=kwargs.get("profile_name"))

    return boto3.Session(**kwargs)


def get_client(service: str, region: Optional[str] = None):
    cfg = Config(retries={"max_attempts": 3, "mode": "adaptive"})
    return get_session().client(service, region_name=region or settings.aws.region, config=cfg)
