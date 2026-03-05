from __future__ import annotations
from functools import lru_cache
from typing import Optional
import boto3
from botocore.config import Config
from config.settings import settings

@lru_cache(maxsize=1)
def get_session() -> boto3.Session:
    kwargs: dict = {"region_name": settings.aws.region}
    if settings.aws.profile: kwargs["profile_name"] = settings.aws.profile
    elif settings.aws.access_key_id:
        kwargs["aws_access_key_id"] = settings.aws.access_key_id
        kwargs["aws_secret_access_key"] = settings.aws.secret_access_key
    return boto3.Session(**kwargs)

def get_client(service: str, region: Optional[str] = None):
    cfg = Config(retries={"max_attempts": 3, "mode": "adaptive"})
    return get_session().client(service, region_name=region or settings.aws.region, config=cfg)
