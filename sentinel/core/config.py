from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from .suppression import Suppression


class AwsAccount(BaseModel):
    """A target account to audit by assuming a role into it."""

    role_arn: str
    account_id: str | None = None            # informational; STS resolves the real one
    regions: list[str] = Field(default_factory=list)  # falls back to aws_regions


class Config(BaseModel):
    aws_profile: str | None = None
    aws_regions: list[str] = Field(default_factory=list)
    aws_accounts: list[AwsAccount] = Field(default_factory=list)
    target_url: str | None = None
    log_paths: list[str] = Field(default_factory=list)
    capture_file: str | None = None
    ignore_ids: list[str] = Field(default_factory=list)
    suppressions: list[Suppression] = Field(default_factory=list)
    output_dir: str = "reports"


def load_config(path: str | Path | None = None) -> Config:
    if path is None:
        return Config()
    raw = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    return Config(**data)
