from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class Config(BaseModel):
    aws_profile: str | None = None
    target_url: str | None = None
    log_paths: list[str] = Field(default_factory=list)
    capture_file: str | None = None
    ignore_ids: list[str] = Field(default_factory=list)
    output_dir: str = "reports"


def load_config(path: str | Path | None = None) -> Config:
    if path is None:
        return Config()
    raw = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    return Config(**data)
