from __future__ import annotations

from pydantic import BaseModel, Field


class Asset(BaseModel):
    """A structured description of the thing a finding is about.

    Binding findings to a typed asset (instead of a bare ``resource: str``) is what
    lets Sentinel group, de-duplicate, and report per account/region/type like a
    real security tool rather than a flat report.
    """

    provider: str                 # "aws" | "host" | "web" | "network"
    type: str                     # "s3_bucket" | "security_group" | "iam_user" | "url" | "ip"
    id: str                       # natural identifier (bucket name, sg id, url, ip)
    name: str | None = None
    account_id: str | None = None
    region: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
