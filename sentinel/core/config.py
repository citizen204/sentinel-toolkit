from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .finding import Severity
from .suppression import Suppression


class StrictModel(BaseModel):
    """Base for every config model: an unrecognised key is an error, not a no-op.

    Without this, `aws_regons: [us-east-1]` parses happily, `aws_regions` stays
    empty, and the scan quietly covers nothing the operator asked for.
    """

    model_config = ConfigDict(extra="forbid")


class RuleConfig(StrictModel):
    """Per-rule overrides. Anything left unset falls back to the rule/profile."""

    enabled: bool | None = None      # force a rule on/off regardless of profile
    severity: Severity | None = None  # re-rate a rule for your environment
    threshold: int | None = None      # for threshold-based rules (brute force, scans)


class AwsAccount(StrictModel):
    """A target account to audit by assuming a role into it."""

    role_arn: str
    account_id: str | None = None            # informational; STS resolves the real one
    regions: list[str] = Field(default_factory=list)  # falls back to aws_regions


class Config(StrictModel):
    aws_profile: str | None = None
    aws_regions: list[str] = Field(default_factory=list)
    aws_accounts: list[AwsAccount] = Field(default_factory=list)
    target_url: str | None = None
    log_paths: list[str] = Field(default_factory=list)
    capture_file: str | None = None
    ignore_ids: list[str] = Field(default_factory=list)
    suppressions: list[Suppression] = Field(default_factory=list)
    # A typo here is rejected at load time rather than silently falling back.
    # baseline = rule defaults | strict = everything | cis = only rules with a
    # verified compliance mapping.
    profile: Literal["baseline", "strict", "cis"] = "baseline"
    rules: dict[str, RuleConfig] = Field(default_factory=dict)
    output_dir: str = "reports"

    def rule_settings(self, rule_id: str) -> RuleConfig:
        return self.rules.get(rule_id) or RuleConfig()

    def threshold_for(self, rule_id: str, default: int) -> int:
        """The configured threshold for a rule, or the rule's own default."""
        value = self.rule_settings(rule_id).threshold
        return default if value is None else value


def load_config(path: str | Path | None = None) -> Config:
    if path is None:
        return Config()
    raw = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    return Config(**data)
